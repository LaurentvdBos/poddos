#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <linux/sched.h>
#include <signal.h>
#include <sched.h>

#include "http.h"
#include "json.h"
#include "untar.h"
#include "inflate.h"
#include "poddos.h"
#include "layer.h"

#if defined(__x86_64__)
#define ARCH "amd64"
#define OS "linux"
#elif defined(__aarch64__)
#define ARCH "arm64"
#define VARIANT "v8"
#define OS "linux"
#else
#error "Unsupported architecture"
#endif

int pull(const char *full_url)
{
    char url[URL_MAX + 1], repository[URL_MAX + 1], ref[URL_MAX + 1], url2[URL_MAX + 1];

    if (sscanf(full_url, "%1000[^/]/%1000[^:]:%1000s", url, repository, ref) != 3)
        return -1;
    snprintf(url2, URL_MAX, "https://%s/v2/%s/manifests/%s", url, repository, ref);

    fprintf(stderr, "Retrieving available manifests...\n");

    FILE *f =
        urlopen(url2, 0,
                "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json");
    if (!f)
        return -1;

    char json[65536] = { 0 };
    int n = fread(json, 1, 65536, f);
    if (!feof(f))
        errx("Buffer for json too small");
    fclose(f);

    if (n == 4096)
        return -1;

    const char *manifests = jget(json, "manifests");
    const char *manifest = NULL;
    for (int i = 0; (manifest = jindex(manifests, i)); i++) {
        const char *platform = jget(manifest, "platform");

        const char *arch = jget(platform, "architecture");
        if (!arch || strncmp(arch + 1, ARCH, strlen(ARCH)))
            continue;

#ifdef VARIANT
        const char *variant = jget(platform, "variant");
        if (variant && strncmp(variant + 1, VARIANT, strlen(VARIANT)))
            continue;
#endif

        const char *os = jget(platform, "os");
        if (!os || strncmp(os + 1, OS, strlen(OS)))
            continue;

        break;
    }

    if (!manifest) {
        fprintf(stderr, "Could not find architecture.\n");
        return -1;
    }

    const char *digest = jget(manifest, "digest");
    if (digest < manifest)
        return -1;

    char digest2[100];
    if (jstr(digest, digest2, 100) == -1)
        return -1;
    fprintf(stderr, "Retrieving manifest (%s)...\n", digest2);

    snprintf(url2, URL_MAX, "https://%s/v2/%s/manifests/%s", url, repository, digest2);
    f = urlopen(url2, 0,
                "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json");
    if (!f)
        return -1;
    n = fread(json, 1, 65536, f);
    if (!feof(f))
        errx("Buffer too small for manifest");
    fclose(f);

    const char *layers = jget(json, "layers");
    const char *layer;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        err("pipe");

    struct clone_args cl_args = { 0 };
    cl_args.flags = CLONE_NEWUSER;
    cl_args.exit_signal = SIGCHLD;
    pid_t pid = syscall(SYS_clone3, &cl_args, sizeof(struct clone_args));
    if (pid == -1)
        err("clone3");
    if (pid == 0) {
        // Child, wait for the parent to setup the uid / gid map
        close(pipefd[1]);
        char buf;
        if (read(pipefd[0], &buf, 1) == -1)
            err("read(pipefd)");
        close(pipefd[0]);

        for (int i = 0; (layer = jindex(layers, i)); i++) {
            char digest[100];
            if (jstr(jget(layer, "digest"), digest, 100) == -1)
                return -1;

            char *dir = strrchr(digest, ':');
            if (!dir)
                errx("Invalid digest: %s", digest);

            if (mkdirat(layer_fd, dir + 1, 0777) == -1) {
                if (errno == EEXIST) {
                    fprintf(stderr, "Skipping %s...\n", digest);
                    continue;
                } else
                    err("mkdir(%s)", dir + 1);
            }

            char media_type[100];
            if (jstr(jget(layer, "mediaType"), media_type, 100) == -1)
                return -1;

            fprintf(stderr, "Pulling %s...\n", digest);
            snprintf(url2, URL_MAX, "https://%s/v2/%s/blobs/%s", url, repository, digest);

            f = urlopen(url2, 0, media_type);
            if (!f)
                return -1;

            if (!strcmp(media_type, "application/vnd.docker.image.rootfs.diff.tar.gzip"))
                f = finfl(f, INFL_AUTOCLOSE);
            if (!strcmp(media_type, "application/vnd.oci.image.layer.v1.tar+gzip"))
                f = finfl(f, INFL_AUTOCLOSE);

            struct tarfile file;
            FILE *data;
            int dir_fd = openat(layer_fd, dir + 1, O_DIRECTORY);
            while ((data = untar(f, &file))) {
                fprintf(stderr, "%s...\n", file.path);
                if (!strncmp(basename(file.path), ".wh.", 4)) {
                    if (!strcmp(basename(file.path), ".wh..wh..opq"))
                        err("Opaque whiteouts are not implemented");

                    // Make the path that should be removed
                    char path[PATH_MAX];
                    strcpy(path, file.path);
                    strcpy(strrchr(path, '/') + 1, strrchr(path, '/') + 5);

                    if (mknodat(dir_fd, path, 0777, makedev(0, 0)) == -1)
                        err("mknod(%s, 0777, (0, 0))", path);
                } else
                    tarwrite(file, data, dir_fd);
                fclose(data);
            }
            fclose(f);
            close(dir_fd);
        }

        quick_exit(0);
    }
    makeugmap(pid);
    close(pipefd[0]);
    close(pipefd[1]);

    int wstatus;
    if (wait(&wstatus) == -1)
        err("wait");
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus))
        errx("Child crashed (exit status %d).", WEXITSTATUS(wstatus));

    // When done, write the configuration, but only if this is a named container
    digest = jget(jget(json, "config"), "digest");
    if (!digest)
        warnx("Could not locate configuration.");
    else {
        char digest[100];
        if (jstr(jget(jget(json, "config"), "digest"), digest, 100) == -1)
            return -1;

        char config[65536] = { 0 };
        snprintf(url2, URL_MAX, "https://%s/v2/%s/blobs/%s", url, repository, digest);
        f = urlopen(url2, 0,
                    "application/vnd.docker.container.image.v1+json, application/vnd.oci.image.config.v1+json");
        if (!f)
            err("Could not download configuration");
        n = fread(config, 1, 65536, f);
        if (!feof(f))
            errx("Buffer too small.");
        fclose(f);

        const char *config_name = name;
        if (!config_name) {
            config_name = strrchr(repository, '/');
            if (!config_name)
                config_name = repository;
            else
                config_name = config_name + 1;
        }

        int fd = openat(layer_fd, config_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd == -1)
            err("open(%s)", config_name);
        FILE *f = fdopen(fd, "w");
        fprintf(f, "[pull]\n--url=%s\n\n", full_url);

        fprintf(f, "[start]\n");

        for (int i = 0; (layer = jindex(layers, i)); i++) {
            char digest[1000];
            if (jstr(jget(layer, "digest"), digest, 1000) == -1)
                errx("Could not parse layers %s", layer);

            fprintf(f, "--overlay=%s\n", strrchr(digest, ':') + 1);
        }

        const char *envir;
        for (int i = 0; (envir = jindex(jget(jget(config, "config"), "Env"), i)); i++) {
            char buf[1000];
            if (jstr(envir, buf, 1000) == -1)
                errx("Could not parse environmental variables");

            fprintf(f, "--env=%s\n", buf);
        }

        char working_dir[PATH_MAX];
        if (jstr(jget(jget(config, "config"), "WorkingDir"), working_dir, PATH_MAX) != -1) {
            fprintf(f, "--directory=%s\n", working_dir);
        }

        const char *entry_point;
        for (int i = 0; (entry_point = jindex(jget(jget(config, "config"), "Entrypoint"), i)); i++) {
            char buf[1000];
            if (jstr(entry_point, buf, 1000) == -1)
                errx("Could not parse entry point");

            fprintf(f, "%s\n", buf);
        }

        const char *cmd;
        for (int i = 0; (cmd = jindex(jget(jget(config, "config"), "Cmd"), i)); i++) {
            char buf[1000];
            if (jstr(cmd, buf, 1000) == -1)
                errx("Could not parse command line");

            fprintf(f, "%s\n", buf);
        }

        fclose(f);

        printf("Pull was successful. Now use the following to start this container:\n");
        printf("  poddos --name=%s start\n", config_name);
    }

    return 0;
}
