#define _GNU_SOURCE
#include <argp.h>
#include <dirent.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "pull.h"
#include "layer.h"
#include "prune.h"
#include "poddos.h"

static struct argp_option global_options[] = {
    {"layer", 'l', "PATH", 0, "Path where layers are stored. "
                              "Defaults to the value of the environmental variable $LAYERPATH, or $XDG_DATA_HOME/poddos if unset (the latter usually resolves to ~/.local/share/poddos)."},
    {"name", 'n', "NAME", 0, "Assign a name to the container. "
                             "This name will be the hostname of the container (if a UTS namespace is created), can be used to store configuration, and is used to create a pidfile."},
    {0}
};

static struct argp_option pull_options[] = {
    {"url", 'u', "URL", 0, "Pull a series of layers from this url"},
    {0}
};

static struct argp_option prune_options[] = {
    {"all", 'a', NULL, 0, "Prune all layers found in the layer path that are not used by any configuration anymore. "
                          "Asks before doing any removal."},
    {"force", 'f', NULL, 0, "If used in combination with --all, do not confirm before removing a layer."},
    {0}
};

static struct argp_option start_options[] = {
    {"overlay", 'o', "PATH", 0, "Overlay paths, to be specified multiple times. "
                                "Each path is overlayed on top of the previous one. "
                                "Modifications to the container are stored in the last path (but see --ephemeral)."},
    {"env", 'e', "FOO=BAR", 0, "Environment variables added when executing, to be specified multiple times if needed."},
    {"ephemeral", 'E', NULL, 0, "All modifications made in the mount namespace are thrown away. "
                                "This is done by making the top-level directory a tmpfs, and requires a kernel that supports user extended attributes on a tmpfs for full support (upstream that is since version 6.6)."},
    {"no-ephemeral", 1004, NULL, 0, "Turn off ephemeral (e.g., in a .2 file)."},
    {"net", 1000, "INTERFACE", 0, "Put container in net namespace and initialize a macvlan (usually called macvlan0) in it. "
                                  "The macvlan is put in bridge mode, such that all containers can connect to eachother directly. "
                                  "An IP (only v4) is obtained via DHCP, so there is a noticable lag when starting the container. "
                                  "Keep in mind that the host cannot directly connect to the containers, which is a known restriction of macvlans. "
                                  "This usually only works with wired links and requires CAP_NET_ADMIN."},
    {"mac", 1001, "MAC", 0, "If --net is provided, the mac address of the macvlan. "
                            "If not provided, the kernel picks one randomly."},
    {"dns", 1003, "DNS", 0, "If --net is provided, the IP address of the DNS server to use. "
                            "If not provided, it is picked from DHCP."},
    {"bind", 1002, "FROM:TO", 0, "Mount the path <FROM> in the container to the path <TO>. "
                                 "<TO> can be omitted, and then it will appear in the same place as <FROM>. "
                                 "All provided paths should be absolute paths."},
    {"directory", 'C', "PATH", 0, "Change to the specified directory before executing the specified command. "
                                  "The specified directory should be an existing directory in the folder structure of the container."},
    {0}
};

static struct argp_option exec_options[] = {
    {"env", 'e', "FOO=BAR", 0, "Environment variables added when executing the command. Specify multiple times to add multiple environmental variables."},
    {0}};

char layer_path[PATH_MAX] = { 0 };

int layer_fd = -1;
const char *url = NULL;

bool ephemeral = false;

bool prune_all = false;
bool force = false;

char *ifname = NULL;
char mac[6] = { 0 };

char *dnsserver = NULL;

char *name = NULL;

char lowerdir[4096] = { 0 };
char upperdir[4096] = { 0 };

char **pargv = NULL;

int nenvp = 0;
char **penvp = NULL;

int nbind = 0;
char **bind_from = NULL, **bind_to = NULL;

char *directory = NULL;

// Count the number of files in the directory <name>. Includes "special files" .. and .
int dircnt(const char *name)
{
    int ret = 0;
    DIR *dirp = opendir(name);
    if (!dirp)
        err("opendir(%s)", name);
    while (readdir(dirp))
        ret++;
    closedir(dirp);

    return ret;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'a':
        prune_all = true;
        break;
    case 'f':
        force = true;
        break;
    case 'o':
        if (upperdir[0] && dircnt(upperdir) > 2) {
            if (!lowerdir[0])
                strcpy(lowerdir, upperdir);
            else {
                char buf[4096];
                int ret = snprintf(buf, 4096, "%s:%s", upperdir, lowerdir);
                if (ret > 4096)
                    errx("Too many layers");
                strcpy(lowerdir, buf);
            }
        }
        if (arg[0] != '/') {
            int ret = snprintf(upperdir, 4096, "%s/%s", layer_path, arg);
            if (ret > 4096)
                errx("Too many layers");
        } else {
            int ret = snprintf(upperdir, 4096, "%s", arg);
            if (ret > 4096)
                errx("Path too long: %s", arg);
        }
        break;
    case 'e':
        penvp = realloc(penvp, (++nenvp) * sizeof(char *));
        if (!penvp)
            err("realloc(penvp)");
        penvp[nenvp - 1] = arg;
        break;
    case 'E':
        ephemeral = true;
        break;
    case 1004: // --no-ephemeral
        ephemeral = false;
        break;
    case 'l':
        int ret = snprintf(layer_path, PATH_MAX, "%s", arg);
        if (ret > PATH_MAX)
            errx("Path too long: %s", arg);
        break;
    case 'n':
        name = arg;
        break;
    case 'u':
        url = arg;
        break;
    case 'C':
        directory = arg;
        break;
    case 1000: // --net
        ifname = arg;
        break;
    case 1001: // --mac
        ret = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                         &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        if (ret != 6)
            errx("Invalid mac address provided.");
        break;
    case 1002: // --bind
        char *from = arg;
        char *to = strchr(from, ':');
        if (to) {
            *to = 0;
            to++;
        } else
            to = from;

        if (from[0] != '/' || to[0] != '/')
            errx("Bind mounts must be absolute paths.");

        nbind++;
        bind_to = realloc(bind_to, sizeof(char *) * nbind);
        if (!bind_to)
            err("realloc");
        bind_from = realloc(bind_from, sizeof(char *) * nbind);
        if (!bind_from)
            err("realloc");

        bind_to[nbind - 1] = to;
        bind_from[nbind - 1] = realpath(from, NULL);
        if (!bind_from[nbind - 1])
            err("realpath(%s)", from);

        break;
    case 1003:
        dnsserver = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int loadconfig(char ***argv, char *action, char *override)
{
    int argc = 1;
    *argv = malloc(sizeof(char **));
    if (!*argv)
        err("malloc");
    (*argv)[0] = malloc(strlen(action) + strlen("poddos") + 2);
    if (!(*argv)[0])
        err("malloc");
    sprintf((*argv)[0], "%s-%s", "poddos", action);

    char file[PATH_MAX];
    snprintf(file, PATH_MAX, "%s%s", name, override);
    int fd = openat(layer_fd, file, O_RDONLY);
    if (fd == -1)
        return argc;
    FILE *f = fdopen(fd, "r");

    bool parsing = false;
    char buf[4096];
    while (!feof(f) && !ferror(f)) {
        if (!fgets(buf, 4096, f))
            break;

        // Ignore empty lines and comments
        if (buf[0] == '\n' || buf[0] == '#')
            continue;

        // Strip off the final \n
        buf[strlen(buf) - 1] = 0;

        char header[21] = { 0 };
        if (sscanf(buf, "[%20[abcdefghijklmnopqrstuvwxyz]]", header))
            parsing = !strcmp(header, action);
        else if (parsing) {
            *argv = realloc(*argv, (++argc) * sizeof(char **));
            if (!*argv)
                err("realloc");
            (*argv)[argc - 1] = malloc(strlen(buf) + 1);
            if (!(*argv)[argc - 1])
                err("malloc");
            strcpy((*argv)[argc - 1], buf);
        }
    }

    fclose(f);

    // Add the final NULL
    *argv = realloc(*argv, (argc + 1) * sizeof(char **));
    if (!argv)
        err("realloc");
    (*argv)[argc] = NULL;

    return argc;
}

int main(int argc, char **argv)
{
    struct argp argp = {
        .options = global_options,
        .parser = parse_opt,
        .args_doc = "pull|start|exec|prune [OPTIONS...]"
    };
    int arg_index = 0;
    argp_parse(&argp, argc, argv, ARGP_NO_ARGS | ARGP_IN_ORDER, &arg_index, NULL);

    if (arg_index >= argc) {
        fprintf(stderr, "Nothing to do.\n");
        return 0;
    }
    // Build the default layer path if the user did not provide any
    if (!layer_path[0]) {
        if (getenv("LAYERPATH"))
            snprintf(layer_path, PATH_MAX, "%s", getenv("LAYERPATH"));
        else if (getenv("XDG_DATA_HOME"))
            snprintf(layer_path, PATH_MAX, "%s/poddos", getenv("XDG_DATA_HOME"));
        else if (getenv("HOME"))
            snprintf(layer_path, PATH_MAX, "%s/.local/share/poddos", getenv("HOME"));
        else
            snprintf(layer_path, PATH_MAX, "/usr/local/share/poddos");
    }
    // Ensure the layer path exists
    if (mkdir(layer_path, 0777) == -1 && errno != EEXIST)
        err("mkdir(%s)", layer_path);

    layer_fd = open(layer_path, O_DIRECTORY | O_CLOEXEC);
    if (layer_fd == -1)
        err("open(%s)", layer_path);
    if (mkdirat(layer_fd, "ephemeral", 0777) == -1 && errno != EEXIST)
        err("mkdir(ephemeral)");

    int argc_from_config = 0;
    char **argv_from_config = NULL;
    if (name)
        argc_from_config = loadconfig(&argv_from_config, argv[arg_index], "");

    int argc_from_override = 0;
    char **argv_from_override = NULL;
    if (name)
        argc_from_override = loadconfig(&argv_from_override, argv[arg_index], ".2");

    if (!strcmp(argv[arg_index], "pull")) {
        argv[arg_index] = "poddos-pull";
        struct argp argp = {
            .options = pull_options,
            .parser = parse_opt,
        };
        if (argc_from_config)
            argp_parse(&argp, argc_from_config, argv_from_config, ARGP_IN_ORDER, NULL, NULL);
        if (argc_from_override)
            argp_parse(&argp, argc_from_override, argv_from_override, ARGP_IN_ORDER, NULL, NULL);
        argp_parse(&argp, argc - arg_index, argv + arg_index, ARGP_IN_ORDER, NULL, NULL);

        pull(url);
    } else if (!strcmp(argv[arg_index], "start")) {
        argv[arg_index] = "poddos-start";
        struct argp argp = {
            .options = start_options,
            .parser = parse_opt,
            .args_doc = "[CMD...]",
            .doc = "Create a new container using a series of overlays as root and start the configured command. "
                "If the command is started from a tty, a pseudo tty is created and the command is started interactively. "
                "If this is not the case, standard input, output and error of the command are captured via a pipe and duplicated to/from standard input, output and error of poddos. "
                "Signals sent to poddos are forwareded to the command. "
                "If the command exits, poddos exits in the same way (i.e., returns the same exit code or signals with the same signal). "
                "The path of the command is resolved using the path as set in the configuration of the container. "
                "By default, no networking is set up, and the network configuration of the host is taken over. "
                "This behavior can be overriden using the --net flag."
        };
        int cmd_index = 0, cmd_index_from_config = 0, cmd_index_from_override = 0;
        if (argc_from_config)
            argp_parse(&argp, argc_from_config, argv_from_config, ARGP_IN_ORDER, &cmd_index_from_config, NULL);
        if (argc_from_override)
            argp_parse(&argp, argc_from_override, argv_from_override, ARGP_IN_ORDER, &cmd_index_from_override, NULL);
        argp_parse(&argp, argc - arg_index, argv + arg_index, ARGP_IN_ORDER, &cmd_index, NULL);

        if (!upperdir[0])
            errx("At least one overlay directory should be provided");
        if (arg_index + cmd_index >= argc && cmd_index_from_config >= argc_from_config
            && cmd_index_from_override >= argc_from_override)
            errx("No command to exeute");

        penvp = realloc(penvp, (++nenvp) * sizeof(char *));
        if (!penvp)
            err("realloc(penvp)");
        penvp[nenvp - 1] = NULL;

        if (arg_index + cmd_index < argc)
            pargv = argv + arg_index + cmd_index;
        else if (cmd_index_from_override < argc_from_override)
            pargv = argv_from_override + cmd_index_from_override;
        else
            pargv = argv_from_config + cmd_index_from_config;

        unsigned flags = 0;
        if (ephemeral)
            flags |= LAYER_EPHEMERAL;
        if (ifname)
            flags |= LAYER_NET;

        lstart(flags, pargv, penvp);
    } else if (!strcmp(argv[arg_index], "exec")) {
        argv[arg_index] = "poddos-exec";
        struct argp argp = {
            .options = exec_options,
            .parser = parse_opt,
            .args_doc = "CMD...",
            .doc = "Execute command in running conatiner. "
                "The path of the command is resolved using the path as set in the configuration of the container, and can be overriden using --env."
                "Signals sent to poddos are forwareded to the command. "
                "If the command exits, poddos exits in the same way (i.e., returns the same exit code or signals with the same signal)."
        };
        int cmd_index = 0;
        if (argc_from_config)
            argp_parse(&argp, argc_from_config, argv_from_config, ARGP_IN_ORDER, NULL, NULL);
        if (argc_from_override)
            argp_parse(&argp, argc_from_override, argv_from_override, ARGP_IN_ORDER, NULL, NULL);
        argp_parse(&argp, argc - arg_index, argv + arg_index, ARGP_IN_ORDER, &cmd_index, NULL);

        if (!name)
            errx("Can only exec in named containers");
        if (arg_index + cmd_index >= argc)
            errx("No command to exeute");

        penvp = realloc(penvp, (++nenvp) * sizeof(char *));
        if (!penvp)
            err("realloc(penvp)");
        penvp[nenvp - 1] = NULL;

        pargv = argv + arg_index + cmd_index;

        lexec(0, pargv, penvp);
    } else if (!strcmp(argv[arg_index], "prune")) {
        argv[arg_index] = "poddos-prune";
        struct argp argp = {
            .options = prune_options,
            .parser = parse_opt,
            .args_doc = "[LAYER...]",
            .doc = "Prune unused layers from disk. "
                "With the --all flag, poddos automatically scans for unused layers. "
                "One can also specify one or more layers explicitly, but then poddos does not check whether they are still in use."
        };
        int cmd_index = 0;
        argp_parse(&argp, argc - arg_index, argv + arg_index, ARGP_IN_ORDER, &cmd_index, NULL);

        char **layers = argv + arg_index + cmd_index;

        for (int i = 0; layers[i]; i++)
            prune(layers[i]);

        if (prune_all)
            pruneall(force);
    } else
        errx("Unrecognized action '%s'.", argv[arg_index]);

    close(layer_fd);
    return 0;
}
