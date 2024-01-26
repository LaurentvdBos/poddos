#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <poll.h>
#include <pty.h>
#include <pwd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
#include <termios.h>
#include <utmp.h>

#include "layer.h"
#include "poddos.h"
#include "net.h"
#include "dhcp.h"

int namefd = -1;

void makeugmap(pid_t pid)
{
    uid_t uid = geteuid();
    gid_t gid = getegid();
    struct passwd *pwd = getpwuid(uid);
    FILE *f;

    char user[33] = { 0 };
    int subid, subidcount;

    int retuid = -1;
    f = fopen("/etc/subuid", "r");
    while (fscanf(f, " %32[^:]:%d:%d", user, &subid, &subidcount) == 3) {
        if (!strcmp(user, pwd->pw_name) || atoi(user) == uid) {
            char cmd[1024];
            snprintf(cmd, 1024, "newuidmap %d 0 %d 1 1 %d %d", pid, uid, subid, subidcount);
            retuid = system(cmd);
            if (retuid == -1) err(1, "system(%s)", cmd);
        }
    }
    fclose(f);

    int retgid = -1;
    f = fopen("/etc/subgid", "r");
    while (fscanf(f, " %32[^:]:%d:%d", user, &subid, &subidcount) == 3) {
        if (!strcmp(user, pwd->pw_name) || atoi(user) == uid) {
            char cmd[1024];
            snprintf(cmd, 1024, "newgidmap %d 0 %d 1 1 %d %d", pid, gid, subid, subidcount);
            retgid = system(cmd);
            if (retgid == -1) err(1, "system(%s)", cmd);
        }
    }
    fclose(f);

    if (retuid != 0) {
        char buf[4096];
        snprintf(buf, 4096, "/proc/%d/uid_map", pid);
        int fd = open(buf, O_WRONLY);
        if (fd == -1) err(1, "open(%s)", buf);

        int n = snprintf(buf, 4096, "%8u %8u %8lu\n", 0, uid, (uid != 0 ? 1 : 4294967295));
        if (write(fd, buf, n) == -1) err(1, "write(uid_map)");

        close(fd);
    }

    if (retgid != 0) {
        char buf[4096];

        if (uid != 0) {
            snprintf(buf, 4096, "/proc/%d/setgroups", pid);
            int fd = open(buf, O_WRONLY);
            if (fd == -1) err(1, "open(%s)", buf);
            if (write(fd, "deny", strlen("deny")) == -1) err(1, "write(setgroups)");
            close(fd);
        }

        snprintf(buf, 4096, "/proc/%d/gid_map", pid);
        int fd = open(buf, O_WRONLY);
        if (fd == -1) err(1, "open(%s)", buf);

        int n = snprintf(buf, 4096, "%8u %8u %8lu\n", 0, gid, (uid != 0 ? 1 : 4294967295));
        if (write(fd, buf, n) == -1) err(1, "write(gid_map)");

        close(fd);
    }
}

void forktochild()
{
    struct termios termp;
    int termfd = -1;
    pid_t pid;
    if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
        struct winsize ws;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == -1) err(1, "ioctl(TIOCGWINSZ)");
        tcgetattr(STDIN_FILENO, &termp);
        pid = forkpty(&termfd, NULL, &termp, &ws);
    }
    else {
        pid = fork();
    }

    if (pid == -1) err(1, "fork");
    if (pid > 0) {
        if (namefd > 0) {
            int fdpid = openat(namefd, name, O_WRONLY | O_CREAT, 0644);
            if (fdpid == -1) err(1, "open(%s)", name);
            FILE *f = fdopen(fdpid, "w");
            fprintf(f, "%d\n", pid);
            fclose(f);
        }

        if (termfd > 0) {
            struct termios termp_raw = { 0 };
            cfmakeraw(&termp_raw);
            tcsetattr(STDIN_FILENO, TCSADRAIN, &termp_raw);

            int flags;
            if ((flags = fcntl(termfd, F_GETFL)) > -1) fcntl(termfd, F_SETFL, flags | O_NONBLOCK);
            if ((flags = fcntl(STDIN_FILENO, F_GETFL)) > -1) fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
            if ((flags = fcntl(STDOUT_FILENO, F_GETFL)) > -1) fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK);
        }

        // Create a mask containing all signals ...
        sigset_t mask;
        sigemptyset(&mask);
        sigfillset(&mask);

        // ... block all signals ...
        if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) err(1, "sigprocmask");

        // ... and create a file pointer that becomes readable for all signals
        int sfd = signalfd(-1, &mask, SFD_CLOEXEC);
        if (sfd == -1) err(1, "signalfd");

        nfds_t nfds = 5;
        struct pollfd pfds[] = {
            { .fd = termfd, .events = 0 },
            { .fd = STDIN_FILENO, .events = 0 },
            { .fd = STDOUT_FILENO, .events = 0 },
            { .fd = -1, .events = POLLIN },
            { .fd = sfd, .events = POLLIN },
        };

        char bufin[1024], bufout[1024];
        int nin = 0, nout = 0;
        for (;;) {
            if (termfd > -1) {
                pfds[0].events = (nin ? POLLOUT : 0) | (!nout ? POLLIN : 0);
                pfds[1].events = (!nin ? POLLIN : 0);
                pfds[2].events = (nout ? POLLOUT : 0);
            }

            if (poll(pfds, nfds, -1) == -1) {
                if (errno == EINTR) continue;
                err(1, "poll");
            }
            if (pfds[1].revents & POLLIN) {
                if ((nin = read(STDIN_FILENO, bufin, 1024)) == -1) err(1, "read(stdin)");
            }
            if (pfds[0].events & POLLOUT || nin > 0) {
                ssize_t n;
                if ((n = write(termfd, bufin, nin)) == -1 && errno != EWOULDBLOCK) err(1, "write(fd)");
                memmove(bufin, bufin+n, nin-n);
                nin -= n;
            }
            if (pfds[0].revents & POLLIN) {
                if ((nout = read(termfd, bufout, 1024)) == -1) err(1, "read(fd)");
            }
            if (pfds[2].revents & POLLOUT || nout > 0) {
                ssize_t n;
                if ((n = write(STDOUT_FILENO, bufout, nout)) == -1 && errno != EWOULDBLOCK) err(1, "write(stdout)");
                memmove(bufout, bufout+n, nout-n);
                nout -= n;
            }
            if (pfds[0].revents & POLLHUP) {
                break;
            }
            if (pfds[3].revents & POLLIN) {
                pfds[3].fd = dhcpstep(pfds[3].fd);
            }
            if (pfds[4].revents & POLLIN) {
                struct signalfd_siginfo fdsi;
                int n = read(sfd, &fdsi, sizeof(fdsi));
                if (n != sizeof(fdsi)) err(1, "read(sfd)");

                if (fdsi.ssi_signo == SIGWINCH && termfd > 0) {
                    // SIGWINCH should not be blindly forwarded, but handled via an ioctl
                    struct winsize ws;
                    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == -1) err(1, "ioctl(TIOCGWINSZ)");
                    if (ioctl(termfd, TIOCSWINSZ, &ws) == -1) err(1, "ioctl(TIOCSWINSZ)");
                }
                else if (fdsi.ssi_signo == SIGALRM) {
                    // SIGALRM indicates a DHCP renewal (or a timeout of a previous renewal...)
                    if (pfds[3].fd > 0) close(pfds[3].fd);
                    pfds[3].fd = dhcpstart();
                    
                    // Set a timer to retry DHCP after 30 seconds
                    alarm(30);
                }
                else if (fdsi.ssi_signo == SIGCHLD) {
                    // SIGCHLD indicates that the child exited
                    break;
                }
                else {
                    // Send the signal to the child
                    kill(pid, fdsi.ssi_signo);
                }
            }
        }

        close(sfd);

        int wstatus;
        if (wait(&wstatus) == -1) err(1, "wait");

        if (termfd > 0) tcsetattr(STDIN_FILENO, TCSADRAIN, &termp);
        if (namefd > 0) unlinkat(namefd, name, 0);

        if (WIFEXITED(wstatus)) exit(WEXITSTATUS(wstatus));
        else {
            // Prepare a mask with the exit signal
            sigset_t mask;
            sigemptyset(&mask);
            sigaddset(&mask, WTERMSIG(wstatus));

            // Ensure this process also exits when this signal is delivered
            signal(WTERMSIG(wstatus), SIG_DFL);

            // Unblock and raise the signal
            if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) err(1, "sigprocmask");
            raise(WTERMSIG(wstatus));
        }
    }
}

void lstart(unsigned flags, char **argv, char **envp)
{
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) err(1, "pipe");

    pid_t pid = fork();
    if (pid == 0) {
        // Child: close write end
        close(pipefd[1]);

        // The read call unblocks when parent has unshared or crashed
        char buf;
        if (read(pipefd[0], &buf, 1) > -1) {
            makeugmap(getppid());
            if (flags & LAYER_NET) net(getppid());
        }

        quick_exit(0);
    }

    if (name) {
        char namedir[PATH_MAX];
        char *tmpdir = getenv("XDG_RUNTIME_DIR") ? getenv("XDG_RUNTIME_DIR") : "/tmp";
        snprintf(namedir, PATH_MAX-1, "%s/poddos", tmpdir);
        if (mkdir(namedir, 0777) == -1 && errno != EEXIST) err(1, "mkdir(%s)", namedir);
        namefd = open(namedir, O_DIRECTORY | O_CLOEXEC);
        if (namefd == -1) err(1, "open(%s)", namedir);
    }

    unsigned uflags = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID;
    if (flags & LAYER_NET) uflags |= CLONE_NEWNET | CLONE_NEWUTS;
    unshare(uflags);

    close(pipefd[0]);
    close(pipefd[1]);

    int wstatus;
    if (wait(&wstatus) == -1) err(1, "wait");
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) errx(WEXITSTATUS(wstatus), "Child crashed");

    // Ensure mount events remain in this namespace. This should already happen
    // by default actually.
    if (mount("ignored", "/", "ignored", MS_PRIVATE | MS_REC, NULL) == -1) err(1, "mount(MS_PRIVATE | MS_REC)");

    // In ephemeral mode, add another layer to the overlays, but make that a tmpfs
    const char *userxattr = "userxattr";
    if (flags & LAYER_EPHEMERAL) {
        char ephemeral[PATH_MAX];
        snprintf(ephemeral, PATH_MAX, "%s/ephemeral", layer_path);
        if (mount("none", ephemeral, "tmpfs", 0, "mode=777") == -1) err(1, "mount(%s)", ephemeral);
        if (upperdir[0] && dircnt(upperdir) > 2) {
			if (!lowerdir[0]) strcpy(lowerdir, upperdir);
			else {
				char buf[4096];
				snprintf(buf, 4096, "%s:%s", upperdir, lowerdir);
				strcpy(lowerdir, buf);
			}
        }
        snprintf(upperdir, PATH_MAX, "%s/upper", ephemeral);
        if (mkdir(upperdir, 0777) == -1) err(1, "mkdir(%s)", upperdir);

        // If the top layer is a tmpfs, turn off userxattr, since it will fail
        // syscalls with -EXDEV. TODO: The following is Ubuntu-specific.
        userxattr = "nouserxattr";
    }

    // Build up the overlayfs; unless there is no lowerdir, since then there is no real overlay
    char mergeddir[PATH_MAX];
    if (lowerdir[0]) {
        char workdir[PATH_MAX];
        snprintf(workdir, PATH_MAX, "%s:work", upperdir);
        snprintf(mergeddir, PATH_MAX, "%s:merged", upperdir);
        if (mkdir(workdir, 0777) == -1 && errno != EEXIST) err(1, "mkdir(%s)", workdir);
        if (mkdir(mergeddir, 0777) == -1 && errno != EEXIST) err(1, "mkdir(%s)", mergeddir);

        char data[4096];
        snprintf(data, 4096, "lowerdir=%s,upperdir=%s,workdir=%s,xino=off,%s", lowerdir, upperdir, workdir, userxattr);

        if (mount("none", mergeddir, "overlay", 0, data) == -1) err(1, "mount(%s, %s)", mergeddir, data);
    }
    else {
        snprintf(mergeddir, PATH_MAX, "%s:merged", upperdir);
        if (mkdirat(layer_fd, mergeddir, 0777) == -1 && errno != EEXIST) err(1, "mkdir(%s)", mergeddir);
        if (mount(upperdir, mergeddir, "ignored", MS_BIND, NULL) == -1) err(1, "mount(%s, %s, MS_BIND)", upperdir, mergeddir);
    }

    // Add bind mounts to configure networking, in case we are not in a separate
    // namespace; we do this before the pivot root such that symlinks resolve
    // correctly.
    if (!(flags & LAYER_NET)) {
        const char *files[] = { "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", NULL };
        for (int i = 0; files[i]; i++) {
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "%s%s", mergeddir, files[i]);

            // Ensure the path exists
            int fd = open(path, O_WRONLY | O_CREAT, 0666);
            if (fd == -1) err(1, "open(%s)", path);
            close(fd);

            // Make the bind mount
            if (mount(files[i], path, "ignored", MS_BIND, NULL) == -1) err(1, "mount(%s)", path);
        }
    }
    else {
        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "%s/etc/hostname", mergeddir);

        char host[HOST_NAME_MAX + 1] = { 0 };
        if (name) {
            strncpy(host, name, HOST_NAME_MAX);
            if (sethostname(host, strlen(host)) == -1) err(1, "sethostname(%s)", host);
        }
        else gethostname(host, HOST_NAME_MAX + 1);

        FILE *f = fopen(path, "w");
        if (!f) err(1, "fopen(%s)", path);
        fprintf(f, "%s\n", host);
        fclose(f);

        bringloup();
    }

    // Pivot root, or in other words, change the root directory to the merged directory
    char oldroot[PATH_MAX];
    snprintf(oldroot, PATH_MAX, "%s/old_root", mergeddir);
    if (mkdir(oldroot, 0777) == -1) err(1, "mkdir(%s)", oldroot);
    if (syscall(SYS_pivot_root, mergeddir, oldroot) == -1) err(1, "pivot_root(%s, %s)", mergeddir, oldroot);
    if (chdir("/") == -1) err(1, "chdir(/)");

    // Populate /dev with the usual things. The mode=755 ensure there is no
    // 'sticky' bit, which blocks writing to a device with -EACCES
    if (mount("none", "/dev", "tmpfs", MS_NOSUID, "mode=755") == -1) err(1, "mount(/dev)");
    if (symlink("/proc/self/fd", "/dev/fd") == -1) err(1, "symlink(/proc/self/fd, /dev/fd)");
    if (symlink("/proc/self/fd/0", "/dev/stdin") == -1) err(1, "symlink(/proc/self/fd/0, /dev/stdin)");
    if (symlink("/proc/self/fd/1", "/dev/stdout") == -1) err(1, "symlink(/proc/self/fd/1, /dev/stdout)");
    if (symlink("/proc/self/fd/2", "/dev/stderr") == -1) err(1, "symlink(/proc/self/fd/2, /dev/stderr)");
    if (mkdir("/dev/shm", 0777) == -1) err(1, "mkdir(/dev/shm)");
    if (mount("none", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777") == -1) err(1, "mount(/dev/shm)");

    // Make bind mounts for /dev/null (mknod is blocked in namespaces)
    const char *devs[] = { "null", "zero", "full", "random", "urandom", "tty", NULL };
    for (int i = 0; devs[i]; i++) {
        char path[PATH_MAX], old_path[PATH_MAX];
        snprintf(path, PATH_MAX, "/dev/%s", devs[i]);
        snprintf(old_path, PATH_MAX, "/old_root/dev/%s", devs[i]);

        // Ensure the file exists
        int fd = open(path, O_WRONLY | O_CREAT, 0666);
        if (fd == -1) err(1, "open(%s)", path);
        close(fd);

        // Make the bind mount
        if (mount(old_path, path, "ignored", MS_BIND, NULL) == -1) err(1, "mount(%s)", path);
    }
    // Mount mqueue
    if (mkdir("/dev/mqueue", 0777) == -1) err(1, "mkdir(/dev/mqueue)");
    if (mount("none", "/dev/mqueue", "mqueue", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == -1) err(1, "mount(/dev/mqueue)");

    // Mount the pty, which allows to create new pseudo ttys
    if (mkdir("/dev/pts", 0777) == -1) err(1, "mkdir(/dev/pts)");
    if (mount("none", "/dev/pts", "devpts", 0, "newinstance,mode=620,ptmxmode=666,gid=5") == -1) err(1, "mount(/dev/pts)");
    if (symlink("pts/ptmx", "/dev/ptmx") == -1) err(1, "symlink(pts/ptmx, /dev/ptmx)");

    // Intialize DHCP before forking
    if (flags & LAYER_NET) {
        int sock = dhcpstart();
        while (sock != -1) sock = dhcpstep(sock);
    }

    // Fork to get pid 1, this will also get us a pty if needed
    forktochild();

    // Turn off the alarm set by DHCP
    alarm(0);

    // Mount /proc (now that we are pid 1)
    if (mount("none", "/proc", "proc", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL) == -1) err(1, "mount(/proc)");

    // Mount /sys (could fail if we do not have a network namespace)
    if (mount("none", "/sys", "sysfs", 0, NULL) == -1) {
        if (mount("/old_root/sys", "/sys", "ignored", MS_BIND | MS_REC, NULL) == -1) err(1, "mount(/old_root/sys, /sys)");
    }
    else {
        if (mount("none", "/sys/fs/cgroup", "cgroup2", 0, NULL) == -1) err(1, "mount(/sys/fs/cgroup)");
    }

    // Make the additional bind mounts that the user requested
    for (int i = 0; i < nbind; i++) {
        char path_from[PATH_MAX], path_to[PATH_MAX];
        snprintf(path_from, PATH_MAX, "/old_root%s", bind_from[i]);
        snprintf(path_to, PATH_MAX, "%s", bind_to[i]);

        // See whether path_from is a directory or not
        int fd = open(path_from, O_DIRECTORY | O_PATH | O_CLOEXEC);
        if (fd == -1 && errno == ENOTDIR) {
            // Create the file, ignore any errors
            fd = open(path_to, O_WRONLY | O_CREAT, 0777);
            if (fd > 0) close(fd);
            else warn("open(%s)", path_to);
        }
        else if (fd > 0) {
            // Create the directory, ignore any errors
            if (mkdir(path_to, 0777) == -1) warn("mkdir(%s)", path_to);
            close(fd);
        }
        else err(1, "open(%s)", path_from);

        if (mount(path_from, path_to, "ignored", MS_BIND | MS_REC, NULL) == -1) err(1, "mount(%s)", path_to);
    }

    if (umount2("/old_root", MNT_DETACH) == -1) err(1, "umount2(/old_root, MNT_DETACH)");
    if (rmdir("/old_root") == -1) err(1, "rmdir(/old_root)");

    // Change directory specified by the user
    if (directory && chdir(directory) == -1) err(1, "chdir(%s)", directory);

    execve(argv[0], argv, envp);
    err(1, "execv");
}

void lexec(unsigned flags, char **argv, char **envp)
{
    char namefile[PATH_MAX];
    char *tmpdir = getenv("XDG_RUNTIME_DIR") ? getenv("XDG_RUNTIME_DIR") : "/tmp";
    snprintf(namefile, PATH_MAX-1, "%s/poddos/%s", tmpdir, name);

    pid_t pid;
    FILE *f = fopen(namefile, "r");
    if (!f) err(1, "fopen(%s)", namefile);
    if (!fscanf(f, "%d", &pid)) errx(1, "Could not read pid from %s", namefile);
    fclose(f);

    // Make a pidfd, pidfd_open already makes it O_CLOEXEC
    int pidfd = syscall(SYS_pidfd_open, pid, 0);
    if (pidfd == -1) err(1, "pidfd_open(%d)", pid);

    // Join all the namespaces that the container possibly has
    unsigned uflags = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUTS;
    setns(pidfd, uflags);

    close(pidfd);

    forktochild();

    execve(argv[0], argv, envp);
    err(1, "execv");
}
