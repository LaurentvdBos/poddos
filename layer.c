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
#include <sys/timerfd.h>
#include <termios.h>
#include <utmp.h>

#include "layer.h"
#include "poddos.h"
#include "net.h"
#include "dhcp.h"

int namefd = -1, timefd = -1;

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
    int infd = -1, outfd = -1, errfd = -1;
    const int istty = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    pid_t pid;
    if (istty) {
        struct winsize ws;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == -1) err(1, "ioctl(TIOCGWINSZ)");
        tcgetattr(STDIN_FILENO, &termp);
        pid = forkpty(&infd, NULL, &termp, &ws);
        outfd = infd;
    }
    else {
        int infds[2], outfds[2], errfds[2];
        if (pipe2(infds, O_CLOEXEC) == -1 || pipe2(outfds, O_CLOEXEC) == -1 || pipe2(errfds, O_CLOEXEC) == -1) err(1, "pipe");
        infd = infds[1];
        outfd = outfds[0];
        errfd = errfds[0];
        
        pid = fork();

        if (pid > 0) {
            close(infds[0]);
            close(outfds[1]);
            close(errfds[1]);
        }
        if (pid == 0) {
            close(infds[1]);
            close(outfds[0]);
            close(errfds[0]);
            dup2(infds[0], STDIN_FILENO);
            dup2(outfds[1], STDOUT_FILENO);
            dup2(errfds[1], STDERR_FILENO);
        }
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

        if (istty) {
            struct termios termp_raw = { 0 };
            cfmakeraw(&termp_raw);
            tcsetattr(STDIN_FILENO, TCSADRAIN, &termp_raw);
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

        const nfds_t nfds = 9;
        struct pollfd pfds[] = {
            { .fd = infd, .events = 0 },
            { .fd = outfd, .events = 0 },
            { .fd = errfd, .events = 0 },
            { .fd = STDIN_FILENO, .events = 0 },
            { .fd = STDOUT_FILENO, .events = 0 },
            { .fd = STDERR_FILENO, .events = 0 },
            { .fd = -1, .events = POLLIN },
            { .fd = sfd, .events = POLLIN },
            { .fd = timefd, .events = POLLIN },
        };

        char bufin[1024], bufout[1024], buferr[1024];
        int nin = 0, nout = 0, nerr = 0;
        int goout = 0;
        for (;;) {
            pfds[0].events = nin ? POLLOUT : 0;
            pfds[1].events = !nout ? POLLIN : 0;
            pfds[2].events = !nerr ? POLLIN : 0;
            pfds[3].events = !nin ? POLLIN : 0;
            pfds[4].events = nout ? POLLOUT : 0;
            pfds[5].events = nerr ? POLLOUT : 0;

            if (poll(pfds, nfds, -1) == -1) {
                if (errno == EINTR) continue;
                err(1, "poll");
            }
            if (pfds[0].revents & POLLOUT) {
                // stdin of the process is writable, and we have stuff to write
                ssize_t n;
                if ((n = write(infd, bufin, nin)) == -1) err(1, "write(infd)");
                memmove(bufin, bufin+n, nin-n);
                nin -= n;
            }
            if (pfds[1].revents & POLLIN) {
                // stdout of process contains data, and we have an empty buffer
                if ((nout = read(outfd, bufout, 1024)) == -1) err(1, "read(outfd)");
            }
            if (pfds[2].revents & POLLIN) {
                // stderr of process contains data, and we have an empty buffer
                if ((nerr = read(errfd, buferr, 1024)) == -1) err(1, "read(errfd)");
            }
            if (pfds[3].revents & POLLIN) {
                // Our stdin has data
                if ((nin = read(STDIN_FILENO, bufin, 1024)) == -1) err(1, "read(stdin)");

                if (!nin) {
                    // stdin is end of file, so closed
                    close(infd);
                    pfds[0].fd = -1;
                    pfds[3].fd = -1;
                }

                // ^] is the group seperator in ASCII, hex 0x1D. If it is
                // pressed three times consecutively, we go out immediately.
                for (int i = 0; i < nin; i++) goout = (bufin[i] == 0x1D ? goout+1 : 0);
                if (goout >= 3) kill(pid, SIGKILL);
            }
            if (pfds[4].revents & POLLOUT) {
                // Our stdout is writable, and we have stuff to write
                ssize_t n;
                if ((n = write(STDOUT_FILENO, bufout, nout)) == -1) err(1, "write(stdout)");
                memmove(bufout, bufout+n, nout-n);
                nout -= n;
            }
            if (pfds[5].revents & POLLOUT) {
                // Our stderr is writable, and we have stuff to write
                ssize_t n;
                if ((n = write(STDERR_FILENO, buferr, nerr)) == -1) err(1, "write(stderr)");
                memmove(buferr, buferr+n, nerr-n);
                nerr -= n;
            }
            if (pfds[1].revents & POLLHUP) {
                // stdout of process hang up, close stdout and stop watching
                pfds[1].fd = -1;
                pfds[4].fd = -1;
                close(STDOUT_FILENO);
            }
            if (pfds[2].revents & POLLHUP) {
                // stderr of process hung up, close stderr and stop watching
                pfds[2].fd = -1;
                pfds[5].fd = -1;
                close(STDERR_FILENO);
            }
            if (pfds[6].revents & POLLIN) {
                // The socket used for DHCP got data
                pfds[6].fd = dhcpstep(macvlan, pfds[6].fd);

                if (pfds[6].fd < 0) {
                    // A negative value indicates that DHCP is done and we need to set a timeout
                    struct itimerspec val = {
                        .it_value = { .tv_sec = -pfds[6].fd, .tv_nsec = 0 },
                        .it_interval = { 0 }
                    };
                    if (timerfd_settime(timefd, 0, &val, NULL) == -1) err(1, "timerfd_settime");
                }
            }
            if (pfds[7].revents & POLLIN) {
                // We received a signal
                struct signalfd_siginfo fdsi;
                int n = read(sfd, &fdsi, sizeof(fdsi));
                if (n != sizeof(fdsi)) err(1, "read(sfd)");

                if (fdsi.ssi_signo == SIGWINCH && istty) {
                    // SIGWINCH should not be blindly forwarded, but handled via an ioctl
                    struct winsize ws;
                    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == -1) err(1, "ioctl(TIOCGWINSZ)");
                    if (ioctl(infd, TIOCSWINSZ, &ws) == -1) err(1, "ioctl(TIOCSWINSZ)");
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
            if (pfds[8].revents & POLLIN) {
                // Timer expiration indicates that we should renew the DHCP
                if (pfds[6].fd > 0) close(pfds[6].fd);
                pfds[6].fd = dhcpstart(macvlan);
                
                // Set a timer to retry DHCP after 30 seconds
                struct itimerspec val = {
                    .it_value = { .tv_sec = 30, .tv_nsec = 0 },
                    .it_interval = { 0 }
                };
                if (timerfd_settime(timefd, 0, &val, NULL) == -1) err(1, "timerfd_settime");
            }
        }

        close(sfd);
        close(timefd);

        int wstatus;
        if (wait(&wstatus) == -1) err(1, "wait");

	// Remove the macvlan, init is going to leave the namespace and
	// in some cases the kernel does not properly clean up the
	// network namespace.
	if (timefd > 0) ifremove(macvlan);

        if (istty) tcsetattr(STDIN_FILENO, TCSADRAIN, &termp);
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
            if (flags & LAYER_NET) makemacvlan(getppid());
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
    if (unshare(uflags) == -1) err(1, "unshare");

    close(pipefd[0]);
    close(pipefd[1]);

    int wstatus;
    if (wait(&wstatus) == -1) err(1, "wait");
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) errx(WEXITSTATUS(wstatus), "Child crashed");

    // Ensure mount events remain in this namespace. This should already happen
    // by default actually.
    if (mount("ignored", "/", "ignored", MS_PRIVATE | MS_REC, NULL) == -1) err(1, "mount(MS_PRIVATE | MS_REC)");

    // In ephemeral mode, add another layer to the overlays, but make that a
    // tmpfs. Ephemeral mode is only properly supported with recent Linux
    // kernels (as in, 6.6 and later), since it requires user extended attribute
    // support.
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
        snprintf(data, 4096, "lowerdir=%s,upperdir=%s,workdir=%s,xino=off,userxattr", lowerdir, upperdir, workdir);

        if (mount("none", mergeddir, "overlay", 0, data) == -1) err(1, "mount(%s, %s)", mergeddir, data);
    }
    else {
        snprintf(mergeddir, PATH_MAX, "%s:merged", upperdir);
        if (mkdirat(layer_fd, mergeddir, 0777) == -1 && errno != EEXIST) err(1, "mkdir(%s)", mergeddir);
        if (mount(upperdir, mergeddir, "ignored", MS_BIND, NULL) == -1) err(1, "mount(%s, %s, MS_BIND)", upperdir, mergeddir);
    }

    // Configure networking: without separate networking, the configuration
    // files are simply bind mounted. Otherwise, /etc/hostname is populated by
    // the container name, /etc/resolv.conf is populated by dhcp, and
    // /etc/hosts is populated by the host /etc/hosts (but not bind mounted).
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

        // Copy /etc/hosts contents
        snprintf(path, PATH_MAX, "%s/etc/hosts", mergeddir);
        FILE *f1 = fopen("/etc/hosts", "r");
        if (!f1) err(1, "fopen(%s)", "/etc/hosts");
        FILE *f2 = fopen(path, "w");
        if (!f2) err(1, "fopen(%s)", path);
        int c;
        while ((c = fgetc(f1)) != EOF) {
            fputc(c, f2);
        }
        fclose(f1);
        fclose(f2);

        // Populate /etc/hostname
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

    // Mount /dev/net/tun
    if (mkdir("/dev/net", 0777) == -1) err(1, "mkdir(/dev/net)");
    int fd = open("/dev/net/tun", O_WRONLY | O_CREAT, 0666);
    if (fd > -1) close(fd);
    if (mount("/old_root/dev/net/tun", "/dev/net/tun", "ignored", MS_BIND, NULL) == -1) err(1, "mount(/dev/net/tun)");

    // Make a timer file descriptor before forking
    if ((flags & LAYER_NET) && (timefd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC | TFD_NONBLOCK)) == -1) err(1, "timefd_create");

    // Fork to get pid 1, this will also get us a pty if needed
    forktochild();

    // Initialize DHCP
    if (flags & LAYER_NET) {
        int sock = dhcpstart(macvlan);
        while (sock > 0) sock = dhcpstep(macvlan, sock);
        struct itimerspec val = {
            .it_value = { .tv_sec = -sock, .tv_nsec = 0 },
            .it_interval = { 0 }
        };
        if (timerfd_settime(timefd, 0, &val, NULL) == -1) err(1, "timerfd_settime");

        close(timefd);
    }

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
    if (setns(pidfd, uflags) == -1) err(1, "setns");

    close(pidfd);

    forktochild();

    execve(argv[0], argv, envp);
    err(1, "execv");
}
