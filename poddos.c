#define _GNU_SOURCE
#include <argp.h>
#include <dirent.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "pull.h"
#include "layer.h"

static struct argp_option global_options[] = {
	{"layer", 'l', "PATH", 0, "Path where layers are stored. Defaults to the value of the environmental variable $LAYERPATH, or $XDG_DATA_HOME/poddos if unset (the latter usually resolves to ~/.local/share/poddos)."},
	{"name", 'n', "NAME", 0, "Assign a name to the container. This name will be the hostname of the container (if a UTS namespace is created), can be used to store configuration, and is used to create a pidfile."},
	{ 0 }
};

static struct argp_option pull_options[] = {
	{"url", 'u', "URL", 0, "Pull a series of layers from this url"},
	{ 0 }
};

static struct argp_option start_options[] = {
	{"overlay", 'o', "PATH", 0, "Overlay paths, to be specified multiple times. "
	                            "Each path is overlayed on top of the previous one. "
								"Modifications to the container are stored in the last path (but see --ephemeral)."},
	{"env", 'e', "FOO=BAR", 0, "Environment variables added when executing, to be specified multiple times if needed."},
	{"ephemeral", 'E', NULL, 0, "All modifications made in the mount namespace are thrown away. "
	                            "This is done by making the top-level directory a tmpfs, and requires a kernel that supports user extended attributes on a tmpfs for full support (upstream that is since version 6.6)."},
	{"net", 1000, "INTERFACE", 0, "Put container in net namespace and initialize a macvlan (usually called macvlan0) in it. "
								  "The macvlan is put in bridge mode, such that all containers can connect to eachother directly. "
								  "An IP (only v4) is obtained via DHCP, so there is a noticable lag when starting the container. "
								  "Keep in mind that the host cannot directly connect to the containers, which is a known restriction of macvlans. "
								  "This usually only works with wired links and requires CAP_NET_ADMIN."},
	{"mac", 1001, "MAC", 0, "If --net is provided, the mac address of the macvlan. "
	                        "If not provided, the kernel picks one randomly."},
	{"bind", 1002, "FROM:TO", 0, "Mount the path <FROM> in the container to the path <TO>. "
	                             "<TO> can be omitted, and then it will appear in the same place as <FROM>. "
								 "All provided paths should be absolute paths."},
	{"directory", 'C', "PATH", 0, "Change to the specified directory before executing the specified command. "
	                              "The specified directory should be an existing directory in the folder structure of the container."},
	{ 0 }
};

static struct argp_option exec_options[] = {
	{"env", 'e', "FOO=BAR", 0, "Environment variables added when executing the command. Specify multiple times to add multiple environmental variables."},
	{ 0 }
};

char layer_path[PATH_MAX] = { 0 };
int layer_fd = -1;
const char *url = NULL;

bool ephemeral = false;

char *ifname = NULL;
char mac[6] = { 0 };

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
	if (!dirp) err(1, "opendir(%s)", name);
	while (readdir(dirp)) ret++;
	closedir(dirp);

	return ret;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'o':
		if (upperdir[0] && dircnt(upperdir) > 2) {
			if (!lowerdir[0]) strcpy(lowerdir, upperdir);
			else {
				char buf[4096];
				snprintf(buf, 4096, "%s:%s", upperdir, lowerdir);
				strcpy(lowerdir, buf);
			}
		}
		if (arg[0] != '/') snprintf(upperdir, 4096, "%s/%s", layer_path, arg);
		else strncpy(upperdir, arg, 4096);
		break;
	case 'e':
		penvp = realloc(penvp, (++nenvp)*sizeof(char *));
		if (!penvp) err(1, "realloc(penvp)");
		penvp[nenvp-1] = arg;
		break;
	case 'E':
		ephemeral = true;
		break;
	case 'l':
		strncpy(layer_path, arg, PATH_MAX-1);
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
		int ret = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		if (ret != 6) {
			warnx("Invalid mac address provided.");
			return 1;
		}
		break;
	case 1002: // --bind
		char *from = arg;
		char *to = strchr(from, ':');
		if (to) {
			*to = 0;
			to++;
		}
		else to = from;
		
		if (from[0] != '/' || to[0] != '/') {
			warnx("Bind mounts must be absolute paths.");
			return 1;
		}

		nbind++;
		bind_to = realloc(bind_to, sizeof(char *)*nbind);
		if (!bind_to) err(1, "realloc");
		bind_from = realloc(bind_from, sizeof(char *)*nbind);
		if (!bind_from) err(1, "realloc");

		bind_to[nbind-1] = to;
		bind_from[nbind-1] = realpath(from, NULL);
		if (!bind_from[nbind-1]) err(1, "realpath(%s)", from);

		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int loadargs(char ***argv, char *action)
{
	int argc = 1;
	*argv = malloc(sizeof(char **));
	if (!*argv) err(1, "malloc");
	(*argv)[0] = malloc(strlen(action) + strlen("poddos") + 2);
	if (!(*argv)[0]) err(1, "malloc");
	sprintf((*argv)[0], "%s-%s", "poddos", action);

	int fd = openat(layer_fd, name, O_RDONLY);
	if (fd == -1) return argc;
	FILE *f = fdopen(fd, "r");

	bool parsing = false;
	char buf[4096];
	while (!feof(f) && !ferror(f)) {
		if (!fgets(buf, 4096, f)) break;

		// Ignore empty lines and comments
		if (buf[0] == '\n' || buf[0] == '#') continue;

		// Strip off the final \n
		buf[strlen(buf)-1] = 0;

		char header[21] = { 0 };
		if (sscanf(buf, "[%20[abcdefghijklmnopqrstuvwxyz]]", header)) parsing = !strcmp(header, action);
		else if (parsing) {
			*argv = realloc(*argv, (++argc) * sizeof(char **));
			if (!*argv) err(1, "realloc");
			(*argv)[argc-1] = malloc(strlen(buf) + 1);
			strcpy((*argv)[argc-1], buf);
		}
	}

	fclose(f);

	// Add the final NULL
	*argv = realloc(*argv, (argc+1)*sizeof(char **));
	if (!argv) err(1, "realloc");
	(*argv)[argc] = NULL;

	return argc;
}

int main(int argc, char **argv)
{
	struct argp argp = {
		.options = global_options,
		.parser = parse_opt,
		.args_doc = "pull|start|exec [OPTIONS...]"
	};
	int arg_index = 0;
	argp_parse(&argp, argc, argv, ARGP_NO_ARGS | ARGP_IN_ORDER, &arg_index, NULL);

	if (arg_index >= argc) {
		fprintf(stderr, "Nothing to do.\n");
		return 0;
	}

	// Build the default layer path if the user did not provide any
	if (!layer_path[0]) {
		if (getenv("LAYERPATH")) strncpy(layer_path, getenv("LAYERPATH"), PATH_MAX-1);
		else if (getenv("XDG_DATA_HOME")) snprintf(layer_path, PATH_MAX, "%s/poddos", getenv("XDG_DATA_HOME"));
		else if (getenv("HOME")) snprintf(layer_path, PATH_MAX, "%s/.local/share/poddos", getenv("HOME"));
		else snprintf(layer_path, PATH_MAX, "/usr/local/share/poddos");
	}

	// Ensure the layer path exists
	if (mkdir(layer_path, 0777) == -1 && errno != EEXIST) err(1, "mkdir(%s)", layer_path);

	layer_fd = open(layer_path, O_DIRECTORY | O_CLOEXEC);
	if (layer_fd == -1) err(1, "open(%s)", layer_path);
	if (mkdirat(layer_fd, "ephemeral", 0777) == -1 && errno != EEXIST) err(1, "mkdir(ephemeral)");

	int argc2 = 0;
	char **argv2 = NULL;
	if (name) argc2 = loadargs(&argv2, argv[arg_index]);

	if (!strcmp(argv[arg_index], "pull")) {
		argv[arg_index] = "poddos-pull";
		struct argp argp = {
			.options = pull_options,
			.parser = parse_opt,
		};
		if (argc2) argp_parse(&argp, argc2, argv2, ARGP_IN_ORDER, NULL, NULL);
		argp_parse(&argp, argc - arg_index, argv + arg_index, ARGP_IN_ORDER, NULL, NULL);

		pull(url);
	}
	else if (!strcmp(argv[arg_index], "start")) {
		argv[arg_index] = "poddos-start";
		struct argp argp = {
			.options = start_options,
			.parser = parse_opt,
			.args_doc = "[CMD...]"
		};
		int cmd_index = 0, cmd_index_2 = 0;
		if (argc2) argp_parse(&argp, argc2, argv2, ARGP_IN_ORDER, &cmd_index_2, NULL);
		argp_parse(&argp, argc - arg_index, argv + arg_index, ARGP_IN_ORDER, &cmd_index, NULL);

		if (!upperdir[0]) errx(1, "At least one overlay directory should be provided");
		if (arg_index + cmd_index >= argc && cmd_index_2 >= argc2) errx(1, "No command to exeute");

		penvp = realloc(penvp, (++nenvp)*sizeof(char *));
		if (!penvp) err(1, "realloc(penvp)");
		penvp[nenvp-1] = NULL;

		if (arg_index + cmd_index < argc) pargv = argv + arg_index + cmd_index;
		else pargv = argv2 + cmd_index_2;

		unsigned flags = 0;
		if (ephemeral) flags |= LAYER_EPHEMERAL;
		if (ifname) flags |= LAYER_NET;

		lstart(flags, pargv, penvp);
	}
	else if (!strcmp(argv[arg_index], "exec")) {
		argv[arg_index] = "poddos-exec";
		struct argp argp = {
			.options = exec_options,
			.parser = parse_opt,
			.args_doc = "[CMD...]"
		};
		int cmd_index = 0, cmd_index_2 = 0;
		if (argc2) argp_parse(&argp, argc2, argv2, ARGP_IN_ORDER | ARGP_PARSE_ARGV0, &cmd_index_2, NULL);
		argp_parse(&argp, argc - arg_index, argv + arg_index, ARGP_IN_ORDER, &cmd_index, NULL);

		if (!name) errx(1, "Can only exec in named containers");
		if (arg_index + cmd_index >= argc && cmd_index_2 >= argc2) errx(1, "No command to exeute");

		penvp = realloc(penvp, (++nenvp)*sizeof(char *));
		if (!penvp) err(1, "realloc(penvp)");
		penvp[nenvp-1] = NULL;

		if (arg_index + cmd_index < argc) pargv = argv + arg_index + cmd_index;
		else pargv = argv2 + cmd_index_2;

		lexec(0, pargv, penvp);
	}
	else fprintf(stderr, "Unrecognized action '%s'.\n", argv[arg_index]);

	close(layer_fd);
	return 0;
}
