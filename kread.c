/*
 * A tool for reading kernel source
 */

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include "kread"


static const char optstring[] =
	"+a:Ab:cCdDe:E:fFhiI:ko:O:p:P:qrs:S:tTu:vVwxX:yzZ";

enum {
	GETOPT_SECCOMP = 0x100,

	GETOPT_QUAL_TRACE,
	GETOPT_QUAL_ABBREV,
	GETOPT_QUAL_VERBOSE,
	GETOPT_QUAL_RAW,
	GETOPT_QUAL_SIGNAL,
	GETOPT_QUAL_STATUS,
	GETOPT_QUAL_READ,
	GETOPT_QUAL_WRITE,
	GETOPT_QUAL_FAULT,
	GETOPT_QUAL_INJECT,
	GETOPT_QUAL_KVM,
};

static const struct option longopts[] = {
	{ "columns",		required_argument, 0, 'a' },
	{ "output-append-mode",	no_argument,	   0, 'A' },
	{ "detach-on",		required_argument, 0, 'b' },
	{ "summary-only",	no_argument,	   0, 'c' },
	{ "summary",		no_argument,	   0, 'C' },
	{ "debug",		no_argument,	   0, 'd' },
	{ "func",		required_argument, 0, 'f' }, /* find func */
	{ "help",		no_argument,	   0, 'h' },
	{ "instruction-pointer", no_argument,      0, 'i' },
	{ "stack-traces",	no_argument,	   0, 'k' },
	{ "output",		required_argument, 0, 'o' },
	{ "attach",		required_argument, 0, 'p' },
	{ "trace-path",		required_argument, 0, 'P' },
	{ "macro",		required_argument, 0, 'm' }, /* analy the value of specify macro */
	{ "summary-sort-by",	required_argument, 0, 'S' },
	{ "user",		required_argument, 0, 'u' },
	{ "no-abbrev",		no_argument,	   0, 'v' },
	{ "version",		no_argument,	   0, 'V' },
	{ "summary-wall-clock", no_argument,	   0, 'w' },
	{ "base-path",		required_argument, 0, 'R' },
	{ "seccomp-bpf",	no_argument,	   0, GETOPT_SECCOMP },

	{ "trace",	required_argument, 0, GETOPT_QUAL_TRACE },
	{ "verbose",	required_argument, 0, GETOPT_QUAL_VERBOSE },
	{ "raw",	required_argument, 0, GETOPT_QUAL_RAW },
	{ "status",	required_argument, 0, GETOPT_QUAL_STATUS },
	{ "read",	required_argument, 0, GETOPT_QUAL_READ },
	{ "write",	required_argument, 0, GETOPT_QUAL_WRITE },
	{ "fault",	required_argument, 0, GETOPT_QUAL_FAULT },

	{ 0, 0, 0, 0 }
};

/* the base address of kernel source */
char *base_path;

static void __attribute__((__noreturn__)) usage(void)
{
	FILE *out = stdio;
	fputs(_(" -a, --all		print\n"), out);
	fputs(_(" -f, --func		find func\n"), out);
	fputs(_(" -m, --macro		analy the value for specify MACRO\n"), out);
	fprintf(stdout,
		"kread --help")

	exit(EXIT_SUCCESS);
}

/*
 * this function will create .kread file in ~ 
 */
static void create_dir()
{
	char dir[40];
	struct passwd *pwd = getpwuid(getuid());
    	sprintf(dir, "/home/%s/%s", pwd->pw_name, ".kread");
	base_path = strdup(dir);
	if (access(base_path, R_OK) < 0) {
		/* Not exist, create file */
		mkdir(base_path, S_IRWXU);
	}

	return;
}

/*
 * check files in KERNEL_FILE[] 
 */
static void check()
{
	int i;
	char file[40];

	debug_msg("check...\n");
	/* traverse all file and check whether these file exist or not */
	for (i=0; i<sizeof(KERNEL_FILE); i++) {
		sprintf(file, "%s/%s", base_path, KERNEL_FILE[i]);
		if (access(base_path, R_OK) < 0) {
			perror("check failed: ");
			goto label_error;
		}
	}
	return;
label_error:
	exit(ENOEXIST);
}

static void init(int argc, char *argv[])
{
	int c, i;
	int optF = 0, zflags = 0;

	while ((c = getopt_long(argc, argv, optstring, longopts, NULL)) != EOF) {
		switch (c) {
		case 'a':
			/* TODO */
			break;
		case 'A':
			/* TODO */
			break;
		case 'f':
			/* set the base addr for kernel */
			char *func_tmp = strdup(optarg);
			find_func_declaration(func_tmp);
			break;
		case 'h':
			usage();
			break;
		case 'R':
			/* set the base addr for kernel */
			base_path = strdup(optarg);
			if (access(base_path, R_OK)) {
				fprintf(stderr, "%s is NOT exist", base_path);
			}

			break;
		case 'c':
			/* TODO */
			break;
		default:
			usage();
			break;
		}
	}

}

static void terminate(void)
{
	int exit_code;

	exit(exit_code);
}

int main(int argc, char *argv[])
{
	/* locialize */
	setlocale(LC_ALL, "");
	create_dir();
	check();
	init(argc, argv);

	terminate();
}


