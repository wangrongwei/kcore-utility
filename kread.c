/*
 * A tool for reading kcore
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <getopt.h>
#include <pwd.h>

#include <common.h>
#include "kread.h"
#include "kcore.h"

static const char optstring[] =
	"+a:Ab:cCdDe:E:fFhiI:k:o:O:p:P:qrs:S:tTu:vVwxX:yzZ";

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
	{ "kcore-info",		no_argument,	   0, 'k' },
	{ "output",		required_argument, 0, 'o' },
	{ "pid",		required_argument, 0, 'p' },
	{ "trace-path",		required_argument, 0, 'P' },
	{ "macro",		required_argument, 0, 'm' }, /* analy the value of specify macro */
	{ "summary-sort-by",	required_argument, 0, 'S' },
	{ "user",		required_argument, 0, 'u' },
	{ "no-abbrev",		no_argument,	   0, 'v' },
	{ "version",		no_argument,	   0, 'V' },
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
char *current_linux_release;
char *current_vmlinux_path;

static void usage(void)
{
	FILE *out = stdout;

	fprintf(out, "kread --help\n");
	fputs(("	-a, --all		print\n"), out);
	fputs(("	-f, --func		find func\n"), out);
	fputs(("	-m, --macro		analy the value for specify MACRO\n"), out);
	fputs(("	-p, --PID		print task info\n"), out);

	exit(EXIT_SUCCESS);
}

/*
 * this function will create .kread file in ~ 
 */
static void create_dir(void)
{
	char dir[40];
	struct passwd *pwd = getpwuid(getuid());

	sprintf(dir, "/home/%s/%s", pwd->pw_name, ".kread");
	base_path = strdup((char *)dir);
	if (access(base_path, R_OK) < 0) {
		/* Not exist, create file */
		mkdir(base_path, S_IRWXU);
	}

	return;
}

/*
 * check files in KERNEL_FILE[] 
 */
static void check(void)
{
	debug_msg("check...\n");
#if 0
	/* traverse all file and check whether these file exist or not */
	for (i=0; i<sizeof(KERNEL_FILE); i++) {
		sprintf(file, "%s/%s", base_path, KERNEL_FILE[i]);
		if (access(base_path, R_OK) < 0) {
			perror("check failed: ");
			goto label_error;
		}
	}
#endif
	return;
label_error:
	exit(ENOEXIST);
}

static void init(int argc, char *argv[])
{
	int c;
	char *func_tmp;
	pid_t pid;

	while ((c = getopt_long(argc, argv, optstring, longopts, NULL)) != EOF) {
		switch (c) {
		case 'a':
			/* TODO */
			break;
		case 'A':
			/* TODO */
			break;
		case 'f':
			/* TODO */
			break;
		case 'h':
			usage();
			break;
		case 'p':
			/* FIXME: pid1,pid2,pid3 */
			pid = (pid_t)strtoul(optarg, NULL, 0);
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


/*
 * Generally, we need default vmlinux to parse kernel variables
 * and struct, etc.
 */
void vmlinux_init(void)
{
	char buf[100];
	FILE *fp;

	fp = popen("uname -r", "r");
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		current_linux_release = strdup(buf);
		/* remove the last \n */
		current_linux_release[strcspn(current_linux_release, "\n")] = '\0';
	}
	pclose(fp);

	sprintf(buf, "/lib/modules/%s/build/vmlinux", current_linux_release);
	current_vmlinux_path = strdup(buf);
	if((access(current_vmlinux_path, F_OK)) != -1) {
		printf("%s exists\n", current_vmlinux_path);
	}
	else {
		printf("%s NOT exists\n", current_vmlinux_path);
		exit(-1);
	}
}

static void terminate(void)
{
	int exit_code = 0;

	kcore_exit();
	exit(exit_code);
}

int main(int argc, char *argv[])
{
	/* locialize */
	setlocale(LC_ALL, "");
	create_dir();
	init(argc, argv);
	kcore_init();
	vmlinux_init();
	arch_kernel_init();
	/* TODO */
	// symbols_init_from_kallsyms();

	terminate();
}
