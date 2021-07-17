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
#include <signal.h> /* for signal */
#include <execinfo.h> /* for backtrace() */
#include <pwd.h>

#include <common.h>
#include "kread.h"
#include "kcore.h"

int pgtable_enabled = 0; /* dump pgtable for PID */
int ptedump_enabled = 0;
int vmadump_enabled = 0; /* dump detailed vma */

/* For debug, the env is KD_DEBUG */
int kr_debug = 0;
extern void signal_handler(int signo);

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
	{ "file",		required_argument, 0, 'f' },
	{ "help",		no_argument,	   0, 'h' },
	{ "inst-pointer",	no_argument,       0, 'i' },
	{ "kcore-info",		no_argument,	   0, 'k' },
	{ "output",		required_argument, 0, 'o' },
	{ "pid",		required_argument, 0, 'p' },
	{ "pgtable",		required_argument, 0, 'P' }, /* TODO */
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

const char *program;
/* the base address of kernel source */
char *base_path;
char *current_linux_release = NULL;
char *current_vmlinux_path = NULL;

static void usage(void)
{
	fprintf(stderr,
		"Usage: %s [options] --help\n"
		"  --help         -h  Print this help\n"
		"  --version      -V  Print current version\n"
		"  --file         -f  vmlinux file\n"
		"  --pid          -p  print task info\n"
		"  --pgtable      -P  dump pgtable of PID\n"
		"\n"
		"  example:\n"
		"  print information of the specify task:\n"
		"\n"
		"		$kread --pgtable[-p] 22366\n"
		"		TODO\n"
		"\n",
		program);

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

pid_t target_pid = -1;
unsigned long target_addr;
static void init(int argc, char *argv[])
{
	int c;
	char *func_tmp;

	while ((c = getopt_long(argc, argv, optstring, longopts, NULL)) != EOF) {
		switch (c) {
		case 'a':
			/* TODO */
			break;
		case 'A':
			/* TODO */
			break;
		case 'f':
			current_vmlinux_path = strdup(optarg);
			break;
		case 'h':
			usage();
			break;
		case 'p':
			ptedump_enabled = 1;
			/* FIXME: pid1,pid2,pid3 */
			target_pid = (pid_t)strtoul(optarg, NULL, 0);
			target_addr = htol(argv[optind], RETURN_ON_ERROR, NULL);
			break;
		case 'P':
			/* TODO */
			pgtable_enabled = 1;
			target_pid = (pid_t)strtoul(optarg, NULL, 0);
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

	/* env */
	kr_debug = strtol(getenv("KR_DEBUG"), NULL, 0);
	signal(SIGSEGV, signal_handler);
	signal(SIGABRT, signal_handler);
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

	/*
	 * if current_vmlinux_path != NULL, indicate the vmlinux path has
	 * been set in '-f'
	 */
	if (!current_vmlinux_path)
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
	program = argv[0];
	init(argc, argv);
	kcore_init();
	vmlinux_init();
	arch_kernel_init();
	/* TODO */
	symbols_init_from_kallsyms();

	if (target_pid != -1) {
		dump_task(target_pid);
		if (pgtable_enabled)
			stat_pgtable(target_pid);
		if (ptedump_enabled) {
			dump_pte(target_pid, target_addr);
		}
	}
	terminate();
}
