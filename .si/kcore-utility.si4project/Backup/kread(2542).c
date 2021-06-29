/*
 * A tool for reading kernel source
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

static struct proc_kcore_data proc_kcore_data = { 0 };
static struct proc_kcore_data *pkd = &proc_kcore_data;
static int kcore_fd;

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

static void usage(void)
{
	FILE *out = stdin;
	fputs((" -a, --all		print\n"), out);
	fputs((" -f, --func		find func\n"), out);
	fputs((" -m, --macro		analy the value for specify MACRO\n"), out);
	fputs((" -p, --PID		print task info\n"), out);
	fprintf(stdout,
		"kread --help");

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
static void check()
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

static void terminate(void)
{
	int exit_code;

	exit(exit_code);
}

/* 将kcore数据初始化并保存到pkd */
static int proc_kcore_init_64(int kcore_fd)
{
	int fd;
	Elf64_Ehdr *elf64;
	Elf64_Phdr *load64;
	Elf64_Phdr *notes64;
	char eheader[MAX_KCORE_ELF_HEADER_SIZE];
	char buf[BUFSIZE];
	size_t load_size, notes_size;

	if (kcore_fd == UNUSED) {
		if ((fd = open("/proc/kcore", O_RDONLY)) < 0) {
			error_msg("/proc/kcore: %s\n", strerror(errno));
			return FALSE;
		}
	} else
		fd = kcore_fd;

	if (read(fd, eheader, MAX_KCORE_ELF_HEADER_SIZE) != MAX_KCORE_ELF_HEADER_SIZE) {
		sprintf(buf, "/proc/kcore: read");
		perror(buf);
		goto bailout;
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		sprintf(buf, "/proc/kcore: lseek");
		perror(buf);
		goto bailout;
	}

	if (fd != kcore_fd)
		close(fd);

	elf64 = (Elf64_Ehdr *)&eheader[0];
	if (elf64->e_phoff > sizeof(eheader) - 2 * sizeof(Elf64_Phdr)) {
		error_msg("/proc/kcore: ELF program header offset too big!\n");
		return FALSE;
	}
	notes64 = (Elf64_Phdr *)&eheader[elf64->e_phoff];
	load64 = notes64 + 1;

	pkd->segments = elf64->e_phnum - 1;

	notes_size = load_size = 0;
	/* 这里待验证是否有问题 */
	if (notes64->p_type == PT_NOTE)
		notes_size = notes64->p_offset + notes64->p_filesz;
	if (notes64->p_type == PT_LOAD)
		load_size = (unsigned long)(load64+(elf64->e_phnum)) - (unsigned long)elf64;

	pkd->header_size = MAX(notes_size, load_size);
	if (!pkd->header_size)
		pkd->header_size = MAX_KCORE_ELF_HEADER_SIZE;

	if ((pkd->elf_header = (char *)malloc(pkd->header_size)) == NULL) {
		error_msg("/proc/kcore: cannot malloc ELF header buffer\n");
		exit(1);
	}

	memcpy(&pkd->elf_header[0], &eheader[0], pkd->header_size);
	pkd->notes64 = (Elf64_Phdr *)&pkd->elf_header[elf64->e_phoff];
	pkd->load64 = pkd->notes64 + 1;
	pkd->flags |= KCORE_ELF64;

	return TRUE;

bailout:
	if (fd != kcore_fd)
		close(fd);
	return FALSE;
}

void kcore_init()
{
	int kcore_fd;
	int ret;

	if ((kcore_fd = open("/proc/kcore", O_RDONLY)) < 0)
		error_msg("/proc/kcore: %s\n", strerror(errno));
	if (!proc_kcore_init_64(kcore_fd))
		error_msg("/proc/kcore: initialization failed\n");
}

/*
 *  Read from /proc/kcore.
 */
int read_proc_kcore(int fd, void *bufptr, int cnt, unsigned long addr, physaddr_t paddr) 
{
	int i; 
	size_t readcnt;
	unsigned long kvaddr;
	Elf64_Phdr *lp64;
	off_t offset;

#if 0
	if (paddr != KCORE_USE_VADDR) {
		if (!machdep->verify_paddr(paddr)) {
			if (CRASHDEBUG(1))
				error_msg("verify_paddr(%lx) failed\n", paddr);
			return READ_ERROR;
		}
	}
#endif
	/*
	 *  Unless specified otherwise, turn the physical address into 
	 *  a unity-mapped kernel virtual address, which should work 
	 *  for 64-bit architectures, and for lowmem access for 32-bit
	 *  architectures.
	 */
	if (paddr == KCORE_USE_VADDR)
		kvaddr = addr;
	else
		kvaddr =  PTOV((unsigned long)paddr);

	offset = UNINITIALIZED;
	readcnt = cnt;

	/*
	 *  If KASLR, the PAGE_OFFSET may be unknown early on, so try
	 *  the (hopefully) mapped kernel address first.
	 */
	for (i = 0; i < pkd->segments; i++) {
		lp64 = pkd->load64 + i;
		if ((addr >= lp64->p_vaddr) &&
		    (addr < (lp64->p_vaddr + lp64->p_memsz))) {
			offset = (off_t)(addr - lp64->p_vaddr) + 
				(off_t)lp64->p_offset;
			break;
		}
	}
	if (offset != UNINITIALIZED)
		return READ_ERROR;

	for (i = 0; i < pkd->segments; i++) {
		lp64 = pkd->load64 + i;
		if ((kvaddr >= lp64->p_vaddr) &&
		    (kvaddr < (lp64->p_vaddr + lp64->p_memsz))) {
			offset = (off_t)(kvaddr - lp64->p_vaddr) + 
				(off_t)lp64->p_offset;
			break;
		}
	}

	if (offset == UNINITIALIZED)
		return SEEK_ERROR;

        if (lseek(fd, offset, SEEK_SET) != offset)
		perror("lseek");

	if (read(fd, bufptr, readcnt) != readcnt)
		return READ_ERROR;

	return cnt;
}

void kcore_exit()
{
	if (pkd->elf_header) {
		free(pkd->elf_header);
	}
	if (kcore_fd > 0)
		close(kcore_fd);
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
	while (fgets(c, sizeof(buf), fp) != NULL) {
		current_linux_release = strdup(buf);
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

int main(int argc, char *argv[])
{
	/* locialize */
	setlocale(LC_ALL, "");
	create_dir();
	check();
	kcore_init();
	vmlinux_init();
	arch_kernel_init();
	symbols_init_from_kallsyms();
	init(argc, argv);

	terminate();
	kcore_exit();
}
