#include <unistd.h>
#include "common.h"
#include "kcore.h"
#include "kread.h"

#include "gdb.h"

unsigned long symbol_init_task;
unsigned long symbol_init_pid_ns;
unsigned long pid_xarray;
struct offset_table offset_table = { 0 };
struct size_table size_table = { 0 };

static struct proc_kcore_data proc_kcore_data = { 0 };
static struct proc_kcore_data *pkd = &proc_kcore_data;
int kcore_fd;

/*
 * Strip line-ending whitespace.
 */
char *strip_ending_whitespace(char *line)
{
	char *p;

	if (line == NULL || strlen(line) == 0)
		return(line);

	p = &LASTCHAR(line);

	while (*p == ' ' || *p == '\t') {
		*p = NULLCHAR;
		if (p == line)
			break;
		p--;
	}

	return(line);
}

/*
 * Strip line-ending linefeeds in a string.
 */
char *strip_linefeeds(char *line)
{
	char *p;

	if (line == NULL || strlen(line) == 0)
		return(line);

	p = &LASTCHAR(line);

	while (*p == '\n') {
		*p = NULLCHAR;
		if (--p < line)
			break; 
	}

	return(line);
}

/*
 * Strip line-beginning whitespace.
 */
char *strip_beginning_whitespace(char *line)
{
	char buf[BUFSIZE];
	char *p;

	if (line == NULL || strlen(line) == 0)
		return(line);

	strcpy(buf, line);
	p = &buf[0];
	while (*p == ' ' || *p == '\t')
		p++;
	strcpy(line, p);

	return(line);
}

/*
 *  Strip line-ending whitespace and linefeeds.
 */
char *strip_line_end(char *line)
{
	strip_linefeeds(line);
	strip_ending_whitespace(line);
	return(line);
}

/*
 * Strip line-beginning and line-ending whitespace and linefeeds.
 */
char *clean_line(char *line)
{
	strip_beginning_whitespace(line);
	strip_linefeeds(line);
	strip_ending_whitespace(line);

	return(line);
}

/*
 * Parse a line into tokens, populate the passed-in argv[] array, and return
 * the count of arguments found.  This function modifies the passed-string 
 * by inserting a NULL character at the end of each token.  Expressions 
 * encompassed by parentheses, and strings encompassed by apostrophes, are 
 * collected into single tokens.
 */
int parse_line(char *str, char *argv[])
{
	int i, j, k;
	int string;
	int expression;

	for (i = 0; i < MAXARGS; i++)
		argv[i] = NULL;

	clean_line(str);

	if (str == NULL || strlen(str) == 0)
		return(0);

	i = j = k = 0;
	string = FALSE;
	expression = 0;

	/*
	 * Special handling for when the first character is a '"'.
	 */
	if (str[0] == '"') {
next:
		do {
			i++;
		} while ((str[i] != NULLCHAR) && (str[i] != '"'));

		switch (str[i])
		{
		case NULLCHAR:
			argv[j] = &str[k];
			return j+1;
		case '"':
			argv[j++] = &str[k+1];
			str[i++] = NULLCHAR;
			if (str[i] == '"') {
				k = i;
				goto next;	
			}
			break;
		}
	} 
	else
		argv[j++] = str;

	while (TRUE) {
		if (j == MAXARGS)
			error_msg("too many arguments in string!\n");

		while (str[i] != ' ' && str[i] != '\t' && str[i] != NULLCHAR) {
			i++;
		}

		switch (str[i]) {
		case ' ':
		case '\t':
			str[i++] = NULLCHAR;

			while (str[i] == ' ' || str[i] == '\t') {
				i++;
			}
	
			if (str[i] == '"') {
				str[i] = ' ';
				string = TRUE;
				i++;
			}

			/*
			 *  Make an expression encompassed by a set of parentheses 
			 *  a single argument.  Also account for embedded sets.
			 */
			if (!string && str[i] == '(') {     
			argv[j++] = &str[i];
			expression = 1;
			while (expression > 0) {
				i++;
				switch (str[i]) {
				case '(':
					expression++;
					break;
				case ')':
					expression--;
					break;
				case NULLCHAR:
				case '\n':
					expression = -1;
					break;
				default:
					break;
				}
			}
			if (expression == 0) {
				i++;
				continue;
			}
		}

		if (str[i] != NULLCHAR && str[i] != '\n') {
			argv[j++] = &str[i];
			if (string) {
				string = FALSE;
				while (str[i] != '"' && str[i] != NULLCHAR)
				i++;
				if (str[i] == '"')
					str[i] = ' ';
			}
			break;
		}
		/* else fall through */
		case '\n':
			str[i] = NULLCHAR;
			/* keep falling... */
		case NULLCHAR:
			argv[j] = NULLCHAR;
			return(j);
		}
	}  
}

/*
 * Determine whether a string contains only hexadecimal characters.
 * If count is non-zero, limit the search to count characters.
 */
int hexadecimal(char *s, int count)
{
    	char *p;
	int cnt, digits;

	if (!count) {
		strip_line_end(s);
		cnt = 0;
	} else
		cnt = count;

	for (p = &s[0], digits = 0; *p; p++) {
		switch(*p) {
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '0':
			digits++;
		case 'x':
		case 'X':
			break;

		case ' ':
			if (*(p+1) == NULLCHAR)
			break;
		else
			return FALSE;
		default:
			return FALSE;
		}

		if (count && (--cnt == 0))
			break;
	}

	return (digits ? TRUE : FALSE);
}

/*
 * Convert a string to a hexadecimal long value.
 */
unsigned long htol(char *s, int flags, int *errptr)
{
	long i, j; 
	unsigned long n;

	if (s == NULL) { 
		if (!(flags & QUIET))
			error_msg("received NULL string\n");
		goto htol_error;
	}

	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
		s += 2;

	if (strlen(s) > MAX_HEXADDR_STRLEN) { 
		if (!(flags & QUIET))
			error_msg("input string too large: \"%s\" (%d vs %d)\n", 
				s, strlen(s), MAX_HEXADDR_STRLEN);
		goto htol_error;
	}

	for (n = i = 0; s[i] != 0; i++) {
		switch (s[i]) {
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			j = (s[i] - 'a') + 10;
			break;
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			j = (s[i] - 'A') + 10;
			break;
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '0':
			j = s[i] - '0';
			break;
		case 'x':
		case 'X':
		case 'h':
			continue;
		default:
			if (!(flags & QUIET))
				error_msg("invalid input: \"%s\"\n", s);
			goto htol_error;
		}
		n = (16 * n) + j;
	}

	return(n);

htol_error:
	return BADADDR;
}

/*
 * Shifts the contents of a string to the right by cnt characters,
 * inserting space characters.  (caller confirms space is available)
 */
char *shift_string_right(char *s, int cnt)
{
	int origlen;

	if (!cnt)
		return(s);

	origlen = strlen(s);
	memmove(s+cnt, s, origlen);
	s[origlen+cnt] = NULLCHAR;
	return(memset(s, ' ', cnt));
}

/*
 * Create a string in a buffer of a given size, centering, or justifying 
 * left or right as requested.  If the opt argument is used, then the string
 * is created with its string/integer value.  If opt is NULL, then the
 * string is already in contained in string s (not justified).  Note that
 * flag LONGLONG_HEX implies that opt is a ulonglong pointer to the 
 * actual value.
 */
char *mkstring(char *s, int size, unsigned long flags, const char *opt)
{
	int len;
	int extra;
	int left;
	int right;

	switch (flags & (LONG_DEC|SLONG_DEC|LONG_HEX|INT_HEX|INT_DEC|LONGLONG_HEX|ZERO_FILL)) {
	case LONG_DEC:
		sprintf(s, "%lu", (unsigned long)opt);
		break;
	case SLONG_DEC:
		sprintf(s, "%ld", (unsigned long)opt);
		break;
	case LONG_HEX:
		sprintf(s, "%lx", (unsigned long)opt);
		break;
	case (LONG_HEX|ZERO_FILL):
		if (VADDR_PRLEN == 8)
			sprintf(s, "%08lx", (unsigned long)opt);
		else if (VADDR_PRLEN == 16)
			sprintf(s, "%016lx", (unsigned long)opt);
		break;
	case INT_DEC:
		sprintf(s, "%u", (unsigned int)((unsigned long)opt));
		break;
	case INT_HEX:
		sprintf(s, "%x", (unsigned int)((unsigned long)opt));
		break;
	case LONGLONG_HEX:
		sprintf(s, "%llx", *((ulonglong *)opt));
		break;
	default:
		if (opt)
			strcpy(s, opt);
		break;
	}

	/*
	 * At this point, string s has the string to be justified,
	 * and has room to work with.  The relevant flags from this
	 * point on are of CENTER, LJUST and RJUST.  If the length 
	 * of string s is already larger than the requested size, 
	 * just return it as is.
	 */
	len = strlen(s);
	if (size <= len) 
		return(s);
	extra = size - len;

	if (flags & CENTER) {
		/*
		 * If absolute centering is not possible, justify the
		 * string as requested -- or to the left if no justify
		 * argument was passed in.
		 */
		if (extra % 2) {
			switch (flags & (LJUST|RJUST)) {
			default:
			case LJUST:
				right = (extra/2) + 1;
				left = extra/2;
				break;
			case RJUST:
				right = extra/2;
				left = (extra/2) + 1;
				break;
			}
		}
		else 
			left = right = extra/2;

		shift_string_right(s, left);
		len = strlen(s);
		memset(s + len, ' ', right);
		s[len + right] = NULLCHAR;
	
		return(s);
	}

	if (flags & LJUST) {
		len = strlen(s);
		memset(s + len, ' ', extra);
		s[len + extra] = NULLCHAR;
	} else if (flags & RJUST) 
		shift_string_right(s, extra);

	return(s);
}

/*
 * Get a symbol value from /proc/kallsyms.
 *
 * This function will rename lookup_symbol_from_kallsyms()
 */
unsigned long lookup_symbol_from_proc_kallsyms(char *symname)
{
	FILE *kp;
	char buf[BUFSIZE];
	char *kallsyms[MAXARGS];
	unsigned long kallsym;
	int found;

	if (!file_exists("/proc/kallsyms", NULL)) {
		error_msg("cannot determine value of %s: "
			"/proc/kallsyms does not exist\n\n", symname);
		return BADVAL;
	}

	if ((kp = fopen("/proc/kallsyms", "r")) == NULL) {
		error_msg("cannot determine value of %s: "
			"cannot open /proc/kallsyms\n\n", symname);
		return BADVAL;
	}

	found = FALSE;
	while (!found && fgets(buf, BUFSIZE, kp) &&
	    (parse_line(buf, kallsyms) == 3)) {
		if (hexadecimal(kallsyms[0], 0) &&
			STREQ(kallsyms[2], symname)) {
			kallsym = htol(kallsyms[0], RETURN_ON_ERROR, NULL);
			found = TRUE;
			break;
		}
	}
	fclose(kp);

	return (found ? kallsym : BADVAL);
}

void arch_kernel_init(void)
{
#ifdef ARM64
	arm64_kernel_init();
#endif
}

/*
 *  Return the task_context structure of the first task found with a pid,
 *  while linking all tasks that have that pid. 
 */
struct task_context *
pid_to_context(unsigned long pid)
{
	int i;
	struct task_context *tc, *firsttc, *lasttc;
#if 0
	tc = FIRST_CONTEXT();
	firsttc = lasttc = NULL;

	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tc->pid == pid) {
			if (!firsttc)
				firsttc = tc;
			if (lasttc)
				lasttc->tc_next = tc;
			tc->tc_next = NULL;
			lasttc = tc;
		}
	}
#endif
        return firsttc;
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

void kcore_init(void)
{
	int ret;

	if ((kcore_fd = open("/proc/kcore", O_RDONLY)) < 0)
		error_msg("/proc/kcore: %s\n", strerror(errno));
	if (!proc_kcore_init_64(kcore_fd))
		error_msg("/proc/kcore: initialization failed\n");
}

/*
 * Read from /proc/kcore.
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
	 * Unless specified otherwise, turn the physical address into 
	 * a unity-mapped kernel virtual address, which should work 
	 * for 64-bit architectures, and for lowmem access for 32-bit
	 * architectures.
	 */
	if (paddr == KCORE_USE_VADDR)
		kvaddr = addr;
	else
		kvaddr = PTOV((unsigned long)paddr);

	offset = UNINITIALIZED;
	readcnt = cnt;

	/*
	 * If KASLR, the PAGE_OFFSET may be unknown early on, so try
	 * the (hopefully) mapped kernel address first.
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
		goto seek_ok;

	for (i = 0; i < pkd->segments; i++) {
		lp64 = pkd->load64 + i;
		if ((kvaddr >= lp64->p_vaddr) &&
			(kvaddr < (lp64->p_vaddr + lp64->p_memsz))) {
			offset = (off_t)(kvaddr - lp64->p_vaddr) + 
				(off_t)lp64->p_offset;
			break;
		}
	}

seek_ok:
	if (offset == UNINITIALIZED) {
		ERROR("failed: seek error when read kcore");
		return SEEK_ERROR;
	}

	if (lseek(fd, offset, SEEK_SET) != offset)
		perror("lseek");

	if (read(fd, bufptr, readcnt) != readcnt)
		return READ_ERROR;

	return cnt;
}

void kcore_exit(void)
{
	if (pkd->elf_header) {
		free(pkd->elf_header);
	}
	if (kcore_fd > 0)
		close(kcore_fd);
}

int kvtop(struct task_context *tc, unsigned long kvaddr, physaddr_t *paddr, int verbose)
{
	physaddr_t unused;

#ifdef X86_64
	return (x86_kvtop(tc ? tc : CURRENT_CONTEXT(), kvaddr, 
		paddr ? paddr : &unused, verbose));
#elif defined(ARM64)
	return (arm64_kvtop(tc ? tc : CURRENT_CONTEXT(), kvaddr, 
		paddr ? paddr : &unused, verbose));
#else
	printf("build error");
	return FALSE;
#endif
}

int uvtop(struct task_context *tc, unsigned long uvaddr, physaddr_t *paddr, int verbose)
{
	physaddr_t unused;

#ifdef X86_64
	return (x86_uvtop(tc ? tc : CURRENT_CONTEXT(), uvaddr,
		paddr ? paddr : &unused, verbose));
#elif defined(ARM64)
	return (arm64_uvtop(tc ? tc : CURRENT_CONTEXT(), uvaddr,
		paddr ? paddr : &unused, verbose));
#else
	printf("build error");
	return FALSE;
#endif
}

/*
 * First, we need translate addr into paddr. 'memtype' has following value:
 * 	KVADDR UADDR
 */
int readmem(ulonglong addr, int memtype, void *buffer, long size,
	char *type, unsigned long error_handle)
{
	long cnt = size;
	char *bufptr = (char *)buffer;
	unsigned long paddr;

	/* translate addr into paddr */
	switch (memtype) {
	case UVADDR:
		if (!uvtop(CURRENT_CONTEXT(), addr, &paddr, 1)) {
			ERROR("failed: uvtop");
			return FALSE;
		}
		break;
	case KVADDR:
		if (!kvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
			ERROR("failed: kvtop");
			return FALSE;
		}
		break;
	case PHYSADDR:
		paddr = addr;
		break;
	}
	/* read data by paddr */
	read_proc_kcore(kcore_fd, bufptr, cnt,
		(memtype == PHYSADDR) || (memtype == XENMACHADDR) ? 0 : addr, paddr);

	return TRUE;
}

/*
 * In kernel, all tasks maybe managed in xarray or radix tree, depend on:
 *
 * struct idr {
 *	struct radix_tree_root	idr_rt;
 *	unsigned int		idr_base;
 *	unsigned int		idr_next;
 * };
 *
 * The 'radix_tree_root' can been defined "xarray" or "radix", so we can judge
 * type of idr_rt to select initial function.
 */
void task_symbol_init(void)
{
	unsigned long node_p;
	/* default: xarray */
	pid_xarray = symbol_init_pid_ns +
		OFFSET(pid_namespace_idr) + OFFSET(idr_idr_rt);
	/* KVADDR -> paddr -> value */
	readmem(pid_xarray + OFFSET(xarray_xa_head), KVADDR, &node_p,
		sizeof(void *), "xarray xa_head", FAULT_ON_ERROR);
}

/* Initial symbols from kallsyms */
void symbols_init_from_kallsyms(void)
{
	symbol_init_pid_ns = lookup_symbol_from_proc_kallsyms("init_pid_ns");
	if (symbol_init_pid_ns == BADVAL) {
		printf("failed: initial init_pid_ns");
	}
	tt->init_pid_ns = symbol_init_pid_ns;

	symbol_init_task = lookup_symbol_from_proc_kallsyms("init_task");
	if (symbol_init_task == BADVAL) {
		printf("failed: initial init_pid_ns");
	}
	/* task */
	task_symbol_init();
}

/*
 * example:
 * 	gdb -batch -ex 'file vmlinux' -ex 'p sizeof(struct task_struct)'
 */
long request_gdb(struct gnu_request *req)
{
	char buf1[100];
	char buf2[100];
	int cmd = req->command;
	int des_p[2], pid;
	int nbytes;

	if(pipe(des_p) == -1) {
		perror("Pipe failed");
		exit(1);
	}

	/* lookup_symbol_in_language */
	// sprintf(buf, "printf \"%%ld\", (u64)(&((struct %s*)0)->%s + 1) - (u64)&((struct %s*)0)->%s",
	//	name, member, name, member);

	switch (cmd) {
	case GNU_PASS_THROUGH:
		sprintf(buf1, "file %s", current_vmlinux_path);
		sprintf(buf2, "p sizeof(struct %s)", req->name);
	break;
	case GNU_GET_DATATYPE:
		sprintf(buf1, "file %s", current_vmlinux_path);
		sprintf(buf2, "p sizeof(struct %s)", req->name);
	break;
	default:
		printf("something error!");
	break;
	}
	char *argv[] = {"gdb", "-batch", "-ex", buf1, "-ex", buf2, NULL};
	char *envp[] = {0, NULL};

	pid = fork();
	if(pid == 0) {
		close(STDOUT_FILENO); //closing stdout
		dup2(des_p[1], STDOUT_FILENO); //replacing stdout with pipe write 
		close(des_p[0]); //closing pipe read

		execve("/usr/bin/gdb", argv, envp);
		exit(0);
	} else {
		/* parent */
		int status;
		waitpid(pid, &status, 0);
		nbytes = read(des_p[0], buf1, sizeof(buf1));
		printf("struct size buf: %s\n", buf1);
	}
	return 8;
}

/*
 * example:
 * 	pahole vmlinux -C task_struct
 */
long request_pahole(struct gnu_request *req)
{
	char buf[200];
	int cmd = req->command;
	int nbytes;
	long ret;

	switch (cmd) {
	case GNU_PASS_THROUGH:
		if (req->member == NULL)
			sprintf(buf, "pahole %s --sizes|awk \'{if($1==\"%s\"){print $2; exit}}\'",
				current_vmlinux_path, req->name);
		else {
			/* request member offset */
			long size = request_pahole_member_number(req->name);
			sprintf(buf, "pahole -JV %s | grep -A %d -m 1 %s|awk \'{if($1==\"%s\"){print $NF}}\' | tr -d \"a-zA-Z=_\"",
				current_vmlinux_path, size, req->name, req->member);
			ret = exec_cmd_return_long(buf, 0);
			if (ret != -1)
				ret /= 8;
			else {
				if (kr_debug)
					printf("failed: %s\n", buf);
				/* pahole -V %s -C %s | grep -m 1 %s|sed 's/.*\(.................\)$/\1/' */
				sprintf(buf, "pahole -V %s -C %s | grep -m 1 %s|sed \'s/.*\\(.................\\)$/\\1/\'|awk \'{print $2}\'",
					current_vmlinux_path, req->name, req->member);
				ret = exec_cmd_return_long(buf, 0);
				if (ret == -1)
					goto tried_and_failed;
				/* success */
			}
			goto success;
		}
	break;
	case GNU_GET_DATATYPE:
		sprintf(buf, "pahole %s --sizes|grep -m 1 %s|awk \'{print $2}\'",
			current_vmlinux_path, req->name);
	break;
	default:
		printf("something error!");
	break;
	}
	ret = exec_cmd_return_long(buf, 0);
success:
	return ret;
tried_and_failed:
	fprintf(stderr, "tried and failed: %s\n", buf);
	return -1;
}

/*
 * #define STRUCT_SIZE(X)      datatype_info((X), NULL, NULL)
 * #define UNION_SIZE(X)       datatype_info((X), NULL, NULL)
 * #define DATATYPE_SIZE(X)    datatype_info((X)->name, NULL, (X))
 * #define MEMBER_OFFSET(X,Y)  datatype_info((X), (Y), NULL)
 * #define MEMBER_SIZE(X,Y)    datatype_info((X), (Y), MEMBER_SIZE_REQUEST)
 * #define MEMBER_TYPE(X,Y)    datatype_info((X), (Y), MEMBER_TYPE_REQUEST)
 */
long datatype_info(char *name, char *member, struct datatype_member *dm)
{
	struct gnu_request request, *req = &request;
	char buf[BUFSIZE];
	long retval;

	strcpy(buf, name);
	memset(req, 0, sizeof(*req));
	if (dm == STRUCT_SIZE_REQUEST || dm == NULL)
		req->command = GNU_PASS_THROUGH;
	else if (dm == MEMBER_SIZE_REQUEST) {
		ERROR("NOT support MEMBER_SIZE_REQUEST");
		return -1;
	}
	else
		req->command = GNU_GET_DATATYPE;
	req->flags |= GNU_RETURN_ON_ERROR;
	req->name = buf;
	req->member = member;
	req->fp = NULL;

	// gdb_command_funnel(req);
	/* request data form gdb */
	retval = request_pahole(req);
	if (retval == -1)
		exit(-1);
	return retval;
}
