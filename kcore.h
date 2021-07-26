#ifndef __KCORE_H__
#define __KCORE_H__

#include <sys/utsname.h>
#include <sys/types.h>    
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include <common.h>

#include "gdb.h"
#include "kernel.h"

#define BUFSIZE  (1500)
#define NULLCHAR ('\0')

#define MAXARGS    (100)   /* max number of arguments to one function */
#define MAXARGLEN  (40)   /* max length of argument */

#define KVADDR             (0x1)
#define UVADDR             (0x2)
#define PHYSADDR           (0x4)
#define XENMACHADDR        (0x8)

#define FAULT_ON_ERROR   (0x1)
#define RETURN_ON_ERROR  (0x2)
#define QUIET            (0x4)
#define HEX_BIAS         (0x8)
#define LONG_LONG       (0x10)
#define RETURN_PARTIAL  (0x20)
#define NO_DEVMEM_SWITCH (0x40)

#define KCORE_ELF64    (0x400)

#define LASTCHAR(s)      (s[strlen(s)-1])
#define FIRSTCHAR(s)     (s[0])

#define MAX_HEXADDR_STRLEN (16)

/* debug */
extern int kr_debug;

/* vmlinux */
extern char *current_linux_release;
extern char *current_vmlinux_path;

/* task */
extern unsigned long symbol_init_pid_ns;
extern unsigned long pid_xarray;
extern struct offset_table offset_table;
extern struct size_table size_table;

#define MEMBER_SIZE_REQUEST ((struct datatype_member *)(-1))
#define ANON_MEMBER_OFFSET_REQUEST ((struct datatype_member *)(-2))
#define MEMBER_TYPE_REQUEST ((struct datatype_member *)(-3))
#define STRUCT_SIZE_REQUEST ((struct datatype_member *)(-4))

#define OFFSET(X) (offset_table.X)
#define ASSIGN_OFFSET(X)   (offset_table.X)
#define ASSIGN_SIZE(X)     (size_table.X)

#define STRUCT_SIZE(X)      datatype_info((X), NULL, STRUCT_SIZE_REQUEST)
#define UNION_SIZE(X)       datatype_info((X), NULL, STRUCT_SIZE_REQUEST)

#define MEMBER_OFFSET_INIT(X, Y, Z) (ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))
#define STRUCT_SIZE_INIT(X, Y) (ASSIGN_SIZE(X) = STRUCT_SIZE(Y))
#define MEMBER_OFFSET(X,Y)  datatype_info((X), (Y), NULL)
#define MEMBER_SIZE(X,Y)    datatype_info((X), (Y), MEMBER_SIZE_REQUEST)
#define MEMBER_TYPE(X,Y)    datatype_info((X), (Y), MEMBER_TYPE_REQUEST)

#define VALID_SIZE(X)      (size_table.X >= 0)
#define VALID_STRUCT(X)    (size_table.X >= 0)
#define VALID_MEMBER(X)    (offset_table.X >= 0)

/* FIXME */
#define IS_TASK_ADDR(X)    (1)

struct task_table {                      /* kernel/local task table data */
	struct task_context *current;
	struct task_context *context_array;
	void (*refresh_task_table)(void);
	unsigned long flags;
	unsigned long task_start;
	unsigned long task_end;
	void *task_local;
	int max_tasks;
	int nr_threads;
	unsigned long running_tasks;
	unsigned long retries;
	unsigned long panicmsg;
	int panic_processor;
	unsigned long *idle_threads;
	unsigned long *panic_threads;
	unsigned long *active_set;
	unsigned long *panic_ksp;
	unsigned long *hardirq_ctx;
	unsigned long *hardirq_tasks;
	unsigned long *softirq_ctx;
	unsigned long *softirq_tasks;
	unsigned long panic_task;
	unsigned long this_task;
	int pidhash_len;
	unsigned long pidhash_addr;
	unsigned long last_task_read;
	unsigned long last_thread_info_read;
	unsigned long last_mm_read;
	char *task_struct;
	char *thread_info;
	char *mm_struct;
	unsigned long init_pid_ns;
	//struct tgid_context *tgid_array;
	//struct tgid_context *last_tgid;
	unsigned long tgid_searches;
	unsigned long tgid_cache_hits;
	long filepages;
	long anonpages;
	unsigned long stack_end_magic;
	unsigned long pf_kthread;
	unsigned long pid_radix_tree;
	int callbacks;
	struct task_context **context_by_task; /* task_context sorted by task addr */
	unsigned long pid_xarray;
};

static inline int string_exists(char *s) { return (s ? TRUE : FALSE); }
#define STREQ(A, B)      (string_exists((char *)A) && string_exists((char *)B) && \
	(strcmp((char *)(A), (char *)(B)) == 0))
#define STRNEQ(A, B)     (string_exists((char *)A) && string_exists((char *)B) && \
	(strncmp((char *)(A), (char *)(B), strlen((char *)(B))) == 0))

extern char *mkstring(char *s, int size, unsigned long flags, const char *opt);
extern unsigned long htol(char *s, int flags, int *errptr);
extern int file_exists(char *file, struct stat *sp);
extern unsigned long lookup_symbol_from_proc_kallsyms(char *symname);

extern long request_gdb(struct gnu_request *req);
extern long request_pahole(struct gnu_request *req);
#endif
