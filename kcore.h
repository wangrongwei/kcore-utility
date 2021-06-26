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

#define TASK_COMM_LEN 16     /* task command name length including NULL */

/* vmlinux */
extern char *current_linux_release;
extern char *current_vmlinux_path;

/* task */
extern unsigned long symbol_init_pid_ns;
extern unsigned long pid_xarray;
extern struct offset_table offset_table;
extern struct size_table size_table;

#define STRUCT_SIZE_REQUEST ((struct datatype_member *)(-4))

#define OFFSET(X) (offset_table.X)
#define ASSIGN_OFFSET(X)   (offset_table.X)
#define ASSIGN_SIZE(X)     (size_table.X)

#define STRUCT_SIZE(X)      datatype_info((X), NULL, STRUCT_SIZE_REQUEST)
#define UNION_SIZE(X)       datatype_info((X), NULL, STRUCT_SIZE_REQUEST)

#define MEMBER_OFFSET_INIT(X, Y, Z) (ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))
#define STRUCT_SIZE_INIT(X, Y) (ASSIGN_SIZE(X) = STRUCT_SIZE(Y))
#define MEMBER_OFFSET(X,Y)  datatype_info((X), (Y), NULL)

struct task_context {       /* context stored for each task */
	unsigned long task;
	unsigned long thread_info;
	unsigned long pid;
	char comm[TASK_COMM_LEN+1];
	int processor;
	unsigned long ptask;
	unsigned long mm_struct;
	struct task_context *tc_next;
};



static inline int string_exists(char *s) { return (s ? TRUE : FALSE); }
#define STREQ(A, B)      (string_exists((char *)A) && string_exists((char *)B) && \
	(strcmp((char *)(A), (char *)(B)) == 0))
#define STRNEQ(A, B)     (string_exists((char *)A) && string_exists((char *)B) && \
	(strncmp((char *)(A), (char *)(B), strlen((char *)(B))) == 0))

extern int file_exists(char *file, struct stat *sp);

extern long request_gdb(struct gnu_request *req);
extern long request_pahole(struct gnu_request *req);
#endif
