#ifndef __KREAD_H__
#define __KREAD_H__

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <elf.h>
#include <sys/types.h>
#include "common.h"
#include "error.h"

#define memmove(d, s, n) memcpy(d, s, n)

#define MAX_KCORE_ELF_HEADER_SIZE (32768)
#define PADDR_NOT_AVAILABLE (0x1ULL)
#define KCORE_USE_VADDR      (-1ULL)

typedef unsigned long long int ulonglong;

#define SEEK_ERROR       (-1)
#define READ_ERROR       (-2)
#define WRITE_ERROR      (-3)
#define PAGE_EXCLUDED    (-4)

struct proc_kcore_data {
	unsigned int flags;
	unsigned int segments;
	char *elf_header;
	size_t header_size;
	Elf64_Phdr *load64;
	Elf64_Phdr *notes64;
	Elf32_Phdr *load32;
	Elf32_Phdr *notes32;
	void *vmcoreinfo;
	unsigned int size_vmcoreinfo;
};

#define KSYMS_START   (0x1)
#define PHYS_OFFSET   (0x2)
#define VM_L2_64K     (0x4)
#define VM_L3_64K     (0x8)
#define VM_L3_4K      (0x10)
#define KDUMP_ENABLED (0x20)
#define IRQ_STACKS    (0x40)
#define NEW_VMEMMAP   (0x80)
#define VM_L4_4K      (0x100)
#define UNW_4_14      (0x200)

#ifdef ARM64
#define _64BIT_
#define MACHINE_TYPE "ARM64"

#define PTOV(X) \
	((unsigned long)(X) - (kcoreinfo->mdesp->physvirt_offset))

#define VTOP(X) arm64_VTOP((unsigned long)(X))
#endif

#ifdef X86_64
#define _64BIT_
#define MACHINE_TYPE "x86_64"

#define PTOV(X) \
	((unsigned long)(X) - (kcoreinfo->mdesp->physvirt_offset))

//#define VTOP(X) arm64_VTOP((unsigned long)(X))
#define VTOP(X) 0
#endif

#define BADADDR  ((unsigned long)(-1))
#define BADVAL   ((unsigned long)(-1))
#define UNUSED   (-1)

#define UNINITIALIZED (BADVAL)

extern void __error_msg(int err_no, const char *fmt, va_list p);
extern void error_msg(const char *fmt, ...);
extern void debug_msg(const char *fmt, ...);

extern int file_exists(char *file, struct stat *sp);
extern void symbols_init_from_kallsyms(void);

extern void dump_task(pid_t pid);
extern void stat_pgtable(pid_t pid);
extern void dump_pte(pid_t pid, unsigned long uvaddr);
extern char *KERNEL_FILE[];
#endif
