#include <stdio.h>
#include "kernel.h"
#include "common.h"

/* FIXME */
unsigned long kernel_pgd[NR_CPUS];

extern struct mach_table *kcoreinfo;

/*
 * For processors with "traditional" kernel/user address space distinction.
 */
int generic_is_kvaddr(unsigned long addr)
{
	return (addr >= (unsigned long)(kcoreinfo->kvbase));
}

/*
 * NOTE: Perhaps even this generic version should tighten up requirements
 *        by calling uvtop()?
 */
int generic_is_uvaddr(unsigned long addr, struct task_context *tc)
{
	return (addr < ULONG(kcoreinfo->kvbase));
}

/*
 * vmlinux: including kernel symbol;
 * modules.order: 
 * System.map: complied address and symbol name;
 * compile_commands.json: .c file and deps files;
 *
 *	these files can help KREAD to find func fastly.
 */
char *KERNEL_FILE[] = {
	"vmlinux",
	"Module.symvers",
	"System.map",
	"compile_commands.json",
	NULL
};

