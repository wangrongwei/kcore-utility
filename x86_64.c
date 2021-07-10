#include "kernel.h"
#include "error.h"

/*
 * Translate kvaddr into paddr.
 */
int
x86_kvtop(struct task_context *tc, unsigned long kvaddr, physaddr_t *paddr, int verbose)
{
	return -1;
}
