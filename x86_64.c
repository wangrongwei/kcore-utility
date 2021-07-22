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

/*
 * Translate uvaddr into paddr.
 */
int
x86_uvtop(struct task_context *tc, unsigned long uvaddr, physaddr_t *paddr, int verbose)
{
	return -1;
}
