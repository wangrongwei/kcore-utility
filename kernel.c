#include <stdio.h>


/*
 * vmlinux: including kernel symbol;
 * modules.order: 
 *
 *	these files can help to find func fastly.
 */
char *KERNEL_FILE[] = {
	"vmlinux",
	"Module.symvers",
	"modules.order"
}




