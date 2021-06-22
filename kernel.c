#include <stdio.h>


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

