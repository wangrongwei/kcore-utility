/*
 * some feature.
 */
#include <stdio.h>
#include <kread_fature.h>


/*
 * print the callstack of specify function.
 *
 */
void callstack(unsigned int fea_code)
{


}

/*
 * ONLY print all sub function name of specify function
 * 	fea_code
 */
void recursive_traversal(unsigned int fea_code)
{

}


void find_func_declaration(char *func_name)
{
	/* ONLY to find the DECLARATION place of a function */
	char *target_file;
	
	if (check_function(func_name) < 0) {
		fprintf(stderr,
			"NOT find %s", func_name);
	}
	
}




