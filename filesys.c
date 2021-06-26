#include <sys/sysmacros.h>
#include <linux/major.h>
#include <regex.h>
#include <sys/utsname.h>
#include <sys/types.h>    
#include <sys/stat.h>
#include <common.h>

/*
 * Determine whether a file exists, using the caller's stat structure if
 * one was passed in.
 */
int file_exists(char *file, struct stat *sp)
{
	struct stat sbuf;

	if (stat(file, sp ? sp : &sbuf) == 0)
		return TRUE;

	return FALSE;
}

