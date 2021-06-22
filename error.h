#ifndef __ERROR_H__
#define __ERROR_H__

#include <stdlib.h>

#define ENORI	126
#define ENOEXIST 127

static inline void
errmsg(char doexit, int excode, char adderr, const char *fmt, ...)
{
	fprintf(stderr, "%s: ", "kread");
	if (fmt != NULL) {
		va_list argp;
		va_start(argp, fmt);
		vfprintf(stderr, fmt, argp);
		va_end(argp);
		if (adderr)
			fprintf(stderr, ": ");
	}
	if (adderr)
		fprintf(stderr, "%m");
	fprintf(stderr, "\n");
	if (doexit)
		exit(excode);
}

#ifndef HAVE_ERR
# define err(E, FMT...) errmsg(1, E, 1, FMT)
#endif

#endif
