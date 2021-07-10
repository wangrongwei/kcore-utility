#ifndef __ERROR_H__
#define __ERROR_H__

#include <stdio.h>
#include <stdlib.h>

#define ENORI	126
#define ENOEXIST 127

#define INFO           (1)
#define FATAL          (2)
#define FATAL_RESTART  (3)
#define WARNING        (4)
#define NOTE           (5)
#define CONT           (6)

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

static void error (int line, const char *errmsg)
{
	fprintf (stderr, "error: %d: %s\n", line, errmsg);
	//++error_count;
}

static void warn (int line, const char *msg)
{
	fprintf (stdout, "warn: %d: %s\n", line, msg);
}

#define ERROR(ERRMSG) error (__LINE__, ERRMSG)
#define WARN(MSG) warn (__LINE__, MSG)
#endif
