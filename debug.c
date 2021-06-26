#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

static void __error_msg(int err_no, const char *fmt, va_list p)
{
	char *msg;

	fflush(NULL);

	msg = NULL;
	if (vasprintf(&msg, fmt, p) >= 0) {
		if (err_no)
			fprintf(stderr, "%s: %s\n", msg, strerror(err_no));
		else
			fprintf(stderr, "%s\n", msg);
		free(msg);
	} 
	else {
		vfprintf(stderr, fmt, p);
		if (err_no)
			fprintf(stderr, ": %s\n", strerror(err_no));
		else
			putc('\n', stderr);
	}
}

void error_msg(const char *fmt, ...)
{
	va_list p;
	va_start(p, fmt);
	__error_msg(errno, fmt, p);
	va_end(p);
}

#ifdef DEBUG
void debug_msg(const char *fmt, ...)
{
	va_list p;
	va_start(p, fmt);
	printf(fmt, p);
	va_end(p);
}

#else
void debug_msg(const char *fmt, ...)
{

}

#endif

