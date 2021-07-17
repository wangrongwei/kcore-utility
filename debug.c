#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <signal.h> /* for signal */
#include <execinfo.h> /* for backtrace() */
#include <errno.h>

#define BACKTRACE_SIZE 16

void dump_stack(void)
{
	int j, nptrs;
	void *buffer[BACKTRACE_SIZE];
	char **strings;

	nptrs = backtrace(buffer, BACKTRACE_SIZE);
	printf("backtrace() returned %d addresses\n", nptrs);

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		exit(EXIT_FAILURE);
	}

	for (j = 0; j < nptrs; j++)
		printf("  [%02d] %s\n", j, strings[j]);

	free(strings);
}

void signal_handler(int signo)
{
	printf("\n---------->catch signal %d<----------\n", signo);
	printf("dump stack start...\n");
	dump_stack();
	printf("dump stack end...\n");

	signal(signo, SIG_DFL);
	raise(signo);
}

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

