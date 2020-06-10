
#ifndef __KREAD_H__
#define __KREAD_H__

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

void __error_msg(int err_no, const char *fmt, va_list p);
void error_msg(const char *fmt, ...);
void debug_msg(const char *fmt, ...);

#endif



