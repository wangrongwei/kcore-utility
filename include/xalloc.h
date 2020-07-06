
#ifndef __KREAD_H__
#define __KREAD_H__

#include <stdlib.h>
#include <string.h>

#include <error.h>

static inline
__attribute__((warn_unused_result))
__ul_returns_nonnull
char *xstrdup(const char *str)
{
	char *ret;

	assert(str);
	ret = strdup(str);
	if (!ret)
		err(XALLOC_EXIT_CODE, "cannot duplicate string");
	return ret;
}


#endif

