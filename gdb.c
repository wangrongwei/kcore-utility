#include "gdb.h"

/* 
 *  Stash a copy of the gdb version locally.  This can be called before
 *  gdb gets initialized, so bypass gdb_interface().
 */
void get_gdb_version(void)
{
        struct gnu_request request;
#if 0
	if (!pc->gdb_version) {
        	request.command = GNU_VERSION;
		gdb_command_funnel(&request);    /* bypass gdb_interface() */
		pc->gdb_version = request.buf;
	}
#endif
}