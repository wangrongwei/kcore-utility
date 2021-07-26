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

/* ffs -- Find the first bit set in the parameter

@deftypefn Supplemental int ffs (int @var{valu})

Find the first (least significant) bit set in @var{valu}.  Bits are
numbered from right to left, starting with bit 1 (corresponding to the
value 1).  If @var{valu} is zero, zero is returned.

@end deftypefn

*/
int ffs(register int valu)
{
	register int bit;

	if (valu == 0)
		return 0;

	for (bit = 1; !(valu & 1); bit++)
		valu >>= 1;

	return bit;
}