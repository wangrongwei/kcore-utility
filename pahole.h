#ifndef __PAHOLE_H__
#define __PAHOLE_H__

extern long exec_cmd_return_long(char *cmd, int base);
extern unsigned long exec_cmd_return_ulong(char *cmd, int base);
extern long request_pahole_member_number(char *name);
#endif
