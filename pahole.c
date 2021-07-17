#include <unistd.h>
#include <sys/wait.h>
#include "kcore.h"
#include "kread.h"

#include "gdb.h"

long exec_cmd_return_long(char *cmd)
{
	char buf[100] = {'\0'};
	int des_p[2], pid;
	int nbytes;

	if(pipe(des_p) == -1) {
		perror("Pipe failed");
		exit(1);
	}

	pid = fork();
	if(pid == 0) {
		close(STDOUT_FILENO);
		/* replacing stdout with pipe write */
		dup2(des_p[1], STDOUT_FILENO);
		close(des_p[0]);

		system(cmd);
		exit(0);
	} else {
		/* parent */
		int status;
		close(des_p[1]);
		waitpid(pid, &status, 0);
		nbytes = read(des_p[0], buf, sizeof(buf));
		if (kr_debug) {
			printf("cmd: %s\n", cmd);
			printf("struct size: %s\n", buf);
		}
		if (buf[0] == '\0') {
			return -1;
		}
	}

	return strtol(buf, NULL, 0);
}

long request_pahole_member_number(char *name)
{
	long size = 0;
	char buf[100];

	sprintf(buf, "pahole %s -n|grep -m 1 %s|awk \'{print $2}\'",
		current_vmlinux_path, name);
	size = exec_cmd_return_long(buf);
	return size;
}


