#include "common.h"
#include "kcore.h"
#include "kernel.h"

#include "error.h"

#define TASK_SLUSH (20)
#define MAX_UNLIMITED_TASK_RETRIES (500)

struct task_table task_table = { 0 };
struct task_table *tt = &task_table;

/*
 *  Allocate or re-allocated space for the task_context array and task list.
 */
static void
allocate_task_space(int cnt)
{
	if (tt->context_array == NULL) {
		if (!(tt->task_local = (void *)malloc(cnt * sizeof(void *))))
			fprintf(stderr, "cannot malloc kernel task array (%d tasks)", cnt);

		if (!(tt->context_array = (struct task_context *)malloc(cnt * sizeof(struct task_context))))
			printf(stderr, "cannot malloc context array (%d tasks)", cnt);
		if (!(tt->context_by_task = (struct task_context **)malloc(cnt * sizeof(struct task_context*))))
			fprintf(stderr, "cannot malloc context_by_task array (%d tasks)",
				cnt);
		/*
		 * if (!(tt->tgid_array = (struct tgid_context *)malloc(cnt * sizeof(struct tgid_context))))
		 * 	fprintf("cannot malloc tgid array (%d tasks)",
		 * 		cnt);
		 */
	} else {
		if (!(tt->task_local = (void *)realloc(tt->task_local, cnt * sizeof(void *))))
			fprintf(stderr, "cannot realloc kernel task array (%d tasks)", cnt);

		if (!(tt->context_array = (struct task_context *)realloc(tt->context_array,
				cnt * sizeof(struct task_context))))
			fprintf(stderr, "cannot realloc context array (%d tasks)", cnt);

		if (!(tt->context_by_task = (struct task_context **)realloc(tt->context_by_task,
				cnt * sizeof(struct task_context*))))
			fprintf(stderr, "cannot realloc context_by_task array (%d tasks)", cnt);

		/*
		 * if (!(tt->tgid_array = (struct tgid_context *)realloc(tt->tgid_array,
		 * 		cnt * sizeof(struct tgid_context))))
		 * 	fprintf(stderr, "%scannot realloc tgid array (%d tasks)",
		 * 		(pc->flags & RUNTIME) ? "" : "\n", cnt);
		 */
	}
}

char * fill_task_struct(unsigned long task)
{
	if (!readmem(task, KVADDR, tt->task_struct, ASSIGN_SIZE(task_struct), "fill_task_struct",
			RETURN_ON_ERROR)) {
		tt->last_task_read = 0;
		return NULL;
	}

	tt->last_task_read = task;
	return tt->task_struct;
}

/*
 *  Linux 4.20: pid_hash[] IDR changed from radix tree to xarray
 */
static int xarray_task_callback(unsigned long task)
{
	unsigned long *tlp;

	if (tt->callbacks < tt->max_tasks) {
		tlp = (unsigned long *)tt->task_local;
		tlp += tt->callbacks++;
		*tlp = task;
	}

	return TRUE;
}

static char * lookup_task_xarray_task_table(pid_t target)
{
	int i, cnt;
	unsigned long count, retries, next, curtask, curpid, upid_ns, pid_tasks_0, task_addr;
	unsigned long *tlp;
	char *tp;
	struct list_pair xp;
	char *pidbuf;

	curpid = NO_PID;
	curtask = NO_TASK;

	count = do_xarray(pid_xarray, XARRAY_COUNT, NULL);
	if (1)
		printf("xarray: count: %ld\n", count);

	retries = 0;
	pidbuf = (char *)malloc(ASSIGN_SIZE(pid));

retry_xarray:
	if (retries)
		printf("\ncannot gather a stable task list via xarray\n");

	if (retries == MAX_UNLIMITED_TASK_RETRIES) {
		printf("\ncannot gather a stable task list via xarray (%d retries)\n",
			retries);
		exit(-1);
	}

	if (count > tt->max_tasks) {
		tt->max_tasks = count + TASK_SLUSH;
		allocate_task_space(tt->max_tasks);
	}

	memset(tt->task_local, '\0', count * sizeof(void *));
	tt->callbacks = 0;
	xp.index = 0;
	xp.value = (void *)&xarray_task_callback;
	count = do_xarray(pid_xarray, XARRAY_DUMP_CB, &xp);
	if (kr_debug)
		printf("do_xarray: count: %ld  tt->callbacks: %d\n", count, tt->callbacks);

	if (count > tt->max_tasks) {
		retries++;
		goto retry_xarray;
	}

	for (i = 0; i < count; i++) {
		tlp = (unsigned long *)tt->task_local;
		tlp += i;
		if ((next = *tlp) == 0)
			break;

		/*
		 * Translate xarray contents to PIDTYPE_PID task.
		 *  - the xarray contents are struct pid pointers
		 *  - upid is contained in pid.numbers[0]
		 *  - upid.ns should point to init->init_pid_ns
		 *  - pid->tasks[0] is first hlist_node in task->pids[3]
		 *  - get task from address of task->pids[0]
		 */
		if (!readmem(next, KVADDR, pidbuf, ASSIGN_SIZE(pid),
				"pid", RETURN_ON_ERROR|QUIET)) {
			printf("\ncannot read pid struct from xarray\n");
			retries++;
			goto retry_xarray;
		}

		upid_ns = ULONG(pidbuf + OFFSET(pid_numbers) + OFFSET(upid_ns));
		if (upid_ns != tt->init_pid_ns)
			continue;
		pid_tasks_0 = ULONG(pidbuf + OFFSET(pid_tasks));
		if (!pid_tasks_0)
			continue;
		if (VALID_MEMBER(task_struct_pids))
			task_addr = pid_tasks_0 - OFFSET(task_struct_pids);
		else
			task_addr = pid_tasks_0 - OFFSET(task_struct_pid_links);

		if (kr_debug)
			printf("pid: %lx  ns: %lx  tasks[0]: %lx task: %lx\n",
				next, upid_ns, pid_tasks_0, task_addr);

		if (!IS_TASK_ADDR(task_addr)) {
			printf("IDR xarray: invalid task address: %lx\n", task_addr);
			retries++;
			goto retry_xarray;
		}

		cnt++;
		if (target != -1 && upid_ns == target)
			goto find;
	}

find:
	free(pidbuf);
	tt->retries = MAX(tt->retries, retries);

	return fill_task_struct(task_addr);
}

void dump_task(pid_t pid)
{
	char *task;
	int pid_max;
	char buf[] = "cat /proc/sys/kernel/pid_max";
	char comm[TASK_COMM_LEN];

	MEMBER_OFFSET_INIT(task_struct_comm, "task_struct", "comm");
	MEMBER_OFFSET_INIT(task_struct_pid, "task_struct", "pid");
	pid_max = exec_cmd_return_long(buf);
	if (pid > pid_max) {
		fprintf(stderr, "pid: %d beyond pid_max (%d)", pid, pid_max);
		return;
	}
	/* task is a physical address */
	task = lookup_task_xarray_task_table(pid);

	/*
	 * dump comm pid
	 */
	if (!readmem(task, PHYSADDR, comm, TASK_COMM_LEN,
				"comm", RETURN_ON_ERROR|QUIET)) {
		fprintf(stderr, "\ncannot read comm from task_struct\n");
		return;
	}
	printf("comm: %s\n", comm);
}

void stat_pgtable(pid_t pid)
{
	return;
}

void dump_pte(pid_t pid, unsigned long addr)
{
	return;
}

