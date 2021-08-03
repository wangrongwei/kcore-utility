#include "common.h"
#include "kcore.h"
#include "kernel.h"
#include "mm.h"

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
	if (tt->task_struct == NULL)
		tt->task_struct = (char *)malloc(ASSIGN_SIZE(task_struct));
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
	pid_t scan_pid;

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
		/*
		 * FIXME
		 * pids in task_struct is NOT valid member.
		 */
		if (VALID_MEMBER(task_struct_pids))
			task_addr = pid_tasks_0 - OFFSET(task_struct_pids);
		else
			task_addr = pid_tasks_0 - OFFSET(task_struct_pid_links);

		if (kr_debug)
			printf("pid: %lx  ns: %lx  tasks[0]: %lx task: %lx\n",
				next, upid_ns, pid_tasks_0, task_addr);

		readmem(task_addr + OFFSET(task_struct_pid), KVADDR, &scan_pid,
			sizeof(pid_t), "pid", RETURN_ON_ERROR|QUIET);
		if (!IS_TASK_ADDR(task_addr)) {
			printf("IDR xarray: invalid task address: %lx\n", task_addr);
			retries++;
			goto retry_xarray;
		}

		cnt++;
		if (target != -1 && scan_pid == target)
			goto find;
	}

	if (!task_addr) {
		return NULL;
	}

find:
	free(pidbuf);
	tt->retries = MAX(tt->retries, retries);

	return fill_task_struct(task_addr);
}

void dump_task(pid_t pid)
{
	char *task = NULL;
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
	if (!task) {
		ERROR("Not find task");
		return;
	}

	/* dump comm pid */
	printf("comm: %s\n", task + OFFSET(task_struct_comm));
}

void *init_vma(pid_t pid, int *nr_vma)
{
	int maps_lines;
	char buf[100]={0};
	struct vma *vma_array;

	sprintf(buf, "cat /proc/%d/maps | awk \'END{print NR}\'", pid);
	maps_lines = exec_cmd_return_long(buf);
	*nr_vma = maps_lines;
	vma_array = (struct vma*)malloc(maps_lines * sizeof(struct vma));
	for (int i=0; i<maps_lines; i++) {
		memset(buf, '\0', 100);
		sprintf(buf, "cat /proc/%d/maps | awk \'NR==%d\' | tr \'-\' \' \' | awk \'{print $1}\'", i+1, pid);
		vma_array[i].start_addr = exec_cmd_return_long(buf);
		memset(buf, '\0', 100);
		sprintf(buf, "cat /proc/%d/maps | awk \'NR==%d\' | tr \'-\' \' \' | awk \'{print $2}\'", i+1, pid);
		vma_array[i].end_addr = exec_cmd_return_long(buf);
		memset(buf, '\0', 100);
		sprintf(buf, "cat /proc/%d/maps | awk \'NR==%d\' | awk \'{print $2}\'", i+1, pid);
		vma_array[i].prot = exec_cmd_return_string(buf);
	}

	return vma_array;
}

#define NODES_SHIFT 3
#define NODES_WIDTH		NODES_SHIFT
#define NODES_MASK		((1UL << NODES_WIDTH) - 1)

#define SECTIONS_WIDTH 0
#define SECTIONS_PGOFF		((sizeof(unsigned long)*8) - SECTIONS_WIDTH)
#define NODES_PGOFF		(SECTIONS_PGOFF - NODES_WIDTH)
#define NODES_PGSHIFT		(NODES_PGOFF * (NODES_WIDTH != 0))

/*
 * This function is mainly to convert page_flags into
 * node number.
 *
 * In most time, the kernel config will affect this
 * function. The below function depend on:
 * 	1. CONFIG_SPARSEMEM=y
 * 	2. CONFIG_VMEMMAP=y
 * 	3. CONFIG_NODES_SHIFT=3
 */
static inline int page_to_nid(long page_flags)
{
	return (page_flags >> NODES_PGSHIFT) & NODES_MASK;
}

/*
 * Show the distribution of pgtable.
 *
 * static inline int page_to_nid(const struct page *page)
 * {
 * 	struct page *p = (struct page *)page;
 *
 * 	return (PF_POISONED_CHECK(p)->flags >> NODES_PGSHIFT) & NODES_MASK;
 * }
 *
 * Consider the difference of data, such as text, data and DSOs pgtable.
 * And the different data maybe have various of affect. So, it is necessary
 * to stat each of pgtable separately.
 */
void stat_pgtable(pid_t pid)
{
	struct vma *vma;
	struct node_stat pgtable_stat[4];
	long flags;
	int nr_vma = 0;

	STRUCT_SIZE_INIT(page, "page");
	MEMBER_OFFSET_INIT(page_flags, "page", "page_flags");

	vma = init_vma(pid, &nr_vma);
	long sz = PAGE_SIZE;
	for(int i=0; i<nr_vma; i++) {
		for (long addr=vma[i].start_addr; addr<vma[i].end_addr; addr += sz) {
			arm64_get_pgtable(NULL, addr, &flags, &sz, 1);
			pgtable_stat[page_to_nid(flags)].nr++;
		}
	}

	/*
	 * FIXME: The number of node is required from system, not set 4
	 * directly.
	 */
	printf("pgtable stat:\n");
	for (int i=0; i<4; i++) {
		printf("node %d: %d\n", i, pgtable_stat[i].nr);
	}
	return;
}

void dump_pte(pid_t pid, unsigned long uvaddr)
{
	unsigned long mm, paddr;
	struct task_context target_context;

	if (tt->last_task_read == 0) {
		ERROR("dump pte failed, task address is not setting");
	}

	target_context.mm_struct = ULONG(tt->task_struct + OFFSET(task_struct_mm));
	uvtop(&target_context, uvaddr, &paddr, 1);
	return;
}

