#ifndef __MM_H__
#define __MM_H__

#define PAGE_SIZE 4096
#define PAGE_SIZE_2MB (2*1024*1024)

struct vma {
	long start_addr;
	long end_addr;
	char *prot;
};

struct node_stat {
	long nr;
};

#endif