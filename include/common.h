#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>

typedef uint64_t physaddr_t;

#ifdef __x86_64__
#define X86_64
#endif

#ifdef __aarch64__
#define ARM64
#endif

/* TODO */
extern unsigned int kernel_version[3];
#define THIS_KERNEL_VERSION ((kernel_version[0] << 16) + \
	(kernel_version[1] << 8) + \
	(kernel_version[2]))
#define LINUX(x,y,z) (((unsigned int)(x) << 16) + ((unsigned int)(y) << 8) + (unsigned int)(z))

/*
 * precision lengths for fprintf
 */ 
#define VADDR_PRLEN      (sizeof(char *) == 8 ? 16 : 8)
#define LONG_LONG_PRLEN  (16)
#define LONG_PRLEN       (sizeof(long) == 8 ? 16 : 8)
#define INT_PRLEN        (sizeof(int) == 8 ? 16 : 8)
#define CHAR_PRLEN       (2)
#define SHORT_PRLEN      (4)

#define CENTER       (0x1)
#define LJUST        (0x2)
#define RJUST        (0x4)
#define LONG_DEC     (0x8)
#define LONG_HEX     (0x10)
#define INT_DEC      (0x20)
#define INT_HEX      (0x40)
#define LONGLONG_HEX (0x80)
#define ZERO_FILL   (0x100)
#define SLONG_DEC   (0x200)

#ifdef X86_64
#define NR_CPUS  (8192)

struct arch_machine_descriptor {
	unsigned long flags;
	unsigned long userspace_top;
	unsigned long page_offset;
	unsigned long vmalloc_start_addr;
	unsigned long vmalloc_end;
	unsigned long vmemmap_vaddr;
	unsigned long vmemmap_end;
	unsigned long modules_vaddr;
	unsigned long modules_end;
	unsigned long phys_offset;
	unsigned long __exception_text_start;
	unsigned long __exception_text_end;
	// struct arm64_pt_regs *panic_task_regs;
	unsigned long PTE_PROT_NONE;
	unsigned long PTE_FILE;
	unsigned long VA_BITS;
	unsigned long __SWP_TYPE_BITS;
	unsigned long __SWP_TYPE_SHIFT;
	unsigned long __SWP_TYPE_MASK;
	unsigned long __SWP_OFFSET_BITS;
	unsigned long __SWP_OFFSET_SHIFT;
	unsigned long __SWP_OFFSET_MASK;
	unsigned long crash_kexec_start;
	unsigned long crash_kexec_end;
	unsigned long crash_save_cpu_start;
	unsigned long crash_save_cpu_end;
	unsigned long kernel_flags;
	unsigned long irq_stack_size;
	unsigned long *irq_stacks;
	char  *irq_stackbuf;
	unsigned long __irqentry_text_start;
	unsigned long __irqentry_text_end;
	/* for exception vector code */
	unsigned long exp_entry1_start;
	unsigned long exp_entry1_end;
	unsigned long exp_entry2_start;
	unsigned long exp_entry2_end;
	/* only needed for v4.6 or later kernel */
	unsigned long kimage_voffset;
	unsigned long kimage_text;
	unsigned long kimage_end;
	unsigned long user_eframe_offset;
	/* for v4.14 or later */
	unsigned long kern_eframe_offset;
	unsigned long machine_kexec_start;
	unsigned long machine_kexec_end;
	unsigned long VA_BITS_ACTUAL;
	unsigned long CONFIG_ARM64_VA_BITS;
	unsigned long VA_START;
	unsigned long CONFIG_ARM64_KERNELPACMASK;
	unsigned long physvirt_offset;
};

#define PAGEBASE(X)   (((unsigned long)(X)) & (unsigned long)kcoreinfo->pagemask)
#endif

#ifdef ARM64
#define NR_CPUS  (4096)   /* TBD */

struct arch_machine_descriptor {
	unsigned long flags;
	unsigned long userspace_top;
	unsigned long page_offset;
	unsigned long vmalloc_start_addr;
	unsigned long vmalloc_end;
	unsigned long vmemmap_vaddr;
	unsigned long vmemmap_end;
	unsigned long modules_vaddr;
	unsigned long modules_end;
	unsigned long phys_offset;
	unsigned long __exception_text_start;
	unsigned long __exception_text_end;
	// struct arm64_pt_regs *panic_task_regs;
	unsigned long PTE_PROT_NONE;
	unsigned long PTE_FILE;
	unsigned long VA_BITS;
	unsigned long __SWP_TYPE_BITS;
	unsigned long __SWP_TYPE_SHIFT;
	unsigned long __SWP_TYPE_MASK;
	unsigned long __SWP_OFFSET_BITS;
	unsigned long __SWP_OFFSET_SHIFT;
	unsigned long __SWP_OFFSET_MASK;
	unsigned long crash_kexec_start;
	unsigned long crash_kexec_end;
	unsigned long crash_save_cpu_start;
	unsigned long crash_save_cpu_end;
	unsigned long kernel_flags;
	unsigned long irq_stack_size;
	unsigned long *irq_stacks;
	char  *irq_stackbuf;
	unsigned long __irqentry_text_start;
	unsigned long __irqentry_text_end;
	/* for exception vector code */
	unsigned long exp_entry1_start;
	unsigned long exp_entry1_end;
	unsigned long exp_entry2_start;
	unsigned long exp_entry2_end;
	/* only needed for v4.6 or later kernel */
	unsigned long kimage_voffset;
	unsigned long kimage_text;
	unsigned long kimage_end;
	unsigned long user_eframe_offset;
	/* for v4.14 or later */
	unsigned long kern_eframe_offset;
	unsigned long machine_kexec_start;
	unsigned long machine_kexec_end;
	unsigned long VA_BITS_ACTUAL;
	unsigned long CONFIG_ARM64_VA_BITS;
	unsigned long VA_START;
	unsigned long CONFIG_ARM64_KERNELPACMASK;
	unsigned long physvirt_offset;
};

#define PAGEBASE(X)   (((unsigned long)(X)) & (unsigned long)kcoreinfo->pagemask)
#endif

#define PAGEOFFSET(X) (((unsigned long)(X)) & kcoreinfo->pageoffset)
/*
 * 48-bit physical address supported. 
 */
#define PHYS_MASK_SHIFT   (48)
#define PHYS_MASK         (((1UL) << PHYS_MASK_SHIFT) - 1)

typedef signed int s32;

/*
 * 3-levels / 4K pages
 */
#define PTRS_PER_PGD_L3_4K   (512)
#define PTRS_PER_PMD_L3_4K   (512)
#define PTRS_PER_PTE_L3_4K   (512)
#define PGDIR_SHIFT_L3_4K    (30)
#define PGDIR_SIZE_L3_4K     ((1UL) << PGDIR_SHIFT_L3_4K)
#define PGDIR_MASK_L3_4K     (~(PGDIR_SIZE_L3_4K-1))
#define PMD_SHIFT_L3_4K      (21)
#define PMD_SIZE_L3_4K       (1UL << PMD_SHIFT_L3_4K)
#define PMD_MASK_L3_4K       (~(PMD_SIZE_L3_4K-1))

/*
 * 4-levels / 4K pages
 * 48-bit VA
 */
#define PTRS_PER_PGD_L4_4K   ((1UL) << (48 - 39))
#define PTRS_PER_PUD_L4_4K   (512)
#define PTRS_PER_PMD_L4_4K   (512)
#define PTRS_PER_PTE_L4_4K   (512)
#define PGDIR_SHIFT_L4_4K    (39)
#define PGDIR_SIZE_L4_4K     ((1UL) << PGDIR_SHIFT_L4_4K)
#define PGDIR_MASK_L4_4K     (~(PGDIR_SIZE_L4_4K-1))
#define PUD_SHIFT_L4_4K      (30)
#define PUD_SIZE_L4_4K       ((1UL) << PUD_SHIFT_L4_4K)
#define PUD_MASK_L4_4K       (~(PUD_SIZE_L4_4K-1))
#define PMD_SHIFT_L4_4K      (21)
#define PMD_SIZE_L4_4K       (1UL << PMD_SHIFT_L4_4K)
#define PMD_MASK_L4_4K       (~(PMD_SIZE_L4_4K-1))

#define PGDIR_SIZE_48VA      (1UL << ((48 - 39) + 3))
#define PGDIR_MASK_48VA      (~(PGDIR_SIZE_48VA - 1))
#define PGDIR_OFFSET_48VA(X) (((unsigned long)(X)) & (PGDIR_SIZE_48VA - 1))

/*
 * Software defined PTE bits definition.
 * (arch/arm64/include/asm/pgtable.h)
 */
#define PTE_VALID       (1UL << 0)
#define PTE_DIRTY       (1UL << 55)
#define PTE_SPECIAL     (1UL << 56)

/*
 * Level 3 descriptor (PTE).
 * (arch/arm64/include/asm/pgtable-hwdef.h)
 */
#define PTE_TYPE_MASK   (3UL << 0)
#define PTE_TYPE_FAULT  (0UL << 0)
#define PTE_TYPE_PAGE   (3UL << 0)
#define PTE_USER        (1UL << 6)         /* AP[1] */
#define PTE_RDONLY      (1UL << 7)         /* AP[2] */
#define PTE_SHARED      (3UL << 8)         /* SH[1:0], inner shareable */
#define PTE_AF          (1UL << 10)        /* Access Flag */
#define PTE_NG          (1UL << 11)        /* nG */
#define PTE_PXN         (1UL << 53)        /* Privileged XN */
#define PTE_UXN         (1UL << 54)        /* User XN */

#define ULONG(ADDR)     *((unsigned long *)((char *)(ADDR)))

#define KILOBYTES(x)  ((x) * (1024))
#define MEGABYTES(x)  ((x) * (1048576))
#define GIGABYTES(x)  ((x) * (1073741824))
#define TB_SHIFT (40)
#define TERABYTES(x) ((x) * (1UL << TB_SHIFT))

#define MEGABYTE_MASK (MEGABYTES(1)-1)

#define VMEMMAP           (0x400000)

extern struct task_table *tt;
/*
 * Global "tt" points to task_table
 */
#define CURRENT_CONTEXT() (tt->current)
#define CURRENT_TASK()    (tt->current->task)
#define CURRENT_PID()     (tt->current->pid)
#define CURRENT_COMM()    (tt->current->comm)
#define RUNNING_TASKS()   (tt->running_tasks)
#define FIRST_CONTEXT()   (tt->context_array)

#define NO_PID   ((unsigned long)-1)
#define NO_TASK  (0)

#ifndef FALSE
#define FALSE   (0)
#endif

#ifndef TRUE
#define TRUE    (!FALSE)
#endif

#define MAX(a,b) (a > b ? a : b)

struct do_xarray_info {
	unsigned long maxcount;
	unsigned long count;
	void *data;
};

struct xarray_ops {
	void (*entry)(unsigned long node, unsigned long slot, const char *path,
		unsigned long index, void *private);
	unsigned int radix;
	void *private;
};

struct list_pair {
	unsigned long index;
	void *value;
};

#define XARRAY_COUNT   (1)
#define XARRAY_SEARCH  (2)
#define XARRAY_DUMP    (3)
#define XARRAY_GATHER  (4)
#define XARRAY_DUMP_CB (5)
#define XARRAY_TAG_MASK      (3UL)
#define XARRAY_TAG_INTERNAL  (2UL)

#endif
