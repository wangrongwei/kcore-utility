#include "kernel.h"
#include "kcore.h"
#include "kread.h"
#include "pgtable.h"

#include "error.h"

#define PTE_ADDR_LOW   ((((1UL) << (48 - kcoreinfo->pageshift)) - 1) << kcoreinfo->pageshift)
#define PTE_ADDR_HIGH  ((0xfUL) << 12)
#define PTE_TO_PHYS(pteval)  (kcoreinfo->max_physmem_bits == 52 ? \
	(((pteval & PTE_ADDR_LOW) | ((pteval & PTE_ADDR_HIGH) << 36))) : (pteval & PTE_ADDR_LOW))

#define PUD_TYPE_MASK   3
#define PUD_TYPE_SECT   1
#define PMD_TYPE_MASK   3
#define PMD_TYPE_SECT   1
#define PMD_TYPE_TABLE  2
#define SECTION_PAGE_MASK_2MB    ((long)(~((MEGABYTES(2))-1)))
#define SECTION_PAGE_MASK_512MB  ((long)(~((MEGABYTES(512))-1)))
#define SECTION_PAGE_MASK_1GB    ((long)(~((GIGABYTES(1))-1)))

static unsigned long XA_CHUNK_SHIFT = UNINITIALIZED;
static unsigned long XA_CHUNK_SIZE = UNINITIALIZED;
static unsigned long XA_CHUNK_MASK = UNINITIALIZED;

struct mach_table kcoreinfo_data = { 0 };
struct mach_table *kcoreinfo = &kcoreinfo_data;

unsigned long _stext_vmlinux = UNINITIALIZED;

/*
 * Include both vmalloc'd, module and vmemmap address space as VMALLOC space.
 */
int arm64_is_vmalloc_addr(unsigned long vaddr)
{
	struct arch_machine_descriptor *desp = kcoreinfo->mdesp;

	if (desp == NULL) {
		ERROR("kcoreinfo->mdesp is NULL");
		return FALSE;
	}
	if ((kcoreinfo->flags & NEW_VMEMMAP) && (vaddr >= desp->kimage_text) &&
			(vaddr <= desp->kimage_end))
		return FALSE;

	if (VA_START && (vaddr >= VA_START))
		return TRUE;

	return ((vaddr >= desp->vmalloc_start_addr && vaddr <= desp->vmalloc_end) ||
			((kcoreinfo->flags & VMEMMAP) &&
			((vaddr >= desp->vmemmap_vaddr && vaddr <= desp->vmemmap_end) ||
			(vaddr >= desp->vmalloc_end && vaddr <= desp->vmemmap_vaddr))) ||
			(vaddr >= desp->modules_vaddr && vaddr <= desp->modules_end));
}

extern int kcore_fd;
static void
arm64_calc_physvirt_offset(void)
{
	unsigned long physvirt_offset, sp;
	kcoreinfo->mdesp->physvirt_offset =
		kcoreinfo->mdesp->phys_offset - kcoreinfo->mdesp->page_offset;

	if ((sp = lookup_symbol_from_proc_kallsyms("physvirt_offset")) &&
			kcoreinfo->mdesp->kimage_voffset) {
		if (sp == BADVAL)
			return;
		if (read_proc_kcore(kcore_fd, &physvirt_offset, sizeof(physvirt_offset),
			sp, sp - kcoreinfo->mdesp->kimage_voffset) > 0)
		{
			kcoreinfo->mdesp->physvirt_offset = physvirt_offset;
		}
	}
}

static void arm64_calc_kimage_voffset(void)
{
	unsigned long phys_addr = 0;
	unsigned long kimage_voffset, vaddr;
	int errflag;

	if (!kcoreinfo->mdesp) {
		ERROR("kcoreinfo->mdesp is NULL");
		return;
	}

	if (kcoreinfo->mdesp->kimage_voffset) /* vmcoreinfo, ioctl, or --machdep override */
		return;

	kimage_voffset = lookup_symbol_from_proc_kallsyms("kimage_voffset");
	if ((kimage_voffset != BADVAL) && (read_proc_kcore(kcore_fd, &vaddr, sizeof(unsigned long),
		kimage_voffset, KCORE_USE_VADDR) > 0))
	{
		kcoreinfo->mdesp->kimage_voffset = vaddr;
		return;
	}
}

static void arm64_init_kernel_pgd(void)
{
	int i;
	unsigned long value, symbol_init_mm;

	symbol_init_mm = lookup_symbol_from_proc_kallsyms("init_mm");
	if (symbol_init_mm == BADVAL ||
			!readmem(symbol_init_mm + OFFSET(mm_struct_pgd), KVADDR,
				&value, sizeof(void *), "init_mm.pgd", RETURN_ON_ERROR)) {
		value = lookup_symbol_from_proc_kallsyms("swapper_pg_dir");
		if (value == BADVAL) {
			WARN("cannot determine kernel pgd location\n");
			return;
		}
	}

	for (i = 0; i < NR_CPUS; i++)
		kernel_pgd[i] = value;
}

/*
 * Include kernel data/struct
 */
void arm64_kernel_init(void)
{
	kcoreinfo->flags |= VM_L4_4K;
	STRUCT_SIZE_INIT(task_struct, "task_struct");
	MEMBER_OFFSET_INIT(task_struct_mm, "task_struct", "mm");
	MEMBER_OFFSET_INIT(task_struct_tasks, "task_struct", "tasks");
	MEMBER_OFFSET_INIT(mm_struct_mmap, "mm_struct", "mmap");
	MEMBER_OFFSET_INIT(mm_struct_pgd, "mm_struct", "pgd");
	MEMBER_OFFSET_INIT(mm_struct_rss, "mm_struct", "rss");

	MEMBER_OFFSET_INIT(pid_namespace_idr, "pid_namespace", "idr");
	MEMBER_OFFSET_INIT(idr_idr_rt, "idr", "idr_rt");

	STRUCT_SIZE_INIT(pid, "pid");
	STRUCT_SIZE_INIT(xarray, "xarray");
	STRUCT_SIZE_INIT(xa_node, "xa_node");
	MEMBER_OFFSET_INIT(xarray_xa_head, "xarray", "xa_head");
	MEMBER_OFFSET_INIT(xa_node_slots, "xa_node", "slots");
	MEMBER_OFFSET_INIT(xa_node_shift, "xa_node", "shift");
	MEMBER_OFFSET_INIT(pid_numbers, "pid", "numbers");
	MEMBER_OFFSET_INIT(upid_ns, "upid", "ns");
	MEMBER_OFFSET_INIT(pid_tasks, "pid", "tasks");
	// MEMBER_OFFSET_INIT(task_struct_pids, "task_struct", "pids");
	MEMBER_OFFSET_INIT(task_struct_pid_links, "task_struct", "pid_links");
	ASSIGN_OFFSET(task_struct_pids) = -1;

	kcoreinfo->mdesp =
		(struct arch_machine_descriptor *)malloc(sizeof(struct arch_machine_descriptor));
	if (VA_BITS_ACTUAL) {
		kcoreinfo->mdesp->page_offset = ARM64_PAGE_OFFSET_ACTUAL;
		kcoreinfo->kvbase = ARM64_PAGE_OFFSET_ACTUAL;
	} else {
		kcoreinfo->mdesp->page_offset = ARM64_PAGE_OFFSET;
		kcoreinfo->kvbase = ARM64_VA_START;
	}

	if (lookup_symbol_from_proc_kallsyms("kimage_voffset") != 0)
		kcoreinfo->flags |= NEW_VMEMMAP;

	kcoreinfo->ptrs_per_pgd = PTRS_PER_PGD_L3_4K;
	kcoreinfo->pgd = (char *)malloc(PTRS_PER_PGD_L3_4K * 8);
	kcoreinfo->pud = (char *)malloc(PTRS_PER_PUD_L4_4K * 8);
	kcoreinfo->pmd = (char *)malloc(PTRS_PER_PMD_L3_4K * 8);
	kcoreinfo->ptbl = (char *)malloc(PTRS_PER_PTE_L3_4K * 8);
	if (kcoreinfo->flags & NEW_VMEMMAP) {
		/* Prioritize support for this situation */
		kcoreinfo->mdesp->kimage_text = lookup_symbol_from_proc_kallsyms("_text");
		kcoreinfo->mdesp->kimage_end = lookup_symbol_from_proc_kallsyms("_end");

		if (VA_BITS_ACTUAL) {
			kcoreinfo->mdesp->modules_vaddr = (_stext_vmlinux & TEXT_OFFSET_MASK) - ARM64_MODULES_VSIZE;
			kcoreinfo->mdesp->modules_end = kcoreinfo->mdesp->modules_vaddr + ARM64_MODULES_VSIZE -1;
		} else {
			kcoreinfo->mdesp->modules_vaddr = ARM64_VA_START;
			if (lookup_symbol_from_proc_kallsyms("kasan_init") != 0)
				kcoreinfo->mdesp->modules_vaddr += ARM64_KASAN_SHADOW_SIZE;
			kcoreinfo->mdesp->modules_end =
				kcoreinfo->mdesp->modules_vaddr + ARM64_MODULES_VSIZE -1;
		}

		kcoreinfo->mdesp->vmalloc_start_addr = kcoreinfo->mdesp->modules_end + 1;

		arm64_calc_kimage_voffset();
	} else {
		kcoreinfo->mdesp->modules_vaddr = ARM64_PAGE_OFFSET - MEGABYTES(64);
		kcoreinfo->mdesp->modules_end = ARM64_PAGE_OFFSET - 1;
		kcoreinfo->mdesp->vmalloc_start_addr = ARM64_VA_START;
	}
	arm64_init_kernel_pgd();
	arm64_calc_physvirt_offset();
	kcoreinfo->mdesp->vmalloc_end = ARM64_VMALLOC_END;
	kcoreinfo->mdesp->vmemmap_vaddr = ARM64_VMEMMAP_VADDR;
	kcoreinfo->mdesp->vmemmap_end = ARM64_VMEMMAP_END;
}

static void 
do_xarray_iter(unsigned long node, unsigned int height, char *path,
	unsigned long index, struct xarray_ops *ops)
{
	unsigned int off;

#if 0
	if (!hq_enter(node))
		error(FATAL,
			"\nduplicate tree node: %lx\n", node);
#endif

	for (off = 0; off < XA_CHUNK_SIZE; off++) {
		unsigned long slot;
		unsigned long shift = (height - 1) * XA_CHUNK_SHIFT;

		readmem(node + OFFSET(xa_node_slots) +
			sizeof(void *) * off, KVADDR, &slot, sizeof(void *),
			"xa_node.slots[off]", FAULT_ON_ERROR);
		if (!slot)
			continue;

		if ((slot & XARRAY_TAG_MASK) == XARRAY_TAG_INTERNAL)
			slot &= ~XARRAY_TAG_INTERNAL;

		if (height == 1)
			ops->entry(node, slot, path, index | off, ops->private);
		else {
			unsigned long child_index = index | (off << shift);
			char child_path[BUFSIZE];
			sprintf(child_path, "%s/%d", path, off);
			do_xarray_iter(slot, height - 1,
				child_path, child_index, ops);
		}
	}
}

int do_xarray_traverse(unsigned long ptr, int is_root, struct xarray_ops *ops)
{
	unsigned long node_p;
	long nlen;
	unsigned int height, is_internal;
	unsigned char shift;
	char path[BUFSIZE];

	if (!VALID_STRUCT(xarray) || !VALID_STRUCT(xa_node) ||
		!VALID_MEMBER(xarray_xa_head) ||
		!VALID_MEMBER(xa_node_slots) || !VALID_MEMBER(xa_node_shift)) {
		ERROR("xarray facility does not exist or has changed its format\n");
	}

	/* Generally, XA_CHUNK_SHIFT = 4 or 6 */
	if (XA_CHUNK_SHIFT == UNINITIALIZED) {
		/*
		 * FIXME: set XA_CHUNK_SHIFT=6 directly, the right way is request the
		 * size from 'xa_node' struct:
		 *
		 * if ((nlen = MEMBER_SIZE("xa_node", "slots")) <= 0)
		 * 	ERROR("cannot determine length of xa_node.slots[] array\n");
		 * nlen /= sizeof(void *);
		 * XA_CHUNK_SHIFT = ffsl(nlen) - 1;
		 */
		XA_CHUNK_SHIFT = 6;
		XA_CHUNK_SIZE = (1UL << XA_CHUNK_SHIFT);
		XA_CHUNK_MASK = (XA_CHUNK_SIZE-1);
	}

	height = 0;
	if (!is_root) {
		node_p = ptr;

		if ((node_p & XARRAY_TAG_MASK) == XARRAY_TAG_INTERNAL)
			node_p &= ~XARRAY_TAG_MASK;

		if (VALID_MEMBER(xa_node_shift)) {
			readmem(node_p + OFFSET(xa_node_shift), KVADDR,
				&shift, sizeof(shift), "xa_node shift",
				FAULT_ON_ERROR);
			height = (shift / XA_CHUNK_SHIFT) + 1;
		} else
			error(FATAL, "-N option is not supported or applicable"
				" for xarrays on this architecture or kernel\n");
	} else {
		readmem(ptr + OFFSET(xarray_xa_head), KVADDR, &node_p,
			sizeof(node_p), "xarray xa_head", FAULT_ON_ERROR);
		is_internal = ((node_p & XARRAY_TAG_MASK) == XARRAY_TAG_INTERNAL);
		if (node_p & XARRAY_TAG_MASK)
			node_p &= ~XARRAY_TAG_MASK;

		if (is_internal && VALID_MEMBER(xa_node_shift)) {
			readmem(node_p + OFFSET(xa_node_shift), KVADDR, &shift,
				sizeof(shift), "xa_node shift", FAULT_ON_ERROR);
			height = (shift / XA_CHUNK_SHIFT) + 1;
		}
	}

	if (kr_debug) {
		fprintf(stdout, "xa_node.slots[%ld]\n", XA_CHUNK_SIZE);
		fprintf(stdout, "pointer at 0x%lx (is_root? %s):\n",
			node_p, is_root ? "yes" : "no");
#if 0
		if (is_root)
			dump_struct("xarray", ptr, RADIX(ops->radix));
		else
			dump_struct("xa_node", node_p, RADIX(ops->radix));
#endif
	}

	if (height == 0) {
		strcpy(path, "direct");
		ops->entry(node_p, node_p, path, 0, ops->private);
	} else {
		strcpy(path, "root");
		do_xarray_iter(node_p, height, path, 0, ops);
	}

	return 0;
}

static void do_xarray_count(unsigned long node, unsigned long slot, const char *path,
	unsigned long index, void *private)
{
	struct do_xarray_info *info = private;
	info->count++;
}

static void do_xarray_search(unsigned long node, unsigned long slot, const char *path,
	unsigned long index, void *private)
{
	struct do_xarray_info *info = private;
	struct list_pair *xp = info->data;

	if (xp->index == index) {
		xp->value = (void *)slot;
		info->count = 1;
	}
}

static void do_xarray_dump(unsigned long node, unsigned long slot, const char *path,
	unsigned long index, void *private)
{
	struct do_xarray_info *info = private;
	fprintf(stdout, "[%ld] %lx\n", index, slot);
	info->count++;
}

static void do_xarray_gather(unsigned long node, unsigned long slot, const char *path,
	unsigned long index, void *private)
{
	struct do_xarray_info *info = private;
	struct list_pair *xp = info->data;

	if (info->maxcount) {
		xp[info->count].index = index;
		xp[info->count].value = (void *)slot;

		info->count++;
		info->maxcount--;
	}
}

static void do_xarray_dump_cb(unsigned long node, unsigned long slot, const char *path,
	unsigned long index, void *private)
{
	struct do_xarray_info *info = private;
	struct list_pair *xp = info->data;
	int (*cb)(unsigned long) = xp->value;

	/* Caller defined operation */
	if (!cb(slot)) {
		if (slot & XARRAY_TAG_MASK) {
			if (1)
				printf("entry has XARRAY_TAG_MASK bits set: %lx\n", slot);
			return;
		}
		printf("do_xarray: callback "
			"operation failed: entry: %ld  item: %lx\n", info->count, slot);
	}
	info->count++;
}

unsigned long do_xarray(unsigned long root, int flag, struct list_pair *xp)
{
	struct do_xarray_info info = {
		.count		= 0,
		.data		= xp,
	};
	struct xarray_ops ops = {
		.radix		= 16,
		.private	= &info,
	};

	switch (flag) {
	case XARRAY_COUNT:
		ops.entry = do_xarray_count;
		break;

	case XARRAY_SEARCH:
		ops.entry = do_xarray_search;
		break;

	case XARRAY_DUMP:
		ops.entry = do_xarray_dump;
		break;

	case XARRAY_GATHER:
		if (!(info.maxcount = xp->index))
			info.maxcount = (unsigned long)(-1); /* caller beware */

		ops.entry = do_xarray_gather;
		break;

	case XARRAY_DUMP_CB:
		if (xp->value == NULL) {
			ERROR("do_xarray: no callback function specified");
			return -EINVAL;
		}
		ops.entry = do_xarray_dump_cb;
		break;

	default:
		printf("do_xarray: invalid flag: %lx\n", flag);
	}

	do_xarray_traverse(root, 1, &ops);
	return info.count;
}

void lookup_vma_for_task(pid_t pid)
{

}

/*
 * Translate a PTE, returning TRUE if the page is present.
 * If a physaddr pointer is passed in, don't print anything.
 */
static int
arm64_translate_pte(unsigned long pte, void *physaddr, ulonglong unused)
{
	int c, others, len1, len2, len3;
	unsigned long paddr;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
	char *arglist[MAXARGS];
	int page_present;

	paddr = PTE_TO_PHYS(pte);
	page_present = pte & (PTE_VALID | kcoreinfo->mdesp->PTE_PROT_NONE);

	if (physaddr) {
		*((unsigned long *)physaddr) = paddr;
		return page_present;
	}

	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(stdout, "%s  ", mkstring(buf1, len1, CENTER|LJUST, "PTE"));

	if (!page_present) {
		/* NOT handle */
		printf("page: not present");
#if 0
		swap_location(pte, buf1);
		if ((c = parse_line(buf1, arglist)) != 3)
			ERROR("cannot determine swap location\n");

		len2 = MAX(strlen(arglist[0]), strlen("SWAP"));
		len3 = MAX(strlen(arglist[2]), strlen("OFFSET"));

		fprintf(fp, "%s  %s\n",
			mkstring(buf2, len2, CENTER|LJUST, "SWAP"),
			mkstring(buf3, len3, CENTER|LJUST, "OFFSET"));

		strcpy(buf2, arglist[0]);
		strcpy(buf3, arglist[2]);
		fprintf(fp, "%s  %s  %s\n",
			mkstring(ptebuf, len1, CENTER|RJUST, NULL),
			mkstring(buf2, len2, CENTER|RJUST, NULL),
			mkstring(buf3, len3, CENTER|RJUST, NULL));
		return page_present;
#endif
	}

	sprintf(physbuf, "%lx", paddr);
	len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
	fprintf(stdout, "%s  ", mkstring(buf1, len2, CENTER|LJUST, "PHYSICAL"));

	fprintf(stdout, "FLAGS\n");

	fprintf(stdout, "%s  %s  ",
		mkstring(ptebuf, len1, CENTER|RJUST, NULL),
		mkstring(physbuf, len2, CENTER|RJUST, NULL));
	fprintf(stdout, "(");
	others = 0;

	if (pte) {
		if (pte & PTE_VALID)
			fprintf(stdout, "%sVALID", others++ ? "|" : "");
		if (pte & kcoreinfo->mdesp->PTE_FILE)
			fprintf(stdout, "%sFILE", others++ ? "|" : "");
		if (pte & kcoreinfo->mdesp->PTE_PROT_NONE)
			fprintf(stdout, "%sPROT_NONE", others++ ? "|" : "");
		if (pte & PTE_USER)
			fprintf(stdout, "%sUSER", others++ ? "|" : "");
		if (pte & PTE_RDONLY)
			fprintf(stdout, "%sRDONLY", others++ ? "|" : "");
		if (pte & PTE_SHARED)
			fprintf(stdout, "%sSHARED", others++ ? "|" : "");
		if (pte & PTE_AF)
			fprintf(stdout, "%sAF", others++ ? "|" : "");
		if (pte & PTE_NG)
			fprintf(stdout, "%sNG", others++ ? "|" : "");
		if (pte & PTE_PXN)
			fprintf(stdout, "%sPXN", others++ ? "|" : "");
		if (pte & PTE_UXN)
			fprintf(stdout, "%sUXN", others++ ? "|" : "");
		if (pte & PTE_DIRTY)
			fprintf(stdout, "%sDIRTY", others++ ? "|" : "");
		if (pte & PTE_SPECIAL)
			fprintf(stdout, "%sSPECIAL", others++ ? "|" : "");
	} else {
		fprintf(stdout, "no mapping");
	}

	fprintf(stdout, ")\n");

	return page_present;
}

static int
arm64_vtop_2level_64k(unsigned long pgd, unsigned long vaddr, physaddr_t *paddr, int verbose)
{
	printf("NOT support: 2level_64k\n");
}

static int
arm64_vtop_3level_64k(unsigned long pgd, unsigned long vaddr, physaddr_t *paddr, int verbose)
{
	printf("NOT support: 3level_64k\n");
}

static int
arm64_vtop_3level_4k(unsigned long pgd, unsigned long vaddr, physaddr_t *paddr, int verbose)
{
	printf("NOT support: 3level_4k\n");
}

static int
arm64_vtop_4level_4k(unsigned long pgd, unsigned long vaddr, physaddr_t *paddr, int verbose)
{
	unsigned long *pgd_base, *pgd_ptr, pgd_val;
	unsigned long *pud_base, *pud_ptr, pud_val;
	unsigned long *pmd_base, *pmd_ptr, pmd_val;
	unsigned long *pte_base, *pte_ptr, pte_val;

	if (verbose)
		fprintf(stdout, "PAGE DIRECTORY: %lx\n", pgd);

	pgd_base = (unsigned long *)pgd;
	FILL_PGD(pgd_base, KVADDR, PTRS_PER_PGD_L4_4K * sizeof(unsigned long));
	pgd_ptr = pgd_base + (((vaddr) >> PGDIR_SHIFT_L4_4K) & (PTRS_PER_PGD_L4_4K - 1));
	pgd_val = ULONG(kcoreinfo->pgd + PGDIR_OFFSET_48VA(pgd_ptr));
	if (verbose)
		fprintf(stdout, "   PGD: %lx => %lx\n", (unsigned long)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;

	pud_base = (unsigned long *)PTOV(pgd_val & PHYS_MASK & PGDIR_MASK_48VA);

	FILL_PUD(pud_base, KVADDR, PTRS_PER_PUD_L4_4K * sizeof(unsigned long));
	pud_ptr = pud_base + (((vaddr) >> PUD_SHIFT_L4_4K) & (PTRS_PER_PUD_L4_4K - 1));
	pud_val = ULONG(kcoreinfo->pud + PAGEOFFSET(pud_ptr));
	if (verbose)
		fprintf(stdout, "   PUD: %lx => %lx\n", (unsigned long)pud_ptr, pud_val);
	if (!pud_val)
		goto no_page;

	pmd_base = (unsigned long *)PTOV(pud_val & PHYS_MASK & (s32)kcoreinfo->pagemask);
	FILL_PMD(pmd_base, KVADDR, PTRS_PER_PMD_L4_4K * sizeof(unsigned long));
	pmd_ptr = pmd_base + (((vaddr) >> PMD_SHIFT_L4_4K) & (PTRS_PER_PMD_L4_4K - 1));
	pmd_val = ULONG(kcoreinfo->pmd + PAGEOFFSET(pmd_ptr));
	if (verbose)
		fprintf(stdout, "   PMD: %lx => %lx\n", (unsigned long)pmd_ptr, pmd_val);
	if (!pmd_val)
		goto no_page;

	if ((pmd_val & PMD_TYPE_MASK) == PMD_TYPE_SECT) {
		unsigned long sectionbase = (pmd_val & SECTION_PAGE_MASK_2MB) & PHYS_MASK;
		if (verbose) {
			fprintf(stdout, "  PAGE: %lx  (2MB)\n\n", sectionbase);
			arm64_translate_pte(pmd_val, 0, 0);
		}
		*paddr = sectionbase + (vaddr & ~SECTION_PAGE_MASK_2MB);
		return TRUE;
	}

	pte_base = (unsigned long *)PTOV(pmd_val & PHYS_MASK & (s32)kcoreinfo->pagemask);
	FILL_PTBL(pte_base, KVADDR, PTRS_PER_PTE_L4_4K * sizeof(unsigned long));
	pte_ptr = pte_base + (((vaddr) >> kcoreinfo->pageshift) & (PTRS_PER_PTE_L4_4K - 1));
	pte_val = ULONG(kcoreinfo->ptbl + PAGEOFFSET(pte_ptr));
	if (verbose)
		fprintf(stdout, "   PTE: %lx => %lx\n", (unsigned long)pte_ptr, pte_val);
	if (!pte_val)
		goto no_page;

	if (pte_val & PTE_VALID) {
		*paddr = (PAGEBASE(pte_val) & PHYS_MASK) + PAGEOFFSET(vaddr);
		if (verbose) {
			fprintf(stdout, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
			arm64_translate_pte(pte_val, 0, 0);
		}
	} else {
		if (IS_UVADDR(vaddr, NULL))
			*paddr = pte_val;
		if (verbose) {
			fprintf(stdout, "\n");
			arm64_translate_pte(pte_val, 0, 0);
		}
		goto no_page;
	}

	return TRUE;
no_page:
	return FALSE;
}

unsigned long arm64_VTOP(unsigned long addr)
{
	struct arch_machine_descriptor *desp= kcoreinfo->mdesp;

	if (kcoreinfo->flags & NEW_VMEMMAP) {
		if (VA_START && (addr >= desp->kimage_text) && (addr <= desp->kimage_end)) {
			return addr - desp->kimage_voffset;
		}

		if (addr >= desp->page_offset)
			return addr + desp->physvirt_offset;
		else if (desp->kimage_voffset)
			return addr - desp->kimage_voffset;
		else /* no randomness */
			return desp->phys_offset
				+ (addr - desp->vmalloc_start_addr);
	} else {
		return desp->phys_offset
			+ (addr - desp->page_offset);
	}
}

/*
 * Translate kvaddr into paddr.
 */
int
arm64_kvtop(struct task_context *tc, unsigned long kvaddr, physaddr_t *paddr, int verbose)
{
	unsigned long kernel_pgd_0;

	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!kcoreinfo->mdesp->vmalloc_start_addr) {
		*paddr = VTOP(kvaddr);
		return TRUE;
	}

	if (!IS_VMALLOC_ADDR(kvaddr)) {
		*paddr = VTOP(kvaddr);
		if (!verbose)
			return TRUE;
	}

	kernel_pgd_0 = kernel_pgd[0];
	*paddr = 0;

	switch (kcoreinfo->flags & (VM_L2_64K|VM_L3_64K|VM_L3_4K|VM_L4_4K)) {
	case VM_L2_64K:
		return arm64_vtop_2level_64k(kernel_pgd_0, kvaddr, paddr, verbose);
	case VM_L3_64K:
		return arm64_vtop_3level_64k(kernel_pgd_0, kvaddr, paddr, verbose);
	case VM_L3_4K:
		return arm64_vtop_3level_4k(kernel_pgd_0, kvaddr, paddr, verbose);
	case VM_L4_4K:
		return arm64_vtop_4level_4k(kernel_pgd_0, kvaddr, paddr, verbose);
	default:
		return FALSE;
	}
}

static int
arm64_uvtop(struct task_context *tc, unsigned long uvaddr, physaddr_t *paddr, int verbose)
{
#if 0
	unsigned long user_pgd;

	readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR,
		&user_pgd, sizeof(long), "user pgd", FAULT_ON_ERROR);

	*paddr = 0;

	switch (machdep->flags & (VM_L2_64K|VM_L3_64K|VM_L3_4K|VM_L4_4K))
	{

	case VM_L2_64K:
		return arm64_vtop_2level_64k(user_pgd, uvaddr, paddr, verbose);
	case VM_L3_64K:
		return arm64_vtop_3level_64k(user_pgd, uvaddr, paddr, verbose);
	case VM_L3_4K:
		return arm64_vtop_3level_4k(user_pgd, uvaddr, paddr, verbose);

	case VM_L4_4K:
		return arm64_vtop_4level_4k(user_pgd, uvaddr, paddr, verbose);
	default:
		return FALSE;
	}
#endif
}

