#include "kernel.h"
#include "kcore.h"
#include "kread.h"

/*
 * Include kernel data/struct
 */
void arm64_kernel_init(void)
{
	MEMBER_OFFSET_INIT(task_struct_mm, "task_struct", "mm");
	MEMBER_OFFSET_INIT(mm_struct_mmap, "mm_struct", "mmap");
	MEMBER_OFFSET_INIT(mm_struct_pgd, "mm_struct", "pgd");
	MEMBER_OFFSET_INIT(mm_struct_rss, "mm_struct", "rss");

	MEMBER_OFFSET_INIT(pid_namespace_idr, "pid_namespace", "idr");
	MEMBER_OFFSET_INIT(idr_idr_rt, "idr", "idr_rt");

	STRUCT_SIZE_INIT(xarray, "xarray");
	STRUCT_SIZE_INIT(xa_node, "xa_node");
	MEMBER_OFFSET_INIT(xarray_xa_head, "xarray", "xa_head");
	MEMBER_OFFSET_INIT(xa_node_slots, "xa_node", "slots");
	MEMBER_OFFSET_INIT(xa_node_shift, "xa_node", "shift");
}

static int
arm64_vtop_4level_4k(unsigned long pgd, unsigned long vaddr, physaddr_t *paddr, int verbose)
{
#if 0
	unsigned long *pgd_base, *pgd_ptr, pgd_val;
	unsigned long *pud_base, *pud_ptr, pud_val;
	unsigned long *pmd_base, *pmd_ptr, pmd_val;
	unsigned long *pte_base, *pte_ptr, pte_val;

        if (verbose)
                fprintf(fp, "PAGE DIRECTORY: %lx\n", pgd);

	pgd_base = (unsigned long *)pgd;
	FILL_PGD(pgd_base, KVADDR, PTRS_PER_PGD_L4_4K * sizeof(unsigned long));
	pgd_ptr = pgd_base + (((vaddr) >> PGDIR_SHIFT_L4_4K) & (PTRS_PER_PGD_L4_4K - 1));
        pgd_val = ULONG(machdep->pgd + PGDIR_OFFSET_48VA(pgd_ptr));
        if (verbose)
                fprintf(fp, "   PGD: %lx => %lx\n", (unsigned long)pgd_ptr, pgd_val);
	if (!pgd_val)
		goto no_page;

	pud_base = (unsigned long *)PTOV(pgd_val & PHYS_MASK & PGDIR_MASK_48VA);

	FILL_PUD(pud_base, KVADDR, PTRS_PER_PUD_L4_4K * sizeof(unsigned long));
	pud_ptr = pud_base + (((vaddr) >> PUD_SHIFT_L4_4K) & (PTRS_PER_PUD_L4_4K - 1));
        pud_val = ULONG(machdep->pud + PAGEOFFSET(pud_ptr));
        if (verbose)
                fprintf(fp, "   PUD: %lx => %lx\n", (unsigned long)pud_ptr, pud_val);
	if (!pud_val)
		goto no_page;

	pmd_base = (unsigned long *)PTOV(pud_val & PHYS_MASK & (s32)machdep->pagemask);
	FILL_PMD(pmd_base, KVADDR, PTRS_PER_PMD_L4_4K * sizeof(unsigned long));
	pmd_ptr = pmd_base + (((vaddr) >> PMD_SHIFT_L4_4K) & (PTRS_PER_PMD_L4_4K - 1));
        pmd_val = ULONG(machdep->pmd + PAGEOFFSET(pmd_ptr));
        if (verbose)
                fprintf(fp, "   PMD: %lx => %lx\n", (unsigned long)pmd_ptr, pmd_val);
	if (!pmd_val)
		goto no_page;

	if ((pmd_val & PMD_TYPE_MASK) == PMD_TYPE_SECT) {
		unsigned long sectionbase = (pmd_val & SECTION_PAGE_MASK_2MB) & PHYS_MASK;
		if (verbose) {
			fprintf(fp, "  PAGE: %lx  (2MB)\n\n", sectionbase);
			arm64_translate_pte(pmd_val, 0, 0);
		}
		*paddr = sectionbase + (vaddr & ~SECTION_PAGE_MASK_2MB);
		return TRUE;
	}

	pte_base = (unsigned long *)PTOV(pmd_val & PHYS_MASK & (s32)machdep->pagemask);
	FILL_PTBL(pte_base, KVADDR, PTRS_PER_PTE_L4_4K * sizeof(unsigned long));
	pte_ptr = pte_base + (((vaddr) >> machdep->pageshift) & (PTRS_PER_PTE_L4_4K - 1));
        pte_val = ULONG(machdep->ptbl + PAGEOFFSET(pte_ptr));
        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (unsigned long)pte_ptr, pte_val);
	if (!pte_val)
		goto no_page;

	if (pte_val & PTE_VALID) {
		*paddr = (PAGEBASE(pte_val) & PHYS_MASK) + PAGEOFFSET(vaddr);
		if (verbose) {
			fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
			arm64_translate_pte(pte_val, 0, 0);
		}
	} else {
		if (IS_UVADDR(vaddr, NULL))
			*paddr = pte_val;
		if (verbose) {
			fprintf(fp, "\n");
			arm64_translate_pte(pte_val, 0, 0);
		}
		goto no_page;
	}
#endif
	return TRUE;
no_page:
	return FALSE;
}


static int
arm64_kvtop(struct task_context *tc, unsigned long kvaddr, physaddr_t *paddr, int verbose)
{
#if 0
	unsigned long kernel_pgd;

	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!vt->vmalloc_start) {
		*paddr = VTOP(kvaddr);
		return TRUE;
	}

	if (!IS_VMALLOC_ADDR(kvaddr)) {
		*paddr = VTOP(kvaddr);
		if (!verbose)
			return TRUE;
	}

	kernel_pgd = vt->kernel_pgd[0];
	*paddr = 0;

	switch (machdep->flags & (VM_L2_64K|VM_L3_64K|VM_L3_4K|VM_L4_4K))
	{
#endif
#if 0
	case VM_L2_64K:
		return arm64_vtop_2level_64k(kernel_pgd, kvaddr, paddr, verbose);
	case VM_L3_64K:
		return arm64_vtop_3level_64k(kernel_pgd, kvaddr, paddr, verbose);
	case VM_L3_4K:
		return arm64_vtop_3level_4k(kernel_pgd, kvaddr, paddr, verbose);

	case VM_L4_4K:
		return arm64_vtop_4level_4k(kernel_pgd, kvaddr, paddr, verbose);
	default:
		return FALSE;
	}
#endif
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

