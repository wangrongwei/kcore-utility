#ifndef __PGTABLE_H__
#define __PGTABLE_H__

extern struct mach_table *kcoreinfo;

#define IS_LAST_PGD_READ(pgd)     ((unsigned long)(pgd) == kcoreinfo->last_pgd_read)
#define IS_LAST_PMD_READ(pmd)     ((unsigned long)(pmd) == kcoreinfo->last_pmd_read)
#define IS_LAST_PTBL_READ(ptbl)   ((unsigned long)(ptbl) == kcoreinfo->last_ptbl_read)
#define IS_LAST_PUD_READ(pud)     ((unsigned long)(pud) == kcoreinfo->last_pud_read)

#define FILL_PGD(PGD, TYPE, SIZE) 					    \
    if (!IS_LAST_PGD_READ(PGD)) {                                           \
            readmem((ulonglong)((unsigned long)(PGD)), TYPE, kcoreinfo->pgd,          \
                    SIZE, "pgd page", FAULT_ON_ERROR);                      \
            kcoreinfo->last_pgd_read = (unsigned long)(PGD);                          \
    }

#define FILL_PUD(PUD, TYPE, SIZE) 					    \
    if (!IS_LAST_PUD_READ(PUD)) {                                           \
            readmem((ulonglong)((unsigned long)(PUD)), TYPE, kcoreinfo->pud,          \
                    SIZE, "pud page", FAULT_ON_ERROR);                      \
            kcoreinfo->last_pud_read = (unsigned long)(PUD);                          \
    }

#define FILL_PMD(PMD, TYPE, SIZE)			                    \
    if (!IS_LAST_PMD_READ(PMD)) {                                           \
            readmem((ulonglong)(PMD), TYPE, kcoreinfo->pmd,                   \
	            SIZE, "pmd page", FAULT_ON_ERROR);                      \
            kcoreinfo->last_pmd_read = (unsigned long)(PMD);                          \
    }

#define FILL_PTBL(PTBL, TYPE, SIZE)			           	    \
    if (!IS_LAST_PTBL_READ(PTBL)) {                                         \
    	    readmem((ulonglong)(PTBL), TYPE, kcoreinfo->ptbl,                 \
	            SIZE, "page table", FAULT_ON_ERROR);                    \
            kcoreinfo->last_ptbl_read = (unsigned long)(PTBL); 	                    \
    }

#endif
