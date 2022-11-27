#ifndef _ASM_X86_PGTABLE_32_H
#define _ASM_X86_PGTABLE_32_H

#include <asm/pgtable_32_types.h>

#ifndef __ASSEMBLY__
#include <asm/processor.h>
#include <linux/threads.h>
#include <asm/paravirt.h>

#include <linux/bitops.h>
#include <linux/list.h>
#include <linux/spinlock.h>

struct mm_struct;
struct vm_area_struct;

extern pgd_t swapper_pg_dir[1024];
extern pgd_t initial_page_table[1024];
extern pmd_t initial_pg_pmd[];

void paging_init(void);
void sync_initial_page_table(void);

#ifdef CONFIG_X86_PAE
# include <asm/pgtable-3level.h>
#else
# include <asm/pgtable-2level.h>
#endif

#define kpte_clear_flush(ptep, vaddr)		\
do {						\
	pte_clear(&init_mm, (vaddr), (ptep));	\
	flush_tlb_one_kernel((vaddr));		\
} while (0)

#endif /* !__ASSEMBLY__ */

#ifdef CONFIG_FLATMEM
#define kern_addr_valid(addr)	(1)
#else
#define kern_addr_valid(kaddr)	(0)
#endif

#if PTRS_PER_PMD > 1
#define PAGE_TABLE_SIZE(pages) (((pages) / PTRS_PER_PMD) + PTRS_PER_PGD)
#else
#define PAGE_TABLE_SIZE(pages) ((pages) / PTRS_PER_PGD)
#endif

#define LOWMEM_PAGES ((((_ULL(2)<<31) - __PAGE_OFFSET) >> PAGE_SHIFT))

#endif /* _ASM_X86_PGTABLE_32_H */
