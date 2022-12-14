#ifndef _ASM_X86_PGTABLE_64_H
#define _ASM_X86_PGTABLE_64_H

#include <linux/const.h>
#include <asm/pgtable_64_types.h>

#ifndef __ASSEMBLY__

#include <asm/processor.h>
#include <linux/bitops.h>
#include <linux/threads.h>
#include <asm/fixmap.h>

extern p4d_t level4_kernel_pgt[512];
extern p4d_t level4_ident_pgt[512];
extern pud_t level3_kernel_pgt[512];
extern pud_t level3_ident_pgt[512];
extern pmd_t level2_kernel_pgt[512];
extern pmd_t level2_fixmap_pgt[512];
extern pmd_t level2_ident_pgt[512];
extern pte_t level1_fixmap_pgt[512 * FIXMAP_PMD_NUM];
extern pgd_t init_top_pgt[];

#define swapper_pg_dir init_top_pgt

extern void paging_init(void);
static inline void sync_initial_page_table(void) { }

#define pte_ERROR(e)					\
	pr_err("%s:%d: bad pte %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pte_val(e))
#define pmd_ERROR(e)					\
	pr_err("%s:%d: bad pmd %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pmd_val(e))
#define pud_ERROR(e)					\
	pr_err("%s:%d: bad pud %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pud_val(e))

#if CONFIG_PGTABLE_LEVELS >= 5
#define p4d_ERROR(e)					\
	pr_err("%s:%d: bad p4d %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), p4d_val(e))
#endif

#define pgd_ERROR(e)					\
	pr_err("%s:%d: bad pgd %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pgd_val(e))

struct mm_struct;

#define mm_p4d_folded mm_p4d_folded
static inline bool mm_p4d_folded(struct mm_struct *mm)
{
	return !pgtable_l5_enabled();
}

void set_pte_vaddr_p4d(p4d_t *p4d_page, unsigned long vaddr, pte_t new_pte);
void set_pte_vaddr_pud(pud_t *pud_page, unsigned long vaddr, pte_t new_pte);

static inline void native_set_pte(pte_t *ptep, pte_t pte)
{
	WRITE_ONCE(*ptep, pte);
}

static inline void native_pte_clear(struct mm_struct *mm, unsigned long addr,
				    pte_t *ptep)
{
	native_set_pte(ptep, native_make_pte(0));
}

static inline void native_set_pte_atomic(pte_t *ptep, pte_t pte)
{
	native_set_pte(ptep, pte);
}

static inline void native_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
	WRITE_ONCE(*pmdp, pmd);
}

static inline void native_pmd_clear(pmd_t *pmd)
{
	native_set_pmd(pmd, native_make_pmd(0));
}

static inline pte_t native_ptep_get_and_clear(pte_t *xp)
{
#ifdef CONFIG_SMP
	return native_make_pte(xchg(&xp->pte, 0));
#else
	/* native_local_ptep_get_and_clear,
	   but duplicated because of cyclic dependency */
	pte_t ret = *xp;
	native_pte_clear(NULL, 0, xp);
	return ret;
#endif
}

static inline pmd_t native_pmdp_get_and_clear(pmd_t *xp)
{
#ifdef CONFIG_SMP
	return native_make_pmd(xchg(&xp->pmd, 0));
#else
	/* native_local_pmdp_get_and_clear,
	   but duplicated because of cyclic dependency */
	pmd_t ret = *xp;
	native_pmd_clear(xp);
	return ret;
#endif
}

static inline void native_set_pud(pud_t *pudp, pud_t pud)
{
	WRITE_ONCE(*pudp, pud);
}

static inline void native_pud_clear(pud_t *pud)
{
	native_set_pud(pud, native_make_pud(0));
}

static inline pud_t native_pudp_get_and_clear(pud_t *xp)
{
#ifdef CONFIG_SMP
	return native_make_pud(xchg(&xp->pud, 0));
#else
	/* native_local_pudp_get_and_clear,
	 * but duplicated because of cyclic dependency
	 */
	pud_t ret = *xp;

	native_pud_clear(xp);
	return ret;
#endif
}

static inline void native_set_p4d(p4d_t *p4dp, p4d_t p4d)
{
	pgd_t pgd;

	if (pgtable_l5_enabled() || !IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION)) {
		WRITE_ONCE(*p4dp, p4d);
		return;
	}

	pgd = native_make_pgd(native_p4d_val(p4d));
	pgd = pti_set_user_pgtbl((pgd_t *)p4dp, pgd);
	WRITE_ONCE(*p4dp, native_make_p4d(native_pgd_val(pgd)));
}

static inline void native_p4d_clear(p4d_t *p4d)
{
	native_set_p4d(p4d, native_make_p4d(0));
}

static inline void native_set_pgd(pgd_t *pgdp, pgd_t pgd)
{
	WRITE_ONCE(*pgdp, pti_set_user_pgtbl(pgdp, pgd));
}

static inline void native_pgd_clear(pgd_t *pgd)
{
	native_set_pgd(pgd, native_make_pgd(0));
}






#define SWP_TYPE_BITS		5

#define SWP_OFFSET_FIRST_BIT	(_PAGE_BIT_PROTNONE + 1)

#define SWP_OFFSET_SHIFT	(SWP_OFFSET_FIRST_BIT+SWP_TYPE_BITS)

#define MAX_SWAPFILES_CHECK() BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > SWP_TYPE_BITS)

#define __swp_type(x) ((x).val >> (64 - SWP_TYPE_BITS))

#define __swp_offset(x) (~(x).val << SWP_TYPE_BITS >> SWP_OFFSET_SHIFT)

#define __swp_entry(type, offset) ((swp_entry_t) { \
	(~(unsigned long)(offset) << SWP_OFFSET_SHIFT >> SWP_TYPE_BITS) \
	| ((unsigned long)(type) << (64-SWP_TYPE_BITS)) })

#define __pte_to_swp_entry(pte)		((swp_entry_t) { pte_val((pte)) })
#define __pmd_to_swp_entry(pmd)		((swp_entry_t) { pmd_val((pmd)) })
#define __swp_entry_to_pte(x)		((pte_t) { .pte = (x).val })
#define __swp_entry_to_pmd(x)		((pmd_t) { .pmd = (x).val })

extern int kern_addr_valid(unsigned long addr);
extern void cleanup_highmap(void);

#define HAVE_ARCH_UNMAPPED_AREA
#define HAVE_ARCH_UNMAPPED_AREA_TOPDOWN

#define PAGE_AGP    PAGE_KERNEL_NOCACHE
#define HAVE_PAGE_AGP 1

#define	kc_vaddr_to_offset(v) ((v) & __VIRTUAL_MASK)
#define	kc_offset_to_vaddr(o) ((o) | ~__VIRTUAL_MASK)

#define __HAVE_ARCH_PTE_SAME

#define vmemmap ((struct page *)VMEMMAP_START)

extern void init_extra_mapping_uc(unsigned long phys, unsigned long size);
extern void init_extra_mapping_wb(unsigned long phys, unsigned long size);

#define gup_fast_permitted gup_fast_permitted
static inline bool gup_fast_permitted(unsigned long start, unsigned long end)
{
	if (end >> __VIRTUAL_MASK_SHIFT)
		return false;
	return true;
}

#include <asm/pgtable-invert.h>

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_PGTABLE_64_H */
