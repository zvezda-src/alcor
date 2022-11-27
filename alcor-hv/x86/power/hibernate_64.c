
#include <linux/gfp.h>
#include <linux/smp.h>
#include <linux/suspend.h>
#include <linux/scatterlist.h>
#include <linux/kdebug.h>
#include <linux/pgtable.h>

#include <crypto/hash.h>

#include <asm/e820/api.h>
#include <asm/init.h>
#include <asm/proto.h>
#include <asm/page.h>
#include <asm/mtrr.h>
#include <asm/sections.h>
#include <asm/suspend.h>
#include <asm/tlbflush.h>

static int set_up_temporary_text_mapping(pgd_t *pgd)
{
	pmd_t *pmd;
	pud_t *pud;
	p4d_t *p4d = NULL;
	pgprot_t pgtable_prot = __pgprot(_KERNPG_TABLE);
	pgprot_t pmd_text_prot = __pgprot(__PAGE_KERNEL_LARGE_EXEC);

	/* Filter out unsupported __PAGE_KERNEL* bits: */
	pgprot_val(pmd_text_prot) &= __default_kernel_pte_mask;
	pgprot_val(pgtable_prot)  &= __default_kernel_pte_mask;

	/*

	if (pgtable_l5_enabled()) {
		p4d = (p4d_t *)get_safe_page(GFP_ATOMIC);
		if (!p4d)
			return -ENOMEM;
	}

	pud = (pud_t *)get_safe_page(GFP_ATOMIC);
	if (!pud)
		return -ENOMEM;

	pmd = (pmd_t *)get_safe_page(GFP_ATOMIC);
	if (!pmd)
		return -ENOMEM;

	set_pmd(pmd + pmd_index(restore_jump_address),
		__pmd((jump_address_phys & PMD_MASK) | pgprot_val(pmd_text_prot)));
	set_pud(pud + pud_index(restore_jump_address),
		__pud(__pa(pmd) | pgprot_val(pgtable_prot)));
	if (p4d) {
		p4d_t new_p4d = __p4d(__pa(pud) | pgprot_val(pgtable_prot));
		pgd_t new_pgd = __pgd(__pa(p4d) | pgprot_val(pgtable_prot));

		set_p4d(p4d + p4d_index(restore_jump_address), new_p4d);
		set_pgd(pgd + pgd_index(restore_jump_address), new_pgd);
	} else {
		/* No p4d for 4-level paging: point the pgd to the pud page table */
		pgd_t new_pgd = __pgd(__pa(pud) | pgprot_val(pgtable_prot));
		set_pgd(pgd + pgd_index(restore_jump_address), new_pgd);
	}

	return 0;
}

static void *alloc_pgt_page(void *context)
{
	return (void *)get_safe_page(GFP_ATOMIC);
}

static int set_up_temporary_mappings(void)
{
	struct x86_mapping_info info = {
		.alloc_pgt_page	= alloc_pgt_page,
		.page_flag	= __PAGE_KERNEL_LARGE_EXEC,
		.offset		= __PAGE_OFFSET,
	};
	unsigned long mstart, mend;
	pgd_t *pgd;
	int result;
	int i;

	pgd = (pgd_t *)get_safe_page(GFP_ATOMIC);
	if (!pgd)
		return -ENOMEM;

	/* Prepare a temporary mapping for the kernel text */
	result = set_up_temporary_text_mapping(pgd);
	if (result)
		return result;

	/* Set up the direct mapping from scratch */
	for (i = 0; i < nr_pfn_mapped; i++) {
		mstart = pfn_mapped[i].start << PAGE_SHIFT;
		mend   = pfn_mapped[i].end << PAGE_SHIFT;

		result = kernel_ident_mapping_init(&info, pgd, mstart, mend);
		if (result)
			return result;
	}

	temp_pgt = __pa(pgd);
	return 0;
}

asmlinkage int swsusp_arch_resume(void)
{
	int error;

	/* We have got enough memory and from now on we cannot recover */
	error = set_up_temporary_mappings();
	if (error)
		return error;

	error = relocate_restore_code();
	if (error)
		return error;

	restore_image();
	return 0;
}
