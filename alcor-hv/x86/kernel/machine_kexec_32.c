
#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/delay.h>
#include <linux/numa.h>
#include <linux/ftrace.h>
#include <linux/suspend.h>
#include <linux/gfp.h>
#include <linux/io.h>

#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/cpufeature.h>
#include <asm/desc.h>
#include <asm/set_memory.h>
#include <asm/debugreg.h>

static void load_segments(void)
{
#define __STR(X) #X
#define STR(X) __STR(X)

	__asm__ __volatile__ (
		"\tljmp $"STR(__KERNEL_CS)",$1f\n"
		"\t1:\n"
		"\tmovl $"STR(__KERNEL_DS)",%%eax\n"
		"\tmovl %%eax,%%ds\n"
		"\tmovl %%eax,%%es\n"
		"\tmovl %%eax,%%ss\n"
		: : : "eax", "memory");
#undef STR
#undef __STR
}

static void machine_kexec_free_page_tables(struct kimage *image)
{
	free_pages((unsigned long)image->arch.pgd, PGD_ALLOCATION_ORDER);
	image->arch.pgd = NULL;
#ifdef CONFIG_X86_PAE
	free_page((unsigned long)image->arch.pmd0);
	image->arch.pmd0 = NULL;
	free_page((unsigned long)image->arch.pmd1);
	image->arch.pmd1 = NULL;
#endif
	free_page((unsigned long)image->arch.pte0);
	image->arch.pte0 = NULL;
	free_page((unsigned long)image->arch.pte1);
	image->arch.pte1 = NULL;
}

static int machine_kexec_alloc_page_tables(struct kimage *image)
{
	image->arch.pgd = (pgd_t *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						    PGD_ALLOCATION_ORDER);
#ifdef CONFIG_X86_PAE
	image->arch.pmd0 = (pmd_t *)get_zeroed_page(GFP_KERNEL);
	image->arch.pmd1 = (pmd_t *)get_zeroed_page(GFP_KERNEL);
#endif
	image->arch.pte0 = (pte_t *)get_zeroed_page(GFP_KERNEL);
	image->arch.pte1 = (pte_t *)get_zeroed_page(GFP_KERNEL);
	if (!image->arch.pgd ||
#ifdef CONFIG_X86_PAE
	    !image->arch.pmd0 || !image->arch.pmd1 ||
#endif
	    !image->arch.pte0 || !image->arch.pte1) {
		return -ENOMEM;
	}
	return 0;
}

static void machine_kexec_page_table_set_one(
	pgd_t *pgd, pmd_t *pmd, pte_t *pte,
	unsigned long vaddr, unsigned long paddr)
{
	p4d_t *p4d;
	pud_t *pud;

	pgd += pgd_index(vaddr);
#ifdef CONFIG_X86_PAE
	if (!(pgd_val(*pgd) & _PAGE_PRESENT))
		set_pgd(pgd, __pgd(__pa(pmd) | _PAGE_PRESENT));
#endif
	p4d = p4d_offset(pgd, vaddr);
	pud = pud_offset(p4d, vaddr);
	pmd = pmd_offset(pud, vaddr);
	if (!(pmd_val(*pmd) & _PAGE_PRESENT))
		set_pmd(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
	pte = pte_offset_kernel(pmd, vaddr);
	set_pte(pte, pfn_pte(paddr >> PAGE_SHIFT, PAGE_KERNEL_EXEC));
}

static void machine_kexec_prepare_page_tables(struct kimage *image)
{
	void *control_page;
	pmd_t *pmd = NULL;

	control_page = page_address(image->control_code_page);
#ifdef CONFIG_X86_PAE
	pmd = image->arch.pmd0;
#endif
	machine_kexec_page_table_set_one(
		image->arch.pgd, pmd, image->arch.pte0,
		(unsigned long)control_page, __pa(control_page));
#ifdef CONFIG_X86_PAE
	pmd = image->arch.pmd1;
#endif
	machine_kexec_page_table_set_one(
		image->arch.pgd, pmd, image->arch.pte1,
		__pa(control_page), __pa(control_page));
}

int machine_kexec_prepare(struct kimage *image)
{
	int error;

	set_memory_x((unsigned long)page_address(image->control_code_page), 1);
	error = machine_kexec_alloc_page_tables(image);
	if (error)
		return error;
	machine_kexec_prepare_page_tables(image);
	return 0;
}

void machine_kexec_cleanup(struct kimage *image)
{
	set_memory_nx((unsigned long)page_address(image->control_code_page), 1);
	machine_kexec_free_page_tables(image);
}

void machine_kexec(struct kimage *image)
{
	unsigned long page_list[PAGES_NR];
	void *control_page;
	int save_ftrace_enabled;
	asmlinkage unsigned long
		(*relocate_kernel_ptr)(unsigned long indirection_page,
				       unsigned long control_page,
				       unsigned long start_address,
				       unsigned int has_pae,
				       unsigned int preserve_context);

#ifdef CONFIG_KEXEC_JUMP
	if (image->preserve_context)
		save_processor_state();
#endif

	save_ftrace_enabled = __ftrace_enabled_save();

	/* Interrupts aren't acceptable while we reboot */
	local_irq_disable();
	hw_breakpoint_disable();

	if (image->preserve_context) {
#ifdef CONFIG_X86_IO_APIC
		/*
		clear_IO_APIC();
		restore_boot_irq_mode();
#endif
	}

	control_page = page_address(image->control_code_page);
	memcpy(control_page, relocate_kernel, KEXEC_CONTROL_CODE_MAX_SIZE);

	relocate_kernel_ptr = control_page;
	page_list[PA_CONTROL_PAGE] = __pa(control_page);
	page_list[VA_CONTROL_PAGE] = (unsigned long)control_page;
	page_list[PA_PGD] = __pa(image->arch.pgd);

	if (image->type == KEXEC_TYPE_DEFAULT)
		page_list[PA_SWAP_PAGE] = (page_to_pfn(image->swap_page)
						<< PAGE_SHIFT);

	/*
	load_segments();
	/*
	native_idt_invalidate();
	native_gdt_invalidate();

	/* now call it */
	image->start = relocate_kernel_ptr((unsigned long)image->head,
					   (unsigned long)page_list,
					   image->start,
					   boot_cpu_has(X86_FEATURE_PAE),
					   image->preserve_context);

#ifdef CONFIG_KEXEC_JUMP
	if (image->preserve_context)
		restore_processor_state();
#endif

	__ftrace_enabled_restore(save_ftrace_enabled);
}
