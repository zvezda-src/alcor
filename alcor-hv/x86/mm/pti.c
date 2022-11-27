#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/cpu.h>

#include <asm/cpufeature.h>
#include <asm/hypervisor.h>
#include <asm/vsyscall.h>
#include <asm/cmdline.h>
#include <asm/pti.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/sections.h>
#include <asm/set_memory.h>

#undef pr_fmt
#define pr_fmt(fmt)     "Kernel/User page tables isolation: " fmt

#ifndef __GFP_NOTRACK
#define __GFP_NOTRACK	0
#endif

#ifdef CONFIG_X86_64
#define	PTI_LEVEL_KERNEL_IMAGE	PTI_CLONE_PMD
#else
#define	PTI_LEVEL_KERNEL_IMAGE	PTI_CLONE_PTE
#endif

static void __init pti_print_if_insecure(const char *reason)
{
	if (boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN))
		pr_info("%s\n", reason);
}

static void __init pti_print_if_secure(const char *reason)
{
	if (!boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN))
		pr_info("%s\n", reason);
}

static enum pti_mode {
	PTI_AUTO = 0,
	PTI_FORCE_OFF,
	PTI_FORCE_ON
} pti_mode;

void __init pti_check_boottime_disable(void)
{
	char arg[5];
	int ret;

	/* Assume mode is auto unless overridden. */
	pti_mode = PTI_AUTO;

	if (hypervisor_is_type(X86_HYPER_XEN_PV)) {
		pti_mode = PTI_FORCE_OFF;
		pti_print_if_insecure("disabled on XEN PV.");
		return;
	}

	ret = cmdline_find_option(boot_command_line, "pti", arg, sizeof(arg));
	if (ret > 0)  {
		if (ret == 3 && !strncmp(arg, "off", 3)) {
			pti_mode = PTI_FORCE_OFF;
			pti_print_if_insecure("disabled on command line.");
			return;
		}
		if (ret == 2 && !strncmp(arg, "on", 2)) {
			pti_mode = PTI_FORCE_ON;
			pti_print_if_secure("force enabled on command line.");
			goto enable;
		}
		if (ret == 4 && !strncmp(arg, "auto", 4)) {
			pti_mode = PTI_AUTO;
			goto autosel;
		}
	}

	if (cmdline_find_option_bool(boot_command_line, "nopti") ||
	    cpu_mitigations_off()) {
		pti_mode = PTI_FORCE_OFF;
		pti_print_if_insecure("disabled on command line.");
		return;
	}

autosel:
	if (!boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN))
		return;
enable:
	setup_force_cpu_cap(X86_FEATURE_PTI);
}

pgd_t __pti_set_user_pgtbl(pgd_t *pgdp, pgd_t pgd)
{
	/*
	if (!pgdp_maps_userspace(pgdp))
		return pgd;

	/*
	kernel_to_user_pgdp(pgdp)->pgd = pgd.pgd;

	/*
	if ((pgd.pgd & (_PAGE_USER|_PAGE_PRESENT)) == (_PAGE_USER|_PAGE_PRESENT) &&
	    (__supported_pte_mask & _PAGE_NX))
		pgd.pgd |= _PAGE_NX;

	/* return the copy of the PGD we want the kernel to use: */
	return pgd;
}

static p4d_t *pti_user_pagetable_walk_p4d(unsigned long address)
{
	pgd_t *pgd = kernel_to_user_pgdp(pgd_offset_k(address));
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK | __GFP_ZERO);

	if (address < PAGE_OFFSET) {
		WARN_ONCE(1, "attempt to walk user address\n");
		return NULL;
	}

	if (pgd_none(*pgd)) {
		unsigned long new_p4d_page = __get_free_page(gfp);
		if (WARN_ON_ONCE(!new_p4d_page))
			return NULL;

		set_pgd(pgd, __pgd(_KERNPG_TABLE | __pa(new_p4d_page)));
	}
	BUILD_BUG_ON(pgd_large(*pgd) != 0);

	return p4d_offset(pgd, address);
}

static pmd_t *pti_user_pagetable_walk_pmd(unsigned long address)
{
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK | __GFP_ZERO);
	p4d_t *p4d;
	pud_t *pud;

	p4d = pti_user_pagetable_walk_p4d(address);
	if (!p4d)
		return NULL;

	BUILD_BUG_ON(p4d_large(*p4d) != 0);
	if (p4d_none(*p4d)) {
		unsigned long new_pud_page = __get_free_page(gfp);
		if (WARN_ON_ONCE(!new_pud_page))
			return NULL;

		set_p4d(p4d, __p4d(_KERNPG_TABLE | __pa(new_pud_page)));
	}

	pud = pud_offset(p4d, address);
	/* The user page tables do not use large mappings: */
	if (pud_large(*pud)) {
		WARN_ON(1);
		return NULL;
	}
	if (pud_none(*pud)) {
		unsigned long new_pmd_page = __get_free_page(gfp);
		if (WARN_ON_ONCE(!new_pmd_page))
			return NULL;

		set_pud(pud, __pud(_KERNPG_TABLE | __pa(new_pmd_page)));
	}

	return pmd_offset(pud, address);
}

static pte_t *pti_user_pagetable_walk_pte(unsigned long address)
{
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK | __GFP_ZERO);
	pmd_t *pmd;
	pte_t *pte;

	pmd = pti_user_pagetable_walk_pmd(address);
	if (!pmd)
		return NULL;

	/* We can't do anything sensible if we hit a large mapping. */
	if (pmd_large(*pmd)) {
		WARN_ON(1);
		return NULL;
	}

	if (pmd_none(*pmd)) {
		unsigned long new_pte_page = __get_free_page(gfp);
		if (!new_pte_page)
			return NULL;

		set_pmd(pmd, __pmd(_KERNPG_TABLE | __pa(new_pte_page)));
	}

	pte = pte_offset_kernel(pmd, address);
	if (pte_flags(*pte) & _PAGE_USER) {
		WARN_ONCE(1, "attempt to walk to user pte\n");
		return NULL;
	}
	return pte;
}

#ifdef CONFIG_X86_VSYSCALL_EMULATION
static void __init pti_setup_vsyscall(void)
{
	pte_t *pte, *target_pte;
	unsigned int level;

	pte = lookup_address(VSYSCALL_ADDR, &level);
	if (!pte || WARN_ON(level != PG_LEVEL_4K) || pte_none(*pte))
		return;

	target_pte = pti_user_pagetable_walk_pte(VSYSCALL_ADDR);
	if (WARN_ON(!target_pte))
		return;

	set_vsyscall_pgtable_user_bits(kernel_to_user_pgdp(swapper_pg_dir));
}
#else
static void __init pti_setup_vsyscall(void) { }
#endif

enum pti_clone_level {
	PTI_CLONE_PMD,
	PTI_CLONE_PTE,
};

static void
pti_clone_pgtable(unsigned long start, unsigned long end,
		  enum pti_clone_level level)
{
	unsigned long addr;

	/*
	for (addr = start; addr < end;) {
		pte_t *pte, *target_pte;
		pmd_t *pmd, *target_pmd;
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;

		/* Overflow check */
		if (addr < start)
			break;

		pgd = pgd_offset_k(addr);
		if (WARN_ON(pgd_none(*pgd)))
			return;
		p4d = p4d_offset(pgd, addr);
		if (WARN_ON(p4d_none(*p4d)))
			return;

		pud = pud_offset(p4d, addr);
		if (pud_none(*pud)) {
			WARN_ON_ONCE(addr & ~PUD_MASK);
			addr = round_up(addr + 1, PUD_SIZE);
			continue;
		}

		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd)) {
			WARN_ON_ONCE(addr & ~PMD_MASK);
			addr = round_up(addr + 1, PMD_SIZE);
			continue;
		}

		if (pmd_large(*pmd) || level == PTI_CLONE_PMD) {
			target_pmd = pti_user_pagetable_walk_pmd(addr);
			if (WARN_ON(!target_pmd))
				return;

			/*
			if (WARN_ON(!(pmd_flags(*pmd) & _PAGE_PRESENT)))
				return;

			/*
			if (boot_cpu_has(X86_FEATURE_PGE))
				*pmd = pmd_set_flags(*pmd, _PAGE_GLOBAL);

			/*
			*target_pmd = *pmd;

			addr += PMD_SIZE;

		} else if (level == PTI_CLONE_PTE) {

			/* Walk the page-table down to the pte level */
			pte = pte_offset_kernel(pmd, addr);
			if (pte_none(*pte)) {
				addr += PAGE_SIZE;
				continue;
			}

			/* Only clone present PTEs */
			if (WARN_ON(!(pte_flags(*pte) & _PAGE_PRESENT)))
				return;

			/* Allocate PTE in the user page-table */
			target_pte = pti_user_pagetable_walk_pte(addr);
			if (WARN_ON(!target_pte))
				return;

			/* Set GLOBAL bit in both PTEs */
			if (boot_cpu_has(X86_FEATURE_PGE))
				*pte = pte_set_flags(*pte, _PAGE_GLOBAL);

			/* Clone the PTE */
			*target_pte = *pte;

			addr += PAGE_SIZE;

		} else {
			BUG();
		}
	}
}

#ifdef CONFIG_X86_64
static void __init pti_clone_p4d(unsigned long addr)
{
	p4d_t *kernel_p4d, *user_p4d;
	pgd_t *kernel_pgd;

	user_p4d = pti_user_pagetable_walk_p4d(addr);
	if (!user_p4d)
		return;

	kernel_pgd = pgd_offset_k(addr);
	kernel_p4d = p4d_offset(kernel_pgd, addr);
}

static void __init pti_clone_user_shared(void)
{
	unsigned int cpu;

	pti_clone_p4d(CPU_ENTRY_AREA_BASE);

	for_each_possible_cpu(cpu) {
		/*

		unsigned long va = (unsigned long)&per_cpu(cpu_tss_rw, cpu);
		phys_addr_t pa = per_cpu_ptr_to_phys((void *)va);
		pte_t *target_pte;

		target_pte = pti_user_pagetable_walk_pte(va);
		if (WARN_ON(!target_pte))
			return;

		*target_pte = pfn_pte(pa >> PAGE_SHIFT, PAGE_KERNEL);
	}
}

#else /* CONFIG_X86_64 */

static void __init pti_clone_user_shared(void)
{
	unsigned long start, end;

	start = CPU_ENTRY_AREA_BASE;
	end   = start + (PAGE_SIZE * CPU_ENTRY_AREA_PAGES);

	pti_clone_pgtable(start, end, PTI_CLONE_PMD);
}
#endif /* CONFIG_X86_64 */

static void __init pti_setup_espfix64(void)
{
#ifdef CONFIG_X86_ESPFIX64
	pti_clone_p4d(ESPFIX_BASE_ADDR);
#endif
}

static void pti_clone_entry_text(void)
{
	pti_clone_pgtable((unsigned long) __entry_text_start,
			  (unsigned long) __entry_text_end,
			  PTI_CLONE_PMD);
}

static inline bool pti_kernel_image_global_ok(void)
{
	/*
	if (cpu_feature_enabled(X86_FEATURE_PCID))
		return false;

	/*
	if (pti_mode != PTI_AUTO)
		return false;

	/*
	if (boot_cpu_has(X86_FEATURE_K8))
		return false;

	/*
	if (IS_ENABLED(CONFIG_RANDSTRUCT))
		return false;

	return true;
}

static void pti_clone_kernel_text(void)
{
	/*
	unsigned long start = PFN_ALIGN(_text);
	unsigned long end_clone  = (unsigned long)__end_rodata_aligned;
	unsigned long end_global = PFN_ALIGN((unsigned long)_etext);

	if (!pti_kernel_image_global_ok())
		return;

	pr_debug("mapping partial kernel image into user address space\n");

	/*
	pti_clone_pgtable(start, end_clone, PTI_LEVEL_KERNEL_IMAGE);

	/*

	/* Set the global bit for normal non-__init kernel text: */
	set_memory_global(start, (end_global - start) >> PAGE_SHIFT);
}

static void pti_set_kernel_image_nonglobal(void)
{
	/*
	unsigned long start = PFN_ALIGN(_text);
	unsigned long end = ALIGN((unsigned long)_end, PMD_PAGE_SIZE);

	/*
	set_memory_nonglobal(start, (end - start) >> PAGE_SHIFT);
}

void __init pti_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_PTI))
		return;

	pr_info("enabled\n");

#ifdef CONFIG_X86_32
	/*
	if (cpuid_ecx(0x1) & BIT(17)) {
		/* Use printk to work around pr_fmt() */
		printk(KERN_WARNING "\n");
		printk(KERN_WARNING "************************************************************\n");
		printk(KERN_WARNING "** WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!  **\n");
		printk(KERN_WARNING "**                                                        **\n");
		printk(KERN_WARNING "** You are using 32-bit PTI on a 64-bit PCID-capable CPU. **\n");
		printk(KERN_WARNING "** Your performance will increase dramatically if you     **\n");
		printk(KERN_WARNING "** switch to a 64-bit kernel!                             **\n");
		printk(KERN_WARNING "**                                                        **\n");
		printk(KERN_WARNING "** WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!  **\n");
		printk(KERN_WARNING "************************************************************\n");
	}
#endif

	pti_clone_user_shared();

	/* Undo all global bits from the init pagetables in head_64.S: */
	pti_set_kernel_image_nonglobal();
	/* Replace some of the global bits just for shared entry text: */
	pti_clone_entry_text();
	pti_setup_espfix64();
	pti_setup_vsyscall();
}

void pti_finalize(void)
{
	if (!boot_cpu_has(X86_FEATURE_PTI))
		return;
	/*
	pti_clone_entry_text();
	pti_clone_kernel_text();

	debug_checkwx_user();
}
