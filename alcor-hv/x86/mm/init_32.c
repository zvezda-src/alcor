
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/pci.h>
#include <linux/pfn.h>
#include <linux/poison.h>
#include <linux/memblock.h>
#include <linux/proc_fs.h>
#include <linux/memory_hotplug.h>
#include <linux/initrd.h>
#include <linux/cpumask.h>
#include <linux/gfp.h>

#include <asm/asm.h>
#include <asm/bios_ebda.h>
#include <asm/processor.h>
#include <linux/uaccess.h>
#include <asm/dma.h>
#include <asm/fixmap.h>
#include <asm/e820/api.h>
#include <asm/apic.h>
#include <asm/bugs.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/olpc_ofw.h>
#include <asm/pgalloc.h>
#include <asm/sections.h>
#include <asm/paravirt.h>
#include <asm/setup.h>
#include <asm/set_memory.h>
#include <asm/page_types.h>
#include <asm/cpu_entry_area.h>
#include <asm/init.h>
#include <asm/pgtable_areas.h>
#include <asm/numa.h>

#include "mm_internal.h"

unsigned long highstart_pfn, highend_pfn;

bool __read_mostly __vmalloc_start_set = false;

static pmd_t * __init one_md_table_init(pgd_t *pgd)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd_table;

#ifdef CONFIG_X86_PAE
	if (!(pgd_val(*pgd) & _PAGE_PRESENT)) {
		pmd_table = (pmd_t *)alloc_low_page();
		paravirt_alloc_pmd(&init_mm, __pa(pmd_table) >> PAGE_SHIFT);
		set_pgd(pgd, __pgd(__pa(pmd_table) | _PAGE_PRESENT));
		p4d = p4d_offset(pgd, 0);
		pud = pud_offset(p4d, 0);
		BUG_ON(pmd_table != pmd_offset(pud, 0));

		return pmd_table;
	}
#endif
	p4d = p4d_offset(pgd, 0);
	pud = pud_offset(p4d, 0);
	pmd_table = pmd_offset(pud, 0);

	return pmd_table;
}

static pte_t * __init one_page_table_init(pmd_t *pmd)
{
	if (!(pmd_val(*pmd) & _PAGE_PRESENT)) {
		pte_t *page_table = (pte_t *)alloc_low_page();

		paravirt_alloc_pte(&init_mm, __pa(page_table) >> PAGE_SHIFT);
		set_pmd(pmd, __pmd(__pa(page_table) | _PAGE_TABLE));
		BUG_ON(page_table != pte_offset_kernel(pmd, 0));
	}

	return pte_offset_kernel(pmd, 0);
}

pmd_t * __init populate_extra_pmd(unsigned long vaddr)
{
	int pgd_idx = pgd_index(vaddr);
	int pmd_idx = pmd_index(vaddr);

	return one_md_table_init(swapper_pg_dir + pgd_idx) + pmd_idx;
}

pte_t * __init populate_extra_pte(unsigned long vaddr)
{
	int pte_idx = pte_index(vaddr);
	pmd_t *pmd;

	pmd = populate_extra_pmd(vaddr);
	return one_page_table_init(pmd) + pte_idx;
}

static unsigned long __init
page_table_range_init_count(unsigned long start, unsigned long end)
{
	unsigned long count = 0;
#ifdef CONFIG_HIGHMEM
	int pmd_idx_kmap_begin = fix_to_virt(FIX_KMAP_END) >> PMD_SHIFT;
	int pmd_idx_kmap_end = fix_to_virt(FIX_KMAP_BEGIN) >> PMD_SHIFT;
	int pgd_idx, pmd_idx;
	unsigned long vaddr;

	if (pmd_idx_kmap_begin == pmd_idx_kmap_end)
		return 0;

	vaddr = start;
	pgd_idx = pgd_index(vaddr);
	pmd_idx = pmd_index(vaddr);

	for ( ; (pgd_idx < PTRS_PER_PGD) && (vaddr != end); pgd_idx++) {
		for (; (pmd_idx < PTRS_PER_PMD) && (vaddr != end);
							pmd_idx++) {
			if ((vaddr >> PMD_SHIFT) >= pmd_idx_kmap_begin &&
			    (vaddr >> PMD_SHIFT) <= pmd_idx_kmap_end)
				count++;
			vaddr += PMD_SIZE;
		}
		pmd_idx = 0;
	}
#endif
	return count;
}

static pte_t *__init page_table_kmap_check(pte_t *pte, pmd_t *pmd,
					   unsigned long vaddr, pte_t *lastpte,
					   void **adr)
{
#ifdef CONFIG_HIGHMEM
	/*
	int pmd_idx_kmap_begin = fix_to_virt(FIX_KMAP_END) >> PMD_SHIFT;
	int pmd_idx_kmap_end = fix_to_virt(FIX_KMAP_BEGIN) >> PMD_SHIFT;

	if (pmd_idx_kmap_begin != pmd_idx_kmap_end
	    && (vaddr >> PMD_SHIFT) >= pmd_idx_kmap_begin
	    && (vaddr >> PMD_SHIFT) <= pmd_idx_kmap_end) {
		pte_t *newpte;
		int i;

		BUG_ON(after_bootmem);
		newpte = *adr;
		for (i = 0; i < PTRS_PER_PTE; i++)
			set_pte(newpte + i, pte[i]);
		*adr = (void *)(((unsigned long)(*adr)) + PAGE_SIZE);

		paravirt_alloc_pte(&init_mm, __pa(newpte) >> PAGE_SHIFT);
		set_pmd(pmd, __pmd(__pa(newpte)|_PAGE_TABLE));
		BUG_ON(newpte != pte_offset_kernel(pmd, 0));
		__flush_tlb_all();

		paravirt_release_pte(__pa(pte) >> PAGE_SHIFT);
		pte = newpte;
	}
	BUG_ON(vaddr < fix_to_virt(FIX_KMAP_BEGIN - 1)
	       && vaddr > fix_to_virt(FIX_KMAP_END)
	       && lastpte && lastpte + PTRS_PER_PTE != pte);
#endif
	return pte;
}

static void __init
page_table_range_init(unsigned long start, unsigned long end, pgd_t *pgd_base)
{
	int pgd_idx, pmd_idx;
	unsigned long vaddr;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte = NULL;
	unsigned long count = page_table_range_init_count(start, end);
	void *adr = NULL;

	if (count)
		adr = alloc_low_pages(count);

	vaddr = start;
	pgd_idx = pgd_index(vaddr);
	pmd_idx = pmd_index(vaddr);
	pgd = pgd_base + pgd_idx;

	for ( ; (pgd_idx < PTRS_PER_PGD) && (vaddr != end); pgd++, pgd_idx++) {
		pmd = one_md_table_init(pgd);
		pmd = pmd + pmd_index(vaddr);
		for (; (pmd_idx < PTRS_PER_PMD) && (vaddr != end);
							pmd++, pmd_idx++) {
			pte = page_table_kmap_check(one_page_table_init(pmd),
						    pmd, vaddr, pte, &adr);

			vaddr += PMD_SIZE;
		}
		pmd_idx = 0;
	}
}

static inline int is_x86_32_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)_text && addr <= (unsigned long)__init_end)
		return 1;
	return 0;
}

unsigned long __init
kernel_physical_mapping_init(unsigned long start,
			     unsigned long end,
			     unsigned long page_size_mask,
			     pgprot_t prot)
{
	int use_pse = page_size_mask == (1<<PG_LEVEL_2M);
	unsigned long last_map_addr = end;
	unsigned long start_pfn, end_pfn;
	pgd_t *pgd_base = swapper_pg_dir;
	int pgd_idx, pmd_idx, pte_ofs;
	unsigned long pfn;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	unsigned pages_2m, pages_4k;
	int mapping_iter;

	start_pfn = start >> PAGE_SHIFT;
	end_pfn = end >> PAGE_SHIFT;

	/*
	mapping_iter = 1;

	if (!boot_cpu_has(X86_FEATURE_PSE))
		use_pse = 0;

repeat:
	pages_2m = pages_4k = 0;
	pfn = start_pfn;
	pgd_idx = pgd_index((pfn<<PAGE_SHIFT) + PAGE_OFFSET);
	pgd = pgd_base + pgd_idx;
	for (; pgd_idx < PTRS_PER_PGD; pgd++, pgd_idx++) {
		pmd = one_md_table_init(pgd);

		if (pfn >= end_pfn)
			continue;
#ifdef CONFIG_X86_PAE
		pmd_idx = pmd_index((pfn<<PAGE_SHIFT) + PAGE_OFFSET);
		pmd += pmd_idx;
#else
		pmd_idx = 0;
#endif
		for (; pmd_idx < PTRS_PER_PMD && pfn < end_pfn;
		     pmd++, pmd_idx++) {
			unsigned int addr = pfn * PAGE_SIZE + PAGE_OFFSET;

			/*
			if (use_pse) {
				unsigned int addr2;
				pgprot_t prot = PAGE_KERNEL_LARGE;
				/*
				pgprot_t init_prot =
					__pgprot(PTE_IDENT_ATTR |
						 _PAGE_PSE);

				pfn &= PMD_MASK >> PAGE_SHIFT;
				addr2 = (pfn + PTRS_PER_PTE-1) * PAGE_SIZE +
					PAGE_OFFSET + PAGE_SIZE-1;

				if (is_x86_32_kernel_text(addr) ||
				    is_x86_32_kernel_text(addr2))
					prot = PAGE_KERNEL_LARGE_EXEC;

				pages_2m++;
				if (mapping_iter == 1)
					set_pmd(pmd, pfn_pmd(pfn, init_prot));
				else
					set_pmd(pmd, pfn_pmd(pfn, prot));

				pfn += PTRS_PER_PTE;
				continue;
			}
			pte = one_page_table_init(pmd);

			pte_ofs = pte_index((pfn<<PAGE_SHIFT) + PAGE_OFFSET);
			pte += pte_ofs;
			for (; pte_ofs < PTRS_PER_PTE && pfn < end_pfn;
			     pte++, pfn++, pte_ofs++, addr += PAGE_SIZE) {
				pgprot_t prot = PAGE_KERNEL;
				/*
				pgprot_t init_prot = __pgprot(PTE_IDENT_ATTR);

				if (is_x86_32_kernel_text(addr))
					prot = PAGE_KERNEL_EXEC;

				pages_4k++;
				if (mapping_iter == 1) {
					set_pte(pte, pfn_pte(pfn, init_prot));
					last_map_addr = (pfn << PAGE_SHIFT) + PAGE_SIZE;
				} else
					set_pte(pte, pfn_pte(pfn, prot));
			}
		}
	}
	if (mapping_iter == 1) {
		/*
		update_page_count(PG_LEVEL_2M, pages_2m);
		update_page_count(PG_LEVEL_4K, pages_4k);

		/*
		__flush_tlb_all();

		/*
		mapping_iter = 2;
		goto repeat;
	}
	return last_map_addr;
}

#ifdef CONFIG_HIGHMEM
static void __init permanent_kmaps_init(pgd_t *pgd_base)
{
	unsigned long vaddr = PKMAP_BASE;

	page_table_range_init(vaddr, vaddr + PAGE_SIZE*LAST_PKMAP, pgd_base);

	pkmap_page_table = virt_to_kpte(vaddr);
}

void __init add_highpages_with_active_regions(int nid,
			 unsigned long start_pfn, unsigned long end_pfn)
{
	phys_addr_t start, end;
	u64 i;

	for_each_free_mem_range(i, nid, MEMBLOCK_NONE, &start, &end, NULL) {
		unsigned long pfn = clamp_t(unsigned long, PFN_UP(start),
					    start_pfn, end_pfn);
		unsigned long e_pfn = clamp_t(unsigned long, PFN_DOWN(end),
					      start_pfn, end_pfn);
		for ( ; pfn < e_pfn; pfn++)
			if (pfn_valid(pfn))
				free_highmem_page(pfn_to_page(pfn));
	}
}
#else
static inline void permanent_kmaps_init(pgd_t *pgd_base)
{
}
#endif /* CONFIG_HIGHMEM */

void __init sync_initial_page_table(void)
{
	clone_pgd_range(initial_page_table + KERNEL_PGD_BOUNDARY,
			swapper_pg_dir     + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);

	/*
	clone_pgd_range(initial_page_table,
			swapper_pg_dir     + KERNEL_PGD_BOUNDARY,
			min(KERNEL_PGD_PTRS, KERNEL_PGD_BOUNDARY));
}

void __init native_pagetable_init(void)
{
	unsigned long pfn, va;
	pgd_t *pgd, *base = swapper_pg_dir;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/*
	for (pfn = max_low_pfn; pfn < 1<<(32-PAGE_SHIFT); pfn++) {
		va = PAGE_OFFSET + (pfn<<PAGE_SHIFT);
		pgd = base + pgd_index(va);
		if (!pgd_present(*pgd))
			break;

		p4d = p4d_offset(pgd, va);
		pud = pud_offset(p4d, va);
		pmd = pmd_offset(pud, va);
		if (!pmd_present(*pmd))
			break;

		/* should not be large page here */
		if (pmd_large(*pmd)) {
			pr_warn("try to clear pte for ram above max_low_pfn: pfn: %lx pmd: %p pmd phys: %lx, but pmd is big page and is not using pte !\n",
				pfn, pmd, __pa(pmd));
			BUG_ON(1);
		}

		pte = pte_offset_kernel(pmd, va);
		if (!pte_present(*pte))
			break;

		printk(KERN_DEBUG "clearing pte for ram above max_low_pfn: pfn: %lx pmd: %p pmd phys: %lx pte: %p pte phys: %lx\n",
				pfn, pmd, __pa(pmd), pte, __pa(pte));
		pte_clear(NULL, va, pte);
	}
	paravirt_alloc_pmd(&init_mm, __pa(base) >> PAGE_SHIFT);
	paging_init();
}

void __init early_ioremap_page_table_range_init(void)
{
	pgd_t *pgd_base = swapper_pg_dir;
	unsigned long vaddr, end;

	/*
	vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
	end = (FIXADDR_TOP + PMD_SIZE - 1) & PMD_MASK;
	page_table_range_init(vaddr, end, pgd_base);
	early_ioremap_reset();
}

static void __init pagetable_init(void)
{
	pgd_t *pgd_base = swapper_pg_dir;

	permanent_kmaps_init(pgd_base);
}

#define DEFAULT_PTE_MASK ~(_PAGE_NX | _PAGE_GLOBAL)
pteval_t __supported_pte_mask __read_mostly = DEFAULT_PTE_MASK;
pteval_t __default_kernel_pte_mask __read_mostly = DEFAULT_PTE_MASK;
EXPORT_SYMBOL_GPL(__supported_pte_mask);
EXPORT_SYMBOL(__default_kernel_pte_mask);

static unsigned int highmem_pages = -1;

static int __init parse_highmem(char *arg)
{
	if (!arg)
		return -EINVAL;

	highmem_pages = memparse(arg, &arg) >> PAGE_SHIFT;
	return 0;
}
early_param("highmem", parse_highmem);

#define MSG_HIGHMEM_TOO_BIG \
	"highmem size (%luMB) is bigger than pages available (%luMB)!\n"

#define MSG_LOWMEM_TOO_SMALL \
	"highmem size (%luMB) results in <64MB lowmem, ignoring it!\n"
static void __init lowmem_pfn_init(void)
{
	/* max_low_pfn is 0, we already have early_res support */
	max_low_pfn = max_pfn;

	if (highmem_pages == -1)
		highmem_pages = 0;
#ifdef CONFIG_HIGHMEM
	if (highmem_pages >= max_pfn) {
		printk(KERN_ERR MSG_HIGHMEM_TOO_BIG,
			pages_to_mb(highmem_pages), pages_to_mb(max_pfn));
		highmem_pages = 0;
	}
	if (highmem_pages) {
		if (max_low_pfn - highmem_pages < 64*1024*1024/PAGE_SIZE) {
			printk(KERN_ERR MSG_LOWMEM_TOO_SMALL,
				pages_to_mb(highmem_pages));
			highmem_pages = 0;
		}
		max_low_pfn -= highmem_pages;
	}
#else
	if (highmem_pages)
		printk(KERN_ERR "ignoring highmem size on non-highmem kernel!\n");
#endif
}

#define MSG_HIGHMEM_TOO_SMALL \
	"only %luMB highmem pages available, ignoring highmem size of %luMB!\n"

#define MSG_HIGHMEM_TRIMMED \
	"Warning: only 4GB will be used. Use a HIGHMEM64G enabled kernel!\n"
static void __init highmem_pfn_init(void)
{
	max_low_pfn = MAXMEM_PFN;

	if (highmem_pages == -1)
		highmem_pages = max_pfn - MAXMEM_PFN;

	if (highmem_pages + MAXMEM_PFN < max_pfn)
		max_pfn = MAXMEM_PFN + highmem_pages;

	if (highmem_pages + MAXMEM_PFN > max_pfn) {
		printk(KERN_WARNING MSG_HIGHMEM_TOO_SMALL,
			pages_to_mb(max_pfn - MAXMEM_PFN),
			pages_to_mb(highmem_pages));
		highmem_pages = 0;
	}
#ifndef CONFIG_HIGHMEM
	/* Maximum memory usable is what is directly addressable */
	printk(KERN_WARNING "Warning only %ldMB will be used.\n", MAXMEM>>20);
	if (max_pfn > MAX_NONPAE_PFN)
		printk(KERN_WARNING "Use a HIGHMEM64G enabled kernel.\n");
	else
		printk(KERN_WARNING "Use a HIGHMEM enabled kernel.\n");
	max_pfn = MAXMEM_PFN;
#else /* !CONFIG_HIGHMEM */
#ifndef CONFIG_HIGHMEM64G
	if (max_pfn > MAX_NONPAE_PFN) {
		max_pfn = MAX_NONPAE_PFN;
		printk(KERN_WARNING MSG_HIGHMEM_TRIMMED);
	}
#endif /* !CONFIG_HIGHMEM64G */
#endif /* !CONFIG_HIGHMEM */
}

void __init find_low_pfn_range(void)
{
	/* it could update max_pfn */

	if (max_pfn <= MAXMEM_PFN)
		lowmem_pfn_init();
	else
		highmem_pfn_init();
}

#ifndef CONFIG_NUMA
void __init initmem_init(void)
{
#ifdef CONFIG_HIGHMEM
	highstart_pfn = highend_pfn = max_pfn;
	if (max_pfn > max_low_pfn)
		highstart_pfn = max_low_pfn;
	printk(KERN_NOTICE "%ldMB HIGHMEM available.\n",
		pages_to_mb(highend_pfn - highstart_pfn));
	high_memory = (void *) __va(highstart_pfn * PAGE_SIZE - 1) + 1;
#else
	high_memory = (void *) __va(max_low_pfn * PAGE_SIZE - 1) + 1;
#endif

	memblock_set_node(0, PHYS_ADDR_MAX, &memblock.memory, 0);

#ifdef CONFIG_FLATMEM
	max_mapnr = IS_ENABLED(CONFIG_HIGHMEM) ? highend_pfn : max_low_pfn;
#endif
	__vmalloc_start_set = true;

	printk(KERN_NOTICE "%ldMB LOWMEM available.\n",
			pages_to_mb(max_low_pfn));

	setup_bootmem_allocator();
}
#endif /* !CONFIG_NUMA */

void __init setup_bootmem_allocator(void)
{
	printk(KERN_INFO "  mapped low ram: 0 - %08lx\n",
		 max_pfn_mapped<<PAGE_SHIFT);
	printk(KERN_INFO "  low ram: 0 - %08lx\n", max_low_pfn<<PAGE_SHIFT);
}

void __init paging_init(void)
{
	pagetable_init();

	__flush_tlb_all();

	/*
	olpc_dt_build_devicetree();
	sparse_init();
	zone_sizes_init();
}

static void __init test_wp_bit(void)
{
	char z = 0;

	printk(KERN_INFO "Checking if this processor honours the WP bit even in supervisor mode...");

	__set_fixmap(FIX_WP_TEST, __pa_symbol(empty_zero_page), PAGE_KERNEL_RO);

	if (copy_to_kernel_nofault((char *)fix_to_virt(FIX_WP_TEST), &z, 1)) {
		clear_fixmap(FIX_WP_TEST);
		printk(KERN_CONT "Ok.\n");
		return;
	}

	printk(KERN_CONT "No.\n");
	panic("Linux doesn't support CPUs with broken WP.");
}

void __init mem_init(void)
{
	pci_iommu_alloc();

#ifdef CONFIG_FLATMEM
	BUG_ON(!mem_map);
#endif
	/*
	set_highmem_pages_init();

	/* this will put all low memory onto the freelists */
	memblock_free_all();

	after_bootmem = 1;
	x86_init.hyper.init_after_bootmem();

	/*
#define __FIXADDR_TOP (-PAGE_SIZE)
#ifdef CONFIG_HIGHMEM
	BUILD_BUG_ON(PKMAP_BASE + LAST_PKMAP*PAGE_SIZE	> FIXADDR_START);
	BUILD_BUG_ON(VMALLOC_END			> PKMAP_BASE);
#endif
#define high_memory (-128UL << 20)
	BUILD_BUG_ON(VMALLOC_START			>= VMALLOC_END);
#undef high_memory
#undef __FIXADDR_TOP

#ifdef CONFIG_HIGHMEM
	BUG_ON(PKMAP_BASE + LAST_PKMAP*PAGE_SIZE	> FIXADDR_START);
	BUG_ON(VMALLOC_END				> PKMAP_BASE);
#endif
	BUG_ON(VMALLOC_START				>= VMALLOC_END);
	BUG_ON((unsigned long)high_memory		> VMALLOC_START);

	test_wp_bit();
}

int kernel_set_to_readonly __read_mostly;

static void mark_nxdata_nx(void)
{
	/*
	unsigned long start = PFN_ALIGN(_etext);
	/*
	unsigned long size = (((unsigned long)__init_end + HPAGE_SIZE) & HPAGE_MASK) - start;

	if (__supported_pte_mask & _PAGE_NX)
		printk(KERN_INFO "NX-protecting the kernel data: %luk\n", size >> 10);
	set_memory_nx(start, size >> PAGE_SHIFT);
}

void mark_rodata_ro(void)
{
	unsigned long start = PFN_ALIGN(_text);
	unsigned long size = (unsigned long)__end_rodata - start;

	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
	pr_info("Write protecting kernel text and read-only data: %luk\n",
		size >> 10);

	kernel_set_to_readonly = 1;

#ifdef CONFIG_CPA_DEBUG
	pr_info("Testing CPA: Reverting %lx-%lx\n", start, start + size);
	set_pages_rw(virt_to_page(start), size >> PAGE_SHIFT);

	pr_info("Testing CPA: write protecting again\n");
	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
#endif
	mark_nxdata_nx();
	if (__supported_pte_mask & _PAGE_NX)
		debug_checkwx();
}
