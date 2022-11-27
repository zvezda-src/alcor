#include <linux/highmem.h>
#include <linux/memblock.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/pfn.h>
#include <linux/percpu.h>
#include <linux/gfp.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/libnvdimm.h>
#include <linux/vmstat.h>
#include <linux/kernel.h>
#include <linux/cc_platform.h>
#include <linux/set_memory.h>

#include <asm/e820/api.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <linux/uaccess.h>
#include <asm/pgalloc.h>
#include <asm/proto.h>
#include <asm/memtype.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>

#include "../mm_internal.h"

struct cpa_data {
	unsigned long	*vaddr;
	pgd_t		*pgd;
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
	unsigned long	numpages;
	unsigned long	curpage;
	unsigned long	pfn;
	unsigned int	flags;
	unsigned int	force_split		: 1,
			force_static_prot	: 1,
			force_flush_all		: 1;
	struct page	**pages;
};

enum cpa_warn {
	CPA_CONFLICT,
	CPA_PROTECT,
	CPA_DETECT,
};

static const int cpa_warn_level = CPA_PROTECT;

static DEFINE_SPINLOCK(cpa_lock);

#define CPA_FLUSHTLB 1
#define CPA_ARRAY 2
#define CPA_PAGES_ARRAY 4
#define CPA_NO_CHECK_ALIAS 8 /* Do not search for aliases */

static inline pgprot_t cachemode2pgprot(enum page_cache_mode pcm)
{
	return __pgprot(cachemode2protval(pcm));
}

#ifdef CONFIG_PROC_FS
static unsigned long direct_pages_count[PG_LEVEL_NUM];

void update_page_count(int level, unsigned long pages)
{
	/* Protect against CPA */
	spin_lock(&pgd_lock);
	direct_pages_count[level] += pages;
	spin_unlock(&pgd_lock);
}

static void split_page_count(int level)
{
	if (direct_pages_count[level] == 0)
		return;

	direct_pages_count[level]--;
	if (system_state == SYSTEM_RUNNING) {
		if (level == PG_LEVEL_2M)
			count_vm_event(DIRECT_MAP_LEVEL2_SPLIT);
		else if (level == PG_LEVEL_1G)
			count_vm_event(DIRECT_MAP_LEVEL3_SPLIT);
	}
	direct_pages_count[level - 1] += PTRS_PER_PTE;
}

void arch_report_meminfo(struct seq_file *m)
{
	seq_printf(m, "DirectMap4k:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_4K] << 2);
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
	seq_printf(m, "DirectMap2M:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_2M] << 11);
#else
	seq_printf(m, "DirectMap4M:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_2M] << 12);
#endif
	if (direct_gbpages)
		seq_printf(m, "DirectMap1G:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_1G] << 20);
}
#else
static inline void split_page_count(int level) { }
#endif

#ifdef CONFIG_X86_CPA_STATISTICS

static unsigned long cpa_1g_checked;
static unsigned long cpa_1g_sameprot;
static unsigned long cpa_1g_preserved;
static unsigned long cpa_2m_checked;
static unsigned long cpa_2m_sameprot;
static unsigned long cpa_2m_preserved;
static unsigned long cpa_4k_install;

static inline void cpa_inc_1g_checked(void)
{
	cpa_1g_checked++;
}

static inline void cpa_inc_2m_checked(void)
{
	cpa_2m_checked++;
}

static inline void cpa_inc_4k_install(void)
{
	data_race(cpa_4k_install++);
}

static inline void cpa_inc_lp_sameprot(int level)
{
	if (level == PG_LEVEL_1G)
		cpa_1g_sameprot++;
	else
		cpa_2m_sameprot++;
}

static inline void cpa_inc_lp_preserved(int level)
{
	if (level == PG_LEVEL_1G)
		cpa_1g_preserved++;
	else
		cpa_2m_preserved++;
}

static int cpastats_show(struct seq_file *m, void *p)
{
	seq_printf(m, "1G pages checked:     %16lu\n", cpa_1g_checked);
	seq_printf(m, "1G pages sameprot:    %16lu\n", cpa_1g_sameprot);
	seq_printf(m, "1G pages preserved:   %16lu\n", cpa_1g_preserved);
	seq_printf(m, "2M pages checked:     %16lu\n", cpa_2m_checked);
	seq_printf(m, "2M pages sameprot:    %16lu\n", cpa_2m_sameprot);
	seq_printf(m, "2M pages preserved:   %16lu\n", cpa_2m_preserved);
	seq_printf(m, "4K pages set-checked: %16lu\n", cpa_4k_install);
	return 0;
}

static int cpastats_open(struct inode *inode, struct file *file)
{
	return single_open(file, cpastats_show, NULL);
}

static const struct file_operations cpastats_fops = {
	.open		= cpastats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init cpa_stats_init(void)
{
	debugfs_create_file("cpa_stats", S_IRUSR, arch_debugfs_dir, NULL,
			    &cpastats_fops);
	return 0;
}
late_initcall(cpa_stats_init);
#else
static inline void cpa_inc_1g_checked(void) { }
static inline void cpa_inc_2m_checked(void) { }
static inline void cpa_inc_4k_install(void) { }
static inline void cpa_inc_lp_sameprot(int level) { }
static inline void cpa_inc_lp_preserved(int level) { }
#endif


static inline int
within(unsigned long addr, unsigned long start, unsigned long end)
{
	return addr >= start && addr < end;
}

static inline int
within_inclusive(unsigned long addr, unsigned long start, unsigned long end)
{
	return addr >= start && addr <= end;
}

#ifdef CONFIG_X86_64

static inline unsigned long highmap_start_pfn(void)
{
	return __pa_symbol(_text) >> PAGE_SHIFT;
}

static inline unsigned long highmap_end_pfn(void)
{
	/* Do not reference physical address outside the kernel. */
	return __pa_symbol(roundup(_brk_end, PMD_SIZE) - 1) >> PAGE_SHIFT;
}

static bool __cpa_pfn_in_highmap(unsigned long pfn)
{
	/*
	return within_inclusive(pfn, highmap_start_pfn(), highmap_end_pfn());
}

#else

static bool __cpa_pfn_in_highmap(unsigned long pfn)
{
	/* There is no highmap on 32-bit */
	return false;
}

#endif

static inline unsigned long fix_addr(unsigned long addr)
{
#ifdef CONFIG_X86_64
	return (long)(addr << 1) >> 1;
#else
	return addr;
#endif
}

static unsigned long __cpa_addr(struct cpa_data *cpa, unsigned long idx)
{
	if (cpa->flags & CPA_PAGES_ARRAY) {
		struct page *page = cpa->pages[idx];

		if (unlikely(PageHighMem(page)))
			return 0;

		return (unsigned long)page_address(page);
	}

	if (cpa->flags & CPA_ARRAY)
		return cpa->vaddr[idx];

	return *cpa->vaddr + idx * PAGE_SIZE;
}


static void clflush_cache_range_opt(void *vaddr, unsigned int size)
{
	const unsigned long clflush_size = boot_cpu_data.x86_clflush_size;
	void *p = (void *)((unsigned long)vaddr & ~(clflush_size - 1));
	void *vend = vaddr + size;

	if (p >= vend)
		return;

	for (; p < vend; p += clflush_size)
		clflushopt(p);
}

void clflush_cache_range(void *vaddr, unsigned int size)
{
	mb();
	clflush_cache_range_opt(vaddr, size);
	mb();
}
EXPORT_SYMBOL_GPL(clflush_cache_range);

#ifdef CONFIG_ARCH_HAS_PMEM_API
void arch_invalidate_pmem(void *addr, size_t size)
{
	clflush_cache_range(addr, size);
}
EXPORT_SYMBOL_GPL(arch_invalidate_pmem);
#endif

static void __cpa_flush_all(void *arg)
{
	unsigned long cache = (unsigned long)arg;

	/*
	__flush_tlb_all();

	if (cache && boot_cpu_data.x86 >= 4)
		wbinvd();
}

static void cpa_flush_all(unsigned long cache)
{
	BUG_ON(irqs_disabled() && !early_boot_irqs_disabled);

	on_each_cpu(__cpa_flush_all, (void *) cache, 1);
}

static void __cpa_flush_tlb(void *data)
{
	struct cpa_data *cpa = data;
	unsigned int i;

	for (i = 0; i < cpa->numpages; i++)
		flush_tlb_one_kernel(fix_addr(__cpa_addr(cpa, i)));
}

static void cpa_flush(struct cpa_data *data, int cache)
{
	struct cpa_data *cpa = data;
	unsigned int i;

	BUG_ON(irqs_disabled() && !early_boot_irqs_disabled);

	if (cache && !static_cpu_has(X86_FEATURE_CLFLUSH)) {
		cpa_flush_all(cache);
		return;
	}

	if (cpa->force_flush_all || cpa->numpages > tlb_single_page_flush_ceiling)
		flush_tlb_all();
	else
		on_each_cpu(__cpa_flush_tlb, cpa, 1);

	if (!cache)
		return;

	mb();
	for (i = 0; i < cpa->numpages; i++) {
		unsigned long addr = __cpa_addr(cpa, i);
		unsigned int level;

		pte_t *pte = lookup_address(addr, &level);

		/*
		if (pte && (pte_val(*pte) & _PAGE_PRESENT))
			clflush_cache_range_opt((void *)fix_addr(addr), PAGE_SIZE);
	}
	mb();
}

static bool overlaps(unsigned long r1_start, unsigned long r1_end,
		     unsigned long r2_start, unsigned long r2_end)
{
	return (r1_start <= r2_end && r1_end >= r2_start) ||
		(r2_start <= r1_end && r2_end >= r1_start);
}

#ifdef CONFIG_PCI_BIOS
#define BIOS_PFN	PFN_DOWN(BIOS_BEGIN)
#define BIOS_PFN_END	PFN_DOWN(BIOS_END - 1)

static pgprotval_t protect_pci_bios(unsigned long spfn, unsigned long epfn)
{
	if (pcibios_enabled && overlaps(spfn, epfn, BIOS_PFN, BIOS_PFN_END))
		return _PAGE_NX;
	return 0;
}
#else
static pgprotval_t protect_pci_bios(unsigned long spfn, unsigned long epfn)
{
	return 0;
}
#endif

static pgprotval_t protect_rodata(unsigned long spfn, unsigned long epfn)
{
	unsigned long epfn_ro, spfn_ro = PFN_DOWN(__pa_symbol(__start_rodata));

	/*
	epfn_ro = PFN_DOWN(__pa_symbol(__end_rodata)) - 1;

	if (kernel_set_to_readonly && overlaps(spfn, epfn, spfn_ro, epfn_ro))
		return _PAGE_RW;
	return 0;
}

static pgprotval_t protect_kernel_text(unsigned long start, unsigned long end)
{
	unsigned long t_end = (unsigned long)_etext - 1;
	unsigned long t_start = (unsigned long)_text;

	if (overlaps(start, end, t_start, t_end))
		return _PAGE_NX;
	return 0;
}

#if defined(CONFIG_X86_64)
static pgprotval_t protect_kernel_text_ro(unsigned long start,
					  unsigned long end)
{
	unsigned long t_end = (unsigned long)__end_rodata_hpage_align - 1;
	unsigned long t_start = (unsigned long)_text;
	unsigned int level;

	if (!kernel_set_to_readonly || !overlaps(start, end, t_start, t_end))
		return 0;
	/*
	if (lookup_address(start, &level) && (level != PG_LEVEL_4K))
		return _PAGE_RW;
	return 0;
}
#else
static pgprotval_t protect_kernel_text_ro(unsigned long start,
					  unsigned long end)
{
	return 0;
}
#endif

static inline bool conflicts(pgprot_t prot, pgprotval_t val)
{
	return (pgprot_val(prot) & ~val) != pgprot_val(prot);
}

static inline void check_conflict(int warnlvl, pgprot_t prot, pgprotval_t val,
				  unsigned long start, unsigned long end,
				  unsigned long pfn, const char *txt)
{
	static const char *lvltxt[] = {
		[CPA_CONFLICT]	= "conflict",
		[CPA_PROTECT]	= "protect",
		[CPA_DETECT]	= "detect",
	};

	if (warnlvl > cpa_warn_level || !conflicts(prot, val))
		return;

	pr_warn("CPA %8s %10s: 0x%016lx - 0x%016lx PFN %lx req %016llx prevent %016llx\n",
		lvltxt[warnlvl], txt, start, end, pfn, (unsigned long long)pgprot_val(prot),
		(unsigned long long)val);
}

static inline pgprot_t static_protections(pgprot_t prot, unsigned long start,
					  unsigned long pfn, unsigned long npg,
					  unsigned long lpsize, int warnlvl)
{
	pgprotval_t forbidden, res;
	unsigned long end;

	/*
	if (!(pgprot_val(prot) & _PAGE_PRESENT))
		return prot;

	/* Operate on the virtual address */
	end = start + npg * PAGE_SIZE - 1;

	res = protect_kernel_text(start, end);
	check_conflict(warnlvl, prot, res, start, end, pfn, "Text NX");
	forbidden = res;

	/*
	if (lpsize != (npg * PAGE_SIZE) || (start & (lpsize - 1))) {
		res = protect_kernel_text_ro(start, end);
		check_conflict(warnlvl, prot, res, start, end, pfn, "Text RO");
		forbidden |= res;
	}

	/* Check the PFN directly */
	res = protect_pci_bios(pfn, pfn + npg - 1);
	check_conflict(warnlvl, prot, res, start, end, pfn, "PCIBIOS NX");
	forbidden |= res;

	res = protect_rodata(pfn, pfn + npg - 1);
	check_conflict(warnlvl, prot, res, start, end, pfn, "Rodata RO");
	forbidden |= res;

	return __pgprot(pgprot_val(prot) & ~forbidden);
}

pte_t *lookup_address_in_pgd(pgd_t *pgd, unsigned long address,
			     unsigned int *level)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;


	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d))
		return NULL;

	if (p4d_large(*p4d) || !p4d_present(*p4d))
		return (pte_t *)p4d;

	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		return NULL;

	if (pud_large(*pud) || !pud_present(*pud))
		return (pte_t *)pud;

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return NULL;

	if (pmd_large(*pmd) || !pmd_present(*pmd))
		return (pte_t *)pmd;


	return pte_offset_kernel(pmd, address);
}

pte_t *lookup_address(unsigned long address, unsigned int *level)
{
	return lookup_address_in_pgd(pgd_offset_k(address), address, level);
}
EXPORT_SYMBOL_GPL(lookup_address);

static pte_t *_lookup_address_cpa(struct cpa_data *cpa, unsigned long address,
				  unsigned int *level)
{
	if (cpa->pgd)
		return lookup_address_in_pgd(cpa->pgd + pgd_index(address),
					       address, level);

	return lookup_address(address, level);
}

pmd_t *lookup_pmd_address(unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	pgd = pgd_offset_k(address);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d) || p4d_large(*p4d) || !p4d_present(*p4d))
		return NULL;

	pud = pud_offset(p4d, address);
	if (pud_none(*pud) || pud_large(*pud) || !pud_present(*pud))
		return NULL;

	return pmd_offset(pud, address);
}

phys_addr_t slow_virt_to_phys(void *__virt_addr)
{
	unsigned long virt_addr = (unsigned long)__virt_addr;
	phys_addr_t phys_addr;
	unsigned long offset;
	enum pg_level level;
	pte_t *pte;

	pte = lookup_address(virt_addr, &level);
	BUG_ON(!pte);

	/*
	switch (level) {
	case PG_LEVEL_1G:
		phys_addr = (phys_addr_t)pud_pfn(*(pud_t *)pte) << PAGE_SHIFT;
		offset = virt_addr & ~PUD_PAGE_MASK;
		break;
	case PG_LEVEL_2M:
		phys_addr = (phys_addr_t)pmd_pfn(*(pmd_t *)pte) << PAGE_SHIFT;
		offset = virt_addr & ~PMD_PAGE_MASK;
		break;
	default:
		phys_addr = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
		offset = virt_addr & ~PAGE_MASK;
	}

	return (phys_addr_t)(phys_addr | offset);
}
EXPORT_SYMBOL_GPL(slow_virt_to_phys);

static void __set_pmd_pte(pte_t *kpte, unsigned long address, pte_t pte)
{
	/* change init_mm */
	set_pte_atomic(kpte, pte);
#ifdef CONFIG_X86_32
	if (!SHARED_KERNEL_PMD) {
		struct page *page;

		list_for_each_entry(page, &pgd_list, lru) {
			pgd_t *pgd;
			p4d_t *p4d;
			pud_t *pud;
			pmd_t *pmd;

			pgd = (pgd_t *)page_address(page) + pgd_index(address);
			p4d = p4d_offset(pgd, address);
			pud = pud_offset(p4d, address);
			pmd = pmd_offset(pud, address);
			set_pte_atomic((pte_t *)pmd, pte);
		}
	}
#endif
}

static pgprot_t pgprot_clear_protnone_bits(pgprot_t prot)
{
	/*
	if (!(pgprot_val(prot) & _PAGE_PRESENT))
		pgprot_val(prot) &= ~_PAGE_GLOBAL;

	return prot;
}

static int __should_split_large_page(pte_t *kpte, unsigned long address,
				     struct cpa_data *cpa)
{
	unsigned long numpages, pmask, psize, lpaddr, pfn, old_pfn;
	pgprot_t old_prot, new_prot, req_prot, chk_prot;
	pte_t new_pte, *tmp;
	enum pg_level level;

	/*
	tmp = _lookup_address_cpa(cpa, address, &level);
	if (tmp != kpte)
		return 1;

	switch (level) {
	case PG_LEVEL_2M:
		old_prot = pmd_pgprot(*(pmd_t *)kpte);
		old_pfn = pmd_pfn(*(pmd_t *)kpte);
		cpa_inc_2m_checked();
		break;
	case PG_LEVEL_1G:
		old_prot = pud_pgprot(*(pud_t *)kpte);
		old_pfn = pud_pfn(*(pud_t *)kpte);
		cpa_inc_1g_checked();
		break;
	default:
		return -EINVAL;
	}

	psize = page_level_size(level);
	pmask = page_level_mask(level);

	/*
	lpaddr = (address + psize) & pmask;
	numpages = (lpaddr - address) >> PAGE_SHIFT;
	if (numpages < cpa->numpages)
		cpa->numpages = numpages;

	/*

	/* Clear PSE (aka _PAGE_PAT) and move PAT bit to correct position */
	req_prot = pgprot_large_2_4k(old_prot);

	pgprot_val(req_prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(req_prot) |= pgprot_val(cpa->mask_set);

	/*
	req_prot = pgprot_4k_2_large(req_prot);
	req_prot = pgprot_clear_protnone_bits(req_prot);
	if (pgprot_val(req_prot) & _PAGE_PRESENT)
		pgprot_val(req_prot) |= _PAGE_PSE;

	/*
	pfn = old_pfn + ((address & (psize - 1)) >> PAGE_SHIFT);
	cpa->pfn = pfn;

	/*
	lpaddr = address & pmask;
	numpages = psize >> PAGE_SHIFT;

	/*
	chk_prot = static_protections(old_prot, lpaddr, old_pfn, numpages,
				      psize, CPA_CONFLICT);

	if (WARN_ON_ONCE(pgprot_val(chk_prot) != pgprot_val(old_prot))) {
		/*
		cpa->force_static_prot = 1;
		return 1;
	}

	/*
	if (pgprot_val(req_prot) == pgprot_val(old_prot)) {
		cpa_inc_lp_sameprot(level);
		return 0;
	}

	/*
	if (address != lpaddr || cpa->numpages != numpages)
		return 1;

	/*
	new_prot = static_protections(req_prot, lpaddr, old_pfn, numpages,
				      psize, CPA_DETECT);

	/*
	if (pgprot_val(req_prot) != pgprot_val(new_prot))
		return 1;

	/* All checks passed. Update the large page mapping. */
	new_pte = pfn_pte(old_pfn, new_prot);
	__set_pmd_pte(kpte, address, new_pte);
	cpa->flags |= CPA_FLUSHTLB;
	cpa_inc_lp_preserved(level);
	return 0;
}

static int should_split_large_page(pte_t *kpte, unsigned long address,
				   struct cpa_data *cpa)
{
	int do_split;

	if (cpa->force_split)
		return 1;

	spin_lock(&pgd_lock);
	do_split = __should_split_large_page(kpte, address, cpa);
	spin_unlock(&pgd_lock);

	return do_split;
}

static void split_set_pte(struct cpa_data *cpa, pte_t *pte, unsigned long pfn,
			  pgprot_t ref_prot, unsigned long address,
			  unsigned long size)
{
	unsigned int npg = PFN_DOWN(size);
	pgprot_t prot;

	/*
	if (!cpa->force_static_prot)
		goto set;

	/* Hand in lpsize = 0 to enforce the protection mechanism */
	prot = static_protections(ref_prot, address, pfn, npg, 0, CPA_PROTECT);

	if (pgprot_val(prot) == pgprot_val(ref_prot))
		goto set;

	/*
	if (size == PAGE_SIZE)
		ref_prot = prot;
	else
		pr_warn_once("CPA: Cannot fixup static protections for PUD split\n");
set:
	set_pte(pte, pfn_pte(pfn, ref_prot));
}

static int
__split_large_page(struct cpa_data *cpa, pte_t *kpte, unsigned long address,
		   struct page *base)
{
	unsigned long lpaddr, lpinc, ref_pfn, pfn, pfninc = 1;
	pte_t *pbase = (pte_t *)page_address(base);
	unsigned int i, level;
	pgprot_t ref_prot;
	pte_t *tmp;

	spin_lock(&pgd_lock);
	/*
	tmp = _lookup_address_cpa(cpa, address, &level);
	if (tmp != kpte) {
		spin_unlock(&pgd_lock);
		return 1;
	}

	paravirt_alloc_pte(&init_mm, page_to_pfn(base));

	switch (level) {
	case PG_LEVEL_2M:
		ref_prot = pmd_pgprot(*(pmd_t *)kpte);
		/*
		ref_prot = pgprot_large_2_4k(ref_prot);
		ref_pfn = pmd_pfn(*(pmd_t *)kpte);
		lpaddr = address & PMD_MASK;
		lpinc = PAGE_SIZE;
		break;

	case PG_LEVEL_1G:
		ref_prot = pud_pgprot(*(pud_t *)kpte);
		ref_pfn = pud_pfn(*(pud_t *)kpte);
		pfninc = PMD_PAGE_SIZE >> PAGE_SHIFT;
		lpaddr = address & PUD_MASK;
		lpinc = PMD_SIZE;
		/*
		if (!(pgprot_val(ref_prot) & _PAGE_PRESENT))
			pgprot_val(ref_prot) &= ~_PAGE_PSE;
		break;

	default:
		spin_unlock(&pgd_lock);
		return 1;
	}

	ref_prot = pgprot_clear_protnone_bits(ref_prot);

	/*
	pfn = ref_pfn;
	for (i = 0; i < PTRS_PER_PTE; i++, pfn += pfninc, lpaddr += lpinc)
		split_set_pte(cpa, pbase + i, pfn, ref_prot, lpaddr, lpinc);

	if (virt_addr_valid(address)) {
		unsigned long pfn = PFN_DOWN(__pa(address));

		if (pfn_range_is_mapped(pfn, pfn + 1))
			split_page_count(level);
	}

	/*
	__set_pmd_pte(kpte, address, mk_pte(base, __pgprot(_KERNPG_TABLE)));

	/*
	flush_tlb_all();
	spin_unlock(&pgd_lock);

	return 0;
}

static int split_large_page(struct cpa_data *cpa, pte_t *kpte,
			    unsigned long address)
{
	struct page *base;

	if (!debug_pagealloc_enabled())
		spin_unlock(&cpa_lock);
	base = alloc_pages(GFP_KERNEL, 0);
	if (!debug_pagealloc_enabled())
		spin_lock(&cpa_lock);
	if (!base)
		return -ENOMEM;

	if (__split_large_page(cpa, kpte, address, base))
		__free_page(base);

	return 0;
}

static bool try_to_free_pte_page(pte_t *pte)
{
	int i;

	for (i = 0; i < PTRS_PER_PTE; i++)
		if (!pte_none(pte[i]))
			return false;

	free_page((unsigned long)pte);
	return true;
}

static bool try_to_free_pmd_page(pmd_t *pmd)
{
	int i;

	for (i = 0; i < PTRS_PER_PMD; i++)
		if (!pmd_none(pmd[i]))
			return false;

	free_page((unsigned long)pmd);
	return true;
}

static bool unmap_pte_range(pmd_t *pmd, unsigned long start, unsigned long end)
{
	pte_t *pte = pte_offset_kernel(pmd, start);

	while (start < end) {
		set_pte(pte, __pte(0));

		start += PAGE_SIZE;
		pte++;
	}

	if (try_to_free_pte_page((pte_t *)pmd_page_vaddr(*pmd))) {
		pmd_clear(pmd);
		return true;
	}
	return false;
}

static void __unmap_pmd_range(pud_t *pud, pmd_t *pmd,
			      unsigned long start, unsigned long end)
{
	if (unmap_pte_range(pmd, start, end))
		if (try_to_free_pmd_page(pud_pgtable(*pud)))
			pud_clear(pud);
}

static void unmap_pmd_range(pud_t *pud, unsigned long start, unsigned long end)
{
	pmd_t *pmd = pmd_offset(pud, start);

	/*
	if (start & (PMD_SIZE - 1)) {
		unsigned long next_page = (start + PMD_SIZE) & PMD_MASK;
		unsigned long pre_end = min_t(unsigned long, end, next_page);

		__unmap_pmd_range(pud, pmd, start, pre_end);

		start = pre_end;
		pmd++;
	}

	/*
	while (end - start >= PMD_SIZE) {
		if (pmd_large(*pmd))
			pmd_clear(pmd);
		else
			__unmap_pmd_range(pud, pmd, start, start + PMD_SIZE);

		start += PMD_SIZE;
		pmd++;
	}

	/*
	if (start < end)
		return __unmap_pmd_range(pud, pmd, start, end);

	/*
	if (!pud_none(*pud))
		if (try_to_free_pmd_page(pud_pgtable(*pud)))
			pud_clear(pud);
}

static void unmap_pud_range(p4d_t *p4d, unsigned long start, unsigned long end)
{
	pud_t *pud = pud_offset(p4d, start);

	/*
	if (start & (PUD_SIZE - 1)) {
		unsigned long next_page = (start + PUD_SIZE) & PUD_MASK;
		unsigned long pre_end	= min_t(unsigned long, end, next_page);

		unmap_pmd_range(pud, start, pre_end);

		start = pre_end;
		pud++;
	}

	/*
	while (end - start >= PUD_SIZE) {

		if (pud_large(*pud))
			pud_clear(pud);
		else
			unmap_pmd_range(pud, start, start + PUD_SIZE);

		start += PUD_SIZE;
		pud++;
	}

	/*
	if (start < end)
		unmap_pmd_range(pud, start, end);

	/*
}

static int alloc_pte_page(pmd_t *pmd)
{
	pte_t *pte = (pte_t *)get_zeroed_page(GFP_KERNEL);
	if (!pte)
		return -1;

	set_pmd(pmd, __pmd(__pa(pte) | _KERNPG_TABLE));
	return 0;
}

static int alloc_pmd_page(pud_t *pud)
{
	pmd_t *pmd = (pmd_t *)get_zeroed_page(GFP_KERNEL);
	if (!pmd)
		return -1;

	set_pud(pud, __pud(__pa(pmd) | _KERNPG_TABLE));
	return 0;
}

static void populate_pte(struct cpa_data *cpa,
			 unsigned long start, unsigned long end,
			 unsigned num_pages, pmd_t *pmd, pgprot_t pgprot)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, start);

	pgprot = pgprot_clear_protnone_bits(pgprot);

	while (num_pages-- && start < end) {
		set_pte(pte, pfn_pte(cpa->pfn, pgprot));

		start	 += PAGE_SIZE;
		cpa->pfn++;
		pte++;
	}
}

static long populate_pmd(struct cpa_data *cpa,
			 unsigned long start, unsigned long end,
			 unsigned num_pages, pud_t *pud, pgprot_t pgprot)
{
	long cur_pages = 0;
	pmd_t *pmd;
	pgprot_t pmd_pgprot;

	/*
	if (start & (PMD_SIZE - 1)) {
		unsigned long pre_end = start + (num_pages << PAGE_SHIFT);
		unsigned long next_page = (start + PMD_SIZE) & PMD_MASK;

		pre_end   = min_t(unsigned long, pre_end, next_page);
		cur_pages = (pre_end - start) >> PAGE_SHIFT;
		cur_pages = min_t(unsigned int, num_pages, cur_pages);

		/*
		pmd = pmd_offset(pud, start);
		if (pmd_none(*pmd))
			if (alloc_pte_page(pmd))
				return -1;

		populate_pte(cpa, start, pre_end, cur_pages, pmd, pgprot);

		start = pre_end;
	}

	/*
	if (num_pages == cur_pages)
		return cur_pages;

	pmd_pgprot = pgprot_4k_2_large(pgprot);

	while (end - start >= PMD_SIZE) {

		/*
		if (pud_none(*pud))
			if (alloc_pmd_page(pud))
				return -1;

		pmd = pmd_offset(pud, start);

		set_pmd(pmd, pmd_mkhuge(pfn_pmd(cpa->pfn,
					canon_pgprot(pmd_pgprot))));

		start	  += PMD_SIZE;
		cpa->pfn  += PMD_SIZE >> PAGE_SHIFT;
		cur_pages += PMD_SIZE >> PAGE_SHIFT;
	}

	/*
	if (start < end) {
		pmd = pmd_offset(pud, start);
		if (pmd_none(*pmd))
			if (alloc_pte_page(pmd))
				return -1;

		populate_pte(cpa, start, end, num_pages - cur_pages,
			     pmd, pgprot);
	}
	return num_pages;
}

static int populate_pud(struct cpa_data *cpa, unsigned long start, p4d_t *p4d,
			pgprot_t pgprot)
{
	pud_t *pud;
	unsigned long end;
	long cur_pages = 0;
	pgprot_t pud_pgprot;

	end = start + (cpa->numpages << PAGE_SHIFT);

	/*
	if (start & (PUD_SIZE - 1)) {
		unsigned long pre_end;
		unsigned long next_page = (start + PUD_SIZE) & PUD_MASK;

		pre_end   = min_t(unsigned long, end, next_page);
		cur_pages = (pre_end - start) >> PAGE_SHIFT;
		cur_pages = min_t(int, (int)cpa->numpages, cur_pages);

		pud = pud_offset(p4d, start);

		/*
		if (pud_none(*pud))
			if (alloc_pmd_page(pud))
				return -1;

		cur_pages = populate_pmd(cpa, start, pre_end, cur_pages,
					 pud, pgprot);
		if (cur_pages < 0)
			return cur_pages;

		start = pre_end;
	}

	/* We mapped them all? */
	if (cpa->numpages == cur_pages)
		return cur_pages;

	pud = pud_offset(p4d, start);
	pud_pgprot = pgprot_4k_2_large(pgprot);

	/*
	while (boot_cpu_has(X86_FEATURE_GBPAGES) && end - start >= PUD_SIZE) {
		set_pud(pud, pud_mkhuge(pfn_pud(cpa->pfn,
				   canon_pgprot(pud_pgprot))));

		start	  += PUD_SIZE;
		cpa->pfn  += PUD_SIZE >> PAGE_SHIFT;
		cur_pages += PUD_SIZE >> PAGE_SHIFT;
		pud++;
	}

	/* Map trailing leftover */
	if (start < end) {
		long tmp;

		pud = pud_offset(p4d, start);
		if (pud_none(*pud))
			if (alloc_pmd_page(pud))
				return -1;

		tmp = populate_pmd(cpa, start, end, cpa->numpages - cur_pages,
				   pud, pgprot);
		if (tmp < 0)
			return cur_pages;

		cur_pages += tmp;
	}
	return cur_pages;
}

static int populate_pgd(struct cpa_data *cpa, unsigned long addr)
{
	pgprot_t pgprot = __pgprot(_KERNPG_TABLE);
	pud_t *pud = NULL;	/* shut up gcc */
	p4d_t *p4d;
	pgd_t *pgd_entry;
	long ret;

	pgd_entry = cpa->pgd + pgd_index(addr);

	if (pgd_none(*pgd_entry)) {
		p4d = (p4d_t *)get_zeroed_page(GFP_KERNEL);
		if (!p4d)
			return -1;

		set_pgd(pgd_entry, __pgd(__pa(p4d) | _KERNPG_TABLE));
	}

	/*
	p4d = p4d_offset(pgd_entry, addr);
	if (p4d_none(*p4d)) {
		pud = (pud_t *)get_zeroed_page(GFP_KERNEL);
		if (!pud)
			return -1;

		set_p4d(p4d, __p4d(__pa(pud) | _KERNPG_TABLE));
	}

	pgprot_val(pgprot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(pgprot) |=  pgprot_val(cpa->mask_set);

	ret = populate_pud(cpa, addr, p4d, pgprot);
	if (ret < 0) {
		/*
		unmap_pud_range(p4d, addr,
				addr + (cpa->numpages << PAGE_SHIFT));
		return ret;
	}

	cpa->numpages = ret;
	return 0;
}

static int __cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr,
			       int primary)
{
	if (cpa->pgd) {
		/*
		return populate_pgd(cpa, vaddr);
	}

	/*
	if (!primary) {
		cpa->numpages = 1;
		return 0;
	}

	/*
	if (within(vaddr, PAGE_OFFSET,
		   PAGE_OFFSET + (max_pfn_mapped << PAGE_SHIFT))) {
		cpa->numpages = 1;
		cpa->pfn = __pa(vaddr) >> PAGE_SHIFT;
		return 0;

	} else if (__cpa_pfn_in_highmap(cpa->pfn)) {
		/* Faults in the highmap are OK, so do not warn: */
		return -EFAULT;
	} else {
		WARN(1, KERN_WARNING "CPA: called for zero pte. "
			"vaddr = %lx cpa->vaddr = %lx\n", vaddr,
			*cpa->vaddr);

		return -EFAULT;
	}
}

static int __change_page_attr(struct cpa_data *cpa, int primary)
{
	unsigned long address;
	int do_split, err;
	unsigned int level;
	pte_t *kpte, old_pte;

	address = __cpa_addr(cpa, cpa->curpage);
repeat:
	kpte = _lookup_address_cpa(cpa, address, &level);
	if (!kpte)
		return __cpa_process_fault(cpa, address, primary);

	old_pte = *kpte;
	if (pte_none(old_pte))
		return __cpa_process_fault(cpa, address, primary);

	if (level == PG_LEVEL_4K) {
		pte_t new_pte;
		pgprot_t new_prot = pte_pgprot(old_pte);
		unsigned long pfn = pte_pfn(old_pte);

		pgprot_val(new_prot) &= ~pgprot_val(cpa->mask_clr);
		pgprot_val(new_prot) |= pgprot_val(cpa->mask_set);

		cpa_inc_4k_install();
		/* Hand in lpsize = 0 to enforce the protection mechanism */
		new_prot = static_protections(new_prot, address, pfn, 1, 0,
					      CPA_PROTECT);

		new_prot = pgprot_clear_protnone_bits(new_prot);

		/*
		new_pte = pfn_pte(pfn, new_prot);
		cpa->pfn = pfn;
		/*
		if (pte_val(old_pte) != pte_val(new_pte)) {
			set_pte_atomic(kpte, new_pte);
			cpa->flags |= CPA_FLUSHTLB;
		}
		cpa->numpages = 1;
		return 0;
	}

	/*
	do_split = should_split_large_page(kpte, address, cpa);
	/*
	if (do_split <= 0)
		return do_split;

	/*
	err = split_large_page(cpa, kpte, address);
	if (!err)
		goto repeat;

	return err;
}

static int __change_page_attr_set_clr(struct cpa_data *cpa, int checkalias);

static int cpa_process_alias(struct cpa_data *cpa)
{
	struct cpa_data alias_cpa;
	unsigned long laddr = (unsigned long)__va(cpa->pfn << PAGE_SHIFT);
	unsigned long vaddr;
	int ret;

	if (!pfn_range_is_mapped(cpa->pfn, cpa->pfn + 1))
		return 0;

	/*
	vaddr = __cpa_addr(cpa, cpa->curpage);
	if (!(within(vaddr, PAGE_OFFSET,
		    PAGE_OFFSET + (max_pfn_mapped << PAGE_SHIFT)))) {

		alias_cpa = *cpa;
		alias_cpa.vaddr = &laddr;
		alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);
		alias_cpa.curpage = 0;

		cpa->force_flush_all = 1;

		ret = __change_page_attr_set_clr(&alias_cpa, 0);
		if (ret)
			return ret;
	}

#ifdef CONFIG_X86_64
	/*
	if (!within(vaddr, (unsigned long)_text, _brk_end) &&
	    __cpa_pfn_in_highmap(cpa->pfn)) {
		unsigned long temp_cpa_vaddr = (cpa->pfn << PAGE_SHIFT) +
					       __START_KERNEL_map - phys_base;
		alias_cpa = *cpa;
		alias_cpa.vaddr = &temp_cpa_vaddr;
		alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);
		alias_cpa.curpage = 0;

		cpa->force_flush_all = 1;
		/*
		__change_page_attr_set_clr(&alias_cpa, 0);
	}
#endif

	return 0;
}

static int __change_page_attr_set_clr(struct cpa_data *cpa, int checkalias)
{
	unsigned long numpages = cpa->numpages;
	unsigned long rempages = numpages;
	int ret = 0;

	while (rempages) {
		/*
		cpa->numpages = rempages;
		/* for array changes, we can't use large page */
		if (cpa->flags & (CPA_ARRAY | CPA_PAGES_ARRAY))
			cpa->numpages = 1;

		if (!debug_pagealloc_enabled())
			spin_lock(&cpa_lock);
		ret = __change_page_attr(cpa, checkalias);
		if (!debug_pagealloc_enabled())
			spin_unlock(&cpa_lock);
		if (ret)
			goto out;

		if (checkalias) {
			ret = cpa_process_alias(cpa);
			if (ret)
				goto out;
		}

		/*
		BUG_ON(cpa->numpages > rempages || !cpa->numpages);
		rempages -= cpa->numpages;
		cpa->curpage += cpa->numpages;
	}

out:
	/* Restore the original numpages */
	cpa->numpages = numpages;
	return ret;
}

static int change_page_attr_set_clr(unsigned long *addr, int numpages,
				    pgprot_t mask_set, pgprot_t mask_clr,
				    int force_split, int in_flag,
				    struct page **pages)
{
	struct cpa_data cpa;
	int ret, cache, checkalias;

	memset(&cpa, 0, sizeof(cpa));

	/*
	mask_set = canon_pgprot(mask_set);

	if (!pgprot_val(mask_set) && !pgprot_val(mask_clr) && !force_split)
		return 0;

	/* Ensure we are PAGE_SIZE aligned */
	if (in_flag & CPA_ARRAY) {
		int i;
		for (i = 0; i < numpages; i++) {
			if (addr[i] & ~PAGE_MASK) {
				addr[i] &= PAGE_MASK;
				WARN_ON_ONCE(1);
			}
		}
	} else if (!(in_flag & CPA_PAGES_ARRAY)) {
		/*
		if (*addr & ~PAGE_MASK) {
			*addr &= PAGE_MASK;
			/*
			WARN_ON_ONCE(1);
		}
	}

	/* Must avoid aliasing mappings in the highmem code */
	kmap_flush_unused();

	vm_unmap_aliases();

	cpa.vaddr = addr;
	cpa.pages = pages;
	cpa.numpages = numpages;
	cpa.mask_set = mask_set;
	cpa.mask_clr = mask_clr;
	cpa.flags = 0;
	cpa.curpage = 0;
	cpa.force_split = force_split;

	if (in_flag & (CPA_ARRAY | CPA_PAGES_ARRAY))
		cpa.flags |= in_flag;

	/* No alias checking for _NX bit modifications */
	checkalias = (pgprot_val(mask_set) | pgprot_val(mask_clr)) != _PAGE_NX;
	/* Has caller explicitly disabled alias checking? */
	if (in_flag & CPA_NO_CHECK_ALIAS)
		checkalias = 0;

	ret = __change_page_attr_set_clr(&cpa, checkalias);

	/*
	if (!(cpa.flags & CPA_FLUSHTLB))
		goto out;

	/*
	cache = !!pgprot2cachemode(mask_set);

	/*
	if (ret) {
		cpa_flush_all(cache);
		goto out;
	}

	cpa_flush(&cpa, cache);
out:
	return ret;
}

static inline int change_page_attr_set(unsigned long *addr, int numpages,
				       pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, mask, __pgprot(0), 0,
		(array ? CPA_ARRAY : 0), NULL);
}

static inline int change_page_attr_clear(unsigned long *addr, int numpages,
					 pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, __pgprot(0), mask, 0,
		(array ? CPA_ARRAY : 0), NULL);
}

static inline int cpa_set_pages_array(struct page **pages, int numpages,
				       pgprot_t mask)
{
	return change_page_attr_set_clr(NULL, numpages, mask, __pgprot(0), 0,
		CPA_PAGES_ARRAY, pages);
}

static inline int cpa_clear_pages_array(struct page **pages, int numpages,
					 pgprot_t mask)
{
	return change_page_attr_set_clr(NULL, numpages, __pgprot(0), mask, 0,
		CPA_PAGES_ARRAY, pages);
}

int __set_memory_prot(unsigned long addr, int numpages, pgprot_t prot)
{
	return change_page_attr_set_clr(&addr, numpages, prot,
					__pgprot(~pgprot_val(prot)), 0, 0,
					NULL);
}

int _set_memory_uc(unsigned long addr, int numpages)
{
	/*
	return change_page_attr_set(&addr, numpages,
				    cachemode2pgprot(_PAGE_CACHE_MODE_UC_MINUS),
				    0);
}

int set_memory_uc(unsigned long addr, int numpages)
{
	int ret;

	/*
	ret = memtype_reserve(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
			      _PAGE_CACHE_MODE_UC_MINUS, NULL);
	if (ret)
		goto out_err;

	ret = _set_memory_uc(addr, numpages);
	if (ret)
		goto out_free;

	return 0;

out_free:
	memtype_free(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);
out_err:
	return ret;
}
EXPORT_SYMBOL(set_memory_uc);

int _set_memory_wc(unsigned long addr, int numpages)
{
	int ret;

	ret = change_page_attr_set(&addr, numpages,
				   cachemode2pgprot(_PAGE_CACHE_MODE_UC_MINUS),
				   0);
	if (!ret) {
		ret = change_page_attr_set_clr(&addr, numpages,
					       cachemode2pgprot(_PAGE_CACHE_MODE_WC),
					       __pgprot(_PAGE_CACHE_MASK),
					       0, 0, NULL);
	}
	return ret;
}

int set_memory_wc(unsigned long addr, int numpages)
{
	int ret;

	ret = memtype_reserve(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
		_PAGE_CACHE_MODE_WC, NULL);
	if (ret)
		return ret;

	ret = _set_memory_wc(addr, numpages);
	if (ret)
		memtype_free(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);

	return ret;
}
EXPORT_SYMBOL(set_memory_wc);

int _set_memory_wt(unsigned long addr, int numpages)
{
	return change_page_attr_set(&addr, numpages,
				    cachemode2pgprot(_PAGE_CACHE_MODE_WT), 0);
}

int _set_memory_wb(unsigned long addr, int numpages)
{
	/* WB cache mode is hard wired to all cache attribute bits being 0 */
	return change_page_attr_clear(&addr, numpages,
				      __pgprot(_PAGE_CACHE_MASK), 0);
}

int set_memory_wb(unsigned long addr, int numpages)
{
	int ret;

	ret = _set_memory_wb(addr, numpages);
	if (ret)
		return ret;

	memtype_free(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);
	return 0;
}
EXPORT_SYMBOL(set_memory_wb);

#ifdef CONFIG_X86_64
int set_mce_nospec(unsigned long pfn)
{
	unsigned long decoy_addr;
	int rc;

	/* SGX pages are not in the 1:1 map */
	if (arch_is_platform_page(pfn << PAGE_SHIFT))
		return 0;
	/*
	decoy_addr = (pfn << PAGE_SHIFT) + (PAGE_OFFSET ^ BIT(63));

	rc = set_memory_np(decoy_addr, 1);
	if (rc)
		pr_warn("Could not invalidate pfn=0x%lx from 1:1 map\n", pfn);
	return rc;
}

static int set_memory_present(unsigned long *addr, int numpages)
{
	return change_page_attr_set(addr, numpages, __pgprot(_PAGE_PRESENT), 0);
}

int clear_mce_nospec(unsigned long pfn)
{
	unsigned long addr = (unsigned long) pfn_to_kaddr(pfn);

	return set_memory_present(&addr, 1);
}
EXPORT_SYMBOL_GPL(clear_mce_nospec);
#endif /* CONFIG_X86_64 */

int set_memory_x(unsigned long addr, int numpages)
{
	if (!(__supported_pte_mask & _PAGE_NX))
		return 0;

	return change_page_attr_clear(&addr, numpages, __pgprot(_PAGE_NX), 0);
}

int set_memory_nx(unsigned long addr, int numpages)
{
	if (!(__supported_pte_mask & _PAGE_NX))
		return 0;

	return change_page_attr_set(&addr, numpages, __pgprot(_PAGE_NX), 0);
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return change_page_attr_clear(&addr, numpages, __pgprot(_PAGE_RW), 0);
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return change_page_attr_set(&addr, numpages, __pgprot(_PAGE_RW), 0);
}

int set_memory_np(unsigned long addr, int numpages)
{
	return change_page_attr_clear(&addr, numpages, __pgprot(_PAGE_PRESENT), 0);
}

int set_memory_np_noalias(unsigned long addr, int numpages)
{
	int cpa_flags = CPA_NO_CHECK_ALIAS;

	return change_page_attr_set_clr(&addr, numpages, __pgprot(0),
					__pgprot(_PAGE_PRESENT), 0,
					cpa_flags, NULL);
}

int set_memory_4k(unsigned long addr, int numpages)
{
	return change_page_attr_set_clr(&addr, numpages, __pgprot(0),
					__pgprot(0), 1, 0, NULL);
}

int set_memory_nonglobal(unsigned long addr, int numpages)
{
	return change_page_attr_clear(&addr, numpages,
				      __pgprot(_PAGE_GLOBAL), 0);
}

int set_memory_global(unsigned long addr, int numpages)
{
	return change_page_attr_set(&addr, numpages,
				    __pgprot(_PAGE_GLOBAL), 0);
}

static int __set_memory_enc_pgtable(unsigned long addr, int numpages, bool enc)
{
	pgprot_t empty = __pgprot(0);
	struct cpa_data cpa;
	int ret;

	/* Should not be working on unaligned addresses */
	if (WARN_ONCE(addr & ~PAGE_MASK, "misaligned address: %#lx\n", addr))
		addr &= PAGE_MASK;

	memset(&cpa, 0, sizeof(cpa));
	cpa.vaddr = &addr;
	cpa.numpages = numpages;
	cpa.mask_set = enc ? pgprot_encrypted(empty) : pgprot_decrypted(empty);
	cpa.mask_clr = enc ? pgprot_decrypted(empty) : pgprot_encrypted(empty);
	cpa.pgd = init_mm.pgd;

	/* Must avoid aliasing mappings in the highmem code */
	kmap_flush_unused();
	vm_unmap_aliases();

	/* Flush the caches as needed before changing the encryption attribute. */
	if (x86_platform.guest.enc_tlb_flush_required(enc))
		cpa_flush(&cpa, x86_platform.guest.enc_cache_flush_required());

	/* Notify hypervisor that we are about to set/clr encryption attribute. */
	x86_platform.guest.enc_status_change_prepare(addr, numpages, enc);

	ret = __change_page_attr_set_clr(&cpa, 1);

	/*
	cpa_flush(&cpa, 0);

	/* Notify hypervisor that we have successfully set/clr encryption attribute. */
	if (!ret) {
		if (!x86_platform.guest.enc_status_change_finish(addr, numpages, enc))
			ret = -EIO;
	}

	return ret;
}

static int __set_memory_enc_dec(unsigned long addr, int numpages, bool enc)
{
	if (hv_is_isolation_supported())
		return hv_set_mem_host_visibility(addr, numpages, !enc);

	if (cc_platform_has(CC_ATTR_MEM_ENCRYPT))
		return __set_memory_enc_pgtable(addr, numpages, enc);

	return 0;
}

int set_memory_encrypted(unsigned long addr, int numpages)
{
	return __set_memory_enc_dec(addr, numpages, true);
}
EXPORT_SYMBOL_GPL(set_memory_encrypted);

int set_memory_decrypted(unsigned long addr, int numpages)
{
	return __set_memory_enc_dec(addr, numpages, false);
}
EXPORT_SYMBOL_GPL(set_memory_decrypted);

int set_pages_uc(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_uc(addr, numpages);
}
EXPORT_SYMBOL(set_pages_uc);

static int _set_pages_array(struct page **pages, int numpages,
		enum page_cache_mode new_type)
{
	unsigned long start;
	unsigned long end;
	enum page_cache_mode set_type;
	int i;
	int free_idx;
	int ret;

	for (i = 0; i < numpages; i++) {
		if (PageHighMem(pages[i]))
			continue;
		start = page_to_pfn(pages[i]) << PAGE_SHIFT;
		end = start + PAGE_SIZE;
		if (memtype_reserve(start, end, new_type, NULL))
			goto err_out;
	}

	/* If WC, set to UC- first and then WC */
	set_type = (new_type == _PAGE_CACHE_MODE_WC) ?
				_PAGE_CACHE_MODE_UC_MINUS : new_type;

	ret = cpa_set_pages_array(pages, numpages,
				  cachemode2pgprot(set_type));
	if (!ret && new_type == _PAGE_CACHE_MODE_WC)
		ret = change_page_attr_set_clr(NULL, numpages,
					       cachemode2pgprot(
						_PAGE_CACHE_MODE_WC),
					       __pgprot(_PAGE_CACHE_MASK),
					       0, CPA_PAGES_ARRAY, pages);
	if (ret)
		goto err_out;
	return 0; /* Success */
err_out:
	free_idx = i;
	for (i = 0; i < free_idx; i++) {
		if (PageHighMem(pages[i]))
			continue;
		start = page_to_pfn(pages[i]) << PAGE_SHIFT;
		end = start + PAGE_SIZE;
		memtype_free(start, end);
	}
	return -EINVAL;
}

int set_pages_array_uc(struct page **pages, int numpages)
{
	return _set_pages_array(pages, numpages, _PAGE_CACHE_MODE_UC_MINUS);
}
EXPORT_SYMBOL(set_pages_array_uc);

int set_pages_array_wc(struct page **pages, int numpages)
{
	return _set_pages_array(pages, numpages, _PAGE_CACHE_MODE_WC);
}
EXPORT_SYMBOL(set_pages_array_wc);

int set_pages_wb(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_wb(addr, numpages);
}
EXPORT_SYMBOL(set_pages_wb);

int set_pages_array_wb(struct page **pages, int numpages)
{
	int retval;
	unsigned long start;
	unsigned long end;
	int i;

	/* WB cache mode is hard wired to all cache attribute bits being 0 */
	retval = cpa_clear_pages_array(pages, numpages,
			__pgprot(_PAGE_CACHE_MASK));
	if (retval)
		return retval;

	for (i = 0; i < numpages; i++) {
		if (PageHighMem(pages[i]))
			continue;
		start = page_to_pfn(pages[i]) << PAGE_SHIFT;
		end = start + PAGE_SIZE;
		memtype_free(start, end);
	}

	return 0;
}
EXPORT_SYMBOL(set_pages_array_wb);

int set_pages_ro(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_ro(addr, numpages);
}

int set_pages_rw(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_rw(addr, numpages);
}

static int __set_pages_p(struct page *page, int numpages)
{
	unsigned long tempaddr = (unsigned long) page_address(page);
	struct cpa_data cpa = { .vaddr = &tempaddr,
				.pgd = NULL,
				.numpages = numpages,
				.mask_set = __pgprot(_PAGE_PRESENT | _PAGE_RW),
				.mask_clr = __pgprot(0),
				.flags = 0};

	/*
	return __change_page_attr_set_clr(&cpa, 0);
}

static int __set_pages_np(struct page *page, int numpages)
{
	unsigned long tempaddr = (unsigned long) page_address(page);
	struct cpa_data cpa = { .vaddr = &tempaddr,
				.pgd = NULL,
				.numpages = numpages,
				.mask_set = __pgprot(0),
				.mask_clr = __pgprot(_PAGE_PRESENT | _PAGE_RW),
				.flags = 0};

	/*
	return __change_page_attr_set_clr(&cpa, 0);
}

int set_direct_map_invalid_noflush(struct page *page)
{
	return __set_pages_np(page, 1);
}

int set_direct_map_default_noflush(struct page *page)
{
	return __set_pages_p(page, 1);
}

#ifdef CONFIG_DEBUG_PAGEALLOC
void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	if (PageHighMem(page))
		return;
	if (!enable) {
		debug_check_no_locks_freed(page_address(page),
					   numpages * PAGE_SIZE);
	}

	/*
	if (enable)
		__set_pages_p(page, numpages);
	else
		__set_pages_np(page, numpages);

	/*
	preempt_disable();
	__flush_tlb_all();
	preempt_enable();

	arch_flush_lazy_mmu_mode();
}
#endif /* CONFIG_DEBUG_PAGEALLOC */

bool kernel_page_present(struct page *page)
{
	unsigned int level;
	pte_t *pte;

	if (PageHighMem(page))
		return false;

	pte = lookup_address((unsigned long)page_address(page), &level);
	return (pte_val(*pte) & _PAGE_PRESENT);
}

int __init kernel_map_pages_in_pgd(pgd_t *pgd, u64 pfn, unsigned long address,
				   unsigned numpages, unsigned long page_flags)
{
	int retval = -EINVAL;

	struct cpa_data cpa = {
		.vaddr = &address,
		.pfn = pfn,
		.pgd = pgd,
		.numpages = numpages,
		.mask_set = __pgprot(0),
		.mask_clr = __pgprot(~page_flags & (_PAGE_NX|_PAGE_RW)),
		.flags = 0,
	};

	WARN_ONCE(num_online_cpus() > 1, "Don't call after initializing SMP");

	if (!(__supported_pte_mask & _PAGE_NX))
		goto out;

	if (!(page_flags & _PAGE_ENC))
		cpa.mask_clr = pgprot_encrypted(cpa.mask_clr);

	cpa.mask_set = __pgprot(_PAGE_PRESENT | page_flags);

	retval = __change_page_attr_set_clr(&cpa, 0);
	__flush_tlb_all();

out:
	return retval;
}

int __init kernel_unmap_pages_in_pgd(pgd_t *pgd, unsigned long address,
				     unsigned long numpages)
{
	int retval;

	/*
	struct cpa_data cpa = {
		.vaddr		= &address,
		.pfn		= 0,
		.pgd		= pgd,
		.numpages	= numpages,
		.mask_set	= __pgprot(0),
		.mask_clr	= __pgprot(_PAGE_PRESENT | _PAGE_RW),
		.flags		= 0,
	};

	WARN_ONCE(num_online_cpus() > 1, "Don't call after initializing SMP");

	retval = __change_page_attr_set_clr(&cpa, 0);
	__flush_tlb_all();

	return retval;
}

#ifdef CONFIG_CPA_DEBUG
#include "cpa-test.c"
#endif
