
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/memblock.h>
#include <linux/pgtable.h>

#include <asm/setup.h>
#include <asm/kaslr.h>

#include "mm_internal.h"

#define TB_SHIFT 40

static const unsigned long vaddr_end = CPU_ENTRY_AREA_BASE;

static __initdata struct kaslr_memory_region {
	unsigned long *base;
	unsigned long size_tb;
} kaslr_regions[] = {
	{ &page_offset_base, 0 },
	{ &vmalloc_base, 0 },
	{ &vmemmap_base, 0 },
};

static inline unsigned long get_padding(struct kaslr_memory_region *region)
{
	return (region->size_tb << TB_SHIFT);
}

void __init kernel_randomize_memory(void)
{
	size_t i;
	unsigned long vaddr_start, vaddr;
	unsigned long rand, memory_tb;
	struct rnd_state rand_state;
	unsigned long remain_entropy;
	unsigned long vmemmap_size;

	vaddr_start = pgtable_l5_enabled() ? __PAGE_OFFSET_BASE_L5 : __PAGE_OFFSET_BASE_L4;
	vaddr = vaddr_start;

	/*
	BUILD_BUG_ON(vaddr_start >= vaddr_end);
	BUILD_BUG_ON(vaddr_end != CPU_ENTRY_AREA_BASE);
	BUILD_BUG_ON(vaddr_end > __START_KERNEL_map);

	if (!kaslr_memory_enabled())
		return;

	kaslr_regions[0].size_tb = 1 << (MAX_PHYSMEM_BITS - TB_SHIFT);
	kaslr_regions[1].size_tb = VMALLOC_SIZE_TB;

	/*
	BUG_ON(kaslr_regions[0].base != &page_offset_base);
	memory_tb = DIV_ROUND_UP(max_pfn << PAGE_SHIFT, 1UL << TB_SHIFT) +
		CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING;

	/* Adapt physical memory region size based on available memory */
	if (memory_tb < kaslr_regions[0].size_tb)
		kaslr_regions[0].size_tb = memory_tb;

	/*
	vmemmap_size = (kaslr_regions[0].size_tb << (TB_SHIFT - PAGE_SHIFT)) *
			sizeof(struct page);
	kaslr_regions[2].size_tb = DIV_ROUND_UP(vmemmap_size, 1UL << TB_SHIFT);

	/* Calculate entropy available between regions */
	remain_entropy = vaddr_end - vaddr_start;
	for (i = 0; i < ARRAY_SIZE(kaslr_regions); i++)
		remain_entropy -= get_padding(&kaslr_regions[i]);

	prandom_seed_state(&rand_state, kaslr_get_random_long("Memory"));

	for (i = 0; i < ARRAY_SIZE(kaslr_regions); i++) {
		unsigned long entropy;

		/*
		entropy = remain_entropy / (ARRAY_SIZE(kaslr_regions) - i);
		prandom_bytes_state(&rand_state, &rand, sizeof(rand));
		entropy = (rand % (entropy + 1)) & PUD_MASK;
		vaddr += entropy;
		*kaslr_regions[i].base = vaddr;

		/*
		vaddr += get_padding(&kaslr_regions[i]);
		vaddr = round_up(vaddr + 1, PUD_SIZE);
		remain_entropy -= entropy;
	}
}

void __meminit init_trampoline_kaslr(void)
{
	pud_t *pud_page_tramp, *pud, *pud_tramp;
	p4d_t *p4d_page_tramp, *p4d, *p4d_tramp;
	unsigned long paddr, vaddr;
	pgd_t *pgd;

	pud_page_tramp = alloc_low_page();

	/*
	paddr = 0;
	vaddr = (unsigned long)__va(paddr);
	pgd = pgd_offset_k(vaddr);

	p4d = p4d_offset(pgd, vaddr);
	pud = pud_offset(p4d, vaddr);

	pud_tramp = pud_page_tramp + pud_index(paddr);

	if (pgtable_l5_enabled()) {
		p4d_page_tramp = alloc_low_page();

		p4d_tramp = p4d_page_tramp + p4d_index(paddr);

		set_p4d(p4d_tramp,
			__p4d(_KERNPG_TABLE | __pa(pud_page_tramp)));

		set_pgd(&trampoline_pgd_entry,
			__pgd(_KERNPG_TABLE | __pa(p4d_page_tramp)));
	} else {
		set_pgd(&trampoline_pgd_entry,
			__pgd(_KERNPG_TABLE | __pa(pud_page_tramp)));
	}
}
