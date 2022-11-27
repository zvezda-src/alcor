
#define pr_fmt(fmt) "PM: hibernation: " fmt

#include <linux/version.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/suspend.h>
#include <linux/delay.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/pm.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/nmi.h>
#include <linux/syscalls.h>
#include <linux/console.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/ktime.h>
#include <linux/set_memory.h>

#include <linux/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/io.h>

#include "power.h"

#if defined(CONFIG_STRICT_KERNEL_RWX) && defined(CONFIG_ARCH_HAS_SET_MEMORY)
static bool hibernate_restore_protection;
static bool hibernate_restore_protection_active;

void enable_restore_image_protection(void)
{
	hibernate_restore_protection = true;
}

static inline void hibernate_restore_protection_begin(void)
{
	hibernate_restore_protection_active = hibernate_restore_protection;
}

static inline void hibernate_restore_protection_end(void)
{
	hibernate_restore_protection_active = false;
}

static inline void hibernate_restore_protect_page(void *page_address)
{
	if (hibernate_restore_protection_active)
		set_memory_ro((unsigned long)page_address, 1);
}

static inline void hibernate_restore_unprotect_page(void *page_address)
{
	if (hibernate_restore_protection_active)
		set_memory_rw((unsigned long)page_address, 1);
}
#else
static inline void hibernate_restore_protection_begin(void) {}
static inline void hibernate_restore_protection_end(void) {}
static inline void hibernate_restore_protect_page(void *page_address) {}
static inline void hibernate_restore_unprotect_page(void *page_address) {}
#endif /* CONFIG_STRICT_KERNEL_RWX  && CONFIG_ARCH_HAS_SET_MEMORY */


static inline void hibernate_map_page(struct page *page)
{
	if (IS_ENABLED(CONFIG_ARCH_HAS_SET_DIRECT_MAP)) {
		int ret = set_direct_map_default_noflush(page);

		if (ret)
			pr_warn_once("Failed to remap page\n");
	} else {
		debug_pagealloc_map_pages(page, 1);
	}
}

static inline void hibernate_unmap_page(struct page *page)
{
	if (IS_ENABLED(CONFIG_ARCH_HAS_SET_DIRECT_MAP)) {
		unsigned long addr = (unsigned long)page_address(page);
		int ret  = set_direct_map_invalid_noflush(page);

		if (ret)
			pr_warn_once("Failed to remap page\n");

		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	} else {
		debug_pagealloc_unmap_pages(page, 1);
	}
}

static int swsusp_page_is_free(struct page *);
static void swsusp_set_page_forbidden(struct page *);
static void swsusp_unset_page_forbidden(struct page *);

unsigned long reserved_size;

void __init hibernate_reserved_size_init(void)
{
	reserved_size = SPARE_PAGES * PAGE_SIZE;
}

unsigned long image_size;

void __init hibernate_image_size_init(void)
{
	image_size = ((totalram_pages() * 2) / 5) * PAGE_SIZE;
}

struct pbe *restore_pblist;


#define LINKED_PAGE_DATA_SIZE	(PAGE_SIZE - sizeof(void *))

struct linked_page {
	struct linked_page *next;
	char data[LINKED_PAGE_DATA_SIZE];
} __packed;

static struct linked_page *safe_pages_list;

static void *buffer;

#define PG_ANY		0
#define PG_SAFE		1
#define PG_UNSAFE_CLEAR	1
#define PG_UNSAFE_KEEP	0

static unsigned int allocated_unsafe_pages;

static void *get_image_page(gfp_t gfp_mask, int safe_needed)
{
	void *res;

	res = (void *)get_zeroed_page(gfp_mask);
	if (safe_needed)
		while (res && swsusp_page_is_free(virt_to_page(res))) {
			/* The page is unsafe, mark it for swsusp_free() */
			swsusp_set_page_forbidden(virt_to_page(res));
			allocated_unsafe_pages++;
			res = (void *)get_zeroed_page(gfp_mask);
		}
	if (res) {
		swsusp_set_page_forbidden(virt_to_page(res));
		swsusp_set_page_free(virt_to_page(res));
	}
	return res;
}

static void *__get_safe_page(gfp_t gfp_mask)
{
	if (safe_pages_list) {
		void *ret = safe_pages_list;

		safe_pages_list = safe_pages_list->next;
		memset(ret, 0, PAGE_SIZE);
		return ret;
	}
	return get_image_page(gfp_mask, PG_SAFE);
}

unsigned long get_safe_page(gfp_t gfp_mask)
{
	return (unsigned long)__get_safe_page(gfp_mask);
}

static struct page *alloc_image_page(gfp_t gfp_mask)
{
	struct page *page;

	page = alloc_page(gfp_mask);
	if (page) {
		swsusp_set_page_forbidden(page);
		swsusp_set_page_free(page);
	}
	return page;
}

static void recycle_safe_page(void *page_address)
{
	struct linked_page *lp = page_address;

	lp->next = safe_pages_list;
	safe_pages_list = lp;
}

static inline void free_image_page(void *addr, int clear_nosave_free)
{
	struct page *page;

	BUG_ON(!virt_addr_valid(addr));

	page = virt_to_page(addr);

	swsusp_unset_page_forbidden(page);
	if (clear_nosave_free)
		swsusp_unset_page_free(page);

	__free_page(page);
}

static inline void free_list_of_pages(struct linked_page *list,
				      int clear_page_nosave)
{
	while (list) {
		struct linked_page *lp = list->next;

		free_image_page(list, clear_page_nosave);
		list = lp;
	}
}

struct chain_allocator {
	struct linked_page *chain;	/* the chain */
	unsigned int used_space;	/* total size of objects allocated out
					   of the current page */
	gfp_t gfp_mask;		/* mask for allocating pages */
	int safe_needed;	/* if set, only "safe" pages are allocated */
};

static void chain_init(struct chain_allocator *ca, gfp_t gfp_mask,
		       int safe_needed)
{
	ca->chain = NULL;
	ca->used_space = LINKED_PAGE_DATA_SIZE;
	ca->gfp_mask = gfp_mask;
	ca->safe_needed = safe_needed;
}

static void *chain_alloc(struct chain_allocator *ca, unsigned int size)
{
	void *ret;

	if (LINKED_PAGE_DATA_SIZE - ca->used_space < size) {
		struct linked_page *lp;

		lp = ca->safe_needed ? __get_safe_page(ca->gfp_mask) :
					get_image_page(ca->gfp_mask, PG_ANY);
		if (!lp)
			return NULL;

		lp->next = ca->chain;
		ca->chain = lp;
		ca->used_space = 0;
	}
	ret = ca->chain->data + ca->used_space;
	ca->used_space += size;
	return ret;
}


#define BM_END_OF_MAP	(~0UL)

#define BM_BITS_PER_BLOCK	(PAGE_SIZE * BITS_PER_BYTE)
#define BM_BLOCK_SHIFT		(PAGE_SHIFT + 3)
#define BM_BLOCK_MASK		((1UL << BM_BLOCK_SHIFT) - 1)

struct rtree_node {
	struct list_head list;
	unsigned long *data;
};

struct mem_zone_bm_rtree {
	struct list_head list;		/* Link Zones together         */
	struct list_head nodes;		/* Radix Tree inner nodes      */
	struct list_head leaves;	/* Radix Tree leaves           */
	unsigned long start_pfn;	/* Zone start page frame       */
	unsigned long end_pfn;		/* Zone end page frame + 1     */
	struct rtree_node *rtree;	/* Radix Tree Root             */
	int levels;			/* Number of Radix Tree Levels */
	unsigned int blocks;		/* Number of Bitmap Blocks     */
};


struct bm_position {
	struct mem_zone_bm_rtree *zone;
	struct rtree_node *node;
	unsigned long node_pfn;
	int node_bit;
};

struct memory_bitmap {
	struct list_head zones;
	struct linked_page *p_list;	/* list of pages used to store zone
					   bitmap objects and bitmap block
					   objects */
	struct bm_position cur;	/* most recently used bit position */
};


#define BM_ENTRIES_PER_LEVEL	(PAGE_SIZE / sizeof(unsigned long))
#if BITS_PER_LONG == 32
#define BM_RTREE_LEVEL_SHIFT	(PAGE_SHIFT - 2)
#else
#define BM_RTREE_LEVEL_SHIFT	(PAGE_SHIFT - 3)
#endif
#define BM_RTREE_LEVEL_MASK	((1UL << BM_RTREE_LEVEL_SHIFT) - 1)

static struct rtree_node *alloc_rtree_node(gfp_t gfp_mask, int safe_needed,
					   struct chain_allocator *ca,
					   struct list_head *list)
{
	struct rtree_node *node;

	node = chain_alloc(ca, sizeof(struct rtree_node));
	if (!node)
		return NULL;

	node->data = get_image_page(gfp_mask, safe_needed);
	if (!node->data)
		return NULL;

	list_add_tail(&node->list, list);

	return node;
}

static int add_rtree_block(struct mem_zone_bm_rtree *zone, gfp_t gfp_mask,
			   int safe_needed, struct chain_allocator *ca)
{
	struct rtree_node *node, *block, **dst;
	unsigned int levels_needed, block_nr;
	int i;

	block_nr = zone->blocks;
	levels_needed = 0;

	/* How many levels do we need for this block nr? */
	while (block_nr) {
		levels_needed += 1;
		block_nr >>= BM_RTREE_LEVEL_SHIFT;
	}

	/* Make sure the rtree has enough levels */
	for (i = zone->levels; i < levels_needed; i++) {
		node = alloc_rtree_node(gfp_mask, safe_needed, ca,
					&zone->nodes);
		if (!node)
			return -ENOMEM;

		node->data[0] = (unsigned long)zone->rtree;
		zone->rtree = node;
		zone->levels += 1;
	}

	/* Allocate new block */
	block = alloc_rtree_node(gfp_mask, safe_needed, ca, &zone->leaves);
	if (!block)
		return -ENOMEM;

	/* Now walk the rtree to insert the block */
	node = zone->rtree;
	dst = &zone->rtree;
	block_nr = zone->blocks;
	for (i = zone->levels; i > 0; i--) {
		int index;

		if (!node) {
			node = alloc_rtree_node(gfp_mask, safe_needed, ca,
						&zone->nodes);
			if (!node)
				return -ENOMEM;
			*dst = node;
		}

		index = block_nr >> ((i - 1) * BM_RTREE_LEVEL_SHIFT);
		index &= BM_RTREE_LEVEL_MASK;
		dst = (struct rtree_node **)&((*dst)->data[index]);
		node = *dst;
	}

	zone->blocks += 1;

	return 0;
}

static void free_zone_bm_rtree(struct mem_zone_bm_rtree *zone,
			       int clear_nosave_free);

static struct mem_zone_bm_rtree *create_zone_bm_rtree(gfp_t gfp_mask,
						      int safe_needed,
						      struct chain_allocator *ca,
						      unsigned long start,
						      unsigned long end)
{
	struct mem_zone_bm_rtree *zone;
	unsigned int i, nr_blocks;
	unsigned long pages;

	pages = end - start;
	zone  = chain_alloc(ca, sizeof(struct mem_zone_bm_rtree));
	if (!zone)
		return NULL;

	INIT_LIST_HEAD(&zone->nodes);
	INIT_LIST_HEAD(&zone->leaves);
	zone->start_pfn = start;
	zone->end_pfn = end;
	nr_blocks = DIV_ROUND_UP(pages, BM_BITS_PER_BLOCK);

	for (i = 0; i < nr_blocks; i++) {
		if (add_rtree_block(zone, gfp_mask, safe_needed, ca)) {
			free_zone_bm_rtree(zone, PG_UNSAFE_CLEAR);
			return NULL;
		}
	}

	return zone;
}

static void free_zone_bm_rtree(struct mem_zone_bm_rtree *zone,
			       int clear_nosave_free)
{
	struct rtree_node *node;

	list_for_each_entry(node, &zone->nodes, list)
		free_image_page(node->data, clear_nosave_free);

	list_for_each_entry(node, &zone->leaves, list)
		free_image_page(node->data, clear_nosave_free);
}

static void memory_bm_position_reset(struct memory_bitmap *bm)
{
	bm->cur.zone = list_entry(bm->zones.next, struct mem_zone_bm_rtree,
				  list);
	bm->cur.node = list_entry(bm->cur.zone->leaves.next,
				  struct rtree_node, list);
	bm->cur.node_pfn = 0;
	bm->cur.node_bit = 0;
}

static void memory_bm_free(struct memory_bitmap *bm, int clear_nosave_free);

struct mem_extent {
	struct list_head hook;
	unsigned long start;
	unsigned long end;
};

static void free_mem_extents(struct list_head *list)
{
	struct mem_extent *ext, *aux;

	list_for_each_entry_safe(ext, aux, list, hook) {
		list_del(&ext->hook);
		kfree(ext);
	}
}

static int create_mem_extents(struct list_head *list, gfp_t gfp_mask)
{
	struct zone *zone;

	INIT_LIST_HEAD(list);

	for_each_populated_zone(zone) {
		unsigned long zone_start, zone_end;
		struct mem_extent *ext, *cur, *aux;

		zone_start = zone->zone_start_pfn;
		zone_end = zone_end_pfn(zone);

		list_for_each_entry(ext, list, hook)
			if (zone_start <= ext->end)
				break;

		if (&ext->hook == list || zone_end < ext->start) {
			/* New extent is necessary */
			struct mem_extent *new_ext;

			new_ext = kzalloc(sizeof(struct mem_extent), gfp_mask);
			if (!new_ext) {
				free_mem_extents(list);
				return -ENOMEM;
			}
			new_ext->start = zone_start;
			new_ext->end = zone_end;
			list_add_tail(&new_ext->hook, &ext->hook);
			continue;
		}

		/* Merge this zone's range of PFNs with the existing one */
		if (zone_start < ext->start)
			ext->start = zone_start;
		if (zone_end > ext->end)
			ext->end = zone_end;

		/* More merging may be possible */
		cur = ext;
		list_for_each_entry_safe_continue(cur, aux, list, hook) {
			if (zone_end < cur->start)
				break;
			if (zone_end < cur->end)
				ext->end = cur->end;
			list_del(&cur->hook);
			kfree(cur);
		}
	}

	return 0;
}

static int memory_bm_create(struct memory_bitmap *bm, gfp_t gfp_mask,
			    int safe_needed)
{
	struct chain_allocator ca;
	struct list_head mem_extents;
	struct mem_extent *ext;
	int error;

	chain_init(&ca, gfp_mask, safe_needed);
	INIT_LIST_HEAD(&bm->zones);

	error = create_mem_extents(&mem_extents, gfp_mask);
	if (error)
		return error;

	list_for_each_entry(ext, &mem_extents, hook) {
		struct mem_zone_bm_rtree *zone;

		zone = create_zone_bm_rtree(gfp_mask, safe_needed, &ca,
					    ext->start, ext->end);
		if (!zone) {
			error = -ENOMEM;
			goto Error;
		}
		list_add_tail(&zone->list, &bm->zones);
	}

	bm->p_list = ca.chain;
	memory_bm_position_reset(bm);
 Exit:
	free_mem_extents(&mem_extents);
	return error;

 Error:
	bm->p_list = ca.chain;
	memory_bm_free(bm, PG_UNSAFE_CLEAR);
	goto Exit;
}

static void memory_bm_free(struct memory_bitmap *bm, int clear_nosave_free)
{
	struct mem_zone_bm_rtree *zone;

	list_for_each_entry(zone, &bm->zones, list)
		free_zone_bm_rtree(zone, clear_nosave_free);

	free_list_of_pages(bm->p_list, clear_nosave_free);

	INIT_LIST_HEAD(&bm->zones);
}

static int memory_bm_find_bit(struct memory_bitmap *bm, unsigned long pfn,
			      void **addr, unsigned int *bit_nr)
{
	struct mem_zone_bm_rtree *curr, *zone;
	struct rtree_node *node;
	int i, block_nr;

	zone = bm->cur.zone;

	if (pfn >= zone->start_pfn && pfn < zone->end_pfn)
		goto zone_found;

	zone = NULL;

	/* Find the right zone */
	list_for_each_entry(curr, &bm->zones, list) {
		if (pfn >= curr->start_pfn && pfn < curr->end_pfn) {
			zone = curr;
			break;
		}
	}

	if (!zone)
		return -EFAULT;

zone_found:
	/*

	/*
	node = bm->cur.node;
	if (zone == bm->cur.zone &&
	    ((pfn - zone->start_pfn) & ~BM_BLOCK_MASK) == bm->cur.node_pfn)
		goto node_found;

	node      = zone->rtree;
	block_nr  = (pfn - zone->start_pfn) >> BM_BLOCK_SHIFT;

	for (i = zone->levels; i > 0; i--) {
		int index;

		index = block_nr >> ((i - 1) * BM_RTREE_LEVEL_SHIFT);
		index &= BM_RTREE_LEVEL_MASK;
		BUG_ON(node->data[index] == 0);
		node = (struct rtree_node *)node->data[index];
	}

node_found:
	/* Update last position */
	bm->cur.zone = zone;
	bm->cur.node = node;
	bm->cur.node_pfn = (pfn - zone->start_pfn) & ~BM_BLOCK_MASK;

	/* Set return values */

	return 0;
}

static void memory_bm_set_bit(struct memory_bitmap *bm, unsigned long pfn)
{
	void *addr;
	unsigned int bit;
	int error;

	error = memory_bm_find_bit(bm, pfn, &addr, &bit);
	BUG_ON(error);
	set_bit(bit, addr);
}

static int mem_bm_set_bit_check(struct memory_bitmap *bm, unsigned long pfn)
{
	void *addr;
	unsigned int bit;
	int error;

	error = memory_bm_find_bit(bm, pfn, &addr, &bit);
	if (!error)
		set_bit(bit, addr);

	return error;
}

static void memory_bm_clear_bit(struct memory_bitmap *bm, unsigned long pfn)
{
	void *addr;
	unsigned int bit;
	int error;

	error = memory_bm_find_bit(bm, pfn, &addr, &bit);
	BUG_ON(error);
	clear_bit(bit, addr);
}

static void memory_bm_clear_current(struct memory_bitmap *bm)
{
	int bit;

	bit = max(bm->cur.node_bit - 1, 0);
	clear_bit(bit, bm->cur.node->data);
}

static int memory_bm_test_bit(struct memory_bitmap *bm, unsigned long pfn)
{
	void *addr;
	unsigned int bit;
	int error;

	error = memory_bm_find_bit(bm, pfn, &addr, &bit);
	BUG_ON(error);
	return test_bit(bit, addr);
}

static bool memory_bm_pfn_present(struct memory_bitmap *bm, unsigned long pfn)
{
	void *addr;
	unsigned int bit;

	return !memory_bm_find_bit(bm, pfn, &addr, &bit);
}

static bool rtree_next_node(struct memory_bitmap *bm)
{
	if (!list_is_last(&bm->cur.node->list, &bm->cur.zone->leaves)) {
		bm->cur.node = list_entry(bm->cur.node->list.next,
					  struct rtree_node, list);
		bm->cur.node_pfn += BM_BITS_PER_BLOCK;
		bm->cur.node_bit  = 0;
		touch_softlockup_watchdog();
		return true;
	}

	/* No more nodes, goto next zone */
	if (!list_is_last(&bm->cur.zone->list, &bm->zones)) {
		bm->cur.zone = list_entry(bm->cur.zone->list.next,
				  struct mem_zone_bm_rtree, list);
		bm->cur.node = list_entry(bm->cur.zone->leaves.next,
					  struct rtree_node, list);
		bm->cur.node_pfn = 0;
		bm->cur.node_bit = 0;
		return true;
	}

	/* No more zones */
	return false;
}

static unsigned long memory_bm_next_pfn(struct memory_bitmap *bm)
{
	unsigned long bits, pfn, pages;
	int bit;

	do {
		pages	  = bm->cur.zone->end_pfn - bm->cur.zone->start_pfn;
		bits      = min(pages - bm->cur.node_pfn, BM_BITS_PER_BLOCK);
		bit	  = find_next_bit(bm->cur.node->data, bits,
					  bm->cur.node_bit);
		if (bit < bits) {
			pfn = bm->cur.zone->start_pfn + bm->cur.node_pfn + bit;
			bm->cur.node_bit = bit + 1;
			return pfn;
		}
	} while (rtree_next_node(bm));

	return BM_END_OF_MAP;
}

struct nosave_region {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
};

static LIST_HEAD(nosave_regions);

static void recycle_zone_bm_rtree(struct mem_zone_bm_rtree *zone)
{
	struct rtree_node *node;

	list_for_each_entry(node, &zone->nodes, list)
		recycle_safe_page(node->data);

	list_for_each_entry(node, &zone->leaves, list)
		recycle_safe_page(node->data);
}

static void memory_bm_recycle(struct memory_bitmap *bm)
{
	struct mem_zone_bm_rtree *zone;
	struct linked_page *p_list;

	list_for_each_entry(zone, &bm->zones, list)
		recycle_zone_bm_rtree(zone);

	p_list = bm->p_list;
	while (p_list) {
		struct linked_page *lp = p_list;

		p_list = lp->next;
		recycle_safe_page(lp);
	}
}

void __init register_nosave_region(unsigned long start_pfn, unsigned long end_pfn)
{
	struct nosave_region *region;

	if (start_pfn >= end_pfn)
		return;

	if (!list_empty(&nosave_regions)) {
		/* Try to extend the previous region (they should be sorted) */
		region = list_entry(nosave_regions.prev,
					struct nosave_region, list);
		if (region->end_pfn == start_pfn) {
			region->end_pfn = end_pfn;
			goto Report;
		}
	}
	/* This allocation cannot fail */
	region = memblock_alloc(sizeof(struct nosave_region),
				SMP_CACHE_BYTES);
	if (!region)
		panic("%s: Failed to allocate %zu bytes\n", __func__,
		      sizeof(struct nosave_region));
	region->start_pfn = start_pfn;
	region->end_pfn = end_pfn;
	list_add_tail(&region->list, &nosave_regions);
 Report:
	pr_info("Registered nosave memory: [mem %#010llx-%#010llx]\n",
		(unsigned long long) start_pfn << PAGE_SHIFT,
		((unsigned long long) end_pfn << PAGE_SHIFT) - 1);
}

static struct memory_bitmap *forbidden_pages_map;

static struct memory_bitmap *free_pages_map;


void swsusp_set_page_free(struct page *page)
{
	if (free_pages_map)
		memory_bm_set_bit(free_pages_map, page_to_pfn(page));
}

static int swsusp_page_is_free(struct page *page)
{
	return free_pages_map ?
		memory_bm_test_bit(free_pages_map, page_to_pfn(page)) : 0;
}

void swsusp_unset_page_free(struct page *page)
{
	if (free_pages_map)
		memory_bm_clear_bit(free_pages_map, page_to_pfn(page));
}

static void swsusp_set_page_forbidden(struct page *page)
{
	if (forbidden_pages_map)
		memory_bm_set_bit(forbidden_pages_map, page_to_pfn(page));
}

int swsusp_page_is_forbidden(struct page *page)
{
	return forbidden_pages_map ?
		memory_bm_test_bit(forbidden_pages_map, page_to_pfn(page)) : 0;
}

static void swsusp_unset_page_forbidden(struct page *page)
{
	if (forbidden_pages_map)
		memory_bm_clear_bit(forbidden_pages_map, page_to_pfn(page));
}

static void mark_nosave_pages(struct memory_bitmap *bm)
{
	struct nosave_region *region;

	if (list_empty(&nosave_regions))
		return;

	list_for_each_entry(region, &nosave_regions, list) {
		unsigned long pfn;

		pr_debug("Marking nosave pages: [mem %#010llx-%#010llx]\n",
			 (unsigned long long) region->start_pfn << PAGE_SHIFT,
			 ((unsigned long long) region->end_pfn << PAGE_SHIFT)
				- 1);

		for (pfn = region->start_pfn; pfn < region->end_pfn; pfn++)
			if (pfn_valid(pfn)) {
				/*
				mem_bm_set_bit_check(bm, pfn);
			}
	}
}

int create_basic_memory_bitmaps(void)
{
	struct memory_bitmap *bm1, *bm2;
	int error = 0;

	if (forbidden_pages_map && free_pages_map)
		return 0;
	else
		BUG_ON(forbidden_pages_map || free_pages_map);

	bm1 = kzalloc(sizeof(struct memory_bitmap), GFP_KERNEL);
	if (!bm1)
		return -ENOMEM;

	error = memory_bm_create(bm1, GFP_KERNEL, PG_ANY);
	if (error)
		goto Free_first_object;

	bm2 = kzalloc(sizeof(struct memory_bitmap), GFP_KERNEL);
	if (!bm2)
		goto Free_first_bitmap;

	error = memory_bm_create(bm2, GFP_KERNEL, PG_ANY);
	if (error)
		goto Free_second_object;

	forbidden_pages_map = bm1;
	free_pages_map = bm2;
	mark_nosave_pages(forbidden_pages_map);

	pr_debug("Basic memory bitmaps created\n");

	return 0;

 Free_second_object:
	kfree(bm2);
 Free_first_bitmap:
	memory_bm_free(bm1, PG_UNSAFE_CLEAR);
 Free_first_object:
	kfree(bm1);
	return -ENOMEM;
}

void free_basic_memory_bitmaps(void)
{
	struct memory_bitmap *bm1, *bm2;

	if (WARN_ON(!(forbidden_pages_map && free_pages_map)))
		return;

	bm1 = forbidden_pages_map;
	bm2 = free_pages_map;
	forbidden_pages_map = NULL;
	free_pages_map = NULL;
	memory_bm_free(bm1, PG_UNSAFE_CLEAR);
	kfree(bm1);
	memory_bm_free(bm2, PG_UNSAFE_CLEAR);
	kfree(bm2);

	pr_debug("Basic memory bitmaps freed\n");
}

static void clear_or_poison_free_page(struct page *page)
{
	if (page_poisoning_enabled_static())
		__kernel_poison_pages(page, 1);
	else if (want_init_on_free())
		clear_highpage(page);
}

void clear_or_poison_free_pages(void)
{
	struct memory_bitmap *bm = free_pages_map;
	unsigned long pfn;

	if (WARN_ON(!(free_pages_map)))
		return;

	if (page_poisoning_enabled() || want_init_on_free()) {
		memory_bm_position_reset(bm);
		pfn = memory_bm_next_pfn(bm);
		while (pfn != BM_END_OF_MAP) {
			if (pfn_valid(pfn))
				clear_or_poison_free_page(pfn_to_page(pfn));

			pfn = memory_bm_next_pfn(bm);
		}
		memory_bm_position_reset(bm);
		pr_info("free pages cleared after restore\n");
	}
}

unsigned int snapshot_additional_pages(struct zone *zone)
{
	unsigned int rtree, nodes;

	rtree = nodes = DIV_ROUND_UP(zone->spanned_pages, BM_BITS_PER_BLOCK);
	rtree += DIV_ROUND_UP(rtree * sizeof(struct rtree_node),
			      LINKED_PAGE_DATA_SIZE);
	while (nodes > 1) {
		nodes = DIV_ROUND_UP(nodes, BM_ENTRIES_PER_LEVEL);
		rtree += nodes;
	}

	return 2 * rtree;
}

#ifdef CONFIG_HIGHMEM
static unsigned int count_free_highmem_pages(void)
{
	struct zone *zone;
	unsigned int cnt = 0;

	for_each_populated_zone(zone)
		if (is_highmem(zone))
			cnt += zone_page_state(zone, NR_FREE_PAGES);

	return cnt;
}

static struct page *saveable_highmem_page(struct zone *zone, unsigned long pfn)
{
	struct page *page;

	if (!pfn_valid(pfn))
		return NULL;

	page = pfn_to_online_page(pfn);
	if (!page || page_zone(page) != zone)
		return NULL;

	BUG_ON(!PageHighMem(page));

	if (swsusp_page_is_forbidden(page) ||  swsusp_page_is_free(page))
		return NULL;

	if (PageReserved(page) || PageOffline(page))
		return NULL;

	if (page_is_guard(page))
		return NULL;

	return page;
}

static unsigned int count_highmem_pages(void)
{
	struct zone *zone;
	unsigned int n = 0;

	for_each_populated_zone(zone) {
		unsigned long pfn, max_zone_pfn;

		if (!is_highmem(zone))
			continue;

		mark_free_pages(zone);
		max_zone_pfn = zone_end_pfn(zone);
		for (pfn = zone->zone_start_pfn; pfn < max_zone_pfn; pfn++)
			if (saveable_highmem_page(zone, pfn))
				n++;
	}
	return n;
}
#else
static inline void *saveable_highmem_page(struct zone *z, unsigned long p)
{
	return NULL;
}
#endif /* CONFIG_HIGHMEM */

static struct page *saveable_page(struct zone *zone, unsigned long pfn)
{
	struct page *page;

	if (!pfn_valid(pfn))
		return NULL;

	page = pfn_to_online_page(pfn);
	if (!page || page_zone(page) != zone)
		return NULL;

	BUG_ON(PageHighMem(page));

	if (swsusp_page_is_forbidden(page) || swsusp_page_is_free(page))
		return NULL;

	if (PageOffline(page))
		return NULL;

	if (PageReserved(page)
	    && (!kernel_page_present(page) || pfn_is_nosave(pfn)))
		return NULL;

	if (page_is_guard(page))
		return NULL;

	return page;
}

static unsigned int count_data_pages(void)
{
	struct zone *zone;
	unsigned long pfn, max_zone_pfn;
	unsigned int n = 0;

	for_each_populated_zone(zone) {
		if (is_highmem(zone))
			continue;

		mark_free_pages(zone);
		max_zone_pfn = zone_end_pfn(zone);
		for (pfn = zone->zone_start_pfn; pfn < max_zone_pfn; pfn++)
			if (saveable_page(zone, pfn))
				n++;
	}
	return n;
}

static inline void do_copy_page(long *dst, long *src)
{
	int n;

	for (n = PAGE_SIZE / sizeof(long); n; n--)
		*dst++ = *src++;
}

static void safe_copy_page(void *dst, struct page *s_page)
{
	if (kernel_page_present(s_page)) {
		do_copy_page(dst, page_address(s_page));
	} else {
		hibernate_map_page(s_page);
		do_copy_page(dst, page_address(s_page));
		hibernate_unmap_page(s_page);
	}
}

#ifdef CONFIG_HIGHMEM
static inline struct page *page_is_saveable(struct zone *zone, unsigned long pfn)
{
	return is_highmem(zone) ?
		saveable_highmem_page(zone, pfn) : saveable_page(zone, pfn);
}

static void copy_data_page(unsigned long dst_pfn, unsigned long src_pfn)
{
	struct page *s_page, *d_page;
	void *src, *dst;

	s_page = pfn_to_page(src_pfn);
	d_page = pfn_to_page(dst_pfn);
	if (PageHighMem(s_page)) {
		src = kmap_atomic(s_page);
		dst = kmap_atomic(d_page);
		do_copy_page(dst, src);
		kunmap_atomic(dst);
		kunmap_atomic(src);
	} else {
		if (PageHighMem(d_page)) {
			/*
			safe_copy_page(buffer, s_page);
			dst = kmap_atomic(d_page);
			copy_page(dst, buffer);
			kunmap_atomic(dst);
		} else {
			safe_copy_page(page_address(d_page), s_page);
		}
	}
}
#else
#define page_is_saveable(zone, pfn)	saveable_page(zone, pfn)

static inline void copy_data_page(unsigned long dst_pfn, unsigned long src_pfn)
{
	safe_copy_page(page_address(pfn_to_page(dst_pfn)),
				pfn_to_page(src_pfn));
}
#endif /* CONFIG_HIGHMEM */

static void copy_data_pages(struct memory_bitmap *copy_bm,
			    struct memory_bitmap *orig_bm)
{
	struct zone *zone;
	unsigned long pfn;

	for_each_populated_zone(zone) {
		unsigned long max_zone_pfn;

		mark_free_pages(zone);
		max_zone_pfn = zone_end_pfn(zone);
		for (pfn = zone->zone_start_pfn; pfn < max_zone_pfn; pfn++)
			if (page_is_saveable(zone, pfn))
				memory_bm_set_bit(orig_bm, pfn);
	}
	memory_bm_position_reset(orig_bm);
	memory_bm_position_reset(copy_bm);
	for(;;) {
		pfn = memory_bm_next_pfn(orig_bm);
		if (unlikely(pfn == BM_END_OF_MAP))
			break;
		copy_data_page(memory_bm_next_pfn(copy_bm), pfn);
	}
}

static unsigned int nr_copy_pages;
static unsigned int nr_meta_pages;
static unsigned int alloc_normal, alloc_highmem;
static struct memory_bitmap orig_bm;
static struct memory_bitmap copy_bm;

void swsusp_free(void)
{
	unsigned long fb_pfn, fr_pfn;

	if (!forbidden_pages_map || !free_pages_map)
		goto out;

	memory_bm_position_reset(forbidden_pages_map);
	memory_bm_position_reset(free_pages_map);

loop:
	fr_pfn = memory_bm_next_pfn(free_pages_map);
	fb_pfn = memory_bm_next_pfn(forbidden_pages_map);

	/*
	do {
		if (fb_pfn < fr_pfn)
			fb_pfn = memory_bm_next_pfn(forbidden_pages_map);
		if (fr_pfn < fb_pfn)
			fr_pfn = memory_bm_next_pfn(free_pages_map);
	} while (fb_pfn != fr_pfn);

	if (fr_pfn != BM_END_OF_MAP && pfn_valid(fr_pfn)) {
		struct page *page = pfn_to_page(fr_pfn);

		memory_bm_clear_current(forbidden_pages_map);
		memory_bm_clear_current(free_pages_map);
		hibernate_restore_unprotect_page(page_address(page));
		__free_page(page);
		goto loop;
	}

out:
	nr_copy_pages = 0;
	nr_meta_pages = 0;
	restore_pblist = NULL;
	buffer = NULL;
	alloc_normal = 0;
	alloc_highmem = 0;
	hibernate_restore_protection_end();
}


#define GFP_IMAGE	(GFP_KERNEL | __GFP_NOWARN)

static unsigned long preallocate_image_pages(unsigned long nr_pages, gfp_t mask)
{
	unsigned long nr_alloc = 0;

	while (nr_pages > 0) {
		struct page *page;

		page = alloc_image_page(mask);
		if (!page)
			break;
		memory_bm_set_bit(&copy_bm, page_to_pfn(page));
		if (PageHighMem(page))
			alloc_highmem++;
		else
			alloc_normal++;
		nr_pages--;
		nr_alloc++;
	}

	return nr_alloc;
}

static unsigned long preallocate_image_memory(unsigned long nr_pages,
					      unsigned long avail_normal)
{
	unsigned long alloc;

	if (avail_normal <= alloc_normal)
		return 0;

	alloc = avail_normal - alloc_normal;
	if (nr_pages < alloc)
		alloc = nr_pages;

	return preallocate_image_pages(alloc, GFP_IMAGE);
}

#ifdef CONFIG_HIGHMEM
static unsigned long preallocate_image_highmem(unsigned long nr_pages)
{
	return preallocate_image_pages(nr_pages, GFP_IMAGE | __GFP_HIGHMEM);
}

static unsigned long __fraction(u64 x, u64 multiplier, u64 base)
{
	return div64_u64(x * multiplier, base);
}

static unsigned long preallocate_highmem_fraction(unsigned long nr_pages,
						  unsigned long highmem,
						  unsigned long total)
{
	unsigned long alloc = __fraction(nr_pages, highmem, total);

	return preallocate_image_pages(alloc, GFP_IMAGE | __GFP_HIGHMEM);
}
#else /* CONFIG_HIGHMEM */
static inline unsigned long preallocate_image_highmem(unsigned long nr_pages)
{
	return 0;
}

static inline unsigned long preallocate_highmem_fraction(unsigned long nr_pages,
							 unsigned long highmem,
							 unsigned long total)
{
	return 0;
}
#endif /* CONFIG_HIGHMEM */

static unsigned long free_unnecessary_pages(void)
{
	unsigned long save, to_free_normal, to_free_highmem, free;

	save = count_data_pages();
	if (alloc_normal >= save) {
		to_free_normal = alloc_normal - save;
		save = 0;
	} else {
		to_free_normal = 0;
		save -= alloc_normal;
	}
	save += count_highmem_pages();
	if (alloc_highmem >= save) {
		to_free_highmem = alloc_highmem - save;
	} else {
		to_free_highmem = 0;
		save -= alloc_highmem;
		if (to_free_normal > save)
			to_free_normal -= save;
		else
			to_free_normal = 0;
	}
	free = to_free_normal + to_free_highmem;

	memory_bm_position_reset(&copy_bm);

	while (to_free_normal > 0 || to_free_highmem > 0) {
		unsigned long pfn = memory_bm_next_pfn(&copy_bm);
		struct page *page = pfn_to_page(pfn);

		if (PageHighMem(page)) {
			if (!to_free_highmem)
				continue;
			to_free_highmem--;
			alloc_highmem--;
		} else {
			if (!to_free_normal)
				continue;
			to_free_normal--;
			alloc_normal--;
		}
		memory_bm_clear_bit(&copy_bm, pfn);
		swsusp_unset_page_forbidden(page);
		swsusp_unset_page_free(page);
		__free_page(page);
	}

	return free;
}

static unsigned long minimum_image_size(unsigned long saveable)
{
	unsigned long size;

	size = global_node_page_state_pages(NR_SLAB_RECLAIMABLE_B)
		+ global_node_page_state(NR_ACTIVE_ANON)
		+ global_node_page_state(NR_INACTIVE_ANON)
		+ global_node_page_state(NR_ACTIVE_FILE)
		+ global_node_page_state(NR_INACTIVE_FILE);

	return saveable <= size ? 0 : saveable - size;
}

int hibernate_preallocate_memory(void)
{
	struct zone *zone;
	unsigned long saveable, size, max_size, count, highmem, pages = 0;
	unsigned long alloc, save_highmem, pages_highmem, avail_normal;
	ktime_t start, stop;
	int error;

	pr_info("Preallocating image memory\n");
	start = ktime_get();

	error = memory_bm_create(&orig_bm, GFP_IMAGE, PG_ANY);
	if (error) {
		pr_err("Cannot allocate original bitmap\n");
		goto err_out;
	}

	error = memory_bm_create(&copy_bm, GFP_IMAGE, PG_ANY);
	if (error) {
		pr_err("Cannot allocate copy bitmap\n");
		goto err_out;
	}

	alloc_normal = 0;
	alloc_highmem = 0;

	/* Count the number of saveable data pages. */
	save_highmem = count_highmem_pages();
	saveable = count_data_pages();

	/*
	count = saveable;
	saveable += save_highmem;
	highmem = save_highmem;
	size = 0;
	for_each_populated_zone(zone) {
		size += snapshot_additional_pages(zone);
		if (is_highmem(zone))
			highmem += zone_page_state(zone, NR_FREE_PAGES);
		else
			count += zone_page_state(zone, NR_FREE_PAGES);
	}
	avail_normal = count;
	count += highmem;
	count -= totalreserve_pages;

	/* Compute the maximum number of saveable pages to leave in memory. */
	max_size = (count - (size + PAGES_FOR_IO)) / 2
			- 2 * DIV_ROUND_UP(reserved_size, PAGE_SIZE);
	/* Compute the desired number of image pages specified by image_size. */
	size = DIV_ROUND_UP(image_size, PAGE_SIZE);
	if (size > max_size)
		size = max_size;
	/*
	if (size >= saveable) {
		pages = preallocate_image_highmem(save_highmem);
		pages += preallocate_image_memory(saveable - pages, avail_normal);
		goto out;
	}

	/* Estimate the minimum size of the image. */
	pages = minimum_image_size(saveable);
	/*
	if (avail_normal > pages)
		avail_normal -= pages;
	else
		avail_normal = 0;
	if (size < pages)
		size = min_t(unsigned long, pages, max_size);

	/*
	shrink_all_memory(saveable - size);

	/*
	pages_highmem = preallocate_image_highmem(highmem / 2);
	alloc = count - max_size;
	if (alloc > pages_highmem)
		alloc -= pages_highmem;
	else
		alloc = 0;
	pages = preallocate_image_memory(alloc, avail_normal);
	if (pages < alloc) {
		/* We have exhausted non-highmem pages, try highmem. */
		alloc -= pages;
		pages += pages_highmem;
		pages_highmem = preallocate_image_highmem(alloc);
		if (pages_highmem < alloc) {
			pr_err("Image allocation is %lu pages short\n",
				alloc - pages_highmem);
			goto err_out;
		}
		pages += pages_highmem;
		/*
		alloc = (count - pages) - size;
		pages += preallocate_image_highmem(alloc);
	} else {
		/*
		alloc = max_size - size;
		size = preallocate_highmem_fraction(alloc, highmem, count);
		pages_highmem += size;
		alloc -= size;
		size = preallocate_image_memory(alloc, avail_normal);
		pages_highmem += preallocate_image_highmem(alloc - size);
		pages += pages_highmem + size;
	}

	/*
	pages -= free_unnecessary_pages();

 out:
	stop = ktime_get();
	pr_info("Allocated %lu pages for snapshot\n", pages);
	swsusp_show_speed(start, stop, pages, "Allocated");

	return 0;

 err_out:
	swsusp_free();
	return -ENOMEM;
}

#ifdef CONFIG_HIGHMEM
static unsigned int count_pages_for_highmem(unsigned int nr_highmem)
{
	unsigned int free_highmem = count_free_highmem_pages() + alloc_highmem;

	if (free_highmem >= nr_highmem)
		nr_highmem = 0;
	else
		nr_highmem -= free_highmem;

	return nr_highmem;
}
#else
static unsigned int count_pages_for_highmem(unsigned int nr_highmem) { return 0; }
#endif /* CONFIG_HIGHMEM */

static int enough_free_mem(unsigned int nr_pages, unsigned int nr_highmem)
{
	struct zone *zone;
	unsigned int free = alloc_normal;

	for_each_populated_zone(zone)
		if (!is_highmem(zone))
			free += zone_page_state(zone, NR_FREE_PAGES);

	nr_pages += count_pages_for_highmem(nr_highmem);
	pr_debug("Normal pages needed: %u + %u, available pages: %u\n",
		 nr_pages, PAGES_FOR_IO, free);

	return free > nr_pages + PAGES_FOR_IO;
}

#ifdef CONFIG_HIGHMEM
static inline int get_highmem_buffer(int safe_needed)
{
	buffer = get_image_page(GFP_ATOMIC, safe_needed);
	return buffer ? 0 : -ENOMEM;
}

static inline unsigned int alloc_highmem_pages(struct memory_bitmap *bm,
					       unsigned int nr_highmem)
{
	unsigned int to_alloc = count_free_highmem_pages();

	if (to_alloc > nr_highmem)
		to_alloc = nr_highmem;

	nr_highmem -= to_alloc;
	while (to_alloc-- > 0) {
		struct page *page;

		page = alloc_image_page(__GFP_HIGHMEM|__GFP_KSWAPD_RECLAIM);
		memory_bm_set_bit(bm, page_to_pfn(page));
	}
	return nr_highmem;
}
#else
static inline int get_highmem_buffer(int safe_needed) { return 0; }

static inline unsigned int alloc_highmem_pages(struct memory_bitmap *bm,
					       unsigned int n) { return 0; }
#endif /* CONFIG_HIGHMEM */

static int swsusp_alloc(struct memory_bitmap *copy_bm,
			unsigned int nr_pages, unsigned int nr_highmem)
{
	if (nr_highmem > 0) {
		if (get_highmem_buffer(PG_ANY))
			goto err_out;
		if (nr_highmem > alloc_highmem) {
			nr_highmem -= alloc_highmem;
			nr_pages += alloc_highmem_pages(copy_bm, nr_highmem);
		}
	}
	if (nr_pages > alloc_normal) {
		nr_pages -= alloc_normal;
		while (nr_pages-- > 0) {
			struct page *page;

			page = alloc_image_page(GFP_ATOMIC);
			if (!page)
				goto err_out;
			memory_bm_set_bit(copy_bm, page_to_pfn(page));
		}
	}

	return 0;

 err_out:
	swsusp_free();
	return -ENOMEM;
}

asmlinkage __visible int swsusp_save(void)
{
	unsigned int nr_pages, nr_highmem;

	pr_info("Creating image:\n");

	drain_local_pages(NULL);
	nr_pages = count_data_pages();
	nr_highmem = count_highmem_pages();
	pr_info("Need to copy %u pages\n", nr_pages + nr_highmem);

	if (!enough_free_mem(nr_pages, nr_highmem)) {
		pr_err("Not enough free memory\n");
		return -ENOMEM;
	}

	if (swsusp_alloc(&copy_bm, nr_pages, nr_highmem)) {
		pr_err("Memory allocation failed\n");
		return -ENOMEM;
	}

	/*
	drain_local_pages(NULL);
	copy_data_pages(&copy_bm, &orig_bm);

	/*

	nr_pages += nr_highmem;
	nr_copy_pages = nr_pages;
	nr_meta_pages = DIV_ROUND_UP(nr_pages * sizeof(long), PAGE_SIZE);

	pr_info("Image created (%d pages copied)\n", nr_pages);

	return 0;
}

#ifndef CONFIG_ARCH_HIBERNATION_HEADER
static int init_header_complete(struct swsusp_info *info)
{
	memcpy(&info->uts, init_utsname(), sizeof(struct new_utsname));
	info->version_code = LINUX_VERSION_CODE;
	return 0;
}

static const char *check_image_kernel(struct swsusp_info *info)
{
	if (info->version_code != LINUX_VERSION_CODE)
		return "kernel version";
	if (strcmp(info->uts.sysname,init_utsname()->sysname))
		return "system type";
	if (strcmp(info->uts.release,init_utsname()->release))
		return "kernel release";
	if (strcmp(info->uts.version,init_utsname()->version))
		return "version";
	if (strcmp(info->uts.machine,init_utsname()->machine))
		return "machine";
	return NULL;
}
#endif /* CONFIG_ARCH_HIBERNATION_HEADER */

unsigned long snapshot_get_image_size(void)
{
	return nr_copy_pages + nr_meta_pages + 1;
}

static int init_header(struct swsusp_info *info)
{
	memset(info, 0, sizeof(struct swsusp_info));
	info->num_physpages = get_num_physpages();
	info->image_pages = nr_copy_pages;
	info->pages = snapshot_get_image_size();
	info->size = info->pages;
	info->size <<= PAGE_SHIFT;
	return init_header_complete(info);
}

static inline void pack_pfns(unsigned long *buf, struct memory_bitmap *bm)
{
	int j;

	for (j = 0; j < PAGE_SIZE / sizeof(long); j++) {
		buf[j] = memory_bm_next_pfn(bm);
		if (unlikely(buf[j] == BM_END_OF_MAP))
			break;
	}
}

int snapshot_read_next(struct snapshot_handle *handle)
{
	if (handle->cur > nr_meta_pages + nr_copy_pages)
		return 0;

	if (!buffer) {
		/* This makes the buffer be freed by swsusp_free() */
		buffer = get_image_page(GFP_ATOMIC, PG_ANY);
		if (!buffer)
			return -ENOMEM;
	}
	if (!handle->cur) {
		int error;

		error = init_header((struct swsusp_info *)buffer);
		if (error)
			return error;
		handle->buffer = buffer;
		memory_bm_position_reset(&orig_bm);
		memory_bm_position_reset(&copy_bm);
	} else if (handle->cur <= nr_meta_pages) {
		clear_page(buffer);
		pack_pfns(buffer, &orig_bm);
	} else {
		struct page *page;

		page = pfn_to_page(memory_bm_next_pfn(&copy_bm));
		if (PageHighMem(page)) {
			/*
			void *kaddr;

			kaddr = kmap_atomic(page);
			copy_page(buffer, kaddr);
			kunmap_atomic(kaddr);
			handle->buffer = buffer;
		} else {
			handle->buffer = page_address(page);
		}
	}
	handle->cur++;
	return PAGE_SIZE;
}

static void duplicate_memory_bitmap(struct memory_bitmap *dst,
				    struct memory_bitmap *src)
{
	unsigned long pfn;

	memory_bm_position_reset(src);
	pfn = memory_bm_next_pfn(src);
	while (pfn != BM_END_OF_MAP) {
		memory_bm_set_bit(dst, pfn);
		pfn = memory_bm_next_pfn(src);
	}
}

static void mark_unsafe_pages(struct memory_bitmap *bm)
{
	unsigned long pfn;

	/* Clear the "free"/"unsafe" bit for all PFNs */
	memory_bm_position_reset(free_pages_map);
	pfn = memory_bm_next_pfn(free_pages_map);
	while (pfn != BM_END_OF_MAP) {
		memory_bm_clear_current(free_pages_map);
		pfn = memory_bm_next_pfn(free_pages_map);
	}

	/* Mark pages that correspond to the "original" PFNs as "unsafe" */
	duplicate_memory_bitmap(free_pages_map, bm);

	allocated_unsafe_pages = 0;
}

static int check_header(struct swsusp_info *info)
{
	const char *reason;

	reason = check_image_kernel(info);
	if (!reason && info->num_physpages != get_num_physpages())
		reason = "memory size";
	if (reason) {
		pr_err("Image mismatch: %s\n", reason);
		return -EPERM;
	}
	return 0;
}

static int load_header(struct swsusp_info *info)
{
	int error;

	restore_pblist = NULL;
	error = check_header(info);
	if (!error) {
		nr_copy_pages = info->image_pages;
		nr_meta_pages = info->pages - info->image_pages - 1;
	}
	return error;
}

static int unpack_orig_pfns(unsigned long *buf, struct memory_bitmap *bm)
{
	int j;

	for (j = 0; j < PAGE_SIZE / sizeof(long); j++) {
		if (unlikely(buf[j] == BM_END_OF_MAP))
			break;

		if (pfn_valid(buf[j]) && memory_bm_pfn_present(bm, buf[j]))
			memory_bm_set_bit(bm, buf[j]);
		else
			return -EFAULT;
	}

	return 0;
}

#ifdef CONFIG_HIGHMEM
struct highmem_pbe {
	struct page *copy_page;	/* data is here now */
	struct page *orig_page;	/* data was here before the suspend */
	struct highmem_pbe *next;
};

static struct highmem_pbe *highmem_pblist;

static unsigned int count_highmem_image_pages(struct memory_bitmap *bm)
{
	unsigned long pfn;
	unsigned int cnt = 0;

	memory_bm_position_reset(bm);
	pfn = memory_bm_next_pfn(bm);
	while (pfn != BM_END_OF_MAP) {
		if (PageHighMem(pfn_to_page(pfn)))
			cnt++;

		pfn = memory_bm_next_pfn(bm);
	}
	return cnt;
}

static unsigned int safe_highmem_pages;

static struct memory_bitmap *safe_highmem_bm;

static int prepare_highmem_image(struct memory_bitmap *bm,
				 unsigned int *nr_highmem_p)
{
	unsigned int to_alloc;

	if (memory_bm_create(bm, GFP_ATOMIC, PG_SAFE))
		return -ENOMEM;

	if (get_highmem_buffer(PG_SAFE))
		return -ENOMEM;

	to_alloc = count_free_highmem_pages();
	if (to_alloc > *nr_highmem_p)
		to_alloc = *nr_highmem_p;
	else
		*nr_highmem_p = to_alloc;

	safe_highmem_pages = 0;
	while (to_alloc-- > 0) {
		struct page *page;

		page = alloc_page(__GFP_HIGHMEM);
		if (!swsusp_page_is_free(page)) {
			/* The page is "safe", set its bit the bitmap */
			memory_bm_set_bit(bm, page_to_pfn(page));
			safe_highmem_pages++;
		}
		/* Mark the page as allocated */
		swsusp_set_page_forbidden(page);
		swsusp_set_page_free(page);
	}
	memory_bm_position_reset(bm);
	safe_highmem_bm = bm;
	return 0;
}

static struct page *last_highmem_page;

static void *get_highmem_page_buffer(struct page *page,
				     struct chain_allocator *ca)
{
	struct highmem_pbe *pbe;
	void *kaddr;

	if (swsusp_page_is_forbidden(page) && swsusp_page_is_free(page)) {
		/*
		last_highmem_page = page;
		return buffer;
	}
	/*
	pbe = chain_alloc(ca, sizeof(struct highmem_pbe));
	if (!pbe) {
		swsusp_free();
		return ERR_PTR(-ENOMEM);
	}
	pbe->orig_page = page;
	if (safe_highmem_pages > 0) {
		struct page *tmp;

		/* Copy of the page will be stored in high memory */
		kaddr = buffer;
		tmp = pfn_to_page(memory_bm_next_pfn(safe_highmem_bm));
		safe_highmem_pages--;
		last_highmem_page = tmp;
		pbe->copy_page = tmp;
	} else {
		/* Copy of the page will be stored in normal memory */
		kaddr = safe_pages_list;
		safe_pages_list = safe_pages_list->next;
		pbe->copy_page = virt_to_page(kaddr);
	}
	pbe->next = highmem_pblist;
	highmem_pblist = pbe;
	return kaddr;
}

static void copy_last_highmem_page(void)
{
	if (last_highmem_page) {
		void *dst;

		dst = kmap_atomic(last_highmem_page);
		copy_page(dst, buffer);
		kunmap_atomic(dst);
		last_highmem_page = NULL;
	}
}

static inline int last_highmem_page_copied(void)
{
	return !last_highmem_page;
}

static inline void free_highmem_data(void)
{
	if (safe_highmem_bm)
		memory_bm_free(safe_highmem_bm, PG_UNSAFE_CLEAR);

	if (buffer)
		free_image_page(buffer, PG_UNSAFE_CLEAR);
}
#else
static unsigned int count_highmem_image_pages(struct memory_bitmap *bm) { return 0; }

static inline int prepare_highmem_image(struct memory_bitmap *bm,
					unsigned int *nr_highmem_p) { return 0; }

static inline void *get_highmem_page_buffer(struct page *page,
					    struct chain_allocator *ca)
{
	return ERR_PTR(-EINVAL);
}

static inline void copy_last_highmem_page(void) {}
static inline int last_highmem_page_copied(void) { return 1; }
static inline void free_highmem_data(void) {}
#endif /* CONFIG_HIGHMEM */

#define PBES_PER_LINKED_PAGE	(LINKED_PAGE_DATA_SIZE / sizeof(struct pbe))

static int prepare_image(struct memory_bitmap *new_bm, struct memory_bitmap *bm)
{
	unsigned int nr_pages, nr_highmem;
	struct linked_page *lp;
	int error;

	/* If there is no highmem, the buffer will not be necessary */
	free_image_page(buffer, PG_UNSAFE_CLEAR);
	buffer = NULL;

	nr_highmem = count_highmem_image_pages(bm);
	mark_unsafe_pages(bm);

	error = memory_bm_create(new_bm, GFP_ATOMIC, PG_SAFE);
	if (error)
		goto Free;

	duplicate_memory_bitmap(new_bm, bm);
	memory_bm_free(bm, PG_UNSAFE_KEEP);
	if (nr_highmem > 0) {
		error = prepare_highmem_image(bm, &nr_highmem);
		if (error)
			goto Free;
	}
	/*
	nr_pages = nr_copy_pages - nr_highmem - allocated_unsafe_pages;
	nr_pages = DIV_ROUND_UP(nr_pages, PBES_PER_LINKED_PAGE);
	while (nr_pages > 0) {
		lp = get_image_page(GFP_ATOMIC, PG_SAFE);
		if (!lp) {
			error = -ENOMEM;
			goto Free;
		}
		lp->next = safe_pages_list;
		safe_pages_list = lp;
		nr_pages--;
	}
	/* Preallocate memory for the image */
	nr_pages = nr_copy_pages - nr_highmem - allocated_unsafe_pages;
	while (nr_pages > 0) {
		lp = (struct linked_page *)get_zeroed_page(GFP_ATOMIC);
		if (!lp) {
			error = -ENOMEM;
			goto Free;
		}
		if (!swsusp_page_is_free(virt_to_page(lp))) {
			/* The page is "safe", add it to the list */
			lp->next = safe_pages_list;
			safe_pages_list = lp;
		}
		/* Mark the page as allocated */
		swsusp_set_page_forbidden(virt_to_page(lp));
		swsusp_set_page_free(virt_to_page(lp));
		nr_pages--;
	}
	return 0;

 Free:
	swsusp_free();
	return error;
}

static void *get_buffer(struct memory_bitmap *bm, struct chain_allocator *ca)
{
	struct pbe *pbe;
	struct page *page;
	unsigned long pfn = memory_bm_next_pfn(bm);

	if (pfn == BM_END_OF_MAP)
		return ERR_PTR(-EFAULT);

	page = pfn_to_page(pfn);
	if (PageHighMem(page))
		return get_highmem_page_buffer(page, ca);

	if (swsusp_page_is_forbidden(page) && swsusp_page_is_free(page))
		/*
		return page_address(page);

	/*
	pbe = chain_alloc(ca, sizeof(struct pbe));
	if (!pbe) {
		swsusp_free();
		return ERR_PTR(-ENOMEM);
	}
	pbe->orig_address = page_address(page);
	pbe->address = safe_pages_list;
	safe_pages_list = safe_pages_list->next;
	pbe->next = restore_pblist;
	restore_pblist = pbe;
	return pbe->address;
}

int snapshot_write_next(struct snapshot_handle *handle)
{
	static struct chain_allocator ca;
	int error = 0;

	/* Check if we have already loaded the entire image */
	if (handle->cur > 1 && handle->cur > nr_meta_pages + nr_copy_pages)
		return 0;

	handle->sync_read = 1;

	if (!handle->cur) {
		if (!buffer)
			/* This makes the buffer be freed by swsusp_free() */
			buffer = get_image_page(GFP_ATOMIC, PG_ANY);

		if (!buffer)
			return -ENOMEM;

		handle->buffer = buffer;
	} else if (handle->cur == 1) {
		error = load_header(buffer);
		if (error)
			return error;

		safe_pages_list = NULL;

		error = memory_bm_create(&copy_bm, GFP_ATOMIC, PG_ANY);
		if (error)
			return error;

		hibernate_restore_protection_begin();
	} else if (handle->cur <= nr_meta_pages + 1) {
		error = unpack_orig_pfns(buffer, &copy_bm);
		if (error)
			return error;

		if (handle->cur == nr_meta_pages + 1) {
			error = prepare_image(&orig_bm, &copy_bm);
			if (error)
				return error;

			chain_init(&ca, GFP_ATOMIC, PG_SAFE);
			memory_bm_position_reset(&orig_bm);
			restore_pblist = NULL;
			handle->buffer = get_buffer(&orig_bm, &ca);
			handle->sync_read = 0;
			if (IS_ERR(handle->buffer))
				return PTR_ERR(handle->buffer);
		}
	} else {
		copy_last_highmem_page();
		hibernate_restore_protect_page(handle->buffer);
		handle->buffer = get_buffer(&orig_bm, &ca);
		if (IS_ERR(handle->buffer))
			return PTR_ERR(handle->buffer);
		if (handle->buffer != buffer)
			handle->sync_read = 0;
	}
	handle->cur++;
	return PAGE_SIZE;
}

void snapshot_write_finalize(struct snapshot_handle *handle)
{
	copy_last_highmem_page();
	hibernate_restore_protect_page(handle->buffer);
	/* Do that only if we have loaded the image entirely */
	if (handle->cur > 1 && handle->cur > nr_meta_pages + nr_copy_pages) {
		memory_bm_recycle(&orig_bm);
		free_highmem_data();
	}
}

int snapshot_image_loaded(struct snapshot_handle *handle)
{
	return !(!nr_copy_pages || !last_highmem_page_copied() ||
			handle->cur <= nr_meta_pages + nr_copy_pages);
}

#ifdef CONFIG_HIGHMEM
static inline void swap_two_pages_data(struct page *p1, struct page *p2,
				       void *buf)
{
	void *kaddr1, *kaddr2;

	kaddr1 = kmap_atomic(p1);
	kaddr2 = kmap_atomic(p2);
	copy_page(buf, kaddr1);
	copy_page(kaddr1, kaddr2);
	copy_page(kaddr2, buf);
	kunmap_atomic(kaddr2);
	kunmap_atomic(kaddr1);
}

int restore_highmem(void)
{
	struct highmem_pbe *pbe = highmem_pblist;
	void *buf;

	if (!pbe)
		return 0;

	buf = get_image_page(GFP_ATOMIC, PG_SAFE);
	if (!buf)
		return -ENOMEM;

	while (pbe) {
		swap_two_pages_data(pbe->copy_page, pbe->orig_page, buf);
		pbe = pbe->next;
	}
	free_image_page(buf, PG_UNSAFE_CLEAR);
	return 0;
}
#endif /* CONFIG_HIGHMEM */
