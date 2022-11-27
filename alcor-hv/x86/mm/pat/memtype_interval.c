
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/interval_tree_generic.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/pgtable.h>

#include <asm/memtype.h>

#include "memtype.h"


static inline u64 interval_start(struct memtype *entry)
{
	return entry->start;
}

static inline u64 interval_end(struct memtype *entry)
{
	return entry->end - 1;
}

INTERVAL_TREE_DEFINE(struct memtype, rb, u64, subtree_max_end,
		     interval_start, interval_end,
		     static, interval)

static struct rb_root_cached memtype_rbroot = RB_ROOT_CACHED;

enum {
	MEMTYPE_EXACT_MATCH	= 0,
	MEMTYPE_END_MATCH	= 1
};

static struct memtype *memtype_match(u64 start, u64 end, int match_type)
{
	struct memtype *entry_match;

	entry_match = interval_iter_first(&memtype_rbroot, start, end-1);

	while (entry_match != NULL && entry_match->start < end) {
		if ((match_type == MEMTYPE_EXACT_MATCH) &&
		    (entry_match->start == start) && (entry_match->end == end))
			return entry_match;

		if ((match_type == MEMTYPE_END_MATCH) &&
		    (entry_match->start < start) && (entry_match->end == end))
			return entry_match;

		entry_match = interval_iter_next(entry_match, start, end-1);
	}

	return NULL; /* Returns NULL if there is no match */
}

static int memtype_check_conflict(u64 start, u64 end,
				  enum page_cache_mode reqtype,
				  enum page_cache_mode *newtype)
{
	struct memtype *entry_match;
	enum page_cache_mode found_type = reqtype;

	entry_match = interval_iter_first(&memtype_rbroot, start, end-1);
	if (entry_match == NULL)
		goto success;

	if (entry_match->type != found_type && newtype == NULL)
		goto failure;

	dprintk("Overlap at 0x%Lx-0x%Lx\n", entry_match->start, entry_match->end);
	found_type = entry_match->type;

	entry_match = interval_iter_next(entry_match, start, end-1);
	while (entry_match) {
		if (entry_match->type != found_type)
			goto failure;

		entry_match = interval_iter_next(entry_match, start, end-1);
	}
success:
	if (newtype)
		*newtype = found_type;

	return 0;

failure:
	pr_info("x86/PAT: %s:%d conflicting memory types %Lx-%Lx %s<->%s\n",
		current->comm, current->pid, start, end,
		cattr_name(found_type), cattr_name(entry_match->type));

	return -EBUSY;
}

int memtype_check_insert(struct memtype *entry_new, enum page_cache_mode *ret_type)
{
	int err = 0;

	err = memtype_check_conflict(entry_new->start, entry_new->end, entry_new->type, ret_type);
	if (err)
		return err;

	if (ret_type)
		entry_new->type = *ret_type;

	interval_insert(entry_new, &memtype_rbroot);
	return 0;
}

struct memtype *memtype_erase(u64 start, u64 end)
{
	struct memtype *entry_old;

	/*
	entry_old = memtype_match(start, end, MEMTYPE_EXACT_MATCH);
	if (!entry_old) {
		entry_old = memtype_match(start, end, MEMTYPE_END_MATCH);
		if (!entry_old)
			return ERR_PTR(-EINVAL);
	}

	if (entry_old->start == start) {
		/* munmap: erase this node */
		interval_remove(entry_old, &memtype_rbroot);
	} else {
		/* mremap: update the end value of this node */
		interval_remove(entry_old, &memtype_rbroot);
		entry_old->end = start;
		interval_insert(entry_old, &memtype_rbroot);

		return NULL;
	}

	return entry_old;
}

struct memtype *memtype_lookup(u64 addr)
{
	return interval_iter_first(&memtype_rbroot, addr, addr + PAGE_SIZE-1);
}

#ifdef CONFIG_DEBUG_FS
int memtype_copy_nth_element(struct memtype *entry_out, loff_t pos)
{
	struct memtype *entry_match;
	int i = 1;

	entry_match = interval_iter_first(&memtype_rbroot, 0, ULONG_MAX);

	while (entry_match && pos != i) {
		entry_match = interval_iter_next(entry_match, 0, ULONG_MAX);
		i++;
	}

	if (entry_match) { /* pos == i */
		*entry_out = *entry_match;
		return 0;
	} else {
		return 1;
	}
}
#endif
