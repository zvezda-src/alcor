
#ifndef __KVM_X86_MMU_TDP_ITER_H
#define __KVM_X86_MMU_TDP_ITER_H

#include <linux/kvm_host.h>

#include "mmu.h"
#include "spte.h"

static inline u64 kvm_tdp_mmu_read_spte(tdp_ptep_t sptep)
{
	return READ_ONCE(*rcu_dereference(sptep));
}

static inline u64 kvm_tdp_mmu_write_spte_atomic(tdp_ptep_t sptep, u64 new_spte)
{
	return xchg(rcu_dereference(sptep), new_spte);
}

static inline void __kvm_tdp_mmu_write_spte(tdp_ptep_t sptep, u64 new_spte)
{
	WRITE_ONCE(*rcu_dereference(sptep), new_spte);
}

static inline u64 kvm_tdp_mmu_write_spte(tdp_ptep_t sptep, u64 old_spte,
					 u64 new_spte, int level)
{
	/*
	if (is_shadow_present_pte(old_spte) && is_last_spte(old_spte, level) &&
	    spte_has_volatile_bits(old_spte))
		return kvm_tdp_mmu_write_spte_atomic(sptep, new_spte);

	__kvm_tdp_mmu_write_spte(sptep, new_spte);
	return old_spte;
}

struct tdp_iter {
	/*
	gfn_t next_last_level_gfn;
	/*
	gfn_t yielded_gfn;
	/* Pointers to the page tables traversed to reach the current SPTE */
	tdp_ptep_t pt_path[PT64_ROOT_MAX_LEVEL];
	/* A pointer to the current SPTE */
	tdp_ptep_t sptep;
	/* The lowest GFN mapped by the current SPTE */
	gfn_t gfn;
	/* The level of the root page given to the iterator */
	int root_level;
	/* The lowest level the iterator should traverse to */
	int min_level;
	/* The iterator's current level within the paging structure */
	int level;
	/* The address space ID, i.e. SMM vs. regular. */
	int as_id;
	/* A snapshot of the value at sptep */
	u64 old_spte;
	/*
	bool valid;
	/*
	bool yielded;
};

#define for_each_tdp_pte_min_level(iter, root, min_level, start, end) \
	for (tdp_iter_start(&iter, root, min_level, start); \
	     iter.valid && iter.gfn < end;		     \
	     tdp_iter_next(&iter))

#define for_each_tdp_pte(iter, root, start, end) \
	for_each_tdp_pte_min_level(iter, root, PG_LEVEL_4K, start, end)

tdp_ptep_t spte_to_child_pt(u64 pte, int level);

void tdp_iter_start(struct tdp_iter *iter, struct kvm_mmu_page *root,
		    int min_level, gfn_t next_last_level_gfn);
void tdp_iter_next(struct tdp_iter *iter);
void tdp_iter_restart(struct tdp_iter *iter);

#endif /* __KVM_X86_MMU_TDP_ITER_H */
