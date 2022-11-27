
#include "mmu_internal.h"
#include "tdp_iter.h"
#include "spte.h"

static void tdp_iter_refresh_sptep(struct tdp_iter *iter)
{
	iter->sptep = iter->pt_path[iter->level - 1] +
		SPTE_INDEX(iter->gfn << PAGE_SHIFT, iter->level);
	iter->old_spte = kvm_tdp_mmu_read_spte(iter->sptep);
}

static gfn_t round_gfn_for_level(gfn_t gfn, int level)
{
	return gfn & -KVM_PAGES_PER_HPAGE(level);
}

void tdp_iter_restart(struct tdp_iter *iter)
{
	iter->yielded = false;
	iter->yielded_gfn = iter->next_last_level_gfn;
	iter->level = iter->root_level;

	iter->gfn = round_gfn_for_level(iter->next_last_level_gfn, iter->level);
	tdp_iter_refresh_sptep(iter);

	iter->valid = true;
}

void tdp_iter_start(struct tdp_iter *iter, struct kvm_mmu_page *root,
		    int min_level, gfn_t next_last_level_gfn)
{
	int root_level = root->role.level;

	WARN_ON(root_level < 1);
	WARN_ON(root_level > PT64_ROOT_MAX_LEVEL);

	iter->next_last_level_gfn = next_last_level_gfn;
	iter->root_level = root_level;
	iter->min_level = min_level;
	iter->pt_path[iter->root_level - 1] = (tdp_ptep_t)root->spt;
	iter->as_id = kvm_mmu_page_as_id(root);

	tdp_iter_restart(iter);
}

tdp_ptep_t spte_to_child_pt(u64 spte, int level)
{
	/*
	if (!is_shadow_present_pte(spte) || is_last_spte(spte, level))
		return NULL;

	return (tdp_ptep_t)__va(spte_to_pfn(spte) << PAGE_SHIFT);
}

static bool try_step_down(struct tdp_iter *iter)
{
	tdp_ptep_t child_pt;

	if (iter->level == iter->min_level)
		return false;

	/*
	iter->old_spte = kvm_tdp_mmu_read_spte(iter->sptep);

	child_pt = spte_to_child_pt(iter->old_spte, iter->level);
	if (!child_pt)
		return false;

	iter->level--;
	iter->pt_path[iter->level - 1] = child_pt;
	iter->gfn = round_gfn_for_level(iter->next_last_level_gfn, iter->level);
	tdp_iter_refresh_sptep(iter);

	return true;
}

static bool try_step_side(struct tdp_iter *iter)
{
	/*
	if (SPTE_INDEX(iter->gfn << PAGE_SHIFT, iter->level) ==
	    (SPTE_ENT_PER_PAGE - 1))
		return false;

	iter->gfn += KVM_PAGES_PER_HPAGE(iter->level);
	iter->next_last_level_gfn = iter->gfn;
	iter->sptep++;
	iter->old_spte = kvm_tdp_mmu_read_spte(iter->sptep);

	return true;
}

static bool try_step_up(struct tdp_iter *iter)
{
	if (iter->level == iter->root_level)
		return false;

	iter->level++;
	iter->gfn = round_gfn_for_level(iter->gfn, iter->level);
	tdp_iter_refresh_sptep(iter);

	return true;
}

void tdp_iter_next(struct tdp_iter *iter)
{
	if (iter->yielded) {
		tdp_iter_restart(iter);
		return;
	}

	if (try_step_down(iter))
		return;

	do {
		if (try_step_side(iter))
			return;
	} while (try_step_up(iter));
	iter->valid = false;
}

