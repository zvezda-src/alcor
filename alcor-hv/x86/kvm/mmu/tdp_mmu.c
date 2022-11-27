
#include "mmu.h"
#include "mmu_internal.h"
#include "mmutrace.h"
#include "tdp_iter.h"
#include "tdp_mmu.h"
#include "spte.h"

#include <asm/cmpxchg.h>
#include <trace/events/kvm.h>

static bool __read_mostly tdp_mmu_enabled = true;
module_param_named(tdp_mmu, tdp_mmu_enabled, bool, 0644);

int kvm_mmu_init_tdp_mmu(struct kvm *kvm)
{
	struct workqueue_struct *wq;

	if (!tdp_enabled || !READ_ONCE(tdp_mmu_enabled))
		return 0;

	wq = alloc_workqueue("kvm", WQ_UNBOUND|WQ_MEM_RECLAIM|WQ_CPU_INTENSIVE, 0);
	if (!wq)
		return -ENOMEM;

	/* This should not be changed for the lifetime of the VM. */
	kvm->arch.tdp_mmu_enabled = true;
	INIT_LIST_HEAD(&kvm->arch.tdp_mmu_roots);
	spin_lock_init(&kvm->arch.tdp_mmu_pages_lock);
	INIT_LIST_HEAD(&kvm->arch.tdp_mmu_pages);
	kvm->arch.tdp_mmu_zap_wq = wq;
	return 1;
}

static __always_inline bool kvm_lockdep_assert_mmu_lock_held(struct kvm *kvm,
							     bool shared)
{
	if (shared)
		lockdep_assert_held_read(&kvm->mmu_lock);
	else
		lockdep_assert_held_write(&kvm->mmu_lock);

	return true;
}

void kvm_mmu_uninit_tdp_mmu(struct kvm *kvm)
{
	if (!kvm->arch.tdp_mmu_enabled)
		return;

	/* Also waits for any queued work items.  */
	destroy_workqueue(kvm->arch.tdp_mmu_zap_wq);

	WARN_ON(!list_empty(&kvm->arch.tdp_mmu_pages));
	WARN_ON(!list_empty(&kvm->arch.tdp_mmu_roots));

	/*
	rcu_barrier();
}

static void tdp_mmu_free_sp(struct kvm_mmu_page *sp)
{
	free_page((unsigned long)sp->spt);
	kmem_cache_free(mmu_page_header_cache, sp);
}

static void tdp_mmu_free_sp_rcu_callback(struct rcu_head *head)
{
	struct kvm_mmu_page *sp = container_of(head, struct kvm_mmu_page,
					       rcu_head);

	tdp_mmu_free_sp(sp);
}

static void tdp_mmu_zap_root(struct kvm *kvm, struct kvm_mmu_page *root,
			     bool shared);

static void tdp_mmu_zap_root_work(struct work_struct *work)
{
	struct kvm_mmu_page *root = container_of(work, struct kvm_mmu_page,
						 tdp_mmu_async_work);
	struct kvm *kvm = root->tdp_mmu_async_data;

	read_lock(&kvm->mmu_lock);

	/*
	tdp_mmu_zap_root(kvm, root, true);

	/*
	kvm_tdp_mmu_put_root(kvm, root, true);

	read_unlock(&kvm->mmu_lock);
}

static void tdp_mmu_schedule_zap_root(struct kvm *kvm, struct kvm_mmu_page *root)
{
	root->tdp_mmu_async_data = kvm;
	INIT_WORK(&root->tdp_mmu_async_work, tdp_mmu_zap_root_work);
	queue_work(kvm->arch.tdp_mmu_zap_wq, &root->tdp_mmu_async_work);
}

static inline bool kvm_tdp_root_mark_invalid(struct kvm_mmu_page *page)
{
	union kvm_mmu_page_role role = page->role;
	role.invalid = true;

	/* No need to use cmpxchg, only the invalid bit can change.  */
	role.word = xchg(&page->role.word, role.word);
	return role.invalid;
}

void kvm_tdp_mmu_put_root(struct kvm *kvm, struct kvm_mmu_page *root,
			  bool shared)
{
	kvm_lockdep_assert_mmu_lock_held(kvm, shared);

	if (!refcount_dec_and_test(&root->tdp_mmu_root_count))
		return;

	WARN_ON(!root->tdp_mmu_page);

	/*
	if (!kvm_tdp_root_mark_invalid(root)) {
		refcount_set(&root->tdp_mmu_root_count, 1);

		/*
		tdp_mmu_schedule_zap_root(kvm, root);
		return;
	}

	spin_lock(&kvm->arch.tdp_mmu_pages_lock);
	list_del_rcu(&root->link);
	spin_unlock(&kvm->arch.tdp_mmu_pages_lock);
	call_rcu(&root->rcu_head, tdp_mmu_free_sp_rcu_callback);
}

static struct kvm_mmu_page *tdp_mmu_next_root(struct kvm *kvm,
					      struct kvm_mmu_page *prev_root,
					      bool shared, bool only_valid)
{
	struct kvm_mmu_page *next_root;

	rcu_read_lock();

	if (prev_root)
		next_root = list_next_or_null_rcu(&kvm->arch.tdp_mmu_roots,
						  &prev_root->link,
						  typeof(*prev_root), link);
	else
		next_root = list_first_or_null_rcu(&kvm->arch.tdp_mmu_roots,
						   typeof(*next_root), link);

	while (next_root) {
		if ((!only_valid || !next_root->role.invalid) &&
		    kvm_tdp_mmu_get_root(next_root))
			break;

		next_root = list_next_or_null_rcu(&kvm->arch.tdp_mmu_roots,
				&next_root->link, typeof(*next_root), link);
	}

	rcu_read_unlock();

	if (prev_root)
		kvm_tdp_mmu_put_root(kvm, prev_root, shared);

	return next_root;
}

#define __for_each_tdp_mmu_root_yield_safe(_kvm, _root, _as_id, _shared, _only_valid)\
	for (_root = tdp_mmu_next_root(_kvm, NULL, _shared, _only_valid);	\
	     _root;								\
	     _root = tdp_mmu_next_root(_kvm, _root, _shared, _only_valid))	\
		if (kvm_lockdep_assert_mmu_lock_held(_kvm, _shared) &&		\
		    kvm_mmu_page_as_id(_root) != _as_id) {			\
		} else

#define for_each_valid_tdp_mmu_root_yield_safe(_kvm, _root, _as_id, _shared)	\
	__for_each_tdp_mmu_root_yield_safe(_kvm, _root, _as_id, _shared, true)

#define for_each_tdp_mmu_root_yield_safe(_kvm, _root, _as_id)			\
	__for_each_tdp_mmu_root_yield_safe(_kvm, _root, _as_id, false, false)

#define for_each_tdp_mmu_root(_kvm, _root, _as_id)			\
	list_for_each_entry(_root, &_kvm->arch.tdp_mmu_roots, link)	\
		if (kvm_lockdep_assert_mmu_lock_held(_kvm, false) &&	\
		    kvm_mmu_page_as_id(_root) != _as_id) {		\
		} else

static struct kvm_mmu_page *tdp_mmu_alloc_sp(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_page *sp;

	sp = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_page_header_cache);
	sp->spt = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_shadow_page_cache);

	return sp;
}

static void tdp_mmu_init_sp(struct kvm_mmu_page *sp, tdp_ptep_t sptep,
			    gfn_t gfn, union kvm_mmu_page_role role)
{
	set_page_private(virt_to_page(sp->spt), (unsigned long)sp);

	sp->role = role;
	sp->gfn = gfn;
	sp->ptep = sptep;
	sp->tdp_mmu_page = true;

	trace_kvm_mmu_get_page(sp, true);
}

static void tdp_mmu_init_child_sp(struct kvm_mmu_page *child_sp,
				  struct tdp_iter *iter)
{
	struct kvm_mmu_page *parent_sp;
	union kvm_mmu_page_role role;

	parent_sp = sptep_to_sp(rcu_dereference(iter->sptep));

	role = parent_sp->role;
	role.level--;

	tdp_mmu_init_sp(child_sp, iter->sptep, iter->gfn, role);
}

hpa_t kvm_tdp_mmu_get_vcpu_root_hpa(struct kvm_vcpu *vcpu)
{
	union kvm_mmu_page_role role = vcpu->arch.mmu->root_role;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_mmu_page *root;

	lockdep_assert_held_write(&kvm->mmu_lock);

	/*
	for_each_tdp_mmu_root(kvm, root, kvm_mmu_role_as_id(role)) {
		if (root->role.word == role.word &&
		    kvm_tdp_mmu_get_root(root))
			goto out;
	}

	root = tdp_mmu_alloc_sp(vcpu);
	tdp_mmu_init_sp(root, NULL, 0, role);

	refcount_set(&root->tdp_mmu_root_count, 1);

	spin_lock(&kvm->arch.tdp_mmu_pages_lock);
	list_add_rcu(&root->link, &kvm->arch.tdp_mmu_roots);
	spin_unlock(&kvm->arch.tdp_mmu_pages_lock);

out:
	return __pa(root->spt);
}

static void handle_changed_spte(struct kvm *kvm, int as_id, gfn_t gfn,
				u64 old_spte, u64 new_spte, int level,
				bool shared);

static void handle_changed_spte_acc_track(u64 old_spte, u64 new_spte, int level)
{
	if (!is_shadow_present_pte(old_spte) || !is_last_spte(old_spte, level))
		return;

	if (is_accessed_spte(old_spte) &&
	    (!is_shadow_present_pte(new_spte) || !is_accessed_spte(new_spte) ||
	     spte_to_pfn(old_spte) != spte_to_pfn(new_spte)))
		kvm_set_pfn_accessed(spte_to_pfn(old_spte));
}

static void handle_changed_spte_dirty_log(struct kvm *kvm, int as_id, gfn_t gfn,
					  u64 old_spte, u64 new_spte, int level)
{
	bool pfn_changed;
	struct kvm_memory_slot *slot;

	if (level > PG_LEVEL_4K)
		return;

	pfn_changed = spte_to_pfn(old_spte) != spte_to_pfn(new_spte);

	if ((!is_writable_pte(old_spte) || pfn_changed) &&
	    is_writable_pte(new_spte)) {
		slot = __gfn_to_memslot(__kvm_memslots(kvm, as_id), gfn);
		mark_page_dirty_in_slot(kvm, slot, gfn);
	}
}

static void tdp_mmu_unlink_sp(struct kvm *kvm, struct kvm_mmu_page *sp,
			      bool shared)
{
	if (shared)
		spin_lock(&kvm->arch.tdp_mmu_pages_lock);
	else
		lockdep_assert_held_write(&kvm->mmu_lock);

	list_del(&sp->link);
	if (sp->lpage_disallowed)
		unaccount_huge_nx_page(kvm, sp);

	if (shared)
		spin_unlock(&kvm->arch.tdp_mmu_pages_lock);
}

static void handle_removed_pt(struct kvm *kvm, tdp_ptep_t pt, bool shared)
{
	struct kvm_mmu_page *sp = sptep_to_sp(rcu_dereference(pt));
	int level = sp->role.level;
	gfn_t base_gfn = sp->gfn;
	int i;

	trace_kvm_mmu_prepare_zap_page(sp);

	tdp_mmu_unlink_sp(kvm, sp, shared);

	for (i = 0; i < SPTE_ENT_PER_PAGE; i++) {
		tdp_ptep_t sptep = pt + i;
		gfn_t gfn = base_gfn + i * KVM_PAGES_PER_HPAGE(level);
		u64 old_spte;

		if (shared) {
			/*
			for (;;) {
				old_spte = kvm_tdp_mmu_write_spte_atomic(sptep, REMOVED_SPTE);
				if (!is_removed_spte(old_spte))
					break;
				cpu_relax();
			}
		} else {
			/*
			old_spte = kvm_tdp_mmu_read_spte(sptep);
			if (!is_shadow_present_pte(old_spte))
				continue;

			/*
			old_spte = kvm_tdp_mmu_write_spte(sptep, old_spte,
							  REMOVED_SPTE, level);
		}
		handle_changed_spte(kvm, kvm_mmu_page_as_id(sp), gfn,
				    old_spte, REMOVED_SPTE, level, shared);
	}

	call_rcu(&sp->rcu_head, tdp_mmu_free_sp_rcu_callback);
}

static void __handle_changed_spte(struct kvm *kvm, int as_id, gfn_t gfn,
				  u64 old_spte, u64 new_spte, int level,
				  bool shared)
{
	bool was_present = is_shadow_present_pte(old_spte);
	bool is_present = is_shadow_present_pte(new_spte);
	bool was_leaf = was_present && is_last_spte(old_spte, level);
	bool is_leaf = is_present && is_last_spte(new_spte, level);
	bool pfn_changed = spte_to_pfn(old_spte) != spte_to_pfn(new_spte);

	WARN_ON(level > PT64_ROOT_MAX_LEVEL);
	WARN_ON(level < PG_LEVEL_4K);
	WARN_ON(gfn & (KVM_PAGES_PER_HPAGE(level) - 1));

	/*
	if (was_leaf && is_leaf && pfn_changed) {
		pr_err("Invalid SPTE change: cannot replace a present leaf\n"
		       "SPTE with another present leaf SPTE mapping a\n"
		       "different PFN!\n"
		       "as_id: %d gfn: %llx old_spte: %llx new_spte: %llx level: %d",
		       as_id, gfn, old_spte, new_spte, level);

		/*
		BUG();
	}

	if (old_spte == new_spte)
		return;

	trace_kvm_tdp_mmu_spte_changed(as_id, gfn, level, old_spte, new_spte);

	if (is_leaf)
		check_spte_writable_invariants(new_spte);

	/*
	if (!was_present && !is_present) {
		/*
		if (WARN_ON(!is_mmio_spte(old_spte) &&
			    !is_mmio_spte(new_spte) &&
			    !is_removed_spte(new_spte)))
			pr_err("Unexpected SPTE change! Nonpresent SPTEs\n"
			       "should not be replaced with another,\n"
			       "different nonpresent SPTE, unless one or both\n"
			       "are MMIO SPTEs, or the new SPTE is\n"
			       "a temporary removed SPTE.\n"
			       "as_id: %d gfn: %llx old_spte: %llx new_spte: %llx level: %d",
			       as_id, gfn, old_spte, new_spte, level);
		return;
	}

	if (is_leaf != was_leaf)
		kvm_update_page_stats(kvm, level, is_leaf ? 1 : -1);

	if (was_leaf && is_dirty_spte(old_spte) &&
	    (!is_present || !is_dirty_spte(new_spte) || pfn_changed))
		kvm_set_pfn_dirty(spte_to_pfn(old_spte));

	/*
	if (was_present && !was_leaf &&
	    (is_leaf || !is_present || WARN_ON_ONCE(pfn_changed)))
		handle_removed_pt(kvm, spte_to_child_pt(old_spte, level), shared);
}

static void handle_changed_spte(struct kvm *kvm, int as_id, gfn_t gfn,
				u64 old_spte, u64 new_spte, int level,
				bool shared)
{
	__handle_changed_spte(kvm, as_id, gfn, old_spte, new_spte, level,
			      shared);
	handle_changed_spte_acc_track(old_spte, new_spte, level);
	handle_changed_spte_dirty_log(kvm, as_id, gfn, old_spte,
				      new_spte, level);
}

static inline int tdp_mmu_set_spte_atomic(struct kvm *kvm,
					  struct tdp_iter *iter,
					  u64 new_spte)
{
	u64 *sptep = rcu_dereference(iter->sptep);

	/*
	WARN_ON_ONCE(iter->yielded || is_removed_spte(iter->old_spte));

	lockdep_assert_held_read(&kvm->mmu_lock);

	/*
	if (!try_cmpxchg64(sptep, &iter->old_spte, new_spte))
		return -EBUSY;

	__handle_changed_spte(kvm, iter->as_id, iter->gfn, iter->old_spte,
			      new_spte, iter->level, true);
	handle_changed_spte_acc_track(iter->old_spte, new_spte, iter->level);

	return 0;
}

static inline int tdp_mmu_zap_spte_atomic(struct kvm *kvm,
					  struct tdp_iter *iter)
{
	int ret;

	/*
	ret = tdp_mmu_set_spte_atomic(kvm, iter, REMOVED_SPTE);
	if (ret)
		return ret;

	kvm_flush_remote_tlbs_with_address(kvm, iter->gfn,
					   KVM_PAGES_PER_HPAGE(iter->level));

	/*
	__kvm_tdp_mmu_write_spte(iter->sptep, 0);

	return 0;
}


static u64 __tdp_mmu_set_spte(struct kvm *kvm, int as_id, tdp_ptep_t sptep,
			      u64 old_spte, u64 new_spte, gfn_t gfn, int level,
			      bool record_acc_track, bool record_dirty_log)
{
	lockdep_assert_held_write(&kvm->mmu_lock);

	/*
	WARN_ON(is_removed_spte(old_spte) || is_removed_spte(new_spte));

	old_spte = kvm_tdp_mmu_write_spte(sptep, old_spte, new_spte, level);

	__handle_changed_spte(kvm, as_id, gfn, old_spte, new_spte, level, false);

	if (record_acc_track)
		handle_changed_spte_acc_track(old_spte, new_spte, level);
	if (record_dirty_log)
		handle_changed_spte_dirty_log(kvm, as_id, gfn, old_spte,
					      new_spte, level);
	return old_spte;
}

static inline void _tdp_mmu_set_spte(struct kvm *kvm, struct tdp_iter *iter,
				     u64 new_spte, bool record_acc_track,
				     bool record_dirty_log)
{
	WARN_ON_ONCE(iter->yielded);

	iter->old_spte = __tdp_mmu_set_spte(kvm, iter->as_id, iter->sptep,
					    iter->old_spte, new_spte,
					    iter->gfn, iter->level,
					    record_acc_track, record_dirty_log);
}

static inline void tdp_mmu_set_spte(struct kvm *kvm, struct tdp_iter *iter,
				    u64 new_spte)
{
	_tdp_mmu_set_spte(kvm, iter, new_spte, true, true);
}

static inline void tdp_mmu_set_spte_no_acc_track(struct kvm *kvm,
						 struct tdp_iter *iter,
						 u64 new_spte)
{
	_tdp_mmu_set_spte(kvm, iter, new_spte, false, true);
}

static inline void tdp_mmu_set_spte_no_dirty_log(struct kvm *kvm,
						 struct tdp_iter *iter,
						 u64 new_spte)
{
	_tdp_mmu_set_spte(kvm, iter, new_spte, true, false);
}

#define tdp_root_for_each_pte(_iter, _root, _start, _end) \
	for_each_tdp_pte(_iter, _root, _start, _end)

#define tdp_root_for_each_leaf_pte(_iter, _root, _start, _end)	\
	tdp_root_for_each_pte(_iter, _root, _start, _end)		\
		if (!is_shadow_present_pte(_iter.old_spte) ||		\
		    !is_last_spte(_iter.old_spte, _iter.level))		\
			continue;					\
		else

#define tdp_mmu_for_each_pte(_iter, _mmu, _start, _end)		\
	for_each_tdp_pte(_iter, to_shadow_page(_mmu->root.hpa), _start, _end)

static inline bool __must_check tdp_mmu_iter_cond_resched(struct kvm *kvm,
							  struct tdp_iter *iter,
							  bool flush, bool shared)
{
	WARN_ON(iter->yielded);

	/* Ensure forward progress has been made before yielding. */
	if (iter->next_last_level_gfn == iter->yielded_gfn)
		return false;

	if (need_resched() || rwlock_needbreak(&kvm->mmu_lock)) {
		if (flush)
			kvm_flush_remote_tlbs(kvm);

		rcu_read_unlock();

		if (shared)
			cond_resched_rwlock_read(&kvm->mmu_lock);
		else
			cond_resched_rwlock_write(&kvm->mmu_lock);

		rcu_read_lock();

		WARN_ON(iter->gfn > iter->next_last_level_gfn);

		iter->yielded = true;
	}

	return iter->yielded;
}

static inline gfn_t tdp_mmu_max_gfn_exclusive(void)
{
	/*
	return kvm_mmu_max_gfn() + 1;
}

static void __tdp_mmu_zap_root(struct kvm *kvm, struct kvm_mmu_page *root,
			       bool shared, int zap_level)
{
	struct tdp_iter iter;

	gfn_t end = tdp_mmu_max_gfn_exclusive();
	gfn_t start = 0;

	for_each_tdp_pte_min_level(iter, root, zap_level, start, end) {
retry:
		if (tdp_mmu_iter_cond_resched(kvm, &iter, false, shared))
			continue;

		if (!is_shadow_present_pte(iter.old_spte))
			continue;

		if (iter.level > zap_level)
			continue;

		if (!shared)
			tdp_mmu_set_spte(kvm, &iter, 0);
		else if (tdp_mmu_set_spte_atomic(kvm, &iter, 0))
			goto retry;
	}
}

static void tdp_mmu_zap_root(struct kvm *kvm, struct kvm_mmu_page *root,
			     bool shared)
{

	/*
	WARN_ON_ONCE(!refcount_read(&root->tdp_mmu_root_count));

	kvm_lockdep_assert_mmu_lock_held(kvm, shared);

	rcu_read_lock();

	/*
	__tdp_mmu_zap_root(kvm, root, shared, PG_LEVEL_1G);
	__tdp_mmu_zap_root(kvm, root, shared, root->role.level);

	rcu_read_unlock();
}

bool kvm_tdp_mmu_zap_sp(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	u64 old_spte;

	/*
	if (WARN_ON_ONCE(!sp->ptep))
		return false;

	old_spte = kvm_tdp_mmu_read_spte(sp->ptep);
	if (WARN_ON_ONCE(!is_shadow_present_pte(old_spte)))
		return false;

	__tdp_mmu_set_spte(kvm, kvm_mmu_page_as_id(sp), sp->ptep, old_spte, 0,
			   sp->gfn, sp->role.level + 1, true, true);

	return true;
}

static bool tdp_mmu_zap_leafs(struct kvm *kvm, struct kvm_mmu_page *root,
			      gfn_t start, gfn_t end, bool can_yield, bool flush)
{
	struct tdp_iter iter;

	end = min(end, tdp_mmu_max_gfn_exclusive());

	lockdep_assert_held_write(&kvm->mmu_lock);

	rcu_read_lock();

	for_each_tdp_pte_min_level(iter, root, PG_LEVEL_4K, start, end) {
		if (can_yield &&
		    tdp_mmu_iter_cond_resched(kvm, &iter, flush, false)) {
			flush = false;
			continue;
		}

		if (!is_shadow_present_pte(iter.old_spte) ||
		    !is_last_spte(iter.old_spte, iter.level))
			continue;

		tdp_mmu_set_spte(kvm, &iter, 0);
		flush = true;
	}

	rcu_read_unlock();

	/*
	return flush;
}

bool kvm_tdp_mmu_zap_leafs(struct kvm *kvm, int as_id, gfn_t start, gfn_t end,
			   bool can_yield, bool flush)
{
	struct kvm_mmu_page *root;

	for_each_tdp_mmu_root_yield_safe(kvm, root, as_id)
		flush = tdp_mmu_zap_leafs(kvm, root, start, end, can_yield, flush);

	return flush;
}

void kvm_tdp_mmu_zap_all(struct kvm *kvm)
{
	struct kvm_mmu_page *root;
	int i;

	/*
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		for_each_tdp_mmu_root_yield_safe(kvm, root, i)
			tdp_mmu_zap_root(kvm, root, false);
	}
}

void kvm_tdp_mmu_zap_invalidated_roots(struct kvm *kvm)
{
	flush_workqueue(kvm->arch.tdp_mmu_zap_wq);
}

void kvm_tdp_mmu_invalidate_all_roots(struct kvm *kvm)
{
	struct kvm_mmu_page *root;

	lockdep_assert_held_write(&kvm->mmu_lock);
	list_for_each_entry(root, &kvm->arch.tdp_mmu_roots, link) {
		if (!root->role.invalid &&
		    !WARN_ON_ONCE(!kvm_tdp_mmu_get_root(root))) {
			root->role.invalid = true;
			tdp_mmu_schedule_zap_root(kvm, root);
		}
	}
}

static int tdp_mmu_map_handle_target_level(struct kvm_vcpu *vcpu,
					  struct kvm_page_fault *fault,
					  struct tdp_iter *iter)
{
	struct kvm_mmu_page *sp = sptep_to_sp(rcu_dereference(iter->sptep));
	u64 new_spte;
	int ret = RET_PF_FIXED;
	bool wrprot = false;

	WARN_ON(sp->role.level != fault->goal_level);
	if (unlikely(!fault->slot))
		new_spte = make_mmio_spte(vcpu, iter->gfn, ACC_ALL);
	else
		wrprot = make_spte(vcpu, sp, fault->slot, ACC_ALL, iter->gfn,
					 fault->pfn, iter->old_spte, fault->prefetch, true,
					 fault->map_writable, &new_spte);

	if (new_spte == iter->old_spte)
		ret = RET_PF_SPURIOUS;
	else if (tdp_mmu_set_spte_atomic(vcpu->kvm, iter, new_spte))
		return RET_PF_RETRY;
	else if (is_shadow_present_pte(iter->old_spte) &&
		 !is_last_spte(iter->old_spte, iter->level))
		kvm_flush_remote_tlbs_with_address(vcpu->kvm, sp->gfn,
						   KVM_PAGES_PER_HPAGE(iter->level + 1));

	/*
	if (wrprot) {
		if (fault->write)
			ret = RET_PF_EMULATE;
	}

	/* If a MMIO SPTE is installed, the MMIO will need to be emulated. */
	if (unlikely(is_mmio_spte(new_spte))) {
		vcpu->stat.pf_mmio_spte_created++;
		trace_mark_mmio_spte(rcu_dereference(iter->sptep), iter->gfn,
				     new_spte);
		ret = RET_PF_EMULATE;
	} else {
		trace_kvm_mmu_set_spte(iter->level, iter->gfn,
				       rcu_dereference(iter->sptep));
	}

	return ret;
}

static int tdp_mmu_link_sp(struct kvm *kvm, struct tdp_iter *iter,
			   struct kvm_mmu_page *sp, bool account_nx,
			   bool shared)
{
	u64 spte = make_nonleaf_spte(sp->spt, !kvm_ad_enabled());
	int ret = 0;

	if (shared) {
		ret = tdp_mmu_set_spte_atomic(kvm, iter, spte);
		if (ret)
			return ret;
	} else {
		tdp_mmu_set_spte(kvm, iter, spte);
	}

	spin_lock(&kvm->arch.tdp_mmu_pages_lock);
	list_add(&sp->link, &kvm->arch.tdp_mmu_pages);
	if (account_nx)
		account_huge_nx_page(kvm, sp);
	spin_unlock(&kvm->arch.tdp_mmu_pages_lock);

	return 0;
}

int kvm_tdp_mmu_map(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	struct tdp_iter iter;
	struct kvm_mmu_page *sp;
	int ret;

	kvm_mmu_hugepage_adjust(vcpu, fault);

	trace_kvm_mmu_spte_requested(fault);

	rcu_read_lock();

	tdp_mmu_for_each_pte(iter, mmu, fault->gfn, fault->gfn + 1) {
		if (fault->nx_huge_page_workaround_enabled)
			disallowed_hugepage_adjust(fault, iter.old_spte, iter.level);

		if (iter.level == fault->goal_level)
			break;

		/*
		if (is_shadow_present_pte(iter.old_spte) &&
		    is_large_pte(iter.old_spte)) {
			if (tdp_mmu_zap_spte_atomic(vcpu->kvm, &iter))
				break;

			/*
			iter.old_spte = kvm_tdp_mmu_read_spte(iter.sptep);
		}

		if (!is_shadow_present_pte(iter.old_spte)) {
			bool account_nx = fault->huge_page_disallowed &&
					  fault->req_level >= iter.level;

			/*
			if (is_removed_spte(iter.old_spte))
				break;

			sp = tdp_mmu_alloc_sp(vcpu);
			tdp_mmu_init_child_sp(sp, &iter);

			if (tdp_mmu_link_sp(vcpu->kvm, &iter, sp, account_nx, true)) {
				tdp_mmu_free_sp(sp);
				break;
			}
		}
	}

	/*
	if (iter.level != fault->goal_level || is_removed_spte(iter.old_spte)) {
		rcu_read_unlock();
		return RET_PF_RETRY;
	}

	ret = tdp_mmu_map_handle_target_level(vcpu, fault, &iter);
	rcu_read_unlock();

	return ret;
}

bool kvm_tdp_mmu_unmap_gfn_range(struct kvm *kvm, struct kvm_gfn_range *range,
				 bool flush)
{
	return kvm_tdp_mmu_zap_leafs(kvm, range->slot->as_id, range->start,
				     range->end, range->may_block, flush);
}

typedef bool (*tdp_handler_t)(struct kvm *kvm, struct tdp_iter *iter,
			      struct kvm_gfn_range *range);

static __always_inline bool kvm_tdp_mmu_handle_gfn(struct kvm *kvm,
						   struct kvm_gfn_range *range,
						   tdp_handler_t handler)
{
	struct kvm_mmu_page *root;
	struct tdp_iter iter;
	bool ret = false;

	/*
	for_each_tdp_mmu_root(kvm, root, range->slot->as_id) {
		rcu_read_lock();

		tdp_root_for_each_leaf_pte(iter, root, range->start, range->end)
			ret |= handler(kvm, &iter, range);

		rcu_read_unlock();
	}

	return ret;
}

static bool age_gfn_range(struct kvm *kvm, struct tdp_iter *iter,
			  struct kvm_gfn_range *range)
{
	u64 new_spte = 0;

	/* If we have a non-accessed entry we don't need to change the pte. */
	if (!is_accessed_spte(iter->old_spte))
		return false;

	new_spte = iter->old_spte;

	if (spte_ad_enabled(new_spte)) {
		new_spte &= ~shadow_accessed_mask;
	} else {
		/*
		if (is_writable_pte(new_spte))
			kvm_set_pfn_dirty(spte_to_pfn(new_spte));

		new_spte = mark_spte_for_access_track(new_spte);
	}

	tdp_mmu_set_spte_no_acc_track(kvm, iter, new_spte);

	return true;
}

bool kvm_tdp_mmu_age_gfn_range(struct kvm *kvm, struct kvm_gfn_range *range)
{
	return kvm_tdp_mmu_handle_gfn(kvm, range, age_gfn_range);
}

static bool test_age_gfn(struct kvm *kvm, struct tdp_iter *iter,
			 struct kvm_gfn_range *range)
{
	return is_accessed_spte(iter->old_spte);
}

bool kvm_tdp_mmu_test_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	return kvm_tdp_mmu_handle_gfn(kvm, range, test_age_gfn);
}

static bool set_spte_gfn(struct kvm *kvm, struct tdp_iter *iter,
			 struct kvm_gfn_range *range)
{
	u64 new_spte;

	/* Huge pages aren't expected to be modified without first being zapped. */
	WARN_ON(pte_huge(range->pte) || range->start + 1 != range->end);

	if (iter->level != PG_LEVEL_4K ||
	    !is_shadow_present_pte(iter->old_spte))
		return false;

	/*
	tdp_mmu_set_spte(kvm, iter, 0);

	if (!pte_write(range->pte)) {
		new_spte = kvm_mmu_changed_pte_notifier_make_spte(iter->old_spte,
								  pte_pfn(range->pte));

		tdp_mmu_set_spte(kvm, iter, new_spte);
	}

	return true;
}

bool kvm_tdp_mmu_set_spte_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	/*
	return kvm_tdp_mmu_handle_gfn(kvm, range, set_spte_gfn);
}

static bool wrprot_gfn_range(struct kvm *kvm, struct kvm_mmu_page *root,
			     gfn_t start, gfn_t end, int min_level)
{
	struct tdp_iter iter;
	u64 new_spte;
	bool spte_set = false;

	rcu_read_lock();

	BUG_ON(min_level > KVM_MAX_HUGEPAGE_LEVEL);

	for_each_tdp_pte_min_level(iter, root, min_level, start, end) {
retry:
		if (tdp_mmu_iter_cond_resched(kvm, &iter, false, true))
			continue;

		if (!is_shadow_present_pte(iter.old_spte) ||
		    !is_last_spte(iter.old_spte, iter.level) ||
		    !(iter.old_spte & PT_WRITABLE_MASK))
			continue;

		new_spte = iter.old_spte & ~PT_WRITABLE_MASK;

		if (tdp_mmu_set_spte_atomic(kvm, &iter, new_spte))
			goto retry;

		spte_set = true;
	}

	rcu_read_unlock();
	return spte_set;
}

bool kvm_tdp_mmu_wrprot_slot(struct kvm *kvm,
			     const struct kvm_memory_slot *slot, int min_level)
{
	struct kvm_mmu_page *root;
	bool spte_set = false;

	lockdep_assert_held_read(&kvm->mmu_lock);

	for_each_valid_tdp_mmu_root_yield_safe(kvm, root, slot->as_id, true)
		spte_set |= wrprot_gfn_range(kvm, root, slot->base_gfn,
			     slot->base_gfn + slot->npages, min_level);

	return spte_set;
}

static struct kvm_mmu_page *__tdp_mmu_alloc_sp_for_split(gfp_t gfp)
{
	struct kvm_mmu_page *sp;

	gfp |= __GFP_ZERO;

	sp = kmem_cache_alloc(mmu_page_header_cache, gfp);
	if (!sp)
		return NULL;

	sp->spt = (void *)__get_free_page(gfp);
	if (!sp->spt) {
		kmem_cache_free(mmu_page_header_cache, sp);
		return NULL;
	}

	return sp;
}

static struct kvm_mmu_page *tdp_mmu_alloc_sp_for_split(struct kvm *kvm,
						       struct tdp_iter *iter,
						       bool shared)
{
	struct kvm_mmu_page *sp;

	/*
	sp = __tdp_mmu_alloc_sp_for_split(GFP_NOWAIT | __GFP_ACCOUNT);
	if (sp)
		return sp;

	rcu_read_unlock();

	if (shared)
		read_unlock(&kvm->mmu_lock);
	else
		write_unlock(&kvm->mmu_lock);

	iter->yielded = true;
	sp = __tdp_mmu_alloc_sp_for_split(GFP_KERNEL_ACCOUNT);

	if (shared)
		read_lock(&kvm->mmu_lock);
	else
		write_lock(&kvm->mmu_lock);

	rcu_read_lock();

	return sp;
}

static int tdp_mmu_split_huge_page(struct kvm *kvm, struct tdp_iter *iter,
				   struct kvm_mmu_page *sp, bool shared)
{
	const u64 huge_spte = iter->old_spte;
	const int level = iter->level;
	int ret, i;

	tdp_mmu_init_child_sp(sp, iter);

	/*
	for (i = 0; i < SPTE_ENT_PER_PAGE; i++)
		sp->spt[i] = make_huge_page_split_spte(kvm, huge_spte, sp->role, i);

	/*
	ret = tdp_mmu_link_sp(kvm, iter, sp, false, shared);
	if (ret)
		goto out;

	/*
	kvm_update_page_stats(kvm, level - 1, SPTE_ENT_PER_PAGE);

out:
	trace_kvm_mmu_split_huge_page(iter->gfn, huge_spte, level, ret);
	return ret;
}

static int tdp_mmu_split_huge_pages_root(struct kvm *kvm,
					 struct kvm_mmu_page *root,
					 gfn_t start, gfn_t end,
					 int target_level, bool shared)
{
	struct kvm_mmu_page *sp = NULL;
	struct tdp_iter iter;
	int ret = 0;

	rcu_read_lock();

	/*
	for_each_tdp_pte_min_level(iter, root, target_level + 1, start, end) {
retry:
		if (tdp_mmu_iter_cond_resched(kvm, &iter, false, shared))
			continue;

		if (!is_shadow_present_pte(iter.old_spte) || !is_large_pte(iter.old_spte))
			continue;

		if (!sp) {
			sp = tdp_mmu_alloc_sp_for_split(kvm, &iter, shared);
			if (!sp) {
				ret = -ENOMEM;
				trace_kvm_mmu_split_huge_page(iter.gfn,
							      iter.old_spte,
							      iter.level, ret);
				break;
			}

			if (iter.yielded)
				continue;
		}

		if (tdp_mmu_split_huge_page(kvm, &iter, sp, shared))
			goto retry;

		sp = NULL;
	}

	rcu_read_unlock();

	/*
	if (sp)
		tdp_mmu_free_sp(sp);

	return ret;
}


void kvm_tdp_mmu_try_split_huge_pages(struct kvm *kvm,
				      const struct kvm_memory_slot *slot,
				      gfn_t start, gfn_t end,
				      int target_level, bool shared)
{
	struct kvm_mmu_page *root;
	int r = 0;

	kvm_lockdep_assert_mmu_lock_held(kvm, shared);

	for_each_valid_tdp_mmu_root_yield_safe(kvm, root, slot->as_id, shared) {
		r = tdp_mmu_split_huge_pages_root(kvm, root, start, end, target_level, shared);
		if (r) {
			kvm_tdp_mmu_put_root(kvm, root, shared);
			break;
		}
	}
}

static bool clear_dirty_gfn_range(struct kvm *kvm, struct kvm_mmu_page *root,
			   gfn_t start, gfn_t end)
{
	struct tdp_iter iter;
	u64 new_spte;
	bool spte_set = false;

	rcu_read_lock();

	tdp_root_for_each_leaf_pte(iter, root, start, end) {
retry:
		if (tdp_mmu_iter_cond_resched(kvm, &iter, false, true))
			continue;

		if (!is_shadow_present_pte(iter.old_spte))
			continue;

		if (spte_ad_need_write_protect(iter.old_spte)) {
			if (is_writable_pte(iter.old_spte))
				new_spte = iter.old_spte & ~PT_WRITABLE_MASK;
			else
				continue;
		} else {
			if (iter.old_spte & shadow_dirty_mask)
				new_spte = iter.old_spte & ~shadow_dirty_mask;
			else
				continue;
		}

		if (tdp_mmu_set_spte_atomic(kvm, &iter, new_spte))
			goto retry;

		spte_set = true;
	}

	rcu_read_unlock();
	return spte_set;
}

bool kvm_tdp_mmu_clear_dirty_slot(struct kvm *kvm,
				  const struct kvm_memory_slot *slot)
{
	struct kvm_mmu_page *root;
	bool spte_set = false;

	lockdep_assert_held_read(&kvm->mmu_lock);

	for_each_valid_tdp_mmu_root_yield_safe(kvm, root, slot->as_id, true)
		spte_set |= clear_dirty_gfn_range(kvm, root, slot->base_gfn,
				slot->base_gfn + slot->npages);

	return spte_set;
}

static void clear_dirty_pt_masked(struct kvm *kvm, struct kvm_mmu_page *root,
				  gfn_t gfn, unsigned long mask, bool wrprot)
{
	struct tdp_iter iter;
	u64 new_spte;

	rcu_read_lock();

	tdp_root_for_each_leaf_pte(iter, root, gfn + __ffs(mask),
				    gfn + BITS_PER_LONG) {
		if (!mask)
			break;

		if (iter.level > PG_LEVEL_4K ||
		    !(mask & (1UL << (iter.gfn - gfn))))
			continue;

		mask &= ~(1UL << (iter.gfn - gfn));

		if (wrprot || spte_ad_need_write_protect(iter.old_spte)) {
			if (is_writable_pte(iter.old_spte))
				new_spte = iter.old_spte & ~PT_WRITABLE_MASK;
			else
				continue;
		} else {
			if (iter.old_spte & shadow_dirty_mask)
				new_spte = iter.old_spte & ~shadow_dirty_mask;
			else
				continue;
		}

		tdp_mmu_set_spte_no_dirty_log(kvm, &iter, new_spte);
	}

	rcu_read_unlock();
}

void kvm_tdp_mmu_clear_dirty_pt_masked(struct kvm *kvm,
				       struct kvm_memory_slot *slot,
				       gfn_t gfn, unsigned long mask,
				       bool wrprot)
{
	struct kvm_mmu_page *root;

	lockdep_assert_held_write(&kvm->mmu_lock);
	for_each_tdp_mmu_root(kvm, root, slot->as_id)
		clear_dirty_pt_masked(kvm, root, gfn, mask, wrprot);
}

static void zap_collapsible_spte_range(struct kvm *kvm,
				       struct kvm_mmu_page *root,
				       const struct kvm_memory_slot *slot)
{
	gfn_t start = slot->base_gfn;
	gfn_t end = start + slot->npages;
	struct tdp_iter iter;
	int max_mapping_level;

	rcu_read_lock();

	for_each_tdp_pte_min_level(iter, root, PG_LEVEL_2M, start, end) {
retry:
		if (tdp_mmu_iter_cond_resched(kvm, &iter, false, true))
			continue;

		if (iter.level > KVM_MAX_HUGEPAGE_LEVEL ||
		    !is_shadow_present_pte(iter.old_spte))
			continue;

		/*
		if (is_last_spte(iter.old_spte, iter.level))
			continue;

		/*
		if (iter.gfn < start || iter.gfn >= end)
			continue;

		max_mapping_level = kvm_mmu_max_mapping_level(kvm, slot,
							      iter.gfn, PG_LEVEL_NUM);
		if (max_mapping_level < iter.level)
			continue;

		/* Note, a successful atomic zap also does a remote TLB flush. */
		if (tdp_mmu_zap_spte_atomic(kvm, &iter))
			goto retry;
	}

	rcu_read_unlock();
}

void kvm_tdp_mmu_zap_collapsible_sptes(struct kvm *kvm,
				       const struct kvm_memory_slot *slot)
{
	struct kvm_mmu_page *root;

	lockdep_assert_held_read(&kvm->mmu_lock);

	for_each_valid_tdp_mmu_root_yield_safe(kvm, root, slot->as_id, true)
		zap_collapsible_spte_range(kvm, root, slot);
}

static bool write_protect_gfn(struct kvm *kvm, struct kvm_mmu_page *root,
			      gfn_t gfn, int min_level)
{
	struct tdp_iter iter;
	u64 new_spte;
	bool spte_set = false;

	BUG_ON(min_level > KVM_MAX_HUGEPAGE_LEVEL);

	rcu_read_lock();

	for_each_tdp_pte_min_level(iter, root, min_level, gfn, gfn + 1) {
		if (!is_shadow_present_pte(iter.old_spte) ||
		    !is_last_spte(iter.old_spte, iter.level))
			continue;

		new_spte = iter.old_spte &
			~(PT_WRITABLE_MASK | shadow_mmu_writable_mask);

		if (new_spte == iter.old_spte)
			break;

		tdp_mmu_set_spte(kvm, &iter, new_spte);
		spte_set = true;
	}

	rcu_read_unlock();

	return spte_set;
}

bool kvm_tdp_mmu_write_protect_gfn(struct kvm *kvm,
				   struct kvm_memory_slot *slot, gfn_t gfn,
				   int min_level)
{
	struct kvm_mmu_page *root;
	bool spte_set = false;

	lockdep_assert_held_write(&kvm->mmu_lock);
	for_each_tdp_mmu_root(kvm, root, slot->as_id)
		spte_set |= write_protect_gfn(kvm, root, gfn, min_level);

	return spte_set;
}

int kvm_tdp_mmu_get_walk(struct kvm_vcpu *vcpu, u64 addr, u64 *sptes,
			 int *root_level)
{
	struct tdp_iter iter;
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	gfn_t gfn = addr >> PAGE_SHIFT;
	int leaf = -1;


	tdp_mmu_for_each_pte(iter, mmu, gfn, gfn + 1) {
		leaf = iter.level;
		sptes[leaf] = iter.old_spte;
	}

	return leaf;
}

u64 *kvm_tdp_mmu_fast_pf_get_last_sptep(struct kvm_vcpu *vcpu, u64 addr,
					u64 *spte)
{
	struct tdp_iter iter;
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	gfn_t gfn = addr >> PAGE_SHIFT;
	tdp_ptep_t sptep = NULL;

	tdp_mmu_for_each_pte(iter, mmu, gfn, gfn + 1) {
		*spte = iter.old_spte;
		sptep = iter.sptep;
	}

	/*
	return rcu_dereference(sptep);
}
