
#include <linux/kvm_host.h>
#include <linux/rculist.h>

#include <asm/kvm_page_track.h>

#include "mmu.h"
#include "mmu_internal.h"

bool kvm_page_track_write_tracking_enabled(struct kvm *kvm)
{
	return IS_ENABLED(CONFIG_KVM_EXTERNAL_WRITE_TRACKING) ||
	       !tdp_enabled || kvm_shadow_root_allocated(kvm);
}

void kvm_page_track_free_memslot(struct kvm_memory_slot *slot)
{
	int i;

	for (i = 0; i < KVM_PAGE_TRACK_MAX; i++) {
		kvfree(slot->arch.gfn_track[i]);
		slot->arch.gfn_track[i] = NULL;
	}
}

int kvm_page_track_create_memslot(struct kvm *kvm,
				  struct kvm_memory_slot *slot,
				  unsigned long npages)
{
	int i;

	for (i = 0; i < KVM_PAGE_TRACK_MAX; i++) {
		if (i == KVM_PAGE_TRACK_WRITE &&
		    !kvm_page_track_write_tracking_enabled(kvm))
			continue;

		slot->arch.gfn_track[i] =
			__vcalloc(npages, sizeof(*slot->arch.gfn_track[i]),
				  GFP_KERNEL_ACCOUNT);
		if (!slot->arch.gfn_track[i])
			goto track_free;
	}

	return 0;

track_free:
	kvm_page_track_free_memslot(slot);
	return -ENOMEM;
}

static inline bool page_track_mode_is_valid(enum kvm_page_track_mode mode)
{
	if (mode < 0 || mode >= KVM_PAGE_TRACK_MAX)
		return false;

	return true;
}

int kvm_page_track_write_tracking_alloc(struct kvm_memory_slot *slot)
{
	unsigned short *gfn_track;

	if (slot->arch.gfn_track[KVM_PAGE_TRACK_WRITE])
		return 0;

	gfn_track = __vcalloc(slot->npages, sizeof(*gfn_track),
			      GFP_KERNEL_ACCOUNT);
	if (gfn_track == NULL)
		return -ENOMEM;

	slot->arch.gfn_track[KVM_PAGE_TRACK_WRITE] = gfn_track;
	return 0;
}

static void update_gfn_track(struct kvm_memory_slot *slot, gfn_t gfn,
			     enum kvm_page_track_mode mode, short count)
{
	int index, val;

	index = gfn_to_index(gfn, slot->base_gfn, PG_LEVEL_4K);

	val = slot->arch.gfn_track[mode][index];

	if (WARN_ON(val + count < 0 || val + count > USHRT_MAX))
		return;

	slot->arch.gfn_track[mode][index] += count;
}

void kvm_slot_page_track_add_page(struct kvm *kvm,
				  struct kvm_memory_slot *slot, gfn_t gfn,
				  enum kvm_page_track_mode mode)
{

	if (WARN_ON(!page_track_mode_is_valid(mode)))
		return;

	if (WARN_ON(mode == KVM_PAGE_TRACK_WRITE &&
		    !kvm_page_track_write_tracking_enabled(kvm)))
		return;

	update_gfn_track(slot, gfn, mode, 1);

	/*
	kvm_mmu_gfn_disallow_lpage(slot, gfn);

	if (mode == KVM_PAGE_TRACK_WRITE)
		if (kvm_mmu_slot_gfn_write_protect(kvm, slot, gfn, PG_LEVEL_4K))
			kvm_flush_remote_tlbs(kvm);
}
EXPORT_SYMBOL_GPL(kvm_slot_page_track_add_page);

void kvm_slot_page_track_remove_page(struct kvm *kvm,
				     struct kvm_memory_slot *slot, gfn_t gfn,
				     enum kvm_page_track_mode mode)
{
	if (WARN_ON(!page_track_mode_is_valid(mode)))
		return;

	if (WARN_ON(mode == KVM_PAGE_TRACK_WRITE &&
		    !kvm_page_track_write_tracking_enabled(kvm)))
		return;

	update_gfn_track(slot, gfn, mode, -1);

	/*
	kvm_mmu_gfn_allow_lpage(slot, gfn);
}
EXPORT_SYMBOL_GPL(kvm_slot_page_track_remove_page);

bool kvm_slot_page_track_is_active(struct kvm *kvm,
				   const struct kvm_memory_slot *slot,
				   gfn_t gfn, enum kvm_page_track_mode mode)
{
	int index;

	if (WARN_ON(!page_track_mode_is_valid(mode)))
		return false;

	if (!slot)
		return false;

	if (mode == KVM_PAGE_TRACK_WRITE &&
	    !kvm_page_track_write_tracking_enabled(kvm))
		return false;

	index = gfn_to_index(gfn, slot->base_gfn, PG_LEVEL_4K);
	return !!READ_ONCE(slot->arch.gfn_track[mode][index]);
}

void kvm_page_track_cleanup(struct kvm *kvm)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;
	cleanup_srcu_struct(&head->track_srcu);
}

int kvm_page_track_init(struct kvm *kvm)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;
	INIT_HLIST_HEAD(&head->track_notifier_list);
	return init_srcu_struct(&head->track_srcu);
}

void
kvm_page_track_register_notifier(struct kvm *kvm,
				 struct kvm_page_track_notifier_node *n)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;

	write_lock(&kvm->mmu_lock);
	hlist_add_head_rcu(&n->node, &head->track_notifier_list);
	write_unlock(&kvm->mmu_lock);
}
EXPORT_SYMBOL_GPL(kvm_page_track_register_notifier);

void
kvm_page_track_unregister_notifier(struct kvm *kvm,
				   struct kvm_page_track_notifier_node *n)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;

	write_lock(&kvm->mmu_lock);
	hlist_del_rcu(&n->node);
	write_unlock(&kvm->mmu_lock);
	synchronize_srcu(&head->track_srcu);
}
EXPORT_SYMBOL_GPL(kvm_page_track_unregister_notifier);

void kvm_page_track_write(struct kvm_vcpu *vcpu, gpa_t gpa, const u8 *new,
			  int bytes)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;

	head = &vcpu->kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_srcu(n, &head->track_notifier_list, node,
				srcu_read_lock_held(&head->track_srcu))
		if (n->track_write)
			n->track_write(vcpu, gpa, new, bytes, n);
	srcu_read_unlock(&head->track_srcu, idx);
}

void kvm_page_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;

	head = &kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_srcu(n, &head->track_notifier_list, node,
				srcu_read_lock_held(&head->track_srcu))
		if (n->track_flush_slot)
			n->track_flush_slot(kvm, slot, n);
	srcu_read_unlock(&head->track_srcu, idx);
}
