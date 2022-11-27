
#include "irq.h"
#include "ioapic.h"
#include "mmu.h"
#include "mmu_internal.h"
#include "tdp_mmu.h"
#include "x86.h"
#include "kvm_cache_regs.h"
#include "kvm_emulate.h"
#include "cpuid.h"
#include "spte.h"

#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/moduleparam.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>
#include <linux/compiler.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/hash.h>
#include <linux/kern_levels.h>
#include <linux/kthread.h>

#include <asm/page.h>
#include <asm/memtype.h>
#include <asm/cmpxchg.h>
#include <asm/io.h>
#include <asm/set_memory.h>
#include <asm/vmx.h>
#include <asm/kvm_page_track.h>
#include "trace.h"

extern bool itlb_multihit_kvm_mitigation;

int __read_mostly nx_huge_pages = -1;
static uint __read_mostly nx_huge_pages_recovery_period_ms;
#ifdef CONFIG_PREEMPT_RT
static uint __read_mostly nx_huge_pages_recovery_ratio = 0;
#else
static uint __read_mostly nx_huge_pages_recovery_ratio = 60;
#endif

static int set_nx_huge_pages(const char *val, const struct kernel_param *kp);
static int set_nx_huge_pages_recovery_param(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops nx_huge_pages_ops = {
	.set = set_nx_huge_pages,
	.get = param_get_bool,
};

static const struct kernel_param_ops nx_huge_pages_recovery_param_ops = {
	.set = set_nx_huge_pages_recovery_param,
	.get = param_get_uint,
};

module_param_cb(nx_huge_pages, &nx_huge_pages_ops, &nx_huge_pages, 0644);
__MODULE_PARM_TYPE(nx_huge_pages, "bool");
module_param_cb(nx_huge_pages_recovery_ratio, &nx_huge_pages_recovery_param_ops,
		&nx_huge_pages_recovery_ratio, 0644);
__MODULE_PARM_TYPE(nx_huge_pages_recovery_ratio, "uint");
module_param_cb(nx_huge_pages_recovery_period_ms, &nx_huge_pages_recovery_param_ops,
		&nx_huge_pages_recovery_period_ms, 0644);
__MODULE_PARM_TYPE(nx_huge_pages_recovery_period_ms, "uint");

static bool __read_mostly force_flush_and_sync_on_reuse;
module_param_named(flush_on_reuse, force_flush_and_sync_on_reuse, bool, 0644);

bool tdp_enabled = false;

static int max_huge_page_level __read_mostly;
static int tdp_root_level __read_mostly;
static int max_tdp_level __read_mostly;

#ifdef MMU_DEBUG
bool dbg = 0;
module_param(dbg, bool, 0644);
#endif

#define PTE_PREFETCH_NUM		8

#include <trace/events/kvm.h>

#define PTE_LIST_EXT 14

struct pte_list_desc {
	struct pte_list_desc *more;
	/*
	u64 spte_count;
	u64 *sptes[PTE_LIST_EXT];
};

struct kvm_shadow_walk_iterator {
	u64 addr;
	hpa_t shadow_addr;
	u64 *sptep;
	int level;
	unsigned index;
};

#define for_each_shadow_entry_using_root(_vcpu, _root, _addr, _walker)     \
	for (shadow_walk_init_using_root(&(_walker), (_vcpu),              \
					 (_root), (_addr));                \
	     shadow_walk_okay(&(_walker));			           \
	     shadow_walk_next(&(_walker)))

#define for_each_shadow_entry(_vcpu, _addr, _walker)            \
	for (shadow_walk_init(&(_walker), _vcpu, _addr);	\
	     shadow_walk_okay(&(_walker));			\
	     shadow_walk_next(&(_walker)))

#define for_each_shadow_entry_lockless(_vcpu, _addr, _walker, spte)	\
	for (shadow_walk_init(&(_walker), _vcpu, _addr);		\
	     shadow_walk_okay(&(_walker)) &&				\
		({ spte = mmu_spte_get_lockless(_walker.sptep); 1; });	\
	     __shadow_walk_next(&(_walker), spte))

static struct kmem_cache *pte_list_desc_cache;
struct kmem_cache *mmu_page_header_cache;
static struct percpu_counter kvm_total_used_mmu_pages;

static void mmu_spte_set(u64 *sptep, u64 spte);

struct kvm_mmu_role_regs {
	const unsigned long cr0;
	const unsigned long cr4;
	const u64 efer;
};

#define CREATE_TRACE_POINTS
#include "mmutrace.h"

#define BUILD_MMU_ROLE_REGS_ACCESSOR(reg, name, flag)			\
static inline bool __maybe_unused					\
____is_##reg##_##name(const struct kvm_mmu_role_regs *regs)		\
{									\
	return !!(regs->reg & flag);					\
}
BUILD_MMU_ROLE_REGS_ACCESSOR(cr0, pg, X86_CR0_PG);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr0, wp, X86_CR0_WP);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, pse, X86_CR4_PSE);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, pae, X86_CR4_PAE);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, smep, X86_CR4_SMEP);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, smap, X86_CR4_SMAP);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, pke, X86_CR4_PKE);
BUILD_MMU_ROLE_REGS_ACCESSOR(cr4, la57, X86_CR4_LA57);
BUILD_MMU_ROLE_REGS_ACCESSOR(efer, nx, EFER_NX);
BUILD_MMU_ROLE_REGS_ACCESSOR(efer, lma, EFER_LMA);

#define BUILD_MMU_ROLE_ACCESSOR(base_or_ext, reg, name)		\
static inline bool __maybe_unused is_##reg##_##name(struct kvm_mmu *mmu)	\
{								\
	return !!(mmu->cpu_role. base_or_ext . reg##_##name);	\
}
BUILD_MMU_ROLE_ACCESSOR(base, cr0, wp);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, pse);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, smep);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, smap);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, pke);
BUILD_MMU_ROLE_ACCESSOR(ext,  cr4, la57);
BUILD_MMU_ROLE_ACCESSOR(base, efer, nx);
BUILD_MMU_ROLE_ACCESSOR(ext,  efer, lma);

static inline bool is_cr0_pg(struct kvm_mmu *mmu)
{
        return mmu->cpu_role.base.level > 0;
}

static inline bool is_cr4_pae(struct kvm_mmu *mmu)
{
        return !mmu->cpu_role.base.has_4_byte_gpte;
}

static struct kvm_mmu_role_regs vcpu_to_role_regs(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_role_regs regs = {
		.cr0 = kvm_read_cr0_bits(vcpu, KVM_MMU_CR0_ROLE_BITS),
		.cr4 = kvm_read_cr4_bits(vcpu, KVM_MMU_CR4_ROLE_BITS),
		.efer = vcpu->arch.efer,
	};

	return regs;
}

static inline bool kvm_available_flush_tlb_with_range(void)
{
	return kvm_x86_ops.tlb_remote_flush_with_range;
}

static void kvm_flush_remote_tlbs_with_range(struct kvm *kvm,
		struct kvm_tlb_range *range)
{
	int ret = -ENOTSUPP;

	if (range && kvm_x86_ops.tlb_remote_flush_with_range)
		ret = static_call(kvm_x86_tlb_remote_flush_with_range)(kvm, range);

	if (ret)
		kvm_flush_remote_tlbs(kvm);
}

void kvm_flush_remote_tlbs_with_address(struct kvm *kvm,
		u64 start_gfn, u64 pages)
{
	struct kvm_tlb_range range;

	range.start_gfn = start_gfn;
	range.pages = pages;

	kvm_flush_remote_tlbs_with_range(kvm, &range);
}

static void mark_mmio_spte(struct kvm_vcpu *vcpu, u64 *sptep, u64 gfn,
			   unsigned int access)
{
	u64 spte = make_mmio_spte(vcpu, gfn, access);

	trace_mark_mmio_spte(sptep, gfn, spte);
	mmu_spte_set(sptep, spte);
}

static gfn_t get_mmio_spte_gfn(u64 spte)
{
	u64 gpa = spte & shadow_nonpresent_or_rsvd_lower_gfn_mask;

	gpa |= (spte >> SHADOW_NONPRESENT_OR_RSVD_MASK_LEN)
	       & shadow_nonpresent_or_rsvd_mask;

	return gpa >> PAGE_SHIFT;
}

static unsigned get_mmio_spte_access(u64 spte)
{
	return spte & shadow_mmio_access_mask;
}

static bool check_mmio_spte(struct kvm_vcpu *vcpu, u64 spte)
{
	u64 kvm_gen, spte_gen, gen;

	gen = kvm_vcpu_memslots(vcpu)->generation;
	if (unlikely(gen & KVM_MEMSLOT_GEN_UPDATE_IN_PROGRESS))
		return false;

	kvm_gen = gen & MMIO_SPTE_GEN_MASK;
	spte_gen = get_mmio_spte_generation(spte);

	trace_check_mmio_spte(spte, kvm_gen, spte_gen);
	return likely(kvm_gen == spte_gen);
}

static int is_cpuid_PSE36(void)
{
	return 1;
}

#ifdef CONFIG_X86_64
static void __set_spte(u64 *sptep, u64 spte)
{
	WRITE_ONCE(*sptep, spte);
}

static void __update_clear_spte_fast(u64 *sptep, u64 spte)
{
	WRITE_ONCE(*sptep, spte);
}

static u64 __update_clear_spte_slow(u64 *sptep, u64 spte)
{
	return xchg(sptep, spte);
}

static u64 __get_spte_lockless(u64 *sptep)
{
	return READ_ONCE(*sptep);
}
#else
union split_spte {
	struct {
		u32 spte_low;
		u32 spte_high;
	};
	u64 spte;
};

static void count_spte_clear(u64 *sptep, u64 spte)
{
	struct kvm_mmu_page *sp =  sptep_to_sp(sptep);

	if (is_shadow_present_pte(spte))
		return;

	/* Ensure the spte is completely set before we increase the count */
	smp_wmb();
	sp->clear_spte_count++;
}

static void __set_spte(u64 *sptep, u64 spte)
{
	union split_spte *ssptep, sspte;

	ssptep = (union split_spte *)sptep;
	sspte = (union split_spte)spte;

	ssptep->spte_high = sspte.spte_high;

	/*
	smp_wmb();

	WRITE_ONCE(ssptep->spte_low, sspte.spte_low);
}

static void __update_clear_spte_fast(u64 *sptep, u64 spte)
{
	union split_spte *ssptep, sspte;

	ssptep = (union split_spte *)sptep;
	sspte = (union split_spte)spte;

	WRITE_ONCE(ssptep->spte_low, sspte.spte_low);

	/*
	smp_wmb();

	ssptep->spte_high = sspte.spte_high;
	count_spte_clear(sptep, spte);
}

static u64 __update_clear_spte_slow(u64 *sptep, u64 spte)
{
	union split_spte *ssptep, sspte, orig;

	ssptep = (union split_spte *)sptep;
	sspte = (union split_spte)spte;

	/* xchg acts as a barrier before the setting of the high bits */
	orig.spte_low = xchg(&ssptep->spte_low, sspte.spte_low);
	orig.spte_high = ssptep->spte_high;
	ssptep->spte_high = sspte.spte_high;
	count_spte_clear(sptep, spte);

	return orig.spte;
}

static u64 __get_spte_lockless(u64 *sptep)
{
	struct kvm_mmu_page *sp =  sptep_to_sp(sptep);
	union split_spte spte, *orig = (union split_spte *)sptep;
	int count;

retry:
	count = sp->clear_spte_count;
	smp_rmb();

	spte.spte_low = orig->spte_low;
	smp_rmb();

	spte.spte_high = orig->spte_high;
	smp_rmb();

	if (unlikely(spte.spte_low != orig->spte_low ||
	      count != sp->clear_spte_count))
		goto retry;

	return spte.spte;
}
#endif

static void mmu_spte_set(u64 *sptep, u64 new_spte)
{
	WARN_ON(is_shadow_present_pte(*sptep));
	__set_spte(sptep, new_spte);
}

static u64 mmu_spte_update_no_track(u64 *sptep, u64 new_spte)
{
	u64 old_spte = *sptep;

	WARN_ON(!is_shadow_present_pte(new_spte));
	check_spte_writable_invariants(new_spte);

	if (!is_shadow_present_pte(old_spte)) {
		mmu_spte_set(sptep, new_spte);
		return old_spte;
	}

	if (!spte_has_volatile_bits(old_spte))
		__update_clear_spte_fast(sptep, new_spte);
	else
		old_spte = __update_clear_spte_slow(sptep, new_spte);

	WARN_ON(spte_to_pfn(old_spte) != spte_to_pfn(new_spte));

	return old_spte;
}

static bool mmu_spte_update(u64 *sptep, u64 new_spte)
{
	bool flush = false;
	u64 old_spte = mmu_spte_update_no_track(sptep, new_spte);

	if (!is_shadow_present_pte(old_spte))
		return false;

	/*
	if (is_mmu_writable_spte(old_spte) &&
	      !is_writable_pte(new_spte))
		flush = true;

	/*

	if (is_accessed_spte(old_spte) && !is_accessed_spte(new_spte)) {
		flush = true;
		kvm_set_pfn_accessed(spte_to_pfn(old_spte));
	}

	if (is_dirty_spte(old_spte) && !is_dirty_spte(new_spte)) {
		flush = true;
		kvm_set_pfn_dirty(spte_to_pfn(old_spte));
	}

	return flush;
}

static u64 mmu_spte_clear_track_bits(struct kvm *kvm, u64 *sptep)
{
	kvm_pfn_t pfn;
	u64 old_spte = *sptep;
	int level = sptep_to_sp(sptep)->role.level;
	struct page *page;

	if (!is_shadow_present_pte(old_spte) ||
	    !spte_has_volatile_bits(old_spte))
		__update_clear_spte_fast(sptep, 0ull);
	else
		old_spte = __update_clear_spte_slow(sptep, 0ull);

	if (!is_shadow_present_pte(old_spte))
		return old_spte;

	kvm_update_page_stats(kvm, level, -1);

	pfn = spte_to_pfn(old_spte);

	/*
	page = kvm_pfn_to_refcounted_page(pfn);
	WARN_ON(page && !page_count(page));

	if (is_accessed_spte(old_spte))
		kvm_set_pfn_accessed(pfn);

	if (is_dirty_spte(old_spte))
		kvm_set_pfn_dirty(pfn);

	return old_spte;
}

static void mmu_spte_clear_no_track(u64 *sptep)
{
	__update_clear_spte_fast(sptep, 0ull);
}

static u64 mmu_spte_get_lockless(u64 *sptep)
{
	return __get_spte_lockless(sptep);
}

static bool mmu_spte_age(u64 *sptep)
{
	u64 spte = mmu_spte_get_lockless(sptep);

	if (!is_accessed_spte(spte))
		return false;

	if (spte_ad_enabled(spte)) {
		clear_bit((ffs(shadow_accessed_mask) - 1),
			  (unsigned long *)sptep);
	} else {
		/*
		if (is_writable_pte(spte))
			kvm_set_pfn_dirty(spte_to_pfn(spte));

		spte = mark_spte_for_access_track(spte);
		mmu_spte_update_no_track(sptep, spte);
	}

	return true;
}

static void walk_shadow_page_lockless_begin(struct kvm_vcpu *vcpu)
{
	if (is_tdp_mmu(vcpu->arch.mmu)) {
		kvm_tdp_mmu_walk_lockless_begin();
	} else {
		/*
		local_irq_disable();

		/*
		smp_store_mb(vcpu->mode, READING_SHADOW_PAGE_TABLES);
	}
}

static void walk_shadow_page_lockless_end(struct kvm_vcpu *vcpu)
{
	if (is_tdp_mmu(vcpu->arch.mmu)) {
		kvm_tdp_mmu_walk_lockless_end();
	} else {
		/*
		smp_store_release(&vcpu->mode, OUTSIDE_GUEST_MODE);
		local_irq_enable();
	}
}

static int mmu_topup_memory_caches(struct kvm_vcpu *vcpu, bool maybe_indirect)
{
	int r;

	/* 1 rmap, 1 parent PTE per level, and the prefetched rmaps. */
	r = kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_pte_list_desc_cache,
				       1 + PT64_ROOT_MAX_LEVEL + PTE_PREFETCH_NUM);
	if (r)
		return r;
	r = kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_shadow_page_cache,
				       PT64_ROOT_MAX_LEVEL);
	if (r)
		return r;
	if (maybe_indirect) {
		r = kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_shadowed_info_cache,
					       PT64_ROOT_MAX_LEVEL);
		if (r)
			return r;
	}
	return kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_page_header_cache,
					  PT64_ROOT_MAX_LEVEL);
}

static void mmu_free_memory_caches(struct kvm_vcpu *vcpu)
{
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_pte_list_desc_cache);
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_shadow_page_cache);
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_shadowed_info_cache);
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_page_header_cache);
}

static void mmu_free_pte_list_desc(struct pte_list_desc *pte_list_desc)
{
	kmem_cache_free(pte_list_desc_cache, pte_list_desc);
}

static bool sp_has_gptes(struct kvm_mmu_page *sp);

static gfn_t kvm_mmu_page_get_gfn(struct kvm_mmu_page *sp, int index)
{
	if (sp->role.passthrough)
		return sp->gfn;

	if (!sp->role.direct)
		return sp->shadowed_translation[index] >> PAGE_SHIFT;

	return sp->gfn + (index << ((sp->role.level - 1) * SPTE_LEVEL_BITS));
}

static u32 kvm_mmu_page_get_access(struct kvm_mmu_page *sp, int index)
{
	if (sp_has_gptes(sp))
		return sp->shadowed_translation[index] & ACC_ALL;

	/*
	return sp->role.access;
}

static void kvm_mmu_page_set_translation(struct kvm_mmu_page *sp, int index,
					 gfn_t gfn, unsigned int access)
{
	if (sp_has_gptes(sp)) {
		sp->shadowed_translation[index] = (gfn << PAGE_SHIFT) | access;
		return;
	}

	WARN_ONCE(access != kvm_mmu_page_get_access(sp, index),
	          "access mismatch under %s page %llx (expected %u, got %u)\n",
	          sp->role.passthrough ? "passthrough" : "direct",
	          sp->gfn, kvm_mmu_page_get_access(sp, index), access);

	WARN_ONCE(gfn != kvm_mmu_page_get_gfn(sp, index),
	          "gfn mismatch under %s page %llx (expected %llx, got %llx)\n",
	          sp->role.passthrough ? "passthrough" : "direct",
	          sp->gfn, kvm_mmu_page_get_gfn(sp, index), gfn);
}

static void kvm_mmu_page_set_access(struct kvm_mmu_page *sp, int index,
				    unsigned int access)
{
	gfn_t gfn = kvm_mmu_page_get_gfn(sp, index);

	kvm_mmu_page_set_translation(sp, index, gfn, access);
}

static struct kvm_lpage_info *lpage_info_slot(gfn_t gfn,
		const struct kvm_memory_slot *slot, int level)
{
	unsigned long idx;

	idx = gfn_to_index(gfn, slot->base_gfn, level);
	return &slot->arch.lpage_info[level - 2][idx];
}

static void update_gfn_disallow_lpage_count(const struct kvm_memory_slot *slot,
					    gfn_t gfn, int count)
{
	struct kvm_lpage_info *linfo;
	int i;

	for (i = PG_LEVEL_2M; i <= KVM_MAX_HUGEPAGE_LEVEL; ++i) {
		linfo = lpage_info_slot(gfn, slot, i);
		linfo->disallow_lpage += count;
		WARN_ON(linfo->disallow_lpage < 0);
	}
}

void kvm_mmu_gfn_disallow_lpage(const struct kvm_memory_slot *slot, gfn_t gfn)
{
	update_gfn_disallow_lpage_count(slot, gfn, 1);
}

void kvm_mmu_gfn_allow_lpage(const struct kvm_memory_slot *slot, gfn_t gfn)
{
	update_gfn_disallow_lpage_count(slot, gfn, -1);
}

static void account_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	gfn_t gfn;

	kvm->arch.indirect_shadow_pages++;
	gfn = sp->gfn;
	slots = kvm_memslots_for_spte_role(kvm, sp->role);
	slot = __gfn_to_memslot(slots, gfn);

	/* the non-leaf shadow pages are keeping readonly. */
	if (sp->role.level > PG_LEVEL_4K)
		return kvm_slot_page_track_add_page(kvm, slot, gfn,
						    KVM_PAGE_TRACK_WRITE);

	kvm_mmu_gfn_disallow_lpage(slot, gfn);

	if (kvm_mmu_slot_gfn_write_protect(kvm, slot, gfn, PG_LEVEL_4K))
		kvm_flush_remote_tlbs_with_address(kvm, gfn, 1);
}

void account_huge_nx_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	if (sp->lpage_disallowed)
		return;

	++kvm->stat.nx_lpage_splits;
	list_add_tail(&sp->lpage_disallowed_link,
		      &kvm->arch.lpage_disallowed_mmu_pages);
	sp->lpage_disallowed = true;
}

static void unaccount_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	gfn_t gfn;

	kvm->arch.indirect_shadow_pages--;
	gfn = sp->gfn;
	slots = kvm_memslots_for_spte_role(kvm, sp->role);
	slot = __gfn_to_memslot(slots, gfn);
	if (sp->role.level > PG_LEVEL_4K)
		return kvm_slot_page_track_remove_page(kvm, slot, gfn,
						       KVM_PAGE_TRACK_WRITE);

	kvm_mmu_gfn_allow_lpage(slot, gfn);
}

void unaccount_huge_nx_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	--kvm->stat.nx_lpage_splits;
	sp->lpage_disallowed = false;
	list_del(&sp->lpage_disallowed_link);
}

static struct kvm_memory_slot *
gfn_to_memslot_dirty_bitmap(struct kvm_vcpu *vcpu, gfn_t gfn,
			    bool no_dirty_log)
{
	struct kvm_memory_slot *slot;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return NULL;
	if (no_dirty_log && kvm_slot_dirty_track_enabled(slot))
		return NULL;

	return slot;
}


static int pte_list_add(struct kvm_mmu_memory_cache *cache, u64 *spte,
			struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	int count = 0;

	if (!rmap_head->val) {
		rmap_printk("%p %llx 0->1\n", spte, *spte);
		rmap_head->val = (unsigned long)spte;
	} else if (!(rmap_head->val & 1)) {
		rmap_printk("%p %llx 1->many\n", spte, *spte);
		desc = kvm_mmu_memory_cache_alloc(cache);
		desc->sptes[0] = (u64 *)rmap_head->val;
		desc->sptes[1] = spte;
		desc->spte_count = 2;
		rmap_head->val = (unsigned long)desc | 1;
		++count;
	} else {
		rmap_printk("%p %llx many->many\n", spte, *spte);
		desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);
		while (desc->spte_count == PTE_LIST_EXT) {
			count += PTE_LIST_EXT;
			if (!desc->more) {
				desc->more = kvm_mmu_memory_cache_alloc(cache);
				desc = desc->more;
				desc->spte_count = 0;
				break;
			}
			desc = desc->more;
		}
		count += desc->spte_count;
		desc->sptes[desc->spte_count++] = spte;
	}
	return count;
}

static void
pte_list_desc_remove_entry(struct kvm_rmap_head *rmap_head,
			   struct pte_list_desc *desc, int i,
			   struct pte_list_desc *prev_desc)
{
	int j = desc->spte_count - 1;

	desc->sptes[i] = desc->sptes[j];
	desc->sptes[j] = NULL;
	desc->spte_count--;
	if (desc->spte_count)
		return;
	if (!prev_desc && !desc->more)
		rmap_head->val = 0;
	else
		if (prev_desc)
			prev_desc->more = desc->more;
		else
			rmap_head->val = (unsigned long)desc->more | 1;
	mmu_free_pte_list_desc(desc);
}

static void pte_list_remove(u64 *spte, struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	struct pte_list_desc *prev_desc;
	int i;

	if (!rmap_head->val) {
		pr_err("%s: %p 0->BUG\n", __func__, spte);
		BUG();
	} else if (!(rmap_head->val & 1)) {
		rmap_printk("%p 1->0\n", spte);
		if ((u64 *)rmap_head->val != spte) {
			pr_err("%s:  %p 1->BUG\n", __func__, spte);
			BUG();
		}
		rmap_head->val = 0;
	} else {
		rmap_printk("%p many->many\n", spte);
		desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);
		prev_desc = NULL;
		while (desc) {
			for (i = 0; i < desc->spte_count; ++i) {
				if (desc->sptes[i] == spte) {
					pte_list_desc_remove_entry(rmap_head,
							desc, i, prev_desc);
					return;
				}
			}
			prev_desc = desc;
			desc = desc->more;
		}
		pr_err("%s: %p many->many\n", __func__, spte);
		BUG();
	}
}

static void kvm_zap_one_rmap_spte(struct kvm *kvm,
				  struct kvm_rmap_head *rmap_head, u64 *sptep)
{
	mmu_spte_clear_track_bits(kvm, sptep);
	pte_list_remove(sptep, rmap_head);
}

static bool kvm_zap_all_rmap_sptes(struct kvm *kvm,
				   struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc, *next;
	int i;

	if (!rmap_head->val)
		return false;

	if (!(rmap_head->val & 1)) {
		mmu_spte_clear_track_bits(kvm, (u64 *)rmap_head->val);
		goto out;
	}

	desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);

	for (; desc; desc = next) {
		for (i = 0; i < desc->spte_count; i++)
			mmu_spte_clear_track_bits(kvm, desc->sptes[i]);
		next = desc->more;
		mmu_free_pte_list_desc(desc);
	}
out:
	/* rmap_head is meaningless now, remember to reset it */
	rmap_head->val = 0;
	return true;
}

unsigned int pte_list_count(struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	unsigned int count = 0;

	if (!rmap_head->val)
		return 0;
	else if (!(rmap_head->val & 1))
		return 1;

	desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);

	while (desc) {
		count += desc->spte_count;
		desc = desc->more;
	}

	return count;
}

static struct kvm_rmap_head *gfn_to_rmap(gfn_t gfn, int level,
					 const struct kvm_memory_slot *slot)
{
	unsigned long idx;

	idx = gfn_to_index(gfn, slot->base_gfn, level);
	return &slot->arch.rmap[level - PG_LEVEL_4K][idx];
}

static bool rmap_can_add(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_memory_cache *mc;

	mc = &vcpu->arch.mmu_pte_list_desc_cache;
	return kvm_mmu_memory_cache_nr_free_objects(mc);
}

static void rmap_remove(struct kvm *kvm, u64 *spte)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	struct kvm_mmu_page *sp;
	gfn_t gfn;
	struct kvm_rmap_head *rmap_head;

	sp = sptep_to_sp(spte);
	gfn = kvm_mmu_page_get_gfn(sp, spte_index(spte));

	/*
	slots = kvm_memslots_for_spte_role(kvm, sp->role);

	slot = __gfn_to_memslot(slots, gfn);
	rmap_head = gfn_to_rmap(gfn, sp->role.level, slot);

	pte_list_remove(spte, rmap_head);
}

struct rmap_iterator {
	/* private fields */
	struct pte_list_desc *desc;	/* holds the sptep if not NULL */
	int pos;			/* index of the sptep */
};

static u64 *rmap_get_first(struct kvm_rmap_head *rmap_head,
			   struct rmap_iterator *iter)
{
	u64 *sptep;

	if (!rmap_head->val)
		return NULL;

	if (!(rmap_head->val & 1)) {
		iter->desc = NULL;
		sptep = (u64 *)rmap_head->val;
		goto out;
	}

	iter->desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);
	iter->pos = 0;
	sptep = iter->desc->sptes[iter->pos];
out:
	BUG_ON(!is_shadow_present_pte(*sptep));
	return sptep;
}

static u64 *rmap_get_next(struct rmap_iterator *iter)
{
	u64 *sptep;

	if (iter->desc) {
		if (iter->pos < PTE_LIST_EXT - 1) {
			++iter->pos;
			sptep = iter->desc->sptes[iter->pos];
			if (sptep)
				goto out;
		}

		iter->desc = iter->desc->more;

		if (iter->desc) {
			iter->pos = 0;
			/* desc->sptes[0] cannot be NULL */
			sptep = iter->desc->sptes[iter->pos];
			goto out;
		}
	}

	return NULL;
out:
	BUG_ON(!is_shadow_present_pte(*sptep));
	return sptep;
}

#define for_each_rmap_spte(_rmap_head_, _iter_, _spte_)			\
	for (_spte_ = rmap_get_first(_rmap_head_, _iter_);		\
	     _spte_; _spte_ = rmap_get_next(_iter_))

static void drop_spte(struct kvm *kvm, u64 *sptep)
{
	u64 old_spte = mmu_spte_clear_track_bits(kvm, sptep);

	if (is_shadow_present_pte(old_spte))
		rmap_remove(kvm, sptep);
}

static void drop_large_spte(struct kvm *kvm, u64 *sptep, bool flush)
{
	struct kvm_mmu_page *sp;

	sp = sptep_to_sp(sptep);
	WARN_ON(sp->role.level == PG_LEVEL_4K);

	drop_spte(kvm, sptep);

	if (flush)
		kvm_flush_remote_tlbs_with_address(kvm, sp->gfn,
			KVM_PAGES_PER_HPAGE(sp->role.level));
}

static bool spte_write_protect(u64 *sptep, bool pt_protect)
{
	u64 spte = *sptep;

	if (!is_writable_pte(spte) &&
	    !(pt_protect && is_mmu_writable_spte(spte)))
		return false;

	rmap_printk("spte %p %llx\n", sptep, *sptep);

	if (pt_protect)
		spte &= ~shadow_mmu_writable_mask;
	spte = spte & ~PT_WRITABLE_MASK;

	return mmu_spte_update(sptep, spte);
}

static bool rmap_write_protect(struct kvm_rmap_head *rmap_head,
			       bool pt_protect)
{
	u64 *sptep;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(rmap_head, &iter, sptep)
		flush |= spte_write_protect(sptep, pt_protect);

	return flush;
}

static bool spte_clear_dirty(u64 *sptep)
{
	u64 spte = *sptep;

	rmap_printk("spte %p %llx\n", sptep, *sptep);

	MMU_WARN_ON(!spte_ad_enabled(spte));
	spte &= ~shadow_dirty_mask;
	return mmu_spte_update(sptep, spte);
}

static bool spte_wrprot_for_clear_dirty(u64 *sptep)
{
	bool was_writable = test_and_clear_bit(PT_WRITABLE_SHIFT,
					       (unsigned long *)sptep);
	if (was_writable && !spte_ad_enabled(*sptep))
		kvm_set_pfn_dirty(spte_to_pfn(*sptep));

	return was_writable;
}

static bool __rmap_clear_dirty(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			       const struct kvm_memory_slot *slot)
{
	u64 *sptep;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(rmap_head, &iter, sptep)
		if (spte_ad_need_write_protect(*sptep))
			flush |= spte_wrprot_for_clear_dirty(sptep);
		else
			flush |= spte_clear_dirty(sptep);

	return flush;
}

static void kvm_mmu_write_protect_pt_masked(struct kvm *kvm,
				     struct kvm_memory_slot *slot,
				     gfn_t gfn_offset, unsigned long mask)
{
	struct kvm_rmap_head *rmap_head;

	if (is_tdp_mmu_enabled(kvm))
		kvm_tdp_mmu_clear_dirty_pt_masked(kvm, slot,
				slot->base_gfn + gfn_offset, mask, true);

	if (!kvm_memslots_have_rmaps(kvm))
		return;

	while (mask) {
		rmap_head = gfn_to_rmap(slot->base_gfn + gfn_offset + __ffs(mask),
					PG_LEVEL_4K, slot);
		rmap_write_protect(rmap_head, false);

		/* clear the first set bit */
		mask &= mask - 1;
	}
}

static void kvm_mmu_clear_dirty_pt_masked(struct kvm *kvm,
					 struct kvm_memory_slot *slot,
					 gfn_t gfn_offset, unsigned long mask)
{
	struct kvm_rmap_head *rmap_head;

	if (is_tdp_mmu_enabled(kvm))
		kvm_tdp_mmu_clear_dirty_pt_masked(kvm, slot,
				slot->base_gfn + gfn_offset, mask, false);

	if (!kvm_memslots_have_rmaps(kvm))
		return;

	while (mask) {
		rmap_head = gfn_to_rmap(slot->base_gfn + gfn_offset + __ffs(mask),
					PG_LEVEL_4K, slot);
		__rmap_clear_dirty(kvm, rmap_head, slot);

		/* clear the first set bit */
		mask &= mask - 1;
	}
}

void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
				struct kvm_memory_slot *slot,
				gfn_t gfn_offset, unsigned long mask)
{
	/*
	if (kvm_dirty_log_manual_protect_and_init_set(kvm)) {
		gfn_t start = slot->base_gfn + gfn_offset + __ffs(mask);
		gfn_t end = slot->base_gfn + gfn_offset + __fls(mask);

		if (READ_ONCE(eager_page_split))
			kvm_mmu_try_split_huge_pages(kvm, slot, start, end, PG_LEVEL_4K);

		kvm_mmu_slot_gfn_write_protect(kvm, slot, start, PG_LEVEL_2M);

		/* Cross two large pages? */
		if (ALIGN(start << PAGE_SHIFT, PMD_SIZE) !=
		    ALIGN(end << PAGE_SHIFT, PMD_SIZE))
			kvm_mmu_slot_gfn_write_protect(kvm, slot, end,
						       PG_LEVEL_2M);
	}

	/* Now handle 4K PTEs.  */
	if (kvm_x86_ops.cpu_dirty_log_size)
		kvm_mmu_clear_dirty_pt_masked(kvm, slot, gfn_offset, mask);
	else
		kvm_mmu_write_protect_pt_masked(kvm, slot, gfn_offset, mask);
}

int kvm_cpu_dirty_log_size(void)
{
	return kvm_x86_ops.cpu_dirty_log_size;
}

bool kvm_mmu_slot_gfn_write_protect(struct kvm *kvm,
				    struct kvm_memory_slot *slot, u64 gfn,
				    int min_level)
{
	struct kvm_rmap_head *rmap_head;
	int i;
	bool write_protected = false;

	if (kvm_memslots_have_rmaps(kvm)) {
		for (i = min_level; i <= KVM_MAX_HUGEPAGE_LEVEL; ++i) {
			rmap_head = gfn_to_rmap(gfn, i, slot);
			write_protected |= rmap_write_protect(rmap_head, true);
		}
	}

	if (is_tdp_mmu_enabled(kvm))
		write_protected |=
			kvm_tdp_mmu_write_protect_gfn(kvm, slot, gfn, min_level);

	return write_protected;
}

static bool kvm_vcpu_write_protect_gfn(struct kvm_vcpu *vcpu, u64 gfn)
{
	struct kvm_memory_slot *slot;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	return kvm_mmu_slot_gfn_write_protect(vcpu->kvm, slot, gfn, PG_LEVEL_4K);
}

static bool __kvm_zap_rmap(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			   const struct kvm_memory_slot *slot)
{
	return kvm_zap_all_rmap_sptes(kvm, rmap_head);
}

static bool kvm_zap_rmap(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			 struct kvm_memory_slot *slot, gfn_t gfn, int level,
			 pte_t unused)
{
	return __kvm_zap_rmap(kvm, rmap_head, slot);
}

static bool kvm_set_pte_rmap(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			     struct kvm_memory_slot *slot, gfn_t gfn, int level,
			     pte_t pte)
{
	u64 *sptep;
	struct rmap_iterator iter;
	bool need_flush = false;
	u64 new_spte;
	kvm_pfn_t new_pfn;

	WARN_ON(pte_huge(pte));
	new_pfn = pte_pfn(pte);

restart:
	for_each_rmap_spte(rmap_head, &iter, sptep) {
		rmap_printk("spte %p %llx gfn %llx (%d)\n",
			    sptep, *sptep, gfn, level);

		need_flush = true;

		if (pte_write(pte)) {
			kvm_zap_one_rmap_spte(kvm, rmap_head, sptep);
			goto restart;
		} else {
			new_spte = kvm_mmu_changed_pte_notifier_make_spte(
					*sptep, new_pfn);

			mmu_spte_clear_track_bits(kvm, sptep);
			mmu_spte_set(sptep, new_spte);
		}
	}

	if (need_flush && kvm_available_flush_tlb_with_range()) {
		kvm_flush_remote_tlbs_with_address(kvm, gfn, 1);
		return false;
	}

	return need_flush;
}

struct slot_rmap_walk_iterator {
	/* input fields. */
	const struct kvm_memory_slot *slot;
	gfn_t start_gfn;
	gfn_t end_gfn;
	int start_level;
	int end_level;

	/* output fields. */
	gfn_t gfn;
	struct kvm_rmap_head *rmap;
	int level;

	/* private field. */
	struct kvm_rmap_head *end_rmap;
};

static void
rmap_walk_init_level(struct slot_rmap_walk_iterator *iterator, int level)
{
	iterator->level = level;
	iterator->gfn = iterator->start_gfn;
	iterator->rmap = gfn_to_rmap(iterator->gfn, level, iterator->slot);
	iterator->end_rmap = gfn_to_rmap(iterator->end_gfn, level, iterator->slot);
}

static void
slot_rmap_walk_init(struct slot_rmap_walk_iterator *iterator,
		    const struct kvm_memory_slot *slot, int start_level,
		    int end_level, gfn_t start_gfn, gfn_t end_gfn)
{
	iterator->slot = slot;
	iterator->start_level = start_level;
	iterator->end_level = end_level;
	iterator->start_gfn = start_gfn;
	iterator->end_gfn = end_gfn;

	rmap_walk_init_level(iterator, iterator->start_level);
}

static bool slot_rmap_walk_okay(struct slot_rmap_walk_iterator *iterator)
{
	return !!iterator->rmap;
}

static void slot_rmap_walk_next(struct slot_rmap_walk_iterator *iterator)
{
	while (++iterator->rmap <= iterator->end_rmap) {
		iterator->gfn += (1UL << KVM_HPAGE_GFN_SHIFT(iterator->level));

		if (iterator->rmap->val)
			return;
	}

	if (++iterator->level > iterator->end_level) {
		iterator->rmap = NULL;
		return;
	}

	rmap_walk_init_level(iterator, iterator->level);
}

#define for_each_slot_rmap_range(_slot_, _start_level_, _end_level_,	\
	   _start_gfn, _end_gfn, _iter_)				\
	for (slot_rmap_walk_init(_iter_, _slot_, _start_level_,		\
				 _end_level_, _start_gfn, _end_gfn);	\
	     slot_rmap_walk_okay(_iter_);				\
	     slot_rmap_walk_next(_iter_))

typedef bool (*rmap_handler_t)(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			       struct kvm_memory_slot *slot, gfn_t gfn,
			       int level, pte_t pte);

static __always_inline bool kvm_handle_gfn_range(struct kvm *kvm,
						 struct kvm_gfn_range *range,
						 rmap_handler_t handler)
{
	struct slot_rmap_walk_iterator iterator;
	bool ret = false;

	for_each_slot_rmap_range(range->slot, PG_LEVEL_4K, KVM_MAX_HUGEPAGE_LEVEL,
				 range->start, range->end - 1, &iterator)
		ret |= handler(kvm, iterator.rmap, range->slot, iterator.gfn,
			       iterator.level, range->pte);

	return ret;
}

bool kvm_unmap_gfn_range(struct kvm *kvm, struct kvm_gfn_range *range)
{
	bool flush = false;

	if (kvm_memslots_have_rmaps(kvm))
		flush = kvm_handle_gfn_range(kvm, range, kvm_zap_rmap);

	if (is_tdp_mmu_enabled(kvm))
		flush = kvm_tdp_mmu_unmap_gfn_range(kvm, range, flush);

	return flush;
}

bool kvm_set_spte_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	bool flush = false;

	if (kvm_memslots_have_rmaps(kvm))
		flush = kvm_handle_gfn_range(kvm, range, kvm_set_pte_rmap);

	if (is_tdp_mmu_enabled(kvm))
		flush |= kvm_tdp_mmu_set_spte_gfn(kvm, range);

	return flush;
}

static bool kvm_age_rmap(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			 struct kvm_memory_slot *slot, gfn_t gfn, int level,
			 pte_t unused)
{
	u64 *sptep;
	struct rmap_iterator iter;
	int young = 0;

	for_each_rmap_spte(rmap_head, &iter, sptep)
		young |= mmu_spte_age(sptep);

	return young;
}

static bool kvm_test_age_rmap(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			      struct kvm_memory_slot *slot, gfn_t gfn,
			      int level, pte_t unused)
{
	u64 *sptep;
	struct rmap_iterator iter;

	for_each_rmap_spte(rmap_head, &iter, sptep)
		if (is_accessed_spte(*sptep))
			return true;
	return false;
}

#define RMAP_RECYCLE_THRESHOLD 1000

static void __rmap_add(struct kvm *kvm,
		       struct kvm_mmu_memory_cache *cache,
		       const struct kvm_memory_slot *slot,
		       u64 *spte, gfn_t gfn, unsigned int access)
{
	struct kvm_mmu_page *sp;
	struct kvm_rmap_head *rmap_head;
	int rmap_count;

	sp = sptep_to_sp(spte);
	kvm_mmu_page_set_translation(sp, spte_index(spte), gfn, access);
	kvm_update_page_stats(kvm, sp->role.level, 1);

	rmap_head = gfn_to_rmap(gfn, sp->role.level, slot);
	rmap_count = pte_list_add(cache, spte, rmap_head);

	if (rmap_count > RMAP_RECYCLE_THRESHOLD) {
		kvm_zap_all_rmap_sptes(kvm, rmap_head);
		kvm_flush_remote_tlbs_with_address(
				kvm, sp->gfn, KVM_PAGES_PER_HPAGE(sp->role.level));
	}
}

static void rmap_add(struct kvm_vcpu *vcpu, const struct kvm_memory_slot *slot,
		     u64 *spte, gfn_t gfn, unsigned int access)
{
	struct kvm_mmu_memory_cache *cache = &vcpu->arch.mmu_pte_list_desc_cache;

	__rmap_add(vcpu->kvm, cache, slot, spte, gfn, access);
}

bool kvm_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	bool young = false;

	if (kvm_memslots_have_rmaps(kvm))
		young = kvm_handle_gfn_range(kvm, range, kvm_age_rmap);

	if (is_tdp_mmu_enabled(kvm))
		young |= kvm_tdp_mmu_age_gfn_range(kvm, range);

	return young;
}

bool kvm_test_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
{
	bool young = false;

	if (kvm_memslots_have_rmaps(kvm))
		young = kvm_handle_gfn_range(kvm, range, kvm_test_age_rmap);

	if (is_tdp_mmu_enabled(kvm))
		young |= kvm_tdp_mmu_test_age_gfn(kvm, range);

	return young;
}

#ifdef MMU_DEBUG
static int is_empty_shadow_page(u64 *spt)
{
	u64 *pos;
	u64 *end;

	for (pos = spt, end = pos + PAGE_SIZE / sizeof(u64); pos != end; pos++)
		if (is_shadow_present_pte(*pos)) {
			printk(KERN_ERR "%s: %p %llx\n", __func__,
			       pos, *pos);
			return 0;
		}
	return 1;
}
#endif

static inline void kvm_mod_used_mmu_pages(struct kvm *kvm, long nr)
{
	kvm->arch.n_used_mmu_pages += nr;
	percpu_counter_add(&kvm_total_used_mmu_pages, nr);
}

static void kvm_mmu_free_shadow_page(struct kvm_mmu_page *sp)
{
	MMU_WARN_ON(!is_empty_shadow_page(sp->spt));
	hlist_del(&sp->hash_link);
	list_del(&sp->link);
	free_page((unsigned long)sp->spt);
	if (!sp->role.direct)
		free_page((unsigned long)sp->shadowed_translation);
	kmem_cache_free(mmu_page_header_cache, sp);
}

static unsigned kvm_page_table_hashfn(gfn_t gfn)
{
	return hash_64(gfn, KVM_MMU_HASH_SHIFT);
}

static void mmu_page_add_parent_pte(struct kvm_mmu_memory_cache *cache,
				    struct kvm_mmu_page *sp, u64 *parent_pte)
{
	if (!parent_pte)
		return;

	pte_list_add(cache, parent_pte, &sp->parent_ptes);
}

static void mmu_page_remove_parent_pte(struct kvm_mmu_page *sp,
				       u64 *parent_pte)
{
	pte_list_remove(parent_pte, &sp->parent_ptes);
}

static void drop_parent_pte(struct kvm_mmu_page *sp,
			    u64 *parent_pte)
{
	mmu_page_remove_parent_pte(sp, parent_pte);
	mmu_spte_clear_no_track(parent_pte);
}

static void mark_unsync(u64 *spte);
static void kvm_mmu_mark_parents_unsync(struct kvm_mmu_page *sp)
{
	u64 *sptep;
	struct rmap_iterator iter;

	for_each_rmap_spte(&sp->parent_ptes, &iter, sptep) {
		mark_unsync(sptep);
	}
}

static void mark_unsync(u64 *spte)
{
	struct kvm_mmu_page *sp;

	sp = sptep_to_sp(spte);
	if (__test_and_set_bit(spte_index(spte), sp->unsync_child_bitmap))
		return;
	if (sp->unsync_children++)
		return;
	kvm_mmu_mark_parents_unsync(sp);
}

static int nonpaging_sync_page(struct kvm_vcpu *vcpu,
			       struct kvm_mmu_page *sp)
{
	return -1;
}

#define KVM_PAGE_ARRAY_NR 16

struct kvm_mmu_pages {
	struct mmu_page_and_offset {
		struct kvm_mmu_page *sp;
		unsigned int idx;
	} page[KVM_PAGE_ARRAY_NR];
	unsigned int nr;
};

static int mmu_pages_add(struct kvm_mmu_pages *pvec, struct kvm_mmu_page *sp,
			 int idx)
{
	int i;

	if (sp->unsync)
		for (i=0; i < pvec->nr; i++)
			if (pvec->page[i].sp == sp)
				return 0;

	pvec->page[pvec->nr].sp = sp;
	pvec->page[pvec->nr].idx = idx;
	pvec->nr++;
	return (pvec->nr == KVM_PAGE_ARRAY_NR);
}

static inline void clear_unsync_child_bit(struct kvm_mmu_page *sp, int idx)
{
	--sp->unsync_children;
	WARN_ON((int)sp->unsync_children < 0);
	__clear_bit(idx, sp->unsync_child_bitmap);
}

static int __mmu_unsync_walk(struct kvm_mmu_page *sp,
			   struct kvm_mmu_pages *pvec)
{
	int i, ret, nr_unsync_leaf = 0;

	for_each_set_bit(i, sp->unsync_child_bitmap, 512) {
		struct kvm_mmu_page *child;
		u64 ent = sp->spt[i];

		if (!is_shadow_present_pte(ent) || is_large_pte(ent)) {
			clear_unsync_child_bit(sp, i);
			continue;
		}

		child = to_shadow_page(ent & SPTE_BASE_ADDR_MASK);

		if (child->unsync_children) {
			if (mmu_pages_add(pvec, child, i))
				return -ENOSPC;

			ret = __mmu_unsync_walk(child, pvec);
			if (!ret) {
				clear_unsync_child_bit(sp, i);
				continue;
			} else if (ret > 0) {
				nr_unsync_leaf += ret;
			} else
				return ret;
		} else if (child->unsync) {
			nr_unsync_leaf++;
			if (mmu_pages_add(pvec, child, i))
				return -ENOSPC;
		} else
			clear_unsync_child_bit(sp, i);
	}

	return nr_unsync_leaf;
}

#define INVALID_INDEX (-1)

static int mmu_unsync_walk(struct kvm_mmu_page *sp,
			   struct kvm_mmu_pages *pvec)
{
	pvec->nr = 0;
	if (!sp->unsync_children)
		return 0;

	mmu_pages_add(pvec, sp, INVALID_INDEX);
	return __mmu_unsync_walk(sp, pvec);
}

static void kvm_unlink_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	WARN_ON(!sp->unsync);
	trace_kvm_mmu_sync_page(sp);
	sp->unsync = 0;
	--kvm->stat.mmu_unsync;
}

static bool kvm_mmu_prepare_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp,
				     struct list_head *invalid_list);
static void kvm_mmu_commit_zap_page(struct kvm *kvm,
				    struct list_head *invalid_list);

static bool sp_has_gptes(struct kvm_mmu_page *sp)
{
	if (sp->role.direct)
		return false;

	if (sp->role.passthrough)
		return false;

	return true;
}

#define for_each_valid_sp(_kvm, _sp, _list)				\
	hlist_for_each_entry(_sp, _list, hash_link)			\
		if (is_obsolete_sp((_kvm), (_sp))) {			\
		} else

#define for_each_gfn_valid_sp_with_gptes(_kvm, _sp, _gfn)		\
	for_each_valid_sp(_kvm, _sp,					\
	  &(_kvm)->arch.mmu_page_hash[kvm_page_table_hashfn(_gfn)])	\
		if ((_sp)->gfn != (_gfn) || !sp_has_gptes(_sp)) {} else

static int kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			 struct list_head *invalid_list)
{
	int ret = vcpu->arch.mmu->sync_page(vcpu, sp);

	if (ret < 0)
		kvm_mmu_prepare_zap_page(vcpu->kvm, sp, invalid_list);
	return ret;
}

static bool kvm_mmu_remote_flush_or_zap(struct kvm *kvm,
					struct list_head *invalid_list,
					bool remote_flush)
{
	if (!remote_flush && list_empty(invalid_list))
		return false;

	if (!list_empty(invalid_list))
		kvm_mmu_commit_zap_page(kvm, invalid_list);
	else
		kvm_flush_remote_tlbs(kvm);
	return true;
}

static bool is_obsolete_sp(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	if (sp->role.invalid)
		return true;

	/* TDP MMU pages due not use the MMU generation. */
	return !sp->tdp_mmu_page &&
	       unlikely(sp->mmu_valid_gen != kvm->arch.mmu_valid_gen);
}

struct mmu_page_path {
	struct kvm_mmu_page *parent[PT64_ROOT_MAX_LEVEL];
	unsigned int idx[PT64_ROOT_MAX_LEVEL];
};

#define for_each_sp(pvec, sp, parents, i)			\
		for (i = mmu_pages_first(&pvec, &parents);	\
			i < pvec.nr && ({ sp = pvec.page[i].sp; 1;});	\
			i = mmu_pages_next(&pvec, &parents, i))

static int mmu_pages_next(struct kvm_mmu_pages *pvec,
			  struct mmu_page_path *parents,
			  int i)
{
	int n;

	for (n = i+1; n < pvec->nr; n++) {
		struct kvm_mmu_page *sp = pvec->page[n].sp;
		unsigned idx = pvec->page[n].idx;
		int level = sp->role.level;

		parents->idx[level-1] = idx;
		if (level == PG_LEVEL_4K)
			break;

		parents->parent[level-2] = sp;
	}

	return n;
}

static int mmu_pages_first(struct kvm_mmu_pages *pvec,
			   struct mmu_page_path *parents)
{
	struct kvm_mmu_page *sp;
	int level;

	if (pvec->nr == 0)
		return 0;

	WARN_ON(pvec->page[0].idx != INVALID_INDEX);

	sp = pvec->page[0].sp;
	level = sp->role.level;
	WARN_ON(level == PG_LEVEL_4K);

	parents->parent[level-2] = sp;

	/* Also set up a sentinel.  Further entries in pvec are all
	 * children of sp, so this element is never overwritten.
	 */
	parents->parent[level-1] = NULL;
	return mmu_pages_next(pvec, parents, 0);
}

static void mmu_pages_clear_parents(struct mmu_page_path *parents)
{
	struct kvm_mmu_page *sp;
	unsigned int level = 0;

	do {
		unsigned int idx = parents->idx[level];
		sp = parents->parent[level];
		if (!sp)
			return;

		WARN_ON(idx == INVALID_INDEX);
		clear_unsync_child_bit(sp, idx);
		level++;
	} while (!sp->unsync_children);
}

static int mmu_sync_children(struct kvm_vcpu *vcpu,
			     struct kvm_mmu_page *parent, bool can_yield)
{
	int i;
	struct kvm_mmu_page *sp;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;
	LIST_HEAD(invalid_list);
	bool flush = false;

	while (mmu_unsync_walk(parent, &pages)) {
		bool protected = false;

		for_each_sp(pages, sp, parents, i)
			protected |= kvm_vcpu_write_protect_gfn(vcpu, sp->gfn);

		if (protected) {
			kvm_mmu_remote_flush_or_zap(vcpu->kvm, &invalid_list, true);
			flush = false;
		}

		for_each_sp(pages, sp, parents, i) {
			kvm_unlink_unsync_page(vcpu->kvm, sp);
			flush |= kvm_sync_page(vcpu, sp, &invalid_list) > 0;
			mmu_pages_clear_parents(&parents);
		}
		if (need_resched() || rwlock_needbreak(&vcpu->kvm->mmu_lock)) {
			kvm_mmu_remote_flush_or_zap(vcpu->kvm, &invalid_list, flush);
			if (!can_yield) {
				kvm_make_request(KVM_REQ_MMU_SYNC, vcpu);
				return -EINTR;
			}

			cond_resched_rwlock_write(&vcpu->kvm->mmu_lock);
			flush = false;
		}
	}

	kvm_mmu_remote_flush_or_zap(vcpu->kvm, &invalid_list, flush);
	return 0;
}

static void __clear_sp_write_flooding_count(struct kvm_mmu_page *sp)
{
	atomic_set(&sp->write_flooding_count,  0);
}

static void clear_sp_write_flooding_count(u64 *spte)
{
	__clear_sp_write_flooding_count(sptep_to_sp(spte));
}

static struct kvm_mmu_page *kvm_mmu_find_shadow_page(struct kvm *kvm,
						     struct kvm_vcpu *vcpu,
						     gfn_t gfn,
						     struct hlist_head *sp_list,
						     union kvm_mmu_page_role role)
{
	struct kvm_mmu_page *sp;
	int ret;
	int collisions = 0;
	LIST_HEAD(invalid_list);

	for_each_valid_sp(kvm, sp, sp_list) {
		if (sp->gfn != gfn) {
			collisions++;
			continue;
		}

		if (sp->role.word != role.word) {
			/*
			if (role.level > PG_LEVEL_4K && sp->unsync)
				kvm_mmu_prepare_zap_page(kvm, sp,
							 &invalid_list);
			continue;
		}

		/* unsync and write-flooding only apply to indirect SPs. */
		if (sp->role.direct)
			goto out;

		if (sp->unsync) {
			if (KVM_BUG_ON(!vcpu, kvm))
				break;

			/*
			ret = kvm_sync_page(vcpu, sp, &invalid_list);
			if (ret < 0)
				break;

			WARN_ON(!list_empty(&invalid_list));
			if (ret > 0)
				kvm_flush_remote_tlbs(kvm);
		}

		__clear_sp_write_flooding_count(sp);

		goto out;
	}

	sp = NULL;
	++kvm->stat.mmu_cache_miss;

out:
	kvm_mmu_commit_zap_page(kvm, &invalid_list);

	if (collisions > kvm->stat.max_mmu_page_hash_collisions)
		kvm->stat.max_mmu_page_hash_collisions = collisions;
	return sp;
}

struct shadow_page_caches {
	struct kvm_mmu_memory_cache *page_header_cache;
	struct kvm_mmu_memory_cache *shadow_page_cache;
	struct kvm_mmu_memory_cache *shadowed_info_cache;
};

static struct kvm_mmu_page *kvm_mmu_alloc_shadow_page(struct kvm *kvm,
						      struct shadow_page_caches *caches,
						      gfn_t gfn,
						      struct hlist_head *sp_list,
						      union kvm_mmu_page_role role)
{
	struct kvm_mmu_page *sp;

	sp = kvm_mmu_memory_cache_alloc(caches->page_header_cache);
	sp->spt = kvm_mmu_memory_cache_alloc(caches->shadow_page_cache);
	if (!role.direct)
		sp->shadowed_translation = kvm_mmu_memory_cache_alloc(caches->shadowed_info_cache);

	set_page_private(virt_to_page(sp->spt), (unsigned long)sp);

	/*
	sp->mmu_valid_gen = kvm->arch.mmu_valid_gen;
	list_add(&sp->link, &kvm->arch.active_mmu_pages);
	kvm_mod_used_mmu_pages(kvm, +1);

	sp->gfn = gfn;
	sp->role = role;
	hlist_add_head(&sp->hash_link, sp_list);
	if (sp_has_gptes(sp))
		account_shadowed(kvm, sp);

	return sp;
}

static struct kvm_mmu_page *__kvm_mmu_get_shadow_page(struct kvm *kvm,
						      struct kvm_vcpu *vcpu,
						      struct shadow_page_caches *caches,
						      gfn_t gfn,
						      union kvm_mmu_page_role role)
{
	struct hlist_head *sp_list;
	struct kvm_mmu_page *sp;
	bool created = false;

	sp_list = &kvm->arch.mmu_page_hash[kvm_page_table_hashfn(gfn)];

	sp = kvm_mmu_find_shadow_page(kvm, vcpu, gfn, sp_list, role);
	if (!sp) {
		created = true;
		sp = kvm_mmu_alloc_shadow_page(kvm, caches, gfn, sp_list, role);
	}

	trace_kvm_mmu_get_page(sp, created);
	return sp;
}

static struct kvm_mmu_page *kvm_mmu_get_shadow_page(struct kvm_vcpu *vcpu,
						    gfn_t gfn,
						    union kvm_mmu_page_role role)
{
	struct shadow_page_caches caches = {
		.page_header_cache = &vcpu->arch.mmu_page_header_cache,
		.shadow_page_cache = &vcpu->arch.mmu_shadow_page_cache,
		.shadowed_info_cache = &vcpu->arch.mmu_shadowed_info_cache,
	};

	return __kvm_mmu_get_shadow_page(vcpu->kvm, vcpu, &caches, gfn, role);
}

static union kvm_mmu_page_role kvm_mmu_child_role(u64 *sptep, bool direct,
						  unsigned int access)
{
	struct kvm_mmu_page *parent_sp = sptep_to_sp(sptep);
	union kvm_mmu_page_role role;

	role = parent_sp->role;
	role.level--;
	role.access = access;
	role.direct = direct;
	role.passthrough = 0;

	/*
	if (role.has_4_byte_gpte) {
		WARN_ON_ONCE(role.level != PG_LEVEL_4K);
		role.quadrant = spte_index(sptep) & 1;
	}

	return role;
}

static struct kvm_mmu_page *kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu,
						 u64 *sptep, gfn_t gfn,
						 bool direct, unsigned int access)
{
	union kvm_mmu_page_role role;

	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep))
		return ERR_PTR(-EEXIST);

	role = kvm_mmu_child_role(sptep, direct, access);
	return kvm_mmu_get_shadow_page(vcpu, gfn, role);
}

static void shadow_walk_init_using_root(struct kvm_shadow_walk_iterator *iterator,
					struct kvm_vcpu *vcpu, hpa_t root,
					u64 addr)
{
	iterator->addr = addr;
	iterator->shadow_addr = root;
	iterator->level = vcpu->arch.mmu->root_role.level;

	if (iterator->level >= PT64_ROOT_4LEVEL &&
	    vcpu->arch.mmu->cpu_role.base.level < PT64_ROOT_4LEVEL &&
	    !vcpu->arch.mmu->root_role.direct)
		iterator->level = PT32E_ROOT_LEVEL;

	if (iterator->level == PT32E_ROOT_LEVEL) {
		/*
		BUG_ON(root != vcpu->arch.mmu->root.hpa);

		iterator->shadow_addr
			= vcpu->arch.mmu->pae_root[(addr >> 30) & 3];
		iterator->shadow_addr &= SPTE_BASE_ADDR_MASK;
		--iterator->level;
		if (!iterator->shadow_addr)
			iterator->level = 0;
	}
}

static void shadow_walk_init(struct kvm_shadow_walk_iterator *iterator,
			     struct kvm_vcpu *vcpu, u64 addr)
{
	shadow_walk_init_using_root(iterator, vcpu, vcpu->arch.mmu->root.hpa,
				    addr);
}

static bool shadow_walk_okay(struct kvm_shadow_walk_iterator *iterator)
{
	if (iterator->level < PG_LEVEL_4K)
		return false;

	iterator->index = SPTE_INDEX(iterator->addr, iterator->level);
	iterator->sptep	= ((u64 *)__va(iterator->shadow_addr)) + iterator->index;
	return true;
}

static void __shadow_walk_next(struct kvm_shadow_walk_iterator *iterator,
			       u64 spte)
{
	if (!is_shadow_present_pte(spte) || is_last_spte(spte, iterator->level)) {
		iterator->level = 0;
		return;
	}

	iterator->shadow_addr = spte & SPTE_BASE_ADDR_MASK;
	--iterator->level;
}

static void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator)
{
	__shadow_walk_next(iterator, *iterator->sptep);
}

static void __link_shadow_page(struct kvm *kvm,
			       struct kvm_mmu_memory_cache *cache, u64 *sptep,
			       struct kvm_mmu_page *sp, bool flush)
{
	u64 spte;

	BUILD_BUG_ON(VMX_EPT_WRITABLE_MASK != PT_WRITABLE_MASK);

	/*
	if (is_shadow_present_pte(*sptep))
		drop_large_spte(kvm, sptep, flush);

	spte = make_nonleaf_spte(sp->spt, sp_ad_disabled(sp));

	mmu_spte_set(sptep, spte);

	mmu_page_add_parent_pte(cache, sp, sptep);

	if (sp->unsync_children || sp->unsync)
		mark_unsync(sptep);
}

static void link_shadow_page(struct kvm_vcpu *vcpu, u64 *sptep,
			     struct kvm_mmu_page *sp)
{
	__link_shadow_page(vcpu->kvm, &vcpu->arch.mmu_pte_list_desc_cache, sptep, sp, true);
}

static void validate_direct_spte(struct kvm_vcpu *vcpu, u64 *sptep,
				   unsigned direct_access)
{
	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep)) {
		struct kvm_mmu_page *child;

		/*
		child = to_shadow_page(*sptep & SPTE_BASE_ADDR_MASK);
		if (child->role.access == direct_access)
			return;

		drop_parent_pte(child, sptep);
		kvm_flush_remote_tlbs_with_address(vcpu->kvm, child->gfn, 1);
	}
}

static int mmu_page_zap_pte(struct kvm *kvm, struct kvm_mmu_page *sp,
			    u64 *spte, struct list_head *invalid_list)
{
	u64 pte;
	struct kvm_mmu_page *child;

	pte = *spte;
	if (is_shadow_present_pte(pte)) {
		if (is_last_spte(pte, sp->role.level)) {
			drop_spte(kvm, spte);
		} else {
			child = to_shadow_page(pte & SPTE_BASE_ADDR_MASK);
			drop_parent_pte(child, spte);

			/*
			if (tdp_enabled && invalid_list &&
			    child->role.guest_mode && !child->parent_ptes.val)
				return kvm_mmu_prepare_zap_page(kvm, child,
								invalid_list);
		}
	} else if (is_mmio_spte(pte)) {
		mmu_spte_clear_no_track(spte);
	}
	return 0;
}

static int kvm_mmu_page_unlink_children(struct kvm *kvm,
					struct kvm_mmu_page *sp,
					struct list_head *invalid_list)
{
	int zapped = 0;
	unsigned i;

	for (i = 0; i < SPTE_ENT_PER_PAGE; ++i)
		zapped += mmu_page_zap_pte(kvm, sp, sp->spt + i, invalid_list);

	return zapped;
}

static void kvm_mmu_unlink_parents(struct kvm_mmu_page *sp)
{
	u64 *sptep;
	struct rmap_iterator iter;

	while ((sptep = rmap_get_first(&sp->parent_ptes, &iter)))
		drop_parent_pte(sp, sptep);
}

static int mmu_zap_unsync_children(struct kvm *kvm,
				   struct kvm_mmu_page *parent,
				   struct list_head *invalid_list)
{
	int i, zapped = 0;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;

	if (parent->role.level == PG_LEVEL_4K)
		return 0;

	while (mmu_unsync_walk(parent, &pages)) {
		struct kvm_mmu_page *sp;

		for_each_sp(pages, sp, parents, i) {
			kvm_mmu_prepare_zap_page(kvm, sp, invalid_list);
			mmu_pages_clear_parents(&parents);
			zapped++;
		}
	}

	return zapped;
}

static bool __kvm_mmu_prepare_zap_page(struct kvm *kvm,
				       struct kvm_mmu_page *sp,
				       struct list_head *invalid_list,
				       int *nr_zapped)
{
	bool list_unstable, zapped_root = false;

	trace_kvm_mmu_prepare_zap_page(sp);
	++kvm->stat.mmu_shadow_zapped;
	kvm_mmu_unlink_parents(sp);

	/* Zapping children means active_mmu_pages has become unstable. */
	list_unstable = *nr_zapped;

	if (!sp->role.invalid && sp_has_gptes(sp))
		unaccount_shadowed(kvm, sp);

	if (sp->unsync)
		kvm_unlink_unsync_page(kvm, sp);
	if (!sp->root_count) {
		/* Count self */
		(*nr_zapped)++;

		/*
		if (sp->role.invalid)
			list_add(&sp->link, invalid_list);
		else
			list_move(&sp->link, invalid_list);
		kvm_mod_used_mmu_pages(kvm, -1);
	} else {
		/*
		list_del(&sp->link);

		/*
		zapped_root = !is_obsolete_sp(kvm, sp);
	}

	if (sp->lpage_disallowed)
		unaccount_huge_nx_page(kvm, sp);

	sp->role.invalid = 1;

	/*
	if (zapped_root)
		kvm_make_all_cpus_request(kvm, KVM_REQ_MMU_FREE_OBSOLETE_ROOTS);
	return list_unstable;
}

static bool kvm_mmu_prepare_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp,
				     struct list_head *invalid_list)
{
	int nr_zapped;

	__kvm_mmu_prepare_zap_page(kvm, sp, invalid_list, &nr_zapped);
	return nr_zapped;
}

static void kvm_mmu_commit_zap_page(struct kvm *kvm,
				    struct list_head *invalid_list)
{
	struct kvm_mmu_page *sp, *nsp;

	if (list_empty(invalid_list))
		return;

	/*
	kvm_flush_remote_tlbs(kvm);

	list_for_each_entry_safe(sp, nsp, invalid_list, link) {
		WARN_ON(!sp->role.invalid || sp->root_count);
		kvm_mmu_free_shadow_page(sp);
	}
}

static unsigned long kvm_mmu_zap_oldest_mmu_pages(struct kvm *kvm,
						  unsigned long nr_to_zap)
{
	unsigned long total_zapped = 0;
	struct kvm_mmu_page *sp, *tmp;
	LIST_HEAD(invalid_list);
	bool unstable;
	int nr_zapped;

	if (list_empty(&kvm->arch.active_mmu_pages))
		return 0;

restart:
	list_for_each_entry_safe_reverse(sp, tmp, &kvm->arch.active_mmu_pages, link) {
		/*
		if (sp->root_count)
			continue;

		unstable = __kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list,
						      &nr_zapped);
		total_zapped += nr_zapped;
		if (total_zapped >= nr_to_zap)
			break;

		if (unstable)
			goto restart;
	}

	kvm_mmu_commit_zap_page(kvm, &invalid_list);

	kvm->stat.mmu_recycled += total_zapped;
	return total_zapped;
}

static inline unsigned long kvm_mmu_available_pages(struct kvm *kvm)
{
	if (kvm->arch.n_max_mmu_pages > kvm->arch.n_used_mmu_pages)
		return kvm->arch.n_max_mmu_pages -
			kvm->arch.n_used_mmu_pages;

	return 0;
}

static int make_mmu_pages_available(struct kvm_vcpu *vcpu)
{
	unsigned long avail = kvm_mmu_available_pages(vcpu->kvm);

	if (likely(avail >= KVM_MIN_FREE_MMU_PAGES))
		return 0;

	kvm_mmu_zap_oldest_mmu_pages(vcpu->kvm, KVM_REFILL_PAGES - avail);

	/*
	if (!kvm_mmu_available_pages(vcpu->kvm))
		return -ENOSPC;
	return 0;
}

void kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned long goal_nr_mmu_pages)
{
	write_lock(&kvm->mmu_lock);

	if (kvm->arch.n_used_mmu_pages > goal_nr_mmu_pages) {
		kvm_mmu_zap_oldest_mmu_pages(kvm, kvm->arch.n_used_mmu_pages -
						  goal_nr_mmu_pages);

		goal_nr_mmu_pages = kvm->arch.n_used_mmu_pages;
	}

	kvm->arch.n_max_mmu_pages = goal_nr_mmu_pages;

	write_unlock(&kvm->mmu_lock);
}

int kvm_mmu_unprotect_page(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);
	int r;

	pgprintk("%s: looking for gfn %llx\n", __func__, gfn);
	r = 0;
	write_lock(&kvm->mmu_lock);
	for_each_gfn_valid_sp_with_gptes(kvm, sp, gfn) {
		pgprintk("%s: gfn %llx role %x\n", __func__, gfn,
			 sp->role.word);
		r = 1;
		kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
	}
	kvm_mmu_commit_zap_page(kvm, &invalid_list);
	write_unlock(&kvm->mmu_lock);

	return r;
}

static int kvm_mmu_unprotect_page_virt(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t gpa;
	int r;

	if (vcpu->arch.mmu->root_role.direct)
		return 0;

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, gva, NULL);

	r = kvm_mmu_unprotect_page(vcpu->kvm, gpa >> PAGE_SHIFT);

	return r;
}

static void kvm_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	trace_kvm_mmu_unsync_page(sp);
	++kvm->stat.mmu_unsync;
	sp->unsync = 1;

	kvm_mmu_mark_parents_unsync(sp);
}

int mmu_try_to_unsync_pages(struct kvm *kvm, const struct kvm_memory_slot *slot,
			    gfn_t gfn, bool can_unsync, bool prefetch)
{
	struct kvm_mmu_page *sp;
	bool locked = false;

	/*
	if (kvm_slot_page_track_is_active(kvm, slot, gfn, KVM_PAGE_TRACK_WRITE))
		return -EPERM;

	/*
	for_each_gfn_valid_sp_with_gptes(kvm, sp, gfn) {
		if (!can_unsync)
			return -EPERM;

		if (sp->unsync)
			continue;

		if (prefetch)
			return -EEXIST;

		/*
		if (!locked) {
			locked = true;
			spin_lock(&kvm->arch.mmu_unsync_pages_lock);

			/*
			if (READ_ONCE(sp->unsync))
				continue;
		}

		WARN_ON(sp->role.level != PG_LEVEL_4K);
		kvm_unsync_page(kvm, sp);
	}
	if (locked)
		spin_unlock(&kvm->arch.mmu_unsync_pages_lock);

	/*
	smp_wmb();

	return 0;
}

static int mmu_set_spte(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot,
			u64 *sptep, unsigned int pte_access, gfn_t gfn,
			kvm_pfn_t pfn, struct kvm_page_fault *fault)
{
	struct kvm_mmu_page *sp = sptep_to_sp(sptep);
	int level = sp->role.level;
	int was_rmapped = 0;
	int ret = RET_PF_FIXED;
	bool flush = false;
	bool wrprot;
	u64 spte;

	/* Prefetching always gets a writable pfn.  */
	bool host_writable = !fault || fault->map_writable;
	bool prefetch = !fault || fault->prefetch;
	bool write_fault = fault && fault->write;

	pgprintk("%s: spte %llx write_fault %d gfn %llx\n", __func__,
		 *sptep, write_fault, gfn);

	if (unlikely(is_noslot_pfn(pfn))) {
		vcpu->stat.pf_mmio_spte_created++;
		mark_mmio_spte(vcpu, sptep, gfn, pte_access);
		return RET_PF_EMULATE;
	}

	if (is_shadow_present_pte(*sptep)) {
		/*
		if (level > PG_LEVEL_4K && !is_large_pte(*sptep)) {
			struct kvm_mmu_page *child;
			u64 pte = *sptep;

			child = to_shadow_page(pte & SPTE_BASE_ADDR_MASK);
			drop_parent_pte(child, sptep);
			flush = true;
		} else if (pfn != spte_to_pfn(*sptep)) {
			pgprintk("hfn old %llx new %llx\n",
				 spte_to_pfn(*sptep), pfn);
			drop_spte(vcpu->kvm, sptep);
			flush = true;
		} else
			was_rmapped = 1;
	}

	wrprot = make_spte(vcpu, sp, slot, pte_access, gfn, pfn, *sptep, prefetch,
			   true, host_writable, &spte);

	if (*sptep == spte) {
		ret = RET_PF_SPURIOUS;
	} else {
		flush |= mmu_spte_update(sptep, spte);
		trace_kvm_mmu_set_spte(level, gfn, sptep);
	}

	if (wrprot) {
		if (write_fault)
			ret = RET_PF_EMULATE;
	}

	if (flush)
		kvm_flush_remote_tlbs_with_address(vcpu->kvm, gfn,
				KVM_PAGES_PER_HPAGE(level));

	pgprintk("%s: setting spte %llx\n", __func__, *sptep);

	if (!was_rmapped) {
		WARN_ON_ONCE(ret == RET_PF_SPURIOUS);
		rmap_add(vcpu, slot, sptep, gfn, pte_access);
	} else {
		/* Already rmapped but the pte_access bits may have changed. */
		kvm_mmu_page_set_access(sp, spte_index(sptep), pte_access);
	}

	return ret;
}

static int direct_pte_prefetch_many(struct kvm_vcpu *vcpu,
				    struct kvm_mmu_page *sp,
				    u64 *start, u64 *end)
{
	struct page *pages[PTE_PREFETCH_NUM];
	struct kvm_memory_slot *slot;
	unsigned int access = sp->role.access;
	int i, ret;
	gfn_t gfn;

	gfn = kvm_mmu_page_get_gfn(sp, spte_index(start));
	slot = gfn_to_memslot_dirty_bitmap(vcpu, gfn, access & ACC_WRITE_MASK);
	if (!slot)
		return -1;

	ret = gfn_to_page_many_atomic(slot, gfn, pages, end - start);
	if (ret <= 0)
		return -1;

	for (i = 0; i < ret; i++, gfn++, start++) {
		mmu_set_spte(vcpu, slot, start, access, gfn,
			     page_to_pfn(pages[i]), NULL);
		put_page(pages[i]);
	}

	return 0;
}

static void __direct_pte_prefetch(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, u64 *sptep)
{
	u64 *spte, *start = NULL;
	int i;

	WARN_ON(!sp->role.direct);

	i = spte_index(sptep) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (is_shadow_present_pte(*spte) || spte == sptep) {
			if (!start)
				continue;
			if (direct_pte_prefetch_many(vcpu, sp, start, spte) < 0)
				return;
			start = NULL;
		} else if (!start)
			start = spte;
	}
	if (start)
		direct_pte_prefetch_many(vcpu, sp, start, spte);
}

static void direct_pte_prefetch(struct kvm_vcpu *vcpu, u64 *sptep)
{
	struct kvm_mmu_page *sp;

	sp = sptep_to_sp(sptep);

	/*
	if (sp_ad_disabled(sp))
		return;

	if (sp->role.level > PG_LEVEL_4K)
		return;

	/*
	if (unlikely(vcpu->kvm->mmu_notifier_count))
		return;

	__direct_pte_prefetch(vcpu, sp, sptep);
}

static int host_pfn_mapping_level(struct kvm *kvm, gfn_t gfn,
				  const struct kvm_memory_slot *slot)
{
	int level = PG_LEVEL_4K;
	unsigned long hva;
	unsigned long flags;
	pgd_t pgd;
	p4d_t p4d;
	pud_t pud;
	pmd_t pmd;

	/*
	hva = __gfn_to_hva_memslot(slot, gfn);

	/*
	local_irq_save(flags);

	/*
	pgd = READ_ONCE(*pgd_offset(kvm->mm, hva));
	if (pgd_none(pgd))
		goto out;

	p4d = READ_ONCE(*p4d_offset(&pgd, hva));
	if (p4d_none(p4d) || !p4d_present(p4d))
		goto out;

	pud = READ_ONCE(*pud_offset(&p4d, hva));
	if (pud_none(pud) || !pud_present(pud))
		goto out;

	if (pud_large(pud)) {
		level = PG_LEVEL_1G;
		goto out;
	}

	pmd = READ_ONCE(*pmd_offset(&pud, hva));
	if (pmd_none(pmd) || !pmd_present(pmd))
		goto out;

	if (pmd_large(pmd))
		level = PG_LEVEL_2M;

out:
	local_irq_restore(flags);
	return level;
}

int kvm_mmu_max_mapping_level(struct kvm *kvm,
			      const struct kvm_memory_slot *slot, gfn_t gfn,
			      int max_level)
{
	struct kvm_lpage_info *linfo;
	int host_level;

	max_level = min(max_level, max_huge_page_level);
	for ( ; max_level > PG_LEVEL_4K; max_level--) {
		linfo = lpage_info_slot(gfn, slot, max_level);
		if (!linfo->disallow_lpage)
			break;
	}

	if (max_level == PG_LEVEL_4K)
		return PG_LEVEL_4K;

	host_level = host_pfn_mapping_level(kvm, gfn, slot);
	return min(host_level, max_level);
}

void kvm_mmu_hugepage_adjust(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_memory_slot *slot = fault->slot;
	kvm_pfn_t mask;

	fault->huge_page_disallowed = fault->exec && fault->nx_huge_page_workaround_enabled;

	if (unlikely(fault->max_level == PG_LEVEL_4K))
		return;

	if (is_error_noslot_pfn(fault->pfn))
		return;

	if (kvm_slot_dirty_track_enabled(slot))
		return;

	/*
	fault->req_level = kvm_mmu_max_mapping_level(vcpu->kvm, slot,
						     fault->gfn, fault->max_level);
	if (fault->req_level == PG_LEVEL_4K || fault->huge_page_disallowed)
		return;

	/*
	fault->goal_level = fault->req_level;
	mask = KVM_PAGES_PER_HPAGE(fault->goal_level) - 1;
	VM_BUG_ON((fault->gfn & mask) != (fault->pfn & mask));
	fault->pfn &= ~mask;
}

void disallowed_hugepage_adjust(struct kvm_page_fault *fault, u64 spte, int cur_level)
{
	if (cur_level > PG_LEVEL_4K &&
	    cur_level == fault->goal_level &&
	    is_shadow_present_pte(spte) &&
	    !is_large_pte(spte)) {
		/*
		u64 page_mask = KVM_PAGES_PER_HPAGE(cur_level) -
				KVM_PAGES_PER_HPAGE(cur_level - 1);
		fault->pfn |= fault->gfn & page_mask;
		fault->goal_level--;
	}
}

static int __direct_map(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_shadow_walk_iterator it;
	struct kvm_mmu_page *sp;
	int ret;
	gfn_t base_gfn = fault->gfn;

	kvm_mmu_hugepage_adjust(vcpu, fault);

	trace_kvm_mmu_spte_requested(fault);
	for_each_shadow_entry(vcpu, fault->addr, it) {
		/*
		if (fault->nx_huge_page_workaround_enabled)
			disallowed_hugepage_adjust(fault, *it.sptep, it.level);

		base_gfn = fault->gfn & ~(KVM_PAGES_PER_HPAGE(it.level) - 1);
		if (it.level == fault->goal_level)
			break;

		sp = kvm_mmu_get_child_sp(vcpu, it.sptep, base_gfn, true, ACC_ALL);
		if (sp == ERR_PTR(-EEXIST))
			continue;

		link_shadow_page(vcpu, it.sptep, sp);
		if (fault->is_tdp && fault->huge_page_disallowed &&
		    fault->req_level >= it.level)
			account_huge_nx_page(vcpu->kvm, sp);
	}

	if (WARN_ON_ONCE(it.level != fault->goal_level))
		return -EFAULT;

	ret = mmu_set_spte(vcpu, fault->slot, it.sptep, ACC_ALL,
			   base_gfn, fault->pfn, fault);
	if (ret == RET_PF_SPURIOUS)
		return ret;

	direct_pte_prefetch(vcpu, it.sptep);
	return ret;
}

static void kvm_send_hwpoison_signal(unsigned long address, struct task_struct *tsk)
{
	send_sig_mceerr(BUS_MCEERR_AR, (void __user *)address, PAGE_SHIFT, tsk);
}

static int kvm_handle_bad_page(struct kvm_vcpu *vcpu, gfn_t gfn, kvm_pfn_t pfn)
{
	/*
	if (pfn == KVM_PFN_ERR_RO_FAULT)
		return RET_PF_EMULATE;

	if (pfn == KVM_PFN_ERR_HWPOISON) {
		kvm_send_hwpoison_signal(kvm_vcpu_gfn_to_hva(vcpu, gfn), current);
		return RET_PF_RETRY;
	}

	return -EFAULT;
}

static int handle_abnormal_pfn(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault,
			       unsigned int access)
{
	/* The pfn is invalid, report the error! */
	if (unlikely(is_error_pfn(fault->pfn)))
		return kvm_handle_bad_page(vcpu, fault->gfn, fault->pfn);

	if (unlikely(!fault->slot)) {
		gva_t gva = fault->is_tdp ? 0 : fault->addr;

		vcpu_cache_mmio_info(vcpu, gva, fault->gfn,
				     access & shadow_mmio_access_mask);
		/*
		if (unlikely(!enable_mmio_caching) ||
		    unlikely(fault->gfn > kvm_mmu_max_gfn()))
			return RET_PF_EMULATE;
	}

	return RET_PF_CONTINUE;
}

static bool page_fault_can_be_fast(struct kvm_page_fault *fault)
{
	/*
	if (fault->rsvd)
		return false;

	/*
	if (!fault->present)
		return !kvm_ad_enabled();

	/*
	return fault->write;
}

static bool
fast_pf_fix_direct_spte(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault,
			u64 *sptep, u64 old_spte, u64 new_spte)
{
	/*
	if (!try_cmpxchg64(sptep, &old_spte, new_spte))
		return false;

	if (is_writable_pte(new_spte) && !is_writable_pte(old_spte))
		mark_page_dirty_in_slot(vcpu->kvm, fault->slot, fault->gfn);

	return true;
}

static bool is_access_allowed(struct kvm_page_fault *fault, u64 spte)
{
	if (fault->exec)
		return is_executable_pte(spte);

	if (fault->write)
		return is_writable_pte(spte);

	/* Fault was on Read access */
	return spte & PT_PRESENT_MASK;
}

static u64 *fast_pf_get_last_sptep(struct kvm_vcpu *vcpu, gpa_t gpa, u64 *spte)
{
	struct kvm_shadow_walk_iterator iterator;
	u64 old_spte;
	u64 *sptep = NULL;

	for_each_shadow_entry_lockless(vcpu, gpa, iterator, old_spte) {
		sptep = iterator.sptep;
		*spte = old_spte;
	}

	return sptep;
}

static int fast_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_mmu_page *sp;
	int ret = RET_PF_INVALID;
	u64 spte = 0ull;
	u64 *sptep = NULL;
	uint retry_count = 0;

	if (!page_fault_can_be_fast(fault))
		return ret;

	walk_shadow_page_lockless_begin(vcpu);

	do {
		u64 new_spte;

		if (is_tdp_mmu(vcpu->arch.mmu))
			sptep = kvm_tdp_mmu_fast_pf_get_last_sptep(vcpu, fault->addr, &spte);
		else
			sptep = fast_pf_get_last_sptep(vcpu, fault->addr, &spte);

		if (!is_shadow_present_pte(spte))
			break;

		sp = sptep_to_sp(sptep);
		if (!is_last_spte(spte, sp->role.level))
			break;

		/*
		if (is_access_allowed(fault, spte)) {
			ret = RET_PF_SPURIOUS;
			break;
		}

		new_spte = spte;

		/*
		if (unlikely(!kvm_ad_enabled()) && is_access_track_spte(spte))
			new_spte = restore_acc_track_spte(new_spte);

		/*
		if (fault->write && is_mmu_writable_spte(spte)) {
			new_spte |= PT_WRITABLE_MASK;

			/*
			if (sp->role.level > PG_LEVEL_4K &&
			    kvm_slot_dirty_track_enabled(fault->slot))
				break;
		}

		/* Verify that the fault can be handled in the fast path */
		if (new_spte == spte ||
		    !is_access_allowed(fault, new_spte))
			break;

		/*
		if (fast_pf_fix_direct_spte(vcpu, fault, sptep, spte, new_spte)) {
			ret = RET_PF_FIXED;
			break;
		}

		if (++retry_count > 4) {
			printk_once(KERN_WARNING
				"kvm: Fast #PF retrying more than 4 times.\n");
			break;
		}

	} while (true);

	trace_fast_page_fault(vcpu, fault, sptep, spte, ret);
	walk_shadow_page_lockless_end(vcpu);

	if (ret != RET_PF_INVALID)
		vcpu->stat.pf_fast++;

	return ret;
}

static void mmu_free_root_page(struct kvm *kvm, hpa_t *root_hpa,
			       struct list_head *invalid_list)
{
	struct kvm_mmu_page *sp;

	if (!VALID_PAGE(*root_hpa))
		return;

	sp = to_shadow_page(*root_hpa & SPTE_BASE_ADDR_MASK);
	if (WARN_ON(!sp))
		return;

	if (is_tdp_mmu_page(sp))
		kvm_tdp_mmu_put_root(kvm, sp, false);
	else if (!--sp->root_count && sp->role.invalid)
		kvm_mmu_prepare_zap_page(kvm, sp, invalid_list);

}

void kvm_mmu_free_roots(struct kvm *kvm, struct kvm_mmu *mmu,
			ulong roots_to_free)
{
	int i;
	LIST_HEAD(invalid_list);
	bool free_active_root;

	BUILD_BUG_ON(KVM_MMU_NUM_PREV_ROOTS >= BITS_PER_LONG);

	/* Before acquiring the MMU lock, see if we need to do any real work. */
	free_active_root = (roots_to_free & KVM_MMU_ROOT_CURRENT)
		&& VALID_PAGE(mmu->root.hpa);

	if (!free_active_root) {
		for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
			if ((roots_to_free & KVM_MMU_ROOT_PREVIOUS(i)) &&
			    VALID_PAGE(mmu->prev_roots[i].hpa))
				break;

		if (i == KVM_MMU_NUM_PREV_ROOTS)
			return;
	}

	write_lock(&kvm->mmu_lock);

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
		if (roots_to_free & KVM_MMU_ROOT_PREVIOUS(i))
			mmu_free_root_page(kvm, &mmu->prev_roots[i].hpa,
					   &invalid_list);

	if (free_active_root) {
		if (to_shadow_page(mmu->root.hpa)) {
			mmu_free_root_page(kvm, &mmu->root.hpa, &invalid_list);
		} else if (mmu->pae_root) {
			for (i = 0; i < 4; ++i) {
				if (!IS_VALID_PAE_ROOT(mmu->pae_root[i]))
					continue;

				mmu_free_root_page(kvm, &mmu->pae_root[i],
						   &invalid_list);
				mmu->pae_root[i] = INVALID_PAE_ROOT;
			}
		}
		mmu->root.hpa = INVALID_PAGE;
		mmu->root.pgd = 0;
	}

	kvm_mmu_commit_zap_page(kvm, &invalid_list);
	write_unlock(&kvm->mmu_lock);
}
EXPORT_SYMBOL_GPL(kvm_mmu_free_roots);

void kvm_mmu_free_guest_mode_roots(struct kvm *kvm, struct kvm_mmu *mmu)
{
	unsigned long roots_to_free = 0;
	hpa_t root_hpa;
	int i;

	/*
	WARN_ON_ONCE(mmu->root_role.guest_mode);

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		root_hpa = mmu->prev_roots[i].hpa;
		if (!VALID_PAGE(root_hpa))
			continue;

		if (!to_shadow_page(root_hpa) ||
			to_shadow_page(root_hpa)->role.guest_mode)
			roots_to_free |= KVM_MMU_ROOT_PREVIOUS(i);
	}

	kvm_mmu_free_roots(kvm, mmu, roots_to_free);
}
EXPORT_SYMBOL_GPL(kvm_mmu_free_guest_mode_roots);


static int mmu_check_root(struct kvm_vcpu *vcpu, gfn_t root_gfn)
{
	int ret = 0;

	if (!kvm_vcpu_is_visible_gfn(vcpu, root_gfn)) {
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		ret = 1;
	}

	return ret;
}

static hpa_t mmu_alloc_root(struct kvm_vcpu *vcpu, gfn_t gfn, int quadrant,
			    u8 level)
{
	union kvm_mmu_page_role role = vcpu->arch.mmu->root_role;
	struct kvm_mmu_page *sp;

	role.level = level;
	role.quadrant = quadrant;

	WARN_ON_ONCE(quadrant && !role.has_4_byte_gpte);
	WARN_ON_ONCE(role.direct && role.has_4_byte_gpte);

	sp = kvm_mmu_get_shadow_page(vcpu, gfn, role);
	++sp->root_count;

	return __pa(sp->spt);
}

static int mmu_alloc_direct_roots(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	u8 shadow_root_level = mmu->root_role.level;
	hpa_t root;
	unsigned i;
	int r;

	write_lock(&vcpu->kvm->mmu_lock);
	r = make_mmu_pages_available(vcpu);
	if (r < 0)
		goto out_unlock;

	if (is_tdp_mmu_enabled(vcpu->kvm)) {
		root = kvm_tdp_mmu_get_vcpu_root_hpa(vcpu);
		mmu->root.hpa = root;
	} else if (shadow_root_level >= PT64_ROOT_4LEVEL) {
		root = mmu_alloc_root(vcpu, 0, 0, shadow_root_level);
		mmu->root.hpa = root;
	} else if (shadow_root_level == PT32E_ROOT_LEVEL) {
		if (WARN_ON_ONCE(!mmu->pae_root)) {
			r = -EIO;
			goto out_unlock;
		}

		for (i = 0; i < 4; ++i) {
			WARN_ON_ONCE(IS_VALID_PAE_ROOT(mmu->pae_root[i]));

			root = mmu_alloc_root(vcpu, i << (30 - PAGE_SHIFT), 0,
					      PT32_ROOT_LEVEL);
			mmu->pae_root[i] = root | PT_PRESENT_MASK |
					   shadow_me_value;
		}
		mmu->root.hpa = __pa(mmu->pae_root);
	} else {
		WARN_ONCE(1, "Bad TDP root level = %d\n", shadow_root_level);
		r = -EIO;
		goto out_unlock;
	}

	/* root.pgd is ignored for direct MMUs. */
	mmu->root.pgd = 0;
out_unlock:
	write_unlock(&vcpu->kvm->mmu_lock);
	return r;
}

static int mmu_first_shadow_root_alloc(struct kvm *kvm)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	int r = 0, i, bkt;

	/*
	if (kvm_shadow_root_allocated(kvm))
		return 0;

	mutex_lock(&kvm->slots_arch_lock);

	/* Recheck, under the lock, whether this is the first shadow root. */
	if (kvm_shadow_root_allocated(kvm))
		goto out_unlock;

	/*
	if (kvm_memslots_have_rmaps(kvm) &&
	    kvm_page_track_write_tracking_enabled(kvm))
		goto out_success;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		slots = __kvm_memslots(kvm, i);
		kvm_for_each_memslot(slot, bkt, slots) {
			/*
			r = memslot_rmap_alloc(slot, slot->npages);
			if (r)
				goto out_unlock;
			r = kvm_page_track_write_tracking_alloc(slot);
			if (r)
				goto out_unlock;
		}
	}

	/*
out_success:
	smp_store_release(&kvm->arch.shadow_root_allocated, true);

out_unlock:
	mutex_unlock(&kvm->slots_arch_lock);
	return r;
}

static int mmu_alloc_shadow_roots(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	u64 pdptrs[4], pm_mask;
	gfn_t root_gfn, root_pgd;
	int quadrant, i, r;
	hpa_t root;

	root_pgd = mmu->get_guest_pgd(vcpu);
	root_gfn = root_pgd >> PAGE_SHIFT;

	if (mmu_check_root(vcpu, root_gfn))
		return 1;

	/*
	if (mmu->cpu_role.base.level == PT32E_ROOT_LEVEL) {
		for (i = 0; i < 4; ++i) {
			pdptrs[i] = mmu->get_pdptr(vcpu, i);
			if (!(pdptrs[i] & PT_PRESENT_MASK))
				continue;

			if (mmu_check_root(vcpu, pdptrs[i] >> PAGE_SHIFT))
				return 1;
		}
	}

	r = mmu_first_shadow_root_alloc(vcpu->kvm);
	if (r)
		return r;

	write_lock(&vcpu->kvm->mmu_lock);
	r = make_mmu_pages_available(vcpu);
	if (r < 0)
		goto out_unlock;

	/*
	if (mmu->cpu_role.base.level >= PT64_ROOT_4LEVEL) {
		root = mmu_alloc_root(vcpu, root_gfn, 0,
				      mmu->root_role.level);
		mmu->root.hpa = root;
		goto set_root_pgd;
	}

	if (WARN_ON_ONCE(!mmu->pae_root)) {
		r = -EIO;
		goto out_unlock;
	}

	/*
	pm_mask = PT_PRESENT_MASK | shadow_me_value;
	if (mmu->root_role.level >= PT64_ROOT_4LEVEL) {
		pm_mask |= PT_ACCESSED_MASK | PT_WRITABLE_MASK | PT_USER_MASK;

		if (WARN_ON_ONCE(!mmu->pml4_root)) {
			r = -EIO;
			goto out_unlock;
		}
		mmu->pml4_root[0] = __pa(mmu->pae_root) | pm_mask;

		if (mmu->root_role.level == PT64_ROOT_5LEVEL) {
			if (WARN_ON_ONCE(!mmu->pml5_root)) {
				r = -EIO;
				goto out_unlock;
			}
			mmu->pml5_root[0] = __pa(mmu->pml4_root) | pm_mask;
		}
	}

	for (i = 0; i < 4; ++i) {
		WARN_ON_ONCE(IS_VALID_PAE_ROOT(mmu->pae_root[i]));

		if (mmu->cpu_role.base.level == PT32E_ROOT_LEVEL) {
			if (!(pdptrs[i] & PT_PRESENT_MASK)) {
				mmu->pae_root[i] = INVALID_PAE_ROOT;
				continue;
			}
			root_gfn = pdptrs[i] >> PAGE_SHIFT;
		}

		/*
		quadrant = (mmu->cpu_role.base.level == PT32_ROOT_LEVEL) ? i : 0;

		root = mmu_alloc_root(vcpu, root_gfn, quadrant, PT32_ROOT_LEVEL);
		mmu->pae_root[i] = root | pm_mask;
	}

	if (mmu->root_role.level == PT64_ROOT_5LEVEL)
		mmu->root.hpa = __pa(mmu->pml5_root);
	else if (mmu->root_role.level == PT64_ROOT_4LEVEL)
		mmu->root.hpa = __pa(mmu->pml4_root);
	else
		mmu->root.hpa = __pa(mmu->pae_root);

set_root_pgd:
	mmu->root.pgd = root_pgd;
out_unlock:
	write_unlock(&vcpu->kvm->mmu_lock);

	return r;
}

static int mmu_alloc_special_roots(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	bool need_pml5 = mmu->root_role.level > PT64_ROOT_4LEVEL;
	u64 *pml5_root = NULL;
	u64 *pml4_root = NULL;
	u64 *pae_root;

	/*
	if (mmu->root_role.direct ||
	    mmu->cpu_role.base.level >= PT64_ROOT_4LEVEL ||
	    mmu->root_role.level < PT64_ROOT_4LEVEL)
		return 0;

	/*
	if (mmu->pae_root && mmu->pml4_root && (!need_pml5 || mmu->pml5_root))
		return 0;

	/*
	if (WARN_ON_ONCE(!tdp_enabled || mmu->pae_root || mmu->pml4_root ||
			 (need_pml5 && mmu->pml5_root)))
		return -EIO;

	/*
	pae_root = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!pae_root)
		return -ENOMEM;

#ifdef CONFIG_X86_64
	pml4_root = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!pml4_root)
		goto err_pml4;

	if (need_pml5) {
		pml5_root = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
		if (!pml5_root)
			goto err_pml5;
	}
#endif

	mmu->pae_root = pae_root;
	mmu->pml4_root = pml4_root;
	mmu->pml5_root = pml5_root;

	return 0;

#ifdef CONFIG_X86_64
err_pml5:
	free_page((unsigned long)pml4_root);
err_pml4:
	free_page((unsigned long)pae_root);
	return -ENOMEM;
#endif
}

static bool is_unsync_root(hpa_t root)
{
	struct kvm_mmu_page *sp;

	if (!VALID_PAGE(root))
		return false;

	/*
	smp_rmb();
	sp = to_shadow_page(root);

	/*
	if (WARN_ON_ONCE(!sp))
		return false;

	if (sp->unsync || sp->unsync_children)
		return true;

	return false;
}

void kvm_mmu_sync_roots(struct kvm_vcpu *vcpu)
{
	int i;
	struct kvm_mmu_page *sp;

	if (vcpu->arch.mmu->root_role.direct)
		return;

	if (!VALID_PAGE(vcpu->arch.mmu->root.hpa))
		return;

	vcpu_clear_mmio_info(vcpu, MMIO_GVA_ANY);

	if (vcpu->arch.mmu->cpu_role.base.level >= PT64_ROOT_4LEVEL) {
		hpa_t root = vcpu->arch.mmu->root.hpa;
		sp = to_shadow_page(root);

		if (!is_unsync_root(root))
			return;

		write_lock(&vcpu->kvm->mmu_lock);
		mmu_sync_children(vcpu, sp, true);
		write_unlock(&vcpu->kvm->mmu_lock);
		return;
	}

	write_lock(&vcpu->kvm->mmu_lock);

	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu->pae_root[i];

		if (IS_VALID_PAE_ROOT(root)) {
			root &= SPTE_BASE_ADDR_MASK;
			sp = to_shadow_page(root);
			mmu_sync_children(vcpu, sp, true);
		}
	}

	write_unlock(&vcpu->kvm->mmu_lock);
}

void kvm_mmu_sync_prev_roots(struct kvm_vcpu *vcpu)
{
	unsigned long roots_to_free = 0;
	int i;

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
		if (is_unsync_root(vcpu->arch.mmu->prev_roots[i].hpa))
			roots_to_free |= KVM_MMU_ROOT_PREVIOUS(i);

	/* sync prev_roots by simply freeing them */
	kvm_mmu_free_roots(vcpu->kvm, vcpu->arch.mmu, roots_to_free);
}

static gpa_t nonpaging_gva_to_gpa(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				  gpa_t vaddr, u64 access,
				  struct x86_exception *exception)
{
	if (exception)
		exception->error_code = 0;
	return kvm_translate_gpa(vcpu, mmu, vaddr, access, exception);
}

static bool mmio_info_in_cache(struct kvm_vcpu *vcpu, u64 addr, bool direct)
{
	/*
	if (mmu_is_nested(vcpu))
		return false;

	if (direct)
		return vcpu_match_mmio_gpa(vcpu, addr);

	return vcpu_match_mmio_gva(vcpu, addr);
}

static int get_walk(struct kvm_vcpu *vcpu, u64 addr, u64 *sptes, int *root_level)
{
	struct kvm_shadow_walk_iterator iterator;
	int leaf = -1;
	u64 spte;

	for (shadow_walk_init(&iterator, vcpu, addr),
	     *root_level = iterator.level;
	     shadow_walk_okay(&iterator);
	     __shadow_walk_next(&iterator, spte)) {
		leaf = iterator.level;
		spte = mmu_spte_get_lockless(iterator.sptep);

		sptes[leaf] = spte;
	}

	return leaf;
}

static bool get_mmio_spte(struct kvm_vcpu *vcpu, u64 addr, u64 *sptep)
{
	u64 sptes[PT64_ROOT_MAX_LEVEL + 1];
	struct rsvd_bits_validate *rsvd_check;
	int root, leaf, level;
	bool reserved = false;

	walk_shadow_page_lockless_begin(vcpu);

	if (is_tdp_mmu(vcpu->arch.mmu))
		leaf = kvm_tdp_mmu_get_walk(vcpu, addr, sptes, &root);
	else
		leaf = get_walk(vcpu, addr, sptes, &root);

	walk_shadow_page_lockless_end(vcpu);

	if (unlikely(leaf < 0)) {
		*sptep = 0ull;
		return reserved;
	}


	/*
	if (!is_shadow_present_pte(sptes[leaf]))
		leaf++;

	rsvd_check = &vcpu->arch.mmu->shadow_zero_check;

	for (level = root; level >= leaf; level--)
		reserved |= is_rsvd_spte(rsvd_check, sptes[level], level);

	if (reserved) {
		pr_err("%s: reserved bits set on MMU-present spte, addr 0x%llx, hierarchy:\n",
		       __func__, addr);
		for (level = root; level >= leaf; level--)
			pr_err("------ spte = 0x%llx level = %d, rsvd bits = 0x%llx",
			       sptes[level], level,
			       get_rsvd_bits(rsvd_check, sptes[level], level));
	}

	return reserved;
}

static int handle_mmio_page_fault(struct kvm_vcpu *vcpu, u64 addr, bool direct)
{
	u64 spte;
	bool reserved;

	if (mmio_info_in_cache(vcpu, addr, direct))
		return RET_PF_EMULATE;

	reserved = get_mmio_spte(vcpu, addr, &spte);
	if (WARN_ON(reserved))
		return -EINVAL;

	if (is_mmio_spte(spte)) {
		gfn_t gfn = get_mmio_spte_gfn(spte);
		unsigned int access = get_mmio_spte_access(spte);

		if (!check_mmio_spte(vcpu, spte))
			return RET_PF_INVALID;

		if (direct)
			addr = 0;

		trace_handle_mmio_page_fault(addr, gfn, access);
		vcpu_cache_mmio_info(vcpu, addr, gfn, access);
		return RET_PF_EMULATE;
	}

	/*
	return RET_PF_RETRY;
}

static bool page_fault_handle_page_track(struct kvm_vcpu *vcpu,
					 struct kvm_page_fault *fault)
{
	if (unlikely(fault->rsvd))
		return false;

	if (!fault->present || !fault->write)
		return false;

	/*
	if (kvm_slot_page_track_is_active(vcpu->kvm, fault->slot, fault->gfn, KVM_PAGE_TRACK_WRITE))
		return true;

	return false;
}

static void shadow_page_table_clear_flood(struct kvm_vcpu *vcpu, gva_t addr)
{
	struct kvm_shadow_walk_iterator iterator;
	u64 spte;

	walk_shadow_page_lockless_begin(vcpu);
	for_each_shadow_entry_lockless(vcpu, addr, iterator, spte)
		clear_sp_write_flooding_count(iterator.sptep);
	walk_shadow_page_lockless_end(vcpu);
}

static u32 alloc_apf_token(struct kvm_vcpu *vcpu)
{
	/* make sure the token value is not 0 */
	u32 id = vcpu->arch.apf.id;

	if (id << 12 == 0)
		vcpu->arch.apf.id = 1;

	return (vcpu->arch.apf.id++ << 12) | vcpu->vcpu_id;
}

static bool kvm_arch_setup_async_pf(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
				    gfn_t gfn)
{
	struct kvm_arch_async_pf arch;

	arch.token = alloc_apf_token(vcpu);
	arch.gfn = gfn;
	arch.direct_map = vcpu->arch.mmu->root_role.direct;
	arch.cr3 = vcpu->arch.mmu->get_guest_pgd(vcpu);

	return kvm_setup_async_pf(vcpu, cr2_or_gpa,
				  kvm_vcpu_gfn_to_hva(vcpu, gfn), &arch);
}

void kvm_arch_async_page_ready(struct kvm_vcpu *vcpu, struct kvm_async_pf *work)
{
	int r;

	if ((vcpu->arch.mmu->root_role.direct != work->arch.direct_map) ||
	      work->wakeup_all)
		return;

	r = kvm_mmu_reload(vcpu);
	if (unlikely(r))
		return;

	if (!vcpu->arch.mmu->root_role.direct &&
	      work->arch.cr3 != vcpu->arch.mmu->get_guest_pgd(vcpu))
		return;

	kvm_mmu_do_page_fault(vcpu, work->cr2_or_gpa, 0, true);
}

static int kvm_faultin_pfn(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_memory_slot *slot = fault->slot;
	bool async;

	/*
	if (slot && (slot->flags & KVM_MEMSLOT_INVALID))
		return RET_PF_RETRY;

	if (!kvm_is_visible_memslot(slot)) {
		/* Don't expose private memslots to L2. */
		if (is_guest_mode(vcpu)) {
			fault->slot = NULL;
			fault->pfn = KVM_PFN_NOSLOT;
			fault->map_writable = false;
			return RET_PF_CONTINUE;
		}
		/*
		if (slot && slot->id == APIC_ACCESS_PAGE_PRIVATE_MEMSLOT &&
		    !kvm_apicv_activated(vcpu->kvm))
			return RET_PF_EMULATE;
	}

	async = false;
	fault->pfn = __gfn_to_pfn_memslot(slot, fault->gfn, false, &async,
					  fault->write, &fault->map_writable,
					  &fault->hva);
	if (!async)
		return RET_PF_CONTINUE; /* *pfn has correct page already */

	if (!fault->prefetch && kvm_can_do_async_pf(vcpu)) {
		trace_kvm_try_async_get_page(fault->addr, fault->gfn);
		if (kvm_find_async_pf_gfn(vcpu, fault->gfn)) {
			trace_kvm_async_pf_repeated_fault(fault->addr, fault->gfn);
			kvm_make_request(KVM_REQ_APF_HALT, vcpu);
			return RET_PF_RETRY;
		} else if (kvm_arch_setup_async_pf(vcpu, fault->addr, fault->gfn)) {
			return RET_PF_RETRY;
		}
	}

	fault->pfn = __gfn_to_pfn_memslot(slot, fault->gfn, false, NULL,
					  fault->write, &fault->map_writable,
					  &fault->hva);
	return RET_PF_CONTINUE;
}

static bool is_page_fault_stale(struct kvm_vcpu *vcpu,
				struct kvm_page_fault *fault, int mmu_seq)
{
	struct kvm_mmu_page *sp = to_shadow_page(vcpu->arch.mmu->root.hpa);

	/* Special roots, e.g. pae_root, are not backed by shadow pages. */
	if (sp && is_obsolete_sp(vcpu->kvm, sp))
		return true;

	/*
	if (!sp && kvm_test_request(KVM_REQ_MMU_FREE_OBSOLETE_ROOTS, vcpu))
		return true;

	return fault->slot &&
	       mmu_notifier_retry_hva(vcpu->kvm, mmu_seq, fault->hva);
}

static int direct_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	bool is_tdp_mmu_fault = is_tdp_mmu(vcpu->arch.mmu);

	unsigned long mmu_seq;
	int r;

	fault->gfn = fault->addr >> PAGE_SHIFT;
	fault->slot = kvm_vcpu_gfn_to_memslot(vcpu, fault->gfn);

	if (page_fault_handle_page_track(vcpu, fault))
		return RET_PF_EMULATE;

	r = fast_page_fault(vcpu, fault);
	if (r != RET_PF_INVALID)
		return r;

	r = mmu_topup_memory_caches(vcpu, false);
	if (r)
		return r;

	mmu_seq = vcpu->kvm->mmu_notifier_seq;
	smp_rmb();

	r = kvm_faultin_pfn(vcpu, fault);
	if (r != RET_PF_CONTINUE)
		return r;

	r = handle_abnormal_pfn(vcpu, fault, ACC_ALL);
	if (r != RET_PF_CONTINUE)
		return r;

	r = RET_PF_RETRY;

	if (is_tdp_mmu_fault)
		read_lock(&vcpu->kvm->mmu_lock);
	else
		write_lock(&vcpu->kvm->mmu_lock);

	if (is_page_fault_stale(vcpu, fault, mmu_seq))
		goto out_unlock;

	r = make_mmu_pages_available(vcpu);
	if (r)
		goto out_unlock;

	if (is_tdp_mmu_fault)
		r = kvm_tdp_mmu_map(vcpu, fault);
	else
		r = __direct_map(vcpu, fault);

out_unlock:
	if (is_tdp_mmu_fault)
		read_unlock(&vcpu->kvm->mmu_lock);
	else
		write_unlock(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(fault->pfn);
	return r;
}

static int nonpaging_page_fault(struct kvm_vcpu *vcpu,
				struct kvm_page_fault *fault)
{
	pgprintk("%s: gva %lx error %x\n", __func__, fault->addr, fault->error_code);

	/* This path builds a PAE pagetable, we can map 2mb pages at maximum. */
	fault->max_level = PG_LEVEL_2M;
	return direct_page_fault(vcpu, fault);
}

int kvm_handle_page_fault(struct kvm_vcpu *vcpu, u64 error_code,
				u64 fault_address, char *insn, int insn_len)
{
	int r = 1;
	u32 flags = vcpu->arch.apf.host_apf_flags;

#ifndef CONFIG_X86_64
	/* A 64-bit CR2 should be impossible on 32-bit KVM. */
	if (WARN_ON_ONCE(fault_address >> 32))
		return -EFAULT;
#endif

	vcpu->arch.l1tf_flush_l1d = true;
	if (!flags) {
		trace_kvm_page_fault(fault_address, error_code);

		if (kvm_event_needs_reinjection(vcpu))
			kvm_mmu_unprotect_page_virt(vcpu, fault_address);
		r = kvm_mmu_page_fault(vcpu, fault_address, error_code, insn,
				insn_len);
	} else if (flags & KVM_PV_REASON_PAGE_NOT_PRESENT) {
		vcpu->arch.apf.host_apf_flags = 0;
		local_irq_disable();
		kvm_async_pf_task_wait_schedule(fault_address);
		local_irq_enable();
	} else {
		WARN_ONCE(1, "Unexpected host async PF flags: %x\n", flags);
	}

	return r;
}
EXPORT_SYMBOL_GPL(kvm_handle_page_fault);

int kvm_tdp_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	/*
	if (shadow_memtype_mask && kvm_arch_has_noncoherent_dma(vcpu->kvm)) {
		for ( ; fault->max_level > PG_LEVEL_4K; --fault->max_level) {
			int page_num = KVM_PAGES_PER_HPAGE(fault->max_level);
			gfn_t base = (fault->addr >> PAGE_SHIFT) & ~(page_num - 1);

			if (kvm_mtrr_check_gfn_range_consistency(vcpu, base, page_num))
				break;
		}
	}

	return direct_page_fault(vcpu, fault);
}

static void nonpaging_init_context(struct kvm_mmu *context)
{
	context->page_fault = nonpaging_page_fault;
	context->gva_to_gpa = nonpaging_gva_to_gpa;
	context->sync_page = nonpaging_sync_page;
	context->invlpg = NULL;
}

static inline bool is_root_usable(struct kvm_mmu_root_info *root, gpa_t pgd,
				  union kvm_mmu_page_role role)
{
	return (role.direct || pgd == root->pgd) &&
	       VALID_PAGE(root->hpa) &&
	       role.word == to_shadow_page(root->hpa)->role.word;
}

static bool cached_root_find_and_keep_current(struct kvm *kvm, struct kvm_mmu *mmu,
					      gpa_t new_pgd,
					      union kvm_mmu_page_role new_role)
{
	uint i;

	if (is_root_usable(&mmu->root, new_pgd, new_role))
		return true;

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		/*
		swap(mmu->root, mmu->prev_roots[i]);
		if (is_root_usable(&mmu->root, new_pgd, new_role))
			return true;
	}

	kvm_mmu_free_roots(kvm, mmu, KVM_MMU_ROOT_CURRENT);
	return false;
}

static bool cached_root_find_without_current(struct kvm *kvm, struct kvm_mmu *mmu,
					     gpa_t new_pgd,
					     union kvm_mmu_page_role new_role)
{
	uint i;

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
		if (is_root_usable(&mmu->prev_roots[i], new_pgd, new_role))
			goto hit;

	return false;

hit:
	swap(mmu->root, mmu->prev_roots[i]);
	/* Bubble up the remaining roots.  */
	for (; i < KVM_MMU_NUM_PREV_ROOTS - 1; i++)
		mmu->prev_roots[i] = mmu->prev_roots[i + 1];
	mmu->prev_roots[i].hpa = INVALID_PAGE;
	return true;
}

static bool fast_pgd_switch(struct kvm *kvm, struct kvm_mmu *mmu,
			    gpa_t new_pgd, union kvm_mmu_page_role new_role)
{
	/*
	if (VALID_PAGE(mmu->root.hpa) && !to_shadow_page(mmu->root.hpa))
		kvm_mmu_free_roots(kvm, mmu, KVM_MMU_ROOT_CURRENT);

	if (VALID_PAGE(mmu->root.hpa))
		return cached_root_find_and_keep_current(kvm, mmu, new_pgd, new_role);
	else
		return cached_root_find_without_current(kvm, mmu, new_pgd, new_role);
}

void kvm_mmu_new_pgd(struct kvm_vcpu *vcpu, gpa_t new_pgd)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	union kvm_mmu_page_role new_role = mmu->root_role;

	if (!fast_pgd_switch(vcpu->kvm, mmu, new_pgd, new_role)) {
		/* kvm_mmu_ensure_valid_pgd will set up a new root.  */
		return;
	}

	/*
	kvm_make_request(KVM_REQ_LOAD_MMU_PGD, vcpu);

	if (force_flush_and_sync_on_reuse) {
		kvm_make_request(KVM_REQ_MMU_SYNC, vcpu);
		kvm_make_request(KVM_REQ_TLB_FLUSH_CURRENT, vcpu);
	}

	/*
	vcpu_clear_mmio_info(vcpu, MMIO_GVA_ANY);

	/*
	if (!new_role.direct)
		__clear_sp_write_flooding_count(
				to_shadow_page(vcpu->arch.mmu->root.hpa));
}
EXPORT_SYMBOL_GPL(kvm_mmu_new_pgd);

static unsigned long get_cr3(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr3(vcpu);
}

static bool sync_mmio_spte(struct kvm_vcpu *vcpu, u64 *sptep, gfn_t gfn,
			   unsigned int access)
{
	if (unlikely(is_mmio_spte(*sptep))) {
		if (gfn != get_mmio_spte_gfn(*sptep)) {
			mmu_spte_clear_no_track(sptep);
			return true;
		}

		mark_mmio_spte(vcpu, sptep, gfn, access);
		return true;
	}

	return false;
}

#define PTTYPE_EPT 18 /* arbitrary */
#define PTTYPE PTTYPE_EPT
#include "paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 64
#include "paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 32
#include "paging_tmpl.h"
#undef PTTYPE

static void
__reset_rsvds_bits_mask(struct rsvd_bits_validate *rsvd_check,
			u64 pa_bits_rsvd, int level, bool nx, bool gbpages,
			bool pse, bool amd)
{
	u64 gbpages_bit_rsvd = 0;
	u64 nonleaf_bit8_rsvd = 0;
	u64 high_bits_rsvd;

	rsvd_check->bad_mt_xwr = 0;

	if (!gbpages)
		gbpages_bit_rsvd = rsvd_bits(7, 7);

	if (level == PT32E_ROOT_LEVEL)
		high_bits_rsvd = pa_bits_rsvd & rsvd_bits(0, 62);
	else
		high_bits_rsvd = pa_bits_rsvd & rsvd_bits(0, 51);

	/* Note, NX doesn't exist in PDPTEs, this is handled below. */
	if (!nx)
		high_bits_rsvd |= rsvd_bits(63, 63);

	/*
	if (amd)
		nonleaf_bit8_rsvd = rsvd_bits(8, 8);

	switch (level) {
	case PT32_ROOT_LEVEL:
		/* no rsvd bits for 2 level 4K page table entries */
		rsvd_check->rsvd_bits_mask[0][1] = 0;
		rsvd_check->rsvd_bits_mask[0][0] = 0;
		rsvd_check->rsvd_bits_mask[1][0] =
			rsvd_check->rsvd_bits_mask[0][0];

		if (!pse) {
			rsvd_check->rsvd_bits_mask[1][1] = 0;
			break;
		}

		if (is_cpuid_PSE36())
			/* 36bits PSE 4MB page */
			rsvd_check->rsvd_bits_mask[1][1] = rsvd_bits(17, 21);
		else
			/* 32 bits PSE 4MB page */
			rsvd_check->rsvd_bits_mask[1][1] = rsvd_bits(13, 21);
		break;
	case PT32E_ROOT_LEVEL:
		rsvd_check->rsvd_bits_mask[0][2] = rsvd_bits(63, 63) |
						   high_bits_rsvd |
						   rsvd_bits(5, 8) |
						   rsvd_bits(1, 2);	/* PDPTE */
		rsvd_check->rsvd_bits_mask[0][1] = high_bits_rsvd;	/* PDE */
		rsvd_check->rsvd_bits_mask[0][0] = high_bits_rsvd;	/* PTE */
		rsvd_check->rsvd_bits_mask[1][1] = high_bits_rsvd |
						   rsvd_bits(13, 20);	/* large page */
		rsvd_check->rsvd_bits_mask[1][0] =
			rsvd_check->rsvd_bits_mask[0][0];
		break;
	case PT64_ROOT_5LEVEL:
		rsvd_check->rsvd_bits_mask[0][4] = high_bits_rsvd |
						   nonleaf_bit8_rsvd |
						   rsvd_bits(7, 7);
		rsvd_check->rsvd_bits_mask[1][4] =
			rsvd_check->rsvd_bits_mask[0][4];
		fallthrough;
	case PT64_ROOT_4LEVEL:
		rsvd_check->rsvd_bits_mask[0][3] = high_bits_rsvd |
						   nonleaf_bit8_rsvd |
						   rsvd_bits(7, 7);
		rsvd_check->rsvd_bits_mask[0][2] = high_bits_rsvd |
						   gbpages_bit_rsvd;
		rsvd_check->rsvd_bits_mask[0][1] = high_bits_rsvd;
		rsvd_check->rsvd_bits_mask[0][0] = high_bits_rsvd;
		rsvd_check->rsvd_bits_mask[1][3] =
			rsvd_check->rsvd_bits_mask[0][3];
		rsvd_check->rsvd_bits_mask[1][2] = high_bits_rsvd |
						   gbpages_bit_rsvd |
						   rsvd_bits(13, 29);
		rsvd_check->rsvd_bits_mask[1][1] = high_bits_rsvd |
						   rsvd_bits(13, 20); /* large page */
		rsvd_check->rsvd_bits_mask[1][0] =
			rsvd_check->rsvd_bits_mask[0][0];
		break;
	}
}

static bool guest_can_use_gbpages(struct kvm_vcpu *vcpu)
{
	/*
	return tdp_enabled ? boot_cpu_has(X86_FEATURE_GBPAGES) :
			     guest_cpuid_has(vcpu, X86_FEATURE_GBPAGES);
}

static void reset_guest_rsvds_bits_mask(struct kvm_vcpu *vcpu,
					struct kvm_mmu *context)
{
	__reset_rsvds_bits_mask(&context->guest_rsvd_check,
				vcpu->arch.reserved_gpa_bits,
				context->cpu_role.base.level, is_efer_nx(context),
				guest_can_use_gbpages(vcpu),
				is_cr4_pse(context),
				guest_cpuid_is_amd_or_hygon(vcpu));
}

static void
__reset_rsvds_bits_mask_ept(struct rsvd_bits_validate *rsvd_check,
			    u64 pa_bits_rsvd, bool execonly, int huge_page_level)
{
	u64 high_bits_rsvd = pa_bits_rsvd & rsvd_bits(0, 51);
	u64 large_1g_rsvd = 0, large_2m_rsvd = 0;
	u64 bad_mt_xwr;

	if (huge_page_level < PG_LEVEL_1G)
		large_1g_rsvd = rsvd_bits(7, 7);
	if (huge_page_level < PG_LEVEL_2M)
		large_2m_rsvd = rsvd_bits(7, 7);

	rsvd_check->rsvd_bits_mask[0][4] = high_bits_rsvd | rsvd_bits(3, 7);
	rsvd_check->rsvd_bits_mask[0][3] = high_bits_rsvd | rsvd_bits(3, 7);
	rsvd_check->rsvd_bits_mask[0][2] = high_bits_rsvd | rsvd_bits(3, 6) | large_1g_rsvd;
	rsvd_check->rsvd_bits_mask[0][1] = high_bits_rsvd | rsvd_bits(3, 6) | large_2m_rsvd;
	rsvd_check->rsvd_bits_mask[0][0] = high_bits_rsvd;

	/* large page */
	rsvd_check->rsvd_bits_mask[1][4] = rsvd_check->rsvd_bits_mask[0][4];
	rsvd_check->rsvd_bits_mask[1][3] = rsvd_check->rsvd_bits_mask[0][3];
	rsvd_check->rsvd_bits_mask[1][2] = high_bits_rsvd | rsvd_bits(12, 29) | large_1g_rsvd;
	rsvd_check->rsvd_bits_mask[1][1] = high_bits_rsvd | rsvd_bits(12, 20) | large_2m_rsvd;
	rsvd_check->rsvd_bits_mask[1][0] = rsvd_check->rsvd_bits_mask[0][0];

	bad_mt_xwr = 0xFFull << (2 * 8);	/* bits 3..5 must not be 2 */
	bad_mt_xwr |= 0xFFull << (3 * 8);	/* bits 3..5 must not be 3 */
	bad_mt_xwr |= 0xFFull << (7 * 8);	/* bits 3..5 must not be 7 */
	bad_mt_xwr |= REPEAT_BYTE(1ull << 2);	/* bits 0..2 must not be 010 */
	bad_mt_xwr |= REPEAT_BYTE(1ull << 6);	/* bits 0..2 must not be 110 */
	if (!execonly) {
		/* bits 0..2 must not be 100 unless VMX capabilities allow it */
		bad_mt_xwr |= REPEAT_BYTE(1ull << 4);
	}
	rsvd_check->bad_mt_xwr = bad_mt_xwr;
}

static void reset_rsvds_bits_mask_ept(struct kvm_vcpu *vcpu,
		struct kvm_mmu *context, bool execonly, int huge_page_level)
{
	__reset_rsvds_bits_mask_ept(&context->guest_rsvd_check,
				    vcpu->arch.reserved_gpa_bits, execonly,
				    huge_page_level);
}

static inline u64 reserved_hpa_bits(void)
{
	return rsvd_bits(shadow_phys_bits, 63);
}

static void reset_shadow_zero_bits_mask(struct kvm_vcpu *vcpu,
					struct kvm_mmu *context)
{
	/* @amd adds a check on bit of SPTEs, which KVM shouldn't use anyways. */
	bool is_amd = true;
	/* KVM doesn't use 2-level page tables for the shadow MMU. */
	bool is_pse = false;
	struct rsvd_bits_validate *shadow_zero_check;
	int i;

	WARN_ON_ONCE(context->root_role.level < PT32E_ROOT_LEVEL);

	shadow_zero_check = &context->shadow_zero_check;
	__reset_rsvds_bits_mask(shadow_zero_check, reserved_hpa_bits(),
				context->root_role.level,
				context->root_role.efer_nx,
				guest_can_use_gbpages(vcpu), is_pse, is_amd);

	if (!shadow_me_mask)
		return;

	for (i = context->root_role.level; --i >= 0;) {
		/*
		shadow_zero_check->rsvd_bits_mask[0][i] |= shadow_me_mask;
		shadow_zero_check->rsvd_bits_mask[1][i] |= shadow_me_mask;
		shadow_zero_check->rsvd_bits_mask[0][i] &= ~shadow_me_value;
		shadow_zero_check->rsvd_bits_mask[1][i] &= ~shadow_me_value;
	}

}

static inline bool boot_cpu_is_amd(void)
{
	WARN_ON_ONCE(!tdp_enabled);
	return shadow_x_mask == 0;
}

static void
reset_tdp_shadow_zero_bits_mask(struct kvm_mmu *context)
{
	struct rsvd_bits_validate *shadow_zero_check;
	int i;

	shadow_zero_check = &context->shadow_zero_check;

	if (boot_cpu_is_amd())
		__reset_rsvds_bits_mask(shadow_zero_check, reserved_hpa_bits(),
					context->root_role.level, true,
					boot_cpu_has(X86_FEATURE_GBPAGES),
					false, true);
	else
		__reset_rsvds_bits_mask_ept(shadow_zero_check,
					    reserved_hpa_bits(), false,
					    max_huge_page_level);

	if (!shadow_me_mask)
		return;

	for (i = context->root_role.level; --i >= 0;) {
		shadow_zero_check->rsvd_bits_mask[0][i] &= ~shadow_me_mask;
		shadow_zero_check->rsvd_bits_mask[1][i] &= ~shadow_me_mask;
	}
}

static void
reset_ept_shadow_zero_bits_mask(struct kvm_mmu *context, bool execonly)
{
	__reset_rsvds_bits_mask_ept(&context->shadow_zero_check,
				    reserved_hpa_bits(), execonly,
				    max_huge_page_level);
}

#define BYTE_MASK(access) \
	((1 & (access) ? 2 : 0) | \
	 (2 & (access) ? 4 : 0) | \
	 (3 & (access) ? 8 : 0) | \
	 (4 & (access) ? 16 : 0) | \
	 (5 & (access) ? 32 : 0) | \
	 (6 & (access) ? 64 : 0) | \
	 (7 & (access) ? 128 : 0))


static void update_permission_bitmask(struct kvm_mmu *mmu, bool ept)
{
	unsigned byte;

	const u8 x = BYTE_MASK(ACC_EXEC_MASK);
	const u8 w = BYTE_MASK(ACC_WRITE_MASK);
	const u8 u = BYTE_MASK(ACC_USER_MASK);

	bool cr4_smep = is_cr4_smep(mmu);
	bool cr4_smap = is_cr4_smap(mmu);
	bool cr0_wp = is_cr0_wp(mmu);
	bool efer_nx = is_efer_nx(mmu);

	for (byte = 0; byte < ARRAY_SIZE(mmu->permissions); ++byte) {
		unsigned pfec = byte << 1;

		/*

		/* Faults from writes to non-writable pages */
		u8 wf = (pfec & PFERR_WRITE_MASK) ? (u8)~w : 0;
		/* Faults from user mode accesses to supervisor pages */
		u8 uf = (pfec & PFERR_USER_MASK) ? (u8)~u : 0;
		/* Faults from fetches of non-executable pages*/
		u8 ff = (pfec & PFERR_FETCH_MASK) ? (u8)~x : 0;
		/* Faults from kernel mode fetches of user pages */
		u8 smepf = 0;
		/* Faults from kernel mode accesses of user pages */
		u8 smapf = 0;

		if (!ept) {
			/* Faults from kernel mode accesses to user pages */
			u8 kf = (pfec & PFERR_USER_MASK) ? 0 : u;

			/* Not really needed: !nx will cause pte.nx to fault */
			if (!efer_nx)
				ff = 0;

			/* Allow supervisor writes if !cr0.wp */
			if (!cr0_wp)
				wf = (pfec & PFERR_USER_MASK) ? wf : 0;

			/* Disallow supervisor fetches of user code if cr4.smep */
			if (cr4_smep)
				smepf = (pfec & PFERR_FETCH_MASK) ? kf : 0;

			/*
			if (cr4_smap)
				smapf = (pfec & (PFERR_RSVD_MASK|PFERR_FETCH_MASK)) ? 0 : kf;
		}

		mmu->permissions[byte] = ff | uf | wf | smepf | smapf;
	}
}

static void update_pkru_bitmask(struct kvm_mmu *mmu)
{
	unsigned bit;
	bool wp;

	mmu->pkru_mask = 0;

	if (!is_cr4_pke(mmu))
		return;

	wp = is_cr0_wp(mmu);

	for (bit = 0; bit < ARRAY_SIZE(mmu->permissions); ++bit) {
		unsigned pfec, pkey_bits;
		bool check_pkey, check_write, ff, uf, wf, pte_user;

		pfec = bit << 1;
		ff = pfec & PFERR_FETCH_MASK;
		uf = pfec & PFERR_USER_MASK;
		wf = pfec & PFERR_WRITE_MASK;

		/* PFEC.RSVD is replaced by ACC_USER_MASK. */
		pte_user = pfec & PFERR_RSVD_MASK;

		/*
		check_pkey = (!ff && pte_user);
		/*
		check_write = check_pkey && wf && (uf || wp);

		/* PKRU.AD stops both read and write access. */
		pkey_bits = !!check_pkey;
		/* PKRU.WD stops write access. */
		pkey_bits |= (!!check_write) << 1;

		mmu->pkru_mask |= (pkey_bits & 3) << pfec;
	}
}

static void reset_guest_paging_metadata(struct kvm_vcpu *vcpu,
					struct kvm_mmu *mmu)
{
	if (!is_cr0_pg(mmu))
		return;

	reset_guest_rsvds_bits_mask(vcpu, mmu);
	update_permission_bitmask(mmu, false);
	update_pkru_bitmask(mmu);
}

static void paging64_init_context(struct kvm_mmu *context)
{
	context->page_fault = paging64_page_fault;
	context->gva_to_gpa = paging64_gva_to_gpa;
	context->sync_page = paging64_sync_page;
	context->invlpg = paging64_invlpg;
}

static void paging32_init_context(struct kvm_mmu *context)
{
	context->page_fault = paging32_page_fault;
	context->gva_to_gpa = paging32_gva_to_gpa;
	context->sync_page = paging32_sync_page;
	context->invlpg = paging32_invlpg;
}

static union kvm_cpu_role
kvm_calc_cpu_role(struct kvm_vcpu *vcpu, const struct kvm_mmu_role_regs *regs)
{
	union kvm_cpu_role role = {0};

	role.base.access = ACC_ALL;
	role.base.smm = is_smm(vcpu);
	role.base.guest_mode = is_guest_mode(vcpu);
	role.ext.valid = 1;

	if (!____is_cr0_pg(regs)) {
		role.base.direct = 1;
		return role;
	}

	role.base.efer_nx = ____is_efer_nx(regs);
	role.base.cr0_wp = ____is_cr0_wp(regs);
	role.base.smep_andnot_wp = ____is_cr4_smep(regs) && !____is_cr0_wp(regs);
	role.base.smap_andnot_wp = ____is_cr4_smap(regs) && !____is_cr0_wp(regs);
	role.base.has_4_byte_gpte = !____is_cr4_pae(regs);

	if (____is_efer_lma(regs))
		role.base.level = ____is_cr4_la57(regs) ? PT64_ROOT_5LEVEL
							: PT64_ROOT_4LEVEL;
	else if (____is_cr4_pae(regs))
		role.base.level = PT32E_ROOT_LEVEL;
	else
		role.base.level = PT32_ROOT_LEVEL;

	role.ext.cr4_smep = ____is_cr4_smep(regs);
	role.ext.cr4_smap = ____is_cr4_smap(regs);
	role.ext.cr4_pse = ____is_cr4_pse(regs);

	/* PKEY and LA57 are active iff long mode is active. */
	role.ext.cr4_pke = ____is_efer_lma(regs) && ____is_cr4_pke(regs);
	role.ext.cr4_la57 = ____is_efer_lma(regs) && ____is_cr4_la57(regs);
	role.ext.efer_lma = ____is_efer_lma(regs);
	return role;
}

static inline int kvm_mmu_get_tdp_level(struct kvm_vcpu *vcpu)
{
	/* tdp_root_level is architecture forced level, use it if nonzero */
	if (tdp_root_level)
		return tdp_root_level;

	/* Use 5-level TDP if and only if it's useful/necessary. */
	if (max_tdp_level == 5 && cpuid_maxphyaddr(vcpu) <= 48)
		return 4;

	return max_tdp_level;
}

static union kvm_mmu_page_role
kvm_calc_tdp_mmu_root_page_role(struct kvm_vcpu *vcpu,
				union kvm_cpu_role cpu_role)
{
	union kvm_mmu_page_role role = {0};

	role.access = ACC_ALL;
	role.cr0_wp = true;
	role.efer_nx = true;
	role.smm = cpu_role.base.smm;
	role.guest_mode = cpu_role.base.guest_mode;
	role.ad_disabled = !kvm_ad_enabled();
	role.level = kvm_mmu_get_tdp_level(vcpu);
	role.direct = true;
	role.has_4_byte_gpte = false;

	return role;
}

static void init_kvm_tdp_mmu(struct kvm_vcpu *vcpu,
			     union kvm_cpu_role cpu_role)
{
	struct kvm_mmu *context = &vcpu->arch.root_mmu;
	union kvm_mmu_page_role root_role = kvm_calc_tdp_mmu_root_page_role(vcpu, cpu_role);

	if (cpu_role.as_u64 == context->cpu_role.as_u64 &&
	    root_role.word == context->root_role.word)
		return;

	context->cpu_role.as_u64 = cpu_role.as_u64;
	context->root_role.word = root_role.word;
	context->page_fault = kvm_tdp_page_fault;
	context->sync_page = nonpaging_sync_page;
	context->invlpg = NULL;
	context->get_guest_pgd = get_cr3;
	context->get_pdptr = kvm_pdptr_read;
	context->inject_page_fault = kvm_inject_page_fault;

	if (!is_cr0_pg(context))
		context->gva_to_gpa = nonpaging_gva_to_gpa;
	else if (is_cr4_pae(context))
		context->gva_to_gpa = paging64_gva_to_gpa;
	else
		context->gva_to_gpa = paging32_gva_to_gpa;

	reset_guest_paging_metadata(vcpu, context);
	reset_tdp_shadow_zero_bits_mask(context);
}

static void shadow_mmu_init_context(struct kvm_vcpu *vcpu, struct kvm_mmu *context,
				    union kvm_cpu_role cpu_role,
				    union kvm_mmu_page_role root_role)
{
	if (cpu_role.as_u64 == context->cpu_role.as_u64 &&
	    root_role.word == context->root_role.word)
		return;

	context->cpu_role.as_u64 = cpu_role.as_u64;
	context->root_role.word = root_role.word;

	if (!is_cr0_pg(context))
		nonpaging_init_context(context);
	else if (is_cr4_pae(context))
		paging64_init_context(context);
	else
		paging32_init_context(context);

	reset_guest_paging_metadata(vcpu, context);
	reset_shadow_zero_bits_mask(vcpu, context);
}

static void kvm_init_shadow_mmu(struct kvm_vcpu *vcpu,
				union kvm_cpu_role cpu_role)
{
	struct kvm_mmu *context = &vcpu->arch.root_mmu;
	union kvm_mmu_page_role root_role;

	root_role = cpu_role.base;

	/* KVM uses PAE paging whenever the guest isn't using 64-bit paging. */
	root_role.level = max_t(u32, root_role.level, PT32E_ROOT_LEVEL);

	/*
	root_role.efer_nx = true;

	shadow_mmu_init_context(vcpu, context, cpu_role, root_role);
}

void kvm_init_shadow_npt_mmu(struct kvm_vcpu *vcpu, unsigned long cr0,
			     unsigned long cr4, u64 efer, gpa_t nested_cr3)
{
	struct kvm_mmu *context = &vcpu->arch.guest_mmu;
	struct kvm_mmu_role_regs regs = {
		.cr0 = cr0,
		.cr4 = cr4 & ~X86_CR4_PKE,
		.efer = efer,
	};
	union kvm_cpu_role cpu_role = kvm_calc_cpu_role(vcpu, &regs);
	union kvm_mmu_page_role root_role;

	/* NPT requires CR0.PG=1. */
	WARN_ON_ONCE(cpu_role.base.direct);

	root_role = cpu_role.base;
	root_role.level = kvm_mmu_get_tdp_level(vcpu);
	if (root_role.level == PT64_ROOT_5LEVEL &&
	    cpu_role.base.level == PT64_ROOT_4LEVEL)
		root_role.passthrough = 1;

	shadow_mmu_init_context(vcpu, context, cpu_role, root_role);
	kvm_mmu_new_pgd(vcpu, nested_cr3);
}
EXPORT_SYMBOL_GPL(kvm_init_shadow_npt_mmu);

static union kvm_cpu_role
kvm_calc_shadow_ept_root_page_role(struct kvm_vcpu *vcpu, bool accessed_dirty,
				   bool execonly, u8 level)
{
	union kvm_cpu_role role = {0};

	/*
	WARN_ON_ONCE(is_smm(vcpu));
	role.base.level = level;
	role.base.has_4_byte_gpte = false;
	role.base.direct = false;
	role.base.ad_disabled = !accessed_dirty;
	role.base.guest_mode = true;
	role.base.access = ACC_ALL;

	role.ext.word = 0;
	role.ext.execonly = execonly;
	role.ext.valid = 1;

	return role;
}

void kvm_init_shadow_ept_mmu(struct kvm_vcpu *vcpu, bool execonly,
			     int huge_page_level, bool accessed_dirty,
			     gpa_t new_eptp)
{
	struct kvm_mmu *context = &vcpu->arch.guest_mmu;
	u8 level = vmx_eptp_page_walk_level(new_eptp);
	union kvm_cpu_role new_mode =
		kvm_calc_shadow_ept_root_page_role(vcpu, accessed_dirty,
						   execonly, level);

	if (new_mode.as_u64 != context->cpu_role.as_u64) {
		/* EPT, and thus nested EPT, does not consume CR0, CR4, nor EFER. */
		context->cpu_role.as_u64 = new_mode.as_u64;
		context->root_role.word = new_mode.base.word;

		context->page_fault = ept_page_fault;
		context->gva_to_gpa = ept_gva_to_gpa;
		context->sync_page = ept_sync_page;
		context->invlpg = ept_invlpg;

		update_permission_bitmask(context, true);
		context->pkru_mask = 0;
		reset_rsvds_bits_mask_ept(vcpu, context, execonly, huge_page_level);
		reset_ept_shadow_zero_bits_mask(context, execonly);
	}

	kvm_mmu_new_pgd(vcpu, new_eptp);
}
EXPORT_SYMBOL_GPL(kvm_init_shadow_ept_mmu);

static void init_kvm_softmmu(struct kvm_vcpu *vcpu,
			     union kvm_cpu_role cpu_role)
{
	struct kvm_mmu *context = &vcpu->arch.root_mmu;

	kvm_init_shadow_mmu(vcpu, cpu_role);

	context->get_guest_pgd     = get_cr3;
	context->get_pdptr         = kvm_pdptr_read;
	context->inject_page_fault = kvm_inject_page_fault;
}

static void init_kvm_nested_mmu(struct kvm_vcpu *vcpu,
				union kvm_cpu_role new_mode)
{
	struct kvm_mmu *g_context = &vcpu->arch.nested_mmu;

	if (new_mode.as_u64 == g_context->cpu_role.as_u64)
		return;

	g_context->cpu_role.as_u64   = new_mode.as_u64;
	g_context->get_guest_pgd     = get_cr3;
	g_context->get_pdptr         = kvm_pdptr_read;
	g_context->inject_page_fault = kvm_inject_page_fault;

	/*
	g_context->invlpg            = NULL;

	/*
	if (!is_paging(vcpu))
		g_context->gva_to_gpa = nonpaging_gva_to_gpa;
	else if (is_long_mode(vcpu))
		g_context->gva_to_gpa = paging64_gva_to_gpa;
	else if (is_pae(vcpu))
		g_context->gva_to_gpa = paging64_gva_to_gpa;
	else
		g_context->gva_to_gpa = paging32_gva_to_gpa;

	reset_guest_paging_metadata(vcpu, g_context);
}

void kvm_init_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_role_regs regs = vcpu_to_role_regs(vcpu);
	union kvm_cpu_role cpu_role = kvm_calc_cpu_role(vcpu, &regs);

	if (mmu_is_nested(vcpu))
		init_kvm_nested_mmu(vcpu, cpu_role);
	else if (tdp_enabled)
		init_kvm_tdp_mmu(vcpu, cpu_role);
	else
		init_kvm_softmmu(vcpu, cpu_role);
}
EXPORT_SYMBOL_GPL(kvm_init_mmu);

void kvm_mmu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
	/*
	vcpu->arch.root_mmu.root_role.word = 0;
	vcpu->arch.guest_mmu.root_role.word = 0;
	vcpu->arch.nested_mmu.root_role.word = 0;
	vcpu->arch.root_mmu.cpu_role.ext.valid = 0;
	vcpu->arch.guest_mmu.cpu_role.ext.valid = 0;
	vcpu->arch.nested_mmu.cpu_role.ext.valid = 0;
	kvm_mmu_reset_context(vcpu);

	/*
	KVM_BUG_ON(vcpu->arch.last_vmentry_cpu != -1, vcpu->kvm);
}

void kvm_mmu_reset_context(struct kvm_vcpu *vcpu)
{
	kvm_mmu_unload(vcpu);
	kvm_init_mmu(vcpu);
}
EXPORT_SYMBOL_GPL(kvm_mmu_reset_context);

int kvm_mmu_load(struct kvm_vcpu *vcpu)
{
	int r;

	r = mmu_topup_memory_caches(vcpu, !vcpu->arch.mmu->root_role.direct);
	if (r)
		goto out;
	r = mmu_alloc_special_roots(vcpu);
	if (r)
		goto out;
	if (vcpu->arch.mmu->root_role.direct)
		r = mmu_alloc_direct_roots(vcpu);
	else
		r = mmu_alloc_shadow_roots(vcpu);
	if (r)
		goto out;

	kvm_mmu_sync_roots(vcpu);

	kvm_mmu_load_pgd(vcpu);

	/*
	static_call(kvm_x86_flush_tlb_current)(vcpu);
out:
	return r;
}

void kvm_mmu_unload(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;

	kvm_mmu_free_roots(kvm, &vcpu->arch.root_mmu, KVM_MMU_ROOTS_ALL);
	WARN_ON(VALID_PAGE(vcpu->arch.root_mmu.root.hpa));
	kvm_mmu_free_roots(kvm, &vcpu->arch.guest_mmu, KVM_MMU_ROOTS_ALL);
	WARN_ON(VALID_PAGE(vcpu->arch.guest_mmu.root.hpa));
	vcpu_clear_mmio_info(vcpu, MMIO_GVA_ANY);
}

static bool is_obsolete_root(struct kvm *kvm, hpa_t root_hpa)
{
	struct kvm_mmu_page *sp;

	if (!VALID_PAGE(root_hpa))
		return false;

	/*
	sp = to_shadow_page(root_hpa);
	return !sp || is_obsolete_sp(kvm, sp);
}

static void __kvm_mmu_free_obsolete_roots(struct kvm *kvm, struct kvm_mmu *mmu)
{
	unsigned long roots_to_free = 0;
	int i;

	if (is_obsolete_root(kvm, mmu->root.hpa))
		roots_to_free |= KVM_MMU_ROOT_CURRENT;

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		if (is_obsolete_root(kvm, mmu->prev_roots[i].hpa))
			roots_to_free |= KVM_MMU_ROOT_PREVIOUS(i);
	}

	if (roots_to_free)
		kvm_mmu_free_roots(kvm, mmu, roots_to_free);
}

void kvm_mmu_free_obsolete_roots(struct kvm_vcpu *vcpu)
{
	__kvm_mmu_free_obsolete_roots(vcpu->kvm, &vcpu->arch.root_mmu);
	__kvm_mmu_free_obsolete_roots(vcpu->kvm, &vcpu->arch.guest_mmu);
}

static bool need_remote_flush(u64 old, u64 new)
{
	if (!is_shadow_present_pte(old))
		return false;
	if (!is_shadow_present_pte(new))
		return true;
	if ((old ^ new) & SPTE_BASE_ADDR_MASK)
		return true;
	old ^= shadow_nx_mask;
	new ^= shadow_nx_mask;
	return (old & ~new & SPTE_PERM_MASK) != 0;
}

static u64 mmu_pte_write_fetch_gpte(struct kvm_vcpu *vcpu, gpa_t *gpa,
				    int *bytes)
{
	u64 gentry = 0;
	int r;

	/*
	if (is_pae(vcpu) && *bytes == 4) {
		/* Handle a 32-bit guest writing two halves of a 64-bit gpte */
		*gpa &= ~(gpa_t)7;
		*bytes = 8;
	}

	if (*bytes == 4 || *bytes == 8) {
		r = kvm_vcpu_read_guest_atomic(vcpu, *gpa, &gentry, *bytes);
		if (r)
			gentry = 0;
	}

	return gentry;
}

static bool detect_write_flooding(struct kvm_mmu_page *sp)
{
	/*
	if (sp->role.level == PG_LEVEL_4K)
		return false;

	atomic_inc(&sp->write_flooding_count);
	return atomic_read(&sp->write_flooding_count) >= 3;
}

static bool detect_write_misaligned(struct kvm_mmu_page *sp, gpa_t gpa,
				    int bytes)
{
	unsigned offset, pte_size, misaligned;

	pgprintk("misaligned: gpa %llx bytes %d role %x\n",
		 gpa, bytes, sp->role.word);

	offset = offset_in_page(gpa);
	pte_size = sp->role.has_4_byte_gpte ? 4 : 8;

	/*
	if (!(offset & (pte_size - 1)) && bytes == 1)
		return false;

	misaligned = (offset ^ (offset + bytes - 1)) & ~(pte_size - 1);
	misaligned |= bytes < 4;

	return misaligned;
}

static u64 *get_written_sptes(struct kvm_mmu_page *sp, gpa_t gpa, int *nspte)
{
	unsigned page_offset, quadrant;
	u64 *spte;
	int level;

	page_offset = offset_in_page(gpa);
	level = sp->role.level;
	if (sp->role.has_4_byte_gpte) {
		page_offset <<= 1;	/* 32->64 */
		/*
		if (level == PT32_ROOT_LEVEL) {
			page_offset &= ~7; /* kill rounding error */
			page_offset <<= 1;
			*nspte = 2;
		}
		quadrant = page_offset >> PAGE_SHIFT;
		page_offset &= ~PAGE_MASK;
		if (quadrant != sp->role.quadrant)
			return NULL;
	}

	spte = &sp->spt[page_offset / sizeof(*spte)];
	return spte;
}

static void kvm_mmu_pte_write(struct kvm_vcpu *vcpu, gpa_t gpa,
			      const u8 *new, int bytes,
			      struct kvm_page_track_notifier_node *node)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);
	u64 entry, gentry, *spte;
	int npte;
	bool flush = false;

	/*
	if (!READ_ONCE(vcpu->kvm->arch.indirect_shadow_pages))
		return;

	pgprintk("%s: gpa %llx bytes %d\n", __func__, gpa, bytes);

	write_lock(&vcpu->kvm->mmu_lock);

	gentry = mmu_pte_write_fetch_gpte(vcpu, &gpa, &bytes);

	++vcpu->kvm->stat.mmu_pte_write;

	for_each_gfn_valid_sp_with_gptes(vcpu->kvm, sp, gfn) {
		if (detect_write_misaligned(sp, gpa, bytes) ||
		      detect_write_flooding(sp)) {
			kvm_mmu_prepare_zap_page(vcpu->kvm, sp, &invalid_list);
			++vcpu->kvm->stat.mmu_flooded;
			continue;
		}

		spte = get_written_sptes(sp, gpa, &npte);
		if (!spte)
			continue;

		while (npte--) {
			entry = *spte;
			mmu_page_zap_pte(vcpu->kvm, sp, spte, NULL);
			if (gentry && sp->role.level != PG_LEVEL_4K)
				++vcpu->kvm->stat.mmu_pde_zapped;
			if (need_remote_flush(entry, *spte))
				flush = true;
			++spte;
		}
	}
	kvm_mmu_remote_flush_or_zap(vcpu->kvm, &invalid_list, flush);
	write_unlock(&vcpu->kvm->mmu_lock);
}

int noinline kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa, u64 error_code,
		       void *insn, int insn_len)
{
	int r, emulation_type = EMULTYPE_PF;
	bool direct = vcpu->arch.mmu->root_role.direct;

	if (WARN_ON(!VALID_PAGE(vcpu->arch.mmu->root.hpa)))
		return RET_PF_RETRY;

	r = RET_PF_INVALID;
	if (unlikely(error_code & PFERR_RSVD_MASK)) {
		r = handle_mmio_page_fault(vcpu, cr2_or_gpa, direct);
		if (r == RET_PF_EMULATE)
			goto emulate;
	}

	if (r == RET_PF_INVALID) {
		r = kvm_mmu_do_page_fault(vcpu, cr2_or_gpa,
					  lower_32_bits(error_code), false);
		if (KVM_BUG_ON(r == RET_PF_INVALID, vcpu->kvm))
			return -EIO;
	}

	if (r < 0)
		return r;
	if (r != RET_PF_EMULATE)
		return 1;

	/*
	if (vcpu->arch.mmu->root_role.direct &&
	    (error_code & PFERR_NESTED_GUEST_PAGE) == PFERR_NESTED_GUEST_PAGE) {
		kvm_mmu_unprotect_page(vcpu->kvm, gpa_to_gfn(cr2_or_gpa));
		return 1;
	}

	/*
	if (!mmio_info_in_cache(vcpu, cr2_or_gpa, direct) && !is_guest_mode(vcpu))
		emulation_type |= EMULTYPE_ALLOW_RETRY_PF;
emulate:
	return x86_emulate_instruction(vcpu, cr2_or_gpa, emulation_type, insn,
				       insn_len);
}
EXPORT_SYMBOL_GPL(kvm_mmu_page_fault);

void kvm_mmu_invalidate_gva(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
			    gva_t gva, hpa_t root_hpa)
{
	int i;

	/* It's actually a GPA for vcpu->arch.guest_mmu.  */
	if (mmu != &vcpu->arch.guest_mmu) {
		/* INVLPG on a non-canonical address is a NOP according to the SDM.  */
		if (is_noncanonical_address(gva, vcpu))
			return;

		static_call(kvm_x86_flush_tlb_gva)(vcpu, gva);
	}

	if (!mmu->invlpg)
		return;

	if (root_hpa == INVALID_PAGE) {
		mmu->invlpg(vcpu, gva, mmu->root.hpa);

		/*
		for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
			if (VALID_PAGE(mmu->prev_roots[i].hpa))
				mmu->invlpg(vcpu, gva, mmu->prev_roots[i].hpa);
	} else {
		mmu->invlpg(vcpu, gva, root_hpa);
	}
}

void kvm_mmu_invlpg(struct kvm_vcpu *vcpu, gva_t gva)
{
	kvm_mmu_invalidate_gva(vcpu, vcpu->arch.walk_mmu, gva, INVALID_PAGE);
	++vcpu->stat.invlpg;
}
EXPORT_SYMBOL_GPL(kvm_mmu_invlpg);


void kvm_mmu_invpcid_gva(struct kvm_vcpu *vcpu, gva_t gva, unsigned long pcid)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	bool tlb_flush = false;
	uint i;

	if (pcid == kvm_get_active_pcid(vcpu)) {
		if (mmu->invlpg)
			mmu->invlpg(vcpu, gva, mmu->root.hpa);
		tlb_flush = true;
	}

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		if (VALID_PAGE(mmu->prev_roots[i].hpa) &&
		    pcid == kvm_get_pcid(vcpu, mmu->prev_roots[i].pgd)) {
			if (mmu->invlpg)
				mmu->invlpg(vcpu, gva, mmu->prev_roots[i].hpa);
			tlb_flush = true;
		}
	}

	if (tlb_flush)
		static_call(kvm_x86_flush_tlb_gva)(vcpu, gva);

	++vcpu->stat.invlpg;

	/*
}

void kvm_configure_mmu(bool enable_tdp, int tdp_forced_root_level,
		       int tdp_max_root_level, int tdp_huge_page_level)
{
	tdp_enabled = enable_tdp;
	tdp_root_level = tdp_forced_root_level;
	max_tdp_level = tdp_max_root_level;

	/*
	if (tdp_enabled)
		max_huge_page_level = tdp_huge_page_level;
	else if (boot_cpu_has(X86_FEATURE_GBPAGES))
		max_huge_page_level = PG_LEVEL_1G;
	else
		max_huge_page_level = PG_LEVEL_2M;
}
EXPORT_SYMBOL_GPL(kvm_configure_mmu);

typedef bool (*slot_level_handler) (struct kvm *kvm,
				    struct kvm_rmap_head *rmap_head,
				    const struct kvm_memory_slot *slot);

static __always_inline bool
slot_handle_level_range(struct kvm *kvm, const struct kvm_memory_slot *memslot,
			slot_level_handler fn, int start_level, int end_level,
			gfn_t start_gfn, gfn_t end_gfn, bool flush_on_yield,
			bool flush)
{
	struct slot_rmap_walk_iterator iterator;

	for_each_slot_rmap_range(memslot, start_level, end_level, start_gfn,
			end_gfn, &iterator) {
		if (iterator.rmap)
			flush |= fn(kvm, iterator.rmap, memslot);

		if (need_resched() || rwlock_needbreak(&kvm->mmu_lock)) {
			if (flush && flush_on_yield) {
				kvm_flush_remote_tlbs_with_address(kvm,
						start_gfn,
						iterator.gfn - start_gfn + 1);
				flush = false;
			}
			cond_resched_rwlock_write(&kvm->mmu_lock);
		}
	}

	return flush;
}

static __always_inline bool
slot_handle_level(struct kvm *kvm, const struct kvm_memory_slot *memslot,
		  slot_level_handler fn, int start_level, int end_level,
		  bool flush_on_yield)
{
	return slot_handle_level_range(kvm, memslot, fn, start_level,
			end_level, memslot->base_gfn,
			memslot->base_gfn + memslot->npages - 1,
			flush_on_yield, false);
}

static __always_inline bool
slot_handle_level_4k(struct kvm *kvm, const struct kvm_memory_slot *memslot,
		     slot_level_handler fn, bool flush_on_yield)
{
	return slot_handle_level(kvm, memslot, fn, PG_LEVEL_4K,
				 PG_LEVEL_4K, flush_on_yield);
}

static void free_mmu_pages(struct kvm_mmu *mmu)
{
	if (!tdp_enabled && mmu->pae_root)
		set_memory_encrypted((unsigned long)mmu->pae_root, 1);
	free_page((unsigned long)mmu->pae_root);
	free_page((unsigned long)mmu->pml4_root);
	free_page((unsigned long)mmu->pml5_root);
}

static int __kvm_mmu_create(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu)
{
	struct page *page;
	int i;

	mmu->root.hpa = INVALID_PAGE;
	mmu->root.pgd = 0;
	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
		mmu->prev_roots[i] = KVM_MMU_ROOT_INFO_INVALID;

	/* vcpu->arch.guest_mmu isn't used when !tdp_enabled. */
	if (!tdp_enabled && mmu == &vcpu->arch.guest_mmu)
		return 0;

	/*
	if (tdp_enabled && kvm_mmu_get_tdp_level(vcpu) > PT32E_ROOT_LEVEL)
		return 0;

	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_DMA32);
	if (!page)
		return -ENOMEM;

	mmu->pae_root = page_address(page);

	/*
	if (!tdp_enabled)
		set_memory_decrypted((unsigned long)mmu->pae_root, 1);
	else
		WARN_ON_ONCE(shadow_me_value);

	for (i = 0; i < 4; ++i)
		mmu->pae_root[i] = INVALID_PAE_ROOT;

	return 0;
}

int kvm_mmu_create(struct kvm_vcpu *vcpu)
{
	int ret;

	vcpu->arch.mmu_pte_list_desc_cache.kmem_cache = pte_list_desc_cache;
	vcpu->arch.mmu_pte_list_desc_cache.gfp_zero = __GFP_ZERO;

	vcpu->arch.mmu_page_header_cache.kmem_cache = mmu_page_header_cache;
	vcpu->arch.mmu_page_header_cache.gfp_zero = __GFP_ZERO;

	vcpu->arch.mmu_shadow_page_cache.gfp_zero = __GFP_ZERO;

	vcpu->arch.mmu = &vcpu->arch.root_mmu;
	vcpu->arch.walk_mmu = &vcpu->arch.root_mmu;

	ret = __kvm_mmu_create(vcpu, &vcpu->arch.guest_mmu);
	if (ret)
		return ret;

	ret = __kvm_mmu_create(vcpu, &vcpu->arch.root_mmu);
	if (ret)
		goto fail_allocate_root;

	return ret;
 fail_allocate_root:
	free_mmu_pages(&vcpu->arch.guest_mmu);
	return ret;
}

#define BATCH_ZAP_PAGES	10
static void kvm_zap_obsolete_pages(struct kvm *kvm)
{
	struct kvm_mmu_page *sp, *node;
	int nr_zapped, batch = 0;
	bool unstable;

restart:
	list_for_each_entry_safe_reverse(sp, node,
	      &kvm->arch.active_mmu_pages, link) {
		/*
		if (!is_obsolete_sp(kvm, sp))
			break;

		/*
		if (WARN_ON(sp->role.invalid))
			continue;

		/*
		if (batch >= BATCH_ZAP_PAGES &&
		    cond_resched_rwlock_write(&kvm->mmu_lock)) {
			batch = 0;
			goto restart;
		}

		unstable = __kvm_mmu_prepare_zap_page(kvm, sp,
				&kvm->arch.zapped_obsolete_pages, &nr_zapped);
		batch += nr_zapped;

		if (unstable)
			goto restart;
	}

	/*
	kvm_mmu_commit_zap_page(kvm, &kvm->arch.zapped_obsolete_pages);
}

static void kvm_mmu_zap_all_fast(struct kvm *kvm)
{
	lockdep_assert_held(&kvm->slots_lock);

	write_lock(&kvm->mmu_lock);
	trace_kvm_mmu_zap_all_fast(kvm);

	/*
	kvm->arch.mmu_valid_gen = kvm->arch.mmu_valid_gen ? 0 : 1;

	/*
	if (is_tdp_mmu_enabled(kvm))
		kvm_tdp_mmu_invalidate_all_roots(kvm);

	/*
	kvm_make_all_cpus_request(kvm, KVM_REQ_MMU_FREE_OBSOLETE_ROOTS);

	kvm_zap_obsolete_pages(kvm);

	write_unlock(&kvm->mmu_lock);

	/*
	if (is_tdp_mmu_enabled(kvm))
		kvm_tdp_mmu_zap_invalidated_roots(kvm);
}

static bool kvm_has_zapped_obsolete_pages(struct kvm *kvm)
{
	return unlikely(!list_empty_careful(&kvm->arch.zapped_obsolete_pages));
}

static void kvm_mmu_invalidate_zap_pages_in_memslot(struct kvm *kvm,
			struct kvm_memory_slot *slot,
			struct kvm_page_track_notifier_node *node)
{
	kvm_mmu_zap_all_fast(kvm);
}

int kvm_mmu_init_vm(struct kvm *kvm)
{
	struct kvm_page_track_notifier_node *node = &kvm->arch.mmu_sp_tracker;
	int r;

	INIT_LIST_HEAD(&kvm->arch.active_mmu_pages);
	INIT_LIST_HEAD(&kvm->arch.zapped_obsolete_pages);
	INIT_LIST_HEAD(&kvm->arch.lpage_disallowed_mmu_pages);
	spin_lock_init(&kvm->arch.mmu_unsync_pages_lock);

	r = kvm_mmu_init_tdp_mmu(kvm);
	if (r < 0)
		return r;

	node->track_write = kvm_mmu_pte_write;
	node->track_flush_slot = kvm_mmu_invalidate_zap_pages_in_memslot;
	kvm_page_track_register_notifier(kvm, node);

	kvm->arch.split_page_header_cache.kmem_cache = mmu_page_header_cache;
	kvm->arch.split_page_header_cache.gfp_zero = __GFP_ZERO;

	kvm->arch.split_shadow_page_cache.gfp_zero = __GFP_ZERO;

	kvm->arch.split_desc_cache.kmem_cache = pte_list_desc_cache;
	kvm->arch.split_desc_cache.gfp_zero = __GFP_ZERO;

	return 0;
}

static void mmu_free_vm_memory_caches(struct kvm *kvm)
{
	kvm_mmu_free_memory_cache(&kvm->arch.split_desc_cache);
	kvm_mmu_free_memory_cache(&kvm->arch.split_page_header_cache);
	kvm_mmu_free_memory_cache(&kvm->arch.split_shadow_page_cache);
}

void kvm_mmu_uninit_vm(struct kvm *kvm)
{
	struct kvm_page_track_notifier_node *node = &kvm->arch.mmu_sp_tracker;

	kvm_page_track_unregister_notifier(kvm, node);

	kvm_mmu_uninit_tdp_mmu(kvm);

	mmu_free_vm_memory_caches(kvm);
}

static bool kvm_rmap_zap_gfn_range(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end)
{
	const struct kvm_memory_slot *memslot;
	struct kvm_memslots *slots;
	struct kvm_memslot_iter iter;
	bool flush = false;
	gfn_t start, end;
	int i;

	if (!kvm_memslots_have_rmaps(kvm))
		return flush;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		slots = __kvm_memslots(kvm, i);

		kvm_for_each_memslot_in_gfn_range(&iter, slots, gfn_start, gfn_end) {
			memslot = iter.slot;
			start = max(gfn_start, memslot->base_gfn);
			end = min(gfn_end, memslot->base_gfn + memslot->npages);
			if (WARN_ON_ONCE(start >= end))
				continue;

			flush = slot_handle_level_range(kvm, memslot, __kvm_zap_rmap,
							PG_LEVEL_4K, KVM_MAX_HUGEPAGE_LEVEL,
							start, end - 1, true, flush);
		}
	}

	return flush;
}

void kvm_zap_gfn_range(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end)
{
	bool flush;
	int i;

	if (WARN_ON_ONCE(gfn_end <= gfn_start))
		return;

	write_lock(&kvm->mmu_lock);

	kvm_inc_notifier_count(kvm, gfn_start, gfn_end);

	flush = kvm_rmap_zap_gfn_range(kvm, gfn_start, gfn_end);

	if (is_tdp_mmu_enabled(kvm)) {
		for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++)
			flush = kvm_tdp_mmu_zap_leafs(kvm, i, gfn_start,
						      gfn_end, true, flush);
	}

	if (flush)
		kvm_flush_remote_tlbs_with_address(kvm, gfn_start,
						   gfn_end - gfn_start);

	kvm_dec_notifier_count(kvm, gfn_start, gfn_end);

	write_unlock(&kvm->mmu_lock);
}

static bool slot_rmap_write_protect(struct kvm *kvm,
				    struct kvm_rmap_head *rmap_head,
				    const struct kvm_memory_slot *slot)
{
	return rmap_write_protect(rmap_head, false);
}

void kvm_mmu_slot_remove_write_access(struct kvm *kvm,
				      const struct kvm_memory_slot *memslot,
				      int start_level)
{
	bool flush = false;

	if (kvm_memslots_have_rmaps(kvm)) {
		write_lock(&kvm->mmu_lock);
		flush = slot_handle_level(kvm, memslot, slot_rmap_write_protect,
					  start_level, KVM_MAX_HUGEPAGE_LEVEL,
					  false);
		write_unlock(&kvm->mmu_lock);
	}

	if (is_tdp_mmu_enabled(kvm)) {
		read_lock(&kvm->mmu_lock);
		flush |= kvm_tdp_mmu_wrprot_slot(kvm, memslot, start_level);
		read_unlock(&kvm->mmu_lock);
	}

	/*
	if (flush)
		kvm_arch_flush_remote_tlbs_memslot(kvm, memslot);
}

static inline bool need_topup(struct kvm_mmu_memory_cache *cache, int min)
{
	return kvm_mmu_memory_cache_nr_free_objects(cache) < min;
}

static bool need_topup_split_caches_or_resched(struct kvm *kvm)
{
	if (need_resched() || rwlock_needbreak(&kvm->mmu_lock))
		return true;

	/*
	return need_topup(&kvm->arch.split_desc_cache, SPLIT_DESC_CACHE_MIN_NR_OBJECTS) ||
	       need_topup(&kvm->arch.split_page_header_cache, 1) ||
	       need_topup(&kvm->arch.split_shadow_page_cache, 1);
}

static int topup_split_caches(struct kvm *kvm)
{
	/*
	const int capacity = SPLIT_DESC_CACHE_MIN_NR_OBJECTS +
			     KVM_ARCH_NR_OBJS_PER_MEMORY_CACHE;
	int r;

	lockdep_assert_held(&kvm->slots_lock);

	r = __kvm_mmu_topup_memory_cache(&kvm->arch.split_desc_cache, capacity,
					 SPLIT_DESC_CACHE_MIN_NR_OBJECTS);
	if (r)
		return r;

	r = kvm_mmu_topup_memory_cache(&kvm->arch.split_page_header_cache, 1);
	if (r)
		return r;

	return kvm_mmu_topup_memory_cache(&kvm->arch.split_shadow_page_cache, 1);
}

static struct kvm_mmu_page *shadow_mmu_get_sp_for_split(struct kvm *kvm, u64 *huge_sptep)
{
	struct kvm_mmu_page *huge_sp = sptep_to_sp(huge_sptep);
	struct shadow_page_caches caches = {};
	union kvm_mmu_page_role role;
	unsigned int access;
	gfn_t gfn;

	gfn = kvm_mmu_page_get_gfn(huge_sp, spte_index(huge_sptep));
	access = kvm_mmu_page_get_access(huge_sp, spte_index(huge_sptep));

	/*
	role = kvm_mmu_child_role(huge_sptep, /*direct=*/true, access);

	/* Direct SPs do not require a shadowed_info_cache. */
	caches.page_header_cache = &kvm->arch.split_page_header_cache;
	caches.shadow_page_cache = &kvm->arch.split_shadow_page_cache;

	/* Safe to pass NULL for vCPU since requesting a direct SP. */
	return __kvm_mmu_get_shadow_page(kvm, NULL, &caches, gfn, role);
}

static void shadow_mmu_split_huge_page(struct kvm *kvm,
				       const struct kvm_memory_slot *slot,
				       u64 *huge_sptep)

{
	struct kvm_mmu_memory_cache *cache = &kvm->arch.split_desc_cache;
	u64 huge_spte = READ_ONCE(*huge_sptep);
	struct kvm_mmu_page *sp;
	bool flush = false;
	u64 *sptep, spte;
	gfn_t gfn;
	int index;

	sp = shadow_mmu_get_sp_for_split(kvm, huge_sptep);

	for (index = 0; index < SPTE_ENT_PER_PAGE; index++) {
		sptep = &sp->spt[index];
		gfn = kvm_mmu_page_get_gfn(sp, index);

		/*
		if (is_shadow_present_pte(*sptep)) {
			flush |= !is_last_spte(*sptep, sp->role.level);
			continue;
		}

		spte = make_huge_page_split_spte(kvm, huge_spte, sp->role, index);
		mmu_spte_set(sptep, spte);
		__rmap_add(kvm, cache, slot, sptep, gfn, sp->role.access);
	}

	__link_shadow_page(kvm, cache, huge_sptep, sp, flush);
}

static int shadow_mmu_try_split_huge_page(struct kvm *kvm,
					  const struct kvm_memory_slot *slot,
					  u64 *huge_sptep)
{
	struct kvm_mmu_page *huge_sp = sptep_to_sp(huge_sptep);
	int level, r = 0;
	gfn_t gfn;
	u64 spte;

	/* Grab information for the tracepoint before dropping the MMU lock. */
	gfn = kvm_mmu_page_get_gfn(huge_sp, spte_index(huge_sptep));
	level = huge_sp->role.level;
	spte = *huge_sptep;

	if (kvm_mmu_available_pages(kvm) <= KVM_MIN_FREE_MMU_PAGES) {
		r = -ENOSPC;
		goto out;
	}

	if (need_topup_split_caches_or_resched(kvm)) {
		write_unlock(&kvm->mmu_lock);
		cond_resched();
		/*
		r = topup_split_caches(kvm) ?: -EAGAIN;
		write_lock(&kvm->mmu_lock);
		goto out;
	}

	shadow_mmu_split_huge_page(kvm, slot, huge_sptep);

out:
	trace_kvm_mmu_split_huge_page(gfn, spte, level, r);
	return r;
}

static bool shadow_mmu_try_split_huge_pages(struct kvm *kvm,
					    struct kvm_rmap_head *rmap_head,
					    const struct kvm_memory_slot *slot)
{
	struct rmap_iterator iter;
	struct kvm_mmu_page *sp;
	u64 *huge_sptep;
	int r;

restart:
	for_each_rmap_spte(rmap_head, &iter, huge_sptep) {
		sp = sptep_to_sp(huge_sptep);

		/* TDP MMU is enabled, so rmap only contains nested MMU SPs. */
		if (WARN_ON_ONCE(!sp->role.guest_mode))
			continue;

		/* The rmaps should never contain non-leaf SPTEs. */
		if (WARN_ON_ONCE(!is_large_pte(*huge_sptep)))
			continue;

		/* SPs with level >PG_LEVEL_4K should never by unsync. */
		if (WARN_ON_ONCE(sp->unsync))
			continue;

		/* Don't bother splitting huge pages on invalid SPs. */
		if (sp->role.invalid)
			continue;

		r = shadow_mmu_try_split_huge_page(kvm, slot, huge_sptep);

		/*
		if (!r || r == -EAGAIN)
			goto restart;

		/* The split failed and shouldn't be retried (e.g. -ENOMEM). */
		break;
	}

	return false;
}

static void kvm_shadow_mmu_try_split_huge_pages(struct kvm *kvm,
						const struct kvm_memory_slot *slot,
						gfn_t start, gfn_t end,
						int target_level)
{
	int level;

	/*
	for (level = KVM_MAX_HUGEPAGE_LEVEL; level > target_level; level--) {
		slot_handle_level_range(kvm, slot, shadow_mmu_try_split_huge_pages,
					level, level, start, end - 1, true, false);
	}
}

void kvm_mmu_try_split_huge_pages(struct kvm *kvm,
				   const struct kvm_memory_slot *memslot,
				   u64 start, u64 end,
				   int target_level)
{
	if (!is_tdp_mmu_enabled(kvm))
		return;

	if (kvm_memslots_have_rmaps(kvm))
		kvm_shadow_mmu_try_split_huge_pages(kvm, memslot, start, end, target_level);

	kvm_tdp_mmu_try_split_huge_pages(kvm, memslot, start, end, target_level, false);

	/*
}

void kvm_mmu_slot_try_split_huge_pages(struct kvm *kvm,
					const struct kvm_memory_slot *memslot,
					int target_level)
{
	u64 start = memslot->base_gfn;
	u64 end = start + memslot->npages;

	if (!is_tdp_mmu_enabled(kvm))
		return;

	if (kvm_memslots_have_rmaps(kvm)) {
		write_lock(&kvm->mmu_lock);
		kvm_shadow_mmu_try_split_huge_pages(kvm, memslot, start, end, target_level);
		write_unlock(&kvm->mmu_lock);
	}

	read_lock(&kvm->mmu_lock);
	kvm_tdp_mmu_try_split_huge_pages(kvm, memslot, start, end, target_level, true);
	read_unlock(&kvm->mmu_lock);

	/*
}

static bool kvm_mmu_zap_collapsible_spte(struct kvm *kvm,
					 struct kvm_rmap_head *rmap_head,
					 const struct kvm_memory_slot *slot)
{
	u64 *sptep;
	struct rmap_iterator iter;
	int need_tlb_flush = 0;
	struct kvm_mmu_page *sp;

restart:
	for_each_rmap_spte(rmap_head, &iter, sptep) {
		sp = sptep_to_sp(sptep);

		/*
		if (sp->role.direct &&
		    sp->role.level < kvm_mmu_max_mapping_level(kvm, slot, sp->gfn,
							       PG_LEVEL_NUM)) {
			kvm_zap_one_rmap_spte(kvm, rmap_head, sptep);

			if (kvm_available_flush_tlb_with_range())
				kvm_flush_remote_tlbs_with_address(kvm, sp->gfn,
					KVM_PAGES_PER_HPAGE(sp->role.level));
			else
				need_tlb_flush = 1;

			goto restart;
		}
	}

	return need_tlb_flush;
}

static void kvm_rmap_zap_collapsible_sptes(struct kvm *kvm,
					   const struct kvm_memory_slot *slot)
{
	/*
	if (slot_handle_level(kvm, slot, kvm_mmu_zap_collapsible_spte,
			      PG_LEVEL_4K, KVM_MAX_HUGEPAGE_LEVEL - 1, true))
		kvm_arch_flush_remote_tlbs_memslot(kvm, slot);
}

void kvm_mmu_zap_collapsible_sptes(struct kvm *kvm,
				   const struct kvm_memory_slot *slot)
{
	if (kvm_memslots_have_rmaps(kvm)) {
		write_lock(&kvm->mmu_lock);
		kvm_rmap_zap_collapsible_sptes(kvm, slot);
		write_unlock(&kvm->mmu_lock);
	}

	if (is_tdp_mmu_enabled(kvm)) {
		read_lock(&kvm->mmu_lock);
		kvm_tdp_mmu_zap_collapsible_sptes(kvm, slot);
		read_unlock(&kvm->mmu_lock);
	}
}

void kvm_arch_flush_remote_tlbs_memslot(struct kvm *kvm,
					const struct kvm_memory_slot *memslot)
{
	/*
	lockdep_assert_held(&kvm->slots_lock);
	kvm_flush_remote_tlbs_with_address(kvm, memslot->base_gfn,
					   memslot->npages);
}

void kvm_mmu_slot_leaf_clear_dirty(struct kvm *kvm,
				   const struct kvm_memory_slot *memslot)
{
	bool flush = false;

	if (kvm_memslots_have_rmaps(kvm)) {
		write_lock(&kvm->mmu_lock);
		/*
		flush = slot_handle_level_4k(kvm, memslot, __rmap_clear_dirty, false);
		write_unlock(&kvm->mmu_lock);
	}

	if (is_tdp_mmu_enabled(kvm)) {
		read_lock(&kvm->mmu_lock);
		flush |= kvm_tdp_mmu_clear_dirty_slot(kvm, memslot);
		read_unlock(&kvm->mmu_lock);
	}

	/*
	if (flush)
		kvm_arch_flush_remote_tlbs_memslot(kvm, memslot);
}

void kvm_mmu_zap_all(struct kvm *kvm)
{
	struct kvm_mmu_page *sp, *node;
	LIST_HEAD(invalid_list);
	int ign;

	write_lock(&kvm->mmu_lock);
restart:
	list_for_each_entry_safe(sp, node, &kvm->arch.active_mmu_pages, link) {
		if (WARN_ON(sp->role.invalid))
			continue;
		if (__kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list, &ign))
			goto restart;
		if (cond_resched_rwlock_write(&kvm->mmu_lock))
			goto restart;
	}

	kvm_mmu_commit_zap_page(kvm, &invalid_list);

	if (is_tdp_mmu_enabled(kvm))
		kvm_tdp_mmu_zap_all(kvm);

	write_unlock(&kvm->mmu_lock);
}

void kvm_mmu_invalidate_mmio_sptes(struct kvm *kvm, u64 gen)
{
	WARN_ON(gen & KVM_MEMSLOT_GEN_UPDATE_IN_PROGRESS);

	gen &= MMIO_SPTE_GEN_MASK;

	/*
	gen &= ~((u64)KVM_ADDRESS_SPACE_NUM - 1);

	/*
	if (unlikely(gen == 0)) {
		kvm_debug_ratelimited("kvm: zapping shadow pages for mmio generation wraparound\n");
		kvm_mmu_zap_all_fast(kvm);
	}
}

static unsigned long
mmu_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	struct kvm *kvm;
	int nr_to_scan = sc->nr_to_scan;
	unsigned long freed = 0;

	mutex_lock(&kvm_lock);

	list_for_each_entry(kvm, &vm_list, vm_list) {
		int idx;
		LIST_HEAD(invalid_list);

		/*
		if (!nr_to_scan--)
			break;
		/*
		if (!kvm->arch.n_used_mmu_pages &&
		    !kvm_has_zapped_obsolete_pages(kvm))
			continue;

		idx = srcu_read_lock(&kvm->srcu);
		write_lock(&kvm->mmu_lock);

		if (kvm_has_zapped_obsolete_pages(kvm)) {
			kvm_mmu_commit_zap_page(kvm,
			      &kvm->arch.zapped_obsolete_pages);
			goto unlock;
		}

		freed = kvm_mmu_zap_oldest_mmu_pages(kvm, sc->nr_to_scan);

unlock:
		write_unlock(&kvm->mmu_lock);
		srcu_read_unlock(&kvm->srcu, idx);

		/*
		list_move_tail(&kvm->vm_list, &vm_list);
		break;
	}

	mutex_unlock(&kvm_lock);
	return freed;
}

static unsigned long
mmu_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	return percpu_counter_read_positive(&kvm_total_used_mmu_pages);
}

static struct shrinker mmu_shrinker = {
	.count_objects = mmu_shrink_count,
	.scan_objects = mmu_shrink_scan,
	.seeks = DEFAULT_SEEKS * 10,
};

static void mmu_destroy_caches(void)
{
	kmem_cache_destroy(pte_list_desc_cache);
	kmem_cache_destroy(mmu_page_header_cache);
}

static bool get_nx_auto_mode(void)
{
	/* Return true when CPU has the bug, and mitigations are ON */
	return boot_cpu_has_bug(X86_BUG_ITLB_MULTIHIT) && !cpu_mitigations_off();
}

static void __set_nx_huge_pages(bool val)
{
	nx_huge_pages = itlb_multihit_kvm_mitigation = val;
}

static int set_nx_huge_pages(const char *val, const struct kernel_param *kp)
{
	bool old_val = nx_huge_pages;
	bool new_val;

	/* In "auto" mode deploy workaround only if CPU has the bug. */
	if (sysfs_streq(val, "off"))
		new_val = 0;
	else if (sysfs_streq(val, "force"))
		new_val = 1;
	else if (sysfs_streq(val, "auto"))
		new_val = get_nx_auto_mode();
	else if (strtobool(val, &new_val) < 0)
		return -EINVAL;

	__set_nx_huge_pages(new_val);

	if (new_val != old_val) {
		struct kvm *kvm;

		mutex_lock(&kvm_lock);

		list_for_each_entry(kvm, &vm_list, vm_list) {
			mutex_lock(&kvm->slots_lock);
			kvm_mmu_zap_all_fast(kvm);
			mutex_unlock(&kvm->slots_lock);

			wake_up_process(kvm->arch.nx_lpage_recovery_thread);
		}
		mutex_unlock(&kvm_lock);
	}

	return 0;
}

void __init kvm_mmu_x86_module_init(void)
{
	if (nx_huge_pages == -1)
		__set_nx_huge_pages(get_nx_auto_mode());

	kvm_mmu_spte_module_init();
}

int kvm_mmu_vendor_module_init(void)
{
	int ret = -ENOMEM;

	/*
	BUILD_BUG_ON(sizeof(union kvm_mmu_page_role) != sizeof(u32));
	BUILD_BUG_ON(sizeof(union kvm_mmu_extended_role) != sizeof(u32));
	BUILD_BUG_ON(sizeof(union kvm_cpu_role) != sizeof(u64));

	kvm_mmu_reset_all_pte_masks();

	pte_list_desc_cache = kmem_cache_create("pte_list_desc",
					    sizeof(struct pte_list_desc),
					    0, SLAB_ACCOUNT, NULL);
	if (!pte_list_desc_cache)
		goto out;

	mmu_page_header_cache = kmem_cache_create("kvm_mmu_page_header",
						  sizeof(struct kvm_mmu_page),
						  0, SLAB_ACCOUNT, NULL);
	if (!mmu_page_header_cache)
		goto out;

	if (percpu_counter_init(&kvm_total_used_mmu_pages, 0, GFP_KERNEL))
		goto out;

	ret = register_shrinker(&mmu_shrinker, "x86-mmu");
	if (ret)
		goto out;

	return 0;

out:
	mmu_destroy_caches();
	return ret;
}

void kvm_mmu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_mmu_unload(vcpu);
	free_mmu_pages(&vcpu->arch.root_mmu);
	free_mmu_pages(&vcpu->arch.guest_mmu);
	mmu_free_memory_caches(vcpu);
}

void kvm_mmu_vendor_module_exit(void)
{
	mmu_destroy_caches();
	percpu_counter_destroy(&kvm_total_used_mmu_pages);
	unregister_shrinker(&mmu_shrinker);
}

static bool calc_nx_huge_pages_recovery_period(uint *period)
{
	/*
	bool enabled = READ_ONCE(nx_huge_pages);
	uint ratio = READ_ONCE(nx_huge_pages_recovery_ratio);

	if (!enabled || !ratio)
		return false;

	if (!*period) {
		/* Make sure the period is not less than one second.  */
		ratio = min(ratio, 3600u);
		*period = 60 * 60 * 1000 / ratio;
	}
	return true;
}

static int set_nx_huge_pages_recovery_param(const char *val, const struct kernel_param *kp)
{
	bool was_recovery_enabled, is_recovery_enabled;
	uint old_period, new_period;
	int err;

	was_recovery_enabled = calc_nx_huge_pages_recovery_period(&old_period);

	err = param_set_uint(val, kp);
	if (err)
		return err;

	is_recovery_enabled = calc_nx_huge_pages_recovery_period(&new_period);

	if (is_recovery_enabled &&
	    (!was_recovery_enabled || old_period > new_period)) {
		struct kvm *kvm;

		mutex_lock(&kvm_lock);

		list_for_each_entry(kvm, &vm_list, vm_list)
			wake_up_process(kvm->arch.nx_lpage_recovery_thread);

		mutex_unlock(&kvm_lock);
	}

	return err;
}

static void kvm_recover_nx_lpages(struct kvm *kvm)
{
	unsigned long nx_lpage_splits = kvm->stat.nx_lpage_splits;
	int rcu_idx;
	struct kvm_mmu_page *sp;
	unsigned int ratio;
	LIST_HEAD(invalid_list);
	bool flush = false;
	ulong to_zap;

	rcu_idx = srcu_read_lock(&kvm->srcu);
	write_lock(&kvm->mmu_lock);

	/*
	rcu_read_lock();

	ratio = READ_ONCE(nx_huge_pages_recovery_ratio);
	to_zap = ratio ? DIV_ROUND_UP(nx_lpage_splits, ratio) : 0;
	for ( ; to_zap; --to_zap) {
		if (list_empty(&kvm->arch.lpage_disallowed_mmu_pages))
			break;

		/*
		sp = list_first_entry(&kvm->arch.lpage_disallowed_mmu_pages,
				      struct kvm_mmu_page,
				      lpage_disallowed_link);
		WARN_ON_ONCE(!sp->lpage_disallowed);
		if (is_tdp_mmu_page(sp)) {
			flush |= kvm_tdp_mmu_zap_sp(kvm, sp);
		} else {
			kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
			WARN_ON_ONCE(sp->lpage_disallowed);
		}

		if (need_resched() || rwlock_needbreak(&kvm->mmu_lock)) {
			kvm_mmu_remote_flush_or_zap(kvm, &invalid_list, flush);
			rcu_read_unlock();

			cond_resched_rwlock_write(&kvm->mmu_lock);
			flush = false;

			rcu_read_lock();
		}
	}
	kvm_mmu_remote_flush_or_zap(kvm, &invalid_list, flush);

	rcu_read_unlock();

	write_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, rcu_idx);
}

static long get_nx_lpage_recovery_timeout(u64 start_time)
{
	bool enabled;
	uint period;

	enabled = calc_nx_huge_pages_recovery_period(&period);

	return enabled ? start_time + msecs_to_jiffies(period) - get_jiffies_64()
		       : MAX_SCHEDULE_TIMEOUT;
}

static int kvm_nx_lpage_recovery_worker(struct kvm *kvm, uintptr_t data)
{
	u64 start_time;
	long remaining_time;

	while (true) {
		start_time = get_jiffies_64();
		remaining_time = get_nx_lpage_recovery_timeout(start_time);

		set_current_state(TASK_INTERRUPTIBLE);
		while (!kthread_should_stop() && remaining_time > 0) {
			schedule_timeout(remaining_time);
			remaining_time = get_nx_lpage_recovery_timeout(start_time);
			set_current_state(TASK_INTERRUPTIBLE);
		}

		set_current_state(TASK_RUNNING);

		if (kthread_should_stop())
			return 0;

		kvm_recover_nx_lpages(kvm);
	}
}

int kvm_mmu_post_init_vm(struct kvm *kvm)
{
	int err;

	err = kvm_vm_create_worker_thread(kvm, kvm_nx_lpage_recovery_worker, 0,
					  "kvm-nx-lpage-recovery",
					  &kvm->arch.nx_lpage_recovery_thread);
	if (!err)
		kthread_unpark(kvm->arch.nx_lpage_recovery_thread);

	return err;
}

void kvm_mmu_pre_destroy_vm(struct kvm *kvm)
{
	if (kvm->arch.nx_lpage_recovery_thread)
		kthread_stop(kvm->arch.nx_lpage_recovery_thread);
}
