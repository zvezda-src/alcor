

#include <linux/kvm_host.h>
#include "mmu.h"
#include "mmu_internal.h"
#include "x86.h"
#include "spte.h"

#include <asm/e820/api.h>
#include <asm/memtype.h>
#include <asm/vmx.h>

bool __read_mostly enable_mmio_caching = true;
static bool __ro_after_init allow_mmio_caching;
module_param_named(mmio_caching, enable_mmio_caching, bool, 0444);
EXPORT_SYMBOL_GPL(enable_mmio_caching);

u64 __read_mostly shadow_host_writable_mask;
u64 __read_mostly shadow_mmu_writable_mask;
u64 __read_mostly shadow_nx_mask;
u64 __read_mostly shadow_x_mask; /* mutual exclusive with nx_mask */
u64 __read_mostly shadow_user_mask;
u64 __read_mostly shadow_accessed_mask;
u64 __read_mostly shadow_dirty_mask;
u64 __read_mostly shadow_mmio_value;
u64 __read_mostly shadow_mmio_mask;
u64 __read_mostly shadow_mmio_access_mask;
u64 __read_mostly shadow_present_mask;
u64 __read_mostly shadow_memtype_mask;
u64 __read_mostly shadow_me_value;
u64 __read_mostly shadow_me_mask;
u64 __read_mostly shadow_acc_track_mask;

u64 __read_mostly shadow_nonpresent_or_rsvd_mask;
u64 __read_mostly shadow_nonpresent_or_rsvd_lower_gfn_mask;

u8 __read_mostly shadow_phys_bits;

void __init kvm_mmu_spte_module_init(void)
{
	/*
	allow_mmio_caching = enable_mmio_caching;
}

static u64 generation_mmio_spte_mask(u64 gen)
{
	u64 mask;

	WARN_ON(gen & ~MMIO_SPTE_GEN_MASK);

	mask = (gen << MMIO_SPTE_GEN_LOW_SHIFT) & MMIO_SPTE_GEN_LOW_MASK;
	mask |= (gen << MMIO_SPTE_GEN_HIGH_SHIFT) & MMIO_SPTE_GEN_HIGH_MASK;
	return mask;
}

u64 make_mmio_spte(struct kvm_vcpu *vcpu, u64 gfn, unsigned int access)
{
	u64 gen = kvm_vcpu_memslots(vcpu)->generation & MMIO_SPTE_GEN_MASK;
	u64 spte = generation_mmio_spte_mask(gen);
	u64 gpa = gfn << PAGE_SHIFT;

	WARN_ON_ONCE(!shadow_mmio_value);

	access &= shadow_mmio_access_mask;
	spte |= shadow_mmio_value | access;
	spte |= gpa | shadow_nonpresent_or_rsvd_mask;
	spte |= (gpa & shadow_nonpresent_or_rsvd_mask)
		<< SHADOW_NONPRESENT_OR_RSVD_MASK_LEN;

	return spte;
}

static bool kvm_is_mmio_pfn(kvm_pfn_t pfn)
{
	if (pfn_valid(pfn))
		return !is_zero_pfn(pfn) && PageReserved(pfn_to_page(pfn)) &&
			/*
			(!pat_enabled() || pat_pfn_immune_to_uc_mtrr(pfn));

	return !e820__mapped_raw_any(pfn_to_hpa(pfn),
				     pfn_to_hpa(pfn + 1) - 1,
				     E820_TYPE_RAM);
}

bool spte_has_volatile_bits(u64 spte)
{
	/*
	if (!is_writable_pte(spte) && is_mmu_writable_spte(spte))
		return true;

	if (is_access_track_spte(spte))
		return true;

	if (spte_ad_enabled(spte)) {
		if (!(spte & shadow_accessed_mask) ||
		    (is_writable_pte(spte) && !(spte & shadow_dirty_mask)))
			return true;
	}

	return false;
}

bool make_spte(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
	       const struct kvm_memory_slot *slot,
	       unsigned int pte_access, gfn_t gfn, kvm_pfn_t pfn,
	       u64 old_spte, bool prefetch, bool can_unsync,
	       bool host_writable, u64 *new_spte)
{
	int level = sp->role.level;
	u64 spte = SPTE_MMU_PRESENT_MASK;
	bool wrprot = false;

	WARN_ON_ONCE(!pte_access && !shadow_present_mask);

	if (sp->role.ad_disabled)
		spte |= SPTE_TDP_AD_DISABLED_MASK;
	else if (kvm_mmu_page_ad_need_write_protect(sp))
		spte |= SPTE_TDP_AD_WRPROT_ONLY_MASK;

	/*
	spte |= shadow_present_mask;
	if (!prefetch)
		spte |= spte_shadow_accessed_mask(spte);

	if (level > PG_LEVEL_4K && (pte_access & ACC_EXEC_MASK) &&
	    is_nx_huge_page_enabled(vcpu->kvm)) {
		pte_access &= ~ACC_EXEC_MASK;
	}

	if (pte_access & ACC_EXEC_MASK)
		spte |= shadow_x_mask;
	else
		spte |= shadow_nx_mask;

	if (pte_access & ACC_USER_MASK)
		spte |= shadow_user_mask;

	if (level > PG_LEVEL_4K)
		spte |= PT_PAGE_SIZE_MASK;

	if (shadow_memtype_mask)
		spte |= static_call(kvm_x86_get_mt_mask)(vcpu, gfn,
							 kvm_is_mmio_pfn(pfn));
	if (host_writable)
		spte |= shadow_host_writable_mask;
	else
		pte_access &= ~ACC_WRITE_MASK;

	if (shadow_me_value && !kvm_is_mmio_pfn(pfn))
		spte |= shadow_me_value;

	spte |= (u64)pfn << PAGE_SHIFT;

	if (pte_access & ACC_WRITE_MASK) {
		spte |= PT_WRITABLE_MASK | shadow_mmu_writable_mask;

		/*
		if (is_writable_pte(old_spte))
			goto out;

		/*
		if (mmu_try_to_unsync_pages(vcpu->kvm, slot, gfn, can_unsync, prefetch)) {
			pgprintk("%s: found shadow page for %llx, marking ro\n",
				 __func__, gfn);
			wrprot = true;
			pte_access &= ~ACC_WRITE_MASK;
			spte &= ~(PT_WRITABLE_MASK | shadow_mmu_writable_mask);
		}
	}

	if (pte_access & ACC_WRITE_MASK)
		spte |= spte_shadow_dirty_mask(spte);

out:
	if (prefetch)
		spte = mark_spte_for_access_track(spte);

	WARN_ONCE(is_rsvd_spte(&vcpu->arch.mmu->shadow_zero_check, spte, level),
		  "spte = 0x%llx, level = %d, rsvd bits = 0x%llx", spte, level,
		  get_rsvd_bits(&vcpu->arch.mmu->shadow_zero_check, spte, level));

	if ((spte & PT_WRITABLE_MASK) && kvm_slot_dirty_track_enabled(slot)) {
		/* Enforced by kvm_mmu_hugepage_adjust. */
		WARN_ON(level > PG_LEVEL_4K);
		mark_page_dirty_in_slot(vcpu->kvm, slot, gfn);
	}

	return wrprot;
}

static u64 make_spte_executable(u64 spte)
{
	bool is_access_track = is_access_track_spte(spte);

	if (is_access_track)
		spte = restore_acc_track_spte(spte);

	spte &= ~shadow_nx_mask;
	spte |= shadow_x_mask;

	if (is_access_track)
		spte = mark_spte_for_access_track(spte);

	return spte;
}

u64 make_huge_page_split_spte(struct kvm *kvm, u64 huge_spte, union kvm_mmu_page_role role,
			      int index)
{
	u64 child_spte;

	if (WARN_ON_ONCE(!is_shadow_present_pte(huge_spte)))
		return 0;

	if (WARN_ON_ONCE(!is_large_pte(huge_spte)))
		return 0;

	child_spte = huge_spte;

	/*
	child_spte |= (index * KVM_PAGES_PER_HPAGE(role.level)) << PAGE_SHIFT;

	if (role.level == PG_LEVEL_4K) {
		child_spte &= ~PT_PAGE_SIZE_MASK;

		/*
		if ((role.access & ACC_EXEC_MASK) && is_nx_huge_page_enabled(kvm))
			child_spte = make_spte_executable(child_spte);
	}

	return child_spte;
}


u64 make_nonleaf_spte(u64 *child_pt, bool ad_disabled)
{
	u64 spte = SPTE_MMU_PRESENT_MASK;

	spte |= __pa(child_pt) | shadow_present_mask | PT_WRITABLE_MASK |
		shadow_user_mask | shadow_x_mask | shadow_me_value;

	if (ad_disabled)
		spte |= SPTE_TDP_AD_DISABLED_MASK;
	else
		spte |= shadow_accessed_mask;

	return spte;
}

u64 kvm_mmu_changed_pte_notifier_make_spte(u64 old_spte, kvm_pfn_t new_pfn)
{
	u64 new_spte;

	new_spte = old_spte & ~SPTE_BASE_ADDR_MASK;
	new_spte |= (u64)new_pfn << PAGE_SHIFT;

	new_spte &= ~PT_WRITABLE_MASK;
	new_spte &= ~shadow_host_writable_mask;
	new_spte &= ~shadow_mmu_writable_mask;

	new_spte = mark_spte_for_access_track(new_spte);

	return new_spte;
}

u64 mark_spte_for_access_track(u64 spte)
{
	if (spte_ad_enabled(spte))
		return spte & ~shadow_accessed_mask;

	if (is_access_track_spte(spte))
		return spte;

	check_spte_writable_invariants(spte);

	WARN_ONCE(spte & (SHADOW_ACC_TRACK_SAVED_BITS_MASK <<
			  SHADOW_ACC_TRACK_SAVED_BITS_SHIFT),
		  "kvm: Access Tracking saved bit locations are not zero\n");

	spte |= (spte & SHADOW_ACC_TRACK_SAVED_BITS_MASK) <<
		SHADOW_ACC_TRACK_SAVED_BITS_SHIFT;
	spte &= ~shadow_acc_track_mask;

	return spte;
}

void kvm_mmu_set_mmio_spte_mask(u64 mmio_value, u64 mmio_mask, u64 access_mask)
{
	BUG_ON((u64)(unsigned)access_mask != access_mask);
	WARN_ON(mmio_value & shadow_nonpresent_or_rsvd_lower_gfn_mask);

	/*
	enable_mmio_caching = allow_mmio_caching;
	if (!enable_mmio_caching)
		mmio_value = 0;

	/*
	if (WARN_ON(mmio_mask & ~SPTE_MMIO_ALLOWED_MASK))
		mmio_value = 0;

	/*
	if (WARN_ON(mmio_value & (shadow_nonpresent_or_rsvd_mask <<
				  SHADOW_NONPRESENT_OR_RSVD_MASK_LEN)))
		mmio_value = 0;

	/*
	if (WARN_ON((mmio_value & mmio_mask) != mmio_value) ||
	    WARN_ON(mmio_value && (REMOVED_SPTE & mmio_mask) == mmio_value))
		mmio_value = 0;

	if (!mmio_value)
		enable_mmio_caching = false;

	shadow_mmio_value = mmio_value;
	shadow_mmio_mask  = mmio_mask;
	shadow_mmio_access_mask = access_mask;
}
EXPORT_SYMBOL_GPL(kvm_mmu_set_mmio_spte_mask);

void kvm_mmu_set_me_spte_mask(u64 me_value, u64 me_mask)
{
	/* shadow_me_value must be a subset of shadow_me_mask */
	if (WARN_ON(me_value & ~me_mask))
		me_value = me_mask = 0;

	shadow_me_value = me_value;
	shadow_me_mask = me_mask;
}
EXPORT_SYMBOL_GPL(kvm_mmu_set_me_spte_mask);

void kvm_mmu_set_ept_masks(bool has_ad_bits, bool has_exec_only)
{
	shadow_user_mask	= VMX_EPT_READABLE_MASK;
	shadow_accessed_mask	= has_ad_bits ? VMX_EPT_ACCESS_BIT : 0ull;
	shadow_dirty_mask	= has_ad_bits ? VMX_EPT_DIRTY_BIT : 0ull;
	shadow_nx_mask		= 0ull;
	shadow_x_mask		= VMX_EPT_EXECUTABLE_MASK;
	shadow_present_mask	= has_exec_only ? 0ull : VMX_EPT_READABLE_MASK;
	/*
	shadow_memtype_mask	= VMX_EPT_MT_MASK | VMX_EPT_IPAT_BIT;
	shadow_acc_track_mask	= VMX_EPT_RWX_MASK;
	shadow_host_writable_mask = EPT_SPTE_HOST_WRITABLE;
	shadow_mmu_writable_mask  = EPT_SPTE_MMU_WRITABLE;

	/*
	kvm_mmu_set_mmio_spte_mask(VMX_EPT_MISCONFIG_WX_VALUE,
				   VMX_EPT_RWX_MASK, 0);
}
EXPORT_SYMBOL_GPL(kvm_mmu_set_ept_masks);

void kvm_mmu_reset_all_pte_masks(void)
{
	u8 low_phys_bits;
	u64 mask;

	shadow_phys_bits = kvm_get_shadow_phys_bits();

	/*
	shadow_nonpresent_or_rsvd_mask = 0;
	low_phys_bits = boot_cpu_data.x86_phys_bits;
	if (boot_cpu_has_bug(X86_BUG_L1TF) &&
	    !WARN_ON_ONCE(boot_cpu_data.x86_cache_bits >=
			  52 - SHADOW_NONPRESENT_OR_RSVD_MASK_LEN)) {
		low_phys_bits = boot_cpu_data.x86_cache_bits
			- SHADOW_NONPRESENT_OR_RSVD_MASK_LEN;
		shadow_nonpresent_or_rsvd_mask =
			rsvd_bits(low_phys_bits, boot_cpu_data.x86_cache_bits - 1);
	}

	shadow_nonpresent_or_rsvd_lower_gfn_mask =
		GENMASK_ULL(low_phys_bits - 1, PAGE_SHIFT);

	shadow_user_mask	= PT_USER_MASK;
	shadow_accessed_mask	= PT_ACCESSED_MASK;
	shadow_dirty_mask	= PT_DIRTY_MASK;
	shadow_nx_mask		= PT64_NX_MASK;
	shadow_x_mask		= 0;
	shadow_present_mask	= PT_PRESENT_MASK;

	/*
	shadow_memtype_mask	= 0;
	shadow_acc_track_mask	= 0;
	shadow_me_mask		= 0;
	shadow_me_value		= 0;

	shadow_host_writable_mask = DEFAULT_SPTE_HOST_WRITABLE;
	shadow_mmu_writable_mask  = DEFAULT_SPTE_MMU_WRITABLE;

	/*
	if (shadow_phys_bits < 52)
		mask = BIT_ULL(51) | PT_PRESENT_MASK;
	else
		mask = 0;

	kvm_mmu_set_mmio_spte_mask(mask, mask, ACC_WRITE_MASK | ACC_USER_MASK);
}
