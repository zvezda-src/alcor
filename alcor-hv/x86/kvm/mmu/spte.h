
#ifndef KVM_X86_MMU_SPTE_H
#define KVM_X86_MMU_SPTE_H

#include "mmu_internal.h"

#define SPTE_MMU_PRESENT_MASK		BIT_ULL(11)

#define SPTE_TDP_AD_SHIFT		52
#define SPTE_TDP_AD_MASK		(3ULL << SPTE_TDP_AD_SHIFT)
#define SPTE_TDP_AD_ENABLED_MASK	(0ULL << SPTE_TDP_AD_SHIFT)
#define SPTE_TDP_AD_DISABLED_MASK	(1ULL << SPTE_TDP_AD_SHIFT)
#define SPTE_TDP_AD_WRPROT_ONLY_MASK	(2ULL << SPTE_TDP_AD_SHIFT)
static_assert(SPTE_TDP_AD_ENABLED_MASK == 0);

#ifdef CONFIG_DYNAMIC_PHYSICAL_MASK
#define SPTE_BASE_ADDR_MASK (physical_mask & ~(u64)(PAGE_SIZE-1))
#else
#define SPTE_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))
#endif

#define SPTE_PERM_MASK (PT_PRESENT_MASK | PT_WRITABLE_MASK | shadow_user_mask \
			| shadow_x_mask | shadow_nx_mask | shadow_me_mask)

#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

#define SPTE_EPT_READABLE_MASK			0x1ull
#define SPTE_EPT_EXECUTABLE_MASK		0x4ull

#define SPTE_LEVEL_BITS			9
#define SPTE_LEVEL_SHIFT(level)		__PT_LEVEL_SHIFT(level, SPTE_LEVEL_BITS)
#define SPTE_INDEX(address, level)	__PT_INDEX(address, level, SPTE_LEVEL_BITS)
#define SPTE_ENT_PER_PAGE		__PT_ENT_PER_PAGE(SPTE_LEVEL_BITS)

#define SHADOW_ACC_TRACK_SAVED_BITS_MASK (SPTE_EPT_READABLE_MASK | \
					  SPTE_EPT_EXECUTABLE_MASK)
#define SHADOW_ACC_TRACK_SAVED_BITS_SHIFT 54
#define SHADOW_ACC_TRACK_SAVED_MASK	(SHADOW_ACC_TRACK_SAVED_BITS_MASK << \
					 SHADOW_ACC_TRACK_SAVED_BITS_SHIFT)
static_assert(!(SPTE_TDP_AD_MASK & SHADOW_ACC_TRACK_SAVED_MASK));


#define DEFAULT_SPTE_HOST_WRITABLE	BIT_ULL(9)
#define DEFAULT_SPTE_MMU_WRITABLE	BIT_ULL(10)

#define EPT_SPTE_HOST_WRITABLE		BIT_ULL(57)
#define EPT_SPTE_MMU_WRITABLE		BIT_ULL(58)

static_assert(!(EPT_SPTE_HOST_WRITABLE & SPTE_TDP_AD_MASK));
static_assert(!(EPT_SPTE_MMU_WRITABLE & SPTE_TDP_AD_MASK));
static_assert(!(EPT_SPTE_HOST_WRITABLE & SHADOW_ACC_TRACK_SAVED_MASK));
static_assert(!(EPT_SPTE_MMU_WRITABLE & SHADOW_ACC_TRACK_SAVED_MASK));

#undef SHADOW_ACC_TRACK_SAVED_MASK


#define MMIO_SPTE_GEN_LOW_START		3
#define MMIO_SPTE_GEN_LOW_END		10

#define MMIO_SPTE_GEN_HIGH_START	52
#define MMIO_SPTE_GEN_HIGH_END		62

#define MMIO_SPTE_GEN_LOW_MASK		GENMASK_ULL(MMIO_SPTE_GEN_LOW_END, \
						    MMIO_SPTE_GEN_LOW_START)
#define MMIO_SPTE_GEN_HIGH_MASK		GENMASK_ULL(MMIO_SPTE_GEN_HIGH_END, \
						    MMIO_SPTE_GEN_HIGH_START)
static_assert(!(SPTE_MMU_PRESENT_MASK &
		(MMIO_SPTE_GEN_LOW_MASK | MMIO_SPTE_GEN_HIGH_MASK)));

#define SPTE_MMIO_ALLOWED_MASK (BIT_ULL(63) | GENMASK_ULL(51, 12) | GENMASK_ULL(2, 0))
static_assert(!(SPTE_MMIO_ALLOWED_MASK &
		(SPTE_MMU_PRESENT_MASK | MMIO_SPTE_GEN_LOW_MASK | MMIO_SPTE_GEN_HIGH_MASK)));

#define MMIO_SPTE_GEN_LOW_BITS		(MMIO_SPTE_GEN_LOW_END - MMIO_SPTE_GEN_LOW_START + 1)
#define MMIO_SPTE_GEN_HIGH_BITS		(MMIO_SPTE_GEN_HIGH_END - MMIO_SPTE_GEN_HIGH_START + 1)

static_assert(MMIO_SPTE_GEN_LOW_BITS == 8 && MMIO_SPTE_GEN_HIGH_BITS == 11);

#define MMIO_SPTE_GEN_LOW_SHIFT		(MMIO_SPTE_GEN_LOW_START - 0)
#define MMIO_SPTE_GEN_HIGH_SHIFT	(MMIO_SPTE_GEN_HIGH_START - MMIO_SPTE_GEN_LOW_BITS)

#define MMIO_SPTE_GEN_MASK		GENMASK_ULL(MMIO_SPTE_GEN_LOW_BITS + MMIO_SPTE_GEN_HIGH_BITS - 1, 0)

extern u64 __read_mostly shadow_host_writable_mask;
extern u64 __read_mostly shadow_mmu_writable_mask;
extern u64 __read_mostly shadow_nx_mask;
extern u64 __read_mostly shadow_x_mask; /* mutual exclusive with nx_mask */
extern u64 __read_mostly shadow_user_mask;
extern u64 __read_mostly shadow_accessed_mask;
extern u64 __read_mostly shadow_dirty_mask;
extern u64 __read_mostly shadow_mmio_value;
extern u64 __read_mostly shadow_mmio_mask;
extern u64 __read_mostly shadow_mmio_access_mask;
extern u64 __read_mostly shadow_present_mask;
extern u64 __read_mostly shadow_memtype_mask;
extern u64 __read_mostly shadow_me_value;
extern u64 __read_mostly shadow_me_mask;

extern u64 __read_mostly shadow_acc_track_mask;

extern u64 __read_mostly shadow_nonpresent_or_rsvd_mask;

#define SHADOW_NONPRESENT_OR_RSVD_MASK_LEN 5

#define REMOVED_SPTE	0x5a0ULL

static_assert(!(REMOVED_SPTE & SPTE_MMU_PRESENT_MASK));

static inline bool is_removed_spte(u64 spte)
{
	return spte == REMOVED_SPTE;
}

static inline int spte_index(u64 *sptep)
{
	return ((unsigned long)sptep / sizeof(*sptep)) & (SPTE_ENT_PER_PAGE - 1);
}

extern u64 __read_mostly shadow_nonpresent_or_rsvd_lower_gfn_mask;

static inline bool is_mmio_spte(u64 spte)
{
	return (spte & shadow_mmio_mask) == shadow_mmio_value &&
	       likely(enable_mmio_caching);
}

static inline bool is_shadow_present_pte(u64 pte)
{
	return !!(pte & SPTE_MMU_PRESENT_MASK);
}

static inline bool kvm_ad_enabled(void)
{
	return !!shadow_accessed_mask;
}

static inline bool sp_ad_disabled(struct kvm_mmu_page *sp)
{
	return sp->role.ad_disabled;
}

static inline bool spte_ad_enabled(u64 spte)
{
	MMU_WARN_ON(!is_shadow_present_pte(spte));
	return (spte & SPTE_TDP_AD_MASK) != SPTE_TDP_AD_DISABLED_MASK;
}

static inline bool spte_ad_need_write_protect(u64 spte)
{
	MMU_WARN_ON(!is_shadow_present_pte(spte));
	/*
	return (spte & SPTE_TDP_AD_MASK) != SPTE_TDP_AD_ENABLED_MASK;
}

static inline u64 spte_shadow_accessed_mask(u64 spte)
{
	MMU_WARN_ON(!is_shadow_present_pte(spte));
	return spte_ad_enabled(spte) ? shadow_accessed_mask : 0;
}

static inline u64 spte_shadow_dirty_mask(u64 spte)
{
	MMU_WARN_ON(!is_shadow_present_pte(spte));
	return spte_ad_enabled(spte) ? shadow_dirty_mask : 0;
}

static inline bool is_access_track_spte(u64 spte)
{
	return !spte_ad_enabled(spte) && (spte & shadow_acc_track_mask) == 0;
}

static inline bool is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

static inline bool is_last_spte(u64 pte, int level)
{
	return (level == PG_LEVEL_4K) || is_large_pte(pte);
}

static inline bool is_executable_pte(u64 spte)
{
	return (spte & (shadow_x_mask | shadow_nx_mask)) == shadow_x_mask;
}

static inline kvm_pfn_t spte_to_pfn(u64 pte)
{
	return (pte & SPTE_BASE_ADDR_MASK) >> PAGE_SHIFT;
}

static inline bool is_accessed_spte(u64 spte)
{
	u64 accessed_mask = spte_shadow_accessed_mask(spte);

	return accessed_mask ? spte & accessed_mask
			     : !is_access_track_spte(spte);
}

static inline bool is_dirty_spte(u64 spte)
{
	u64 dirty_mask = spte_shadow_dirty_mask(spte);

	return dirty_mask ? spte & dirty_mask : spte & PT_WRITABLE_MASK;
}

static inline u64 get_rsvd_bits(struct rsvd_bits_validate *rsvd_check, u64 pte,
				int level)
{
	int bit7 = (pte >> 7) & 1;

	return rsvd_check->rsvd_bits_mask[bit7][level-1];
}

static inline bool __is_rsvd_bits_set(struct rsvd_bits_validate *rsvd_check,
				      u64 pte, int level)
{
	return pte & get_rsvd_bits(rsvd_check, pte, level);
}

static inline bool __is_bad_mt_xwr(struct rsvd_bits_validate *rsvd_check,
				   u64 pte)
{
	return rsvd_check->bad_mt_xwr & BIT_ULL(pte & 0x3f);
}

static __always_inline bool is_rsvd_spte(struct rsvd_bits_validate *rsvd_check,
					 u64 spte, int level)
{
	return __is_bad_mt_xwr(rsvd_check, spte) ||
	       __is_rsvd_bits_set(rsvd_check, spte, level);
}

static inline bool is_writable_pte(unsigned long pte)
{
	return pte & PT_WRITABLE_MASK;
}

static inline void check_spte_writable_invariants(u64 spte)
{
	if (spte & shadow_mmu_writable_mask)
		WARN_ONCE(!(spte & shadow_host_writable_mask),
			  "kvm: MMU-writable SPTE is not Host-writable: %llx",
			  spte);
	else
		WARN_ONCE(is_writable_pte(spte),
			  "kvm: Writable SPTE is not MMU-writable: %llx", spte);
}

static inline bool is_mmu_writable_spte(u64 spte)
{
	return spte & shadow_mmu_writable_mask;
}

static inline u64 get_mmio_spte_generation(u64 spte)
{
	u64 gen;

	gen = (spte & MMIO_SPTE_GEN_LOW_MASK) >> MMIO_SPTE_GEN_LOW_SHIFT;
	gen |= (spte & MMIO_SPTE_GEN_HIGH_MASK) >> MMIO_SPTE_GEN_HIGH_SHIFT;
	return gen;
}

bool spte_has_volatile_bits(u64 spte);

bool make_spte(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
	       const struct kvm_memory_slot *slot,
	       unsigned int pte_access, gfn_t gfn, kvm_pfn_t pfn,
	       u64 old_spte, bool prefetch, bool can_unsync,
	       bool host_writable, u64 *new_spte);
u64 make_huge_page_split_spte(struct kvm *kvm, u64 huge_spte,
		      	      union kvm_mmu_page_role role, int index);
u64 make_nonleaf_spte(u64 *child_pt, bool ad_disabled);
u64 make_mmio_spte(struct kvm_vcpu *vcpu, u64 gfn, unsigned int access);
u64 mark_spte_for_access_track(u64 spte);

static inline u64 restore_acc_track_spte(u64 spte)
{
	u64 saved_bits = (spte >> SHADOW_ACC_TRACK_SAVED_BITS_SHIFT)
			 & SHADOW_ACC_TRACK_SAVED_BITS_MASK;

	spte &= ~shadow_acc_track_mask;
	spte &= ~(SHADOW_ACC_TRACK_SAVED_BITS_MASK <<
		  SHADOW_ACC_TRACK_SAVED_BITS_SHIFT);
	spte |= saved_bits;

	return spte;
}

u64 kvm_mmu_changed_pte_notifier_make_spte(u64 old_spte, kvm_pfn_t new_pfn);

void __init kvm_mmu_spte_module_init(void);
void kvm_mmu_reset_all_pte_masks(void);

#endif
