
#include <linux/objtool.h>
#include <linux/percpu.h>

#include <asm/debugreg.h>
#include <asm/mmu_context.h>

#include "cpuid.h"
#include "evmcs.h"
#include "hyperv.h"
#include "mmu.h"
#include "nested.h"
#include "pmu.h"
#include "sgx.h"
#include "trace.h"
#include "vmx.h"
#include "x86.h"

static bool __read_mostly enable_shadow_vmcs = 1;
module_param_named(enable_shadow_vmcs, enable_shadow_vmcs, bool, S_IRUGO);

static bool __read_mostly nested_early_check = 0;
module_param(nested_early_check, bool, S_IRUGO);

#define CC KVM_NESTED_VMENTER_CONSISTENCY_CHECK

#define VMX_VPID_EXTENT_SUPPORTED_MASK		\
	(VMX_VPID_EXTENT_INDIVIDUAL_ADDR_BIT |	\
	VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT |	\
	VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT |	\
	VMX_VPID_EXTENT_SINGLE_NON_GLOBAL_BIT)

#define VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE 5

enum {
	VMX_VMREAD_BITMAP,
	VMX_VMWRITE_BITMAP,
	VMX_BITMAP_NR
};
static unsigned long *vmx_bitmap[VMX_BITMAP_NR];

#define vmx_vmread_bitmap                    (vmx_bitmap[VMX_VMREAD_BITMAP])
#define vmx_vmwrite_bitmap                   (vmx_bitmap[VMX_VMWRITE_BITMAP])

struct shadow_vmcs_field {
	u16	encoding;
	u16	offset;
};
static struct shadow_vmcs_field shadow_read_only_fields[] = {
#define SHADOW_FIELD_RO(x, y) { x, offsetof(struct vmcs12, y) },
#include "vmcs_shadow_fields.h"
};
static int max_shadow_read_only_fields =
	ARRAY_SIZE(shadow_read_only_fields);

static struct shadow_vmcs_field shadow_read_write_fields[] = {
#define SHADOW_FIELD_RW(x, y) { x, offsetof(struct vmcs12, y) },
#include "vmcs_shadow_fields.h"
};
static int max_shadow_read_write_fields =
	ARRAY_SIZE(shadow_read_write_fields);

static void init_vmcs_shadow_fields(void)
{
	int i, j;

	memset(vmx_vmread_bitmap, 0xff, PAGE_SIZE);
	memset(vmx_vmwrite_bitmap, 0xff, PAGE_SIZE);

	for (i = j = 0; i < max_shadow_read_only_fields; i++) {
		struct shadow_vmcs_field entry = shadow_read_only_fields[i];
		u16 field = entry.encoding;

		if (vmcs_field_width(field) == VMCS_FIELD_WIDTH_U64 &&
		    (i + 1 == max_shadow_read_only_fields ||
		     shadow_read_only_fields[i + 1].encoding != field + 1))
			pr_err("Missing field from shadow_read_only_field %x\n",
			       field + 1);

		clear_bit(field, vmx_vmread_bitmap);
		if (field & 1)
#ifdef CONFIG_X86_64
			continue;
#else
			entry.offset += sizeof(u32);
#endif
		shadow_read_only_fields[j++] = entry;
	}
	max_shadow_read_only_fields = j;

	for (i = j = 0; i < max_shadow_read_write_fields; i++) {
		struct shadow_vmcs_field entry = shadow_read_write_fields[i];
		u16 field = entry.encoding;

		if (vmcs_field_width(field) == VMCS_FIELD_WIDTH_U64 &&
		    (i + 1 == max_shadow_read_write_fields ||
		     shadow_read_write_fields[i + 1].encoding != field + 1))
			pr_err("Missing field from shadow_read_write_field %x\n",
			       field + 1);

		WARN_ONCE(field >= GUEST_ES_AR_BYTES &&
			  field <= GUEST_TR_AR_BYTES,
			  "Update vmcs12_write_any() to drop reserved bits from AR_BYTES");

		/*
		switch (field) {
		case GUEST_PML_INDEX:
			if (!cpu_has_vmx_pml())
				continue;
			break;
		case VMX_PREEMPTION_TIMER_VALUE:
			if (!cpu_has_vmx_preemption_timer())
				continue;
			break;
		case GUEST_INTR_STATUS:
			if (!cpu_has_vmx_apicv())
				continue;
			break;
		default:
			break;
		}

		clear_bit(field, vmx_vmwrite_bitmap);
		clear_bit(field, vmx_vmread_bitmap);
		if (field & 1)
#ifdef CONFIG_X86_64
			continue;
#else
			entry.offset += sizeof(u32);
#endif
		shadow_read_write_fields[j++] = entry;
	}
	max_shadow_read_write_fields = j;
}

static int nested_vmx_succeed(struct kvm_vcpu *vcpu)
{
	vmx_set_rflags(vcpu, vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			    X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF));
	return kvm_skip_emulated_instruction(vcpu);
}

static int nested_vmx_failInvalid(struct kvm_vcpu *vcpu)
{
	vmx_set_rflags(vcpu, (vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF |
			    X86_EFLAGS_SF | X86_EFLAGS_OF))
			| X86_EFLAGS_CF);
	return kvm_skip_emulated_instruction(vcpu);
}

static int nested_vmx_failValid(struct kvm_vcpu *vcpu,
				u32 vm_instruction_error)
{
	vmx_set_rflags(vcpu, (vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			    X86_EFLAGS_SF | X86_EFLAGS_OF))
			| X86_EFLAGS_ZF);
	get_vmcs12(vcpu)->vm_instruction_error = vm_instruction_error;
	/*
	if (to_vmx(vcpu)->nested.hv_evmcs_vmptr != EVMPTR_INVALID)
		to_vmx(vcpu)->nested.need_vmcs12_to_shadow_sync = true;

	return kvm_skip_emulated_instruction(vcpu);
}

static int nested_vmx_fail(struct kvm_vcpu *vcpu, u32 vm_instruction_error)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
	if (vmx->nested.current_vmptr == INVALID_GPA &&
	    !evmptr_is_valid(vmx->nested.hv_evmcs_vmptr))
		return nested_vmx_failInvalid(vcpu);

	return nested_vmx_failValid(vcpu, vm_instruction_error);
}

static void nested_vmx_abort(struct kvm_vcpu *vcpu, u32 indicator)
{
	/* TODO: not to reset guest simply here. */
	kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
	pr_debug_ratelimited("kvm: nested vmx abort, indicator %d\n", indicator);
}

static inline bool vmx_control_verify(u32 control, u32 low, u32 high)
{
	return fixed_bits_valid(control, low, high);
}

static inline u64 vmx_control_msr(u32 low, u32 high)
{
	return low | ((u64)high << 32);
}

static void vmx_disable_shadow_vmcs(struct vcpu_vmx *vmx)
{
	secondary_exec_controls_clearbit(vmx, SECONDARY_EXEC_SHADOW_VMCS);
	vmcs_write64(VMCS_LINK_POINTER, INVALID_GPA);
	vmx->nested.need_vmcs12_to_shadow_sync = false;
}

static inline void nested_release_evmcs(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (evmptr_is_valid(vmx->nested.hv_evmcs_vmptr)) {
		kvm_vcpu_unmap(vcpu, &vmx->nested.hv_evmcs_map, true);
		vmx->nested.hv_evmcs = NULL;
	}

	vmx->nested.hv_evmcs_vmptr = EVMPTR_INVALID;
}

static void vmx_sync_vmcs_host_state(struct vcpu_vmx *vmx,
				     struct loaded_vmcs *prev)
{
	struct vmcs_host_state *dest, *src;

	if (unlikely(!vmx->guest_state_loaded))
		return;

	src = &prev->host_state;
	dest = &vmx->loaded_vmcs->host_state;

	vmx_set_host_fs_gs(dest, src->fs_sel, src->gs_sel, src->fs_base, src->gs_base);
	dest->ldt_sel = src->ldt_sel;
#ifdef CONFIG_X86_64
	dest->ds_sel = src->ds_sel;
	dest->es_sel = src->es_sel;
#endif
}

static void vmx_switch_vmcs(struct kvm_vcpu *vcpu, struct loaded_vmcs *vmcs)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct loaded_vmcs *prev;
	int cpu;

	if (WARN_ON_ONCE(vmx->loaded_vmcs == vmcs))
		return;

	cpu = get_cpu();
	prev = vmx->loaded_vmcs;
	vmx->loaded_vmcs = vmcs;
	vmx_vcpu_load_vmcs(vcpu, cpu, prev);
	vmx_sync_vmcs_host_state(vmx, prev);
	put_cpu();

	vcpu->arch.regs_avail = ~VMX_REGS_LAZY_LOAD_SET;

	/*
	vcpu->arch.regs_dirty = 0;
}

static void free_nested(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (WARN_ON_ONCE(vmx->loaded_vmcs != &vmx->vmcs01))
		vmx_switch_vmcs(vcpu, &vmx->vmcs01);

	if (!vmx->nested.vmxon && !vmx->nested.smm.vmxon)
		return;

	kvm_clear_request(KVM_REQ_GET_NESTED_STATE_PAGES, vcpu);

	vmx->nested.vmxon = false;
	vmx->nested.smm.vmxon = false;
	vmx->nested.vmxon_ptr = INVALID_GPA;
	free_vpid(vmx->nested.vpid02);
	vmx->nested.posted_intr_nv = -1;
	vmx->nested.current_vmptr = INVALID_GPA;
	if (enable_shadow_vmcs) {
		vmx_disable_shadow_vmcs(vmx);
		vmcs_clear(vmx->vmcs01.shadow_vmcs);
		free_vmcs(vmx->vmcs01.shadow_vmcs);
		vmx->vmcs01.shadow_vmcs = NULL;
	}
	kfree(vmx->nested.cached_vmcs12);
	vmx->nested.cached_vmcs12 = NULL;
	kfree(vmx->nested.cached_shadow_vmcs12);
	vmx->nested.cached_shadow_vmcs12 = NULL;
	/*
	kvm_vcpu_unmap(vcpu, &vmx->nested.apic_access_page_map, false);
	kvm_vcpu_unmap(vcpu, &vmx->nested.virtual_apic_map, true);
	kvm_vcpu_unmap(vcpu, &vmx->nested.pi_desc_map, true);
	vmx->nested.pi_desc = NULL;

	kvm_mmu_free_roots(vcpu->kvm, &vcpu->arch.guest_mmu, KVM_MMU_ROOTS_ALL);

	nested_release_evmcs(vcpu);

	free_loaded_vmcs(&vmx->nested.vmcs02);
}

void nested_vmx_free_vcpu(struct kvm_vcpu *vcpu)
{
	vcpu_load(vcpu);
	vmx_leave_nested(vcpu);
	vcpu_put(vcpu);
}

#define EPTP_PA_MASK   GENMASK_ULL(51, 12)

static bool nested_ept_root_matches(hpa_t root_hpa, u64 root_eptp, u64 eptp)
{
	return VALID_PAGE(root_hpa) &&
	       ((root_eptp & EPTP_PA_MASK) == (eptp & EPTP_PA_MASK));
}

static void nested_ept_invalidate_addr(struct kvm_vcpu *vcpu, gpa_t eptp,
				       gpa_t addr)
{
	uint i;
	struct kvm_mmu_root_info *cached_root;

	WARN_ON_ONCE(!mmu_is_nested(vcpu));

	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		cached_root = &vcpu->arch.mmu->prev_roots[i];

		if (nested_ept_root_matches(cached_root->hpa, cached_root->pgd,
					    eptp))
			vcpu->arch.mmu->invlpg(vcpu, addr, cached_root->hpa);
	}
}

static void nested_ept_inject_page_fault(struct kvm_vcpu *vcpu,
		struct x86_exception *fault)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 vm_exit_reason;
	unsigned long exit_qualification = vcpu->arch.exit_qualification;

	if (vmx->nested.pml_full) {
		vm_exit_reason = EXIT_REASON_PML_FULL;
		vmx->nested.pml_full = false;
		exit_qualification &= INTR_INFO_UNBLOCK_NMI;
	} else {
		if (fault->error_code & PFERR_RSVD_MASK)
			vm_exit_reason = EXIT_REASON_EPT_MISCONFIG;
		else
			vm_exit_reason = EXIT_REASON_EPT_VIOLATION;

		/*
		nested_ept_invalidate_addr(vcpu, vmcs12->ept_pointer,
					   fault->address);
	}

	nested_vmx_vmexit(vcpu, vm_exit_reason, 0, exit_qualification);
	vmcs12->guest_physical_address = fault->address;
}

static void nested_ept_new_eptp(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	bool execonly = vmx->nested.msrs.ept_caps & VMX_EPT_EXECUTE_ONLY_BIT;
	int ept_lpage_level = ept_caps_to_lpage_level(vmx->nested.msrs.ept_caps);

	kvm_init_shadow_ept_mmu(vcpu, execonly, ept_lpage_level,
				nested_ept_ad_enabled(vcpu),
				nested_ept_get_eptp(vcpu));
}

static void nested_ept_init_mmu_context(struct kvm_vcpu *vcpu)
{
	WARN_ON(mmu_is_nested(vcpu));

	vcpu->arch.mmu = &vcpu->arch.guest_mmu;
	nested_ept_new_eptp(vcpu);
	vcpu->arch.mmu->get_guest_pgd     = nested_ept_get_eptp;
	vcpu->arch.mmu->inject_page_fault = nested_ept_inject_page_fault;
	vcpu->arch.mmu->get_pdptr         = kvm_pdptr_read;

	vcpu->arch.walk_mmu              = &vcpu->arch.nested_mmu;
}

static void nested_ept_uninit_mmu_context(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu = &vcpu->arch.root_mmu;
	vcpu->arch.walk_mmu = &vcpu->arch.root_mmu;
}

static bool nested_vmx_is_page_fault_vmexit(struct vmcs12 *vmcs12,
					    u16 error_code)
{
	bool inequality, bit;

	bit = (vmcs12->exception_bitmap & (1u << PF_VECTOR)) != 0;
	inequality =
		(error_code & vmcs12->page_fault_error_code_mask) !=
		 vmcs12->page_fault_error_code_match;
	return inequality ^ bit;
}


static int nested_vmx_check_exception(struct kvm_vcpu *vcpu, unsigned long *exit_qual)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	unsigned int nr = vcpu->arch.exception.nr;
	bool has_payload = vcpu->arch.exception.has_payload;
	unsigned long payload = vcpu->arch.exception.payload;

	if (nr == PF_VECTOR) {
		if (vcpu->arch.exception.nested_apf) {
			*exit_qual = vcpu->arch.apf.nested_apf_token;
			return 1;
		}
		if (nested_vmx_is_page_fault_vmexit(vmcs12,
						    vcpu->arch.exception.error_code)) {
			*exit_qual = has_payload ? payload : vcpu->arch.cr2;
			return 1;
		}
	} else if (vmcs12->exception_bitmap & (1u << nr)) {
		if (nr == DB_VECTOR) {
			if (!has_payload) {
				payload = vcpu->arch.dr6;
				payload &= ~DR6_BT;
				payload ^= DR6_ACTIVE_LOW;
			}
			*exit_qual = payload;
		} else
			*exit_qual = 0;
		return 1;
	}

	return 0;
}

static bool nested_vmx_handle_page_fault_workaround(struct kvm_vcpu *vcpu,
						    struct x86_exception *fault)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	WARN_ON(!is_guest_mode(vcpu));

	if (nested_vmx_is_page_fault_vmexit(vmcs12, fault->error_code) &&
	    !WARN_ON_ONCE(to_vmx(vcpu)->nested.nested_run_pending)) {
		vmcs12->vm_exit_intr_error_code = fault->error_code;
		nested_vmx_vmexit(vcpu, EXIT_REASON_EXCEPTION_NMI,
				  PF_VECTOR | INTR_TYPE_HARD_EXCEPTION |
				  INTR_INFO_DELIVER_CODE_MASK | INTR_INFO_VALID_MASK,
				  fault->address);
		return true;
	}
	return false;
}

static int nested_vmx_check_io_bitmap_controls(struct kvm_vcpu *vcpu,
					       struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has(vmcs12, CPU_BASED_USE_IO_BITMAPS))
		return 0;

	if (CC(!page_address_valid(vcpu, vmcs12->io_bitmap_a)) ||
	    CC(!page_address_valid(vcpu, vmcs12->io_bitmap_b)))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_msr_bitmap_controls(struct kvm_vcpu *vcpu,
						struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has(vmcs12, CPU_BASED_USE_MSR_BITMAPS))
		return 0;

	if (CC(!page_address_valid(vcpu, vmcs12->msr_bitmap)))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_tpr_shadow_controls(struct kvm_vcpu *vcpu,
						struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW))
		return 0;

	if (CC(!page_address_valid(vcpu, vmcs12->virtual_apic_page_addr)))
		return -EINVAL;

	return 0;
}

static void nested_vmx_disable_intercept_for_x2apic_msr(unsigned long *msr_bitmap_l1,
							unsigned long *msr_bitmap_l0,
							u32 msr, int type)
{
	if (type & MSR_TYPE_R && !vmx_test_msr_bitmap_read(msr_bitmap_l1, msr))
		vmx_clear_msr_bitmap_read(msr_bitmap_l0, msr);

	if (type & MSR_TYPE_W && !vmx_test_msr_bitmap_write(msr_bitmap_l1, msr))
		vmx_clear_msr_bitmap_write(msr_bitmap_l0, msr);
}

static inline void enable_x2apic_msr_intercepts(unsigned long *msr_bitmap)
{
	int msr;

	for (msr = 0x800; msr <= 0x8ff; msr += BITS_PER_LONG) {
		unsigned word = msr / BITS_PER_LONG;

		msr_bitmap[word] = ~0;
		msr_bitmap[word + (0x800 / sizeof(long))] = ~0;
	}
}

#define BUILD_NVMX_MSR_INTERCEPT_HELPER(rw)					\
static inline									\
void nested_vmx_set_msr_##rw##_intercept(struct vcpu_vmx *vmx,			\
					 unsigned long *msr_bitmap_l1,		\
					 unsigned long *msr_bitmap_l0, u32 msr)	\
{										\
	if (vmx_test_msr_bitmap_##rw(vmx->vmcs01.msr_bitmap, msr) ||		\
	    vmx_test_msr_bitmap_##rw(msr_bitmap_l1, msr))			\
		vmx_set_msr_bitmap_##rw(msr_bitmap_l0, msr);			\
	else									\
		vmx_clear_msr_bitmap_##rw(msr_bitmap_l0, msr);			\
}
BUILD_NVMX_MSR_INTERCEPT_HELPER(read)
BUILD_NVMX_MSR_INTERCEPT_HELPER(write)

static inline void nested_vmx_set_intercept_for_msr(struct vcpu_vmx *vmx,
						    unsigned long *msr_bitmap_l1,
						    unsigned long *msr_bitmap_l0,
						    u32 msr, int types)
{
	if (types & MSR_TYPE_R)
		nested_vmx_set_msr_read_intercept(vmx, msr_bitmap_l1,
						  msr_bitmap_l0, msr);
	if (types & MSR_TYPE_W)
		nested_vmx_set_msr_write_intercept(vmx, msr_bitmap_l1,
						   msr_bitmap_l0, msr);
}

static inline bool nested_vmx_prepare_msr_bitmap(struct kvm_vcpu *vcpu,
						 struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int msr;
	unsigned long *msr_bitmap_l1;
	unsigned long *msr_bitmap_l0 = vmx->nested.vmcs02.msr_bitmap;
	struct hv_enlightened_vmcs *evmcs = vmx->nested.hv_evmcs;
	struct kvm_host_map *map = &vmx->nested.msr_bitmap_map;

	/* Nothing to do if the MSR bitmap is not in use.  */
	if (!cpu_has_vmx_msr_bitmap() ||
	    !nested_cpu_has(vmcs12, CPU_BASED_USE_MSR_BITMAPS))
		return false;

	/*
	if (!vmx->nested.force_msr_bitmap_recalc && evmcs &&
	    evmcs->hv_enlightenments_control.msr_bitmap &&
	    evmcs->hv_clean_fields & HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP)
		return true;

	if (kvm_vcpu_map(vcpu, gpa_to_gfn(vmcs12->msr_bitmap), map))
		return false;

	msr_bitmap_l1 = (unsigned long *)map->hva;

	/*
	enable_x2apic_msr_intercepts(msr_bitmap_l0);

	if (nested_cpu_has_virt_x2apic_mode(vmcs12)) {
		if (nested_cpu_has_apic_reg_virt(vmcs12)) {
			/*
			for (msr = 0x800; msr <= 0x8ff; msr += BITS_PER_LONG) {
				unsigned word = msr / BITS_PER_LONG;

				msr_bitmap_l0[word] = msr_bitmap_l1[word];
			}
		}

		nested_vmx_disable_intercept_for_x2apic_msr(
			msr_bitmap_l1, msr_bitmap_l0,
			X2APIC_MSR(APIC_TASKPRI),
			MSR_TYPE_R | MSR_TYPE_W);

		if (nested_cpu_has_vid(vmcs12)) {
			nested_vmx_disable_intercept_for_x2apic_msr(
				msr_bitmap_l1, msr_bitmap_l0,
				X2APIC_MSR(APIC_EOI),
				MSR_TYPE_W);
			nested_vmx_disable_intercept_for_x2apic_msr(
				msr_bitmap_l1, msr_bitmap_l0,
				X2APIC_MSR(APIC_SELF_IPI),
				MSR_TYPE_W);
		}
	}

	/*
#ifdef CONFIG_X86_64
	nested_vmx_set_intercept_for_msr(vmx, msr_bitmap_l1, msr_bitmap_l0,
					 MSR_FS_BASE, MSR_TYPE_RW);

	nested_vmx_set_intercept_for_msr(vmx, msr_bitmap_l1, msr_bitmap_l0,
					 MSR_GS_BASE, MSR_TYPE_RW);

	nested_vmx_set_intercept_for_msr(vmx, msr_bitmap_l1, msr_bitmap_l0,
					 MSR_KERNEL_GS_BASE, MSR_TYPE_RW);
#endif
	nested_vmx_set_intercept_for_msr(vmx, msr_bitmap_l1, msr_bitmap_l0,
					 MSR_IA32_SPEC_CTRL, MSR_TYPE_RW);

	nested_vmx_set_intercept_for_msr(vmx, msr_bitmap_l1, msr_bitmap_l0,
					 MSR_IA32_PRED_CMD, MSR_TYPE_W);

	kvm_vcpu_unmap(vcpu, &vmx->nested.msr_bitmap_map, false);

	vmx->nested.force_msr_bitmap_recalc = false;

	return true;
}

static void nested_cache_shadow_vmcs12(struct kvm_vcpu *vcpu,
				       struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct gfn_to_hva_cache *ghc = &vmx->nested.shadow_vmcs12_cache;

	if (!nested_cpu_has_shadow_vmcs(vmcs12) ||
	    vmcs12->vmcs_link_pointer == INVALID_GPA)
		return;

	if (ghc->gpa != vmcs12->vmcs_link_pointer &&
	    kvm_gfn_to_hva_cache_init(vcpu->kvm, ghc,
				      vmcs12->vmcs_link_pointer, VMCS12_SIZE))
		return;

	kvm_read_guest_cached(vmx->vcpu.kvm, ghc, get_shadow_vmcs12(vcpu),
			      VMCS12_SIZE);
}

static void nested_flush_cached_shadow_vmcs12(struct kvm_vcpu *vcpu,
					      struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct gfn_to_hva_cache *ghc = &vmx->nested.shadow_vmcs12_cache;

	if (!nested_cpu_has_shadow_vmcs(vmcs12) ||
	    vmcs12->vmcs_link_pointer == INVALID_GPA)
		return;

	if (ghc->gpa != vmcs12->vmcs_link_pointer &&
	    kvm_gfn_to_hva_cache_init(vcpu->kvm, ghc,
				      vmcs12->vmcs_link_pointer, VMCS12_SIZE))
		return;

	kvm_write_guest_cached(vmx->vcpu.kvm, ghc, get_shadow_vmcs12(vcpu),
			       VMCS12_SIZE);
}

static bool nested_exit_intr_ack_set(struct kvm_vcpu *vcpu)
{
	return get_vmcs12(vcpu)->vm_exit_controls &
		VM_EXIT_ACK_INTR_ON_EXIT;
}

static int nested_vmx_check_apic_access_controls(struct kvm_vcpu *vcpu,
					  struct vmcs12 *vmcs12)
{
	if (nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES) &&
	    CC(!page_address_valid(vcpu, vmcs12->apic_access_addr)))
		return -EINVAL;
	else
		return 0;
}

static int nested_vmx_check_apicv_controls(struct kvm_vcpu *vcpu,
					   struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has_virt_x2apic_mode(vmcs12) &&
	    !nested_cpu_has_apic_reg_virt(vmcs12) &&
	    !nested_cpu_has_vid(vmcs12) &&
	    !nested_cpu_has_posted_intr(vmcs12))
		return 0;

	/*
	if (CC(nested_cpu_has_virt_x2apic_mode(vmcs12) &&
	       nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)))
		return -EINVAL;

	/*
	if (CC(nested_cpu_has_vid(vmcs12) && !nested_exit_on_intr(vcpu)))
		return -EINVAL;

	/*
	if (nested_cpu_has_posted_intr(vmcs12) &&
	   (CC(!nested_cpu_has_vid(vmcs12)) ||
	    CC(!nested_exit_intr_ack_set(vcpu)) ||
	    CC((vmcs12->posted_intr_nv & 0xff00)) ||
	    CC(!kvm_vcpu_is_legal_aligned_gpa(vcpu, vmcs12->posted_intr_desc_addr, 64))))
		return -EINVAL;

	/* tpr shadow is needed by all apicv features. */
	if (CC(!nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW)))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_msr_switch(struct kvm_vcpu *vcpu,
				       u32 count, u64 addr)
{
	if (count == 0)
		return 0;

	if (!kvm_vcpu_is_legal_aligned_gpa(vcpu, addr, 16) ||
	    !kvm_vcpu_is_legal_gpa(vcpu, (addr + count * sizeof(struct vmx_msr_entry) - 1)))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_exit_msr_switch_controls(struct kvm_vcpu *vcpu,
						     struct vmcs12 *vmcs12)
{
	if (CC(nested_vmx_check_msr_switch(vcpu,
					   vmcs12->vm_exit_msr_load_count,
					   vmcs12->vm_exit_msr_load_addr)) ||
	    CC(nested_vmx_check_msr_switch(vcpu,
					   vmcs12->vm_exit_msr_store_count,
					   vmcs12->vm_exit_msr_store_addr)))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_entry_msr_switch_controls(struct kvm_vcpu *vcpu,
                                                      struct vmcs12 *vmcs12)
{
	if (CC(nested_vmx_check_msr_switch(vcpu,
					   vmcs12->vm_entry_msr_load_count,
					   vmcs12->vm_entry_msr_load_addr)))
                return -EINVAL;

	return 0;
}

static int nested_vmx_check_pml_controls(struct kvm_vcpu *vcpu,
					 struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has_pml(vmcs12))
		return 0;

	if (CC(!nested_cpu_has_ept(vmcs12)) ||
	    CC(!page_address_valid(vcpu, vmcs12->pml_address)))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_unrestricted_guest_controls(struct kvm_vcpu *vcpu,
							struct vmcs12 *vmcs12)
{
	if (CC(nested_cpu_has2(vmcs12, SECONDARY_EXEC_UNRESTRICTED_GUEST) &&
	       !nested_cpu_has_ept(vmcs12)))
		return -EINVAL;
	return 0;
}

static int nested_vmx_check_mode_based_ept_exec_controls(struct kvm_vcpu *vcpu,
							 struct vmcs12 *vmcs12)
{
	if (CC(nested_cpu_has2(vmcs12, SECONDARY_EXEC_MODE_BASED_EPT_EXEC) &&
	       !nested_cpu_has_ept(vmcs12)))
		return -EINVAL;
	return 0;
}

static int nested_vmx_check_shadow_vmcs_controls(struct kvm_vcpu *vcpu,
						 struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has_shadow_vmcs(vmcs12))
		return 0;

	if (CC(!page_address_valid(vcpu, vmcs12->vmread_bitmap)) ||
	    CC(!page_address_valid(vcpu, vmcs12->vmwrite_bitmap)))
		return -EINVAL;

	return 0;
}

static int nested_vmx_msr_check_common(struct kvm_vcpu *vcpu,
				       struct vmx_msr_entry *e)
{
	/* x2APIC MSR accesses are not allowed */
	if (CC(vcpu->arch.apic_base & X2APIC_ENABLE && e->index >> 8 == 0x8))
		return -EINVAL;
	if (CC(e->index == MSR_IA32_UCODE_WRITE) || /* SDM Table 35-2 */
	    CC(e->index == MSR_IA32_UCODE_REV))
		return -EINVAL;
	if (CC(e->reserved != 0))
		return -EINVAL;
	return 0;
}

static int nested_vmx_load_msr_check(struct kvm_vcpu *vcpu,
				     struct vmx_msr_entry *e)
{
	if (CC(e->index == MSR_FS_BASE) ||
	    CC(e->index == MSR_GS_BASE) ||
	    CC(e->index == MSR_IA32_SMM_MONITOR_CTL) || /* SMM is not supported */
	    nested_vmx_msr_check_common(vcpu, e))
		return -EINVAL;
	return 0;
}

static int nested_vmx_store_msr_check(struct kvm_vcpu *vcpu,
				      struct vmx_msr_entry *e)
{
	if (CC(e->index == MSR_IA32_SMBASE) || /* SMM is not supported */
	    nested_vmx_msr_check_common(vcpu, e))
		return -EINVAL;
	return 0;
}

static u32 nested_vmx_max_atomic_switch_msrs(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 vmx_misc = vmx_control_msr(vmx->nested.msrs.misc_low,
				       vmx->nested.msrs.misc_high);

	return (vmx_misc_max_msr(vmx_misc) + 1) * VMX_MISC_MSR_LIST_MULTIPLIER;
}

static u32 nested_vmx_load_msr(struct kvm_vcpu *vcpu, u64 gpa, u32 count)
{
	u32 i;
	struct vmx_msr_entry e;
	u32 max_msr_list_size = nested_vmx_max_atomic_switch_msrs(vcpu);

	for (i = 0; i < count; i++) {
		if (unlikely(i >= max_msr_list_size))
			goto fail;

		if (kvm_vcpu_read_guest(vcpu, gpa + i * sizeof(e),
					&e, sizeof(e))) {
			pr_debug_ratelimited(
				"%s cannot read MSR entry (%u, 0x%08llx)\n",
				__func__, i, gpa + i * sizeof(e));
			goto fail;
		}
		if (nested_vmx_load_msr_check(vcpu, &e)) {
			pr_debug_ratelimited(
				"%s check failed (%u, 0x%x, 0x%x)\n",
				__func__, i, e.index, e.reserved);
			goto fail;
		}
		if (kvm_set_msr(vcpu, e.index, e.value)) {
			pr_debug_ratelimited(
				"%s cannot write MSR (%u, 0x%x, 0x%llx)\n",
				__func__, i, e.index, e.value);
			goto fail;
		}
	}
	return 0;
fail:
	/* Note, max_msr_list_size is at most 4096, i.e. this can't wrap. */
	return i + 1;
}

static bool nested_vmx_get_vmexit_msr_value(struct kvm_vcpu *vcpu,
					    u32 msr_index,
					    u64 *data)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
	if (msr_index == MSR_IA32_TSC) {
		int i = vmx_find_loadstore_msr_slot(&vmx->msr_autostore.guest,
						    MSR_IA32_TSC);

		if (i >= 0) {
			u64 val = vmx->msr_autostore.guest.val[i].value;

			*data = kvm_read_l1_tsc(vcpu, val);
			return true;
		}
	}

	if (kvm_get_msr(vcpu, msr_index, data)) {
		pr_debug_ratelimited("%s cannot read MSR (0x%x)\n", __func__,
			msr_index);
		return false;
	}
	return true;
}

static bool read_and_check_msr_entry(struct kvm_vcpu *vcpu, u64 gpa, int i,
				     struct vmx_msr_entry *e)
{
	if (kvm_vcpu_read_guest(vcpu,
				gpa + i * sizeof(*e),
				e, 2 * sizeof(u32))) {
		pr_debug_ratelimited(
			"%s cannot read MSR entry (%u, 0x%08llx)\n",
			__func__, i, gpa + i * sizeof(*e));
		return false;
	}
	if (nested_vmx_store_msr_check(vcpu, e)) {
		pr_debug_ratelimited(
			"%s check failed (%u, 0x%x, 0x%x)\n",
			__func__, i, e->index, e->reserved);
		return false;
	}
	return true;
}

static int nested_vmx_store_msr(struct kvm_vcpu *vcpu, u64 gpa, u32 count)
{
	u64 data;
	u32 i;
	struct vmx_msr_entry e;
	u32 max_msr_list_size = nested_vmx_max_atomic_switch_msrs(vcpu);

	for (i = 0; i < count; i++) {
		if (unlikely(i >= max_msr_list_size))
			return -EINVAL;

		if (!read_and_check_msr_entry(vcpu, gpa, i, &e))
			return -EINVAL;

		if (!nested_vmx_get_vmexit_msr_value(vcpu, e.index, &data))
			return -EINVAL;

		if (kvm_vcpu_write_guest(vcpu,
					 gpa + i * sizeof(e) +
					     offsetof(struct vmx_msr_entry, value),
					 &data, sizeof(data))) {
			pr_debug_ratelimited(
				"%s cannot write MSR (%u, 0x%x, 0x%llx)\n",
				__func__, i, e.index, data);
			return -EINVAL;
		}
	}
	return 0;
}

static bool nested_msr_store_list_has_msr(struct kvm_vcpu *vcpu, u32 msr_index)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	u32 count = vmcs12->vm_exit_msr_store_count;
	u64 gpa = vmcs12->vm_exit_msr_store_addr;
	struct vmx_msr_entry e;
	u32 i;

	for (i = 0; i < count; i++) {
		if (!read_and_check_msr_entry(vcpu, gpa, i, &e))
			return false;

		if (e.index == msr_index)
			return true;
	}
	return false;
}

static void prepare_vmx_msr_autostore_list(struct kvm_vcpu *vcpu,
					   u32 msr_index)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmx_msrs *autostore = &vmx->msr_autostore.guest;
	bool in_vmcs12_store_list;
	int msr_autostore_slot;
	bool in_autostore_list;
	int last;

	msr_autostore_slot = vmx_find_loadstore_msr_slot(autostore, msr_index);
	in_autostore_list = msr_autostore_slot >= 0;
	in_vmcs12_store_list = nested_msr_store_list_has_msr(vcpu, msr_index);

	if (in_vmcs12_store_list && !in_autostore_list) {
		if (autostore->nr == MAX_NR_LOADSTORE_MSRS) {
			/*
			pr_warn_ratelimited(
				"Not enough msr entries in msr_autostore.  Can't add msr %x\n",
				msr_index);
			return;
		}
		last = autostore->nr++;
		autostore->val[last].index = msr_index;
	} else if (!in_vmcs12_store_list && in_autostore_list) {
		last = --autostore->nr;
		autostore->val[msr_autostore_slot] = autostore->val[last];
	}
}

static int nested_vmx_load_cr3(struct kvm_vcpu *vcpu, unsigned long cr3,
			       bool nested_ept, bool reload_pdptrs,
			       enum vm_entry_failure_code *entry_failure_code)
{
	if (CC(kvm_vcpu_is_illegal_gpa(vcpu, cr3))) {
		*entry_failure_code = ENTRY_FAIL_DEFAULT;
		return -EINVAL;
	}

	/*
	if (reload_pdptrs && !nested_ept && is_pae_paging(vcpu) &&
	    CC(!load_pdptrs(vcpu, cr3))) {
		*entry_failure_code = ENTRY_FAIL_PDPTE;
		return -EINVAL;
	}

	vcpu->arch.cr3 = cr3;
	kvm_register_mark_dirty(vcpu, VCPU_EXREG_CR3);

	/* Re-initialize the MMU, e.g. to pick up CR4 MMU role changes. */
	kvm_init_mmu(vcpu);

	if (!nested_ept)
		kvm_mmu_new_pgd(vcpu, cr3);

	return 0;
}

static bool nested_has_guest_tlb_tag(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	return enable_ept ||
	       (nested_cpu_has_vpid(vmcs12) && to_vmx(vcpu)->nested.vpid02);
}

static void nested_vmx_transition_tlb_flush(struct kvm_vcpu *vcpu,
					    struct vmcs12 *vmcs12,
					    bool is_vmenter)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
	if (!nested_cpu_has_vpid(vmcs12)) {
		kvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);
		return;
	}

	/* L2 should never have a VPID if VPID is disabled. */
	WARN_ON(!enable_vpid);

	/*
	if (is_vmenter && vmcs12->virtual_processor_id != vmx->nested.last_vpid) {
		vmx->nested.last_vpid = vmcs12->virtual_processor_id;
		kvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);
		return;
	}

	/*
	if (!nested_has_guest_tlb_tag(vcpu))
		kvm_make_request(KVM_REQ_TLB_FLUSH_CURRENT, vcpu);
}

static bool is_bitwise_subset(u64 superset, u64 subset, u64 mask)
{
	superset &= mask;
	subset &= mask;

	return (superset | subset) == superset;
}

static int vmx_restore_vmx_basic(struct vcpu_vmx *vmx, u64 data)
{
	const u64 feature_and_reserved =
		/* feature (except bit 48; see below) */
		BIT_ULL(49) | BIT_ULL(54) | BIT_ULL(55) |
		/* reserved */
		BIT_ULL(31) | GENMASK_ULL(47, 45) | GENMASK_ULL(63, 56);
	u64 vmx_basic = vmcs_config.nested.basic;

	if (!is_bitwise_subset(vmx_basic, data, feature_and_reserved))
		return -EINVAL;

	/*
	if (data & BIT_ULL(48))
		return -EINVAL;

	if (vmx_basic_vmcs_revision_id(vmx_basic) !=
	    vmx_basic_vmcs_revision_id(data))
		return -EINVAL;

	if (vmx_basic_vmcs_size(vmx_basic) > vmx_basic_vmcs_size(data))
		return -EINVAL;

	vmx->nested.msrs.basic = data;
	return 0;
}

static void vmx_get_control_msr(struct nested_vmx_msrs *msrs, u32 msr_index,
				u32 **low, u32 **high)
{
	switch (msr_index) {
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
		*low = &msrs->pinbased_ctls_low;
		*high = &msrs->pinbased_ctls_high;
		break;
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
		*low = &msrs->procbased_ctls_low;
		*high = &msrs->procbased_ctls_high;
		break;
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
		*low = &msrs->exit_ctls_low;
		*high = &msrs->exit_ctls_high;
		break;
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
		*low = &msrs->entry_ctls_low;
		*high = &msrs->entry_ctls_high;
		break;
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		*low = &msrs->secondary_ctls_low;
		*high = &msrs->secondary_ctls_high;
		break;
	default:
		BUG();
	}
}

static int
vmx_restore_control_msr(struct vcpu_vmx *vmx, u32 msr_index, u64 data)
{
	u32 *lowp, *highp;
	u64 supported;

	vmx_get_control_msr(&vmcs_config.nested, msr_index, &lowp, &highp);

	supported = vmx_control_msr(*lowp, *highp);

	/* Check must-be-1 bits are still 1. */
	if (!is_bitwise_subset(data, supported, GENMASK_ULL(31, 0)))
		return -EINVAL;

	/* Check must-be-0 bits are still 0. */
	if (!is_bitwise_subset(supported, data, GENMASK_ULL(63, 32)))
		return -EINVAL;

	vmx_get_control_msr(&vmx->nested.msrs, msr_index, &lowp, &highp);
	return 0;
}

static int vmx_restore_vmx_misc(struct vcpu_vmx *vmx, u64 data)
{
	const u64 feature_and_reserved_bits =
		/* feature */
		BIT_ULL(5) | GENMASK_ULL(8, 6) | BIT_ULL(14) | BIT_ULL(15) |
		BIT_ULL(28) | BIT_ULL(29) | BIT_ULL(30) |
		/* reserved */
		GENMASK_ULL(13, 9) | BIT_ULL(31);
	u64 vmx_misc = vmx_control_msr(vmcs_config.nested.misc_low,
				       vmcs_config.nested.misc_high);

	if (!is_bitwise_subset(vmx_misc, data, feature_and_reserved_bits))
		return -EINVAL;

	if ((vmx->nested.msrs.pinbased_ctls_high &
	     PIN_BASED_VMX_PREEMPTION_TIMER) &&
	    vmx_misc_preemption_timer_rate(data) !=
	    vmx_misc_preemption_timer_rate(vmx_misc))
		return -EINVAL;

	if (vmx_misc_cr3_count(data) > vmx_misc_cr3_count(vmx_misc))
		return -EINVAL;

	if (vmx_misc_max_msr(data) > vmx_misc_max_msr(vmx_misc))
		return -EINVAL;

	if (vmx_misc_mseg_revid(data) != vmx_misc_mseg_revid(vmx_misc))
		return -EINVAL;

	vmx->nested.msrs.misc_low = data;
	vmx->nested.msrs.misc_high = data >> 32;

	return 0;
}

static int vmx_restore_vmx_ept_vpid_cap(struct vcpu_vmx *vmx, u64 data)
{
	u64 vmx_ept_vpid_cap = vmx_control_msr(vmcs_config.nested.ept_caps,
					       vmcs_config.nested.vpid_caps);

	/* Every bit is either reserved or a feature bit. */
	if (!is_bitwise_subset(vmx_ept_vpid_cap, data, -1ULL))
		return -EINVAL;

	vmx->nested.msrs.ept_caps = data;
	vmx->nested.msrs.vpid_caps = data >> 32;
	return 0;
}

static u64 *vmx_get_fixed0_msr(struct nested_vmx_msrs *msrs, u32 msr_index)
{
	switch (msr_index) {
	case MSR_IA32_VMX_CR0_FIXED0:
		return &msrs->cr0_fixed0;
	case MSR_IA32_VMX_CR4_FIXED0:
		return &msrs->cr4_fixed0;
	default:
		BUG();
	}
}

static int vmx_restore_fixed0_msr(struct vcpu_vmx *vmx, u32 msr_index, u64 data)
{
	const u64 *msr = vmx_get_fixed0_msr(&vmcs_config.nested, msr_index);

	/*
	if (!is_bitwise_subset(data, *msr, -1ULL))
		return -EINVAL;

	return 0;
}

int vmx_set_vmx_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 data)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
	if (vmx->nested.vmxon)
		return -EBUSY;

	switch (msr_index) {
	case MSR_IA32_VMX_BASIC:
		return vmx_restore_vmx_basic(vmx, data);
	case MSR_IA32_VMX_PINBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
		/*
		return -EINVAL;
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		return vmx_restore_control_msr(vmx, msr_index, data);
	case MSR_IA32_VMX_MISC:
		return vmx_restore_vmx_misc(vmx, data);
	case MSR_IA32_VMX_CR0_FIXED0:
	case MSR_IA32_VMX_CR4_FIXED0:
		return vmx_restore_fixed0_msr(vmx, msr_index, data);
	case MSR_IA32_VMX_CR0_FIXED1:
	case MSR_IA32_VMX_CR4_FIXED1:
		/*
		return -EINVAL;
	case MSR_IA32_VMX_EPT_VPID_CAP:
		return vmx_restore_vmx_ept_vpid_cap(vmx, data);
	case MSR_IA32_VMX_VMCS_ENUM:
		vmx->nested.msrs.vmcs_enum = data;
		return 0;
	case MSR_IA32_VMX_VMFUNC:
		if (data & ~vmcs_config.nested.vmfunc_controls)
			return -EINVAL;
		vmx->nested.msrs.vmfunc_controls = data;
		return 0;
	default:
		/*
		return -EINVAL;
	}
}

int vmx_get_vmx_msr(struct nested_vmx_msrs *msrs, u32 msr_index, u64 *pdata)
{
	switch (msr_index) {
	case MSR_IA32_VMX_BASIC:
		*pdata = msrs->basic;
		break;
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_PINBASED_CTLS:
		*pdata = vmx_control_msr(
			msrs->pinbased_ctls_low,
			msrs->pinbased_ctls_high);
		if (msr_index == MSR_IA32_VMX_PINBASED_CTLS)
			*pdata |= PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
		*pdata = vmx_control_msr(
			msrs->procbased_ctls_low,
			msrs->procbased_ctls_high);
		if (msr_index == MSR_IA32_VMX_PROCBASED_CTLS)
			*pdata |= CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
		*pdata = vmx_control_msr(
			msrs->exit_ctls_low,
			msrs->exit_ctls_high);
		if (msr_index == MSR_IA32_VMX_EXIT_CTLS)
			*pdata |= VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
		*pdata = vmx_control_msr(
			msrs->entry_ctls_low,
			msrs->entry_ctls_high);
		if (msr_index == MSR_IA32_VMX_ENTRY_CTLS)
			*pdata |= VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_MISC:
		*pdata = vmx_control_msr(
			msrs->misc_low,
			msrs->misc_high);
		break;
	case MSR_IA32_VMX_CR0_FIXED0:
		*pdata = msrs->cr0_fixed0;
		break;
	case MSR_IA32_VMX_CR0_FIXED1:
		*pdata = msrs->cr0_fixed1;
		break;
	case MSR_IA32_VMX_CR4_FIXED0:
		*pdata = msrs->cr4_fixed0;
		break;
	case MSR_IA32_VMX_CR4_FIXED1:
		*pdata = msrs->cr4_fixed1;
		break;
	case MSR_IA32_VMX_VMCS_ENUM:
		*pdata = msrs->vmcs_enum;
		break;
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		*pdata = vmx_control_msr(
			msrs->secondary_ctls_low,
			msrs->secondary_ctls_high);
		break;
	case MSR_IA32_VMX_EPT_VPID_CAP:
		*pdata = msrs->ept_caps |
			((u64)msrs->vpid_caps << 32);
		break;
	case MSR_IA32_VMX_VMFUNC:
		*pdata = msrs->vmfunc_controls;
		break;
	default:
		return 1;
	}

	return 0;
}

static void copy_shadow_to_vmcs12(struct vcpu_vmx *vmx)
{
	struct vmcs *shadow_vmcs = vmx->vmcs01.shadow_vmcs;
	struct vmcs12 *vmcs12 = get_vmcs12(&vmx->vcpu);
	struct shadow_vmcs_field field;
	unsigned long val;
	int i;

	if (WARN_ON(!shadow_vmcs))
		return;

	preempt_disable();

	vmcs_load(shadow_vmcs);

	for (i = 0; i < max_shadow_read_write_fields; i++) {
		field = shadow_read_write_fields[i];
		val = __vmcs_readl(field.encoding);
		vmcs12_write_any(vmcs12, field.encoding, field.offset, val);
	}

	vmcs_clear(shadow_vmcs);
	vmcs_load(vmx->loaded_vmcs->vmcs);

	preempt_enable();
}

static void copy_vmcs12_to_shadow(struct vcpu_vmx *vmx)
{
	const struct shadow_vmcs_field *fields[] = {
		shadow_read_write_fields,
		shadow_read_only_fields
	};
	const int max_fields[] = {
		max_shadow_read_write_fields,
		max_shadow_read_only_fields
	};
	struct vmcs *shadow_vmcs = vmx->vmcs01.shadow_vmcs;
	struct vmcs12 *vmcs12 = get_vmcs12(&vmx->vcpu);
	struct shadow_vmcs_field field;
	unsigned long val;
	int i, q;

	if (WARN_ON(!shadow_vmcs))
		return;

	vmcs_load(shadow_vmcs);

	for (q = 0; q < ARRAY_SIZE(fields); q++) {
		for (i = 0; i < max_fields[q]; i++) {
			field = fields[q][i];
			val = vmcs12_read_any(vmcs12, field.encoding,
					      field.offset);
			__vmcs_writel(field.encoding, val);
		}
	}

	vmcs_clear(shadow_vmcs);
	vmcs_load(vmx->loaded_vmcs->vmcs);
}

static void copy_enlightened_to_vmcs12(struct vcpu_vmx *vmx, u32 hv_clean_fields)
{
	struct vmcs12 *vmcs12 = vmx->nested.cached_vmcs12;
	struct hv_enlightened_vmcs *evmcs = vmx->nested.hv_evmcs;

	/* HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE */
	vmcs12->tpr_threshold = evmcs->tpr_threshold;
	vmcs12->guest_rip = evmcs->guest_rip;

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC))) {
		vmcs12->guest_rsp = evmcs->guest_rsp;
		vmcs12->guest_rflags = evmcs->guest_rflags;
		vmcs12->guest_interruptibility_info =
			evmcs->guest_interruptibility_info;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_PROC))) {
		vmcs12->cpu_based_vm_exec_control =
			evmcs->cpu_based_vm_exec_control;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN))) {
		vmcs12->exception_bitmap = evmcs->exception_bitmap;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY))) {
		vmcs12->vm_entry_controls = evmcs->vm_entry_controls;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT))) {
		vmcs12->vm_entry_intr_info_field =
			evmcs->vm_entry_intr_info_field;
		vmcs12->vm_entry_exception_error_code =
			evmcs->vm_entry_exception_error_code;
		vmcs12->vm_entry_instruction_len =
			evmcs->vm_entry_instruction_len;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1))) {
		vmcs12->host_ia32_pat = evmcs->host_ia32_pat;
		vmcs12->host_ia32_efer = evmcs->host_ia32_efer;
		vmcs12->host_cr0 = evmcs->host_cr0;
		vmcs12->host_cr3 = evmcs->host_cr3;
		vmcs12->host_cr4 = evmcs->host_cr4;
		vmcs12->host_ia32_sysenter_esp = evmcs->host_ia32_sysenter_esp;
		vmcs12->host_ia32_sysenter_eip = evmcs->host_ia32_sysenter_eip;
		vmcs12->host_rip = evmcs->host_rip;
		vmcs12->host_ia32_sysenter_cs = evmcs->host_ia32_sysenter_cs;
		vmcs12->host_es_selector = evmcs->host_es_selector;
		vmcs12->host_cs_selector = evmcs->host_cs_selector;
		vmcs12->host_ss_selector = evmcs->host_ss_selector;
		vmcs12->host_ds_selector = evmcs->host_ds_selector;
		vmcs12->host_fs_selector = evmcs->host_fs_selector;
		vmcs12->host_gs_selector = evmcs->host_gs_selector;
		vmcs12->host_tr_selector = evmcs->host_tr_selector;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1))) {
		vmcs12->pin_based_vm_exec_control =
			evmcs->pin_based_vm_exec_control;
		vmcs12->vm_exit_controls = evmcs->vm_exit_controls;
		vmcs12->secondary_vm_exec_control =
			evmcs->secondary_vm_exec_control;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP))) {
		vmcs12->io_bitmap_a = evmcs->io_bitmap_a;
		vmcs12->io_bitmap_b = evmcs->io_bitmap_b;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP))) {
		vmcs12->msr_bitmap = evmcs->msr_bitmap;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2))) {
		vmcs12->guest_es_base = evmcs->guest_es_base;
		vmcs12->guest_cs_base = evmcs->guest_cs_base;
		vmcs12->guest_ss_base = evmcs->guest_ss_base;
		vmcs12->guest_ds_base = evmcs->guest_ds_base;
		vmcs12->guest_fs_base = evmcs->guest_fs_base;
		vmcs12->guest_gs_base = evmcs->guest_gs_base;
		vmcs12->guest_ldtr_base = evmcs->guest_ldtr_base;
		vmcs12->guest_tr_base = evmcs->guest_tr_base;
		vmcs12->guest_gdtr_base = evmcs->guest_gdtr_base;
		vmcs12->guest_idtr_base = evmcs->guest_idtr_base;
		vmcs12->guest_es_limit = evmcs->guest_es_limit;
		vmcs12->guest_cs_limit = evmcs->guest_cs_limit;
		vmcs12->guest_ss_limit = evmcs->guest_ss_limit;
		vmcs12->guest_ds_limit = evmcs->guest_ds_limit;
		vmcs12->guest_fs_limit = evmcs->guest_fs_limit;
		vmcs12->guest_gs_limit = evmcs->guest_gs_limit;
		vmcs12->guest_ldtr_limit = evmcs->guest_ldtr_limit;
		vmcs12->guest_tr_limit = evmcs->guest_tr_limit;
		vmcs12->guest_gdtr_limit = evmcs->guest_gdtr_limit;
		vmcs12->guest_idtr_limit = evmcs->guest_idtr_limit;
		vmcs12->guest_es_ar_bytes = evmcs->guest_es_ar_bytes;
		vmcs12->guest_cs_ar_bytes = evmcs->guest_cs_ar_bytes;
		vmcs12->guest_ss_ar_bytes = evmcs->guest_ss_ar_bytes;
		vmcs12->guest_ds_ar_bytes = evmcs->guest_ds_ar_bytes;
		vmcs12->guest_fs_ar_bytes = evmcs->guest_fs_ar_bytes;
		vmcs12->guest_gs_ar_bytes = evmcs->guest_gs_ar_bytes;
		vmcs12->guest_ldtr_ar_bytes = evmcs->guest_ldtr_ar_bytes;
		vmcs12->guest_tr_ar_bytes = evmcs->guest_tr_ar_bytes;
		vmcs12->guest_es_selector = evmcs->guest_es_selector;
		vmcs12->guest_cs_selector = evmcs->guest_cs_selector;
		vmcs12->guest_ss_selector = evmcs->guest_ss_selector;
		vmcs12->guest_ds_selector = evmcs->guest_ds_selector;
		vmcs12->guest_fs_selector = evmcs->guest_fs_selector;
		vmcs12->guest_gs_selector = evmcs->guest_gs_selector;
		vmcs12->guest_ldtr_selector = evmcs->guest_ldtr_selector;
		vmcs12->guest_tr_selector = evmcs->guest_tr_selector;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2))) {
		vmcs12->tsc_offset = evmcs->tsc_offset;
		vmcs12->virtual_apic_page_addr = evmcs->virtual_apic_page_addr;
		vmcs12->xss_exit_bitmap = evmcs->xss_exit_bitmap;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR))) {
		vmcs12->cr0_guest_host_mask = evmcs->cr0_guest_host_mask;
		vmcs12->cr4_guest_host_mask = evmcs->cr4_guest_host_mask;
		vmcs12->cr0_read_shadow = evmcs->cr0_read_shadow;
		vmcs12->cr4_read_shadow = evmcs->cr4_read_shadow;
		vmcs12->guest_cr0 = evmcs->guest_cr0;
		vmcs12->guest_cr3 = evmcs->guest_cr3;
		vmcs12->guest_cr4 = evmcs->guest_cr4;
		vmcs12->guest_dr7 = evmcs->guest_dr7;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER))) {
		vmcs12->host_fs_base = evmcs->host_fs_base;
		vmcs12->host_gs_base = evmcs->host_gs_base;
		vmcs12->host_tr_base = evmcs->host_tr_base;
		vmcs12->host_gdtr_base = evmcs->host_gdtr_base;
		vmcs12->host_idtr_base = evmcs->host_idtr_base;
		vmcs12->host_rsp = evmcs->host_rsp;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT))) {
		vmcs12->ept_pointer = evmcs->ept_pointer;
		vmcs12->virtual_processor_id = evmcs->virtual_processor_id;
	}

	if (unlikely(!(hv_clean_fields &
		       HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1))) {
		vmcs12->vmcs_link_pointer = evmcs->vmcs_link_pointer;
		vmcs12->guest_ia32_debugctl = evmcs->guest_ia32_debugctl;
		vmcs12->guest_ia32_pat = evmcs->guest_ia32_pat;
		vmcs12->guest_ia32_efer = evmcs->guest_ia32_efer;
		vmcs12->guest_pdptr0 = evmcs->guest_pdptr0;
		vmcs12->guest_pdptr1 = evmcs->guest_pdptr1;
		vmcs12->guest_pdptr2 = evmcs->guest_pdptr2;
		vmcs12->guest_pdptr3 = evmcs->guest_pdptr3;
		vmcs12->guest_pending_dbg_exceptions =
			evmcs->guest_pending_dbg_exceptions;
		vmcs12->guest_sysenter_esp = evmcs->guest_sysenter_esp;
		vmcs12->guest_sysenter_eip = evmcs->guest_sysenter_eip;
		vmcs12->guest_bndcfgs = evmcs->guest_bndcfgs;
		vmcs12->guest_activity_state = evmcs->guest_activity_state;
		vmcs12->guest_sysenter_cs = evmcs->guest_sysenter_cs;
	}

	/*

	/*

	return;
}

static void copy_vmcs12_to_enlightened(struct vcpu_vmx *vmx)
{
	struct vmcs12 *vmcs12 = vmx->nested.cached_vmcs12;
	struct hv_enlightened_vmcs *evmcs = vmx->nested.hv_evmcs;

	/*

	evmcs->guest_es_selector = vmcs12->guest_es_selector;
	evmcs->guest_cs_selector = vmcs12->guest_cs_selector;
	evmcs->guest_ss_selector = vmcs12->guest_ss_selector;
	evmcs->guest_ds_selector = vmcs12->guest_ds_selector;
	evmcs->guest_fs_selector = vmcs12->guest_fs_selector;
	evmcs->guest_gs_selector = vmcs12->guest_gs_selector;
	evmcs->guest_ldtr_selector = vmcs12->guest_ldtr_selector;
	evmcs->guest_tr_selector = vmcs12->guest_tr_selector;

	evmcs->guest_es_limit = vmcs12->guest_es_limit;
	evmcs->guest_cs_limit = vmcs12->guest_cs_limit;
	evmcs->guest_ss_limit = vmcs12->guest_ss_limit;
	evmcs->guest_ds_limit = vmcs12->guest_ds_limit;
	evmcs->guest_fs_limit = vmcs12->guest_fs_limit;
	evmcs->guest_gs_limit = vmcs12->guest_gs_limit;
	evmcs->guest_ldtr_limit = vmcs12->guest_ldtr_limit;
	evmcs->guest_tr_limit = vmcs12->guest_tr_limit;
	evmcs->guest_gdtr_limit = vmcs12->guest_gdtr_limit;
	evmcs->guest_idtr_limit = vmcs12->guest_idtr_limit;

	evmcs->guest_es_ar_bytes = vmcs12->guest_es_ar_bytes;
	evmcs->guest_cs_ar_bytes = vmcs12->guest_cs_ar_bytes;
	evmcs->guest_ss_ar_bytes = vmcs12->guest_ss_ar_bytes;
	evmcs->guest_ds_ar_bytes = vmcs12->guest_ds_ar_bytes;
	evmcs->guest_fs_ar_bytes = vmcs12->guest_fs_ar_bytes;
	evmcs->guest_gs_ar_bytes = vmcs12->guest_gs_ar_bytes;
	evmcs->guest_ldtr_ar_bytes = vmcs12->guest_ldtr_ar_bytes;
	evmcs->guest_tr_ar_bytes = vmcs12->guest_tr_ar_bytes;

	evmcs->guest_es_base = vmcs12->guest_es_base;
	evmcs->guest_cs_base = vmcs12->guest_cs_base;
	evmcs->guest_ss_base = vmcs12->guest_ss_base;
	evmcs->guest_ds_base = vmcs12->guest_ds_base;
	evmcs->guest_fs_base = vmcs12->guest_fs_base;
	evmcs->guest_gs_base = vmcs12->guest_gs_base;
	evmcs->guest_ldtr_base = vmcs12->guest_ldtr_base;
	evmcs->guest_tr_base = vmcs12->guest_tr_base;
	evmcs->guest_gdtr_base = vmcs12->guest_gdtr_base;
	evmcs->guest_idtr_base = vmcs12->guest_idtr_base;

	evmcs->guest_ia32_pat = vmcs12->guest_ia32_pat;
	evmcs->guest_ia32_efer = vmcs12->guest_ia32_efer;

	evmcs->guest_pdptr0 = vmcs12->guest_pdptr0;
	evmcs->guest_pdptr1 = vmcs12->guest_pdptr1;
	evmcs->guest_pdptr2 = vmcs12->guest_pdptr2;
	evmcs->guest_pdptr3 = vmcs12->guest_pdptr3;

	evmcs->guest_pending_dbg_exceptions =
		vmcs12->guest_pending_dbg_exceptions;
	evmcs->guest_sysenter_esp = vmcs12->guest_sysenter_esp;
	evmcs->guest_sysenter_eip = vmcs12->guest_sysenter_eip;

	evmcs->guest_activity_state = vmcs12->guest_activity_state;
	evmcs->guest_sysenter_cs = vmcs12->guest_sysenter_cs;

	evmcs->guest_cr0 = vmcs12->guest_cr0;
	evmcs->guest_cr3 = vmcs12->guest_cr3;
	evmcs->guest_cr4 = vmcs12->guest_cr4;
	evmcs->guest_dr7 = vmcs12->guest_dr7;

	evmcs->guest_physical_address = vmcs12->guest_physical_address;

	evmcs->vm_instruction_error = vmcs12->vm_instruction_error;
	evmcs->vm_exit_reason = vmcs12->vm_exit_reason;
	evmcs->vm_exit_intr_info = vmcs12->vm_exit_intr_info;
	evmcs->vm_exit_intr_error_code = vmcs12->vm_exit_intr_error_code;
	evmcs->idt_vectoring_info_field = vmcs12->idt_vectoring_info_field;
	evmcs->idt_vectoring_error_code = vmcs12->idt_vectoring_error_code;
	evmcs->vm_exit_instruction_len = vmcs12->vm_exit_instruction_len;
	evmcs->vmx_instruction_info = vmcs12->vmx_instruction_info;

	evmcs->exit_qualification = vmcs12->exit_qualification;

	evmcs->guest_linear_address = vmcs12->guest_linear_address;
	evmcs->guest_rsp = vmcs12->guest_rsp;
	evmcs->guest_rflags = vmcs12->guest_rflags;

	evmcs->guest_interruptibility_info =
		vmcs12->guest_interruptibility_info;
	evmcs->cpu_based_vm_exec_control = vmcs12->cpu_based_vm_exec_control;
	evmcs->vm_entry_controls = vmcs12->vm_entry_controls;
	evmcs->vm_entry_intr_info_field = vmcs12->vm_entry_intr_info_field;
	evmcs->vm_entry_exception_error_code =
		vmcs12->vm_entry_exception_error_code;
	evmcs->vm_entry_instruction_len = vmcs12->vm_entry_instruction_len;

	evmcs->guest_rip = vmcs12->guest_rip;

	evmcs->guest_bndcfgs = vmcs12->guest_bndcfgs;

	return;
}

static enum nested_evmptrld_status nested_vmx_handle_enlightened_vmptrld(
	struct kvm_vcpu *vcpu, bool from_launch)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	bool evmcs_gpa_changed = false;
	u64 evmcs_gpa;

	if (likely(!vmx->nested.enlightened_vmcs_enabled))
		return EVMPTRLD_DISABLED;

	if (!nested_enlightened_vmentry(vcpu, &evmcs_gpa)) {
		nested_release_evmcs(vcpu);
		return EVMPTRLD_DISABLED;
	}

	if (unlikely(evmcs_gpa != vmx->nested.hv_evmcs_vmptr)) {
		vmx->nested.current_vmptr = INVALID_GPA;

		nested_release_evmcs(vcpu);

		if (kvm_vcpu_map(vcpu, gpa_to_gfn(evmcs_gpa),
				 &vmx->nested.hv_evmcs_map))
			return EVMPTRLD_ERROR;

		vmx->nested.hv_evmcs = vmx->nested.hv_evmcs_map.hva;

		/*
		if ((vmx->nested.hv_evmcs->revision_id != KVM_EVMCS_VERSION) &&
		    (vmx->nested.hv_evmcs->revision_id != VMCS12_REVISION)) {
			nested_release_evmcs(vcpu);
			return EVMPTRLD_VMFAIL;
		}

		vmx->nested.hv_evmcs_vmptr = evmcs_gpa;

		evmcs_gpa_changed = true;
		/*
		if (from_launch) {
			struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
			memset(vmcs12, 0, sizeof(*vmcs12));
			vmcs12->hdr.revision_id = VMCS12_REVISION;
		}

	}

	/*
	if (from_launch || evmcs_gpa_changed) {
		vmx->nested.hv_evmcs->hv_clean_fields &=
			~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;

		vmx->nested.force_msr_bitmap_recalc = true;
	}

	return EVMPTRLD_SUCCEEDED;
}

void nested_sync_vmcs12_to_shadow(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (evmptr_is_valid(vmx->nested.hv_evmcs_vmptr))
		copy_vmcs12_to_enlightened(vmx);
	else
		copy_vmcs12_to_shadow(vmx);

	vmx->nested.need_vmcs12_to_shadow_sync = false;
}

static enum hrtimer_restart vmx_preemption_timer_fn(struct hrtimer *timer)
{
	struct vcpu_vmx *vmx =
		container_of(timer, struct vcpu_vmx, nested.preemption_timer);

	vmx->nested.preemption_timer_expired = true;
	kvm_make_request(KVM_REQ_EVENT, &vmx->vcpu);
	kvm_vcpu_kick(&vmx->vcpu);

	return HRTIMER_NORESTART;
}

static u64 vmx_calc_preemption_timer_value(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	u64 l1_scaled_tsc = kvm_read_l1_tsc(vcpu, rdtsc()) >>
			    VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE;

	if (!vmx->nested.has_preemption_timer_deadline) {
		vmx->nested.preemption_timer_deadline =
			vmcs12->vmx_preemption_timer_value + l1_scaled_tsc;
		vmx->nested.has_preemption_timer_deadline = true;
	}
	return vmx->nested.preemption_timer_deadline - l1_scaled_tsc;
}

static void vmx_start_preemption_timer(struct kvm_vcpu *vcpu,
					u64 preemption_timeout)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
	if (preemption_timeout == 0) {
		vmx_preemption_timer_fn(&vmx->nested.preemption_timer);
		return;
	}

	if (vcpu->arch.virtual_tsc_khz == 0)
		return;

	preemption_timeout <<= VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE;
	preemption_timeout *= 1000000;
	do_div(preemption_timeout, vcpu->arch.virtual_tsc_khz);
	hrtimer_start(&vmx->nested.preemption_timer,
		      ktime_add_ns(ktime_get(), preemption_timeout),
		      HRTIMER_MODE_ABS_PINNED);
}

static u64 nested_vmx_calc_efer(struct vcpu_vmx *vmx, struct vmcs12 *vmcs12)
{
	if (vmx->nested.nested_run_pending &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_EFER))
		return vmcs12->guest_ia32_efer;
	else if (vmcs12->vm_entry_controls & VM_ENTRY_IA32E_MODE)
		return vmx->vcpu.arch.efer | (EFER_LMA | EFER_LME);
	else
		return vmx->vcpu.arch.efer & ~(EFER_LMA | EFER_LME);
}

static void prepare_vmcs02_constant_state(struct vcpu_vmx *vmx)
{
	struct kvm *kvm = vmx->vcpu.kvm;

	/*
	if (vmx->nested.vmcs02_initialized)
		return;
	vmx->nested.vmcs02_initialized = true;

	/*
	if (enable_ept && nested_early_check)
		vmcs_write64(EPT_POINTER,
			     construct_eptp(&vmx->vcpu, 0, PT64_ROOT_4LEVEL));

	/* All VMFUNCs are currently emulated through L0 vmexits.  */
	if (cpu_has_vmx_vmfunc())
		vmcs_write64(VM_FUNCTION_CONTROL, 0);

	if (cpu_has_vmx_posted_intr())
		vmcs_write16(POSTED_INTR_NV, POSTED_INTR_NESTED_VECTOR);

	if (cpu_has_vmx_msr_bitmap())
		vmcs_write64(MSR_BITMAP, __pa(vmx->nested.vmcs02.msr_bitmap));

	/*
	if (enable_pml) {
		vmcs_write64(PML_ADDRESS, 0);
		vmcs_write16(GUEST_PML_INDEX, -1);
	}

	if (cpu_has_vmx_encls_vmexit())
		vmcs_write64(ENCLS_EXITING_BITMAP, INVALID_GPA);

	if (kvm_notify_vmexit_enabled(kvm))
		vmcs_write32(NOTIFY_WINDOW, kvm->arch.notify_window);

	/*
	vmcs_write64(VM_EXIT_MSR_STORE_ADDR, __pa(vmx->msr_autostore.guest.val));
	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.host.val));
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.guest.val));

	vmx_set_constant_host_state(vmx);
}

static void prepare_vmcs02_early_rare(struct vcpu_vmx *vmx,
				      struct vmcs12 *vmcs12)
{
	prepare_vmcs02_constant_state(vmx);

	vmcs_write64(VMCS_LINK_POINTER, INVALID_GPA);

	if (enable_vpid) {
		if (nested_cpu_has_vpid(vmcs12) && vmx->nested.vpid02)
			vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->nested.vpid02);
		else
			vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->vpid);
	}
}

static void prepare_vmcs02_early(struct vcpu_vmx *vmx, struct loaded_vmcs *vmcs01,
				 struct vmcs12 *vmcs12)
{
	u32 exec_control;
	u64 guest_efer = nested_vmx_calc_efer(vmx, vmcs12);

	if (vmx->nested.dirty_vmcs12 || evmptr_is_valid(vmx->nested.hv_evmcs_vmptr))
		prepare_vmcs02_early_rare(vmx, vmcs12);

	/*
	exec_control = __pin_controls_get(vmcs01);
	exec_control |= (vmcs12->pin_based_vm_exec_control &
			 ~PIN_BASED_VMX_PREEMPTION_TIMER);

	/* Posted interrupts setting is only taken from vmcs12.  */
	vmx->nested.pi_pending = false;
	if (nested_cpu_has_posted_intr(vmcs12))
		vmx->nested.posted_intr_nv = vmcs12->posted_intr_nv;
	else
		exec_control &= ~PIN_BASED_POSTED_INTR;
	pin_controls_set(vmx, exec_control);

	/*
	exec_control = __exec_controls_get(vmcs01); /* L0's desires */
	exec_control &= ~CPU_BASED_INTR_WINDOW_EXITING;
	exec_control &= ~CPU_BASED_NMI_WINDOW_EXITING;
	exec_control &= ~CPU_BASED_TPR_SHADOW;
	exec_control |= vmcs12->cpu_based_vm_exec_control;

	vmx->nested.l1_tpr_threshold = -1;
	if (exec_control & CPU_BASED_TPR_SHADOW)
		vmcs_write32(TPR_THRESHOLD, vmcs12->tpr_threshold);
#ifdef CONFIG_X86_64
	else
		exec_control |= CPU_BASED_CR8_LOAD_EXITING |
				CPU_BASED_CR8_STORE_EXITING;
#endif

	/*
	exec_control |= CPU_BASED_UNCOND_IO_EXITING;
	exec_control &= ~CPU_BASED_USE_IO_BITMAPS;

	/*
	exec_control &= ~CPU_BASED_USE_MSR_BITMAPS;
	exec_control |= exec_controls_get(vmx) & CPU_BASED_USE_MSR_BITMAPS;

	exec_controls_set(vmx, exec_control);

	/*
	if (cpu_has_secondary_exec_ctrls()) {
		exec_control = __secondary_exec_controls_get(vmcs01);

		/* Take the following fields only from vmcs12 */
		exec_control &= ~(SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
				  SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
				  SECONDARY_EXEC_ENABLE_INVPCID |
				  SECONDARY_EXEC_ENABLE_RDTSCP |
				  SECONDARY_EXEC_XSAVES |
				  SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE |
				  SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |
				  SECONDARY_EXEC_APIC_REGISTER_VIRT |
				  SECONDARY_EXEC_ENABLE_VMFUNC |
				  SECONDARY_EXEC_DESC);

		if (nested_cpu_has(vmcs12,
				   CPU_BASED_ACTIVATE_SECONDARY_CONTROLS))
			exec_control |= vmcs12->secondary_vm_exec_control;

		/* PML is emulated and never enabled in hardware for L2. */
		exec_control &= ~SECONDARY_EXEC_ENABLE_PML;

		/* VMCS shadowing for L2 is emulated for now */
		exec_control &= ~SECONDARY_EXEC_SHADOW_VMCS;

		/*
		if (!boot_cpu_has(X86_FEATURE_UMIP) && vmx_umip_emulated() &&
		    (vmcs12->guest_cr4 & X86_CR4_UMIP))
			exec_control |= SECONDARY_EXEC_DESC;

		if (exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY)
			vmcs_write16(GUEST_INTR_STATUS,
				vmcs12->guest_intr_status);

		if (!nested_cpu_has2(vmcs12, SECONDARY_EXEC_UNRESTRICTED_GUEST))
		    exec_control &= ~SECONDARY_EXEC_UNRESTRICTED_GUEST;

		if (exec_control & SECONDARY_EXEC_ENCLS_EXITING)
			vmx_write_encls_bitmap(&vmx->vcpu, vmcs12);

		secondary_exec_controls_set(vmx, exec_control);
	}

	/*
	exec_control = __vm_entry_controls_get(vmcs01);
	exec_control |= vmcs12->vm_entry_controls;
	exec_control &= ~(VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_IA32_EFER);
	if (cpu_has_load_ia32_efer()) {
		if (guest_efer & EFER_LMA)
			exec_control |= VM_ENTRY_IA32E_MODE;
		if (guest_efer != host_efer)
			exec_control |= VM_ENTRY_LOAD_IA32_EFER;
	}
	vm_entry_controls_set(vmx, exec_control);

	/*
	exec_control = __vm_exit_controls_get(vmcs01);
	if (cpu_has_load_ia32_efer() && guest_efer != host_efer)
		exec_control |= VM_EXIT_LOAD_IA32_EFER;
	else
		exec_control &= ~VM_EXIT_LOAD_IA32_EFER;
	vm_exit_controls_set(vmx, exec_control);

	/*
	if (vmx->nested.nested_run_pending) {
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     vmcs12->vm_entry_intr_info_field);
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE,
			     vmcs12->vm_entry_exception_error_code);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmcs12->vm_entry_instruction_len);
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO,
			     vmcs12->guest_interruptibility_info);
		vmx->loaded_vmcs->nmi_known_unmasked =
			!(vmcs12->guest_interruptibility_info & GUEST_INTR_STATE_NMI);
	} else {
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
	}
}

static void prepare_vmcs02_rare(struct vcpu_vmx *vmx, struct vmcs12 *vmcs12)
{
	struct hv_enlightened_vmcs *hv_evmcs = vmx->nested.hv_evmcs;

	if (!hv_evmcs || !(hv_evmcs->hv_clean_fields &
			   HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2)) {
		vmcs_write16(GUEST_ES_SELECTOR, vmcs12->guest_es_selector);
		vmcs_write16(GUEST_CS_SELECTOR, vmcs12->guest_cs_selector);
		vmcs_write16(GUEST_SS_SELECTOR, vmcs12->guest_ss_selector);
		vmcs_write16(GUEST_DS_SELECTOR, vmcs12->guest_ds_selector);
		vmcs_write16(GUEST_FS_SELECTOR, vmcs12->guest_fs_selector);
		vmcs_write16(GUEST_GS_SELECTOR, vmcs12->guest_gs_selector);
		vmcs_write16(GUEST_LDTR_SELECTOR, vmcs12->guest_ldtr_selector);
		vmcs_write16(GUEST_TR_SELECTOR, vmcs12->guest_tr_selector);
		vmcs_write32(GUEST_ES_LIMIT, vmcs12->guest_es_limit);
		vmcs_write32(GUEST_CS_LIMIT, vmcs12->guest_cs_limit);
		vmcs_write32(GUEST_SS_LIMIT, vmcs12->guest_ss_limit);
		vmcs_write32(GUEST_DS_LIMIT, vmcs12->guest_ds_limit);
		vmcs_write32(GUEST_FS_LIMIT, vmcs12->guest_fs_limit);
		vmcs_write32(GUEST_GS_LIMIT, vmcs12->guest_gs_limit);
		vmcs_write32(GUEST_LDTR_LIMIT, vmcs12->guest_ldtr_limit);
		vmcs_write32(GUEST_TR_LIMIT, vmcs12->guest_tr_limit);
		vmcs_write32(GUEST_GDTR_LIMIT, vmcs12->guest_gdtr_limit);
		vmcs_write32(GUEST_IDTR_LIMIT, vmcs12->guest_idtr_limit);
		vmcs_write32(GUEST_CS_AR_BYTES, vmcs12->guest_cs_ar_bytes);
		vmcs_write32(GUEST_SS_AR_BYTES, vmcs12->guest_ss_ar_bytes);
		vmcs_write32(GUEST_ES_AR_BYTES, vmcs12->guest_es_ar_bytes);
		vmcs_write32(GUEST_DS_AR_BYTES, vmcs12->guest_ds_ar_bytes);
		vmcs_write32(GUEST_FS_AR_BYTES, vmcs12->guest_fs_ar_bytes);
		vmcs_write32(GUEST_GS_AR_BYTES, vmcs12->guest_gs_ar_bytes);
		vmcs_write32(GUEST_LDTR_AR_BYTES, vmcs12->guest_ldtr_ar_bytes);
		vmcs_write32(GUEST_TR_AR_BYTES, vmcs12->guest_tr_ar_bytes);
		vmcs_writel(GUEST_ES_BASE, vmcs12->guest_es_base);
		vmcs_writel(GUEST_CS_BASE, vmcs12->guest_cs_base);
		vmcs_writel(GUEST_SS_BASE, vmcs12->guest_ss_base);
		vmcs_writel(GUEST_DS_BASE, vmcs12->guest_ds_base);
		vmcs_writel(GUEST_FS_BASE, vmcs12->guest_fs_base);
		vmcs_writel(GUEST_GS_BASE, vmcs12->guest_gs_base);
		vmcs_writel(GUEST_LDTR_BASE, vmcs12->guest_ldtr_base);
		vmcs_writel(GUEST_TR_BASE, vmcs12->guest_tr_base);
		vmcs_writel(GUEST_GDTR_BASE, vmcs12->guest_gdtr_base);
		vmcs_writel(GUEST_IDTR_BASE, vmcs12->guest_idtr_base);

		vmx->segment_cache.bitmask = 0;
	}

	if (!hv_evmcs || !(hv_evmcs->hv_clean_fields &
			   HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1)) {
		vmcs_write32(GUEST_SYSENTER_CS, vmcs12->guest_sysenter_cs);
		vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS,
			    vmcs12->guest_pending_dbg_exceptions);
		vmcs_writel(GUEST_SYSENTER_ESP, vmcs12->guest_sysenter_esp);
		vmcs_writel(GUEST_SYSENTER_EIP, vmcs12->guest_sysenter_eip);

		/*
		if (enable_ept) {
			vmcs_write64(GUEST_PDPTR0, vmcs12->guest_pdptr0);
			vmcs_write64(GUEST_PDPTR1, vmcs12->guest_pdptr1);
			vmcs_write64(GUEST_PDPTR2, vmcs12->guest_pdptr2);
			vmcs_write64(GUEST_PDPTR3, vmcs12->guest_pdptr3);
		}

		if (kvm_mpx_supported() && vmx->nested.nested_run_pending &&
		    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_BNDCFGS))
			vmcs_write64(GUEST_BNDCFGS, vmcs12->guest_bndcfgs);
	}

	if (nested_cpu_has_xsaves(vmcs12))
		vmcs_write64(XSS_EXIT_BITMAP, vmcs12->xss_exit_bitmap);

	/*
	if (vmx_need_pf_intercept(&vmx->vcpu)) {
		/*
		vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
		vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	} else {
		vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, vmcs12->page_fault_error_code_mask);
		vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, vmcs12->page_fault_error_code_match);
	}

	if (cpu_has_vmx_apicv()) {
		vmcs_write64(EOI_EXIT_BITMAP0, vmcs12->eoi_exit_bitmap0);
		vmcs_write64(EOI_EXIT_BITMAP1, vmcs12->eoi_exit_bitmap1);
		vmcs_write64(EOI_EXIT_BITMAP2, vmcs12->eoi_exit_bitmap2);
		vmcs_write64(EOI_EXIT_BITMAP3, vmcs12->eoi_exit_bitmap3);
	}

	/*
	prepare_vmx_msr_autostore_list(&vmx->vcpu, MSR_IA32_TSC);

	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, vmx->msr_autostore.guest.nr);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vmx->msr_autoload.host.nr);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vmx->msr_autoload.guest.nr);

	set_cr4_guest_host_mask(vmx);
}

static int prepare_vmcs02(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12,
			  bool from_vmentry,
			  enum vm_entry_failure_code *entry_failure_code)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	bool load_guest_pdptrs_vmcs12 = false;

	if (vmx->nested.dirty_vmcs12 || evmptr_is_valid(vmx->nested.hv_evmcs_vmptr)) {
		prepare_vmcs02_rare(vmx, vmcs12);
		vmx->nested.dirty_vmcs12 = false;

		load_guest_pdptrs_vmcs12 = !evmptr_is_valid(vmx->nested.hv_evmcs_vmptr) ||
			!(vmx->nested.hv_evmcs->hv_clean_fields &
			  HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	}

	if (vmx->nested.nested_run_pending &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_DEBUG_CONTROLS)) {
		kvm_set_dr(vcpu, 7, vmcs12->guest_dr7);
		vmcs_write64(GUEST_IA32_DEBUGCTL, vmcs12->guest_ia32_debugctl);
	} else {
		kvm_set_dr(vcpu, 7, vcpu->arch.dr7);
		vmcs_write64(GUEST_IA32_DEBUGCTL, vmx->nested.pre_vmenter_debugctl);
	}
	if (kvm_mpx_supported() && (!vmx->nested.nested_run_pending ||
	    !(vmcs12->vm_entry_controls & VM_ENTRY_LOAD_BNDCFGS)))
		vmcs_write64(GUEST_BNDCFGS, vmx->nested.pre_vmenter_bndcfgs);
	vmx_set_rflags(vcpu, vmcs12->guest_rflags);

	/* EXCEPTION_BITMAP and CR0_GUEST_HOST_MASK should basically be the
	 * bitwise-or of what L1 wants to trap for L2, and what we want to
	 * trap. Note that CR0.TS also needs updating - we do this later.
	 */
	vmx_update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits &= ~vmcs12->cr0_guest_host_mask;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);

	if (vmx->nested.nested_run_pending &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_PAT)) {
		vmcs_write64(GUEST_IA32_PAT, vmcs12->guest_ia32_pat);
		vcpu->arch.pat = vmcs12->guest_ia32_pat;
	} else if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
		vmcs_write64(GUEST_IA32_PAT, vmx->vcpu.arch.pat);
	}

	vcpu->arch.tsc_offset = kvm_calc_nested_tsc_offset(
			vcpu->arch.l1_tsc_offset,
			vmx_get_l2_tsc_offset(vcpu),
			vmx_get_l2_tsc_multiplier(vcpu));

	vcpu->arch.tsc_scaling_ratio = kvm_calc_nested_tsc_multiplier(
			vcpu->arch.l1_tsc_scaling_ratio,
			vmx_get_l2_tsc_multiplier(vcpu));

	vmcs_write64(TSC_OFFSET, vcpu->arch.tsc_offset);
	if (kvm_caps.has_tsc_control)
		vmcs_write64(TSC_MULTIPLIER, vcpu->arch.tsc_scaling_ratio);

	nested_vmx_transition_tlb_flush(vcpu, vmcs12, true);

	if (nested_cpu_has_ept(vmcs12))
		nested_ept_init_mmu_context(vcpu);

	/*
	vmx_set_cr0(vcpu, vmcs12->guest_cr0);
	vmcs_writel(CR0_READ_SHADOW, nested_read_cr0(vmcs12));

	vmx_set_cr4(vcpu, vmcs12->guest_cr4);
	vmcs_writel(CR4_READ_SHADOW, nested_read_cr4(vmcs12));

	vcpu->arch.efer = nested_vmx_calc_efer(vmx, vmcs12);
	/* Note: may modify VM_ENTRY/EXIT_CONTROLS and GUEST/HOST_IA32_EFER */
	vmx_set_efer(vcpu, vcpu->arch.efer);

	/*
	if (CC(from_vmentry && !vmx_guest_state_valid(vcpu))) {
		*entry_failure_code = ENTRY_FAIL_DEFAULT;
		return -EINVAL;
	}

	/* Shadow page tables on either EPT or shadow page tables. */
	if (nested_vmx_load_cr3(vcpu, vmcs12->guest_cr3, nested_cpu_has_ept(vmcs12),
				from_vmentry, entry_failure_code))
		return -EINVAL;

	/*
	if (enable_ept)
		vmcs_writel(GUEST_CR3, vmcs12->guest_cr3);

	/* Late preparation of GUEST_PDPTRs now that EFER and CRs are set. */
	if (load_guest_pdptrs_vmcs12 && nested_cpu_has_ept(vmcs12) &&
	    is_pae_paging(vcpu)) {
		vmcs_write64(GUEST_PDPTR0, vmcs12->guest_pdptr0);
		vmcs_write64(GUEST_PDPTR1, vmcs12->guest_pdptr1);
		vmcs_write64(GUEST_PDPTR2, vmcs12->guest_pdptr2);
		vmcs_write64(GUEST_PDPTR3, vmcs12->guest_pdptr3);
	}

	if ((vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL) &&
	    intel_pmu_has_perf_global_ctrl(vcpu_to_pmu(vcpu)) &&
	    WARN_ON_ONCE(kvm_set_msr(vcpu, MSR_CORE_PERF_GLOBAL_CTRL,
				     vmcs12->guest_ia32_perf_global_ctrl))) {
		*entry_failure_code = ENTRY_FAIL_DEFAULT;
		return -EINVAL;
	}

	kvm_rsp_write(vcpu, vmcs12->guest_rsp);
	kvm_rip_write(vcpu, vmcs12->guest_rip);

	/*
	if (evmptr_is_valid(vmx->nested.hv_evmcs_vmptr))
		vmx->nested.hv_evmcs->hv_clean_fields |=
			HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;

	return 0;
}

static int nested_vmx_check_nmi_controls(struct vmcs12 *vmcs12)
{
	if (CC(!nested_cpu_has_nmi_exiting(vmcs12) &&
	       nested_cpu_has_virtual_nmis(vmcs12)))
		return -EINVAL;

	if (CC(!nested_cpu_has_virtual_nmis(vmcs12) &&
	       nested_cpu_has(vmcs12, CPU_BASED_NMI_WINDOW_EXITING)))
		return -EINVAL;

	return 0;
}

static bool nested_vmx_check_eptp(struct kvm_vcpu *vcpu, u64 new_eptp)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/* Check for memory type validity */
	switch (new_eptp & VMX_EPTP_MT_MASK) {
	case VMX_EPTP_MT_UC:
		if (CC(!(vmx->nested.msrs.ept_caps & VMX_EPTP_UC_BIT)))
			return false;
		break;
	case VMX_EPTP_MT_WB:
		if (CC(!(vmx->nested.msrs.ept_caps & VMX_EPTP_WB_BIT)))
			return false;
		break;
	default:
		return false;
	}

	/* Page-walk levels validity. */
	switch (new_eptp & VMX_EPTP_PWL_MASK) {
	case VMX_EPTP_PWL_5:
		if (CC(!(vmx->nested.msrs.ept_caps & VMX_EPT_PAGE_WALK_5_BIT)))
			return false;
		break;
	case VMX_EPTP_PWL_4:
		if (CC(!(vmx->nested.msrs.ept_caps & VMX_EPT_PAGE_WALK_4_BIT)))
			return false;
		break;
	default:
		return false;
	}

	/* Reserved bits should not be set */
	if (CC(kvm_vcpu_is_illegal_gpa(vcpu, new_eptp) || ((new_eptp >> 7) & 0x1f)))
		return false;

	/* AD, if set, should be supported */
	if (new_eptp & VMX_EPTP_AD_ENABLE_BIT) {
		if (CC(!(vmx->nested.msrs.ept_caps & VMX_EPT_AD_BIT)))
			return false;
	}

	return true;
}

static int nested_check_vm_execution_controls(struct kvm_vcpu *vcpu,
                                              struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (CC(!vmx_control_verify(vmcs12->pin_based_vm_exec_control,
				   vmx->nested.msrs.pinbased_ctls_low,
				   vmx->nested.msrs.pinbased_ctls_high)) ||
	    CC(!vmx_control_verify(vmcs12->cpu_based_vm_exec_control,
				   vmx->nested.msrs.procbased_ctls_low,
				   vmx->nested.msrs.procbased_ctls_high)))
		return -EINVAL;

	if (nested_cpu_has(vmcs12, CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) &&
	    CC(!vmx_control_verify(vmcs12->secondary_vm_exec_control,
				   vmx->nested.msrs.secondary_ctls_low,
				   vmx->nested.msrs.secondary_ctls_high)))
		return -EINVAL;

	if (CC(vmcs12->cr3_target_count > nested_cpu_vmx_misc_cr3_count(vcpu)) ||
	    nested_vmx_check_io_bitmap_controls(vcpu, vmcs12) ||
	    nested_vmx_check_msr_bitmap_controls(vcpu, vmcs12) ||
	    nested_vmx_check_tpr_shadow_controls(vcpu, vmcs12) ||
	    nested_vmx_check_apic_access_controls(vcpu, vmcs12) ||
	    nested_vmx_check_apicv_controls(vcpu, vmcs12) ||
	    nested_vmx_check_nmi_controls(vmcs12) ||
	    nested_vmx_check_pml_controls(vcpu, vmcs12) ||
	    nested_vmx_check_unrestricted_guest_controls(vcpu, vmcs12) ||
	    nested_vmx_check_mode_based_ept_exec_controls(vcpu, vmcs12) ||
	    nested_vmx_check_shadow_vmcs_controls(vcpu, vmcs12) ||
	    CC(nested_cpu_has_vpid(vmcs12) && !vmcs12->virtual_processor_id))
		return -EINVAL;

	if (!nested_cpu_has_preemption_timer(vmcs12) &&
	    nested_cpu_has_save_preemption_timer(vmcs12))
		return -EINVAL;

	if (nested_cpu_has_ept(vmcs12) &&
	    CC(!nested_vmx_check_eptp(vcpu, vmcs12->ept_pointer)))
		return -EINVAL;

	if (nested_cpu_has_vmfunc(vmcs12)) {
		if (CC(vmcs12->vm_function_control &
		       ~vmx->nested.msrs.vmfunc_controls))
			return -EINVAL;

		if (nested_cpu_has_eptp_switching(vmcs12)) {
			if (CC(!nested_cpu_has_ept(vmcs12)) ||
			    CC(!page_address_valid(vcpu, vmcs12->eptp_list_address)))
				return -EINVAL;
		}
	}

	return 0;
}

static int nested_check_vm_exit_controls(struct kvm_vcpu *vcpu,
                                         struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (CC(!vmx_control_verify(vmcs12->vm_exit_controls,
				    vmx->nested.msrs.exit_ctls_low,
				    vmx->nested.msrs.exit_ctls_high)) ||
	    CC(nested_vmx_check_exit_msr_switch_controls(vcpu, vmcs12)))
		return -EINVAL;

	return 0;
}

static int nested_check_vm_entry_controls(struct kvm_vcpu *vcpu,
					  struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (CC(!vmx_control_verify(vmcs12->vm_entry_controls,
				    vmx->nested.msrs.entry_ctls_low,
				    vmx->nested.msrs.entry_ctls_high)))
		return -EINVAL;

	/*
	if (vmcs12->vm_entry_intr_info_field & INTR_INFO_VALID_MASK) {
		u32 intr_info = vmcs12->vm_entry_intr_info_field;
		u8 vector = intr_info & INTR_INFO_VECTOR_MASK;
		u32 intr_type = intr_info & INTR_INFO_INTR_TYPE_MASK;
		bool has_error_code = intr_info & INTR_INFO_DELIVER_CODE_MASK;
		bool should_have_error_code;
		bool urg = nested_cpu_has2(vmcs12,
					   SECONDARY_EXEC_UNRESTRICTED_GUEST);
		bool prot_mode = !urg || vmcs12->guest_cr0 & X86_CR0_PE;

		/* VM-entry interruption-info field: interruption type */
		if (CC(intr_type == INTR_TYPE_RESERVED) ||
		    CC(intr_type == INTR_TYPE_OTHER_EVENT &&
		       !nested_cpu_supports_monitor_trap_flag(vcpu)))
			return -EINVAL;

		/* VM-entry interruption-info field: vector */
		if (CC(intr_type == INTR_TYPE_NMI_INTR && vector != NMI_VECTOR) ||
		    CC(intr_type == INTR_TYPE_HARD_EXCEPTION && vector > 31) ||
		    CC(intr_type == INTR_TYPE_OTHER_EVENT && vector != 0))
			return -EINVAL;

		/* VM-entry interruption-info field: deliver error code */
		should_have_error_code =
			intr_type == INTR_TYPE_HARD_EXCEPTION && prot_mode &&
			x86_exception_has_error_code(vector);
		if (CC(has_error_code != should_have_error_code))
			return -EINVAL;

		/* VM-entry exception error code */
		if (CC(has_error_code &&
		       vmcs12->vm_entry_exception_error_code & GENMASK(31, 16)))
			return -EINVAL;

		/* VM-entry interruption-info field: reserved bits */
		if (CC(intr_info & INTR_INFO_RESVD_BITS_MASK))
			return -EINVAL;

		/* VM-entry instruction length */
		switch (intr_type) {
		case INTR_TYPE_SOFT_EXCEPTION:
		case INTR_TYPE_SOFT_INTR:
		case INTR_TYPE_PRIV_SW_EXCEPTION:
			if (CC(vmcs12->vm_entry_instruction_len > 15) ||
			    CC(vmcs12->vm_entry_instruction_len == 0 &&
			    CC(!nested_cpu_has_zero_length_injection(vcpu))))
				return -EINVAL;
		}
	}

	if (nested_vmx_check_entry_msr_switch_controls(vcpu, vmcs12))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_controls(struct kvm_vcpu *vcpu,
				     struct vmcs12 *vmcs12)
{
	if (nested_check_vm_execution_controls(vcpu, vmcs12) ||
	    nested_check_vm_exit_controls(vcpu, vmcs12) ||
	    nested_check_vm_entry_controls(vcpu, vmcs12))
		return -EINVAL;

	if (to_vmx(vcpu)->nested.enlightened_vmcs_enabled)
		return nested_evmcs_check_controls(vmcs12);

	return 0;
}

static int nested_vmx_check_address_space_size(struct kvm_vcpu *vcpu,
				       struct vmcs12 *vmcs12)
{
#ifdef CONFIG_X86_64
	if (CC(!!(vmcs12->vm_exit_controls & VM_EXIT_HOST_ADDR_SPACE_SIZE) !=
		!!(vcpu->arch.efer & EFER_LMA)))
		return -EINVAL;
#endif
	return 0;
}

static int nested_vmx_check_host_state(struct kvm_vcpu *vcpu,
				       struct vmcs12 *vmcs12)
{
	bool ia32e;

	if (CC(!nested_host_cr0_valid(vcpu, vmcs12->host_cr0)) ||
	    CC(!nested_host_cr4_valid(vcpu, vmcs12->host_cr4)) ||
	    CC(kvm_vcpu_is_illegal_gpa(vcpu, vmcs12->host_cr3)))
		return -EINVAL;

	if (CC(is_noncanonical_address(vmcs12->host_ia32_sysenter_esp, vcpu)) ||
	    CC(is_noncanonical_address(vmcs12->host_ia32_sysenter_eip, vcpu)))
		return -EINVAL;

	if ((vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_PAT) &&
	    CC(!kvm_pat_valid(vmcs12->host_ia32_pat)))
		return -EINVAL;

	if ((vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL) &&
	    CC(!kvm_valid_perf_global_ctrl(vcpu_to_pmu(vcpu),
					   vmcs12->host_ia32_perf_global_ctrl)))
		return -EINVAL;

#ifdef CONFIG_X86_64
	ia32e = !!(vmcs12->vm_exit_controls & VM_EXIT_HOST_ADDR_SPACE_SIZE);
#else
	ia32e = false;
#endif

	if (ia32e) {
		if (CC(!(vmcs12->host_cr4 & X86_CR4_PAE)))
			return -EINVAL;
	} else {
		if (CC(vmcs12->vm_entry_controls & VM_ENTRY_IA32E_MODE) ||
		    CC(vmcs12->host_cr4 & X86_CR4_PCIDE) ||
		    CC((vmcs12->host_rip) >> 32))
			return -EINVAL;
	}

	if (CC(vmcs12->host_cs_selector & (SEGMENT_RPL_MASK | SEGMENT_TI_MASK)) ||
	    CC(vmcs12->host_ss_selector & (SEGMENT_RPL_MASK | SEGMENT_TI_MASK)) ||
	    CC(vmcs12->host_ds_selector & (SEGMENT_RPL_MASK | SEGMENT_TI_MASK)) ||
	    CC(vmcs12->host_es_selector & (SEGMENT_RPL_MASK | SEGMENT_TI_MASK)) ||
	    CC(vmcs12->host_fs_selector & (SEGMENT_RPL_MASK | SEGMENT_TI_MASK)) ||
	    CC(vmcs12->host_gs_selector & (SEGMENT_RPL_MASK | SEGMENT_TI_MASK)) ||
	    CC(vmcs12->host_tr_selector & (SEGMENT_RPL_MASK | SEGMENT_TI_MASK)) ||
	    CC(vmcs12->host_cs_selector == 0) ||
	    CC(vmcs12->host_tr_selector == 0) ||
	    CC(vmcs12->host_ss_selector == 0 && !ia32e))
		return -EINVAL;

	if (CC(is_noncanonical_address(vmcs12->host_fs_base, vcpu)) ||
	    CC(is_noncanonical_address(vmcs12->host_gs_base, vcpu)) ||
	    CC(is_noncanonical_address(vmcs12->host_gdtr_base, vcpu)) ||
	    CC(is_noncanonical_address(vmcs12->host_idtr_base, vcpu)) ||
	    CC(is_noncanonical_address(vmcs12->host_tr_base, vcpu)) ||
	    CC(is_noncanonical_address(vmcs12->host_rip, vcpu)))
		return -EINVAL;

	/*
	if (vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_EFER) {
		if (CC(!kvm_valid_efer(vcpu, vmcs12->host_ia32_efer)) ||
		    CC(ia32e != !!(vmcs12->host_ia32_efer & EFER_LMA)) ||
		    CC(ia32e != !!(vmcs12->host_ia32_efer & EFER_LME)))
			return -EINVAL;
	}

	return 0;
}

static int nested_vmx_check_vmcs_link_ptr(struct kvm_vcpu *vcpu,
					  struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct gfn_to_hva_cache *ghc = &vmx->nested.shadow_vmcs12_cache;
	struct vmcs_hdr hdr;

	if (vmcs12->vmcs_link_pointer == INVALID_GPA)
		return 0;

	if (CC(!page_address_valid(vcpu, vmcs12->vmcs_link_pointer)))
		return -EINVAL;

	if (ghc->gpa != vmcs12->vmcs_link_pointer &&
	    CC(kvm_gfn_to_hva_cache_init(vcpu->kvm, ghc,
					 vmcs12->vmcs_link_pointer, VMCS12_SIZE)))
                return -EINVAL;

	if (CC(kvm_read_guest_offset_cached(vcpu->kvm, ghc, &hdr,
					    offsetof(struct vmcs12, hdr),
					    sizeof(hdr))))
		return -EINVAL;

	if (CC(hdr.revision_id != VMCS12_REVISION) ||
	    CC(hdr.shadow_vmcs != nested_cpu_has_shadow_vmcs(vmcs12)))
		return -EINVAL;

	return 0;
}

static int nested_check_guest_non_reg_state(struct vmcs12 *vmcs12)
{
	if (CC(vmcs12->guest_activity_state != GUEST_ACTIVITY_ACTIVE &&
	       vmcs12->guest_activity_state != GUEST_ACTIVITY_HLT &&
	       vmcs12->guest_activity_state != GUEST_ACTIVITY_WAIT_SIPI))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_guest_state(struct kvm_vcpu *vcpu,
					struct vmcs12 *vmcs12,
					enum vm_entry_failure_code *entry_failure_code)
{
	bool ia32e;


	if (CC(!nested_guest_cr0_valid(vcpu, vmcs12->guest_cr0)) ||
	    CC(!nested_guest_cr4_valid(vcpu, vmcs12->guest_cr4)))
		return -EINVAL;

	if ((vmcs12->vm_entry_controls & VM_ENTRY_LOAD_DEBUG_CONTROLS) &&
	    CC(!kvm_dr7_valid(vmcs12->guest_dr7)))
		return -EINVAL;

	if ((vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_PAT) &&
	    CC(!kvm_pat_valid(vmcs12->guest_ia32_pat)))
		return -EINVAL;

	if (nested_vmx_check_vmcs_link_ptr(vcpu, vmcs12)) {
		*entry_failure_code = ENTRY_FAIL_VMCS_LINK_PTR;
		return -EINVAL;
	}

	if ((vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL) &&
	    CC(!kvm_valid_perf_global_ctrl(vcpu_to_pmu(vcpu),
					   vmcs12->guest_ia32_perf_global_ctrl)))
		return -EINVAL;

	/*
	if (to_vmx(vcpu)->nested.nested_run_pending &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_EFER)) {
		ia32e = (vmcs12->vm_entry_controls & VM_ENTRY_IA32E_MODE) != 0;
		if (CC(!kvm_valid_efer(vcpu, vmcs12->guest_ia32_efer)) ||
		    CC(ia32e != !!(vmcs12->guest_ia32_efer & EFER_LMA)) ||
		    CC(((vmcs12->guest_cr0 & X86_CR0_PG) &&
		     ia32e != !!(vmcs12->guest_ia32_efer & EFER_LME))))
			return -EINVAL;
	}

	if ((vmcs12->vm_entry_controls & VM_ENTRY_LOAD_BNDCFGS) &&
	    (CC(is_noncanonical_address(vmcs12->guest_bndcfgs & PAGE_MASK, vcpu)) ||
	     CC((vmcs12->guest_bndcfgs & MSR_IA32_BNDCFGS_RSVD))))
		return -EINVAL;

	if (nested_check_guest_non_reg_state(vmcs12))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_vmentry_hw(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long cr3, cr4;
	bool vm_fail;

	if (!nested_early_check)
		return 0;

	if (vmx->msr_autoload.host.nr)
		vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	if (vmx->msr_autoload.guest.nr)
		vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);

	preempt_disable();

	vmx_prepare_switch_to_guest(vcpu);

	/*
	vmcs_writel(GUEST_RFLAGS, 0);

	cr3 = __get_current_cr3_fast();
	if (unlikely(cr3 != vmx->loaded_vmcs->host_state.cr3)) {
		vmcs_writel(HOST_CR3, cr3);
		vmx->loaded_vmcs->host_state.cr3 = cr3;
	}

	cr4 = cr4_read_shadow();
	if (unlikely(cr4 != vmx->loaded_vmcs->host_state.cr4)) {
		vmcs_writel(HOST_CR4, cr4);
		vmx->loaded_vmcs->host_state.cr4 = cr4;
	}

	vm_fail = __vmx_vcpu_run(vmx, (unsigned long *)&vcpu->arch.regs,
				 __vmx_vcpu_run_flags(vmx));

	if (vmx->msr_autoload.host.nr)
		vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vmx->msr_autoload.host.nr);
	if (vmx->msr_autoload.guest.nr)
		vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vmx->msr_autoload.guest.nr);

	if (vm_fail) {
		u32 error = vmcs_read32(VM_INSTRUCTION_ERROR);

		preempt_enable();

		trace_kvm_nested_vmenter_failed(
			"early hardware check VM-instruction error: ", error);
		WARN_ON_ONCE(error != VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		return 1;
	}

	/*
	if (hw_breakpoint_active())
		set_debugreg(__this_cpu_read(cpu_dr7), 7);
	local_irq_enable();
	preempt_enable();

	/*
	WARN_ON(!(vmcs_read32(VM_EXIT_REASON) &
		VMX_EXIT_REASONS_FAILED_VMENTRY));

	return 0;
}

static bool nested_get_evmcs_page(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
	if (vmx->nested.enlightened_vmcs_enabled &&
	    vmx->nested.hv_evmcs_vmptr == EVMPTR_MAP_PENDING) {
		enum nested_evmptrld_status evmptrld_status =
			nested_vmx_handle_enlightened_vmptrld(vcpu, false);

		if (evmptrld_status == EVMPTRLD_VMFAIL ||
		    evmptrld_status == EVMPTRLD_ERROR)
			return false;

		/*
		vmx->nested.need_vmcs12_to_shadow_sync = true;
	}

	return true;
}

static bool nested_get_vmcs12_pages(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_host_map *map;

	if (!vcpu->arch.pdptrs_from_userspace &&
	    !nested_cpu_has_ept(vmcs12) && is_pae_paging(vcpu)) {
		/*
		if (CC(!load_pdptrs(vcpu, vcpu->arch.cr3)))
			return false;
	}


	if (nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)) {
		map = &vmx->nested.apic_access_page_map;

		if (!kvm_vcpu_map(vcpu, gpa_to_gfn(vmcs12->apic_access_addr), map)) {
			vmcs_write64(APIC_ACCESS_ADDR, pfn_to_hpa(map->pfn));
		} else {
			pr_debug_ratelimited("%s: no backing for APIC-access address in vmcs12\n",
					     __func__);
			vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			vcpu->run->internal.suberror =
				KVM_INTERNAL_ERROR_EMULATION;
			vcpu->run->internal.ndata = 0;
			return false;
		}
	}

	if (nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW)) {
		map = &vmx->nested.virtual_apic_map;

		if (!kvm_vcpu_map(vcpu, gpa_to_gfn(vmcs12->virtual_apic_page_addr), map)) {
			vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, pfn_to_hpa(map->pfn));
		} else if (nested_cpu_has(vmcs12, CPU_BASED_CR8_LOAD_EXITING) &&
		           nested_cpu_has(vmcs12, CPU_BASED_CR8_STORE_EXITING) &&
			   !nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)) {
			/*
			exec_controls_clearbit(vmx, CPU_BASED_TPR_SHADOW);
		} else {
			/*
			vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, INVALID_GPA);
		}
	}

	if (nested_cpu_has_posted_intr(vmcs12)) {
		map = &vmx->nested.pi_desc_map;

		if (!kvm_vcpu_map(vcpu, gpa_to_gfn(vmcs12->posted_intr_desc_addr), map)) {
			vmx->nested.pi_desc =
				(struct pi_desc *)(((void *)map->hva) +
				offset_in_page(vmcs12->posted_intr_desc_addr));
			vmcs_write64(POSTED_INTR_DESC_ADDR,
				     pfn_to_hpa(map->pfn) + offset_in_page(vmcs12->posted_intr_desc_addr));
		} else {
			/*
			vmx->nested.pi_desc = NULL;
			pin_controls_clearbit(vmx, PIN_BASED_POSTED_INTR);
		}
	}
	if (nested_vmx_prepare_msr_bitmap(vcpu, vmcs12))
		exec_controls_setbit(vmx, CPU_BASED_USE_MSR_BITMAPS);
	else
		exec_controls_clearbit(vmx, CPU_BASED_USE_MSR_BITMAPS);

	return true;
}

static bool vmx_get_nested_state_pages(struct kvm_vcpu *vcpu)
{
	if (!nested_get_evmcs_page(vcpu)) {
		pr_debug_ratelimited("%s: enlightened vmptrld failed\n",
				     __func__);
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror =
			KVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 0;

		return false;
	}

	if (is_guest_mode(vcpu) && !nested_get_vmcs12_pages(vcpu))
		return false;

	return true;
}

static int nested_vmx_write_pml_buffer(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	struct vmcs12 *vmcs12;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	gpa_t dst;

	if (WARN_ON_ONCE(!is_guest_mode(vcpu)))
		return 0;

	if (WARN_ON_ONCE(vmx->nested.pml_full))
		return 1;

	/*
	vmcs12 = get_vmcs12(vcpu);
	if (!nested_cpu_has_pml(vmcs12))
		return 0;

	if (vmcs12->guest_pml_index >= PML_ENTITY_NUM) {
		vmx->nested.pml_full = true;
		return 1;
	}

	gpa &= ~0xFFFull;
	dst = vmcs12->pml_address + sizeof(u64) * vmcs12->guest_pml_index;

	if (kvm_write_guest_page(vcpu->kvm, gpa_to_gfn(dst), &gpa,
				 offset_in_page(dst), sizeof(gpa)))
		return 0;

	vmcs12->guest_pml_index--;

	return 0;
}

static int nested_vmx_check_permission(struct kvm_vcpu *vcpu)
{
	if (!to_vmx(vcpu)->nested.vmxon) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 0;
	}

	if (vmx_get_cpl(vcpu)) {
		kvm_inject_gp(vcpu, 0);
		return 0;
	}

	return 1;
}

static u8 vmx_has_apicv_interrupt(struct kvm_vcpu *vcpu)
{
	u8 rvi = vmx_get_rvi();
	u8 vppr = kvm_lapic_get_reg(vcpu->arch.apic, APIC_PROCPRI);

	return ((rvi & 0xf0) > (vppr & 0xf0));
}

static void load_vmcs12_host_state(struct kvm_vcpu *vcpu,
				   struct vmcs12 *vmcs12);

enum nvmx_vmentry_status nested_vmx_enter_non_root_mode(struct kvm_vcpu *vcpu,
							bool from_vmentry)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	enum vm_entry_failure_code entry_failure_code;
	bool evaluate_pending_interrupts;
	union vmx_exit_reason exit_reason = {
		.basic = EXIT_REASON_INVALID_STATE,
		.failed_vmentry = 1,
	};
	u32 failed_index;

	kvm_service_local_tlb_flush_requests(vcpu);

	evaluate_pending_interrupts = exec_controls_get(vmx) &
		(CPU_BASED_INTR_WINDOW_EXITING | CPU_BASED_NMI_WINDOW_EXITING);
	if (likely(!evaluate_pending_interrupts) && kvm_vcpu_apicv_active(vcpu))
		evaluate_pending_interrupts |= vmx_has_apicv_interrupt(vcpu);

	if (!vmx->nested.nested_run_pending ||
	    !(vmcs12->vm_entry_controls & VM_ENTRY_LOAD_DEBUG_CONTROLS))
		vmx->nested.pre_vmenter_debugctl = vmcs_read64(GUEST_IA32_DEBUGCTL);
	if (kvm_mpx_supported() &&
	    (!vmx->nested.nested_run_pending ||
	     !(vmcs12->vm_entry_controls & VM_ENTRY_LOAD_BNDCFGS)))
		vmx->nested.pre_vmenter_bndcfgs = vmcs_read64(GUEST_BNDCFGS);

	/*
	if (!enable_ept && !nested_early_check)
		vmcs_writel(GUEST_CR3, vcpu->arch.cr3);

	vmx_switch_vmcs(vcpu, &vmx->nested.vmcs02);

	prepare_vmcs02_early(vmx, &vmx->vmcs01, vmcs12);

	if (from_vmentry) {
		if (unlikely(!nested_get_vmcs12_pages(vcpu))) {
			vmx_switch_vmcs(vcpu, &vmx->vmcs01);
			return NVMX_VMENTRY_KVM_INTERNAL_ERROR;
		}

		if (nested_vmx_check_vmentry_hw(vcpu)) {
			vmx_switch_vmcs(vcpu, &vmx->vmcs01);
			return NVMX_VMENTRY_VMFAIL;
		}

		if (nested_vmx_check_guest_state(vcpu, vmcs12,
						 &entry_failure_code)) {
			exit_reason.basic = EXIT_REASON_INVALID_STATE;
			vmcs12->exit_qualification = entry_failure_code;
			goto vmentry_fail_vmexit;
		}
	}

	enter_guest_mode(vcpu);

	if (prepare_vmcs02(vcpu, vmcs12, from_vmentry, &entry_failure_code)) {
		exit_reason.basic = EXIT_REASON_INVALID_STATE;
		vmcs12->exit_qualification = entry_failure_code;
		goto vmentry_fail_vmexit_guest_mode;
	}

	if (from_vmentry) {
		failed_index = nested_vmx_load_msr(vcpu,
						   vmcs12->vm_entry_msr_load_addr,
						   vmcs12->vm_entry_msr_load_count);
		if (failed_index) {
			exit_reason.basic = EXIT_REASON_MSR_LOAD_FAIL;
			vmcs12->exit_qualification = failed_index;
			goto vmentry_fail_vmexit_guest_mode;
		}
	} else {
		/*
		kvm_make_request(KVM_REQ_GET_NESTED_STATE_PAGES, vcpu);
	}

	/*
	if (unlikely(evaluate_pending_interrupts))
		kvm_make_request(KVM_REQ_EVENT, vcpu);

	/*
	vmx->nested.preemption_timer_expired = false;
	if (nested_cpu_has_preemption_timer(vmcs12)) {
		u64 timer_value = vmx_calc_preemption_timer_value(vcpu);
		vmx_start_preemption_timer(vcpu, timer_value);
	}

	/*
	return NVMX_VMENTRY_SUCCESS;

	/*
vmentry_fail_vmexit_guest_mode:
	if (vmcs12->cpu_based_vm_exec_control & CPU_BASED_USE_TSC_OFFSETTING)
		vcpu->arch.tsc_offset -= vmcs12->tsc_offset;
	leave_guest_mode(vcpu);

vmentry_fail_vmexit:
	vmx_switch_vmcs(vcpu, &vmx->vmcs01);

	if (!from_vmentry)
		return NVMX_VMENTRY_VMEXIT;

	load_vmcs12_host_state(vcpu, vmcs12);
	vmcs12->vm_exit_reason = exit_reason.full;
	if (enable_shadow_vmcs || evmptr_is_valid(vmx->nested.hv_evmcs_vmptr))
		vmx->nested.need_vmcs12_to_shadow_sync = true;
	return NVMX_VMENTRY_VMEXIT;
}

static int nested_vmx_run(struct kvm_vcpu *vcpu, bool launch)
{
	struct vmcs12 *vmcs12;
	enum nvmx_vmentry_status status;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 interrupt_shadow = vmx_get_interrupt_shadow(vcpu);
	enum nested_evmptrld_status evmptrld_status;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	evmptrld_status = nested_vmx_handle_enlightened_vmptrld(vcpu, launch);
	if (evmptrld_status == EVMPTRLD_ERROR) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	kvm_pmu_trigger_event(vcpu, PERF_COUNT_HW_BRANCH_INSTRUCTIONS);

	if (CC(evmptrld_status == EVMPTRLD_VMFAIL))
		return nested_vmx_failInvalid(vcpu);

	if (CC(!evmptr_is_valid(vmx->nested.hv_evmcs_vmptr) &&
	       vmx->nested.current_vmptr == INVALID_GPA))
		return nested_vmx_failInvalid(vcpu);

	vmcs12 = get_vmcs12(vcpu);

	/*
	if (CC(vmcs12->hdr.shadow_vmcs))
		return nested_vmx_failInvalid(vcpu);

	if (evmptr_is_valid(vmx->nested.hv_evmcs_vmptr)) {
		copy_enlightened_to_vmcs12(vmx, vmx->nested.hv_evmcs->hv_clean_fields);
		/* Enlightened VMCS doesn't have launch state */
		vmcs12->launch_state = !launch;
	} else if (enable_shadow_vmcs) {
		copy_shadow_to_vmcs12(vmx);
	}

	/*
	if (CC(interrupt_shadow & KVM_X86_SHADOW_INT_MOV_SS))
		return nested_vmx_fail(vcpu, VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS);

	if (CC(vmcs12->launch_state == launch))
		return nested_vmx_fail(vcpu,
			launch ? VMXERR_VMLAUNCH_NONCLEAR_VMCS
			       : VMXERR_VMRESUME_NONLAUNCHED_VMCS);

	if (nested_vmx_check_controls(vcpu, vmcs12))
		return nested_vmx_fail(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);

	if (nested_vmx_check_address_space_size(vcpu, vmcs12))
		return nested_vmx_fail(vcpu, VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);

	if (nested_vmx_check_host_state(vcpu, vmcs12))
		return nested_vmx_fail(vcpu, VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);

	/*
	vmx->nested.nested_run_pending = 1;
	vmx->nested.has_preemption_timer_deadline = false;
	status = nested_vmx_enter_non_root_mode(vcpu, true);
	if (unlikely(status != NVMX_VMENTRY_SUCCESS))
		goto vmentry_failed;

	/* Emulate processing of posted interrupts on VM-Enter. */
	if (nested_cpu_has_posted_intr(vmcs12) &&
	    kvm_apic_has_interrupt(vcpu) == vmx->nested.posted_intr_nv) {
		vmx->nested.pi_pending = true;
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		kvm_apic_clear_irr(vcpu, vmx->nested.posted_intr_nv);
	}

	/* Hide L1D cache contents from the nested guest.  */
	vmx->vcpu.arch.l1tf_flush_l1d = true;

	/*
	nested_cache_shadow_vmcs12(vcpu, vmcs12);

	switch (vmcs12->guest_activity_state) {
	case GUEST_ACTIVITY_HLT:
		/*
		if (!(vmcs12->vm_entry_intr_info_field & INTR_INFO_VALID_MASK) &&
		    !nested_cpu_has(vmcs12, CPU_BASED_NMI_WINDOW_EXITING) &&
		    !(nested_cpu_has(vmcs12, CPU_BASED_INTR_WINDOW_EXITING) &&
		      (vmcs12->guest_rflags & X86_EFLAGS_IF))) {
			vmx->nested.nested_run_pending = 0;
			return kvm_emulate_halt_noskip(vcpu);
		}
		break;
	case GUEST_ACTIVITY_WAIT_SIPI:
		vmx->nested.nested_run_pending = 0;
		vcpu->arch.mp_state = KVM_MP_STATE_INIT_RECEIVED;
		break;
	default:
		break;
	}

	return 1;

vmentry_failed:
	vmx->nested.nested_run_pending = 0;
	if (status == NVMX_VMENTRY_KVM_INTERNAL_ERROR)
		return 0;
	if (status == NVMX_VMENTRY_VMEXIT)
		return 1;
	WARN_ON_ONCE(status != NVMX_VMENTRY_VMFAIL);
	return nested_vmx_fail(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
}

static inline unsigned long
vmcs12_guest_cr0(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12)
{
	return
	/*1*/	(vmcs_readl(GUEST_CR0) & vcpu->arch.cr0_guest_owned_bits) |
	/*2*/	(vmcs12->guest_cr0 & vmcs12->cr0_guest_host_mask) |
	/*3*/	(vmcs_readl(CR0_READ_SHADOW) & ~(vmcs12->cr0_guest_host_mask |
			vcpu->arch.cr0_guest_owned_bits));
}

static inline unsigned long
vmcs12_guest_cr4(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12)
{
	return
	/*1*/	(vmcs_readl(GUEST_CR4) & vcpu->arch.cr4_guest_owned_bits) |
	/*2*/	(vmcs12->guest_cr4 & vmcs12->cr4_guest_host_mask) |
	/*3*/	(vmcs_readl(CR4_READ_SHADOW) & ~(vmcs12->cr4_guest_host_mask |
			vcpu->arch.cr4_guest_owned_bits));
}

static void vmcs12_save_pending_event(struct kvm_vcpu *vcpu,
				      struct vmcs12 *vmcs12,
				      u32 vm_exit_reason, u32 exit_intr_info)
{
	u32 idt_vectoring;
	unsigned int nr;

	/*
	if ((u16)vm_exit_reason == EXIT_REASON_TRIPLE_FAULT ||
	    ((u16)vm_exit_reason == EXIT_REASON_EXCEPTION_NMI &&
	     is_double_fault(exit_intr_info))) {
		vmcs12->idt_vectoring_info_field = 0;
	} else if (vcpu->arch.exception.injected) {
		nr = vcpu->arch.exception.nr;
		idt_vectoring = nr | VECTORING_INFO_VALID_MASK;

		if (kvm_exception_is_soft(nr)) {
			vmcs12->vm_exit_instruction_len =
				vcpu->arch.event_exit_inst_len;
			idt_vectoring |= INTR_TYPE_SOFT_EXCEPTION;
		} else
			idt_vectoring |= INTR_TYPE_HARD_EXCEPTION;

		if (vcpu->arch.exception.has_error_code) {
			idt_vectoring |= VECTORING_INFO_DELIVER_CODE_MASK;
			vmcs12->idt_vectoring_error_code =
				vcpu->arch.exception.error_code;
		}

		vmcs12->idt_vectoring_info_field = idt_vectoring;
	} else if (vcpu->arch.nmi_injected) {
		vmcs12->idt_vectoring_info_field =
			INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR;
	} else if (vcpu->arch.interrupt.injected) {
		nr = vcpu->arch.interrupt.nr;
		idt_vectoring = nr | VECTORING_INFO_VALID_MASK;

		if (vcpu->arch.interrupt.soft) {
			idt_vectoring |= INTR_TYPE_SOFT_INTR;
			vmcs12->vm_entry_instruction_len =
				vcpu->arch.event_exit_inst_len;
		} else
			idt_vectoring |= INTR_TYPE_EXT_INTR;

		vmcs12->idt_vectoring_info_field = idt_vectoring;
	} else {
		vmcs12->idt_vectoring_info_field = 0;
	}
}


void nested_mark_vmcs12_pages_dirty(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	gfn_t gfn;

	/*

	if (nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW)) {
		gfn = vmcs12->virtual_apic_page_addr >> PAGE_SHIFT;
		kvm_vcpu_mark_page_dirty(vcpu, gfn);
	}

	if (nested_cpu_has_posted_intr(vmcs12)) {
		gfn = vmcs12->posted_intr_desc_addr >> PAGE_SHIFT;
		kvm_vcpu_mark_page_dirty(vcpu, gfn);
	}
}

static int vmx_complete_nested_posted_interrupt(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int max_irr;
	void *vapic_page;
	u16 status;

	if (!vmx->nested.pi_pending)
		return 0;

	if (!vmx->nested.pi_desc)
		goto mmio_needed;

	vmx->nested.pi_pending = false;

	if (!pi_test_and_clear_on(vmx->nested.pi_desc))
		return 0;

	max_irr = find_last_bit((unsigned long *)vmx->nested.pi_desc->pir, 256);
	if (max_irr != 256) {
		vapic_page = vmx->nested.virtual_apic_map.hva;
		if (!vapic_page)
			goto mmio_needed;

		__kvm_apic_update_irr(vmx->nested.pi_desc->pir,
			vapic_page, &max_irr);
		status = vmcs_read16(GUEST_INTR_STATUS);
		if ((u8)max_irr > ((u8)status & 0xff)) {
			status &= ~0xff;
			status |= (u8)max_irr;
			vmcs_write16(GUEST_INTR_STATUS, status);
		}
	}

	nested_mark_vmcs12_pages_dirty(vcpu);
	return 0;

mmio_needed:
	kvm_handle_memory_failure(vcpu, X86EMUL_IO_NEEDED, NULL);
	return -ENXIO;
}

static void nested_vmx_inject_exception_vmexit(struct kvm_vcpu *vcpu,
					       unsigned long exit_qual)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	unsigned int nr = vcpu->arch.exception.nr;
	u32 intr_info = nr | INTR_INFO_VALID_MASK;

	if (vcpu->arch.exception.has_error_code) {
		vmcs12->vm_exit_intr_error_code = vcpu->arch.exception.error_code;
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (kvm_exception_is_soft(nr))
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	else
		intr_info |= INTR_TYPE_HARD_EXCEPTION;

	if (!(vmcs12->idt_vectoring_info_field & VECTORING_INFO_VALID_MASK) &&
	    vmx_get_nmi_mask(vcpu))
		intr_info |= INTR_INFO_UNBLOCK_NMI;

	nested_vmx_vmexit(vcpu, EXIT_REASON_EXCEPTION_NMI, intr_info, exit_qual);
}

static inline bool vmx_pending_dbg_trap(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.exception.pending &&
			vcpu->arch.exception.nr == DB_VECTOR &&
			vcpu->arch.exception.payload;
}

static void nested_vmx_update_pending_dbg(struct kvm_vcpu *vcpu)
{
	if (vmx_pending_dbg_trap(vcpu))
		vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS,
			    vcpu->arch.exception.payload);
}

static bool nested_vmx_preemption_timer_pending(struct kvm_vcpu *vcpu)
{
	return nested_cpu_has_preemption_timer(get_vmcs12(vcpu)) &&
	       to_vmx(vcpu)->nested.preemption_timer_expired;
}

static int vmx_check_nested_events(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qual;
	bool block_nested_events =
	    vmx->nested.nested_run_pending || kvm_event_needs_reinjection(vcpu);
	bool mtf_pending = vmx->nested.mtf_pending;
	struct kvm_lapic *apic = vcpu->arch.apic;

	/*
	if (!block_nested_events)
		vmx->nested.mtf_pending = false;

	if (lapic_in_kernel(vcpu) &&
		test_bit(KVM_APIC_INIT, &apic->pending_events)) {
		if (block_nested_events)
			return -EBUSY;
		nested_vmx_update_pending_dbg(vcpu);
		clear_bit(KVM_APIC_INIT, &apic->pending_events);
		if (vcpu->arch.mp_state != KVM_MP_STATE_INIT_RECEIVED)
			nested_vmx_vmexit(vcpu, EXIT_REASON_INIT_SIGNAL, 0, 0);
		return 0;
	}

	if (lapic_in_kernel(vcpu) &&
	    test_bit(KVM_APIC_SIPI, &apic->pending_events)) {
		if (block_nested_events)
			return -EBUSY;

		clear_bit(KVM_APIC_SIPI, &apic->pending_events);
		if (vcpu->arch.mp_state == KVM_MP_STATE_INIT_RECEIVED)
			nested_vmx_vmexit(vcpu, EXIT_REASON_SIPI_SIGNAL, 0,
						apic->sipi_vector & 0xFFUL);
		return 0;
	}

	/*

	if (vcpu->arch.exception.pending && !vmx_pending_dbg_trap(vcpu)) {
		if (vmx->nested.nested_run_pending)
			return -EBUSY;
		if (!nested_vmx_check_exception(vcpu, &exit_qual))
			goto no_vmexit;
		nested_vmx_inject_exception_vmexit(vcpu, exit_qual);
		return 0;
	}

	if (mtf_pending) {
		if (block_nested_events)
			return -EBUSY;
		nested_vmx_update_pending_dbg(vcpu);
		nested_vmx_vmexit(vcpu, EXIT_REASON_MONITOR_TRAP_FLAG, 0, 0);
		return 0;
	}

	if (vcpu->arch.exception.pending) {
		if (vmx->nested.nested_run_pending)
			return -EBUSY;
		if (!nested_vmx_check_exception(vcpu, &exit_qual))
			goto no_vmexit;
		nested_vmx_inject_exception_vmexit(vcpu, exit_qual);
		return 0;
	}

	if (nested_vmx_preemption_timer_pending(vcpu)) {
		if (block_nested_events)
			return -EBUSY;
		nested_vmx_vmexit(vcpu, EXIT_REASON_PREEMPTION_TIMER, 0, 0);
		return 0;
	}

	if (vcpu->arch.smi_pending && !is_smm(vcpu)) {
		if (block_nested_events)
			return -EBUSY;
		goto no_vmexit;
	}

	if (vcpu->arch.nmi_pending && !vmx_nmi_blocked(vcpu)) {
		if (block_nested_events)
			return -EBUSY;
		if (!nested_exit_on_nmi(vcpu))
			goto no_vmexit;

		nested_vmx_vmexit(vcpu, EXIT_REASON_EXCEPTION_NMI,
				  NMI_VECTOR | INTR_TYPE_NMI_INTR |
				  INTR_INFO_VALID_MASK, 0);
		/*
		vcpu->arch.nmi_pending = 0;
		vmx_set_nmi_mask(vcpu, true);
		return 0;
	}

	if (kvm_cpu_has_interrupt(vcpu) && !vmx_interrupt_blocked(vcpu)) {
		if (block_nested_events)
			return -EBUSY;
		if (!nested_exit_on_intr(vcpu))
			goto no_vmexit;
		nested_vmx_vmexit(vcpu, EXIT_REASON_EXTERNAL_INTERRUPT, 0, 0);
		return 0;
	}

no_vmexit:
	return vmx_complete_nested_posted_interrupt(vcpu);
}

static u32 vmx_get_preemption_timer_value(struct kvm_vcpu *vcpu)
{
	ktime_t remaining =
		hrtimer_get_remaining(&to_vmx(vcpu)->nested.preemption_timer);
	u64 value;

	if (ktime_to_ns(remaining) <= 0)
		return 0;

	value = ktime_to_ns(remaining) * vcpu->arch.virtual_tsc_khz;
	do_div(value, 1000000);
	return value >> VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE;
}

static bool is_vmcs12_ext_field(unsigned long field)
{
	switch (field) {
	case GUEST_ES_SELECTOR:
	case GUEST_CS_SELECTOR:
	case GUEST_SS_SELECTOR:
	case GUEST_DS_SELECTOR:
	case GUEST_FS_SELECTOR:
	case GUEST_GS_SELECTOR:
	case GUEST_LDTR_SELECTOR:
	case GUEST_TR_SELECTOR:
	case GUEST_ES_LIMIT:
	case GUEST_CS_LIMIT:
	case GUEST_SS_LIMIT:
	case GUEST_DS_LIMIT:
	case GUEST_FS_LIMIT:
	case GUEST_GS_LIMIT:
	case GUEST_LDTR_LIMIT:
	case GUEST_TR_LIMIT:
	case GUEST_GDTR_LIMIT:
	case GUEST_IDTR_LIMIT:
	case GUEST_ES_AR_BYTES:
	case GUEST_DS_AR_BYTES:
	case GUEST_FS_AR_BYTES:
	case GUEST_GS_AR_BYTES:
	case GUEST_LDTR_AR_BYTES:
	case GUEST_TR_AR_BYTES:
	case GUEST_ES_BASE:
	case GUEST_CS_BASE:
	case GUEST_SS_BASE:
	case GUEST_DS_BASE:
	case GUEST_FS_BASE:
	case GUEST_GS_BASE:
	case GUEST_LDTR_BASE:
	case GUEST_TR_BASE:
	case GUEST_GDTR_BASE:
	case GUEST_IDTR_BASE:
	case GUEST_PENDING_DBG_EXCEPTIONS:
	case GUEST_BNDCFGS:
		return true;
	default:
		break;
	}

	return false;
}

static void sync_vmcs02_to_vmcs12_rare(struct kvm_vcpu *vcpu,
				       struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmcs12->guest_es_selector = vmcs_read16(GUEST_ES_SELECTOR);
	vmcs12->guest_cs_selector = vmcs_read16(GUEST_CS_SELECTOR);
	vmcs12->guest_ss_selector = vmcs_read16(GUEST_SS_SELECTOR);
	vmcs12->guest_ds_selector = vmcs_read16(GUEST_DS_SELECTOR);
	vmcs12->guest_fs_selector = vmcs_read16(GUEST_FS_SELECTOR);
	vmcs12->guest_gs_selector = vmcs_read16(GUEST_GS_SELECTOR);
	vmcs12->guest_ldtr_selector = vmcs_read16(GUEST_LDTR_SELECTOR);
	vmcs12->guest_tr_selector = vmcs_read16(GUEST_TR_SELECTOR);
	vmcs12->guest_es_limit = vmcs_read32(GUEST_ES_LIMIT);
	vmcs12->guest_cs_limit = vmcs_read32(GUEST_CS_LIMIT);
	vmcs12->guest_ss_limit = vmcs_read32(GUEST_SS_LIMIT);
	vmcs12->guest_ds_limit = vmcs_read32(GUEST_DS_LIMIT);
	vmcs12->guest_fs_limit = vmcs_read32(GUEST_FS_LIMIT);
	vmcs12->guest_gs_limit = vmcs_read32(GUEST_GS_LIMIT);
	vmcs12->guest_ldtr_limit = vmcs_read32(GUEST_LDTR_LIMIT);
	vmcs12->guest_tr_limit = vmcs_read32(GUEST_TR_LIMIT);
	vmcs12->guest_gdtr_limit = vmcs_read32(GUEST_GDTR_LIMIT);
	vmcs12->guest_idtr_limit = vmcs_read32(GUEST_IDTR_LIMIT);
	vmcs12->guest_es_ar_bytes = vmcs_read32(GUEST_ES_AR_BYTES);
	vmcs12->guest_ds_ar_bytes = vmcs_read32(GUEST_DS_AR_BYTES);
	vmcs12->guest_fs_ar_bytes = vmcs_read32(GUEST_FS_AR_BYTES);
	vmcs12->guest_gs_ar_bytes = vmcs_read32(GUEST_GS_AR_BYTES);
	vmcs12->guest_ldtr_ar_bytes = vmcs_read32(GUEST_LDTR_AR_BYTES);
	vmcs12->guest_tr_ar_bytes = vmcs_read32(GUEST_TR_AR_BYTES);
	vmcs12->guest_es_base = vmcs_readl(GUEST_ES_BASE);
	vmcs12->guest_cs_base = vmcs_readl(GUEST_CS_BASE);
	vmcs12->guest_ss_base = vmcs_readl(GUEST_SS_BASE);
	vmcs12->guest_ds_base = vmcs_readl(GUEST_DS_BASE);
	vmcs12->guest_fs_base = vmcs_readl(GUEST_FS_BASE);
	vmcs12->guest_gs_base = vmcs_readl(GUEST_GS_BASE);
	vmcs12->guest_ldtr_base = vmcs_readl(GUEST_LDTR_BASE);
	vmcs12->guest_tr_base = vmcs_readl(GUEST_TR_BASE);
	vmcs12->guest_gdtr_base = vmcs_readl(GUEST_GDTR_BASE);
	vmcs12->guest_idtr_base = vmcs_readl(GUEST_IDTR_BASE);
	vmcs12->guest_pending_dbg_exceptions =
		vmcs_readl(GUEST_PENDING_DBG_EXCEPTIONS);

	vmx->nested.need_sync_vmcs02_to_vmcs12_rare = false;
}

static void copy_vmcs02_to_vmcs12_rare(struct kvm_vcpu *vcpu,
				       struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int cpu;

	if (!vmx->nested.need_sync_vmcs02_to_vmcs12_rare)
		return;


	WARN_ON_ONCE(vmx->loaded_vmcs != &vmx->vmcs01);

	cpu = get_cpu();
	vmx->loaded_vmcs = &vmx->nested.vmcs02;
	vmx_vcpu_load_vmcs(vcpu, cpu, &vmx->vmcs01);

	sync_vmcs02_to_vmcs12_rare(vcpu, vmcs12);

	vmx->loaded_vmcs = &vmx->vmcs01;
	vmx_vcpu_load_vmcs(vcpu, cpu, &vmx->nested.vmcs02);
	put_cpu();
}

static void sync_vmcs02_to_vmcs12(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (evmptr_is_valid(vmx->nested.hv_evmcs_vmptr))
		sync_vmcs02_to_vmcs12_rare(vcpu, vmcs12);

	vmx->nested.need_sync_vmcs02_to_vmcs12_rare =
		!evmptr_is_valid(vmx->nested.hv_evmcs_vmptr);

	vmcs12->guest_cr0 = vmcs12_guest_cr0(vcpu, vmcs12);
	vmcs12->guest_cr4 = vmcs12_guest_cr4(vcpu, vmcs12);

	vmcs12->guest_rsp = kvm_rsp_read(vcpu);
	vmcs12->guest_rip = kvm_rip_read(vcpu);
	vmcs12->guest_rflags = vmcs_readl(GUEST_RFLAGS);

	vmcs12->guest_cs_ar_bytes = vmcs_read32(GUEST_CS_AR_BYTES);
	vmcs12->guest_ss_ar_bytes = vmcs_read32(GUEST_SS_AR_BYTES);

	vmcs12->guest_interruptibility_info =
		vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);

	if (vcpu->arch.mp_state == KVM_MP_STATE_HALTED)
		vmcs12->guest_activity_state = GUEST_ACTIVITY_HLT;
	else if (vcpu->arch.mp_state == KVM_MP_STATE_INIT_RECEIVED)
		vmcs12->guest_activity_state = GUEST_ACTIVITY_WAIT_SIPI;
	else
		vmcs12->guest_activity_state = GUEST_ACTIVITY_ACTIVE;

	if (nested_cpu_has_preemption_timer(vmcs12) &&
	    vmcs12->vm_exit_controls & VM_EXIT_SAVE_VMX_PREEMPTION_TIMER &&
	    !vmx->nested.nested_run_pending)
		vmcs12->vmx_preemption_timer_value =
			vmx_get_preemption_timer_value(vcpu);

	/*
	if (enable_ept) {
		vmcs12->guest_cr3 = vmcs_readl(GUEST_CR3);
		if (nested_cpu_has_ept(vmcs12) && is_pae_paging(vcpu)) {
			vmcs12->guest_pdptr0 = vmcs_read64(GUEST_PDPTR0);
			vmcs12->guest_pdptr1 = vmcs_read64(GUEST_PDPTR1);
			vmcs12->guest_pdptr2 = vmcs_read64(GUEST_PDPTR2);
			vmcs12->guest_pdptr3 = vmcs_read64(GUEST_PDPTR3);
		}
	}

	vmcs12->guest_linear_address = vmcs_readl(GUEST_LINEAR_ADDRESS);

	if (nested_cpu_has_vid(vmcs12))
		vmcs12->guest_intr_status = vmcs_read16(GUEST_INTR_STATUS);

	vmcs12->vm_entry_controls =
		(vmcs12->vm_entry_controls & ~VM_ENTRY_IA32E_MODE) |
		(vm_entry_controls_get(to_vmx(vcpu)) & VM_ENTRY_IA32E_MODE);

	if (vmcs12->vm_exit_controls & VM_EXIT_SAVE_DEBUG_CONTROLS)
		kvm_get_dr(vcpu, 7, (unsigned long *)&vmcs12->guest_dr7);

	if (vmcs12->vm_exit_controls & VM_EXIT_SAVE_IA32_EFER)
		vmcs12->guest_ia32_efer = vcpu->arch.efer;
}

static void prepare_vmcs12(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12,
			   u32 vm_exit_reason, u32 exit_intr_info,
			   unsigned long exit_qualification)
{
	/* update exit information fields: */
	vmcs12->vm_exit_reason = vm_exit_reason;
	if (to_vmx(vcpu)->exit_reason.enclave_mode)
		vmcs12->vm_exit_reason |= VMX_EXIT_REASONS_SGX_ENCLAVE_MODE;
	vmcs12->exit_qualification = exit_qualification;

	/*
	if (!(vmcs12->vm_exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY)) {
		vmcs12->launch_state = 1;

		/* vm_entry_intr_info_field is cleared on exit. Emulate this
		 * instead of reading the real value. */
		vmcs12->vm_entry_intr_info_field &= ~INTR_INFO_VALID_MASK;

		/*
		vmcs12_save_pending_event(vcpu, vmcs12,
					  vm_exit_reason, exit_intr_info);

		vmcs12->vm_exit_intr_info = exit_intr_info;
		vmcs12->vm_exit_instruction_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		vmcs12->vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);

		/*
		if (nested_vmx_store_msr(vcpu,
					 vmcs12->vm_exit_msr_store_addr,
					 vmcs12->vm_exit_msr_store_count))
			nested_vmx_abort(vcpu,
					 VMX_ABORT_SAVE_GUEST_MSR_FAIL);
	}

	/*
	vcpu->arch.nmi_injected = false;
	kvm_clear_exception_queue(vcpu);
	kvm_clear_interrupt_queue(vcpu);
}

static void load_vmcs12_host_state(struct kvm_vcpu *vcpu,
				   struct vmcs12 *vmcs12)
{
	enum vm_entry_failure_code ignored;
	struct kvm_segment seg;

	if (vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_EFER)
		vcpu->arch.efer = vmcs12->host_ia32_efer;
	else if (vmcs12->vm_exit_controls & VM_EXIT_HOST_ADDR_SPACE_SIZE)
		vcpu->arch.efer |= (EFER_LMA | EFER_LME);
	else
		vcpu->arch.efer &= ~(EFER_LMA | EFER_LME);
	vmx_set_efer(vcpu, vcpu->arch.efer);

	kvm_rsp_write(vcpu, vmcs12->host_rsp);
	kvm_rip_write(vcpu, vmcs12->host_rip);
	vmx_set_rflags(vcpu, X86_EFLAGS_FIXED);
	vmx_set_interrupt_shadow(vcpu, 0);

	/*
	vcpu->arch.cr0_guest_owned_bits = KVM_POSSIBLE_CR0_GUEST_BITS;
	vmx_set_cr0(vcpu, vmcs12->host_cr0);

	/* Same as above - no reason to call set_cr4_guest_host_mask().  */
	vcpu->arch.cr4_guest_owned_bits = ~vmcs_readl(CR4_GUEST_HOST_MASK);
	vmx_set_cr4(vcpu, vmcs12->host_cr4);

	nested_ept_uninit_mmu_context(vcpu);

	/*
	if (nested_vmx_load_cr3(vcpu, vmcs12->host_cr3, false, true, &ignored))
		nested_vmx_abort(vcpu, VMX_ABORT_LOAD_HOST_PDPTE_FAIL);

	nested_vmx_transition_tlb_flush(vcpu, vmcs12, false);

	vmcs_write32(GUEST_SYSENTER_CS, vmcs12->host_ia32_sysenter_cs);
	vmcs_writel(GUEST_SYSENTER_ESP, vmcs12->host_ia32_sysenter_esp);
	vmcs_writel(GUEST_SYSENTER_EIP, vmcs12->host_ia32_sysenter_eip);
	vmcs_writel(GUEST_IDTR_BASE, vmcs12->host_idtr_base);
	vmcs_writel(GUEST_GDTR_BASE, vmcs12->host_gdtr_base);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xFFFF);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xFFFF);

	/* If not VM_EXIT_CLEAR_BNDCFGS, the L2 value propagates to L1.  */
	if (vmcs12->vm_exit_controls & VM_EXIT_CLEAR_BNDCFGS)
		vmcs_write64(GUEST_BNDCFGS, 0);

	if (vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_PAT) {
		vmcs_write64(GUEST_IA32_PAT, vmcs12->host_ia32_pat);
		vcpu->arch.pat = vmcs12->host_ia32_pat;
	}
	if ((vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL) &&
	    intel_pmu_has_perf_global_ctrl(vcpu_to_pmu(vcpu)))
		WARN_ON_ONCE(kvm_set_msr(vcpu, MSR_CORE_PERF_GLOBAL_CTRL,
					 vmcs12->host_ia32_perf_global_ctrl));

	/* Set L1 segment info according to Intel SDM
	    27.5.2 Loading Host Segment and Descriptor-Table Registers */
	seg = (struct kvm_segment) {
		.base = 0,
		.limit = 0xFFFFFFFF,
		.selector = vmcs12->host_cs_selector,
		.type = 11,
		.present = 1,
		.s = 1,
		.g = 1
	};
	if (vmcs12->vm_exit_controls & VM_EXIT_HOST_ADDR_SPACE_SIZE)
		seg.l = 1;
	else
		seg.db = 1;
	__vmx_set_segment(vcpu, &seg, VCPU_SREG_CS);
	seg = (struct kvm_segment) {
		.base = 0,
		.limit = 0xFFFFFFFF,
		.type = 3,
		.present = 1,
		.s = 1,
		.db = 1,
		.g = 1
	};
	seg.selector = vmcs12->host_ds_selector;
	__vmx_set_segment(vcpu, &seg, VCPU_SREG_DS);
	seg.selector = vmcs12->host_es_selector;
	__vmx_set_segment(vcpu, &seg, VCPU_SREG_ES);
	seg.selector = vmcs12->host_ss_selector;
	__vmx_set_segment(vcpu, &seg, VCPU_SREG_SS);
	seg.selector = vmcs12->host_fs_selector;
	seg.base = vmcs12->host_fs_base;
	__vmx_set_segment(vcpu, &seg, VCPU_SREG_FS);
	seg.selector = vmcs12->host_gs_selector;
	seg.base = vmcs12->host_gs_base;
	__vmx_set_segment(vcpu, &seg, VCPU_SREG_GS);
	seg = (struct kvm_segment) {
		.base = vmcs12->host_tr_base,
		.limit = 0x67,
		.selector = vmcs12->host_tr_selector,
		.type = 11,
		.present = 1
	};
	__vmx_set_segment(vcpu, &seg, VCPU_SREG_TR);

	memset(&seg, 0, sizeof(seg));
	seg.unusable = 1;
	__vmx_set_segment(vcpu, &seg, VCPU_SREG_LDTR);

	kvm_set_dr(vcpu, 7, 0x400);
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	if (nested_vmx_load_msr(vcpu, vmcs12->vm_exit_msr_load_addr,
				vmcs12->vm_exit_msr_load_count))
		nested_vmx_abort(vcpu, VMX_ABORT_LOAD_HOST_MSR_FAIL);

	to_vmx(vcpu)->emulation_required = vmx_emulation_required(vcpu);
}

static inline u64 nested_vmx_get_vmcs01_guest_efer(struct vcpu_vmx *vmx)
{
	struct vmx_uret_msr *efer_msr;
	unsigned int i;

	if (vm_entry_controls_get(vmx) & VM_ENTRY_LOAD_IA32_EFER)
		return vmcs_read64(GUEST_IA32_EFER);

	if (cpu_has_load_ia32_efer())
		return host_efer;

	for (i = 0; i < vmx->msr_autoload.guest.nr; ++i) {
		if (vmx->msr_autoload.guest.val[i].index == MSR_EFER)
			return vmx->msr_autoload.guest.val[i].value;
	}

	efer_msr = vmx_find_uret_msr(vmx, MSR_EFER);
	if (efer_msr)
		return efer_msr->data;

	return host_efer;
}

static void nested_vmx_restore_host_state(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmx_msr_entry g, h;
	gpa_t gpa;
	u32 i, j;

	vcpu->arch.pat = vmcs_read64(GUEST_IA32_PAT);

	if (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_DEBUG_CONTROLS) {
		/*
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
			kvm_set_dr(vcpu, 7, DR7_FIXED_1);
		else
			WARN_ON(kvm_set_dr(vcpu, 7, vmcs_readl(GUEST_DR7)));
	}

	/*
	vmx_set_efer(vcpu, nested_vmx_get_vmcs01_guest_efer(vmx));

	vcpu->arch.cr0_guest_owned_bits = KVM_POSSIBLE_CR0_GUEST_BITS;
	vmx_set_cr0(vcpu, vmcs_readl(CR0_READ_SHADOW));

	vcpu->arch.cr4_guest_owned_bits = ~vmcs_readl(CR4_GUEST_HOST_MASK);
	vmx_set_cr4(vcpu, vmcs_readl(CR4_READ_SHADOW));

	nested_ept_uninit_mmu_context(vcpu);
	vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);
	kvm_register_mark_available(vcpu, VCPU_EXREG_CR3);

	/*
	if (enable_ept && is_pae_paging(vcpu))
		ept_save_pdptrs(vcpu);

	kvm_mmu_reset_context(vcpu);

	/*
	for (i = 0; i < vmcs12->vm_entry_msr_load_count; i++) {
		gpa = vmcs12->vm_entry_msr_load_addr + (i * sizeof(g));
		if (kvm_vcpu_read_guest(vcpu, gpa, &g, sizeof(g))) {
			pr_debug_ratelimited(
				"%s read MSR index failed (%u, 0x%08llx)\n",
				__func__, i, gpa);
			goto vmabort;
		}

		for (j = 0; j < vmcs12->vm_exit_msr_load_count; j++) {
			gpa = vmcs12->vm_exit_msr_load_addr + (j * sizeof(h));
			if (kvm_vcpu_read_guest(vcpu, gpa, &h, sizeof(h))) {
				pr_debug_ratelimited(
					"%s read MSR failed (%u, 0x%08llx)\n",
					__func__, j, gpa);
				goto vmabort;
			}
			if (h.index != g.index)
				continue;
			if (h.value == g.value)
				break;

			if (nested_vmx_load_msr_check(vcpu, &h)) {
				pr_debug_ratelimited(
					"%s check failed (%u, 0x%x, 0x%x)\n",
					__func__, j, h.index, h.reserved);
				goto vmabort;
			}

			if (kvm_set_msr(vcpu, h.index, h.value)) {
				pr_debug_ratelimited(
					"%s WRMSR failed (%u, 0x%x, 0x%llx)\n",
					__func__, j, h.index, h.value);
				goto vmabort;
			}
		}
	}

	return;

vmabort:
	nested_vmx_abort(vcpu, VMX_ABORT_LOAD_HOST_MSR_FAIL);
}

void nested_vmx_vmexit(struct kvm_vcpu *vcpu, u32 vm_exit_reason,
		       u32 exit_intr_info, unsigned long exit_qualification)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	/* trying to cancel vmlaunch/vmresume is a bug */
	WARN_ON_ONCE(vmx->nested.nested_run_pending);

	if (kvm_check_request(KVM_REQ_GET_NESTED_STATE_PAGES, vcpu)) {
		/*
		(void)nested_get_evmcs_page(vcpu);
	}

	/* Service pending TLB flush requests for L2 before switching to L1. */
	kvm_service_local_tlb_flush_requests(vcpu);

	/*
	if (enable_ept && is_pae_paging(vcpu))
		vmx_ept_load_pdptrs(vcpu);

	leave_guest_mode(vcpu);

	if (nested_cpu_has_preemption_timer(vmcs12))
		hrtimer_cancel(&to_vmx(vcpu)->nested.preemption_timer);

	if (nested_cpu_has(vmcs12, CPU_BASED_USE_TSC_OFFSETTING)) {
		vcpu->arch.tsc_offset = vcpu->arch.l1_tsc_offset;
		if (nested_cpu_has2(vmcs12, SECONDARY_EXEC_TSC_SCALING))
			vcpu->arch.tsc_scaling_ratio = vcpu->arch.l1_tsc_scaling_ratio;
	}

	if (likely(!vmx->fail)) {
		sync_vmcs02_to_vmcs12(vcpu, vmcs12);

		if (vm_exit_reason != -1)
			prepare_vmcs12(vcpu, vmcs12, vm_exit_reason,
				       exit_intr_info, exit_qualification);

		/*
		nested_flush_cached_shadow_vmcs12(vcpu, vmcs12);
	} else {
		/*
		WARN_ON_ONCE(vmcs_read32(VM_INSTRUCTION_ERROR) !=
			     VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		WARN_ON_ONCE(nested_early_check);
	}

	vmx_switch_vmcs(vcpu, &vmx->vmcs01);

	/* Update any VMCS fields that might have changed while L2 ran */
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vmx->msr_autoload.host.nr);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vmx->msr_autoload.guest.nr);
	vmcs_write64(TSC_OFFSET, vcpu->arch.tsc_offset);
	if (kvm_caps.has_tsc_control)
		vmcs_write64(TSC_MULTIPLIER, vcpu->arch.tsc_scaling_ratio);

	if (vmx->nested.l1_tpr_threshold != -1)
		vmcs_write32(TPR_THRESHOLD, vmx->nested.l1_tpr_threshold);

	if (vmx->nested.change_vmcs01_virtual_apic_mode) {
		vmx->nested.change_vmcs01_virtual_apic_mode = false;
		vmx_set_virtual_apic_mode(vcpu);
	}

	if (vmx->nested.update_vmcs01_cpu_dirty_logging) {
		vmx->nested.update_vmcs01_cpu_dirty_logging = false;
		vmx_update_cpu_dirty_logging(vcpu);
	}

	/* Unpin physical memory we referred to in vmcs02 */
	kvm_vcpu_unmap(vcpu, &vmx->nested.apic_access_page_map, false);
	kvm_vcpu_unmap(vcpu, &vmx->nested.virtual_apic_map, true);
	kvm_vcpu_unmap(vcpu, &vmx->nested.pi_desc_map, true);
	vmx->nested.pi_desc = NULL;

	if (vmx->nested.reload_vmcs01_apic_access_page) {
		vmx->nested.reload_vmcs01_apic_access_page = false;
		kvm_make_request(KVM_REQ_APIC_PAGE_RELOAD, vcpu);
	}

	if (vmx->nested.update_vmcs01_apicv_status) {
		vmx->nested.update_vmcs01_apicv_status = false;
		kvm_make_request(KVM_REQ_APICV_UPDATE, vcpu);
	}

	if ((vm_exit_reason != -1) &&
	    (enable_shadow_vmcs || evmptr_is_valid(vmx->nested.hv_evmcs_vmptr)))
		vmx->nested.need_vmcs12_to_shadow_sync = true;

	/* in case we halted in L2 */
	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

	if (likely(!vmx->fail)) {
		if ((u16)vm_exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT &&
		    nested_exit_intr_ack_set(vcpu)) {
			int irq = kvm_cpu_get_interrupt(vcpu);
			WARN_ON(irq < 0);
			vmcs12->vm_exit_intr_info = irq |
				INTR_INFO_VALID_MASK | INTR_TYPE_EXT_INTR;
		}

		if (vm_exit_reason != -1)
			trace_kvm_nested_vmexit_inject(vmcs12->vm_exit_reason,
						       vmcs12->exit_qualification,
						       vmcs12->idt_vectoring_info_field,
						       vmcs12->vm_exit_intr_info,
						       vmcs12->vm_exit_intr_error_code,
						       KVM_ISA_VMX);

		load_vmcs12_host_state(vcpu, vmcs12);

		return;
	}

	/*
	(void)nested_vmx_fail(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);

	/*
	nested_vmx_restore_host_state(vcpu);

	vmx->fail = 0;
}

static void nested_vmx_triple_fault(struct kvm_vcpu *vcpu)
{
	nested_vmx_vmexit(vcpu, EXIT_REASON_TRIPLE_FAULT, 0, 0);
}

int get_vmx_mem_address(struct kvm_vcpu *vcpu, unsigned long exit_qualification,
			u32 vmx_instruction_info, bool wr, int len, gva_t *ret)
{
	gva_t off;
	bool exn;
	struct kvm_segment s;

	/*
	int  scaling = vmx_instruction_info & 3;
	int  addr_size = (vmx_instruction_info >> 7) & 7;
	bool is_reg = vmx_instruction_info & (1u << 10);
	int  seg_reg = (vmx_instruction_info >> 15) & 7;
	int  index_reg = (vmx_instruction_info >> 18) & 0xf;
	bool index_is_valid = !(vmx_instruction_info & (1u << 22));
	int  base_reg       = (vmx_instruction_info >> 23) & 0xf;
	bool base_is_valid  = !(vmx_instruction_info & (1u << 27));

	if (is_reg) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	/* Addr = segment_base + offset */
	/* offset = base + [index * scale] + displacement */
	off = exit_qualification; /* holds the displacement */
	if (addr_size == 1)
		off = (gva_t)sign_extend64(off, 31);
	else if (addr_size == 0)
		off = (gva_t)sign_extend64(off, 15);
	if (base_is_valid)
		off += kvm_register_read(vcpu, base_reg);
	if (index_is_valid)
		off += kvm_register_read(vcpu, index_reg) << scaling;
	vmx_get_segment(vcpu, &s, seg_reg);

	/*
	if (addr_size == 1) /* 32 bit */
		off &= 0xffffffff;
	else if (addr_size == 0) /* 16 bit */
		off &= 0xffff;

	/* Checks for #GP/#SS exceptions. */
	exn = false;
	if (is_long_mode(vcpu)) {
		/*
		if (seg_reg == VCPU_SREG_FS || seg_reg == VCPU_SREG_GS)
			*ret = s.base + off;
		else
			*ret = off;

		/* Long mode: #GP(0)/#SS(0) if the memory address is in a
		 * non-canonical form. This is the only check on the memory
		 * destination for long mode!
		 */
		exn = is_noncanonical_address(*ret, vcpu);
	} else {
		/*
		*ret = (s.base + off) & 0xffffffff;

		/* Protected mode: apply checks for segment validity in the
		 * following order:
		 * - segment type check (#GP(0) may be thrown)
		 * - usability check (#GP(0)/#SS(0))
		 * - limit check (#GP(0)/#SS(0))
		 */
		if (wr)
			/* #GP(0) if the destination operand is located in a
			 * read-only data segment or any code segment.
			 */
			exn = ((s.type & 0xa) == 0 || (s.type & 8));
		else
			/* #GP(0) if the source operand is located in an
			 * execute-only code segment
			 */
			exn = ((s.type & 0xa) == 8);
		if (exn) {
			kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
			return 1;
		}
		/* Protected mode: #GP(0)/#SS(0) if the segment is unusable.
		 */
		exn = (s.unusable != 0);

		/*
		if (!(s.base == 0 && s.limit == 0xffffffff &&
		     ((s.type & 8) || !(s.type & 4))))
			exn = exn || ((u64)off + len - 1 > s.limit);
	}
	if (exn) {
		kvm_queue_exception_e(vcpu,
				      seg_reg == VCPU_SREG_SS ?
						SS_VECTOR : GP_VECTOR,
				      0);
		return 1;
	}

	return 0;
}

static int nested_vmx_get_vmptr(struct kvm_vcpu *vcpu, gpa_t *vmpointer,
				int *ret)
{
	gva_t gva;
	struct x86_exception e;
	int r;

	if (get_vmx_mem_address(vcpu, vmx_get_exit_qual(vcpu),
				vmcs_read32(VMX_INSTRUCTION_INFO), false,
				sizeof(*vmpointer), &gva)) {
		*ret = 1;
		return -EINVAL;
	}

	r = kvm_read_guest_virt(vcpu, gva, vmpointer, sizeof(*vmpointer), &e);
	if (r != X86EMUL_CONTINUE) {
		*ret = kvm_handle_memory_failure(vcpu, r, &e);
		return -EINVAL;
	}

	return 0;
}

static struct vmcs *alloc_shadow_vmcs(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct loaded_vmcs *loaded_vmcs = vmx->loaded_vmcs;

	/*
	if (WARN_ON(loaded_vmcs != &vmx->vmcs01 || loaded_vmcs->shadow_vmcs))
		return loaded_vmcs->shadow_vmcs;

	loaded_vmcs->shadow_vmcs = alloc_vmcs(true);
	if (loaded_vmcs->shadow_vmcs)
		vmcs_clear(loaded_vmcs->shadow_vmcs);

	return loaded_vmcs->shadow_vmcs;
}

static int enter_vmx_operation(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int r;

	r = alloc_loaded_vmcs(&vmx->nested.vmcs02);
	if (r < 0)
		goto out_vmcs02;

	vmx->nested.cached_vmcs12 = kzalloc(VMCS12_SIZE, GFP_KERNEL_ACCOUNT);
	if (!vmx->nested.cached_vmcs12)
		goto out_cached_vmcs12;

	vmx->nested.shadow_vmcs12_cache.gpa = INVALID_GPA;
	vmx->nested.cached_shadow_vmcs12 = kzalloc(VMCS12_SIZE, GFP_KERNEL_ACCOUNT);
	if (!vmx->nested.cached_shadow_vmcs12)
		goto out_cached_shadow_vmcs12;

	if (enable_shadow_vmcs && !alloc_shadow_vmcs(vcpu))
		goto out_shadow_vmcs;

	hrtimer_init(&vmx->nested.preemption_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED);
	vmx->nested.preemption_timer.function = vmx_preemption_timer_fn;

	vmx->nested.vpid02 = allocate_vpid();

	vmx->nested.vmcs02_initialized = false;
	vmx->nested.vmxon = true;

	if (vmx_pt_mode_is_host_guest()) {
		vmx->pt_desc.guest.ctl = 0;
		pt_update_intercept_for_msr(vcpu);
	}

	return 0;

out_shadow_vmcs:
	kfree(vmx->nested.cached_shadow_vmcs12);

out_cached_shadow_vmcs12:
	kfree(vmx->nested.cached_vmcs12);

out_cached_vmcs12:
	free_loaded_vmcs(&vmx->nested.vmcs02);

out_vmcs02:
	return -ENOMEM;
}

static int handle_vmxon(struct kvm_vcpu *vcpu)
{
	int ret;
	gpa_t vmptr;
	uint32_t revision;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	const u64 VMXON_NEEDED_FEATURES = FEAT_CTL_LOCKED
		| FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX;

	/*
	if (!nested_host_cr0_valid(vcpu, kvm_read_cr0(vcpu)) ||
	    !nested_host_cr4_valid(vcpu, kvm_read_cr4(vcpu))) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	/*
	if (vmx_get_cpl(vcpu)) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	if (vmx->nested.vmxon)
		return nested_vmx_fail(vcpu, VMXERR_VMXON_IN_VMX_ROOT_OPERATION);

	if ((vmx->msr_ia32_feature_control & VMXON_NEEDED_FEATURES)
			!= VMXON_NEEDED_FEATURES) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	if (nested_vmx_get_vmptr(vcpu, &vmptr, &ret))
		return ret;

	/*
	if (!page_address_valid(vcpu, vmptr))
		return nested_vmx_failInvalid(vcpu);

	if (kvm_read_guest(vcpu->kvm, vmptr, &revision, sizeof(revision)) ||
	    revision != VMCS12_REVISION)
		return nested_vmx_failInvalid(vcpu);

	vmx->nested.vmxon_ptr = vmptr;
	ret = enter_vmx_operation(vcpu);
	if (ret)
		return ret;

	return nested_vmx_succeed(vcpu);
}

static inline void nested_release_vmcs12(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (vmx->nested.current_vmptr == INVALID_GPA)
		return;

	copy_vmcs02_to_vmcs12_rare(vcpu, get_vmcs12(vcpu));

	if (enable_shadow_vmcs) {
		/* copy to memory all shadowed fields in case
		   they were modified */
		copy_shadow_to_vmcs12(vmx);
		vmx_disable_shadow_vmcs(vmx);
	}
	vmx->nested.posted_intr_nv = -1;

	/* Flush VMCS12 to guest memory */
	kvm_vcpu_write_guest_page(vcpu,
				  vmx->nested.current_vmptr >> PAGE_SHIFT,
				  vmx->nested.cached_vmcs12, 0, VMCS12_SIZE);

	kvm_mmu_free_roots(vcpu->kvm, &vcpu->arch.guest_mmu, KVM_MMU_ROOTS_ALL);

	vmx->nested.current_vmptr = INVALID_GPA;
}

static int handle_vmxoff(struct kvm_vcpu *vcpu)
{
	if (!nested_vmx_check_permission(vcpu))
		return 1;

	free_nested(vcpu);

	/* Process a latched INIT during time CPU was in VMX operation */
	kvm_make_request(KVM_REQ_EVENT, vcpu);

	return nested_vmx_succeed(vcpu);
}

static int handle_vmclear(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 zero = 0;
	gpa_t vmptr;
	u64 evmcs_gpa;
	int r;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (nested_vmx_get_vmptr(vcpu, &vmptr, &r))
		return r;

	if (!page_address_valid(vcpu, vmptr))
		return nested_vmx_fail(vcpu, VMXERR_VMCLEAR_INVALID_ADDRESS);

	if (vmptr == vmx->nested.vmxon_ptr)
		return nested_vmx_fail(vcpu, VMXERR_VMCLEAR_VMXON_POINTER);

	/*
	if (likely(!vmx->nested.enlightened_vmcs_enabled ||
		   !nested_enlightened_vmentry(vcpu, &evmcs_gpa))) {
		if (vmptr == vmx->nested.current_vmptr)
			nested_release_vmcs12(vcpu);

		kvm_vcpu_write_guest(vcpu,
				     vmptr + offsetof(struct vmcs12,
						      launch_state),
				     &zero, sizeof(zero));
	} else if (vmx->nested.hv_evmcs && vmptr == vmx->nested.hv_evmcs_vmptr) {
		nested_release_evmcs(vcpu);
	}

	return nested_vmx_succeed(vcpu);
}

static int handle_vmlaunch(struct kvm_vcpu *vcpu)
{
	return nested_vmx_run(vcpu, true);
}

static int handle_vmresume(struct kvm_vcpu *vcpu)
{

	return nested_vmx_run(vcpu, false);
}

static int handle_vmread(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = is_guest_mode(vcpu) ? get_shadow_vmcs12(vcpu)
						    : get_vmcs12(vcpu);
	unsigned long exit_qualification = vmx_get_exit_qual(vcpu);
	u32 instr_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct x86_exception e;
	unsigned long field;
	u64 value;
	gva_t gva = 0;
	short offset;
	int len, r;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	/* Decode instruction info and find the field to read */
	field = kvm_register_read(vcpu, (((instr_info) >> 28) & 0xf));

	if (!evmptr_is_valid(vmx->nested.hv_evmcs_vmptr)) {
		/*
		if (vmx->nested.current_vmptr == INVALID_GPA ||
		    (is_guest_mode(vcpu) &&
		     get_vmcs12(vcpu)->vmcs_link_pointer == INVALID_GPA))
			return nested_vmx_failInvalid(vcpu);

		offset = get_vmcs12_field_offset(field);
		if (offset < 0)
			return nested_vmx_fail(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);

		if (!is_guest_mode(vcpu) && is_vmcs12_ext_field(field))
			copy_vmcs02_to_vmcs12_rare(vcpu, vmcs12);

		/* Read the field, zero-extended to a u64 value */
		value = vmcs12_read_any(vmcs12, field, offset);
	} else {
		/*
		if (WARN_ON_ONCE(is_guest_mode(vcpu)))
			return nested_vmx_failInvalid(vcpu);

		offset = evmcs_field_offset(field, NULL);
		if (offset < 0)
			return nested_vmx_fail(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);

		/* Read the field, zero-extended to a u64 value */
		value = evmcs_read_any(vmx->nested.hv_evmcs, field, offset);
	}

	/*
	if (instr_info & BIT(10)) {
		kvm_register_write(vcpu, (((instr_info) >> 3) & 0xf), value);
	} else {
		len = is_64_bit_mode(vcpu) ? 8 : 4;
		if (get_vmx_mem_address(vcpu, exit_qualification,
					instr_info, true, len, &gva))
			return 1;
		/* _system ok, nested_vmx_check_permission has verified cpl=0 */
		r = kvm_write_guest_virt_system(vcpu, gva, &value, len, &e);
		if (r != X86EMUL_CONTINUE)
			return kvm_handle_memory_failure(vcpu, r, &e);
	}

	return nested_vmx_succeed(vcpu);
}

static bool is_shadow_field_rw(unsigned long field)
{
	switch (field) {
#define SHADOW_FIELD_RW(x, y) case x:
#include "vmcs_shadow_fields.h"
		return true;
	default:
		break;
	}
	return false;
}

static bool is_shadow_field_ro(unsigned long field)
{
	switch (field) {
#define SHADOW_FIELD_RO(x, y) case x:
#include "vmcs_shadow_fields.h"
		return true;
	default:
		break;
	}
	return false;
}

static int handle_vmwrite(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = is_guest_mode(vcpu) ? get_shadow_vmcs12(vcpu)
						    : get_vmcs12(vcpu);
	unsigned long exit_qualification = vmx_get_exit_qual(vcpu);
	u32 instr_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct x86_exception e;
	unsigned long field;
	short offset;
	gva_t gva;
	int len, r;

	/*
	u64 value = 0;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	/*
	if (vmx->nested.current_vmptr == INVALID_GPA ||
	    (is_guest_mode(vcpu) &&
	     get_vmcs12(vcpu)->vmcs_link_pointer == INVALID_GPA))
		return nested_vmx_failInvalid(vcpu);

	if (instr_info & BIT(10))
		value = kvm_register_read(vcpu, (((instr_info) >> 3) & 0xf));
	else {
		len = is_64_bit_mode(vcpu) ? 8 : 4;
		if (get_vmx_mem_address(vcpu, exit_qualification,
					instr_info, false, len, &gva))
			return 1;
		r = kvm_read_guest_virt(vcpu, gva, &value, len, &e);
		if (r != X86EMUL_CONTINUE)
			return kvm_handle_memory_failure(vcpu, r, &e);
	}

	field = kvm_register_read(vcpu, (((instr_info) >> 28) & 0xf));

	offset = get_vmcs12_field_offset(field);
	if (offset < 0)
		return nested_vmx_fail(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);

	/*
	if (vmcs_field_readonly(field) &&
	    !nested_cpu_has_vmwrite_any_field(vcpu))
		return nested_vmx_fail(vcpu, VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT);

	/*
	if (!is_guest_mode(vcpu) && !is_shadow_field_rw(field))
		copy_vmcs02_to_vmcs12_rare(vcpu, vmcs12);

	/*
	if (field >= GUEST_ES_AR_BYTES && field <= GUEST_TR_AR_BYTES)
		value &= 0x1f0ff;

	vmcs12_write_any(vmcs12, field, offset, value);

	/*
	if (!is_guest_mode(vcpu) && !is_shadow_field_rw(field)) {
		/*
		if (enable_shadow_vmcs && is_shadow_field_ro(field)) {
			preempt_disable();
			vmcs_load(vmx->vmcs01.shadow_vmcs);

			__vmcs_writel(field, value);

			vmcs_clear(vmx->vmcs01.shadow_vmcs);
			vmcs_load(vmx->loaded_vmcs->vmcs);
			preempt_enable();
		}
		vmx->nested.dirty_vmcs12 = true;
	}

	return nested_vmx_succeed(vcpu);
}

static void set_current_vmptr(struct vcpu_vmx *vmx, gpa_t vmptr)
{
	vmx->nested.current_vmptr = vmptr;
	if (enable_shadow_vmcs) {
		secondary_exec_controls_setbit(vmx, SECONDARY_EXEC_SHADOW_VMCS);
		vmcs_write64(VMCS_LINK_POINTER,
			     __pa(vmx->vmcs01.shadow_vmcs));
		vmx->nested.need_vmcs12_to_shadow_sync = true;
	}
	vmx->nested.dirty_vmcs12 = true;
	vmx->nested.force_msr_bitmap_recalc = true;
}

static int handle_vmptrld(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	gpa_t vmptr;
	int r;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (nested_vmx_get_vmptr(vcpu, &vmptr, &r))
		return r;

	if (!page_address_valid(vcpu, vmptr))
		return nested_vmx_fail(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);

	if (vmptr == vmx->nested.vmxon_ptr)
		return nested_vmx_fail(vcpu, VMXERR_VMPTRLD_VMXON_POINTER);

	/* Forbid normal VMPTRLD if Enlightened version was used */
	if (evmptr_is_valid(vmx->nested.hv_evmcs_vmptr))
		return 1;

	if (vmx->nested.current_vmptr != vmptr) {
		struct gfn_to_hva_cache *ghc = &vmx->nested.vmcs12_cache;
		struct vmcs_hdr hdr;

		if (kvm_gfn_to_hva_cache_init(vcpu->kvm, ghc, vmptr, VMCS12_SIZE)) {
			/*
			return nested_vmx_fail(vcpu,
				VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID);
		}

		if (kvm_read_guest_offset_cached(vcpu->kvm, ghc, &hdr,
						 offsetof(struct vmcs12, hdr),
						 sizeof(hdr))) {
			return nested_vmx_fail(vcpu,
				VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID);
		}

		if (hdr.revision_id != VMCS12_REVISION ||
		    (hdr.shadow_vmcs &&
		     !nested_cpu_has_vmx_shadow_vmcs(vcpu))) {
			return nested_vmx_fail(vcpu,
				VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID);
		}

		nested_release_vmcs12(vcpu);

		/*
		if (kvm_read_guest_cached(vcpu->kvm, ghc, vmx->nested.cached_vmcs12,
					  VMCS12_SIZE)) {
			return nested_vmx_fail(vcpu,
				VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID);
		}

		set_current_vmptr(vmx, vmptr);
	}

	return nested_vmx_succeed(vcpu);
}

static int handle_vmptrst(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qual = vmx_get_exit_qual(vcpu);
	u32 instr_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	gpa_t current_vmptr = to_vmx(vcpu)->nested.current_vmptr;
	struct x86_exception e;
	gva_t gva;
	int r;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (unlikely(evmptr_is_valid(to_vmx(vcpu)->nested.hv_evmcs_vmptr)))
		return 1;

	if (get_vmx_mem_address(vcpu, exit_qual, instr_info,
				true, sizeof(gpa_t), &gva))
		return 1;
	/* *_system ok, nested_vmx_check_permission has verified cpl=0 */
	r = kvm_write_guest_virt_system(vcpu, gva, (void *)&current_vmptr,
					sizeof(gpa_t), &e);
	if (r != X86EMUL_CONTINUE)
		return kvm_handle_memory_failure(vcpu, r, &e);

	return nested_vmx_succeed(vcpu);
}

static int handle_invept(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 vmx_instruction_info, types;
	unsigned long type, roots_to_free;
	struct kvm_mmu *mmu;
	gva_t gva;
	struct x86_exception e;
	struct {
		u64 eptp, gpa;
	} operand;
	int i, r, gpr_index;

	if (!(vmx->nested.msrs.secondary_ctls_high &
	      SECONDARY_EXEC_ENABLE_EPT) ||
	    !(vmx->nested.msrs.ept_caps & VMX_EPT_INVEPT_BIT)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	gpr_index = vmx_get_instr_info_reg2(vmx_instruction_info);
	type = kvm_register_read(vcpu, gpr_index);

	types = (vmx->nested.msrs.ept_caps >> VMX_EPT_EXTENT_SHIFT) & 6;

	if (type >= 32 || !(types & (1 << type)))
		return nested_vmx_fail(vcpu, VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);

	/* According to the Intel VMX instruction reference, the memory
	 * operand is read even if it isn't needed (e.g., for type==global)
	 */
	if (get_vmx_mem_address(vcpu, vmx_get_exit_qual(vcpu),
			vmx_instruction_info, false, sizeof(operand), &gva))
		return 1;
	r = kvm_read_guest_virt(vcpu, gva, &operand, sizeof(operand), &e);
	if (r != X86EMUL_CONTINUE)
		return kvm_handle_memory_failure(vcpu, r, &e);

	/*
	mmu = &vcpu->arch.guest_mmu;

	switch (type) {
	case VMX_EPT_EXTENT_CONTEXT:
		if (!nested_vmx_check_eptp(vcpu, operand.eptp))
			return nested_vmx_fail(vcpu,
				VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);

		roots_to_free = 0;
		if (nested_ept_root_matches(mmu->root.hpa, mmu->root.pgd,
					    operand.eptp))
			roots_to_free |= KVM_MMU_ROOT_CURRENT;

		for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
			if (nested_ept_root_matches(mmu->prev_roots[i].hpa,
						    mmu->prev_roots[i].pgd,
						    operand.eptp))
				roots_to_free |= KVM_MMU_ROOT_PREVIOUS(i);
		}
		break;
	case VMX_EPT_EXTENT_GLOBAL:
		roots_to_free = KVM_MMU_ROOTS_ALL;
		break;
	default:
		BUG();
		break;
	}

	if (roots_to_free)
		kvm_mmu_free_roots(vcpu->kvm, mmu, roots_to_free);

	return nested_vmx_succeed(vcpu);
}

static int handle_invvpid(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 vmx_instruction_info;
	unsigned long type, types;
	gva_t gva;
	struct x86_exception e;
	struct {
		u64 vpid;
		u64 gla;
	} operand;
	u16 vpid02;
	int r, gpr_index;

	if (!(vmx->nested.msrs.secondary_ctls_high &
	      SECONDARY_EXEC_ENABLE_VPID) ||
			!(vmx->nested.msrs.vpid_caps & VMX_VPID_INVVPID_BIT)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	gpr_index = vmx_get_instr_info_reg2(vmx_instruction_info);
	type = kvm_register_read(vcpu, gpr_index);

	types = (vmx->nested.msrs.vpid_caps &
			VMX_VPID_EXTENT_SUPPORTED_MASK) >> 8;

	if (type >= 32 || !(types & (1 << type)))
		return nested_vmx_fail(vcpu,
			VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);

	/* according to the intel vmx instruction reference, the memory
	 * operand is read even if it isn't needed (e.g., for type==global)
	 */
	if (get_vmx_mem_address(vcpu, vmx_get_exit_qual(vcpu),
			vmx_instruction_info, false, sizeof(operand), &gva))
		return 1;
	r = kvm_read_guest_virt(vcpu, gva, &operand, sizeof(operand), &e);
	if (r != X86EMUL_CONTINUE)
		return kvm_handle_memory_failure(vcpu, r, &e);

	if (operand.vpid >> 16)
		return nested_vmx_fail(vcpu,
			VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);

	vpid02 = nested_get_vpid02(vcpu);
	switch (type) {
	case VMX_VPID_EXTENT_INDIVIDUAL_ADDR:
		if (!operand.vpid ||
		    is_noncanonical_address(operand.gla, vcpu))
			return nested_vmx_fail(vcpu,
				VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		vpid_sync_vcpu_addr(vpid02, operand.gla);
		break;
	case VMX_VPID_EXTENT_SINGLE_CONTEXT:
	case VMX_VPID_EXTENT_SINGLE_NON_GLOBAL:
		if (!operand.vpid)
			return nested_vmx_fail(vcpu,
				VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		vpid_sync_context(vpid02);
		break;
	case VMX_VPID_EXTENT_ALL_CONTEXT:
		vpid_sync_context(vpid02);
		break;
	default:
		WARN_ON_ONCE(1);
		return kvm_skip_emulated_instruction(vcpu);
	}

	/*
	if (!enable_ept)
		kvm_mmu_free_guest_mode_roots(vcpu->kvm, &vcpu->arch.root_mmu);

	return nested_vmx_succeed(vcpu);
}

static int nested_vmx_eptp_switching(struct kvm_vcpu *vcpu,
				     struct vmcs12 *vmcs12)
{
	u32 index = kvm_rcx_read(vcpu);
	u64 new_eptp;

	if (WARN_ON_ONCE(!nested_cpu_has_ept(vmcs12)))
		return 1;
	if (index >= VMFUNC_EPTP_ENTRIES)
		return 1;

	if (kvm_vcpu_read_guest_page(vcpu, vmcs12->eptp_list_address >> PAGE_SHIFT,
				     &new_eptp, index * 8, 8))
		return 1;

	/*
	if (vmcs12->ept_pointer != new_eptp) {
		if (!nested_vmx_check_eptp(vcpu, new_eptp))
			return 1;

		vmcs12->ept_pointer = new_eptp;
		nested_ept_new_eptp(vcpu);

		if (!nested_cpu_has_vpid(vmcs12))
			kvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);
	}

	return 0;
}

static int handle_vmfunc(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12;
	u32 function = kvm_rax_read(vcpu);

	/*
	if (!is_guest_mode(vcpu)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	vmcs12 = get_vmcs12(vcpu);

	/*
	if (WARN_ON_ONCE((function > 63) || !nested_cpu_has_vmfunc(vmcs12))) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	if (!(vmcs12->vm_function_control & BIT_ULL(function)))
		goto fail;

	switch (function) {
	case 0:
		if (nested_vmx_eptp_switching(vcpu, vmcs12))
			goto fail;
		break;
	default:
		goto fail;
	}
	return kvm_skip_emulated_instruction(vcpu);

fail:
	/*
	nested_vmx_vmexit(vcpu, vmx->exit_reason.full,
			  vmx_get_intr_info(vcpu),
			  vmx_get_exit_qual(vcpu));
	return 1;
}

bool nested_vmx_check_io_bitmaps(struct kvm_vcpu *vcpu, unsigned int port,
				 int size)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	gpa_t bitmap, last_bitmap;
	u8 b;

	last_bitmap = INVALID_GPA;
	b = -1;

	while (size > 0) {
		if (port < 0x8000)
			bitmap = vmcs12->io_bitmap_a;
		else if (port < 0x10000)
			bitmap = vmcs12->io_bitmap_b;
		else
			return true;
		bitmap += (port & 0x7fff) / 8;

		if (last_bitmap != bitmap)
			if (kvm_vcpu_read_guest(vcpu, bitmap, &b, 1))
				return true;
		if (b & (1 << (port & 7)))
			return true;

		port++;
		size--;
		last_bitmap = bitmap;
	}

	return false;
}

static bool nested_vmx_exit_handled_io(struct kvm_vcpu *vcpu,
				       struct vmcs12 *vmcs12)
{
	unsigned long exit_qualification;
	unsigned short port;
	int size;

	if (!nested_cpu_has(vmcs12, CPU_BASED_USE_IO_BITMAPS))
		return nested_cpu_has(vmcs12, CPU_BASED_UNCOND_IO_EXITING);

	exit_qualification = vmx_get_exit_qual(vcpu);

	port = exit_qualification >> 16;
	size = (exit_qualification & 7) + 1;

	return nested_vmx_check_io_bitmaps(vcpu, port, size);
}

static bool nested_vmx_exit_handled_msr(struct kvm_vcpu *vcpu,
					struct vmcs12 *vmcs12,
					union vmx_exit_reason exit_reason)
{
	u32 msr_index = kvm_rcx_read(vcpu);
	gpa_t bitmap;

	if (!nested_cpu_has(vmcs12, CPU_BASED_USE_MSR_BITMAPS))
		return true;

	/*
	bitmap = vmcs12->msr_bitmap;
	if (exit_reason.basic == EXIT_REASON_MSR_WRITE)
		bitmap += 2048;
	if (msr_index >= 0xc0000000) {
		msr_index -= 0xc0000000;
		bitmap += 1024;
	}

	/* Then read the msr_index'th bit from this bitmap: */
	if (msr_index < 1024*8) {
		unsigned char b;
		if (kvm_vcpu_read_guest(vcpu, bitmap + msr_index/8, &b, 1))
			return true;
		return 1 & (b >> (msr_index & 7));
	} else
		return true; /* let L1 handle the wrong parameter */
}

static bool nested_vmx_exit_handled_cr(struct kvm_vcpu *vcpu,
	struct vmcs12 *vmcs12)
{
	unsigned long exit_qualification = vmx_get_exit_qual(vcpu);
	int cr = exit_qualification & 15;
	int reg;
	unsigned long val;

	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		reg = (exit_qualification >> 8) & 15;
		val = kvm_register_read(vcpu, reg);
		switch (cr) {
		case 0:
			if (vmcs12->cr0_guest_host_mask &
			    (val ^ vmcs12->cr0_read_shadow))
				return true;
			break;
		case 3:
			if (nested_cpu_has(vmcs12, CPU_BASED_CR3_LOAD_EXITING))
				return true;
			break;
		case 4:
			if (vmcs12->cr4_guest_host_mask &
			    (vmcs12->cr4_read_shadow ^ val))
				return true;
			break;
		case 8:
			if (nested_cpu_has(vmcs12, CPU_BASED_CR8_LOAD_EXITING))
				return true;
			break;
		}
		break;
	case 2: /* clts */
		if ((vmcs12->cr0_guest_host_mask & X86_CR0_TS) &&
		    (vmcs12->cr0_read_shadow & X86_CR0_TS))
			return true;
		break;
	case 1: /* mov from cr */
		switch (cr) {
		case 3:
			if (vmcs12->cpu_based_vm_exec_control &
			    CPU_BASED_CR3_STORE_EXITING)
				return true;
			break;
		case 8:
			if (vmcs12->cpu_based_vm_exec_control &
			    CPU_BASED_CR8_STORE_EXITING)
				return true;
			break;
		}
		break;
	case 3: /* lmsw */
		/*
		val = (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f;
		if (vmcs12->cr0_guest_host_mask & 0xe &
		    (val ^ vmcs12->cr0_read_shadow))
			return true;
		if ((vmcs12->cr0_guest_host_mask & 0x1) &&
		    !(vmcs12->cr0_read_shadow & 0x1) &&
		    (val & 0x1))
			return true;
		break;
	}
	return false;
}

static bool nested_vmx_exit_handled_encls(struct kvm_vcpu *vcpu,
					  struct vmcs12 *vmcs12)
{
	u32 encls_leaf;

	if (!guest_cpuid_has(vcpu, X86_FEATURE_SGX) ||
	    !nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENCLS_EXITING))
		return false;

	encls_leaf = kvm_rax_read(vcpu);
	if (encls_leaf > 62)
		encls_leaf = 63;
	return vmcs12->encls_exiting_bitmap & BIT_ULL(encls_leaf);
}

static bool nested_vmx_exit_handled_vmcs_access(struct kvm_vcpu *vcpu,
	struct vmcs12 *vmcs12, gpa_t bitmap)
{
	u32 vmx_instruction_info;
	unsigned long field;
	u8 b;

	if (!nested_cpu_has_shadow_vmcs(vmcs12))
		return true;

	/* Decode instruction info and find the field to access */
	vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	field = kvm_register_read(vcpu, (((vmx_instruction_info) >> 28) & 0xf));

	/* Out-of-range fields always cause a VM exit from L2 to L1 */
	if (field >> 15)
		return true;

	if (kvm_vcpu_read_guest(vcpu, bitmap + field/8, &b, 1))
		return true;

	return 1 & (b >> (field & 7));
}

static bool nested_vmx_exit_handled_mtf(struct vmcs12 *vmcs12)
{
	u32 entry_intr_info = vmcs12->vm_entry_intr_info_field;

	if (nested_cpu_has_mtf(vmcs12))
		return true;

	/*
	return entry_intr_info == (INTR_INFO_VALID_MASK
				   | INTR_TYPE_OTHER_EVENT);
}

static bool nested_vmx_l0_wants_exit(struct kvm_vcpu *vcpu,
				     union vmx_exit_reason exit_reason)
{
	u32 intr_info;

	switch ((u16)exit_reason.basic) {
	case EXIT_REASON_EXCEPTION_NMI:
		intr_info = vmx_get_intr_info(vcpu);
		if (is_nmi(intr_info))
			return true;
		else if (is_page_fault(intr_info))
			return vcpu->arch.apf.host_apf_flags ||
			       vmx_need_pf_intercept(vcpu);
		else if (is_debug(intr_info) &&
			 vcpu->guest_debug &
			 (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))
			return true;
		else if (is_breakpoint(intr_info) &&
			 vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			return true;
		else if (is_alignment_check(intr_info) &&
			 !vmx_guest_inject_ac(vcpu))
			return true;
		return false;
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return true;
	case EXIT_REASON_MCE_DURING_VMENTRY:
		return true;
	case EXIT_REASON_EPT_VIOLATION:
		/*
		return true;
	case EXIT_REASON_EPT_MISCONFIG:
		/*
		return true;
	case EXIT_REASON_PREEMPTION_TIMER:
		return true;
	case EXIT_REASON_PML_FULL:
		/*
		return true;
	case EXIT_REASON_VMFUNC:
		/* VM functions are emulated through L2->L0 vmexits. */
		return true;
	case EXIT_REASON_BUS_LOCK:
		/*
		return true;
	default:
		break;
	}
	return false;
}

static bool nested_vmx_l1_wants_exit(struct kvm_vcpu *vcpu,
				     union vmx_exit_reason exit_reason)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	u32 intr_info;

	switch ((u16)exit_reason.basic) {
	case EXIT_REASON_EXCEPTION_NMI:
		intr_info = vmx_get_intr_info(vcpu);
		if (is_nmi(intr_info))
			return true;
		else if (is_page_fault(intr_info))
			return true;
		return vmcs12->exception_bitmap &
				(1u << (intr_info & INTR_INFO_VECTOR_MASK));
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return nested_exit_on_intr(vcpu);
	case EXIT_REASON_TRIPLE_FAULT:
		return true;
	case EXIT_REASON_INTERRUPT_WINDOW:
		return nested_cpu_has(vmcs12, CPU_BASED_INTR_WINDOW_EXITING);
	case EXIT_REASON_NMI_WINDOW:
		return nested_cpu_has(vmcs12, CPU_BASED_NMI_WINDOW_EXITING);
	case EXIT_REASON_TASK_SWITCH:
		return true;
	case EXIT_REASON_CPUID:
		return true;
	case EXIT_REASON_HLT:
		return nested_cpu_has(vmcs12, CPU_BASED_HLT_EXITING);
	case EXIT_REASON_INVD:
		return true;
	case EXIT_REASON_INVLPG:
		return nested_cpu_has(vmcs12, CPU_BASED_INVLPG_EXITING);
	case EXIT_REASON_RDPMC:
		return nested_cpu_has(vmcs12, CPU_BASED_RDPMC_EXITING);
	case EXIT_REASON_RDRAND:
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_RDRAND_EXITING);
	case EXIT_REASON_RDSEED:
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_RDSEED_EXITING);
	case EXIT_REASON_RDTSC: case EXIT_REASON_RDTSCP:
		return nested_cpu_has(vmcs12, CPU_BASED_RDTSC_EXITING);
	case EXIT_REASON_VMREAD:
		return nested_vmx_exit_handled_vmcs_access(vcpu, vmcs12,
			vmcs12->vmread_bitmap);
	case EXIT_REASON_VMWRITE:
		return nested_vmx_exit_handled_vmcs_access(vcpu, vmcs12,
			vmcs12->vmwrite_bitmap);
	case EXIT_REASON_VMCALL: case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH: case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST: case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMOFF: case EXIT_REASON_VMON:
	case EXIT_REASON_INVEPT: case EXIT_REASON_INVVPID:
		/*
		return true;
	case EXIT_REASON_CR_ACCESS:
		return nested_vmx_exit_handled_cr(vcpu, vmcs12);
	case EXIT_REASON_DR_ACCESS:
		return nested_cpu_has(vmcs12, CPU_BASED_MOV_DR_EXITING);
	case EXIT_REASON_IO_INSTRUCTION:
		return nested_vmx_exit_handled_io(vcpu, vmcs12);
	case EXIT_REASON_GDTR_IDTR: case EXIT_REASON_LDTR_TR:
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_DESC);
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
		return nested_vmx_exit_handled_msr(vcpu, vmcs12, exit_reason);
	case EXIT_REASON_INVALID_STATE:
		return true;
	case EXIT_REASON_MWAIT_INSTRUCTION:
		return nested_cpu_has(vmcs12, CPU_BASED_MWAIT_EXITING);
	case EXIT_REASON_MONITOR_TRAP_FLAG:
		return nested_vmx_exit_handled_mtf(vmcs12);
	case EXIT_REASON_MONITOR_INSTRUCTION:
		return nested_cpu_has(vmcs12, CPU_BASED_MONITOR_EXITING);
	case EXIT_REASON_PAUSE_INSTRUCTION:
		return nested_cpu_has(vmcs12, CPU_BASED_PAUSE_EXITING) ||
			nested_cpu_has2(vmcs12,
				SECONDARY_EXEC_PAUSE_LOOP_EXITING);
	case EXIT_REASON_MCE_DURING_VMENTRY:
		return true;
	case EXIT_REASON_TPR_BELOW_THRESHOLD:
		return nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW);
	case EXIT_REASON_APIC_ACCESS:
	case EXIT_REASON_APIC_WRITE:
	case EXIT_REASON_EOI_INDUCED:
		/*
		return true;
	case EXIT_REASON_INVPCID:
		return
			nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_INVPCID) &&
			nested_cpu_has(vmcs12, CPU_BASED_INVLPG_EXITING);
	case EXIT_REASON_WBINVD:
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_WBINVD_EXITING);
	case EXIT_REASON_XSETBV:
		return true;
	case EXIT_REASON_XSAVES: case EXIT_REASON_XRSTORS:
		/*
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_XSAVES);
	case EXIT_REASON_UMWAIT:
	case EXIT_REASON_TPAUSE:
		return nested_cpu_has2(vmcs12,
			SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE);
	case EXIT_REASON_ENCLS:
		return nested_vmx_exit_handled_encls(vcpu, vmcs12);
	case EXIT_REASON_NOTIFY:
		/* Notify VM exit is not exposed to L1 */
		return false;
	default:
		return true;
	}
}

bool nested_vmx_reflect_vmexit(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	union vmx_exit_reason exit_reason = vmx->exit_reason;
	unsigned long exit_qual;
	u32 exit_intr_info;

	WARN_ON_ONCE(vmx->nested.nested_run_pending);

	/*
	if (unlikely(vmx->fail)) {
		trace_kvm_nested_vmenter_failed(
			"hardware VM-instruction error: ",
			vmcs_read32(VM_INSTRUCTION_ERROR));
		exit_intr_info = 0;
		exit_qual = 0;
		goto reflect_vmexit;
	}

	trace_kvm_nested_vmexit(vcpu, KVM_ISA_VMX);

	/* If L0 (KVM) wants the exit, it trumps L1's desires. */
	if (nested_vmx_l0_wants_exit(vcpu, exit_reason))
		return false;

	/* If L1 doesn't want the exit, handle it in L0. */
	if (!nested_vmx_l1_wants_exit(vcpu, exit_reason))
		return false;

	/*
	exit_intr_info = vmx_get_intr_info(vcpu);
	if (is_exception_with_error_code(exit_intr_info)) {
		struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

		vmcs12->vm_exit_intr_error_code =
			vmcs_read32(VM_EXIT_INTR_ERROR_CODE);
	}
	exit_qual = vmx_get_exit_qual(vcpu);

reflect_vmexit:
	nested_vmx_vmexit(vcpu, exit_reason.full, exit_intr_info, exit_qual);
	return true;
}

static int vmx_get_nested_state(struct kvm_vcpu *vcpu,
				struct kvm_nested_state __user *user_kvm_nested_state,
				u32 user_data_size)
{
	struct vcpu_vmx *vmx;
	struct vmcs12 *vmcs12;
	struct kvm_nested_state kvm_state = {
		.flags = 0,
		.format = KVM_STATE_NESTED_FORMAT_VMX,
		.size = sizeof(kvm_state),
		.hdr.vmx.flags = 0,
		.hdr.vmx.vmxon_pa = INVALID_GPA,
		.hdr.vmx.vmcs12_pa = INVALID_GPA,
		.hdr.vmx.preemption_timer_deadline = 0,
	};
	struct kvm_vmx_nested_state_data __user *user_vmx_nested_state =
		&user_kvm_nested_state->data.vmx[0];

	if (!vcpu)
		return kvm_state.size + sizeof(*user_vmx_nested_state);

	vmx = to_vmx(vcpu);
	vmcs12 = get_vmcs12(vcpu);

	if (nested_vmx_allowed(vcpu) &&
	    (vmx->nested.vmxon || vmx->nested.smm.vmxon)) {
		kvm_state.hdr.vmx.vmxon_pa = vmx->nested.vmxon_ptr;
		kvm_state.hdr.vmx.vmcs12_pa = vmx->nested.current_vmptr;

		if (vmx_has_valid_vmcs12(vcpu)) {
			kvm_state.size += sizeof(user_vmx_nested_state->vmcs12);

			/* 'hv_evmcs_vmptr' can also be EVMPTR_MAP_PENDING here */
			if (vmx->nested.hv_evmcs_vmptr != EVMPTR_INVALID)
				kvm_state.flags |= KVM_STATE_NESTED_EVMCS;

			if (is_guest_mode(vcpu) &&
			    nested_cpu_has_shadow_vmcs(vmcs12) &&
			    vmcs12->vmcs_link_pointer != INVALID_GPA)
				kvm_state.size += sizeof(user_vmx_nested_state->shadow_vmcs12);
		}

		if (vmx->nested.smm.vmxon)
			kvm_state.hdr.vmx.smm.flags |= KVM_STATE_NESTED_SMM_VMXON;

		if (vmx->nested.smm.guest_mode)
			kvm_state.hdr.vmx.smm.flags |= KVM_STATE_NESTED_SMM_GUEST_MODE;

		if (is_guest_mode(vcpu)) {
			kvm_state.flags |= KVM_STATE_NESTED_GUEST_MODE;

			if (vmx->nested.nested_run_pending)
				kvm_state.flags |= KVM_STATE_NESTED_RUN_PENDING;

			if (vmx->nested.mtf_pending)
				kvm_state.flags |= KVM_STATE_NESTED_MTF_PENDING;

			if (nested_cpu_has_preemption_timer(vmcs12) &&
			    vmx->nested.has_preemption_timer_deadline) {
				kvm_state.hdr.vmx.flags |=
					KVM_STATE_VMX_PREEMPTION_TIMER_DEADLINE;
				kvm_state.hdr.vmx.preemption_timer_deadline =
					vmx->nested.preemption_timer_deadline;
			}
		}
	}

	if (user_data_size < kvm_state.size)
		goto out;

	if (copy_to_user(user_kvm_nested_state, &kvm_state, sizeof(kvm_state)))
		return -EFAULT;

	if (!vmx_has_valid_vmcs12(vcpu))
		goto out;

	/*
	if (is_guest_mode(vcpu)) {
		sync_vmcs02_to_vmcs12(vcpu, vmcs12);
		sync_vmcs02_to_vmcs12_rare(vcpu, vmcs12);
	} else  {
		copy_vmcs02_to_vmcs12_rare(vcpu, get_vmcs12(vcpu));
		if (!vmx->nested.need_vmcs12_to_shadow_sync) {
			if (evmptr_is_valid(vmx->nested.hv_evmcs_vmptr))
				/*
				copy_enlightened_to_vmcs12(vmx, 0);
			else if (enable_shadow_vmcs)
				copy_shadow_to_vmcs12(vmx);
		}
	}

	BUILD_BUG_ON(sizeof(user_vmx_nested_state->vmcs12) < VMCS12_SIZE);
	BUILD_BUG_ON(sizeof(user_vmx_nested_state->shadow_vmcs12) < VMCS12_SIZE);

	/*
	if (copy_to_user(user_vmx_nested_state->vmcs12, vmcs12, VMCS12_SIZE))
		return -EFAULT;

	if (nested_cpu_has_shadow_vmcs(vmcs12) &&
	    vmcs12->vmcs_link_pointer != INVALID_GPA) {
		if (copy_to_user(user_vmx_nested_state->shadow_vmcs12,
				 get_shadow_vmcs12(vcpu), VMCS12_SIZE))
			return -EFAULT;
	}
out:
	return kvm_state.size;
}

void vmx_leave_nested(struct kvm_vcpu *vcpu)
{
	if (is_guest_mode(vcpu)) {
		to_vmx(vcpu)->nested.nested_run_pending = 0;
		nested_vmx_vmexit(vcpu, -1, 0, 0);
	}
	free_nested(vcpu);
}

static int vmx_set_nested_state(struct kvm_vcpu *vcpu,
				struct kvm_nested_state __user *user_kvm_nested_state,
				struct kvm_nested_state *kvm_state)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12;
	enum vm_entry_failure_code ignored;
	struct kvm_vmx_nested_state_data __user *user_vmx_nested_state =
		&user_kvm_nested_state->data.vmx[0];
	int ret;

	if (kvm_state->format != KVM_STATE_NESTED_FORMAT_VMX)
		return -EINVAL;

	if (kvm_state->hdr.vmx.vmxon_pa == INVALID_GPA) {
		if (kvm_state->hdr.vmx.smm.flags)
			return -EINVAL;

		if (kvm_state->hdr.vmx.vmcs12_pa != INVALID_GPA)
			return -EINVAL;

		/*
		if (kvm_state->flags & ~KVM_STATE_NESTED_EVMCS)
			return -EINVAL;
	} else {
		if (!nested_vmx_allowed(vcpu))
			return -EINVAL;

		if (!page_address_valid(vcpu, kvm_state->hdr.vmx.vmxon_pa))
			return -EINVAL;
	}

	if ((kvm_state->hdr.vmx.smm.flags & KVM_STATE_NESTED_SMM_GUEST_MODE) &&
	    (kvm_state->flags & KVM_STATE_NESTED_GUEST_MODE))
		return -EINVAL;

	if (kvm_state->hdr.vmx.smm.flags &
	    ~(KVM_STATE_NESTED_SMM_GUEST_MODE | KVM_STATE_NESTED_SMM_VMXON))
		return -EINVAL;

	if (kvm_state->hdr.vmx.flags & ~KVM_STATE_VMX_PREEMPTION_TIMER_DEADLINE)
		return -EINVAL;

	/*
	if (is_smm(vcpu) ?
		(kvm_state->flags &
		 (KVM_STATE_NESTED_GUEST_MODE | KVM_STATE_NESTED_RUN_PENDING))
		: kvm_state->hdr.vmx.smm.flags)
		return -EINVAL;

	if ((kvm_state->hdr.vmx.smm.flags & KVM_STATE_NESTED_SMM_GUEST_MODE) &&
	    !(kvm_state->hdr.vmx.smm.flags & KVM_STATE_NESTED_SMM_VMXON))
		return -EINVAL;

	if ((kvm_state->flags & KVM_STATE_NESTED_EVMCS) &&
		(!nested_vmx_allowed(vcpu) || !vmx->nested.enlightened_vmcs_enabled))
			return -EINVAL;

	vmx_leave_nested(vcpu);

	if (kvm_state->hdr.vmx.vmxon_pa == INVALID_GPA)
		return 0;

	vmx->nested.vmxon_ptr = kvm_state->hdr.vmx.vmxon_pa;
	ret = enter_vmx_operation(vcpu);
	if (ret)
		return ret;

	/* Empty 'VMXON' state is permitted if no VMCS loaded */
	if (kvm_state->size < sizeof(*kvm_state) + sizeof(*vmcs12)) {
		/* See vmx_has_valid_vmcs12.  */
		if ((kvm_state->flags & KVM_STATE_NESTED_GUEST_MODE) ||
		    (kvm_state->flags & KVM_STATE_NESTED_EVMCS) ||
		    (kvm_state->hdr.vmx.vmcs12_pa != INVALID_GPA))
			return -EINVAL;
		else
			return 0;
	}

	if (kvm_state->hdr.vmx.vmcs12_pa != INVALID_GPA) {
		if (kvm_state->hdr.vmx.vmcs12_pa == kvm_state->hdr.vmx.vmxon_pa ||
		    !page_address_valid(vcpu, kvm_state->hdr.vmx.vmcs12_pa))
			return -EINVAL;

		set_current_vmptr(vmx, kvm_state->hdr.vmx.vmcs12_pa);
	} else if (kvm_state->flags & KVM_STATE_NESTED_EVMCS) {
		/*
		vmx->nested.hv_evmcs_vmptr = EVMPTR_MAP_PENDING;
		kvm_make_request(KVM_REQ_GET_NESTED_STATE_PAGES, vcpu);
	} else {
		return -EINVAL;
	}

	if (kvm_state->hdr.vmx.smm.flags & KVM_STATE_NESTED_SMM_VMXON) {
		vmx->nested.smm.vmxon = true;
		vmx->nested.vmxon = false;

		if (kvm_state->hdr.vmx.smm.flags & KVM_STATE_NESTED_SMM_GUEST_MODE)
			vmx->nested.smm.guest_mode = true;
	}

	vmcs12 = get_vmcs12(vcpu);
	if (copy_from_user(vmcs12, user_vmx_nested_state->vmcs12, sizeof(*vmcs12)))
		return -EFAULT;

	if (vmcs12->hdr.revision_id != VMCS12_REVISION)
		return -EINVAL;

	if (!(kvm_state->flags & KVM_STATE_NESTED_GUEST_MODE))
		return 0;

	vmx->nested.nested_run_pending =
		!!(kvm_state->flags & KVM_STATE_NESTED_RUN_PENDING);

	vmx->nested.mtf_pending =
		!!(kvm_state->flags & KVM_STATE_NESTED_MTF_PENDING);

	ret = -EINVAL;
	if (nested_cpu_has_shadow_vmcs(vmcs12) &&
	    vmcs12->vmcs_link_pointer != INVALID_GPA) {
		struct vmcs12 *shadow_vmcs12 = get_shadow_vmcs12(vcpu);

		if (kvm_state->size <
		    sizeof(*kvm_state) +
		    sizeof(user_vmx_nested_state->vmcs12) + sizeof(*shadow_vmcs12))
			goto error_guest_mode;

		if (copy_from_user(shadow_vmcs12,
				   user_vmx_nested_state->shadow_vmcs12,
				   sizeof(*shadow_vmcs12))) {
			ret = -EFAULT;
			goto error_guest_mode;
		}

		if (shadow_vmcs12->hdr.revision_id != VMCS12_REVISION ||
		    !shadow_vmcs12->hdr.shadow_vmcs)
			goto error_guest_mode;
	}

	vmx->nested.has_preemption_timer_deadline = false;
	if (kvm_state->hdr.vmx.flags & KVM_STATE_VMX_PREEMPTION_TIMER_DEADLINE) {
		vmx->nested.has_preemption_timer_deadline = true;
		vmx->nested.preemption_timer_deadline =
			kvm_state->hdr.vmx.preemption_timer_deadline;
	}

	if (nested_vmx_check_controls(vcpu, vmcs12) ||
	    nested_vmx_check_host_state(vcpu, vmcs12) ||
	    nested_vmx_check_guest_state(vcpu, vmcs12, &ignored))
		goto error_guest_mode;

	vmx->nested.dirty_vmcs12 = true;
	vmx->nested.force_msr_bitmap_recalc = true;
	ret = nested_vmx_enter_non_root_mode(vcpu, false);
	if (ret)
		goto error_guest_mode;

	return 0;

error_guest_mode:
	vmx->nested.nested_run_pending = 0;
	return ret;
}

void nested_vmx_set_vmcs_shadowing_bitmap(void)
{
	if (enable_shadow_vmcs) {
		vmcs_write64(VMREAD_BITMAP, __pa(vmx_vmread_bitmap));
		vmcs_write64(VMWRITE_BITMAP, __pa(vmx_vmwrite_bitmap));
	}
}

#define VMCS12_IDX_TO_ENC(idx) ((u16)(((u16)(idx) >> 6) | ((u16)(idx) << 10)))

static u64 nested_vmx_calc_vmcs_enum_msr(void)
{
	/*
	unsigned int max_idx, idx;
	int i;

	/*
	max_idx = 0;
	for (i = 0; i < nr_vmcs12_fields; i++) {
		/* The vmcs12 table is very, very sparsely populated. */
		if (!vmcs12_field_offsets[i])
			continue;

		idx = vmcs_field_index(VMCS12_IDX_TO_ENC(i));
		if (idx > max_idx)
			max_idx = idx;
	}

	return (u64)max_idx << VMCS_FIELD_INDEX_SHIFT;
}

void nested_vmx_setup_ctls_msrs(struct nested_vmx_msrs *msrs, u32 ept_caps)
{
	/*

	/* pin-based controls */
	rdmsr(MSR_IA32_VMX_PINBASED_CTLS,
		msrs->pinbased_ctls_low,
		msrs->pinbased_ctls_high);
	msrs->pinbased_ctls_low |=
		PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
	msrs->pinbased_ctls_high &=
		PIN_BASED_EXT_INTR_MASK |
		PIN_BASED_NMI_EXITING |
		PIN_BASED_VIRTUAL_NMIS |
		(enable_apicv ? PIN_BASED_POSTED_INTR : 0);
	msrs->pinbased_ctls_high |=
		PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR |
		PIN_BASED_VMX_PREEMPTION_TIMER;

	/* exit controls */
	rdmsr(MSR_IA32_VMX_EXIT_CTLS,
		msrs->exit_ctls_low,
		msrs->exit_ctls_high);
	msrs->exit_ctls_low =
		VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR;

	msrs->exit_ctls_high &=
#ifdef CONFIG_X86_64
		VM_EXIT_HOST_ADDR_SPACE_SIZE |
#endif
		VM_EXIT_LOAD_IA32_PAT | VM_EXIT_SAVE_IA32_PAT |
		VM_EXIT_CLEAR_BNDCFGS | VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL;
	msrs->exit_ctls_high |=
		VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR |
		VM_EXIT_LOAD_IA32_EFER | VM_EXIT_SAVE_IA32_EFER |
		VM_EXIT_SAVE_VMX_PREEMPTION_TIMER | VM_EXIT_ACK_INTR_ON_EXIT;

	/* We support free control of debug control saving. */
	msrs->exit_ctls_low &= ~VM_EXIT_SAVE_DEBUG_CONTROLS;

	/* entry controls */
	rdmsr(MSR_IA32_VMX_ENTRY_CTLS,
		msrs->entry_ctls_low,
		msrs->entry_ctls_high);
	msrs->entry_ctls_low =
		VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR;
	msrs->entry_ctls_high &=
#ifdef CONFIG_X86_64
		VM_ENTRY_IA32E_MODE |
#endif
		VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_BNDCFGS |
		VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL;
	msrs->entry_ctls_high |=
		(VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR | VM_ENTRY_LOAD_IA32_EFER);

	/* We support free control of debug control loading. */
	msrs->entry_ctls_low &= ~VM_ENTRY_LOAD_DEBUG_CONTROLS;

	/* cpu-based controls */
	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS,
		msrs->procbased_ctls_low,
		msrs->procbased_ctls_high);
	msrs->procbased_ctls_low =
		CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
	msrs->procbased_ctls_high &=
		CPU_BASED_INTR_WINDOW_EXITING |
		CPU_BASED_NMI_WINDOW_EXITING | CPU_BASED_USE_TSC_OFFSETTING |
		CPU_BASED_HLT_EXITING | CPU_BASED_INVLPG_EXITING |
		CPU_BASED_MWAIT_EXITING | CPU_BASED_CR3_LOAD_EXITING |
		CPU_BASED_CR3_STORE_EXITING |
#ifdef CONFIG_X86_64
		CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING |
#endif
		CPU_BASED_MOV_DR_EXITING | CPU_BASED_UNCOND_IO_EXITING |
		CPU_BASED_USE_IO_BITMAPS | CPU_BASED_MONITOR_TRAP_FLAG |
		CPU_BASED_MONITOR_EXITING | CPU_BASED_RDPMC_EXITING |
		CPU_BASED_RDTSC_EXITING | CPU_BASED_PAUSE_EXITING |
		CPU_BASED_TPR_SHADOW | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	/*
	msrs->procbased_ctls_high |=
		CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR |
		CPU_BASED_USE_MSR_BITMAPS;

	/* We support free control of CR3 access interception. */
	msrs->procbased_ctls_low &=
		~(CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING);

	/*
	if (msrs->procbased_ctls_high & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)
		rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2,
		      msrs->secondary_ctls_low,
		      msrs->secondary_ctls_high);

	msrs->secondary_ctls_low = 0;
	msrs->secondary_ctls_high &=
		SECONDARY_EXEC_DESC |
		SECONDARY_EXEC_ENABLE_RDTSCP |
		SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
		SECONDARY_EXEC_WBINVD_EXITING |
		SECONDARY_EXEC_APIC_REGISTER_VIRT |
		SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |
		SECONDARY_EXEC_RDRAND_EXITING |
		SECONDARY_EXEC_ENABLE_INVPCID |
		SECONDARY_EXEC_RDSEED_EXITING |
		SECONDARY_EXEC_XSAVES |
		SECONDARY_EXEC_TSC_SCALING;

	/*
	msrs->secondary_ctls_high |=
		SECONDARY_EXEC_SHADOW_VMCS;

	if (enable_ept) {
		/* nested EPT: emulate EPT also to L1 */
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_ENABLE_EPT;
		msrs->ept_caps =
			VMX_EPT_PAGE_WALK_4_BIT |
			VMX_EPT_PAGE_WALK_5_BIT |
			VMX_EPTP_WB_BIT |
			VMX_EPT_INVEPT_BIT |
			VMX_EPT_EXECUTE_ONLY_BIT;

		msrs->ept_caps &= ept_caps;
		msrs->ept_caps |= VMX_EPT_EXTENT_GLOBAL_BIT |
			VMX_EPT_EXTENT_CONTEXT_BIT | VMX_EPT_2MB_PAGE_BIT |
			VMX_EPT_1GB_PAGE_BIT;
		if (enable_ept_ad_bits) {
			msrs->secondary_ctls_high |=
				SECONDARY_EXEC_ENABLE_PML;
			msrs->ept_caps |= VMX_EPT_AD_BIT;
		}
	}

	if (cpu_has_vmx_vmfunc()) {
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_ENABLE_VMFUNC;
		/*
		if (enable_ept)
			msrs->vmfunc_controls =
				VMX_VMFUNC_EPTP_SWITCHING;
	}

	/*
	if (enable_vpid) {
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_ENABLE_VPID;
		msrs->vpid_caps = VMX_VPID_INVVPID_BIT |
			VMX_VPID_EXTENT_SUPPORTED_MASK;
	}

	if (enable_unrestricted_guest)
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_UNRESTRICTED_GUEST;

	if (flexpriority_enabled)
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;

	if (enable_sgx)
		msrs->secondary_ctls_high |= SECONDARY_EXEC_ENCLS_EXITING;

	/* miscellaneous data */
	rdmsr(MSR_IA32_VMX_MISC,
		msrs->misc_low,
		msrs->misc_high);
	msrs->misc_low &= VMX_MISC_SAVE_EFER_LMA;
	msrs->misc_low |=
		MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS |
		VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE |
		VMX_MISC_ACTIVITY_HLT |
		VMX_MISC_ACTIVITY_WAIT_SIPI;
	msrs->misc_high = 0;

	/*
	msrs->basic =
		VMCS12_REVISION |
		VMX_BASIC_TRUE_CTLS |
		((u64)VMCS12_SIZE << VMX_BASIC_VMCS_SIZE_SHIFT) |
		(VMX_BASIC_MEM_TYPE_WB << VMX_BASIC_MEM_TYPE_SHIFT);

	if (cpu_has_vmx_basic_inout())
		msrs->basic |= VMX_BASIC_INOUT;

	/*
#define VMXON_CR0_ALWAYSON     (X86_CR0_PE | X86_CR0_PG | X86_CR0_NE)
#define VMXON_CR4_ALWAYSON     X86_CR4_VMXE
	msrs->cr0_fixed0 = VMXON_CR0_ALWAYSON;
	msrs->cr4_fixed0 = VMXON_CR4_ALWAYSON;

	/* These MSRs specify bits which the guest must keep fixed off. */
	rdmsrl(MSR_IA32_VMX_CR0_FIXED1, msrs->cr0_fixed1);
	rdmsrl(MSR_IA32_VMX_CR4_FIXED1, msrs->cr4_fixed1);

	if (vmx_umip_emulated())
		msrs->cr4_fixed1 |= X86_CR4_UMIP;

	msrs->vmcs_enum = nested_vmx_calc_vmcs_enum_msr();
}

void nested_vmx_hardware_unsetup(void)
{
	int i;

	if (enable_shadow_vmcs) {
		for (i = 0; i < VMX_BITMAP_NR; i++)
			free_page((unsigned long)vmx_bitmap[i]);
	}
}

__init int nested_vmx_hardware_setup(int (*exit_handlers[])(struct kvm_vcpu *))
{
	int i;

	if (!cpu_has_vmx_shadow_vmcs())
		enable_shadow_vmcs = 0;
	if (enable_shadow_vmcs) {
		for (i = 0; i < VMX_BITMAP_NR; i++) {
			/*
			vmx_bitmap[i] = (unsigned long *)
				__get_free_page(GFP_KERNEL);
			if (!vmx_bitmap[i]) {
				nested_vmx_hardware_unsetup();
				return -ENOMEM;
			}
		}

		init_vmcs_shadow_fields();
	}

	exit_handlers[EXIT_REASON_VMCLEAR]	= handle_vmclear;
	exit_handlers[EXIT_REASON_VMLAUNCH]	= handle_vmlaunch;
	exit_handlers[EXIT_REASON_VMPTRLD]	= handle_vmptrld;
	exit_handlers[EXIT_REASON_VMPTRST]	= handle_vmptrst;
	exit_handlers[EXIT_REASON_VMREAD]	= handle_vmread;
	exit_handlers[EXIT_REASON_VMRESUME]	= handle_vmresume;
	exit_handlers[EXIT_REASON_VMWRITE]	= handle_vmwrite;
	exit_handlers[EXIT_REASON_VMOFF]	= handle_vmxoff;
	exit_handlers[EXIT_REASON_VMON]		= handle_vmxon;
	exit_handlers[EXIT_REASON_INVEPT]	= handle_invept;
	exit_handlers[EXIT_REASON_INVVPID]	= handle_invvpid;
	exit_handlers[EXIT_REASON_VMFUNC]	= handle_vmfunc;

	return 0;
}

struct kvm_x86_nested_ops vmx_nested_ops = {
	.leave_nested = vmx_leave_nested,
	.check_events = vmx_check_nested_events,
	.handle_page_fault_workaround = nested_vmx_handle_page_fault_workaround,
	.hv_timer_pending = nested_vmx_preemption_timer_pending,
	.triple_fault = nested_vmx_triple_fault,
	.get_state = vmx_get_nested_state,
	.set_state = vmx_set_nested_state,
	.get_nested_state_pages = vmx_get_nested_state_pages,
	.write_log_dirty = nested_vmx_write_pml_buffer,
	.enable_evmcs = nested_enable_evmcs,
	.get_evmcs_version = nested_get_evmcs_version,
};
