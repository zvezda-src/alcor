
#define pr_fmt(fmt) "SVM: " fmt

#include <linux/kvm_types.h>
#include <linux/hashtable.h>
#include <linux/amd-iommu.h>
#include <linux/kvm_host.h>

#include <asm/irq_remapping.h>

#include "trace.h"
#include "lapic.h"
#include "x86.h"
#include "irq.h"
#include "svm.h"

#define AVIC_VCPU_ID_BITS		8
#define AVIC_VCPU_ID_MASK		((1 << AVIC_VCPU_ID_BITS) - 1)

#define AVIC_VM_ID_BITS			24
#define AVIC_VM_ID_NR			(1 << AVIC_VM_ID_BITS)
#define AVIC_VM_ID_MASK			((1 << AVIC_VM_ID_BITS) - 1)

#define AVIC_GATAG(x, y)		(((x & AVIC_VM_ID_MASK) << AVIC_VCPU_ID_BITS) | \
						(y & AVIC_VCPU_ID_MASK))
#define AVIC_GATAG_TO_VMID(x)		((x >> AVIC_VCPU_ID_BITS) & AVIC_VM_ID_MASK)
#define AVIC_GATAG_TO_VCPUID(x)		(x & AVIC_VCPU_ID_MASK)

static bool force_avic;
module_param_unsafe(force_avic, bool, 0444);

#define SVM_VM_DATA_HASH_BITS	8
static DEFINE_HASHTABLE(svm_vm_data_hash, SVM_VM_DATA_HASH_BITS);
static u32 next_vm_id = 0;
static bool next_vm_id_wrapped = 0;
static DEFINE_SPINLOCK(svm_vm_data_hash_lock);
enum avic_modes avic_mode;

struct amd_svm_iommu_ir {
	struct list_head node;	/* Used by SVM for per-vcpu ir_list */
	void *data;		/* Storing pointer to struct amd_ir_data */
};

static void avic_activate_vmcb(struct vcpu_svm *svm)
{
	struct vmcb *vmcb = svm->vmcb01.ptr;

	vmcb->control.int_ctl &= ~(AVIC_ENABLE_MASK | X2APIC_MODE_MASK);
	vmcb->control.avic_physical_id &= ~AVIC_PHYSICAL_MAX_INDEX_MASK;

	vmcb->control.int_ctl |= AVIC_ENABLE_MASK;

	/* Note:
	 * KVM can support hybrid-AVIC mode, where KVM emulates x2APIC
	 * MSR accesses, while interrupt injection to a running vCPU
	 * can be achieved using AVIC doorbell. The AVIC hardware still
	 * accelerate MMIO accesses, but this does not cause any harm
	 * as the guest is not supposed to access xAPIC mmio when uses x2APIC.
	 */
	if (apic_x2apic_mode(svm->vcpu.arch.apic) &&
	    avic_mode == AVIC_MODE_X2) {
		vmcb->control.int_ctl |= X2APIC_MODE_MASK;
		vmcb->control.avic_physical_id |= X2AVIC_MAX_PHYSICAL_ID;
		/* Disabling MSR intercept for x2APIC registers */
		svm_set_x2apic_msr_interception(svm, false);
	} else {
		/* For xAVIC and hybrid-xAVIC modes */
		vmcb->control.avic_physical_id |= AVIC_MAX_PHYSICAL_ID;
		/* Enabling MSR intercept for x2APIC registers */
		svm_set_x2apic_msr_interception(svm, true);
	}
}

static void avic_deactivate_vmcb(struct vcpu_svm *svm)
{
	struct vmcb *vmcb = svm->vmcb01.ptr;

	vmcb->control.int_ctl &= ~(AVIC_ENABLE_MASK | X2APIC_MODE_MASK);
	vmcb->control.avic_physical_id &= ~AVIC_PHYSICAL_MAX_INDEX_MASK;

	/*
	if (is_guest_mode(&svm->vcpu) &&
	    vmcb12_is_intercept(&svm->nested.ctl, INTERCEPT_MSR_PROT))
		return;

	/* Enabling MSR intercept for x2APIC registers */
	svm_set_x2apic_msr_interception(svm, true);
}

int avic_ga_log_notifier(u32 ga_tag)
{
	unsigned long flags;
	struct kvm_svm *kvm_svm;
	struct kvm_vcpu *vcpu = NULL;
	u32 vm_id = AVIC_GATAG_TO_VMID(ga_tag);
	u32 vcpu_id = AVIC_GATAG_TO_VCPUID(ga_tag);

	pr_debug("SVM: %s: vm_id=%#x, vcpu_id=%#x\n", __func__, vm_id, vcpu_id);
	trace_kvm_avic_ga_log(vm_id, vcpu_id);

	spin_lock_irqsave(&svm_vm_data_hash_lock, flags);
	hash_for_each_possible(svm_vm_data_hash, kvm_svm, hnode, vm_id) {
		if (kvm_svm->avic_vm_id != vm_id)
			continue;
		vcpu = kvm_get_vcpu_by_id(&kvm_svm->kvm, vcpu_id);
		break;
	}
	spin_unlock_irqrestore(&svm_vm_data_hash_lock, flags);

	/* Note:
	 * At this point, the IOMMU should have already set the pending
	 * bit in the vAPIC backing page. So, we just need to schedule
	 * in the vcpu.
	 */
	if (vcpu)
		kvm_vcpu_wake_up(vcpu);

	return 0;
}

void avic_vm_destroy(struct kvm *kvm)
{
	unsigned long flags;
	struct kvm_svm *kvm_svm = to_kvm_svm(kvm);

	if (!enable_apicv)
		return;

	if (kvm_svm->avic_logical_id_table_page)
		__free_page(kvm_svm->avic_logical_id_table_page);
	if (kvm_svm->avic_physical_id_table_page)
		__free_page(kvm_svm->avic_physical_id_table_page);

	spin_lock_irqsave(&svm_vm_data_hash_lock, flags);
	hash_del(&kvm_svm->hnode);
	spin_unlock_irqrestore(&svm_vm_data_hash_lock, flags);
}

int avic_vm_init(struct kvm *kvm)
{
	unsigned long flags;
	int err = -ENOMEM;
	struct kvm_svm *kvm_svm = to_kvm_svm(kvm);
	struct kvm_svm *k2;
	struct page *p_page;
	struct page *l_page;
	u32 vm_id;

	if (!enable_apicv)
		return 0;

	/* Allocating physical APIC ID table (4KB) */
	p_page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!p_page)
		goto free_avic;

	kvm_svm->avic_physical_id_table_page = p_page;

	/* Allocating logical APIC ID table (4KB) */
	l_page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!l_page)
		goto free_avic;

	kvm_svm->avic_logical_id_table_page = l_page;

	spin_lock_irqsave(&svm_vm_data_hash_lock, flags);
 again:
	vm_id = next_vm_id = (next_vm_id + 1) & AVIC_VM_ID_MASK;
	if (vm_id == 0) { /* id is 1-based, zero is not okay */
		next_vm_id_wrapped = 1;
		goto again;
	}
	/* Is it still in use? Only possible if wrapped at least once */
	if (next_vm_id_wrapped) {
		hash_for_each_possible(svm_vm_data_hash, k2, hnode, vm_id) {
			if (k2->avic_vm_id == vm_id)
				goto again;
		}
	}
	kvm_svm->avic_vm_id = vm_id;
	hash_add(svm_vm_data_hash, &kvm_svm->hnode, kvm_svm->avic_vm_id);
	spin_unlock_irqrestore(&svm_vm_data_hash_lock, flags);

	return 0;

free_avic:
	avic_vm_destroy(kvm);
	return err;
}

void avic_init_vmcb(struct vcpu_svm *svm, struct vmcb *vmcb)
{
	struct kvm_svm *kvm_svm = to_kvm_svm(svm->vcpu.kvm);
	phys_addr_t bpa = __sme_set(page_to_phys(svm->avic_backing_page));
	phys_addr_t lpa = __sme_set(page_to_phys(kvm_svm->avic_logical_id_table_page));
	phys_addr_t ppa = __sme_set(page_to_phys(kvm_svm->avic_physical_id_table_page));

	vmcb->control.avic_backing_page = bpa & AVIC_HPA_MASK;
	vmcb->control.avic_logical_id = lpa & AVIC_HPA_MASK;
	vmcb->control.avic_physical_id = ppa & AVIC_HPA_MASK;
	vmcb->control.avic_vapic_bar = APIC_DEFAULT_PHYS_BASE & VMCB_AVIC_APIC_BAR_MASK;

	if (kvm_apicv_activated(svm->vcpu.kvm))
		avic_activate_vmcb(svm);
	else
		avic_deactivate_vmcb(svm);
}

static u64 *avic_get_physical_id_entry(struct kvm_vcpu *vcpu,
				       unsigned int index)
{
	u64 *avic_physical_id_table;
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);

	if ((avic_mode == AVIC_MODE_X1 && index > AVIC_MAX_PHYSICAL_ID) ||
	    (avic_mode == AVIC_MODE_X2 && index > X2AVIC_MAX_PHYSICAL_ID))
		return NULL;

	avic_physical_id_table = page_address(kvm_svm->avic_physical_id_table_page);

	return &avic_physical_id_table[index];
}

static int avic_alloc_access_page(struct kvm *kvm)
{
	void __user *ret;
	int r = 0;

	mutex_lock(&kvm->slots_lock);

	if (kvm->arch.apic_access_memslot_enabled)
		goto out;

	ret = __x86_set_memory_region(kvm,
				      APIC_ACCESS_PAGE_PRIVATE_MEMSLOT,
				      APIC_DEFAULT_PHYS_BASE,
				      PAGE_SIZE);
	if (IS_ERR(ret)) {
		r = PTR_ERR(ret);
		goto out;
	}

	kvm->arch.apic_access_memslot_enabled = true;
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static int avic_init_backing_page(struct kvm_vcpu *vcpu)
{
	u64 *entry, new_entry;
	int id = vcpu->vcpu_id;
	struct vcpu_svm *svm = to_svm(vcpu);

	if ((avic_mode == AVIC_MODE_X1 && id > AVIC_MAX_PHYSICAL_ID) ||
	    (avic_mode == AVIC_MODE_X2 && id > X2AVIC_MAX_PHYSICAL_ID))
		return -EINVAL;

	if (!vcpu->arch.apic->regs)
		return -EINVAL;

	if (kvm_apicv_activated(vcpu->kvm)) {
		int ret;

		ret = avic_alloc_access_page(vcpu->kvm);
		if (ret)
			return ret;
	}

	svm->avic_backing_page = virt_to_page(vcpu->arch.apic->regs);

	/* Setting AVIC backing page address in the phy APIC ID table */
	entry = avic_get_physical_id_entry(vcpu, id);
	if (!entry)
		return -EINVAL;

	new_entry = __sme_set((page_to_phys(svm->avic_backing_page) &
			      AVIC_PHYSICAL_ID_ENTRY_BACKING_PAGE_MASK) |
			      AVIC_PHYSICAL_ID_ENTRY_VALID_MASK);
	WRITE_ONCE(*entry, new_entry);

	svm->avic_physical_id_cache = entry;

	return 0;
}

void avic_ring_doorbell(struct kvm_vcpu *vcpu)
{
	/*
	int cpu = READ_ONCE(vcpu->cpu);

	if (cpu != get_cpu()) {
		wrmsrl(MSR_AMD64_SVM_AVIC_DOORBELL, kvm_cpu_get_apicid(cpu));
		trace_kvm_avic_doorbell(vcpu->vcpu_id, kvm_cpu_get_apicid(cpu));
	}
	put_cpu();
}

static int avic_kick_target_vcpus_fast(struct kvm *kvm, struct kvm_lapic *source,
				       u32 icrl, u32 icrh, u32 index)
{
	u32 l1_physical_id, dest;
	struct kvm_vcpu *target_vcpu;
	int dest_mode = icrl & APIC_DEST_MASK;
	int shorthand = icrl & APIC_SHORT_MASK;
	struct kvm_svm *kvm_svm = to_kvm_svm(kvm);

	if (shorthand != APIC_DEST_NOSHORT)
		return -EINVAL;

	if (apic_x2apic_mode(source))
		dest = icrh;
	else
		dest = GET_XAPIC_DEST_FIELD(icrh);

	if (dest_mode == APIC_DEST_PHYSICAL) {
		/* broadcast destination, use slow path */
		if (apic_x2apic_mode(source) && dest == X2APIC_BROADCAST)
			return -EINVAL;
		if (!apic_x2apic_mode(source) && dest == APIC_BROADCAST)
			return -EINVAL;

		l1_physical_id = dest;

		if (WARN_ON_ONCE(l1_physical_id != index))
			return -EINVAL;

	} else {
		u32 bitmap, cluster;
		int logid_index;

		if (apic_x2apic_mode(source)) {
			/* 16 bit dest mask, 16 bit cluster id */
			bitmap = dest & 0xFFFF0000;
			cluster = (dest >> 16) << 4;
		} else if (kvm_lapic_get_reg(source, APIC_DFR) == APIC_DFR_FLAT) {
			/* 8 bit dest mask*/
			bitmap = dest;
			cluster = 0;
		} else {
			/* 4 bit desk mask, 4 bit cluster id */
			bitmap = dest & 0xF;
			cluster = (dest >> 4) << 2;
		}

		if (unlikely(!bitmap))
			/* guest bug: nobody to send the logical interrupt to */
			return 0;

		if (!is_power_of_2(bitmap))
			/* multiple logical destinations, use slow path */
			return -EINVAL;

		logid_index = cluster + __ffs(bitmap);

		if (!apic_x2apic_mode(source)) {
			u32 *avic_logical_id_table =
				page_address(kvm_svm->avic_logical_id_table_page);

			u32 logid_entry = avic_logical_id_table[logid_index];

			if (WARN_ON_ONCE(index != logid_index))
				return -EINVAL;

			/* guest bug: non existing/reserved logical destination */
			if (unlikely(!(logid_entry & AVIC_LOGICAL_ID_ENTRY_VALID_MASK)))
				return 0;

			l1_physical_id = logid_entry &
					 AVIC_LOGICAL_ID_ENTRY_GUEST_PHYSICAL_ID_MASK;
		} else {
			/*
			int cluster = (icrh & 0xffff0000) >> 16;
			int apic = ffs(icrh & 0xffff) - 1;

			/*
			if (apic < 0 || icrh != (1 << apic))
				return -EINVAL;

			l1_physical_id = (cluster << 4) + apic;
		}
	}

	target_vcpu = kvm_get_vcpu_by_id(kvm, l1_physical_id);
	if (unlikely(!target_vcpu))
		/* guest bug: non existing vCPU is a target of this IPI*/
		return 0;

	target_vcpu->arch.apic->irr_pending = true;
	svm_complete_interrupt_delivery(target_vcpu,
					icrl & APIC_MODE_MASK,
					icrl & APIC_INT_LEVELTRIG,
					icrl & APIC_VECTOR_MASK);
	return 0;
}

static void avic_kick_target_vcpus(struct kvm *kvm, struct kvm_lapic *source,
				   u32 icrl, u32 icrh, u32 index)
{
	unsigned long i;
	struct kvm_vcpu *vcpu;

	if (!avic_kick_target_vcpus_fast(kvm, source, icrl, icrh, index))
		return;

	trace_kvm_avic_kick_vcpu_slowpath(icrh, icrl, index);

	/*
	kvm_for_each_vcpu(i, vcpu, kvm) {
		u32 dest;

		if (apic_x2apic_mode(vcpu->arch.apic))
			dest = icrh;
		else
			dest = GET_XAPIC_DEST_FIELD(icrh);

		if (kvm_apic_match_dest(vcpu, source, icrl & APIC_SHORT_MASK,
					dest, icrl & APIC_DEST_MASK)) {
			vcpu->arch.apic->irr_pending = true;
			svm_complete_interrupt_delivery(vcpu,
							icrl & APIC_MODE_MASK,
							icrl & APIC_INT_LEVELTRIG,
							icrl & APIC_VECTOR_MASK);
		}
	}
}

int avic_incomplete_ipi_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 icrh = svm->vmcb->control.exit_info_1 >> 32;
	u32 icrl = svm->vmcb->control.exit_info_1;
	u32 id = svm->vmcb->control.exit_info_2 >> 32;
	u32 index = svm->vmcb->control.exit_info_2 & 0x1FF;
	struct kvm_lapic *apic = vcpu->arch.apic;

	trace_kvm_avic_incomplete_ipi(vcpu->vcpu_id, icrh, icrl, id, index);

	switch (id) {
	case AVIC_IPI_FAILURE_INVALID_INT_TYPE:
		/*
		if (icrl & APIC_ICR_BUSY)
			kvm_apic_write_nodecode(vcpu, APIC_ICR);
		else
			kvm_apic_send_ipi(apic, icrl, icrh);
		break;
	case AVIC_IPI_FAILURE_TARGET_NOT_RUNNING:
		/*
		avic_kick_target_vcpus(vcpu->kvm, apic, icrl, icrh, index);
		break;
	case AVIC_IPI_FAILURE_INVALID_TARGET:
		break;
	case AVIC_IPI_FAILURE_INVALID_BACKING_PAGE:
		WARN_ONCE(1, "Invalid backing page\n");
		break;
	default:
		pr_err("Unknown IPI interception\n");
	}

	return 1;
}

unsigned long avic_vcpu_get_apicv_inhibit_reasons(struct kvm_vcpu *vcpu)
{
	if (is_guest_mode(vcpu))
		return APICV_INHIBIT_REASON_NESTED;
	return 0;
}

static u32 *avic_get_logical_id_entry(struct kvm_vcpu *vcpu, u32 ldr, bool flat)
{
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);
	int index;
	u32 *logical_apic_id_table;
	int dlid = GET_APIC_LOGICAL_ID(ldr);

	if (!dlid)
		return NULL;

	if (flat) { /* flat */
		index = ffs(dlid) - 1;
		if (index > 7)
			return NULL;
	} else { /* cluster */
		int cluster = (dlid & 0xf0) >> 4;
		int apic = ffs(dlid & 0x0f) - 1;

		if ((apic < 0) || (apic > 7) ||
		    (cluster >= 0xf))
			return NULL;
		index = (cluster << 2) + apic;
	}

	logical_apic_id_table = (u32 *) page_address(kvm_svm->avic_logical_id_table_page);

	return &logical_apic_id_table[index];
}

static int avic_ldr_write(struct kvm_vcpu *vcpu, u8 g_physical_id, u32 ldr)
{
	bool flat;
	u32 *entry, new_entry;

	flat = kvm_lapic_get_reg(vcpu->arch.apic, APIC_DFR) == APIC_DFR_FLAT;
	entry = avic_get_logical_id_entry(vcpu, ldr, flat);
	if (!entry)
		return -EINVAL;

	new_entry = READ_ONCE(*entry);
	new_entry &= ~AVIC_LOGICAL_ID_ENTRY_GUEST_PHYSICAL_ID_MASK;
	new_entry |= (g_physical_id & AVIC_LOGICAL_ID_ENTRY_GUEST_PHYSICAL_ID_MASK);
	new_entry |= AVIC_LOGICAL_ID_ENTRY_VALID_MASK;
	WRITE_ONCE(*entry, new_entry);

	return 0;
}

static void avic_invalidate_logical_id_entry(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	bool flat = svm->dfr_reg == APIC_DFR_FLAT;
	u32 *entry;

	/* Note: x2AVIC does not use logical APIC ID table */
	if (apic_x2apic_mode(vcpu->arch.apic))
		return;

	entry = avic_get_logical_id_entry(vcpu, svm->ldr_reg, flat);
	if (entry)
		clear_bit(AVIC_LOGICAL_ID_ENTRY_VALID_BIT, (unsigned long *)entry);
}

static int avic_handle_ldr_update(struct kvm_vcpu *vcpu)
{
	int ret = 0;
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 ldr = kvm_lapic_get_reg(vcpu->arch.apic, APIC_LDR);
	u32 id = kvm_xapic_id(vcpu->arch.apic);

	/* AVIC does not support LDR update for x2APIC */
	if (apic_x2apic_mode(vcpu->arch.apic))
		return 0;

	if (ldr == svm->ldr_reg)
		return 0;

	avic_invalidate_logical_id_entry(vcpu);

	if (ldr)
		ret = avic_ldr_write(vcpu, id, ldr);

	if (!ret)
		svm->ldr_reg = ldr;

	return ret;
}

static void avic_handle_dfr_update(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 dfr = kvm_lapic_get_reg(vcpu->arch.apic, APIC_DFR);

	if (svm->dfr_reg == dfr)
		return;

	avic_invalidate_logical_id_entry(vcpu);
	svm->dfr_reg = dfr;
}

static int avic_unaccel_trap_write(struct kvm_vcpu *vcpu)
{
	u32 offset = to_svm(vcpu)->vmcb->control.exit_info_1 &
				AVIC_UNACCEL_ACCESS_OFFSET_MASK;

	switch (offset) {
	case APIC_LDR:
		if (avic_handle_ldr_update(vcpu))
			return 0;
		break;
	case APIC_DFR:
		avic_handle_dfr_update(vcpu);
		break;
	default:
		break;
	}

	kvm_apic_write_nodecode(vcpu, offset);
	return 1;
}

static bool is_avic_unaccelerated_access_trap(u32 offset)
{
	bool ret = false;

	switch (offset) {
	case APIC_ID:
	case APIC_EOI:
	case APIC_RRR:
	case APIC_LDR:
	case APIC_DFR:
	case APIC_SPIV:
	case APIC_ESR:
	case APIC_ICR:
	case APIC_LVTT:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_LVTERR:
	case APIC_TMICT:
	case APIC_TDCR:
		ret = true;
		break;
	default:
		break;
	}
	return ret;
}

int avic_unaccelerated_access_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int ret = 0;
	u32 offset = svm->vmcb->control.exit_info_1 &
		     AVIC_UNACCEL_ACCESS_OFFSET_MASK;
	u32 vector = svm->vmcb->control.exit_info_2 &
		     AVIC_UNACCEL_ACCESS_VECTOR_MASK;
	bool write = (svm->vmcb->control.exit_info_1 >> 32) &
		     AVIC_UNACCEL_ACCESS_WRITE_MASK;
	bool trap = is_avic_unaccelerated_access_trap(offset);

	trace_kvm_avic_unaccelerated_access(vcpu->vcpu_id, offset,
					    trap, write, vector);
	if (trap) {
		/* Handling Trap */
		WARN_ONCE(!write, "svm: Handling trap read.\n");
		ret = avic_unaccel_trap_write(vcpu);
	} else {
		/* Handling Fault */
		ret = kvm_emulate_instruction(vcpu, 0);
	}

	return ret;
}

int avic_init_vcpu(struct vcpu_svm *svm)
{
	int ret;
	struct kvm_vcpu *vcpu = &svm->vcpu;

	if (!enable_apicv || !irqchip_in_kernel(vcpu->kvm))
		return 0;

	ret = avic_init_backing_page(vcpu);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&svm->ir_list);
	spin_lock_init(&svm->ir_list_lock);
	svm->dfr_reg = APIC_DFR_FLAT;

	return ret;
}

void avic_apicv_post_state_restore(struct kvm_vcpu *vcpu)
{
	avic_handle_dfr_update(vcpu);
	avic_handle_ldr_update(vcpu);
}

void avic_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	if (!lapic_in_kernel(vcpu) || avic_mode == AVIC_MODE_NONE)
		return;

	if (kvm_get_apic_mode(vcpu) == LAPIC_MODE_INVALID) {
		WARN_ONCE(true, "Invalid local APIC state (vcpu_id=%d)", vcpu->vcpu_id);
		return;
	}
	avic_refresh_apicv_exec_ctrl(vcpu);
}

static int avic_set_pi_irte_mode(struct kvm_vcpu *vcpu, bool activate)
{
	int ret = 0;
	unsigned long flags;
	struct amd_svm_iommu_ir *ir;
	struct vcpu_svm *svm = to_svm(vcpu);

	if (!kvm_arch_has_assigned_device(vcpu->kvm))
		return 0;

	/*
	spin_lock_irqsave(&svm->ir_list_lock, flags);

	if (list_empty(&svm->ir_list))
		goto out;

	list_for_each_entry(ir, &svm->ir_list, node) {
		if (activate)
			ret = amd_iommu_activate_guest_mode(ir->data);
		else
			ret = amd_iommu_deactivate_guest_mode(ir->data);
		if (ret)
			break;
	}
out:
	spin_unlock_irqrestore(&svm->ir_list_lock, flags);
	return ret;
}

static void svm_ir_list_del(struct vcpu_svm *svm, struct amd_iommu_pi_data *pi)
{
	unsigned long flags;
	struct amd_svm_iommu_ir *cur;

	spin_lock_irqsave(&svm->ir_list_lock, flags);
	list_for_each_entry(cur, &svm->ir_list, node) {
		if (cur->data != pi->ir_data)
			continue;
		list_del(&cur->node);
		kfree(cur);
		break;
	}
	spin_unlock_irqrestore(&svm->ir_list_lock, flags);
}

static int svm_ir_list_add(struct vcpu_svm *svm, struct amd_iommu_pi_data *pi)
{
	int ret = 0;
	unsigned long flags;
	struct amd_svm_iommu_ir *ir;

	/**
	 * In some cases, the existing irte is updated and re-set,
	 * so we need to check here if it's already been * added
	 * to the ir_list.
	 */
	if (pi->ir_data && (pi->prev_ga_tag != 0)) {
		struct kvm *kvm = svm->vcpu.kvm;
		u32 vcpu_id = AVIC_GATAG_TO_VCPUID(pi->prev_ga_tag);
		struct kvm_vcpu *prev_vcpu = kvm_get_vcpu_by_id(kvm, vcpu_id);
		struct vcpu_svm *prev_svm;

		if (!prev_vcpu) {
			ret = -EINVAL;
			goto out;
		}

		prev_svm = to_svm(prev_vcpu);
		svm_ir_list_del(prev_svm, pi);
	}

	/**
	 * Allocating new amd_iommu_pi_data, which will get
	 * add to the per-vcpu ir_list.
	 */
	ir = kzalloc(sizeof(struct amd_svm_iommu_ir), GFP_KERNEL_ACCOUNT);
	if (!ir) {
		ret = -ENOMEM;
		goto out;
	}
	ir->data = pi->ir_data;

	spin_lock_irqsave(&svm->ir_list_lock, flags);
	list_add(&ir->node, &svm->ir_list);
	spin_unlock_irqrestore(&svm->ir_list_lock, flags);
out:
	return ret;
}

static int
get_pi_vcpu_info(struct kvm *kvm, struct kvm_kernel_irq_routing_entry *e,
		 struct vcpu_data *vcpu_info, struct vcpu_svm **svm)
{
	struct kvm_lapic_irq irq;
	struct kvm_vcpu *vcpu = NULL;

	kvm_set_msi_irq(kvm, e, &irq);

	if (!kvm_intr_is_single_vcpu(kvm, &irq, &vcpu) ||
	    !kvm_irq_is_postable(&irq)) {
		pr_debug("SVM: %s: use legacy intr remap mode for irq %u\n",
			 __func__, irq.vector);
		return -1;
	}

	pr_debug("SVM: %s: use GA mode for irq %u\n", __func__,
		 irq.vector);
	vcpu_info->pi_desc_addr = __sme_set(page_to_phys((*svm)->avic_backing_page));
	vcpu_info->vector = irq.vector;

	return 0;
}

int avic_pi_update_irte(struct kvm *kvm, unsigned int host_irq,
			uint32_t guest_irq, bool set)
{
	struct kvm_kernel_irq_routing_entry *e;
	struct kvm_irq_routing_table *irq_rt;
	int idx, ret = 0;

	if (!kvm_arch_has_assigned_device(kvm) ||
	    !irq_remapping_cap(IRQ_POSTING_CAP))
		return 0;

	pr_debug("SVM: %s: host_irq=%#x, guest_irq=%#x, set=%#x\n",
		 __func__, host_irq, guest_irq, set);

	idx = srcu_read_lock(&kvm->irq_srcu);
	irq_rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);

	if (guest_irq >= irq_rt->nr_rt_entries ||
		hlist_empty(&irq_rt->map[guest_irq])) {
		pr_warn_once("no route for guest_irq %u/%u (broken user space?)\n",
			     guest_irq, irq_rt->nr_rt_entries);
		goto out;
	}

	hlist_for_each_entry(e, &irq_rt->map[guest_irq], link) {
		struct vcpu_data vcpu_info;
		struct vcpu_svm *svm = NULL;

		if (e->type != KVM_IRQ_ROUTING_MSI)
			continue;

		/**
		 * Here, we setup with legacy mode in the following cases:
		 * 1. When cannot target interrupt to a specific vcpu.
		 * 2. Unsetting posted interrupt.
		 * 3. APIC virtualization is disabled for the vcpu.
		 * 4. IRQ has incompatible delivery mode (SMI, INIT, etc)
		 */
		if (!get_pi_vcpu_info(kvm, e, &vcpu_info, &svm) && set &&
		    kvm_vcpu_apicv_active(&svm->vcpu)) {
			struct amd_iommu_pi_data pi;

			/* Try to enable guest_mode in IRTE */
			pi.base = __sme_set(page_to_phys(svm->avic_backing_page) &
					    AVIC_HPA_MASK);
			pi.ga_tag = AVIC_GATAG(to_kvm_svm(kvm)->avic_vm_id,
						     svm->vcpu.vcpu_id);
			pi.is_guest_mode = true;
			pi.vcpu_data = &vcpu_info;
			ret = irq_set_vcpu_affinity(host_irq, &pi);

			/**
			 * Here, we successfully setting up vcpu affinity in
			 * IOMMU guest mode. Now, we need to store the posted
			 * interrupt information in a per-vcpu ir_list so that
			 * we can reference to them directly when we update vcpu
			 * scheduling information in IOMMU irte.
			 */
			if (!ret && pi.is_guest_mode)
				svm_ir_list_add(svm, &pi);
		} else {
			/* Use legacy mode in IRTE */
			struct amd_iommu_pi_data pi;

			/**
			 * Here, pi is used to:
			 * - Tell IOMMU to use legacy mode for this interrupt.
			 * - Retrieve ga_tag of prior interrupt remapping data.
			 */
			pi.prev_ga_tag = 0;
			pi.is_guest_mode = false;
			ret = irq_set_vcpu_affinity(host_irq, &pi);

			/**
			 * Check if the posted interrupt was previously
			 * setup with the guest_mode by checking if the ga_tag
			 * was cached. If so, we need to clean up the per-vcpu
			 * ir_list.
			 */
			if (!ret && pi.prev_ga_tag) {
				int id = AVIC_GATAG_TO_VCPUID(pi.prev_ga_tag);
				struct kvm_vcpu *vcpu;

				vcpu = kvm_get_vcpu_by_id(kvm, id);
				if (vcpu)
					svm_ir_list_del(to_svm(vcpu), &pi);
			}
		}

		if (!ret && svm) {
			trace_kvm_pi_irte_update(host_irq, svm->vcpu.vcpu_id,
						 e->gsi, vcpu_info.vector,
						 vcpu_info.pi_desc_addr, set);
		}

		if (ret < 0) {
			pr_err("%s: failed to update PI IRTE\n", __func__);
			goto out;
		}
	}

	ret = 0;
out:
	srcu_read_unlock(&kvm->irq_srcu, idx);
	return ret;
}

bool avic_check_apicv_inhibit_reasons(enum kvm_apicv_inhibit reason)
{
	ulong supported = BIT(APICV_INHIBIT_REASON_DISABLE) |
			  BIT(APICV_INHIBIT_REASON_ABSENT) |
			  BIT(APICV_INHIBIT_REASON_HYPERV) |
			  BIT(APICV_INHIBIT_REASON_NESTED) |
			  BIT(APICV_INHIBIT_REASON_IRQWIN) |
			  BIT(APICV_INHIBIT_REASON_PIT_REINJ) |
			  BIT(APICV_INHIBIT_REASON_BLOCKIRQ) |
			  BIT(APICV_INHIBIT_REASON_SEV)      |
			  BIT(APICV_INHIBIT_REASON_APIC_ID_MODIFIED) |
			  BIT(APICV_INHIBIT_REASON_APIC_BASE_MODIFIED);

	return supported & BIT(reason);
}


static inline int
avic_update_iommu_vcpu_affinity(struct kvm_vcpu *vcpu, int cpu, bool r)
{
	int ret = 0;
	unsigned long flags;
	struct amd_svm_iommu_ir *ir;
	struct vcpu_svm *svm = to_svm(vcpu);

	if (!kvm_arch_has_assigned_device(vcpu->kvm))
		return 0;

	/*
	spin_lock_irqsave(&svm->ir_list_lock, flags);

	if (list_empty(&svm->ir_list))
		goto out;

	list_for_each_entry(ir, &svm->ir_list, node) {
		ret = amd_iommu_update_ga(cpu, r, ir->data);
		if (ret)
			break;
	}
out:
	spin_unlock_irqrestore(&svm->ir_list_lock, flags);
	return ret;
}

void avic_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	u64 entry;
	int h_physical_id = kvm_cpu_get_apicid(cpu);
	struct vcpu_svm *svm = to_svm(vcpu);

	lockdep_assert_preemption_disabled();

	if (WARN_ON(h_physical_id & ~AVIC_PHYSICAL_ID_ENTRY_HOST_PHYSICAL_ID_MASK))
		return;

	/*
	if (kvm_vcpu_is_blocking(vcpu))
		return;

	entry = READ_ONCE(*(svm->avic_physical_id_cache));

	entry &= ~AVIC_PHYSICAL_ID_ENTRY_HOST_PHYSICAL_ID_MASK;
	entry |= (h_physical_id & AVIC_PHYSICAL_ID_ENTRY_HOST_PHYSICAL_ID_MASK);
	entry |= AVIC_PHYSICAL_ID_ENTRY_IS_RUNNING_MASK;

	WRITE_ONCE(*(svm->avic_physical_id_cache), entry);
	avic_update_iommu_vcpu_affinity(vcpu, h_physical_id, true);
}

void avic_vcpu_put(struct kvm_vcpu *vcpu)
{
	u64 entry;
	struct vcpu_svm *svm = to_svm(vcpu);

	lockdep_assert_preemption_disabled();

	entry = READ_ONCE(*(svm->avic_physical_id_cache));

	/* Nothing to do if IsRunning == '0' due to vCPU blocking. */
	if (!(entry & AVIC_PHYSICAL_ID_ENTRY_IS_RUNNING_MASK))
		return;

	avic_update_iommu_vcpu_affinity(vcpu, -1, 0);

	entry &= ~AVIC_PHYSICAL_ID_ENTRY_IS_RUNNING_MASK;
	WRITE_ONCE(*(svm->avic_physical_id_cache), entry);
}


void avic_refresh_apicv_exec_ctrl(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb *vmcb = svm->vmcb01.ptr;
	bool activated = kvm_vcpu_apicv_active(vcpu);

	if (!enable_apicv)
		return;

	if (activated) {
		/**
		 * During AVIC temporary deactivation, guest could update
		 * APIC ID, DFR and LDR registers, which would not be trapped
		 * by avic_unaccelerated_access_interception(). In this case,
		 * we need to check and update the AVIC logical APIC ID table
		 * accordingly before re-activating.
		 */
		avic_apicv_post_state_restore(vcpu);
		avic_activate_vmcb(svm);
	} else {
		avic_deactivate_vmcb(svm);
	}
	vmcb_mark_dirty(vmcb, VMCB_AVIC);

	if (activated)
		avic_vcpu_load(vcpu, vcpu->cpu);
	else
		avic_vcpu_put(vcpu);

	avic_set_pi_irte_mode(vcpu, activated);
}

void avic_vcpu_blocking(struct kvm_vcpu *vcpu)
{
	if (!kvm_vcpu_apicv_active(vcpu))
		return;

       /*
	avic_vcpu_put(vcpu);
}

void avic_vcpu_unblocking(struct kvm_vcpu *vcpu)
{
	if (!kvm_vcpu_apicv_active(vcpu))
		return;

	avic_vcpu_load(vcpu, vcpu->cpu);
}

bool avic_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	if (!npt_enabled)
		return false;

	if (boot_cpu_has(X86_FEATURE_AVIC)) {
		avic_mode = AVIC_MODE_X1;
		pr_info("AVIC enabled\n");
	} else if (force_avic) {
		/*
		avic_mode = AVIC_MODE_X1;
		pr_warn("AVIC is not supported in CPUID but force enabled");
		pr_warn("Your system might crash and burn");
	}

	/* AVIC is a prerequisite for x2AVIC. */
	if (boot_cpu_has(X86_FEATURE_X2AVIC)) {
		if (avic_mode == AVIC_MODE_X1) {
			avic_mode = AVIC_MODE_X2;
			pr_info("x2AVIC enabled\n");
		} else {
			pr_warn(FW_BUG "Cannot support x2AVIC due to AVIC is disabled");
			pr_warn(FW_BUG "Try enable AVIC using force_avic option");
		}
	}

	if (avic_mode != AVIC_MODE_NONE)
		amd_iommu_register_ga_log_notifier(&avic_ga_log_notifier);

	return !!avic_mode;
}
