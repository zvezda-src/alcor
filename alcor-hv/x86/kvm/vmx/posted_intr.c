#include <linux/kvm_host.h>

#include <asm/irq_remapping.h>
#include <asm/cpu.h>

#include "lapic.h"
#include "irq.h"
#include "posted_intr.h"
#include "trace.h"
#include "vmx.h"

static DEFINE_PER_CPU(struct list_head, wakeup_vcpus_on_cpu);
static DEFINE_PER_CPU(raw_spinlock_t, wakeup_vcpus_on_cpu_lock);

static inline struct pi_desc *vcpu_to_pi_desc(struct kvm_vcpu *vcpu)
{
	return &(to_vmx(vcpu)->pi_desc);
}

static int pi_try_set_control(struct pi_desc *pi_desc, u64 *pold, u64 new)
{
	/*
	if (!try_cmpxchg64(&pi_desc->control, pold, new))
		return -EBUSY;

	return 0;
}

void vmx_vcpu_pi_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct pi_desc old, new;
	unsigned long flags;
	unsigned int dest;

	/*
	if (!enable_apicv || !lapic_in_kernel(vcpu))
		return;

	/*
	if (pi_desc->nv != POSTED_INTR_WAKEUP_VECTOR && vcpu->cpu == cpu) {
		/*
		if (pi_test_and_clear_sn(pi_desc))
			goto after_clear_sn;
		return;
	}

	local_irq_save(flags);

	/*
	if (pi_desc->nv == POSTED_INTR_WAKEUP_VECTOR) {
		raw_spin_lock(&per_cpu(wakeup_vcpus_on_cpu_lock, vcpu->cpu));
		list_del(&vmx->pi_wakeup_list);
		raw_spin_unlock(&per_cpu(wakeup_vcpus_on_cpu_lock, vcpu->cpu));
	}

	dest = cpu_physical_id(cpu);
	if (!x2apic_mode)
		dest = (dest << 8) & 0xFF00;

	old.control = READ_ONCE(pi_desc->control);
	do {
		new.control = old.control;

		/*
		new.ndst = dest;
		new.sn = 0;

		/*
		new.nv = POSTED_INTR_VECTOR;
	} while (pi_try_set_control(pi_desc, &old.control, new.control));

	local_irq_restore(flags);

after_clear_sn:

	/*
	smp_mb__after_atomic();

	if (!pi_is_pir_empty(pi_desc))
		pi_set_on(pi_desc);
}

static bool vmx_can_use_vtd_pi(struct kvm *kvm)
{
	return irqchip_in_kernel(kvm) && enable_apicv &&
		kvm_arch_has_assigned_device(kvm) &&
		irq_remapping_cap(IRQ_POSTING_CAP);
}

static void pi_enable_wakeup_handler(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct pi_desc old, new;
	unsigned long flags;

	local_irq_save(flags);

	raw_spin_lock(&per_cpu(wakeup_vcpus_on_cpu_lock, vcpu->cpu));
	list_add_tail(&vmx->pi_wakeup_list,
		      &per_cpu(wakeup_vcpus_on_cpu, vcpu->cpu));
	raw_spin_unlock(&per_cpu(wakeup_vcpus_on_cpu_lock, vcpu->cpu));

	WARN(pi_desc->sn, "PI descriptor SN field set before blocking");

	old.control = READ_ONCE(pi_desc->control);
	do {
		/* set 'NV' to 'wakeup vector' */
		new.control = old.control;
		new.nv = POSTED_INTR_WAKEUP_VECTOR;
	} while (pi_try_set_control(pi_desc, &old.control, new.control));

	/*
	if (pi_test_on(&new))
		apic->send_IPI_self(POSTED_INTR_WAKEUP_VECTOR);

	local_irq_restore(flags);
}

static bool vmx_needs_pi_wakeup(struct kvm_vcpu *vcpu)
{
	/*
	return vmx_can_use_ipiv(vcpu) || vmx_can_use_vtd_pi(vcpu->kvm);
}

void vmx_vcpu_pi_put(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

	if (!vmx_needs_pi_wakeup(vcpu))
		return;

	if (kvm_vcpu_is_blocking(vcpu) && !vmx_interrupt_blocked(vcpu))
		pi_enable_wakeup_handler(vcpu);

	/*
	if (vcpu->preempted)
		pi_set_sn(pi_desc);
}

void pi_wakeup_handler(void)
{
	int cpu = smp_processor_id();
	struct list_head *wakeup_list = &per_cpu(wakeup_vcpus_on_cpu, cpu);
	raw_spinlock_t *spinlock = &per_cpu(wakeup_vcpus_on_cpu_lock, cpu);
	struct vcpu_vmx *vmx;

	raw_spin_lock(spinlock);
	list_for_each_entry(vmx, wakeup_list, pi_wakeup_list) {

		if (pi_test_on(&vmx->pi_desc))
			kvm_vcpu_wake_up(&vmx->vcpu);
	}
	raw_spin_unlock(spinlock);
}

void __init pi_init_cpu(int cpu)
{
	INIT_LIST_HEAD(&per_cpu(wakeup_vcpus_on_cpu, cpu));
	raw_spin_lock_init(&per_cpu(wakeup_vcpus_on_cpu_lock, cpu));
}

bool pi_has_pending_interrupt(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

	return pi_test_on(pi_desc) ||
		(pi_test_sn(pi_desc) && !pi_is_pir_empty(pi_desc));
}


void vmx_pi_start_assignment(struct kvm *kvm)
{
	if (!irq_remapping_cap(IRQ_POSTING_CAP))
		return;

	kvm_make_all_cpus_request(kvm, KVM_REQ_UNBLOCK);
}

int vmx_pi_update_irte(struct kvm *kvm, unsigned int host_irq,
		       uint32_t guest_irq, bool set)
{
	struct kvm_kernel_irq_routing_entry *e;
	struct kvm_irq_routing_table *irq_rt;
	struct kvm_lapic_irq irq;
	struct kvm_vcpu *vcpu;
	struct vcpu_data vcpu_info;
	int idx, ret = 0;

	if (!vmx_can_use_vtd_pi(kvm))
		return 0;

	idx = srcu_read_lock(&kvm->irq_srcu);
	irq_rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
	if (guest_irq >= irq_rt->nr_rt_entries ||
	    hlist_empty(&irq_rt->map[guest_irq])) {
		pr_warn_once("no route for guest_irq %u/%u (broken user space?)\n",
			     guest_irq, irq_rt->nr_rt_entries);
		goto out;
	}

	hlist_for_each_entry(e, &irq_rt->map[guest_irq], link) {
		if (e->type != KVM_IRQ_ROUTING_MSI)
			continue;
		/*

		kvm_set_msi_irq(kvm, e, &irq);
		if (!kvm_intr_is_single_vcpu(kvm, &irq, &vcpu) ||
		    !kvm_irq_is_postable(&irq)) {
			/*
			ret = irq_set_vcpu_affinity(host_irq, NULL);
			if (ret < 0) {
				printk(KERN_INFO
				   "failed to back to remapped mode, irq: %u\n",
				   host_irq);
				goto out;
			}

			continue;
		}

		vcpu_info.pi_desc_addr = __pa(vcpu_to_pi_desc(vcpu));
		vcpu_info.vector = irq.vector;

		trace_kvm_pi_irte_update(host_irq, vcpu->vcpu_id, e->gsi,
				vcpu_info.vector, vcpu_info.pi_desc_addr, set);

		if (set)
			ret = irq_set_vcpu_affinity(host_irq, &vcpu_info);
		else
			ret = irq_set_vcpu_affinity(host_irq, NULL);

		if (ret < 0) {
			printk(KERN_INFO "%s: failed to update PI IRTE\n",
					__func__);
			goto out;
		}
	}

	ret = 0;
out:
	srcu_read_unlock(&kvm->irq_srcu, idx);
	return ret;
}
