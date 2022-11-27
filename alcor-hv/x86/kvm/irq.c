
#include <linux/export.h>
#include <linux/kvm_host.h>

#include "irq.h"
#include "i8254.h"
#include "x86.h"
#include "xen.h"

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	int r = 0;

	if (lapic_in_kernel(vcpu))
		r = apic_has_pending_timer(vcpu);
	if (kvm_xen_timer_enabled(vcpu))
		r += kvm_xen_has_pending_timer(vcpu);

	return r;
}
EXPORT_SYMBOL(kvm_cpu_has_pending_timer);

static int pending_userspace_extint(struct kvm_vcpu *v)
{
	return v->arch.pending_external_vector != -1;
}

int kvm_cpu_has_extint(struct kvm_vcpu *v)
{
	/*
	if (!lapic_in_kernel(v))
		return v->arch.interrupt.injected;

	if (kvm_xen_has_interrupt(v))
		return 1;

	if (!kvm_apic_accept_pic_intr(v))
		return 0;

	if (irqchip_split(v->kvm))
		return pending_userspace_extint(v);
	else
		return v->kvm->arch.vpic->output;
}

int kvm_cpu_has_injectable_intr(struct kvm_vcpu *v)
{
	if (kvm_cpu_has_extint(v))
		return 1;

	if (!is_guest_mode(v) && kvm_vcpu_apicv_active(v))
		return 0;

	return kvm_apic_has_interrupt(v) != -1; /* LAPIC */
}
EXPORT_SYMBOL_GPL(kvm_cpu_has_injectable_intr);

int kvm_cpu_has_interrupt(struct kvm_vcpu *v)
{
	if (kvm_cpu_has_extint(v))
		return 1;

	return kvm_apic_has_interrupt(v) != -1;	/* LAPIC */
}
EXPORT_SYMBOL_GPL(kvm_cpu_has_interrupt);

static int kvm_cpu_get_extint(struct kvm_vcpu *v)
{
	if (!kvm_cpu_has_extint(v)) {
		WARN_ON(!lapic_in_kernel(v));
		return -1;
	}

	if (!lapic_in_kernel(v))
		return v->arch.interrupt.nr;

	if (kvm_xen_has_interrupt(v))
		return v->kvm->arch.xen.upcall_vector;

	if (irqchip_split(v->kvm)) {
		int vector = v->arch.pending_external_vector;

		v->arch.pending_external_vector = -1;
		return vector;
	} else
		return kvm_pic_read_irq(v->kvm); /* PIC */
}

int kvm_cpu_get_interrupt(struct kvm_vcpu *v)
{
	int vector = kvm_cpu_get_extint(v);
	if (vector != -1)
		return vector;			/* PIC */

	return kvm_get_apic_interrupt(v);	/* APIC */
}
EXPORT_SYMBOL_GPL(kvm_cpu_get_interrupt);

void kvm_inject_pending_timer_irqs(struct kvm_vcpu *vcpu)
{
	if (lapic_in_kernel(vcpu))
		kvm_inject_apic_timer_irqs(vcpu);
	if (kvm_xen_timer_enabled(vcpu))
		kvm_xen_inject_timer_irqs(vcpu);
}
EXPORT_SYMBOL_GPL(kvm_inject_pending_timer_irqs);

void __kvm_migrate_timers(struct kvm_vcpu *vcpu)
{
	__kvm_migrate_apic_timer(vcpu);
	__kvm_migrate_pit_timer(vcpu);
	static_call_cond(kvm_x86_migrate_timers)(vcpu);
}

bool kvm_arch_irqfd_allowed(struct kvm *kvm, struct kvm_irqfd *args)
{
	bool resample = args->flags & KVM_IRQFD_FLAG_RESAMPLE;

	return resample ? irqchip_kernel(kvm) : irqchip_in_kernel(kvm);
}
