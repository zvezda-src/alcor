#ifndef _ASM_X86_XEN_EVENTS_H
#define _ASM_X86_XEN_EVENTS_H

#include <xen/xen.h>

enum ipi_vector {
	XEN_RESCHEDULE_VECTOR,
	XEN_CALL_FUNCTION_VECTOR,
	XEN_CALL_FUNCTION_SINGLE_VECTOR,
	XEN_SPIN_UNLOCK_VECTOR,
	XEN_IRQ_WORK_VECTOR,
	XEN_NMI_VECTOR,

	XEN_NR_IPIS,
};

static inline int xen_irqs_disabled(struct pt_regs *regs)
{
	return raw_irqs_disabled_flags(regs->flags);
}

#define xchg_xen_ulong(ptr, val) xchg((ptr), (val))

extern int xen_have_vector_callback;

static inline bool xen_support_evtchn_rebind(void)
{
	return (!xen_hvm_domain() || xen_have_vector_callback);
}

#endif /* _ASM_X86_XEN_EVENTS_H */
