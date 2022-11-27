#ifndef _ASM_X86_HYPERVISOR_H
#define _ASM_X86_HYPERVISOR_H

enum x86_hypervisor_type {
	X86_HYPER_NATIVE = 0,
	X86_HYPER_VMWARE,
	X86_HYPER_MS_HYPERV,
	X86_HYPER_XEN_PV,
	X86_HYPER_XEN_HVM,
	X86_HYPER_KVM,
	X86_HYPER_JAILHOUSE,
	X86_HYPER_ACRN,
};

#ifdef CONFIG_HYPERVISOR_GUEST

#include <asm/kvm_para.h>
#include <asm/x86_init.h>
#include <asm/xen/hypervisor.h>

struct hypervisor_x86 {
	/* Hypervisor name */
	const char	*name;

	/* Detection routine */
	uint32_t	(*detect)(void);

	/* Hypervisor type */
	enum x86_hypervisor_type type;

	/* init time callbacks */
	struct x86_hyper_init init;

	/* runtime callbacks */
	struct x86_hyper_runtime runtime;

	/* ignore nopv parameter */
	bool ignore_nopv;
};

extern const struct hypervisor_x86 x86_hyper_vmware;
extern const struct hypervisor_x86 x86_hyper_ms_hyperv;
extern const struct hypervisor_x86 x86_hyper_xen_pv;
extern const struct hypervisor_x86 x86_hyper_kvm;
extern const struct hypervisor_x86 x86_hyper_jailhouse;
extern const struct hypervisor_x86 x86_hyper_acrn;
extern struct hypervisor_x86 x86_hyper_xen_hvm;

extern bool nopv;
extern enum x86_hypervisor_type x86_hyper_type;
extern void init_hypervisor_platform(void);
static inline bool hypervisor_is_type(enum x86_hypervisor_type type)
{
	return x86_hyper_type == type;
}
#else
static inline void init_hypervisor_platform(void) { }
static inline bool hypervisor_is_type(enum x86_hypervisor_type type)
{
	return type == X86_HYPER_NATIVE;
}
#endif /* CONFIG_HYPERVISOR_GUEST */
#endif /* _ASM_X86_HYPERVISOR_H */
