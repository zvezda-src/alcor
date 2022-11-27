
#ifndef __ARCH_X86_KVM_SVM_HYPERV_H__
#define __ARCH_X86_KVM_SVM_HYPERV_H__

#include <asm/mshyperv.h>

#include "../hyperv.h"

struct hv_enlightenments {
	struct __packed hv_enlightenments_control {
		u32 nested_flush_hypercall:1;
		u32 msr_bitmap:1;
		u32 enlightened_npt_tlb: 1;
		u32 reserved:29;
	} __packed hv_enlightenments_control;
	u32 hv_vp_id;
	u64 hv_vm_id;
	u64 partition_assist_page;
	u64 reserved;
} __packed;

#define VMCB_HV_NESTED_ENLIGHTENMENTS VMCB_SW

#endif /* __ARCH_X86_KVM_SVM_HYPERV_H__ */
