
#ifndef __XEN_PUBLIC_ARCH_X86_CPUID_H__
#define __XEN_PUBLIC_ARCH_X86_CPUID_H__


#define XEN_CPUID_FIRST_LEAF 0x40000000
#define XEN_CPUID_LEAF(i)    (XEN_CPUID_FIRST_LEAF + (i))

#define XEN_CPUID_SIGNATURE_EBX 0x566e6558 /* "XenV" */
#define XEN_CPUID_SIGNATURE_ECX 0x65584d4d /* "MMXe" */
#define XEN_CPUID_SIGNATURE_EDX 0x4d4d566e /* "nVMM" */



#define _XEN_CPUID_FEAT1_MMU_PT_UPDATE_PRESERVE_AD 0
#define XEN_CPUID_FEAT1_MMU_PT_UPDATE_PRESERVE_AD  (1u<<0)


#define XEN_HVM_CPUID_APIC_ACCESS_VIRT (1u << 0) /* Virtualized APIC registers */
#define XEN_HVM_CPUID_X2APIC_VIRT      (1u << 1) /* Virtualized x2APIC accesses */
#define XEN_HVM_CPUID_IOMMU_MAPPINGS   (1u << 2)
#define XEN_HVM_CPUID_VCPU_ID_PRESENT  (1u << 3) /* vcpu id is present in EBX */
#define XEN_HVM_CPUID_DOMID_PRESENT    (1u << 4) /* domid is present in ECX */
#define XEN_HVM_CPUID_EXT_DEST_ID      (1u << 5)


#define XEN_CPUID_MACHINE_ADDRESS_WIDTH_MASK (0xffu << 0)

#define XEN_CPUID_MAX_NUM_LEAVES 5

#endif /* __XEN_PUBLIC_ARCH_X86_CPUID_H__ */
