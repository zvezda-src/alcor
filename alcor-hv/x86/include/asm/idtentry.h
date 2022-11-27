#ifndef _ASM_X86_IDTENTRY_H
#define _ASM_X86_IDTENTRY_H

#include <asm/trapnr.h>

#define IDT_ALIGN	(8 * (1 + HAS_KERNEL_IBT))

#ifndef __ASSEMBLY__
#include <linux/entry-common.h>
#include <linux/hardirq.h>

#include <asm/irq_stack.h>

#define DECLARE_IDTENTRY(vector, func)					\
	asmlinkage void asm_##func(void);				\
	asmlinkage void xen_asm_##func(void);				\
	__visible void func(struct pt_regs *regs)

#define DEFINE_IDTENTRY(func)						\
static __always_inline void __##func(struct pt_regs *regs);		\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
									\
	instrumentation_begin();					\
	__##func (regs);						\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static __always_inline void __##func(struct pt_regs *regs)

#define DECLARE_IDTENTRY_SW	DECLARE_IDTENTRY
#define DEFINE_IDTENTRY_SW	DEFINE_IDTENTRY

#define DECLARE_IDTENTRY_ERRORCODE(vector, func)			\
	asmlinkage void asm_##func(void);				\
	asmlinkage void xen_asm_##func(void);				\
	__visible void func(struct pt_regs *regs, unsigned long error_code)

#define DEFINE_IDTENTRY_ERRORCODE(func)					\
static __always_inline void __##func(struct pt_regs *regs,		\
				     unsigned long error_code);		\
									\
__visible noinstr void func(struct pt_regs *regs,			\
			    unsigned long error_code)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
									\
	instrumentation_begin();					\
	__##func (regs, error_code);					\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static __always_inline void __##func(struct pt_regs *regs,		\
				     unsigned long error_code)

#define DECLARE_IDTENTRY_RAW(vector, func)				\
	DECLARE_IDTENTRY(vector, func)

#define DEFINE_IDTENTRY_RAW(func)					\
__visible noinstr void func(struct pt_regs *regs)

#define DECLARE_IDTENTRY_RAW_ERRORCODE(vector, func)			\
	DECLARE_IDTENTRY_ERRORCODE(vector, func)

#define DEFINE_IDTENTRY_RAW_ERRORCODE(func)				\
__visible noinstr void func(struct pt_regs *regs, unsigned long error_code)

#define DECLARE_IDTENTRY_IRQ(vector, func)				\
	DECLARE_IDTENTRY_ERRORCODE(vector, func)

#define DEFINE_IDTENTRY_IRQ(func)					\
static void __##func(struct pt_regs *regs, u32 vector);			\
									\
__visible noinstr void func(struct pt_regs *regs,			\
			    unsigned long error_code)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
	u32 vector = (u32)(u8)error_code;				\
									\
	instrumentation_begin();					\
	kvm_set_cpu_l1tf_flush_l1d();					\
	run_irq_on_irqstack_cond(__##func, regs, vector);		\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static noinline void __##func(struct pt_regs *regs, u32 vector)

#define DECLARE_IDTENTRY_SYSVEC(vector, func)				\
	DECLARE_IDTENTRY(vector, func)

#define DEFINE_IDTENTRY_SYSVEC(func)					\
static void __##func(struct pt_regs *regs);				\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
									\
	instrumentation_begin();					\
	kvm_set_cpu_l1tf_flush_l1d();					\
	run_sysvec_on_irqstack_cond(__##func, regs);			\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static noinline void __##func(struct pt_regs *regs)

#define DEFINE_IDTENTRY_SYSVEC_SIMPLE(func)				\
static __always_inline void __##func(struct pt_regs *regs);		\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
									\
	instrumentation_begin();					\
	__irq_enter_raw();						\
	kvm_set_cpu_l1tf_flush_l1d();					\
	__##func (regs);						\
	__irq_exit_raw();						\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static __always_inline void __##func(struct pt_regs *regs)

#define DECLARE_IDTENTRY_XENCB(vector, func)				\
	DECLARE_IDTENTRY(vector, func)

#ifdef CONFIG_X86_64
#define DECLARE_IDTENTRY_IST(vector, func)				\
	DECLARE_IDTENTRY_RAW(vector, func);				\
	__visible void noist_##func(struct pt_regs *regs)

#define DECLARE_IDTENTRY_VC(vector, func)				\
	DECLARE_IDTENTRY_RAW_ERRORCODE(vector, func);			\
	__visible noinstr void kernel_##func(struct pt_regs *regs, unsigned long error_code);	\
	__visible noinstr void   user_##func(struct pt_regs *regs, unsigned long error_code)

#define DEFINE_IDTENTRY_IST(func)					\
	DEFINE_IDTENTRY_RAW(func)

#define DEFINE_IDTENTRY_NOIST(func)					\
	DEFINE_IDTENTRY_RAW(noist_##func)

#define DECLARE_IDTENTRY_DF(vector, func)				\
	DECLARE_IDTENTRY_RAW_ERRORCODE(vector, func)

#define DEFINE_IDTENTRY_DF(func)					\
	DEFINE_IDTENTRY_RAW_ERRORCODE(func)

			       when raised from kernel mode
#define DEFINE_IDTENTRY_VC_KERNEL(func)				\
	DEFINE_IDTENTRY_RAW_ERRORCODE(kernel_##func)

			     when raised from user mode
#define DEFINE_IDTENTRY_VC_USER(func)				\
	DEFINE_IDTENTRY_RAW_ERRORCODE(user_##func)

#else	/* CONFIG_X86_64 */

#define DECLARE_IDTENTRY_DF(vector, func)				\
	asmlinkage void asm_##func(void);				\
	__visible void func(struct pt_regs *regs,			\
			    unsigned long error_code,			\
			    unsigned long address)

#define DEFINE_IDTENTRY_DF(func)					\
__visible noinstr void func(struct pt_regs *regs,			\
			    unsigned long error_code,			\
			    unsigned long address)

#endif	/* !CONFIG_X86_64 */

#define DECLARE_IDTENTRY_NMI		DECLARE_IDTENTRY_RAW
#define DEFINE_IDTENTRY_NMI		DEFINE_IDTENTRY_RAW

#ifdef CONFIG_X86_64
#define DECLARE_IDTENTRY_MCE		DECLARE_IDTENTRY_IST
#define DEFINE_IDTENTRY_MCE		DEFINE_IDTENTRY_IST
#define DEFINE_IDTENTRY_MCE_USER	DEFINE_IDTENTRY_NOIST

#define DECLARE_IDTENTRY_DEBUG		DECLARE_IDTENTRY_IST
#define DEFINE_IDTENTRY_DEBUG		DEFINE_IDTENTRY_IST
#define DEFINE_IDTENTRY_DEBUG_USER	DEFINE_IDTENTRY_NOIST
#endif

#else /* !__ASSEMBLY__ */

#define DECLARE_IDTENTRY(vector, func)					\
	idtentry vector asm_##func func has_error_code=0

#define DECLARE_IDTENTRY_ERRORCODE(vector, func)			\
	idtentry vector asm_##func func has_error_code=1

#define DECLARE_IDTENTRY_SW(vector, func)

#define DECLARE_IDTENTRY_RAW(vector, func)				\
	DECLARE_IDTENTRY(vector, func)

#define DECLARE_IDTENTRY_RAW_ERRORCODE(vector, func)			\
	DECLARE_IDTENTRY_ERRORCODE(vector, func)

#define DECLARE_IDTENTRY_IRQ(vector, func)				\
	idtentry_irq vector func

#define DECLARE_IDTENTRY_SYSVEC(vector, func)				\
	idtentry_sysvec vector func

#ifdef CONFIG_X86_64
# define DECLARE_IDTENTRY_MCE(vector, func)				\
	idtentry_mce_db vector asm_##func func

# define DECLARE_IDTENTRY_DEBUG(vector, func)				\
	idtentry_mce_db vector asm_##func func

# define DECLARE_IDTENTRY_DF(vector, func)				\
	idtentry_df vector asm_##func func

# define DECLARE_IDTENTRY_XENCB(vector, func)				\
	DECLARE_IDTENTRY(vector, func)

# define DECLARE_IDTENTRY_VC(vector, func)				\
	idtentry_vc vector asm_##func func

#else
# define DECLARE_IDTENTRY_MCE(vector, func)				\
	DECLARE_IDTENTRY(vector, func)

# define DECLARE_IDTENTRY_DF(vector, func)

# define DECLARE_IDTENTRY_XENCB(vector, func)

#endif

#define DECLARE_IDTENTRY_NMI(vector, func)

	.align IDT_ALIGN
SYM_CODE_START(irq_entries_start)
    vector=FIRST_EXTERNAL_VECTOR
    .rept NR_EXTERNAL_VECTORS
	UNWIND_HINT_IRET_REGS
0 :
	ENDBR
	.byte	0x6a, vector
	jmp	asm_common_interrupt
	/* Ensure that the above is IDT_ALIGN bytes max */
	.fill 0b + IDT_ALIGN - ., 1, 0xcc
	vector = vector+1
    .endr
SYM_CODE_END(irq_entries_start)

#ifdef CONFIG_X86_LOCAL_APIC
	.align IDT_ALIGN
SYM_CODE_START(spurious_entries_start)
    vector=FIRST_SYSTEM_VECTOR
    .rept NR_SYSTEM_VECTORS
	UNWIND_HINT_IRET_REGS
0 :
	ENDBR
	.byte	0x6a, vector
	jmp	asm_spurious_interrupt
	/* Ensure that the above is IDT_ALIGN bytes max */
	.fill 0b + IDT_ALIGN - ., 1, 0xcc
	vector = vector+1
    .endr
SYM_CODE_END(spurious_entries_start)
#endif

#endif /* __ASSEMBLY__ */


#define X86_TRAP_OTHER		0xFFFF

DECLARE_IDTENTRY(X86_TRAP_DE,		exc_divide_error);
DECLARE_IDTENTRY(X86_TRAP_OF,		exc_overflow);
DECLARE_IDTENTRY(X86_TRAP_BR,		exc_bounds);
DECLARE_IDTENTRY(X86_TRAP_NM,		exc_device_not_available);
DECLARE_IDTENTRY(X86_TRAP_OLD_MF,	exc_coproc_segment_overrun);
DECLARE_IDTENTRY(X86_TRAP_SPURIOUS,	exc_spurious_interrupt_bug);
DECLARE_IDTENTRY(X86_TRAP_MF,		exc_coprocessor_error);
DECLARE_IDTENTRY(X86_TRAP_XF,		exc_simd_coprocessor_error);

DECLARE_IDTENTRY_SW(X86_TRAP_IRET,	iret_error);

DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_TS,	exc_invalid_tss);
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_NP,	exc_segment_not_present);
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_SS,	exc_stack_segment);
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_GP,	exc_general_protection);
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_AC,	exc_alignment_check);

DECLARE_IDTENTRY_RAW(X86_TRAP_UD,		exc_invalid_op);
DECLARE_IDTENTRY_RAW(X86_TRAP_BP,		exc_int3);
DECLARE_IDTENTRY_RAW_ERRORCODE(X86_TRAP_PF,	exc_page_fault);

#ifdef CONFIG_X86_MCE
#ifdef CONFIG_X86_64
DECLARE_IDTENTRY_MCE(X86_TRAP_MC,	exc_machine_check);
#else
DECLARE_IDTENTRY_RAW(X86_TRAP_MC,	exc_machine_check);
#endif
#ifdef CONFIG_XEN_PV
DECLARE_IDTENTRY_RAW(X86_TRAP_MC,	xenpv_exc_machine_check);
#endif
#endif


#if defined(CONFIG_X86_64) && IS_ENABLED(CONFIG_KVM_INTEL)
DECLARE_IDTENTRY(X86_TRAP_NMI,		exc_nmi_noist);
#else
#define asm_exc_nmi_noist		asm_exc_nmi
#endif

DECLARE_IDTENTRY_NMI(X86_TRAP_NMI,	exc_nmi);
#ifdef CONFIG_XEN_PV
DECLARE_IDTENTRY_RAW(X86_TRAP_NMI,	xenpv_exc_nmi);
#endif

#ifdef CONFIG_X86_64
DECLARE_IDTENTRY_DEBUG(X86_TRAP_DB,	exc_debug);
#else
DECLARE_IDTENTRY_RAW(X86_TRAP_DB,	exc_debug);
#endif
#ifdef CONFIG_XEN_PV
DECLARE_IDTENTRY_RAW(X86_TRAP_DB,	xenpv_exc_debug);
#endif

DECLARE_IDTENTRY_DF(X86_TRAP_DF,	exc_double_fault);
#ifdef CONFIG_XEN_PV
DECLARE_IDTENTRY_RAW_ERRORCODE(X86_TRAP_DF,	xenpv_exc_double_fault);
#endif

#ifdef CONFIG_X86_KERNEL_IBT
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_CP,	exc_control_protection);
#endif

#ifdef CONFIG_AMD_MEM_ENCRYPT
DECLARE_IDTENTRY_VC(X86_TRAP_VC,	exc_vmm_communication);
#endif

#ifdef CONFIG_XEN_PV
DECLARE_IDTENTRY_XENCB(X86_TRAP_OTHER,	exc_xen_hypervisor_callback);
DECLARE_IDTENTRY_RAW(X86_TRAP_OTHER,	exc_xen_unknown_trap);
#endif

#ifdef CONFIG_INTEL_TDX_GUEST
DECLARE_IDTENTRY(X86_TRAP_VE,		exc_virtualization_exception);
#endif

DECLARE_IDTENTRY_IRQ(X86_TRAP_OTHER,	common_interrupt);
#ifdef CONFIG_X86_LOCAL_APIC
DECLARE_IDTENTRY_IRQ(X86_TRAP_OTHER,	spurious_interrupt);
#endif

#ifdef CONFIG_X86_LOCAL_APIC
DECLARE_IDTENTRY_SYSVEC(ERROR_APIC_VECTOR,		sysvec_error_interrupt);
DECLARE_IDTENTRY_SYSVEC(SPURIOUS_APIC_VECTOR,		sysvec_spurious_apic_interrupt);
DECLARE_IDTENTRY_SYSVEC(LOCAL_TIMER_VECTOR,		sysvec_apic_timer_interrupt);
DECLARE_IDTENTRY_SYSVEC(X86_PLATFORM_IPI_VECTOR,	sysvec_x86_platform_ipi);
#endif

#ifdef CONFIG_SMP
DECLARE_IDTENTRY(RESCHEDULE_VECTOR,			sysvec_reschedule_ipi);
DECLARE_IDTENTRY_SYSVEC(IRQ_MOVE_CLEANUP_VECTOR,	sysvec_irq_move_cleanup);
DECLARE_IDTENTRY_SYSVEC(REBOOT_VECTOR,			sysvec_reboot);
DECLARE_IDTENTRY_SYSVEC(CALL_FUNCTION_SINGLE_VECTOR,	sysvec_call_function_single);
DECLARE_IDTENTRY_SYSVEC(CALL_FUNCTION_VECTOR,		sysvec_call_function);
#endif

#ifdef CONFIG_X86_LOCAL_APIC
# ifdef CONFIG_X86_MCE_THRESHOLD
DECLARE_IDTENTRY_SYSVEC(THRESHOLD_APIC_VECTOR,		sysvec_threshold);
# endif

# ifdef CONFIG_X86_MCE_AMD
DECLARE_IDTENTRY_SYSVEC(DEFERRED_ERROR_VECTOR,		sysvec_deferred_error);
# endif

# ifdef CONFIG_X86_THERMAL_VECTOR
DECLARE_IDTENTRY_SYSVEC(THERMAL_APIC_VECTOR,		sysvec_thermal);
# endif

# ifdef CONFIG_IRQ_WORK
DECLARE_IDTENTRY_SYSVEC(IRQ_WORK_VECTOR,		sysvec_irq_work);
# endif
#endif

#ifdef CONFIG_HAVE_KVM
DECLARE_IDTENTRY_SYSVEC(POSTED_INTR_VECTOR,		sysvec_kvm_posted_intr_ipi);
DECLARE_IDTENTRY_SYSVEC(POSTED_INTR_WAKEUP_VECTOR,	sysvec_kvm_posted_intr_wakeup_ipi);
DECLARE_IDTENTRY_SYSVEC(POSTED_INTR_NESTED_VECTOR,	sysvec_kvm_posted_intr_nested_ipi);
#endif

#if IS_ENABLED(CONFIG_HYPERV)
DECLARE_IDTENTRY_SYSVEC(HYPERVISOR_CALLBACK_VECTOR,	sysvec_hyperv_callback);
DECLARE_IDTENTRY_SYSVEC(HYPERV_REENLIGHTENMENT_VECTOR,	sysvec_hyperv_reenlightenment);
DECLARE_IDTENTRY_SYSVEC(HYPERV_STIMER0_VECTOR,	sysvec_hyperv_stimer0);
#endif

#if IS_ENABLED(CONFIG_ACRN_GUEST)
DECLARE_IDTENTRY_SYSVEC(HYPERVISOR_CALLBACK_VECTOR,	sysvec_acrn_hv_callback);
#endif

#ifdef CONFIG_XEN_PVHVM
DECLARE_IDTENTRY_SYSVEC(HYPERVISOR_CALLBACK_VECTOR,	sysvec_xen_hvm_callback);
#endif

#ifdef CONFIG_KVM_GUEST
DECLARE_IDTENTRY_SYSVEC(HYPERVISOR_CALLBACK_VECTOR,	sysvec_kvm_asyncpf_interrupt);
#endif

#undef X86_TRAP_OTHER

#endif
