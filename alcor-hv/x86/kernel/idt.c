#include <linux/interrupt.h>

#include <asm/cpu_entry_area.h>
#include <asm/set_memory.h>
#include <asm/traps.h>
#include <asm/proto.h>
#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <asm/idtentry.h>

#define DPL0		0x0
#define DPL3		0x3

#define DEFAULT_STACK	0

#define G(_vector, _addr, _ist, _type, _dpl, _segment)	\
	{						\
		.vector		= _vector,		\
		.bits.ist	= _ist,			\
		.bits.type	= _type,		\
		.bits.dpl	= _dpl,			\
		.bits.p		= 1,			\
		.addr		= _addr,		\
		.segment	= _segment,		\
	}

#define INTG(_vector, _addr)				\
	G(_vector, _addr, DEFAULT_STACK, GATE_INTERRUPT, DPL0, __KERNEL_CS)

#define SYSG(_vector, _addr)				\
	G(_vector, _addr, DEFAULT_STACK, GATE_INTERRUPT, DPL3, __KERNEL_CS)

#ifdef CONFIG_X86_64
#define ISTG(_vector, _addr, _ist)			\
	G(_vector, _addr, _ist + 1, GATE_INTERRUPT, DPL0, __KERNEL_CS)
#else
#define ISTG(_vector, _addr, _ist)	INTG(_vector, _addr)
#endif

#define TSKG(_vector, _gdt)				\
	G(_vector, NULL, DEFAULT_STACK, GATE_TASK, DPL0, _gdt << 3)

#define IDT_TABLE_SIZE		(IDT_ENTRIES * sizeof(gate_desc))

static bool idt_setup_done __initdata;

static const __initconst struct idt_data early_idts[] = {
	INTG(X86_TRAP_DB,		asm_exc_debug),
	SYSG(X86_TRAP_BP,		asm_exc_int3),

#ifdef CONFIG_X86_32
	/*
	INTG(X86_TRAP_PF,		asm_exc_page_fault),
#endif
#ifdef CONFIG_INTEL_TDX_GUEST
	INTG(X86_TRAP_VE,		asm_exc_virtualization_exception),
#endif
};

static const __initconst struct idt_data def_idts[] = {
	INTG(X86_TRAP_DE,		asm_exc_divide_error),
	ISTG(X86_TRAP_NMI,		asm_exc_nmi, IST_INDEX_NMI),
	INTG(X86_TRAP_BR,		asm_exc_bounds),
	INTG(X86_TRAP_UD,		asm_exc_invalid_op),
	INTG(X86_TRAP_NM,		asm_exc_device_not_available),
	INTG(X86_TRAP_OLD_MF,		asm_exc_coproc_segment_overrun),
	INTG(X86_TRAP_TS,		asm_exc_invalid_tss),
	INTG(X86_TRAP_NP,		asm_exc_segment_not_present),
	INTG(X86_TRAP_SS,		asm_exc_stack_segment),
	INTG(X86_TRAP_GP,		asm_exc_general_protection),
	INTG(X86_TRAP_SPURIOUS,		asm_exc_spurious_interrupt_bug),
	INTG(X86_TRAP_MF,		asm_exc_coprocessor_error),
	INTG(X86_TRAP_AC,		asm_exc_alignment_check),
	INTG(X86_TRAP_XF,		asm_exc_simd_coprocessor_error),

#ifdef CONFIG_X86_32
	TSKG(X86_TRAP_DF,		GDT_ENTRY_DOUBLEFAULT_TSS),
#else
	ISTG(X86_TRAP_DF,		asm_exc_double_fault, IST_INDEX_DF),
#endif
	ISTG(X86_TRAP_DB,		asm_exc_debug, IST_INDEX_DB),

#ifdef CONFIG_X86_MCE
	ISTG(X86_TRAP_MC,		asm_exc_machine_check, IST_INDEX_MCE),
#endif

#ifdef CONFIG_X86_KERNEL_IBT
	INTG(X86_TRAP_CP,		asm_exc_control_protection),
#endif

#ifdef CONFIG_AMD_MEM_ENCRYPT
	ISTG(X86_TRAP_VC,		asm_exc_vmm_communication, IST_INDEX_VC),
#endif

	SYSG(X86_TRAP_OF,		asm_exc_overflow),
#if defined(CONFIG_IA32_EMULATION)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_compat),
#elif defined(CONFIG_X86_32)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_32),
#endif
};

static const __initconst struct idt_data apic_idts[] = {
#ifdef CONFIG_SMP
	INTG(RESCHEDULE_VECTOR,			asm_sysvec_reschedule_ipi),
	INTG(CALL_FUNCTION_VECTOR,		asm_sysvec_call_function),
	INTG(CALL_FUNCTION_SINGLE_VECTOR,	asm_sysvec_call_function_single),
	INTG(IRQ_MOVE_CLEANUP_VECTOR,		asm_sysvec_irq_move_cleanup),
	INTG(REBOOT_VECTOR,			asm_sysvec_reboot),
#endif

#ifdef CONFIG_X86_THERMAL_VECTOR
	INTG(THERMAL_APIC_VECTOR,		asm_sysvec_thermal),
#endif

#ifdef CONFIG_X86_MCE_THRESHOLD
	INTG(THRESHOLD_APIC_VECTOR,		asm_sysvec_threshold),
#endif

#ifdef CONFIG_X86_MCE_AMD
	INTG(DEFERRED_ERROR_VECTOR,		asm_sysvec_deferred_error),
#endif

#ifdef CONFIG_X86_LOCAL_APIC
	INTG(LOCAL_TIMER_VECTOR,		asm_sysvec_apic_timer_interrupt),
	INTG(X86_PLATFORM_IPI_VECTOR,		asm_sysvec_x86_platform_ipi),
# ifdef CONFIG_HAVE_KVM
	INTG(POSTED_INTR_VECTOR,		asm_sysvec_kvm_posted_intr_ipi),
	INTG(POSTED_INTR_WAKEUP_VECTOR,		asm_sysvec_kvm_posted_intr_wakeup_ipi),
	INTG(POSTED_INTR_NESTED_VECTOR,		asm_sysvec_kvm_posted_intr_nested_ipi),
# endif
# ifdef CONFIG_IRQ_WORK
	INTG(IRQ_WORK_VECTOR,			asm_sysvec_irq_work),
# endif
	INTG(SPURIOUS_APIC_VECTOR,		asm_sysvec_spurious_apic_interrupt),
	INTG(ERROR_APIC_VECTOR,			asm_sysvec_error_interrupt),
#endif
};

static gate_desc idt_table[IDT_ENTRIES] __page_aligned_bss;

static struct desc_ptr idt_descr __ro_after_init = {
	.size		= IDT_TABLE_SIZE - 1,
	.address	= (unsigned long) idt_table,
};

void load_current_idt(void)
{
	lockdep_assert_irqs_disabled();
	load_idt(&idt_descr);
}

#ifdef CONFIG_X86_F00F_BUG
bool idt_is_f00f_address(unsigned long address)
{
	return ((address - idt_descr.address) >> 3) == 6;
}
#endif

static __init void
idt_setup_from_table(gate_desc *idt, const struct idt_data *t, int size, bool sys)
{
	gate_desc desc;

	for (; size > 0; t++, size--) {
		idt_init_desc(&desc, t);
		write_idt_entry(idt, t->vector, &desc);
		if (sys)
			set_bit(t->vector, system_vectors);
	}
}

static __init void set_intr_gate(unsigned int n, const void *addr)
{
	struct idt_data data;

	init_idt_data(&data, n, addr);

	idt_setup_from_table(idt_table, &data, 1, false);
}

void __init idt_setup_early_traps(void)
{
	idt_setup_from_table(idt_table, early_idts, ARRAY_SIZE(early_idts),
			     true);
	load_idt(&idt_descr);
}

void __init idt_setup_traps(void)
{
	idt_setup_from_table(idt_table, def_idts, ARRAY_SIZE(def_idts), true);
}

#ifdef CONFIG_X86_64
static const __initconst struct idt_data early_pf_idts[] = {
	INTG(X86_TRAP_PF,		asm_exc_page_fault),
};

void __init idt_setup_early_pf(void)
{
	idt_setup_from_table(idt_table, early_pf_idts,
			     ARRAY_SIZE(early_pf_idts), true);
}
#endif

static void __init idt_map_in_cea(void)
{
	/*
	cea_set_pte(CPU_ENTRY_AREA_RO_IDT_VADDR, __pa_symbol(idt_table),
		    PAGE_KERNEL_RO);
	idt_descr.address = CPU_ENTRY_AREA_RO_IDT;
}

void __init idt_setup_apic_and_irq_gates(void)
{
	int i = FIRST_EXTERNAL_VECTOR;
	void *entry;

	idt_setup_from_table(idt_table, apic_idts, ARRAY_SIZE(apic_idts), true);

	for_each_clear_bit_from(i, system_vectors, FIRST_SYSTEM_VECTOR) {
		entry = irq_entries_start + IDT_ALIGN * (i - FIRST_EXTERNAL_VECTOR);
		set_intr_gate(i, entry);
	}

#ifdef CONFIG_X86_LOCAL_APIC
	for_each_clear_bit_from(i, system_vectors, NR_VECTORS) {
		/*
		entry = spurious_entries_start + IDT_ALIGN * (i - FIRST_SYSTEM_VECTOR);
		set_intr_gate(i, entry);
	}
#endif
	/* Map IDT into CPU entry area and reload it. */
	idt_map_in_cea();
	load_idt(&idt_descr);

	/* Make the IDT table read only */
	set_memory_ro((unsigned long)&idt_table, 1);

	idt_setup_done = true;
}

void __init idt_setup_early_handler(void)
{
	int i;

	for (i = 0; i < NUM_EXCEPTION_VECTORS; i++)
		set_intr_gate(i, early_idt_handler_array[i]);
#ifdef CONFIG_X86_32
	for ( ; i < NR_VECTORS; i++)
		set_intr_gate(i, early_ignore_irq);
#endif
	load_idt(&idt_descr);
}

void idt_invalidate(void)
{
	static const struct desc_ptr idt = { .address = 0, .size = 0 };

	load_idt(&idt);
}

void __init alloc_intr_gate(unsigned int n, const void *addr)
{
	if (WARN_ON(n < FIRST_SYSTEM_VECTOR))
		return;

	if (WARN_ON(idt_setup_done))
		return;

	if (!WARN_ON(test_and_set_bit(n, system_vectors)))
		set_intr_gate(n, addr);
}
