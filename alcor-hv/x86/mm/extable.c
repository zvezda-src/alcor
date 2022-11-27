#include <linux/extable.h>
#include <linux/uaccess.h>
#include <linux/sched/debug.h>
#include <linux/bitfield.h>
#include <xen/xen.h>

#include <asm/fpu/api.h>
#include <asm/sev.h>
#include <asm/traps.h>
#include <asm/kdebug.h>
#include <asm/insn-eval.h>
#include <asm/sgx.h>

static inline unsigned long *pt_regs_nr(struct pt_regs *regs, int nr)
{
	int reg_offset = pt_regs_offset(regs, nr);
	static unsigned long __dummy;

	if (WARN_ON_ONCE(reg_offset < 0))
		return &__dummy;

	return (unsigned long *)((unsigned long)regs + reg_offset);
}

static inline unsigned long
ex_fixup_addr(const struct exception_table_entry *x)
{
	return (unsigned long)&x->fixup + x->fixup;
}

static bool ex_handler_default(const struct exception_table_entry *e,
			       struct pt_regs *regs)
{
	if (e->data & EX_FLAG_CLEAR_AX)
		regs->ax = 0;
	if (e->data & EX_FLAG_CLEAR_DX)
		regs->dx = 0;

	regs->ip = ex_fixup_addr(e);
	return true;
}

static bool ex_handler_fault(const struct exception_table_entry *fixup,
			     struct pt_regs *regs, int trapnr)
{
	regs->ax = trapnr;
	return ex_handler_default(fixup, regs);
}

static bool ex_handler_sgx(const struct exception_table_entry *fixup,
			   struct pt_regs *regs, int trapnr)
{
	regs->ax = trapnr | SGX_ENCLS_FAULT_FLAG;
	return ex_handler_default(fixup, regs);
}

static bool ex_handler_fprestore(const struct exception_table_entry *fixup,
				 struct pt_regs *regs)
{
	regs->ip = ex_fixup_addr(fixup);

	WARN_ONCE(1, "Bad FPU state detected at %pB, reinitializing FPU registers.",
		  (void *)instruction_pointer(regs));

	fpu_reset_from_exception_fixup();
	return true;
}

static bool ex_handler_uaccess(const struct exception_table_entry *fixup,
			       struct pt_regs *regs, int trapnr)
{
	WARN_ONCE(trapnr == X86_TRAP_GP, "General protection fault in user access. Non-canonical address?");
	return ex_handler_default(fixup, regs);
}

static bool ex_handler_copy(const struct exception_table_entry *fixup,
			    struct pt_regs *regs, int trapnr)
{
	WARN_ONCE(trapnr == X86_TRAP_GP, "General protection fault in user access. Non-canonical address?");
	return ex_handler_fault(fixup, regs, trapnr);
}

static bool ex_handler_msr(const struct exception_table_entry *fixup,
			   struct pt_regs *regs, bool wrmsr, bool safe, int reg)
{
	if (__ONCE_LITE_IF(!safe && wrmsr)) {
		pr_warn("unchecked MSR access error: WRMSR to 0x%x (tried to write 0x%08x%08x) at rIP: 0x%lx (%pS)\n",
			(unsigned int)regs->cx, (unsigned int)regs->dx,
			(unsigned int)regs->ax,  regs->ip, (void *)regs->ip);
		show_stack_regs(regs);
	}

	if (__ONCE_LITE_IF(!safe && !wrmsr)) {
		pr_warn("unchecked MSR access error: RDMSR from 0x%x at rIP: 0x%lx (%pS)\n",
			(unsigned int)regs->cx, regs->ip, (void *)regs->ip);
		show_stack_regs(regs);
	}

	if (!wrmsr) {
		/* Pretend that the read succeeded and returned 0. */
		regs->ax = 0;
		regs->dx = 0;
	}

	if (safe)
		*pt_regs_nr(regs, reg) = -EIO;

	return ex_handler_default(fixup, regs);
}

static bool ex_handler_clear_fs(const struct exception_table_entry *fixup,
				struct pt_regs *regs)
{
	if (static_cpu_has(X86_BUG_NULL_SEG))
		asm volatile ("mov %0, %%fs" : : "rm" (__USER_DS));
	asm volatile ("mov %0, %%fs" : : "rm" (0));
	return ex_handler_default(fixup, regs);
}

static bool ex_handler_imm_reg(const struct exception_table_entry *fixup,
			       struct pt_regs *regs, int reg, int imm)
{
	return ex_handler_default(fixup, regs);
}

static bool ex_handler_ucopy_len(const struct exception_table_entry *fixup,
				  struct pt_regs *regs, int trapnr, int reg, int imm)
{
	regs->cx = imm * regs->cx + *pt_regs_nr(regs, reg);
	return ex_handler_uaccess(fixup, regs, trapnr);
}

int ex_get_fixup_type(unsigned long ip)
{
	const struct exception_table_entry *e = search_exception_tables(ip);

	return e ? FIELD_GET(EX_DATA_TYPE_MASK, e->data) : EX_TYPE_NONE;
}

int fixup_exception(struct pt_regs *regs, int trapnr, unsigned long error_code,
		    unsigned long fault_addr)
{
	const struct exception_table_entry *e;
	int type, reg, imm;

#ifdef CONFIG_PNPBIOS
	if (unlikely(SEGMENT_IS_PNP_CODE(regs->cs))) {
		extern u32 pnp_bios_fault_eip, pnp_bios_fault_esp;
		extern u32 pnp_bios_is_utter_crap;
		pnp_bios_is_utter_crap = 1;
		printk(KERN_CRIT "PNPBIOS fault.. attempting recovery.\n");
		__asm__ volatile(
			"movl %0, %%esp\n\t"
			"jmp *%1\n\t"
			: : "g" (pnp_bios_fault_esp), "g" (pnp_bios_fault_eip));
		panic("do_trap: can't hit this");
	}
#endif

	e = search_exception_tables(regs->ip);
	if (!e)
		return 0;

	type = FIELD_GET(EX_DATA_TYPE_MASK, e->data);
	reg  = FIELD_GET(EX_DATA_REG_MASK,  e->data);
	imm  = FIELD_GET(EX_DATA_IMM_MASK,  e->data);

	switch (type) {
	case EX_TYPE_DEFAULT:
	case EX_TYPE_DEFAULT_MCE_SAFE:
		return ex_handler_default(e, regs);
	case EX_TYPE_FAULT:
	case EX_TYPE_FAULT_MCE_SAFE:
		return ex_handler_fault(e, regs, trapnr);
	case EX_TYPE_UACCESS:
		return ex_handler_uaccess(e, regs, trapnr);
	case EX_TYPE_COPY:
		return ex_handler_copy(e, regs, trapnr);
	case EX_TYPE_CLEAR_FS:
		return ex_handler_clear_fs(e, regs);
	case EX_TYPE_FPU_RESTORE:
		return ex_handler_fprestore(e, regs);
	case EX_TYPE_BPF:
		return ex_handler_bpf(e, regs);
	case EX_TYPE_WRMSR:
		return ex_handler_msr(e, regs, true, false, reg);
	case EX_TYPE_RDMSR:
		return ex_handler_msr(e, regs, false, false, reg);
	case EX_TYPE_WRMSR_SAFE:
		return ex_handler_msr(e, regs, true, true, reg);
	case EX_TYPE_RDMSR_SAFE:
		return ex_handler_msr(e, regs, false, true, reg);
	case EX_TYPE_WRMSR_IN_MCE:
		ex_handler_msr_mce(regs, true);
		break;
	case EX_TYPE_RDMSR_IN_MCE:
		ex_handler_msr_mce(regs, false);
		break;
	case EX_TYPE_POP_REG:
		regs->sp += sizeof(long);
		fallthrough;
	case EX_TYPE_IMM_REG:
		return ex_handler_imm_reg(e, regs, reg, imm);
	case EX_TYPE_FAULT_SGX:
		return ex_handler_sgx(e, regs, trapnr);
	case EX_TYPE_UCOPY_LEN:
		return ex_handler_ucopy_len(e, regs, trapnr, reg, imm);
	}
	BUG();
}

extern unsigned int early_recursion_flag;

void __init early_fixup_exception(struct pt_regs *regs, int trapnr)
{
	/* Ignore early NMIs. */
	if (trapnr == X86_TRAP_NMI)
		return;

	if (early_recursion_flag > 2)
		goto halt_loop;

	/*
	if (!xen_pv_domain() && regs->cs != __KERNEL_CS)
		goto fail;

	/*
	if (fixup_exception(regs, trapnr, regs->orig_ax, 0))
		return;

	if (trapnr == X86_TRAP_UD) {
		if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN) {
			/* Skip the ud2. */
			regs->ip += LEN_UD2;
			return;
		}

		/*
	}

fail:
	early_printk("PANIC: early exception 0x%02x IP %lx:%lx error %lx cr2 0x%lx\n",
		     (unsigned)trapnr, (unsigned long)regs->cs, regs->ip,
		     regs->orig_ax, read_cr2());

	show_regs(regs);

halt_loop:
	while (true)
		halt();
}
