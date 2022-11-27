

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/context_tracking.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/kdebug.h>
#include <linux/kgdb.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/ptrace.h>
#include <linux/uprobes.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/kexec.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/timer.h>
#include <linux/init.h>
#include <linux/bug.h>
#include <linux/nmi.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/io.h>
#include <linux/hardirq.h>
#include <linux/atomic.h>
#include <linux/ioasid.h>

#include <asm/stacktrace.h>
#include <asm/processor.h>
#include <asm/debugreg.h>
#include <asm/realmode.h>
#include <asm/text-patching.h>
#include <asm/ftrace.h>
#include <asm/traps.h>
#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/cpu.h>
#include <asm/cpu_entry_area.h>
#include <asm/mce.h>
#include <asm/fixmap.h>
#include <asm/mach_traps.h>
#include <asm/alternative.h>
#include <asm/fpu/xstate.h>
#include <asm/vm86.h>
#include <asm/umip.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/vdso.h>
#include <asm/tdx.h>

#ifdef CONFIG_X86_64
#include <asm/x86_init.h>
#include <asm/proto.h>
#else
#include <asm/processor-flags.h>
#include <asm/setup.h>
#include <asm/proto.h>
#endif

DECLARE_BITMAP(system_vectors, NR_VECTORS);

static inline void cond_local_irq_enable(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_enable();
}

static inline void cond_local_irq_disable(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_disable();
}

__always_inline int is_valid_bugaddr(unsigned long addr)
{
	if (addr < TASK_SIZE_MAX)
		return 0;

	/*
	return *(unsigned short *)addr == INSN_UD2;
}

static nokprobe_inline int
do_trap_no_signal(struct task_struct *tsk, int trapnr, const char *str,
		  struct pt_regs *regs,	long error_code)
{
	if (v8086_mode(regs)) {
		/*
		if (trapnr < X86_TRAP_UD) {
			if (!handle_vm86_trap((struct kernel_vm86_regs *) regs,
						error_code, trapnr))
				return 0;
		}
	} else if (!user_mode(regs)) {
		if (fixup_exception(regs, trapnr, error_code, 0))
			return 0;

		tsk->thread.error_code = error_code;
		tsk->thread.trap_nr = trapnr;
		die(str, regs, error_code);
	} else {
		if (fixup_vdso_exception(regs, trapnr, error_code, 0))
			return 0;
	}

	/*
	tsk->thread.error_code = error_code;
	tsk->thread.trap_nr = trapnr;

	return -1;
}

static void show_signal(struct task_struct *tsk, int signr,
			const char *type, const char *desc,
			struct pt_regs *regs, long error_code)
{
	if (show_unhandled_signals && unhandled_signal(tsk, signr) &&
	    printk_ratelimit()) {
		pr_info("%s[%d] %s%s ip:%lx sp:%lx error:%lx",
			tsk->comm, task_pid_nr(tsk), type, desc,
			regs->ip, regs->sp, error_code);
		print_vma_addr(KERN_CONT " in ", regs->ip);
		pr_cont("\n");
	}
}

static void
do_trap(int trapnr, int signr, char *str, struct pt_regs *regs,
	long error_code, int sicode, void __user *addr)
{
	struct task_struct *tsk = current;

	if (!do_trap_no_signal(tsk, trapnr, str, regs, error_code))
		return;

	show_signal(tsk, signr, "trap ", str, regs, error_code);

	if (!sicode)
		force_sig(signr);
	else
		force_sig_fault(signr, sicode, addr);
}
NOKPROBE_SYMBOL(do_trap);

static void do_error_trap(struct pt_regs *regs, long error_code, char *str,
	unsigned long trapnr, int signr, int sicode, void __user *addr)
{
	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");

	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr) !=
			NOTIFY_STOP) {
		cond_local_irq_enable(regs);
		do_trap(trapnr, signr, str, regs, error_code, sicode, addr);
		cond_local_irq_disable(regs);
	}
}

static __always_inline void __user *error_get_trap_addr(struct pt_regs *regs)
{
	return (void __user *)uprobe_get_trap_addr(regs);
}

DEFINE_IDTENTRY(exc_divide_error)
{
	do_error_trap(regs, 0, "divide error", X86_TRAP_DE, SIGFPE,
		      FPE_INTDIV, error_get_trap_addr(regs));
}

DEFINE_IDTENTRY(exc_overflow)
{
	do_error_trap(regs, 0, "overflow", X86_TRAP_OF, SIGSEGV, 0, NULL);
}

#ifdef CONFIG_X86_KERNEL_IBT

static __ro_after_init bool ibt_fatal = true;

extern void ibt_selftest_ip(void); /* code label defined in asm below */

enum cp_error_code {
	CP_EC        = (1 << 15) - 1,

	CP_RET       = 1,
	CP_IRET      = 2,
	CP_ENDBR     = 3,
	CP_RSTRORSSP = 4,
	CP_SETSSBSY  = 5,

	CP_ENCL	     = 1 << 15,
};

DEFINE_IDTENTRY_ERRORCODE(exc_control_protection)
{
	if (!cpu_feature_enabled(X86_FEATURE_IBT)) {
		pr_err("Unexpected #CP\n");
		BUG();
	}

	if (WARN_ON_ONCE(user_mode(regs) || (error_code & CP_EC) != CP_ENDBR))
		return;

	if (unlikely(regs->ip == (unsigned long)&ibt_selftest_ip)) {
		regs->ax = 0;
		return;
	}

	pr_err("Missing ENDBR: %pS\n", (void *)instruction_pointer(regs));
	if (!ibt_fatal) {
		printk(KERN_DEFAULT CUT_HERE);
		__warn(__FILE__, __LINE__, (void *)regs->ip, TAINT_WARN, regs, NULL);
		return;
	}
	BUG();
}

noinline bool ibt_selftest(void)
{
	unsigned long ret;

	asm ("	lea ibt_selftest_ip(%%rip), %%rax\n\t"
	     ANNOTATE_RETPOLINE_SAFE
	     "	jmp *%%rax\n\t"
	     "ibt_selftest_ip:\n\t"
	     UNWIND_HINT_FUNC
	     ANNOTATE_NOENDBR
	     "	nop\n\t"

	     : "=a" (ret) : : "memory");

	return !ret;
}

static int __init ibt_setup(char *str)
{
	if (!strcmp(str, "off"))
		setup_clear_cpu_cap(X86_FEATURE_IBT);

	if (!strcmp(str, "warn"))
		ibt_fatal = false;

	return 1;
}

__setup("ibt=", ibt_setup);

#endif /* CONFIG_X86_KERNEL_IBT */

#ifdef CONFIG_X86_F00F_BUG
void handle_invalid_op(struct pt_regs *regs)
#else
static inline void handle_invalid_op(struct pt_regs *regs)
#endif
{
	do_error_trap(regs, 0, "invalid opcode", X86_TRAP_UD, SIGILL,
		      ILL_ILLOPN, error_get_trap_addr(regs));
}

static noinstr bool handle_bug(struct pt_regs *regs)
{
	bool handled = false;

	if (!is_valid_bugaddr(regs->ip))
		return handled;

	/*
	instrumentation_begin();
	/*
	if (regs->flags & X86_EFLAGS_IF)
		raw_local_irq_enable();
	if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN) {
		regs->ip += LEN_UD2;
		handled = true;
	}
	if (regs->flags & X86_EFLAGS_IF)
		raw_local_irq_disable();
	instrumentation_end();

	return handled;
}

DEFINE_IDTENTRY_RAW(exc_invalid_op)
{
	irqentry_state_t state;

	/*
	if (!user_mode(regs) && handle_bug(regs))
		return;

	state = irqentry_enter(regs);
	instrumentation_begin();
	handle_invalid_op(regs);
	instrumentation_end();
	irqentry_exit(regs, state);
}

DEFINE_IDTENTRY(exc_coproc_segment_overrun)
{
	do_error_trap(regs, 0, "coprocessor segment overrun",
		      X86_TRAP_OLD_MF, SIGFPE, 0, NULL);
}

DEFINE_IDTENTRY_ERRORCODE(exc_invalid_tss)
{
	do_error_trap(regs, error_code, "invalid TSS", X86_TRAP_TS, SIGSEGV,
		      0, NULL);
}

DEFINE_IDTENTRY_ERRORCODE(exc_segment_not_present)
{
	do_error_trap(regs, error_code, "segment not present", X86_TRAP_NP,
		      SIGBUS, 0, NULL);
}

DEFINE_IDTENTRY_ERRORCODE(exc_stack_segment)
{
	do_error_trap(regs, error_code, "stack segment", X86_TRAP_SS, SIGBUS,
		      0, NULL);
}

DEFINE_IDTENTRY_ERRORCODE(exc_alignment_check)
{
	char *str = "alignment check";

	if (notify_die(DIE_TRAP, str, regs, error_code, X86_TRAP_AC, SIGBUS) == NOTIFY_STOP)
		return;

	if (!user_mode(regs))
		die("Split lock detected\n", regs, error_code);

	local_irq_enable();

	if (handle_user_split_lock(regs, error_code))
		goto out;

	do_trap(X86_TRAP_AC, SIGBUS, "alignment check", regs,
		error_code, BUS_ADRALN, NULL);

out:
	local_irq_disable();
}

#ifdef CONFIG_VMAP_STACK
__visible void __noreturn handle_stack_overflow(struct pt_regs *regs,
						unsigned long fault_address,
						struct stack_info *info)
{
	const char *name = stack_type_name(info->type);

	printk(KERN_EMERG "BUG: %s stack guard page was hit at %p (stack is %p..%p)\n",
	       name, (void *)fault_address, info->begin, info->end);

	die("stack guard page", regs, 0);

	/* Be absolutely certain we don't return. */
	panic("%s stack guard hit", name);
}
#endif

DEFINE_IDTENTRY_DF(exc_double_fault)
{
	static const char str[] = "double fault";
	struct task_struct *tsk = current;

#ifdef CONFIG_VMAP_STACK
	unsigned long address = read_cr2();
	struct stack_info info;
#endif

#ifdef CONFIG_X86_ESPFIX64
	extern unsigned char native_irq_return_iret[];

	/*
	if (((long)regs->sp >> P4D_SHIFT) == ESPFIX_PGD_ENTRY &&
		regs->cs == __KERNEL_CS &&
		regs->ip == (unsigned long)native_irq_return_iret)
	{
		struct pt_regs *gpregs = (struct pt_regs *)this_cpu_read(cpu_tss_rw.x86_tss.sp0) - 1;
		unsigned long *p = (unsigned long *)regs->sp;

		/*
		gpregs->ip	= p[0];
		gpregs->cs	= p[1];
		gpregs->flags	= p[2];
		gpregs->sp	= p[3];
		gpregs->ss	= p[4];
		gpregs->orig_ax = 0;  /* Missing (lost) #GP error code */

		/*
		regs->ip = (unsigned long)asm_exc_general_protection;
		regs->sp = (unsigned long)&gpregs->orig_ax;

		return;
	}
#endif

	irqentry_nmi_enter(regs);
	instrumentation_begin();
	notify_die(DIE_TRAP, str, regs, error_code, X86_TRAP_DF, SIGSEGV);

	tsk->thread.error_code = error_code;
	tsk->thread.trap_nr = X86_TRAP_DF;

#ifdef CONFIG_VMAP_STACK
	/*
	if (get_stack_guard_info((void *)address, &info))
		handle_stack_overflow(regs, address, &info);
#endif

	pr_emerg("PANIC: double fault, error_code: 0x%lx\n", error_code);
	die("double fault", regs, error_code);
	panic("Machine halted.");
	instrumentation_end();
}

DEFINE_IDTENTRY(exc_bounds)
{
	if (notify_die(DIE_TRAP, "bounds", regs, 0,
			X86_TRAP_BR, SIGSEGV) == NOTIFY_STOP)
		return;
	cond_local_irq_enable(regs);

	if (!user_mode(regs))
		die("bounds", regs, 0);

	do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, 0, 0, NULL);

	cond_local_irq_disable(regs);
}

enum kernel_gp_hint {
	GP_NO_HINT,
	GP_NON_CANONICAL,
	GP_CANONICAL
};

static enum kernel_gp_hint get_kernel_gp_address(struct pt_regs *regs,
						 unsigned long *addr)
{
	u8 insn_buf[MAX_INSN_SIZE];
	struct insn insn;
	int ret;

	if (copy_from_kernel_nofault(insn_buf, (void *)regs->ip,
			MAX_INSN_SIZE))
		return GP_NO_HINT;

	ret = insn_decode_kernel(&insn, insn_buf);
	if (ret < 0)
		return GP_NO_HINT;

	if (*addr == -1UL)
		return GP_NO_HINT;

#ifdef CONFIG_X86_64
	/*
	if (*addr < ~__VIRTUAL_MASK &&
	    *addr + insn.opnd_bytes - 1 > __VIRTUAL_MASK)
		return GP_NON_CANONICAL;
#endif

	return GP_CANONICAL;
}

#define GPFSTR "general protection fault"

static bool fixup_iopl_exception(struct pt_regs *regs)
{
	struct thread_struct *t = &current->thread;
	unsigned char byte;
	unsigned long ip;

	if (!IS_ENABLED(CONFIG_X86_IOPL_IOPERM) || t->iopl_emul != 3)
		return false;

	if (insn_get_effective_ip(regs, &ip))
		return false;

	if (get_user(byte, (const char __user *)ip))
		return false;

	if (byte != 0xfa && byte != 0xfb)
		return false;

	if (!t->iopl_warn && printk_ratelimit()) {
		pr_err("%s[%d] attempts to use CLI/STI, pretending it's a NOP, ip:%lx",
		       current->comm, task_pid_nr(current), ip);
		print_vma_addr(KERN_CONT " in ", ip);
		pr_cont("\n");
		t->iopl_warn = 1;
	}

	regs->ip += 1;
	return true;
}

static bool try_fixup_enqcmd_gp(void)
{
#ifdef CONFIG_IOMMU_SVA
	u32 pasid;

	/*
	lockdep_assert_irqs_disabled();

	/*
	if (!cpu_feature_enabled(X86_FEATURE_ENQCMD))
		return false;

	pasid = current->mm->pasid;

	/*
	if (!pasid_valid(pasid))
		return false;

	/*
	if (current->pasid_activated)
		return false;

	wrmsrl(MSR_IA32_PASID, pasid | MSR_IA32_PASID_VALID);
	current->pasid_activated = 1;

	return true;
#else
	return false;
#endif
}

static bool gp_try_fixup_and_notify(struct pt_regs *regs, int trapnr,
				    unsigned long error_code, const char *str)
{
	if (fixup_exception(regs, trapnr, error_code, 0))
		return true;

	current->thread.error_code = error_code;
	current->thread.trap_nr = trapnr;

	/*
	if (!preemptible() && kprobe_running() &&
	    kprobe_fault_handler(regs, trapnr))
		return true;

	return notify_die(DIE_GPF, str, regs, error_code, trapnr, SIGSEGV) == NOTIFY_STOP;
}

static void gp_user_force_sig_segv(struct pt_regs *regs, int trapnr,
				   unsigned long error_code, const char *str)
{
	current->thread.error_code = error_code;
	current->thread.trap_nr = trapnr;
	show_signal(current, SIGSEGV, "", str, regs, error_code);
	force_sig(SIGSEGV);
}

DEFINE_IDTENTRY_ERRORCODE(exc_general_protection)
{
	char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;
	enum kernel_gp_hint hint = GP_NO_HINT;
	unsigned long gp_addr;

	if (user_mode(regs) && try_fixup_enqcmd_gp())
		return;

	cond_local_irq_enable(regs);

	if (static_cpu_has(X86_FEATURE_UMIP)) {
		if (user_mode(regs) && fixup_umip_exception(regs))
			goto exit;
	}

	if (v8086_mode(regs)) {
		local_irq_enable();
		handle_vm86_fault((struct kernel_vm86_regs *) regs, error_code);
		local_irq_disable();
		return;
	}

	if (user_mode(regs)) {
		if (fixup_iopl_exception(regs))
			goto exit;

		if (fixup_vdso_exception(regs, X86_TRAP_GP, error_code, 0))
			goto exit;

		gp_user_force_sig_segv(regs, X86_TRAP_GP, error_code, desc);
		goto exit;
	}

	if (gp_try_fixup_and_notify(regs, X86_TRAP_GP, error_code, desc))
		goto exit;

	if (error_code)
		snprintf(desc, sizeof(desc), "segment-related " GPFSTR);
	else
		hint = get_kernel_gp_address(regs, &gp_addr);

	if (hint != GP_NO_HINT)
		snprintf(desc, sizeof(desc), GPFSTR ", %s 0x%lx",
			 (hint == GP_NON_CANONICAL) ? "probably for non-canonical address"
						    : "maybe for address",
			 gp_addr);

	/*
	if (hint != GP_NON_CANONICAL)
		gp_addr = 0;

	die_addr(desc, regs, error_code, gp_addr);

exit:
	cond_local_irq_disable(regs);
}

static bool do_int3(struct pt_regs *regs)
{
	int res;

#ifdef CONFIG_KGDB_LOW_LEVEL_TRAP
	if (kgdb_ll_trap(DIE_INT3, "int3", regs, 0, X86_TRAP_BP,
			 SIGTRAP) == NOTIFY_STOP)
		return true;
#endif /* CONFIG_KGDB_LOW_LEVEL_TRAP */

#ifdef CONFIG_KPROBES
	if (kprobe_int3_handler(regs))
		return true;
#endif
	res = notify_die(DIE_INT3, "int3", regs, 0, X86_TRAP_BP, SIGTRAP);

	return res == NOTIFY_STOP;
}
NOKPROBE_SYMBOL(do_int3);

static void do_int3_user(struct pt_regs *regs)
{
	if (do_int3(regs))
		return;

	cond_local_irq_enable(regs);
	do_trap(X86_TRAP_BP, SIGTRAP, "int3", regs, 0, 0, NULL);
	cond_local_irq_disable(regs);
}

DEFINE_IDTENTRY_RAW(exc_int3)
{
	/*
	if (poke_int3_handler(regs))
		return;

	/*
	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);
		instrumentation_begin();
		do_int3_user(regs);
		instrumentation_end();
		irqentry_exit_to_user_mode(regs);
	} else {
		irqentry_state_t irq_state = irqentry_nmi_enter(regs);

		instrumentation_begin();
		if (!do_int3(regs))
			die("int3", regs, 0);
		instrumentation_end();
		irqentry_nmi_exit(regs, irq_state);
	}
}

#ifdef CONFIG_X86_64
asmlinkage __visible noinstr struct pt_regs *sync_regs(struct pt_regs *eregs)
{
	struct pt_regs *regs = (struct pt_regs *)this_cpu_read(cpu_current_top_of_stack) - 1;
	if (regs != eregs)
		*regs = *eregs;
	return regs;
}

#ifdef CONFIG_AMD_MEM_ENCRYPT
asmlinkage __visible noinstr struct pt_regs *vc_switch_off_ist(struct pt_regs *regs)
{
	unsigned long sp, *stack;
	struct stack_info info;
	struct pt_regs *regs_ret;

	/*
	if (ip_within_syscall_gap(regs)) {
		sp = this_cpu_read(cpu_current_top_of_stack);
		goto sync;
	}

	/*
	sp    = regs->sp;
	stack = (unsigned long *)sp;

	if (!get_stack_info_noinstr(stack, current, &info) || info.type == STACK_TYPE_ENTRY ||
	    info.type > STACK_TYPE_EXCEPTION_LAST)
		sp = __this_cpu_ist_top_va(VC2);

sync:
	/*
	sp = ALIGN_DOWN(sp, 8) - sizeof(*regs_ret);

	regs_ret = (struct pt_regs *)sp;

	return regs_ret;
}
#endif

asmlinkage __visible noinstr struct pt_regs *fixup_bad_iret(struct pt_regs *bad_regs)
{
	struct pt_regs tmp, *new_stack;

	/*
	new_stack = (struct pt_regs *)__this_cpu_read(cpu_tss_rw.x86_tss.sp0) - 1;

	/* Copy the IRET target to the temporary storage. */
	__memcpy(&tmp.ip, (void *)bad_regs->sp, 5*8);

	/* Copy the remainder of the stack from the current stack. */
	__memcpy(&tmp, bad_regs, offsetof(struct pt_regs, ip));

	/* Update the entry stack */
	__memcpy(new_stack, &tmp, sizeof(tmp));

	BUG_ON(!user_mode(new_stack));
	return new_stack;
}
#endif

static bool is_sysenter_singlestep(struct pt_regs *regs)
{
	/*
#ifdef CONFIG_X86_32
	return (regs->ip - (unsigned long)__begin_SYSENTER_singlestep_region) <
		(unsigned long)__end_SYSENTER_singlestep_region -
		(unsigned long)__begin_SYSENTER_singlestep_region;
#elif defined(CONFIG_IA32_EMULATION)
	return (regs->ip - (unsigned long)entry_SYSENTER_compat) <
		(unsigned long)__end_entry_SYSENTER_compat -
		(unsigned long)entry_SYSENTER_compat;
#else
	return false;
#endif
}

static __always_inline unsigned long debug_read_clear_dr6(void)
{
	unsigned long dr6;

	/*
	get_debugreg(dr6, 6);
	set_debugreg(DR6_RESERVED, 6);
	dr6 ^= DR6_RESERVED; /* Flip to positive polarity */

	return dr6;
}


static bool notify_debug(struct pt_regs *regs, unsigned long *dr6)
{
	/*
	if (notify_die(DIE_DEBUG, "debug", regs, (long)dr6, 0, SIGTRAP) == NOTIFY_STOP)
		return true;

	return false;
}

static __always_inline void exc_debug_kernel(struct pt_regs *regs,
					     unsigned long dr6)
{
	/*
	unsigned long dr7 = local_db_save();
	irqentry_state_t irq_state = irqentry_nmi_enter(regs);
	instrumentation_begin();

	/*
	WARN_ON_ONCE(user_mode(regs));

	if (test_thread_flag(TIF_BLOCKSTEP)) {
		/*
		unsigned long debugctl;

		rdmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
		debugctl |= DEBUGCTLMSR_BTF;
		wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
	}

	/*
	if ((dr6 & DR_STEP) && is_sysenter_singlestep(regs))
		dr6 &= ~DR_STEP;

	/*
	if (!dr6)
		goto out;

	if (notify_debug(regs, &dr6))
		goto out;

	/*
	if (WARN_ON_ONCE(dr6 & DR_STEP))
		regs->flags &= ~X86_EFLAGS_TF;
out:
	instrumentation_end();
	irqentry_nmi_exit(regs, irq_state);

	local_db_restore(dr7);
}

static __always_inline void exc_debug_user(struct pt_regs *regs,
					   unsigned long dr6)
{
	bool icebp;

	/*
	WARN_ON_ONCE(!user_mode(regs));

	/*

	irqentry_enter_from_user_mode(regs);
	instrumentation_begin();

	/*
	current->thread.virtual_dr6 = (dr6 & DR_STEP);

	/*
	clear_thread_flag(TIF_BLOCKSTEP);

	/*
	icebp = !dr6;

	if (notify_debug(regs, &dr6))
		goto out;

	/* It's safe to allow irq's after DR6 has been saved */
	local_irq_enable();

	if (v8086_mode(regs)) {
		handle_vm86_trap((struct kernel_vm86_regs *)regs, 0, X86_TRAP_DB);
		goto out_irq;
	}

	/* #DB for bus lock can only be triggered from userspace. */
	if (dr6 & DR_BUS_LOCK)
		handle_bus_lock(regs);

	/* Add the virtual_dr6 bits for signals. */
	dr6 |= current->thread.virtual_dr6;
	if (dr6 & (DR_STEP | DR_TRAP_BITS) || icebp)
		send_sigtrap(regs, 0, get_si_code(dr6));

out_irq:
	local_irq_disable();
out:
	instrumentation_end();
	irqentry_exit_to_user_mode(regs);
}

#ifdef CONFIG_X86_64
DEFINE_IDTENTRY_DEBUG(exc_debug)
{
	exc_debug_kernel(regs, debug_read_clear_dr6());
}

DEFINE_IDTENTRY_DEBUG_USER(exc_debug)
{
	exc_debug_user(regs, debug_read_clear_dr6());
}
#else
DEFINE_IDTENTRY_RAW(exc_debug)
{
	unsigned long dr6 = debug_read_clear_dr6();

	if (user_mode(regs))
		exc_debug_user(regs, dr6);
	else
		exc_debug_kernel(regs, dr6);
}
#endif

static void math_error(struct pt_regs *regs, int trapnr)
{
	struct task_struct *task = current;
	struct fpu *fpu = &task->thread.fpu;
	int si_code;
	char *str = (trapnr == X86_TRAP_MF) ? "fpu exception" :
						"simd exception";

	cond_local_irq_enable(regs);

	if (!user_mode(regs)) {
		if (fixup_exception(regs, trapnr, 0, 0))
			goto exit;

		task->thread.error_code = 0;
		task->thread.trap_nr = trapnr;

		if (notify_die(DIE_TRAP, str, regs, 0, trapnr,
			       SIGFPE) != NOTIFY_STOP)
			die(str, regs, 0);
		goto exit;
	}

	/*
	fpu_sync_fpstate(fpu);

	task->thread.trap_nr	= trapnr;
	task->thread.error_code = 0;

	si_code = fpu__exception_code(fpu, trapnr);
	/* Retry when we get spurious exceptions: */
	if (!si_code)
		goto exit;

	if (fixup_vdso_exception(regs, trapnr, 0, 0))
		goto exit;

	force_sig_fault(SIGFPE, si_code,
			(void __user *)uprobe_get_trap_addr(regs));
exit:
	cond_local_irq_disable(regs);
}

DEFINE_IDTENTRY(exc_coprocessor_error)
{
	math_error(regs, X86_TRAP_MF);
}

DEFINE_IDTENTRY(exc_simd_coprocessor_error)
{
	if (IS_ENABLED(CONFIG_X86_INVD_BUG)) {
		/* AMD 486 bug: INVD in CPL 0 raises #XF instead of #GP */
		if (!static_cpu_has(X86_FEATURE_XMM)) {
			__exc_general_protection(regs, 0);
			return;
		}
	}
	math_error(regs, X86_TRAP_XF);
}

DEFINE_IDTENTRY(exc_spurious_interrupt_bug)
{
	/*
}

static bool handle_xfd_event(struct pt_regs *regs)
{
	u64 xfd_err;
	int err;

	if (!IS_ENABLED(CONFIG_X86_64) || !cpu_feature_enabled(X86_FEATURE_XFD))
		return false;

	rdmsrl(MSR_IA32_XFD_ERR, xfd_err);
	if (!xfd_err)
		return false;

	wrmsrl(MSR_IA32_XFD_ERR, 0);

	/* Die if that happens in kernel space */
	if (WARN_ON(!user_mode(regs)))
		return false;

	local_irq_enable();

	err = xfd_enable_feature(xfd_err);

	switch (err) {
	case -EPERM:
		force_sig_fault(SIGILL, ILL_ILLOPC, error_get_trap_addr(regs));
		break;
	case -EFAULT:
		force_sig(SIGSEGV);
		break;
	}

	local_irq_disable();
	return true;
}

DEFINE_IDTENTRY(exc_device_not_available)
{
	unsigned long cr0 = read_cr0();

	if (handle_xfd_event(regs))
		return;

#ifdef CONFIG_MATH_EMULATION
	if (!boot_cpu_has(X86_FEATURE_FPU) && (cr0 & X86_CR0_EM)) {
		struct math_emu_info info = { };

		cond_local_irq_enable(regs);

		info.regs = regs;
		math_emulate(&info);

		cond_local_irq_disable(regs);
		return;
	}
#endif

	/* This should not happen. */
	if (WARN(cr0 & X86_CR0_TS, "CR0.TS was set")) {
		/* Try to fix it up and carry on. */
		write_cr0(cr0 & ~X86_CR0_TS);
	} else {
		/*
		die("unexpected #NM exception", regs, 0);
	}
}

#ifdef CONFIG_INTEL_TDX_GUEST

#define VE_FAULT_STR "VE fault"

static void ve_raise_fault(struct pt_regs *regs, long error_code)
{
	if (user_mode(regs)) {
		gp_user_force_sig_segv(regs, X86_TRAP_VE, error_code, VE_FAULT_STR);
		return;
	}

	if (gp_try_fixup_and_notify(regs, X86_TRAP_VE, error_code, VE_FAULT_STR))
		return;

	die_addr(VE_FAULT_STR, regs, error_code, 0);
}

DEFINE_IDTENTRY(exc_virtualization_exception)
{
	struct ve_info ve;

	/*
	tdx_get_ve_info(&ve);

	cond_local_irq_enable(regs);

	/*
	if (!tdx_handle_virt_exception(regs, &ve))
		ve_raise_fault(regs, 0);

	cond_local_irq_disable(regs);
}

#endif

#ifdef CONFIG_X86_32
DEFINE_IDTENTRY_SW(iret_error)
{
	local_irq_enable();
	if (notify_die(DIE_TRAP, "iret exception", regs, 0,
			X86_TRAP_IRET, SIGILL) != NOTIFY_STOP) {
		do_trap(X86_TRAP_IRET, SIGILL, "iret exception", regs, 0,
			ILL_BADSTK, (void __user *)NULL);
	}
	local_irq_disable();
}
#endif

void __init trap_init(void)
{
	/* Init cpu_entry_area before IST entries are set up */
	setup_cpu_entry_areas();

	/* Init GHCB memory pages when running as an SEV-ES guest */
	sev_es_init_vc_handling();

	/* Initialize TSS before setting up traps so ISTs work */
	cpu_init_exception_handling();
	/* Setup traps as cpu_init() might #GP */
	idt_setup_traps();
	cpu_init();
}
