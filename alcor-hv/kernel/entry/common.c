
#include <linux/context_tracking.h>
#include <linux/entry-common.h>
#include <linux/resume_user_mode.h>
#include <linux/highmem.h>
#include <linux/jump_label.h>
#include <linux/livepatch.h>
#include <linux/audit.h>
#include <linux/tick.h>

#include "common.h"

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

static __always_inline void __enter_from_user_mode(struct pt_regs *regs)
{
	arch_enter_from_user_mode(regs);
	lockdep_hardirqs_off(CALLER_ADDR0);

	CT_WARN_ON(ct_state() != CONTEXT_USER);
	user_exit_irqoff();

	instrumentation_begin();
	trace_hardirqs_off_finish();
	instrumentation_end();
}

void noinstr enter_from_user_mode(struct pt_regs *regs)
{
	__enter_from_user_mode(regs);
}

static inline void syscall_enter_audit(struct pt_regs *regs, long syscall)
{
	if (unlikely(audit_context())) {
		unsigned long args[6];

		syscall_get_arguments(current, regs, args);
		audit_syscall_entry(syscall, args[0], args[1], args[2], args[3]);
	}
}

static long syscall_trace_enter(struct pt_regs *regs, long syscall,
				unsigned long work)
{
	long ret = 0;

	/*
	if (work & SYSCALL_WORK_SYSCALL_USER_DISPATCH) {
		if (syscall_user_dispatch(regs))
			return -1L;
	}

	/* Handle ptrace */
	if (work & (SYSCALL_WORK_SYSCALL_TRACE | SYSCALL_WORK_SYSCALL_EMU)) {
		ret = ptrace_report_syscall_entry(regs);
		if (ret || (work & SYSCALL_WORK_SYSCALL_EMU))
			return -1L;
	}

	/* Do seccomp after ptrace, to catch any tracer changes. */
	if (work & SYSCALL_WORK_SECCOMP) {
		ret = __secure_computing(NULL);
		if (ret == -1L)
			return ret;
	}

	/* Either of the above might have changed the syscall number */
	syscall = syscall_get_nr(current, regs);

	if (unlikely(work & SYSCALL_WORK_SYSCALL_TRACEPOINT))
		trace_sys_enter(regs, syscall);

	syscall_enter_audit(regs, syscall);

	return ret ? : syscall;
}

static __always_inline long
__syscall_enter_from_user_work(struct pt_regs *regs, long syscall)
{
	unsigned long work = READ_ONCE(current_thread_info()->syscall_work);

	if (work & SYSCALL_WORK_ENTER)
		syscall = syscall_trace_enter(regs, syscall, work);

	return syscall;
}

long syscall_enter_from_user_mode_work(struct pt_regs *regs, long syscall)
{
	return __syscall_enter_from_user_work(regs, syscall);
}

noinstr long syscall_enter_from_user_mode(struct pt_regs *regs, long syscall)
{
	long ret;

	__enter_from_user_mode(regs);

	instrumentation_begin();
	local_irq_enable();
	ret = __syscall_enter_from_user_work(regs, syscall);
	instrumentation_end();

	return ret;
}

noinstr void syscall_enter_from_user_mode_prepare(struct pt_regs *regs)
{
	__enter_from_user_mode(regs);
	instrumentation_begin();
	local_irq_enable();
	instrumentation_end();
}

static __always_inline void __exit_to_user_mode(void)
{
	instrumentation_begin();
	trace_hardirqs_on_prepare();
	lockdep_hardirqs_on_prepare();
	instrumentation_end();

	user_enter_irqoff();
	arch_exit_to_user_mode();
	lockdep_hardirqs_on(CALLER_ADDR0);
}

void noinstr exit_to_user_mode(void)
{
	__exit_to_user_mode();
}

void __weak arch_do_signal_or_restart(struct pt_regs *regs) { }

static unsigned long exit_to_user_mode_loop(struct pt_regs *regs,
					    unsigned long ti_work)
{
	/*
	while (ti_work & EXIT_TO_USER_MODE_WORK) {

		local_irq_enable_exit_to_user(ti_work);

		if (ti_work & _TIF_NEED_RESCHED)
			schedule();

		if (ti_work & _TIF_UPROBE)
			uprobe_notify_resume(regs);

		if (ti_work & _TIF_PATCH_PENDING)
			klp_update_patch_state(current);

		if (ti_work & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL))
			arch_do_signal_or_restart(regs);

		if (ti_work & _TIF_NOTIFY_RESUME)
			resume_user_mode_work(regs);

		/* Architecture specific TIF work */
		arch_exit_to_user_mode_work(regs, ti_work);

		/*
		local_irq_disable_exit_to_user();

		/* Check if any of the above work has queued a deferred wakeup */
		tick_nohz_user_enter_prepare();

		ti_work = read_thread_flags();
	}

	/* Return the latest work state for arch_exit_to_user_mode() */
	return ti_work;
}

static void exit_to_user_mode_prepare(struct pt_regs *regs)
{
	unsigned long ti_work = read_thread_flags();

	lockdep_assert_irqs_disabled();

	/* Flush pending rcuog wakeup before the last need_resched() check */
	tick_nohz_user_enter_prepare();

	if (unlikely(ti_work & EXIT_TO_USER_MODE_WORK))
		ti_work = exit_to_user_mode_loop(regs, ti_work);

	arch_exit_to_user_mode_prepare(regs, ti_work);

	/* Ensure that the address limit is intact and no locks are held */
	addr_limit_user_check();
	kmap_assert_nomap();
	lockdep_assert_irqs_disabled();
	lockdep_sys_exit();
}

static inline bool report_single_step(unsigned long work)
{
	if (work & SYSCALL_WORK_SYSCALL_EMU)
		return false;

	return work & SYSCALL_WORK_SYSCALL_EXIT_TRAP;
}

static void syscall_exit_work(struct pt_regs *regs, unsigned long work)
{
	bool step;

	/*
	if (work & SYSCALL_WORK_SYSCALL_USER_DISPATCH) {
		if (unlikely(current->syscall_dispatch.on_dispatch)) {
			current->syscall_dispatch.on_dispatch = false;
			return;
		}
	}

	audit_syscall_exit(regs);

	if (work & SYSCALL_WORK_SYSCALL_TRACEPOINT)
		trace_sys_exit(regs, syscall_get_return_value(current, regs));

	step = report_single_step(work);
	if (step || work & SYSCALL_WORK_SYSCALL_TRACE)
		ptrace_report_syscall_exit(regs, step);
}

static void syscall_exit_to_user_mode_prepare(struct pt_regs *regs)
{
	unsigned long work = READ_ONCE(current_thread_info()->syscall_work);
	unsigned long nr = syscall_get_nr(current, regs);

	CT_WARN_ON(ct_state() != CONTEXT_KERNEL);

	if (IS_ENABLED(CONFIG_PROVE_LOCKING)) {
		if (WARN(irqs_disabled(), "syscall %lu left IRQs disabled", nr))
			local_irq_enable();
	}

	rseq_syscall(regs);

	/*
	if (unlikely(work & SYSCALL_WORK_EXIT))
		syscall_exit_work(regs, work);
}

static __always_inline void __syscall_exit_to_user_mode_work(struct pt_regs *regs)
{
	syscall_exit_to_user_mode_prepare(regs);
	local_irq_disable_exit_to_user();
	exit_to_user_mode_prepare(regs);
}

void syscall_exit_to_user_mode_work(struct pt_regs *regs)
{
	__syscall_exit_to_user_mode_work(regs);
}

__visible noinstr void syscall_exit_to_user_mode(struct pt_regs *regs)
{
	instrumentation_begin();
	__syscall_exit_to_user_mode_work(regs);
	instrumentation_end();
	__exit_to_user_mode();
}

noinstr void irqentry_enter_from_user_mode(struct pt_regs *regs)
{
	__enter_from_user_mode(regs);
}

noinstr void irqentry_exit_to_user_mode(struct pt_regs *regs)
{
	instrumentation_begin();
	exit_to_user_mode_prepare(regs);
	instrumentation_end();
	__exit_to_user_mode();
}

noinstr irqentry_state_t irqentry_enter(struct pt_regs *regs)
{
	irqentry_state_t ret = {
		.exit_rcu = false,
	};

	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);
		return ret;
	}

	/*
	if (!IS_ENABLED(CONFIG_TINY_RCU) && is_idle_task(current)) {
		/*
		lockdep_hardirqs_off(CALLER_ADDR0);
		ct_irq_enter();
		instrumentation_begin();
		trace_hardirqs_off_finish();
		instrumentation_end();

		ret.exit_rcu = true;
		return ret;
	}

	/*
	lockdep_hardirqs_off(CALLER_ADDR0);
	instrumentation_begin();
	rcu_irq_enter_check_tick();
	trace_hardirqs_off_finish();
	instrumentation_end();

	return ret;
}

void raw_irqentry_exit_cond_resched(void)
{
	if (!preempt_count()) {
		/* Sanity check RCU and thread stack */
		rcu_irq_exit_check_preempt();
		if (IS_ENABLED(CONFIG_DEBUG_ENTRY))
			WARN_ON_ONCE(!on_thread_stack());
		if (need_resched())
			preempt_schedule_irq();
	}
}
#ifdef CONFIG_PREEMPT_DYNAMIC
#if defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)
DEFINE_STATIC_CALL(irqentry_exit_cond_resched, raw_irqentry_exit_cond_resched);
#elif defined(CONFIG_HAVE_PREEMPT_DYNAMIC_KEY)
DEFINE_STATIC_KEY_TRUE(sk_dynamic_irqentry_exit_cond_resched);
void dynamic_irqentry_exit_cond_resched(void)
{
	if (!static_branch_unlikely(&sk_dynamic_irqentry_exit_cond_resched))
		return;
	raw_irqentry_exit_cond_resched();
}
#endif
#endif

noinstr void irqentry_exit(struct pt_regs *regs, irqentry_state_t state)
{
	lockdep_assert_irqs_disabled();

	/* Check whether this returns to user mode */
	if (user_mode(regs)) {
		irqentry_exit_to_user_mode(regs);
	} else if (!regs_irqs_disabled(regs)) {
		/*
		if (state.exit_rcu) {
			instrumentation_begin();
			/* Tell the tracer that IRET will enable interrupts */
			trace_hardirqs_on_prepare();
			lockdep_hardirqs_on_prepare();
			instrumentation_end();
			ct_irq_exit();
			lockdep_hardirqs_on(CALLER_ADDR0);
			return;
		}

		instrumentation_begin();
		if (IS_ENABLED(CONFIG_PREEMPTION))
			irqentry_exit_cond_resched();

		/* Covers both tracing and lockdep */
		trace_hardirqs_on();
		instrumentation_end();
	} else {
		/*
		if (state.exit_rcu)
			ct_irq_exit();
	}
}

irqentry_state_t noinstr irqentry_nmi_enter(struct pt_regs *regs)
{
	irqentry_state_t irq_state;

	irq_state.lockdep = lockdep_hardirqs_enabled();

	__nmi_enter();
	lockdep_hardirqs_off(CALLER_ADDR0);
	lockdep_hardirq_enter();
	ct_nmi_enter();

	instrumentation_begin();
	trace_hardirqs_off_finish();
	ftrace_nmi_enter();
	instrumentation_end();

	return irq_state;
}

void noinstr irqentry_nmi_exit(struct pt_regs *regs, irqentry_state_t irq_state)
{
	instrumentation_begin();
	ftrace_nmi_exit();
	if (irq_state.lockdep) {
		trace_hardirqs_on_prepare();
		lockdep_hardirqs_on_prepare();
	}
	instrumentation_end();

	ct_nmi_exit();
	lockdep_hardirq_exit();
	if (irq_state.lockdep)
		lockdep_hardirqs_on(CALLER_ADDR0);
	__nmi_exit();
}
