
#include <linux/context_tracking.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/hardirq.h>
#include <linux/export.h>
#include <linux/kprobes.h>
#include <trace/events/rcu.h>


DEFINE_PER_CPU(struct context_tracking, context_tracking) = {
#ifdef CONFIG_CONTEXT_TRACKING_IDLE
	.dynticks_nesting = 1,
	.dynticks_nmi_nesting = DYNTICK_IRQ_NONIDLE,
#endif
	.state = ATOMIC_INIT(RCU_DYNTICKS_IDX),
};
EXPORT_SYMBOL_GPL(context_tracking);

#ifdef CONFIG_CONTEXT_TRACKING_IDLE
#define TPS(x)  tracepoint_string(x)

static __always_inline void rcu_dynticks_task_enter(void)
{
#if defined(CONFIG_TASKS_RCU) && defined(CONFIG_NO_HZ_FULL)
	WRITE_ONCE(current->rcu_tasks_idle_cpu, smp_processor_id());
#endif /* #if defined(CONFIG_TASKS_RCU) && defined(CONFIG_NO_HZ_FULL) */
}

static __always_inline void rcu_dynticks_task_exit(void)
{
#if defined(CONFIG_TASKS_RCU) && defined(CONFIG_NO_HZ_FULL)
	WRITE_ONCE(current->rcu_tasks_idle_cpu, -1);
#endif /* #if defined(CONFIG_TASKS_RCU) && defined(CONFIG_NO_HZ_FULL) */
}

static __always_inline void rcu_dynticks_task_trace_enter(void)
{
#ifdef CONFIG_TASKS_TRACE_RCU
	if (IS_ENABLED(CONFIG_TASKS_TRACE_RCU_READ_MB))
		current->trc_reader_special.b.need_mb = true;
#endif /* #ifdef CONFIG_TASKS_TRACE_RCU */
}

static __always_inline void rcu_dynticks_task_trace_exit(void)
{
#ifdef CONFIG_TASKS_TRACE_RCU
	if (IS_ENABLED(CONFIG_TASKS_TRACE_RCU_READ_MB))
		current->trc_reader_special.b.need_mb = false;
#endif /* #ifdef CONFIG_TASKS_TRACE_RCU */
}

static noinstr void ct_kernel_exit_state(int offset)
{
	int seq;

	/*
	rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
	seq = ct_state_inc(offset);
	// RCU is no longer watching.  Better be in extended quiescent state!
	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && (seq & RCU_DYNTICKS_IDX));
}

static noinstr void ct_kernel_enter_state(int offset)
{
	int seq;

	/*
	seq = ct_state_inc(offset);
	// RCU is now watching.  Better not be in an extended quiescent state!
	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && !(seq & RCU_DYNTICKS_IDX));
}

static void noinstr ct_kernel_exit(bool user, int offset)
{
	struct context_tracking *ct = this_cpu_ptr(&context_tracking);

	WARN_ON_ONCE(ct_dynticks_nmi_nesting() != DYNTICK_IRQ_NONIDLE);
	WRITE_ONCE(ct->dynticks_nmi_nesting, 0);
	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
		     ct_dynticks_nesting() == 0);
	if (ct_dynticks_nesting() != 1) {
		// RCU will still be watching, so just do accounting and leave.
		ct->dynticks_nesting--;
		return;
	}

	instrumentation_begin();
	lockdep_assert_irqs_disabled();
	trace_rcu_dyntick(TPS("Start"), ct_dynticks_nesting(), 0, ct_dynticks());
	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && !user && !is_idle_task(current));
	rcu_preempt_deferred_qs(current);

	// instrumentation for the noinstr ct_kernel_exit_state()
	instrument_atomic_write(&ct->state, sizeof(ct->state));

	instrumentation_end();
	WRITE_ONCE(ct->dynticks_nesting, 0); /* Avoid irq-access tearing. */
	// RCU is watching here ...
	ct_kernel_exit_state(offset);
	// ... but is no longer watching here.
	rcu_dynticks_task_enter();
}

static void noinstr ct_kernel_enter(bool user, int offset)
{
	struct context_tracking *ct = this_cpu_ptr(&context_tracking);
	long oldval;

	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && !raw_irqs_disabled());
	oldval = ct_dynticks_nesting();
	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && oldval < 0);
	if (oldval) {
		// RCU was already watching, so just do accounting and leave.
		ct->dynticks_nesting++;
		return;
	}
	rcu_dynticks_task_exit();
	// RCU is not watching here ...
	ct_kernel_enter_state(offset);
	// ... but is watching here.
	instrumentation_begin();

	// instrumentation for the noinstr ct_kernel_enter_state()
	instrument_atomic_write(&ct->state, sizeof(ct->state));

	trace_rcu_dyntick(TPS("End"), ct_dynticks_nesting(), 1, ct_dynticks());
	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && !user && !is_idle_task(current));
	WRITE_ONCE(ct->dynticks_nesting, 1);
	WARN_ON_ONCE(ct_dynticks_nmi_nesting());
	WRITE_ONCE(ct->dynticks_nmi_nesting, DYNTICK_IRQ_NONIDLE);
	instrumentation_end();
}

void noinstr ct_nmi_exit(void)
{
	struct context_tracking *ct = this_cpu_ptr(&context_tracking);

	instrumentation_begin();
	/*
	WARN_ON_ONCE(ct_dynticks_nmi_nesting() <= 0);
	WARN_ON_ONCE(rcu_dynticks_curr_cpu_in_eqs());

	/*
	if (ct_dynticks_nmi_nesting() != 1) {
		trace_rcu_dyntick(TPS("--="), ct_dynticks_nmi_nesting(), ct_dynticks_nmi_nesting() - 2,
				  ct_dynticks());
		WRITE_ONCE(ct->dynticks_nmi_nesting, /* No store tearing. */
			   ct_dynticks_nmi_nesting() - 2);
		instrumentation_end();
		return;
	}

	/* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
	trace_rcu_dyntick(TPS("Startirq"), ct_dynticks_nmi_nesting(), 0, ct_dynticks());
	WRITE_ONCE(ct->dynticks_nmi_nesting, 0); /* Avoid store tearing. */

	// instrumentation for the noinstr ct_kernel_exit_state()
	instrument_atomic_write(&ct->state, sizeof(ct->state));
	instrumentation_end();

	// RCU is watching here ...
	ct_kernel_exit_state(RCU_DYNTICKS_IDX);
	// ... but is no longer watching here.

	if (!in_nmi())
		rcu_dynticks_task_enter();
}

void noinstr ct_nmi_enter(void)
{
	long incby = 2;
	struct context_tracking *ct = this_cpu_ptr(&context_tracking);

	/* Complain about underflow. */
	WARN_ON_ONCE(ct_dynticks_nmi_nesting() < 0);

	/*
	if (rcu_dynticks_curr_cpu_in_eqs()) {

		if (!in_nmi())
			rcu_dynticks_task_exit();

		// RCU is not watching here ...
		ct_kernel_enter_state(RCU_DYNTICKS_IDX);
		// ... but is watching here.

		instrumentation_begin();
		// instrumentation for the noinstr rcu_dynticks_curr_cpu_in_eqs()
		instrument_atomic_read(&ct->state, sizeof(ct->state));
		// instrumentation for the noinstr ct_kernel_enter_state()
		instrument_atomic_write(&ct->state, sizeof(ct->state));

		incby = 1;
	} else if (!in_nmi()) {
		instrumentation_begin();
		rcu_irq_enter_check_tick();
	} else  {
		instrumentation_begin();
	}

	trace_rcu_dyntick(incby == 1 ? TPS("Endirq") : TPS("++="),
			  ct_dynticks_nmi_nesting(),
			  ct_dynticks_nmi_nesting() + incby, ct_dynticks());
	instrumentation_end();
	WRITE_ONCE(ct->dynticks_nmi_nesting, /* Prevent store tearing. */
		   ct_dynticks_nmi_nesting() + incby);
	barrier();
}

void noinstr ct_idle_enter(void)
{
	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && !raw_irqs_disabled());
	ct_kernel_exit(false, RCU_DYNTICKS_IDX + CONTEXT_IDLE);
}
EXPORT_SYMBOL_GPL(ct_idle_enter);

void noinstr ct_idle_exit(void)
{
	unsigned long flags;

	raw_local_irq_save(flags);
	ct_kernel_enter(false, RCU_DYNTICKS_IDX - CONTEXT_IDLE);
	raw_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(ct_idle_exit);

noinstr void ct_irq_enter(void)
{
	lockdep_assert_irqs_disabled();
	ct_nmi_enter();
}

noinstr void ct_irq_exit(void)
{
	lockdep_assert_irqs_disabled();
	ct_nmi_exit();
}

void ct_irq_enter_irqson(void)
{
	unsigned long flags;

	local_irq_save(flags);
	ct_irq_enter();
	local_irq_restore(flags);
}

void ct_irq_exit_irqson(void)
{
	unsigned long flags;

	local_irq_save(flags);
	ct_irq_exit();
	local_irq_restore(flags);
}
#else
static __always_inline void ct_kernel_exit(bool user, int offset) { }
static __always_inline void ct_kernel_enter(bool user, int offset) { }
#endif /* #ifdef CONFIG_CONTEXT_TRACKING_IDLE */

#ifdef CONFIG_CONTEXT_TRACKING_USER

#define CREATE_TRACE_POINTS
#include <trace/events/context_tracking.h>

DEFINE_STATIC_KEY_FALSE(context_tracking_key);
EXPORT_SYMBOL_GPL(context_tracking_key);

static noinstr bool context_tracking_recursion_enter(void)
{
	int recursion;

	recursion = __this_cpu_inc_return(context_tracking.recursion);
	if (recursion == 1)
		return true;

	WARN_ONCE((recursion < 1), "Invalid context tracking recursion value %d\n", recursion);
	__this_cpu_dec(context_tracking.recursion);

	return false;
}

static __always_inline void context_tracking_recursion_exit(void)
{
	__this_cpu_dec(context_tracking.recursion);
}

void noinstr __ct_user_enter(enum ctx_state state)
{
	struct context_tracking *ct = this_cpu_ptr(&context_tracking);
	lockdep_assert_irqs_disabled();

	/* Kernel threads aren't supposed to go to userspace */
	WARN_ON_ONCE(!current->mm);

	if (!context_tracking_recursion_enter())
		return;

	if (__ct_state() != state) {
		if (ct->active) {
			/*
			if (state == CONTEXT_USER) {
				instrumentation_begin();
				trace_user_enter(0);
				vtime_user_enter(current);
				instrumentation_end();
			}
			/*
			rcu_irq_work_resched();

			/*
			ct_kernel_exit(true, RCU_DYNTICKS_IDX + state);

			/*
			if (!IS_ENABLED(CONFIG_CONTEXT_TRACKING_IDLE))
				atomic_set(&ct->state, state);
		} else {
			/*
			if (!IS_ENABLED(CONFIG_CONTEXT_TRACKING_IDLE)) {
				/* Tracking for vtime only, no concurrent RCU EQS accounting */
				atomic_set(&ct->state, state);
			} else {
				/*
				atomic_add(state, &ct->state);
			}
		}
	}
	context_tracking_recursion_exit();
}
EXPORT_SYMBOL_GPL(__ct_user_enter);

void ct_user_enter(enum ctx_state state)
{
	unsigned long flags;

	/*
	if (in_interrupt())
		return;

	local_irq_save(flags);
	__ct_user_enter(state);
	local_irq_restore(flags);
}
NOKPROBE_SYMBOL(ct_user_enter);
EXPORT_SYMBOL_GPL(ct_user_enter);

void user_enter_callable(void)
{
	user_enter();
}
NOKPROBE_SYMBOL(user_enter_callable);

void noinstr __ct_user_exit(enum ctx_state state)
{
	struct context_tracking *ct = this_cpu_ptr(&context_tracking);

	if (!context_tracking_recursion_enter())
		return;

	if (__ct_state() == state) {
		if (ct->active) {
			/*
			ct_kernel_enter(true, RCU_DYNTICKS_IDX - state);
			if (state == CONTEXT_USER) {
				instrumentation_begin();
				vtime_user_exit(current);
				trace_user_exit(0);
				instrumentation_end();
			}

			/*
			if (!IS_ENABLED(CONFIG_CONTEXT_TRACKING_IDLE))
				atomic_set(&ct->state, CONTEXT_KERNEL);

		} else {
			if (!IS_ENABLED(CONFIG_CONTEXT_TRACKING_IDLE)) {
				/* Tracking for vtime only, no concurrent RCU EQS accounting */
				atomic_set(&ct->state, CONTEXT_KERNEL);
			} else {
				/*
				atomic_sub(state, &ct->state);
			}
		}
	}
	context_tracking_recursion_exit();
}
EXPORT_SYMBOL_GPL(__ct_user_exit);

void ct_user_exit(enum ctx_state state)
{
	unsigned long flags;

	if (in_interrupt())
		return;

	local_irq_save(flags);
	__ct_user_exit(state);
	local_irq_restore(flags);
}
NOKPROBE_SYMBOL(ct_user_exit);
EXPORT_SYMBOL_GPL(ct_user_exit);

void user_exit_callable(void)
{
	user_exit();
}
NOKPROBE_SYMBOL(user_exit_callable);

void __init ct_cpu_track_user(int cpu)
{
	static __initdata bool initialized = false;

	if (!per_cpu(context_tracking.active, cpu)) {
		per_cpu(context_tracking.active, cpu) = true;
		static_branch_inc(&context_tracking_key);
	}

	if (initialized)
		return;

#ifdef CONFIG_HAVE_TIF_NOHZ
	/*
	set_tsk_thread_flag(&init_task, TIF_NOHZ);
#endif
	WARN_ON_ONCE(!tasklist_empty());

	initialized = true;
}

#ifdef CONFIG_CONTEXT_TRACKING_USER_FORCE
void __init context_tracking_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		ct_cpu_track_user(cpu);
}
#endif

#endif /* #ifdef CONFIG_CONTEXT_TRACKING_USER */
