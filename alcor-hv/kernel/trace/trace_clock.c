#include <linux/spinlock.h>
#include <linux/irqflags.h>
#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/ktime.h>
#include <linux/trace_clock.h>

u64 notrace trace_clock_local(void)
{
	u64 clock;

	/*
	preempt_disable_notrace();
	clock = sched_clock();
	preempt_enable_notrace();

	return clock;
}
EXPORT_SYMBOL_GPL(trace_clock_local);

u64 notrace trace_clock(void)
{
	return local_clock();
}
EXPORT_SYMBOL_GPL(trace_clock);

u64 notrace trace_clock_jiffies(void)
{
	return jiffies_64_to_clock_t(jiffies_64 - INITIAL_JIFFIES);
}
EXPORT_SYMBOL_GPL(trace_clock_jiffies);


static struct {
	u64 prev_time;
	arch_spinlock_t lock;
} trace_clock_struct ____cacheline_aligned_in_smp =
	{
		.lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED,
	};

u64 notrace trace_clock_global(void)
{
	unsigned long flags;
	int this_cpu;
	u64 now, prev_time;

	raw_local_irq_save(flags);

	this_cpu = raw_smp_processor_id();

	/*
	smp_rmb();
	prev_time = READ_ONCE(trace_clock_struct.prev_time);
	now = sched_clock_cpu(this_cpu);

	/* Make sure that now is always greater than or equal to prev_time */
	if ((s64)(now - prev_time) < 0)
		now = prev_time;

	/*
	if (unlikely(in_nmi()))
		goto out;

	/* Tracing can cause strange recursion, always use a try lock */
	if (arch_spin_trylock(&trace_clock_struct.lock)) {
		/* Reread prev_time in case it was already updated */
		prev_time = READ_ONCE(trace_clock_struct.prev_time);
		if ((s64)(now - prev_time) < 0)
			now = prev_time;

		trace_clock_struct.prev_time = now;

		/* The unlock acts as the wmb for the above rmb */
		arch_spin_unlock(&trace_clock_struct.lock);
	}
 out:
	raw_local_irq_restore(flags);

	return now;
}
EXPORT_SYMBOL_GPL(trace_clock_global);

static atomic64_t trace_counter;

u64 notrace trace_clock_counter(void)
{
	return atomic64_add_return(1, &trace_counter);
}
