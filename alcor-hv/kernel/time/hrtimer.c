
#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/hrtimer.h>
#include <linux/notifier.h>
#include <linux/syscalls.h>
#include <linux/interrupt.h>
#include <linux/tick.h>
#include <linux/err.h>
#include <linux/debugobjects.h>
#include <linux/sched/signal.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/sched/deadline.h>
#include <linux/sched/nohz.h>
#include <linux/sched/debug.h>
#include <linux/timer.h>
#include <linux/freezer.h>
#include <linux/compat.h>

#include <linux/uaccess.h>

#include <trace/events/timer.h>

#include "tick-internal.h"

#define MASK_SHIFT		(HRTIMER_BASE_MONOTONIC_SOFT)
#define HRTIMER_ACTIVE_HARD	((1U << MASK_SHIFT) - 1)
#define HRTIMER_ACTIVE_SOFT	(HRTIMER_ACTIVE_HARD << MASK_SHIFT)
#define HRTIMER_ACTIVE_ALL	(HRTIMER_ACTIVE_SOFT | HRTIMER_ACTIVE_HARD)

DEFINE_PER_CPU(struct hrtimer_cpu_base, hrtimer_bases) =
{
	.lock = __RAW_SPIN_LOCK_UNLOCKED(hrtimer_bases.lock),
	.clock_base =
	{
		{
			.index = HRTIMER_BASE_MONOTONIC,
			.clockid = CLOCK_MONOTONIC,
			.get_time = &ktime_get,
		},
		{
			.index = HRTIMER_BASE_REALTIME,
			.clockid = CLOCK_REALTIME,
			.get_time = &ktime_get_real,
		},
		{
			.index = HRTIMER_BASE_BOOTTIME,
			.clockid = CLOCK_BOOTTIME,
			.get_time = &ktime_get_boottime,
		},
		{
			.index = HRTIMER_BASE_TAI,
			.clockid = CLOCK_TAI,
			.get_time = &ktime_get_clocktai,
		},
		{
			.index = HRTIMER_BASE_MONOTONIC_SOFT,
			.clockid = CLOCK_MONOTONIC,
			.get_time = &ktime_get,
		},
		{
			.index = HRTIMER_BASE_REALTIME_SOFT,
			.clockid = CLOCK_REALTIME,
			.get_time = &ktime_get_real,
		},
		{
			.index = HRTIMER_BASE_BOOTTIME_SOFT,
			.clockid = CLOCK_BOOTTIME,
			.get_time = &ktime_get_boottime,
		},
		{
			.index = HRTIMER_BASE_TAI_SOFT,
			.clockid = CLOCK_TAI,
			.get_time = &ktime_get_clocktai,
		},
	}
};

static const int hrtimer_clock_to_base_table[MAX_CLOCKS] = {
	/* Make sure we catch unsupported clockids */
	[0 ... MAX_CLOCKS - 1]	= HRTIMER_MAX_CLOCK_BASES,

	[CLOCK_REALTIME]	= HRTIMER_BASE_REALTIME,
	[CLOCK_MONOTONIC]	= HRTIMER_BASE_MONOTONIC,
	[CLOCK_BOOTTIME]	= HRTIMER_BASE_BOOTTIME,
	[CLOCK_TAI]		= HRTIMER_BASE_TAI,
};

#ifdef CONFIG_SMP

static struct hrtimer_cpu_base migration_cpu_base = {
	.clock_base = { {
		.cpu_base = &migration_cpu_base,
		.seq      = SEQCNT_RAW_SPINLOCK_ZERO(migration_cpu_base.seq,
						     &migration_cpu_base.lock),
	}, },
};

#define migration_base	migration_cpu_base.clock_base[0]

static inline bool is_migration_base(struct hrtimer_clock_base *base)
{
	return base == &migration_base;
}

static
struct hrtimer_clock_base *lock_hrtimer_base(const struct hrtimer *timer,
					     unsigned long *flags)
{
	struct hrtimer_clock_base *base;

	for (;;) {
		base = READ_ONCE(timer->base);
		if (likely(base != &migration_base)) {
			raw_spin_lock_irqsave(&base->cpu_base->lock, *flags);
			if (likely(base == timer->base))
				return base;
			/* The timer has migrated to another CPU: */
			raw_spin_unlock_irqrestore(&base->cpu_base->lock, *flags);
		}
		cpu_relax();
	}
}

static int
hrtimer_check_target(struct hrtimer *timer, struct hrtimer_clock_base *new_base)
{
	ktime_t expires;

	expires = ktime_sub(hrtimer_get_expires(timer), new_base->offset);
	return expires < new_base->cpu_base->expires_next;
}

static inline
struct hrtimer_cpu_base *get_target_base(struct hrtimer_cpu_base *base,
					 int pinned)
{
#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
	if (static_branch_likely(&timers_migration_enabled) && !pinned)
		return &per_cpu(hrtimer_bases, get_nohz_timer_target());
#endif
	return base;
}

static inline struct hrtimer_clock_base *
switch_hrtimer_base(struct hrtimer *timer, struct hrtimer_clock_base *base,
		    int pinned)
{
	struct hrtimer_cpu_base *new_cpu_base, *this_cpu_base;
	struct hrtimer_clock_base *new_base;
	int basenum = base->index;

	this_cpu_base = this_cpu_ptr(&hrtimer_bases);
	new_cpu_base = get_target_base(this_cpu_base, pinned);
again:
	new_base = &new_cpu_base->clock_base[basenum];

	if (base != new_base) {
		/*
		if (unlikely(hrtimer_callback_running(timer)))
			return base;

		/* See the comment in lock_hrtimer_base() */
		WRITE_ONCE(timer->base, &migration_base);
		raw_spin_unlock(&base->cpu_base->lock);
		raw_spin_lock(&new_base->cpu_base->lock);

		if (new_cpu_base != this_cpu_base &&
		    hrtimer_check_target(timer, new_base)) {
			raw_spin_unlock(&new_base->cpu_base->lock);
			raw_spin_lock(&base->cpu_base->lock);
			new_cpu_base = this_cpu_base;
			WRITE_ONCE(timer->base, base);
			goto again;
		}
		WRITE_ONCE(timer->base, new_base);
	} else {
		if (new_cpu_base != this_cpu_base &&
		    hrtimer_check_target(timer, new_base)) {
			new_cpu_base = this_cpu_base;
			goto again;
		}
	}
	return new_base;
}

#else /* CONFIG_SMP */

static inline bool is_migration_base(struct hrtimer_clock_base *base)
{
	return false;
}

static inline struct hrtimer_clock_base *
lock_hrtimer_base(const struct hrtimer *timer, unsigned long *flags)
{
	struct hrtimer_clock_base *base = timer->base;

	raw_spin_lock_irqsave(&base->cpu_base->lock, *flags);

	return base;
}

# define switch_hrtimer_base(t, b, p)	(b)

#endif	/* !CONFIG_SMP */

#if BITS_PER_LONG < 64
s64 __ktime_divns(const ktime_t kt, s64 div)
{
	int sft = 0;
	s64 dclc;
	u64 tmp;

	dclc = ktime_to_ns(kt);
	tmp = dclc < 0 ? -dclc : dclc;

	/* Make sure the divisor is less than 2^32: */
	while (div >> 32) {
		sft++;
		div >>= 1;
	}
	tmp >>= sft;
	do_div(tmp, (u32) div);
	return dclc < 0 ? -tmp : tmp;
}
EXPORT_SYMBOL_GPL(__ktime_divns);
#endif /* BITS_PER_LONG >= 64 */

ktime_t ktime_add_safe(const ktime_t lhs, const ktime_t rhs)
{
	ktime_t res = ktime_add_unsafe(lhs, rhs);

	/*
	if (res < 0 || res < lhs || res < rhs)
		res = ktime_set(KTIME_SEC_MAX, 0);

	return res;
}

EXPORT_SYMBOL_GPL(ktime_add_safe);

#ifdef CONFIG_DEBUG_OBJECTS_TIMERS

static const struct debug_obj_descr hrtimer_debug_descr;

static void *hrtimer_debug_hint(void *addr)
{
	return ((struct hrtimer *) addr)->function;
}

static bool hrtimer_fixup_init(void *addr, enum debug_obj_state state)
{
	struct hrtimer *timer = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		hrtimer_cancel(timer);
		debug_object_init(timer, &hrtimer_debug_descr);
		return true;
	default:
		return false;
	}
}

static bool hrtimer_fixup_activate(void *addr, enum debug_obj_state state)
{
	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		WARN_ON(1);
		fallthrough;
	default:
		return false;
	}
}

static bool hrtimer_fixup_free(void *addr, enum debug_obj_state state)
{
	struct hrtimer *timer = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		hrtimer_cancel(timer);
		debug_object_free(timer, &hrtimer_debug_descr);
		return true;
	default:
		return false;
	}
}

static const struct debug_obj_descr hrtimer_debug_descr = {
	.name		= "hrtimer",
	.debug_hint	= hrtimer_debug_hint,
	.fixup_init	= hrtimer_fixup_init,
	.fixup_activate	= hrtimer_fixup_activate,
	.fixup_free	= hrtimer_fixup_free,
};

static inline void debug_hrtimer_init(struct hrtimer *timer)
{
	debug_object_init(timer, &hrtimer_debug_descr);
}

static inline void debug_hrtimer_activate(struct hrtimer *timer,
					  enum hrtimer_mode mode)
{
	debug_object_activate(timer, &hrtimer_debug_descr);
}

static inline void debug_hrtimer_deactivate(struct hrtimer *timer)
{
	debug_object_deactivate(timer, &hrtimer_debug_descr);
}

static void __hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
			   enum hrtimer_mode mode);

void hrtimer_init_on_stack(struct hrtimer *timer, clockid_t clock_id,
			   enum hrtimer_mode mode)
{
	debug_object_init_on_stack(timer, &hrtimer_debug_descr);
	__hrtimer_init(timer, clock_id, mode);
}
EXPORT_SYMBOL_GPL(hrtimer_init_on_stack);

static void __hrtimer_init_sleeper(struct hrtimer_sleeper *sl,
				   clockid_t clock_id, enum hrtimer_mode mode);

void hrtimer_init_sleeper_on_stack(struct hrtimer_sleeper *sl,
				   clockid_t clock_id, enum hrtimer_mode mode)
{
	debug_object_init_on_stack(&sl->timer, &hrtimer_debug_descr);
	__hrtimer_init_sleeper(sl, clock_id, mode);
}
EXPORT_SYMBOL_GPL(hrtimer_init_sleeper_on_stack);

void destroy_hrtimer_on_stack(struct hrtimer *timer)
{
	debug_object_free(timer, &hrtimer_debug_descr);
}
EXPORT_SYMBOL_GPL(destroy_hrtimer_on_stack);

#else

static inline void debug_hrtimer_init(struct hrtimer *timer) { }
static inline void debug_hrtimer_activate(struct hrtimer *timer,
					  enum hrtimer_mode mode) { }
static inline void debug_hrtimer_deactivate(struct hrtimer *timer) { }
#endif

static inline void
debug_init(struct hrtimer *timer, clockid_t clockid,
	   enum hrtimer_mode mode)
{
	debug_hrtimer_init(timer);
	trace_hrtimer_init(timer, clockid, mode);
}

static inline void debug_activate(struct hrtimer *timer,
				  enum hrtimer_mode mode)
{
	debug_hrtimer_activate(timer, mode);
	trace_hrtimer_start(timer, mode);
}

static inline void debug_deactivate(struct hrtimer *timer)
{
	debug_hrtimer_deactivate(timer);
	trace_hrtimer_cancel(timer);
}

static struct hrtimer_clock_base *
__next_base(struct hrtimer_cpu_base *cpu_base, unsigned int *active)
{
	unsigned int idx;

	if (!*active)
		return NULL;

	idx = __ffs(*active);

	return &cpu_base->clock_base[idx];
}

#define for_each_active_base(base, cpu_base, active)	\
	while ((base = __next_base((cpu_base), &(active))))

static ktime_t __hrtimer_next_event_base(struct hrtimer_cpu_base *cpu_base,
					 const struct hrtimer *exclude,
					 unsigned int active,
					 ktime_t expires_next)
{
	struct hrtimer_clock_base *base;
	ktime_t expires;

	for_each_active_base(base, cpu_base, active) {
		struct timerqueue_node *next;
		struct hrtimer *timer;

		next = timerqueue_getnext(&base->active);
		timer = container_of(next, struct hrtimer, node);
		if (timer == exclude) {
			/* Get to the next timer in the queue. */
			next = timerqueue_iterate_next(next);
			if (!next)
				continue;

			timer = container_of(next, struct hrtimer, node);
		}
		expires = ktime_sub(hrtimer_get_expires(timer), base->offset);
		if (expires < expires_next) {
			expires_next = expires;

			/* Skip cpu_base update if a timer is being excluded. */
			if (exclude)
				continue;

			if (timer->is_soft)
				cpu_base->softirq_next_timer = timer;
			else
				cpu_base->next_timer = timer;
		}
	}
	/*
	if (expires_next < 0)
		expires_next = 0;
	return expires_next;
}

static ktime_t
__hrtimer_get_next_event(struct hrtimer_cpu_base *cpu_base, unsigned int active_mask)
{
	unsigned int active;
	struct hrtimer *next_timer = NULL;
	ktime_t expires_next = KTIME_MAX;

	if (!cpu_base->softirq_activated && (active_mask & HRTIMER_ACTIVE_SOFT)) {
		active = cpu_base->active_bases & HRTIMER_ACTIVE_SOFT;
		cpu_base->softirq_next_timer = NULL;
		expires_next = __hrtimer_next_event_base(cpu_base, NULL,
							 active, KTIME_MAX);

		next_timer = cpu_base->softirq_next_timer;
	}

	if (active_mask & HRTIMER_ACTIVE_HARD) {
		active = cpu_base->active_bases & HRTIMER_ACTIVE_HARD;
		cpu_base->next_timer = next_timer;
		expires_next = __hrtimer_next_event_base(cpu_base, NULL, active,
							 expires_next);
	}

	return expires_next;
}

static ktime_t hrtimer_update_next_event(struct hrtimer_cpu_base *cpu_base)
{
	ktime_t expires_next, soft = KTIME_MAX;

	/*
	if (!cpu_base->softirq_activated) {
		soft = __hrtimer_get_next_event(cpu_base, HRTIMER_ACTIVE_SOFT);
		/*
		cpu_base->softirq_expires_next = soft;
	}

	expires_next = __hrtimer_get_next_event(cpu_base, HRTIMER_ACTIVE_HARD);
	/*
	if (expires_next > soft) {
		cpu_base->next_timer = cpu_base->softirq_next_timer;
		expires_next = soft;
	}

	return expires_next;
}

static inline ktime_t hrtimer_update_base(struct hrtimer_cpu_base *base)
{
	ktime_t *offs_real = &base->clock_base[HRTIMER_BASE_REALTIME].offset;
	ktime_t *offs_boot = &base->clock_base[HRTIMER_BASE_BOOTTIME].offset;
	ktime_t *offs_tai = &base->clock_base[HRTIMER_BASE_TAI].offset;

	ktime_t now = ktime_get_update_offsets_now(&base->clock_was_set_seq,
					    offs_real, offs_boot, offs_tai);

	base->clock_base[HRTIMER_BASE_REALTIME_SOFT].offset = *offs_real;
	base->clock_base[HRTIMER_BASE_BOOTTIME_SOFT].offset = *offs_boot;
	base->clock_base[HRTIMER_BASE_TAI_SOFT].offset = *offs_tai;

	return now;
}

static inline int __hrtimer_hres_active(struct hrtimer_cpu_base *cpu_base)
{
	return IS_ENABLED(CONFIG_HIGH_RES_TIMERS) ?
		cpu_base->hres_active : 0;
}

static inline int hrtimer_hres_active(void)
{
	return __hrtimer_hres_active(this_cpu_ptr(&hrtimer_bases));
}

static void __hrtimer_reprogram(struct hrtimer_cpu_base *cpu_base,
				struct hrtimer *next_timer,
				ktime_t expires_next)
{
	cpu_base->expires_next = expires_next;

	/*
	if (!__hrtimer_hres_active(cpu_base) || cpu_base->hang_detected)
		return;

	tick_program_event(expires_next, 1);
}

static void
hrtimer_force_reprogram(struct hrtimer_cpu_base *cpu_base, int skip_equal)
{
	ktime_t expires_next;

	expires_next = hrtimer_update_next_event(cpu_base);

	if (skip_equal && expires_next == cpu_base->expires_next)
		return;

	__hrtimer_reprogram(cpu_base, cpu_base->next_timer, expires_next);
}

#ifdef CONFIG_HIGH_RES_TIMERS

static bool hrtimer_hres_enabled __read_mostly  = true;
unsigned int hrtimer_resolution __read_mostly = LOW_RES_NSEC;
EXPORT_SYMBOL_GPL(hrtimer_resolution);

static int __init setup_hrtimer_hres(char *str)
{
	return (kstrtobool(str, &hrtimer_hres_enabled) == 0);
}

__setup("highres=", setup_hrtimer_hres);

static inline int hrtimer_is_hres_enabled(void)
{
	return hrtimer_hres_enabled;
}

static void retrigger_next_event(void *arg);

static void hrtimer_switch_to_hres(void)
{
	struct hrtimer_cpu_base *base = this_cpu_ptr(&hrtimer_bases);

	if (tick_init_highres()) {
		pr_warn("Could not switch to high resolution mode on CPU %u\n",
			base->cpu);
		return;
	}
	base->hres_active = 1;
	hrtimer_resolution = HIGH_RES_NSEC;

	tick_setup_sched_timer();
	/* "Retrigger" the interrupt to get things going */
	retrigger_next_event(NULL);
}

#else

static inline int hrtimer_is_hres_enabled(void) { return 0; }
static inline void hrtimer_switch_to_hres(void) { }

#endif /* CONFIG_HIGH_RES_TIMERS */
static void retrigger_next_event(void *arg)
{
	struct hrtimer_cpu_base *base = this_cpu_ptr(&hrtimer_bases);

	/*
	if (!__hrtimer_hres_active(base) && !tick_nohz_active)
		return;

	raw_spin_lock(&base->lock);
	hrtimer_update_base(base);
	if (__hrtimer_hres_active(base))
		hrtimer_force_reprogram(base, 0);
	else
		hrtimer_update_next_event(base);
	raw_spin_unlock(&base->lock);
}

static void hrtimer_reprogram(struct hrtimer *timer, bool reprogram)
{
	struct hrtimer_cpu_base *cpu_base = this_cpu_ptr(&hrtimer_bases);
	struct hrtimer_clock_base *base = timer->base;
	ktime_t expires = ktime_sub(hrtimer_get_expires(timer), base->offset);

	WARN_ON_ONCE(hrtimer_get_expires_tv64(timer) < 0);

	/*
	if (expires < 0)
		expires = 0;

	if (timer->is_soft) {
		/*
		struct hrtimer_cpu_base *timer_cpu_base = base->cpu_base;

		if (timer_cpu_base->softirq_activated)
			return;

		if (!ktime_before(expires, timer_cpu_base->softirq_expires_next))
			return;

		timer_cpu_base->softirq_next_timer = timer;
		timer_cpu_base->softirq_expires_next = expires;

		if (!ktime_before(expires, timer_cpu_base->expires_next) ||
		    !reprogram)
			return;
	}

	/*
	if (base->cpu_base != cpu_base)
		return;

	if (expires >= cpu_base->expires_next)
		return;

	/*
	if (cpu_base->in_hrtirq)
		return;

	cpu_base->next_timer = timer;

	__hrtimer_reprogram(cpu_base, timer, expires);
}

static bool update_needs_ipi(struct hrtimer_cpu_base *cpu_base,
			     unsigned int active)
{
	struct hrtimer_clock_base *base;
	unsigned int seq;
	ktime_t expires;

	/*
	seq = cpu_base->clock_was_set_seq;
	hrtimer_update_base(cpu_base);

	/*
	if (seq == cpu_base->clock_was_set_seq)
		return false;

	/*
	if (cpu_base->in_hrtirq)
		return false;

	/*
	active &= cpu_base->active_bases;

	for_each_active_base(base, cpu_base, active) {
		struct timerqueue_node *next;

		next = timerqueue_getnext(&base->active);
		expires = ktime_sub(next->expires, base->offset);
		if (expires < cpu_base->expires_next)
			return true;

		/* Extra check for softirq clock bases */
		if (base->clockid < HRTIMER_BASE_MONOTONIC_SOFT)
			continue;
		if (cpu_base->softirq_activated)
			continue;
		if (expires < cpu_base->softirq_expires_next)
			return true;
	}
	return false;
}

void clock_was_set(unsigned int bases)
{
	struct hrtimer_cpu_base *cpu_base = raw_cpu_ptr(&hrtimer_bases);
	cpumask_var_t mask;
	int cpu;

	if (!__hrtimer_hres_active(cpu_base) && !tick_nohz_active)
		goto out_timerfd;

	if (!zalloc_cpumask_var(&mask, GFP_KERNEL)) {
		on_each_cpu(retrigger_next_event, NULL, 1);
		goto out_timerfd;
	}

	/* Avoid interrupting CPUs if possible */
	cpus_read_lock();
	for_each_online_cpu(cpu) {
		unsigned long flags;

		cpu_base = &per_cpu(hrtimer_bases, cpu);
		raw_spin_lock_irqsave(&cpu_base->lock, flags);

		if (update_needs_ipi(cpu_base, bases))
			cpumask_set_cpu(cpu, mask);

		raw_spin_unlock_irqrestore(&cpu_base->lock, flags);
	}

	preempt_disable();
	smp_call_function_many(mask, retrigger_next_event, NULL, 1);
	preempt_enable();
	cpus_read_unlock();
	free_cpumask_var(mask);

out_timerfd:
	timerfd_clock_was_set();
}

static void clock_was_set_work(struct work_struct *work)
{
	clock_was_set(CLOCK_SET_WALL);
}

static DECLARE_WORK(hrtimer_work, clock_was_set_work);

void clock_was_set_delayed(void)
{
	schedule_work(&hrtimer_work);
}

void hrtimers_resume_local(void)
{
	lockdep_assert_irqs_disabled();
	/* Retrigger on the local CPU */
	retrigger_next_event(NULL);
}

static inline
void unlock_hrtimer_base(const struct hrtimer *timer, unsigned long *flags)
{
	raw_spin_unlock_irqrestore(&timer->base->cpu_base->lock, *flags);
}

u64 hrtimer_forward(struct hrtimer *timer, ktime_t now, ktime_t interval)
{
	u64 orun = 1;
	ktime_t delta;

	delta = ktime_sub(now, hrtimer_get_expires(timer));

	if (delta < 0)
		return 0;

	if (WARN_ON(timer->state & HRTIMER_STATE_ENQUEUED))
		return 0;

	if (interval < hrtimer_resolution)
		interval = hrtimer_resolution;

	if (unlikely(delta >= interval)) {
		s64 incr = ktime_to_ns(interval);

		orun = ktime_divns(delta, incr);
		hrtimer_add_expires_ns(timer, incr * orun);
		if (hrtimer_get_expires_tv64(timer) > now)
			return orun;
		/*
		orun++;
	}
	hrtimer_add_expires(timer, interval);

	return orun;
}
EXPORT_SYMBOL_GPL(hrtimer_forward);

static int enqueue_hrtimer(struct hrtimer *timer,
			   struct hrtimer_clock_base *base,
			   enum hrtimer_mode mode)
{
	debug_activate(timer, mode);

	base->cpu_base->active_bases |= 1 << base->index;

	/* Pairs with the lockless read in hrtimer_is_queued() */
	WRITE_ONCE(timer->state, HRTIMER_STATE_ENQUEUED);

	return timerqueue_add(&base->active, &timer->node);
}

static void __remove_hrtimer(struct hrtimer *timer,
			     struct hrtimer_clock_base *base,
			     u8 newstate, int reprogram)
{
	struct hrtimer_cpu_base *cpu_base = base->cpu_base;
	u8 state = timer->state;

	/* Pairs with the lockless read in hrtimer_is_queued() */
	WRITE_ONCE(timer->state, newstate);
	if (!(state & HRTIMER_STATE_ENQUEUED))
		return;

	if (!timerqueue_del(&base->active, &timer->node))
		cpu_base->active_bases &= ~(1 << base->index);

	/*
	if (reprogram && timer == cpu_base->next_timer)
		hrtimer_force_reprogram(cpu_base, 1);
}

static inline int
remove_hrtimer(struct hrtimer *timer, struct hrtimer_clock_base *base,
	       bool restart, bool keep_local)
{
	u8 state = timer->state;

	if (state & HRTIMER_STATE_ENQUEUED) {
		bool reprogram;

		/*
		debug_deactivate(timer);
		reprogram = base->cpu_base == this_cpu_ptr(&hrtimer_bases);

		/*
		if (!restart)
			state = HRTIMER_STATE_INACTIVE;
		else
			reprogram &= !keep_local;

		__remove_hrtimer(timer, base, state, reprogram);
		return 1;
	}
	return 0;
}

static inline ktime_t hrtimer_update_lowres(struct hrtimer *timer, ktime_t tim,
					    const enum hrtimer_mode mode)
{
#ifdef CONFIG_TIME_LOW_RES
	/*
	timer->is_rel = mode & HRTIMER_MODE_REL;
	if (timer->is_rel)
		tim = ktime_add_safe(tim, hrtimer_resolution);
#endif
	return tim;
}

static void
hrtimer_update_softirq_timer(struct hrtimer_cpu_base *cpu_base, bool reprogram)
{
	ktime_t expires;

	/*
	expires = __hrtimer_get_next_event(cpu_base, HRTIMER_ACTIVE_SOFT);

	/*
	if (expires == KTIME_MAX)
		return;

	/*
	hrtimer_reprogram(cpu_base->softirq_next_timer, reprogram);
}

static int __hrtimer_start_range_ns(struct hrtimer *timer, ktime_t tim,
				    u64 delta_ns, const enum hrtimer_mode mode,
				    struct hrtimer_clock_base *base)
{
	struct hrtimer_clock_base *new_base;
	bool force_local, first;

	/*
	force_local = base->cpu_base == this_cpu_ptr(&hrtimer_bases);
	force_local &= base->cpu_base->next_timer == timer;

	/*
	remove_hrtimer(timer, base, true, force_local);

	if (mode & HRTIMER_MODE_REL)
		tim = ktime_add_safe(tim, base->get_time());

	tim = hrtimer_update_lowres(timer, tim, mode);

	hrtimer_set_expires_range_ns(timer, tim, delta_ns);

	/* Switch the timer base, if necessary: */
	if (!force_local) {
		new_base = switch_hrtimer_base(timer, base,
					       mode & HRTIMER_MODE_PINNED);
	} else {
		new_base = base;
	}

	first = enqueue_hrtimer(timer, new_base, mode);
	if (!force_local)
		return first;

	/*
	hrtimer_force_reprogram(new_base->cpu_base, 1);
	return 0;
}

void hrtimer_start_range_ns(struct hrtimer *timer, ktime_t tim,
			    u64 delta_ns, const enum hrtimer_mode mode)
{
	struct hrtimer_clock_base *base;
	unsigned long flags;

	/*
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
		WARN_ON_ONCE(!(mode & HRTIMER_MODE_SOFT) ^ !timer->is_soft);
	else
		WARN_ON_ONCE(!(mode & HRTIMER_MODE_HARD) ^ !timer->is_hard);

	base = lock_hrtimer_base(timer, &flags);

	if (__hrtimer_start_range_ns(timer, tim, delta_ns, mode, base))
		hrtimer_reprogram(timer, true);

	unlock_hrtimer_base(timer, &flags);
}
EXPORT_SYMBOL_GPL(hrtimer_start_range_ns);

int hrtimer_try_to_cancel(struct hrtimer *timer)
{
	struct hrtimer_clock_base *base;
	unsigned long flags;
	int ret = -1;

	/*
	if (!hrtimer_active(timer))
		return 0;

	base = lock_hrtimer_base(timer, &flags);

	if (!hrtimer_callback_running(timer))
		ret = remove_hrtimer(timer, base, false, false);

	unlock_hrtimer_base(timer, &flags);

	return ret;

}
EXPORT_SYMBOL_GPL(hrtimer_try_to_cancel);

#ifdef CONFIG_PREEMPT_RT
static void hrtimer_cpu_base_init_expiry_lock(struct hrtimer_cpu_base *base)
{
	spin_lock_init(&base->softirq_expiry_lock);
}

static void hrtimer_cpu_base_lock_expiry(struct hrtimer_cpu_base *base)
{
	spin_lock(&base->softirq_expiry_lock);
}

static void hrtimer_cpu_base_unlock_expiry(struct hrtimer_cpu_base *base)
{
	spin_unlock(&base->softirq_expiry_lock);
}

static void hrtimer_sync_wait_running(struct hrtimer_cpu_base *cpu_base,
				      unsigned long flags)
{
	if (atomic_read(&cpu_base->timer_waiters)) {
		raw_spin_unlock_irqrestore(&cpu_base->lock, flags);
		spin_unlock(&cpu_base->softirq_expiry_lock);
		spin_lock(&cpu_base->softirq_expiry_lock);
		raw_spin_lock_irq(&cpu_base->lock);
	}
}

void hrtimer_cancel_wait_running(const struct hrtimer *timer)
{
	/* Lockless read. Prevent the compiler from reloading it below */
	struct hrtimer_clock_base *base = READ_ONCE(timer->base);

	/*
	if (!timer->is_soft || is_migration_base(base)) {
		cpu_relax();
		return;
	}

	/*
	atomic_inc(&base->cpu_base->timer_waiters);
	spin_lock_bh(&base->cpu_base->softirq_expiry_lock);
	atomic_dec(&base->cpu_base->timer_waiters);
	spin_unlock_bh(&base->cpu_base->softirq_expiry_lock);
}
#else
static inline void
hrtimer_cpu_base_init_expiry_lock(struct hrtimer_cpu_base *base) { }
static inline void
hrtimer_cpu_base_lock_expiry(struct hrtimer_cpu_base *base) { }
static inline void
hrtimer_cpu_base_unlock_expiry(struct hrtimer_cpu_base *base) { }
static inline void hrtimer_sync_wait_running(struct hrtimer_cpu_base *base,
					     unsigned long flags) { }
#endif

int hrtimer_cancel(struct hrtimer *timer)
{
	int ret;

	do {
		ret = hrtimer_try_to_cancel(timer);

		if (ret < 0)
			hrtimer_cancel_wait_running(timer);
	} while (ret < 0);
	return ret;
}
EXPORT_SYMBOL_GPL(hrtimer_cancel);

ktime_t __hrtimer_get_remaining(const struct hrtimer *timer, bool adjust)
{
	unsigned long flags;
	ktime_t rem;

	lock_hrtimer_base(timer, &flags);
	if (IS_ENABLED(CONFIG_TIME_LOW_RES) && adjust)
		rem = hrtimer_expires_remaining_adjusted(timer);
	else
		rem = hrtimer_expires_remaining(timer);
	unlock_hrtimer_base(timer, &flags);

	return rem;
}
EXPORT_SYMBOL_GPL(__hrtimer_get_remaining);

#ifdef CONFIG_NO_HZ_COMMON
u64 hrtimer_get_next_event(void)
{
	struct hrtimer_cpu_base *cpu_base = this_cpu_ptr(&hrtimer_bases);
	u64 expires = KTIME_MAX;
	unsigned long flags;

	raw_spin_lock_irqsave(&cpu_base->lock, flags);

	if (!__hrtimer_hres_active(cpu_base))
		expires = __hrtimer_get_next_event(cpu_base, HRTIMER_ACTIVE_ALL);

	raw_spin_unlock_irqrestore(&cpu_base->lock, flags);

	return expires;
}

u64 hrtimer_next_event_without(const struct hrtimer *exclude)
{
	struct hrtimer_cpu_base *cpu_base = this_cpu_ptr(&hrtimer_bases);
	u64 expires = KTIME_MAX;
	unsigned long flags;

	raw_spin_lock_irqsave(&cpu_base->lock, flags);

	if (__hrtimer_hres_active(cpu_base)) {
		unsigned int active;

		if (!cpu_base->softirq_activated) {
			active = cpu_base->active_bases & HRTIMER_ACTIVE_SOFT;
			expires = __hrtimer_next_event_base(cpu_base, exclude,
							    active, KTIME_MAX);
		}
		active = cpu_base->active_bases & HRTIMER_ACTIVE_HARD;
		expires = __hrtimer_next_event_base(cpu_base, exclude, active,
						    expires);
	}

	raw_spin_unlock_irqrestore(&cpu_base->lock, flags);

	return expires;
}
#endif

static inline int hrtimer_clockid_to_base(clockid_t clock_id)
{
	if (likely(clock_id < MAX_CLOCKS)) {
		int base = hrtimer_clock_to_base_table[clock_id];

		if (likely(base != HRTIMER_MAX_CLOCK_BASES))
			return base;
	}
	WARN(1, "Invalid clockid %d. Using MONOTONIC\n", clock_id);
	return HRTIMER_BASE_MONOTONIC;
}

static void __hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
			   enum hrtimer_mode mode)
{
	bool softtimer = !!(mode & HRTIMER_MODE_SOFT);
	struct hrtimer_cpu_base *cpu_base;
	int base;

	/*
	if (IS_ENABLED(CONFIG_PREEMPT_RT) && !(mode & HRTIMER_MODE_HARD))
		softtimer = true;

	memset(timer, 0, sizeof(struct hrtimer));

	cpu_base = raw_cpu_ptr(&hrtimer_bases);

	/*
	if (clock_id == CLOCK_REALTIME && mode & HRTIMER_MODE_REL)
		clock_id = CLOCK_MONOTONIC;

	base = softtimer ? HRTIMER_MAX_CLOCK_BASES / 2 : 0;
	base += hrtimer_clockid_to_base(clock_id);
	timer->is_soft = softtimer;
	timer->is_hard = !!(mode & HRTIMER_MODE_HARD);
	timer->base = &cpu_base->clock_base[base];
	timerqueue_init(&timer->node);
}

void hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
		  enum hrtimer_mode mode)
{
	debug_init(timer, clock_id, mode);
	__hrtimer_init(timer, clock_id, mode);
}
EXPORT_SYMBOL_GPL(hrtimer_init);

bool hrtimer_active(const struct hrtimer *timer)
{
	struct hrtimer_clock_base *base;
	unsigned int seq;

	do {
		base = READ_ONCE(timer->base);
		seq = raw_read_seqcount_begin(&base->seq);

		if (timer->state != HRTIMER_STATE_INACTIVE ||
		    base->running == timer)
			return true;

	} while (read_seqcount_retry(&base->seq, seq) ||
		 base != READ_ONCE(timer->base));

	return false;
}
EXPORT_SYMBOL_GPL(hrtimer_active);


static void __run_hrtimer(struct hrtimer_cpu_base *cpu_base,
			  struct hrtimer_clock_base *base,
			  struct hrtimer *timer, ktime_t *now,
			  unsigned long flags) __must_hold(&cpu_base->lock)
{
	enum hrtimer_restart (*fn)(struct hrtimer *);
	bool expires_in_hardirq;
	int restart;

	lockdep_assert_held(&cpu_base->lock);

	debug_deactivate(timer);
	base->running = timer;

	/*
	raw_write_seqcount_barrier(&base->seq);

	__remove_hrtimer(timer, base, HRTIMER_STATE_INACTIVE, 0);
	fn = timer->function;

	/*
	if (IS_ENABLED(CONFIG_TIME_LOW_RES))
		timer->is_rel = false;

	/*
	raw_spin_unlock_irqrestore(&cpu_base->lock, flags);
	trace_hrtimer_expire_entry(timer, now);
	expires_in_hardirq = lockdep_hrtimer_enter(timer);

	restart = fn(timer);

	lockdep_hrtimer_exit(expires_in_hardirq);
	trace_hrtimer_expire_exit(timer);
	raw_spin_lock_irq(&cpu_base->lock);

	/*
	if (restart != HRTIMER_NORESTART &&
	    !(timer->state & HRTIMER_STATE_ENQUEUED))
		enqueue_hrtimer(timer, base, HRTIMER_MODE_ABS);

	/*
	raw_write_seqcount_barrier(&base->seq);

	WARN_ON_ONCE(base->running != timer);
	base->running = NULL;
}

static void __hrtimer_run_queues(struct hrtimer_cpu_base *cpu_base, ktime_t now,
				 unsigned long flags, unsigned int active_mask)
{
	struct hrtimer_clock_base *base;
	unsigned int active = cpu_base->active_bases & active_mask;

	for_each_active_base(base, cpu_base, active) {
		struct timerqueue_node *node;
		ktime_t basenow;

		basenow = ktime_add(now, base->offset);

		while ((node = timerqueue_getnext(&base->active))) {
			struct hrtimer *timer;

			timer = container_of(node, struct hrtimer, node);

			/*
			if (basenow < hrtimer_get_softexpires_tv64(timer))
				break;

			__run_hrtimer(cpu_base, base, timer, &basenow, flags);
			if (active_mask == HRTIMER_ACTIVE_SOFT)
				hrtimer_sync_wait_running(cpu_base, flags);
		}
	}
}

static __latent_entropy void hrtimer_run_softirq(struct softirq_action *h)
{
	struct hrtimer_cpu_base *cpu_base = this_cpu_ptr(&hrtimer_bases);
	unsigned long flags;
	ktime_t now;

	hrtimer_cpu_base_lock_expiry(cpu_base);
	raw_spin_lock_irqsave(&cpu_base->lock, flags);

	now = hrtimer_update_base(cpu_base);
	__hrtimer_run_queues(cpu_base, now, flags, HRTIMER_ACTIVE_SOFT);

	cpu_base->softirq_activated = 0;
	hrtimer_update_softirq_timer(cpu_base, true);

	raw_spin_unlock_irqrestore(&cpu_base->lock, flags);
	hrtimer_cpu_base_unlock_expiry(cpu_base);
}

#ifdef CONFIG_HIGH_RES_TIMERS

void hrtimer_interrupt(struct clock_event_device *dev)
{
	struct hrtimer_cpu_base *cpu_base = this_cpu_ptr(&hrtimer_bases);
	ktime_t expires_next, now, entry_time, delta;
	unsigned long flags;
	int retries = 0;

	BUG_ON(!cpu_base->hres_active);
	cpu_base->nr_events++;
	dev->next_event = KTIME_MAX;

	raw_spin_lock_irqsave(&cpu_base->lock, flags);
	entry_time = now = hrtimer_update_base(cpu_base);
retry:
	cpu_base->in_hrtirq = 1;
	/*
	cpu_base->expires_next = KTIME_MAX;

	if (!ktime_before(now, cpu_base->softirq_expires_next)) {
		cpu_base->softirq_expires_next = KTIME_MAX;
		cpu_base->softirq_activated = 1;
		raise_softirq_irqoff(HRTIMER_SOFTIRQ);
	}

	__hrtimer_run_queues(cpu_base, now, flags, HRTIMER_ACTIVE_HARD);

	/* Reevaluate the clock bases for the [soft] next expiry */
	expires_next = hrtimer_update_next_event(cpu_base);
	/*
	cpu_base->expires_next = expires_next;
	cpu_base->in_hrtirq = 0;
	raw_spin_unlock_irqrestore(&cpu_base->lock, flags);

	/* Reprogramming necessary ? */
	if (!tick_program_event(expires_next, 0)) {
		cpu_base->hang_detected = 0;
		return;
	}

	/*
	raw_spin_lock_irqsave(&cpu_base->lock, flags);
	now = hrtimer_update_base(cpu_base);
	cpu_base->nr_retries++;
	if (++retries < 3)
		goto retry;
	/*
	cpu_base->nr_hangs++;
	cpu_base->hang_detected = 1;
	raw_spin_unlock_irqrestore(&cpu_base->lock, flags);

	delta = ktime_sub(now, entry_time);
	if ((unsigned int)delta > cpu_base->max_hang_time)
		cpu_base->max_hang_time = (unsigned int) delta;
	/*
	if (delta > 100 * NSEC_PER_MSEC)
		expires_next = ktime_add_ns(now, 100 * NSEC_PER_MSEC);
	else
		expires_next = ktime_add(now, delta);
	tick_program_event(expires_next, 1);
	pr_warn_once("hrtimer: interrupt took %llu ns\n", ktime_to_ns(delta));
}

static inline void __hrtimer_peek_ahead_timers(void)
{
	struct tick_device *td;

	if (!hrtimer_hres_active())
		return;

	td = this_cpu_ptr(&tick_cpu_device);
	if (td && td->evtdev)
		hrtimer_interrupt(td->evtdev);
}

#else /* CONFIG_HIGH_RES_TIMERS */

static inline void __hrtimer_peek_ahead_timers(void) { }

#endif	/* !CONFIG_HIGH_RES_TIMERS */

void hrtimer_run_queues(void)
{
	struct hrtimer_cpu_base *cpu_base = this_cpu_ptr(&hrtimer_bases);
	unsigned long flags;
	ktime_t now;

	if (__hrtimer_hres_active(cpu_base))
		return;

	/*
	if (tick_check_oneshot_change(!hrtimer_is_hres_enabled())) {
		hrtimer_switch_to_hres();
		return;
	}

	raw_spin_lock_irqsave(&cpu_base->lock, flags);
	now = hrtimer_update_base(cpu_base);

	if (!ktime_before(now, cpu_base->softirq_expires_next)) {
		cpu_base->softirq_expires_next = KTIME_MAX;
		cpu_base->softirq_activated = 1;
		raise_softirq_irqoff(HRTIMER_SOFTIRQ);
	}

	__hrtimer_run_queues(cpu_base, now, flags, HRTIMER_ACTIVE_HARD);
	raw_spin_unlock_irqrestore(&cpu_base->lock, flags);
}

static enum hrtimer_restart hrtimer_wakeup(struct hrtimer *timer)
{
	struct hrtimer_sleeper *t =
		container_of(timer, struct hrtimer_sleeper, timer);
	struct task_struct *task = t->task;

	t->task = NULL;
	if (task)
		wake_up_process(task);

	return HRTIMER_NORESTART;
}

void hrtimer_sleeper_start_expires(struct hrtimer_sleeper *sl,
				   enum hrtimer_mode mode)
{
	/*
	if (IS_ENABLED(CONFIG_PREEMPT_RT) && sl->timer.is_hard)
		mode |= HRTIMER_MODE_HARD;

	hrtimer_start_expires(&sl->timer, mode);
}
EXPORT_SYMBOL_GPL(hrtimer_sleeper_start_expires);

static void __hrtimer_init_sleeper(struct hrtimer_sleeper *sl,
				   clockid_t clock_id, enum hrtimer_mode mode)
{
	/*
	if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
		if (task_is_realtime(current) && !(mode & HRTIMER_MODE_SOFT))
			mode |= HRTIMER_MODE_HARD;
	}

	__hrtimer_init(&sl->timer, clock_id, mode);
	sl->timer.function = hrtimer_wakeup;
	sl->task = current;
}

void hrtimer_init_sleeper(struct hrtimer_sleeper *sl, clockid_t clock_id,
			  enum hrtimer_mode mode)
{
	debug_init(&sl->timer, clock_id, mode);
	__hrtimer_init_sleeper(sl, clock_id, mode);

}
EXPORT_SYMBOL_GPL(hrtimer_init_sleeper);

int nanosleep_copyout(struct restart_block *restart, struct timespec64 *ts)
{
	switch(restart->nanosleep.type) {
#ifdef CONFIG_COMPAT_32BIT_TIME
	case TT_COMPAT:
		if (put_old_timespec32(ts, restart->nanosleep.compat_rmtp))
			return -EFAULT;
		break;
#endif
	case TT_NATIVE:
		if (put_timespec64(ts, restart->nanosleep.rmtp))
			return -EFAULT;
		break;
	default:
		BUG();
	}
	return -ERESTART_RESTARTBLOCK;
}

static int __sched do_nanosleep(struct hrtimer_sleeper *t, enum hrtimer_mode mode)
{
	struct restart_block *restart;

	do {
		set_current_state(TASK_INTERRUPTIBLE);
		hrtimer_sleeper_start_expires(t, mode);

		if (likely(t->task))
			freezable_schedule();

		hrtimer_cancel(&t->timer);
		mode = HRTIMER_MODE_ABS;

	} while (t->task && !signal_pending(current));

	__set_current_state(TASK_RUNNING);

	if (!t->task)
		return 0;

	restart = &current->restart_block;
	if (restart->nanosleep.type != TT_NONE) {
		ktime_t rem = hrtimer_expires_remaining(&t->timer);
		struct timespec64 rmt;

		if (rem <= 0)
			return 0;
		rmt = ktime_to_timespec64(rem);

		return nanosleep_copyout(restart, &rmt);
	}
	return -ERESTART_RESTARTBLOCK;
}

static long __sched hrtimer_nanosleep_restart(struct restart_block *restart)
{
	struct hrtimer_sleeper t;
	int ret;

	hrtimer_init_sleeper_on_stack(&t, restart->nanosleep.clockid,
				      HRTIMER_MODE_ABS);
	hrtimer_set_expires_tv64(&t.timer, restart->nanosleep.expires);
	ret = do_nanosleep(&t, HRTIMER_MODE_ABS);
	destroy_hrtimer_on_stack(&t.timer);
	return ret;
}

long hrtimer_nanosleep(ktime_t rqtp, const enum hrtimer_mode mode,
		       const clockid_t clockid)
{
	struct restart_block *restart;
	struct hrtimer_sleeper t;
	int ret = 0;
	u64 slack;

	slack = current->timer_slack_ns;
	if (dl_task(current) || rt_task(current))
		slack = 0;

	hrtimer_init_sleeper_on_stack(&t, clockid, mode);
	hrtimer_set_expires_range_ns(&t.timer, rqtp, slack);
	ret = do_nanosleep(&t, mode);
	if (ret != -ERESTART_RESTARTBLOCK)
		goto out;

	/* Absolute timers do not update the rmtp value and restart: */
	if (mode == HRTIMER_MODE_ABS) {
		ret = -ERESTARTNOHAND;
		goto out;
	}

	restart = &current->restart_block;
	restart->nanosleep.clockid = t.timer.base->clockid;
	restart->nanosleep.expires = hrtimer_get_expires_tv64(&t.timer);
	set_restart_fn(restart, hrtimer_nanosleep_restart);
out:
	destroy_hrtimer_on_stack(&t.timer);
	return ret;
}

#ifdef CONFIG_64BIT

SYSCALL_DEFINE2(nanosleep, struct __kernel_timespec __user *, rqtp,
		struct __kernel_timespec __user *, rmtp)
{
	struct timespec64 tu;

	if (get_timespec64(&tu, rqtp))
		return -EFAULT;

	if (!timespec64_valid(&tu))
		return -EINVAL;

	current->restart_block.nanosleep.type = rmtp ? TT_NATIVE : TT_NONE;
	current->restart_block.nanosleep.rmtp = rmtp;
	return hrtimer_nanosleep(timespec64_to_ktime(tu), HRTIMER_MODE_REL,
				 CLOCK_MONOTONIC);
}

#endif

#ifdef CONFIG_COMPAT_32BIT_TIME

SYSCALL_DEFINE2(nanosleep_time32, struct old_timespec32 __user *, rqtp,
		       struct old_timespec32 __user *, rmtp)
{
	struct timespec64 tu;

	if (get_old_timespec32(&tu, rqtp))
		return -EFAULT;

	if (!timespec64_valid(&tu))
		return -EINVAL;

	current->restart_block.nanosleep.type = rmtp ? TT_COMPAT : TT_NONE;
	current->restart_block.nanosleep.compat_rmtp = rmtp;
	return hrtimer_nanosleep(timespec64_to_ktime(tu), HRTIMER_MODE_REL,
				 CLOCK_MONOTONIC);
}
#endif

int hrtimers_prepare_cpu(unsigned int cpu)
{
	struct hrtimer_cpu_base *cpu_base = &per_cpu(hrtimer_bases, cpu);
	int i;

	for (i = 0; i < HRTIMER_MAX_CLOCK_BASES; i++) {
		struct hrtimer_clock_base *clock_b = &cpu_base->clock_base[i];

		clock_b->cpu_base = cpu_base;
		seqcount_raw_spinlock_init(&clock_b->seq, &cpu_base->lock);
		timerqueue_init_head(&clock_b->active);
	}

	cpu_base->cpu = cpu;
	cpu_base->active_bases = 0;
	cpu_base->hres_active = 0;
	cpu_base->hang_detected = 0;
	cpu_base->next_timer = NULL;
	cpu_base->softirq_next_timer = NULL;
	cpu_base->expires_next = KTIME_MAX;
	cpu_base->softirq_expires_next = KTIME_MAX;
	hrtimer_cpu_base_init_expiry_lock(cpu_base);
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU

static void migrate_hrtimer_list(struct hrtimer_clock_base *old_base,
				struct hrtimer_clock_base *new_base)
{
	struct hrtimer *timer;
	struct timerqueue_node *node;

	while ((node = timerqueue_getnext(&old_base->active))) {
		timer = container_of(node, struct hrtimer, node);
		BUG_ON(hrtimer_callback_running(timer));
		debug_deactivate(timer);

		/*
		__remove_hrtimer(timer, old_base, HRTIMER_STATE_ENQUEUED, 0);
		timer->base = new_base;
		/*
		enqueue_hrtimer(timer, new_base, HRTIMER_MODE_ABS);
	}
}

int hrtimers_dead_cpu(unsigned int scpu)
{
	struct hrtimer_cpu_base *old_base, *new_base;
	int i;

	BUG_ON(cpu_online(scpu));
	tick_cancel_sched_timer(scpu);

	/*
	local_bh_disable();
	local_irq_disable();
	old_base = &per_cpu(hrtimer_bases, scpu);
	new_base = this_cpu_ptr(&hrtimer_bases);
	/*
	raw_spin_lock(&new_base->lock);
	raw_spin_lock_nested(&old_base->lock, SINGLE_DEPTH_NESTING);

	for (i = 0; i < HRTIMER_MAX_CLOCK_BASES; i++) {
		migrate_hrtimer_list(&old_base->clock_base[i],
				     &new_base->clock_base[i]);
	}

	/*
	hrtimer_update_softirq_timer(new_base, false);

	raw_spin_unlock(&old_base->lock);
	raw_spin_unlock(&new_base->lock);

	/* Check, if we got expired work to do */
	__hrtimer_peek_ahead_timers();
	local_irq_enable();
	local_bh_enable();
	return 0;
}

#endif /* CONFIG_HOTPLUG_CPU */

void __init hrtimers_init(void)
{
	hrtimers_prepare_cpu(smp_processor_id());
	open_softirq(HRTIMER_SOFTIRQ, hrtimer_run_softirq);
}

int __sched
schedule_hrtimeout_range_clock(ktime_t *expires, u64 delta,
			       const enum hrtimer_mode mode, clockid_t clock_id)
{
	struct hrtimer_sleeper t;

	/*
	if (expires && *expires == 0) {
		__set_current_state(TASK_RUNNING);
		return 0;
	}

	/*
	if (!expires) {
		schedule();
		return -EINTR;
	}

	hrtimer_init_sleeper_on_stack(&t, clock_id, mode);
	hrtimer_set_expires_range_ns(&t.timer, *expires, delta);
	hrtimer_sleeper_start_expires(&t, mode);

	if (likely(t.task))
		schedule();

	hrtimer_cancel(&t.timer);
	destroy_hrtimer_on_stack(&t.timer);

	__set_current_state(TASK_RUNNING);

	return !t.task ? 0 : -EINTR;
}
EXPORT_SYMBOL_GPL(schedule_hrtimeout_range_clock);

int __sched schedule_hrtimeout_range(ktime_t *expires, u64 delta,
				     const enum hrtimer_mode mode)
{
	return schedule_hrtimeout_range_clock(expires, delta, mode,
					      CLOCK_MONOTONIC);
}
EXPORT_SYMBOL_GPL(schedule_hrtimeout_range);

int __sched schedule_hrtimeout(ktime_t *expires,
			       const enum hrtimer_mode mode)
{
	return schedule_hrtimeout_range(expires, 0, mode);
}
EXPORT_SYMBOL_GPL(schedule_hrtimeout);
