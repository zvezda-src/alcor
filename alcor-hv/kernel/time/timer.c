
#include <linux/kernel_stat.h>
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pid_namespace.h>
#include <linux/notifier.h>
#include <linux/thread_info.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/posix-timers.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/tick.h>
#include <linux/kallsyms.h>
#include <linux/irq_work.h>
#include <linux/sched/signal.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/nohz.h>
#include <linux/sched/debug.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/random.h>
#include <linux/sysctl.h>

#include <linux/uaccess.h>
#include <asm/unistd.h>
#include <asm/div64.h>
#include <asm/timex.h>
#include <asm/io.h>

#include "tick-internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/timer.h>

__visible u64 jiffies_64 __cacheline_aligned_in_smp = INITIAL_JIFFIES;

EXPORT_SYMBOL(jiffies_64);


#define LVL_CLK_SHIFT	3
#define LVL_CLK_DIV	(1UL << LVL_CLK_SHIFT)
#define LVL_CLK_MASK	(LVL_CLK_DIV - 1)
#define LVL_SHIFT(n)	((n) * LVL_CLK_SHIFT)
#define LVL_GRAN(n)	(1UL << LVL_SHIFT(n))

#define LVL_START(n)	((LVL_SIZE - 1) << (((n) - 1) * LVL_CLK_SHIFT))

#define LVL_BITS	6
#define LVL_SIZE	(1UL << LVL_BITS)
#define LVL_MASK	(LVL_SIZE - 1)
#define LVL_OFFS(n)	((n) * LVL_SIZE)

#if HZ > 100
# define LVL_DEPTH	9
# else
# define LVL_DEPTH	8
#endif

#define WHEEL_TIMEOUT_CUTOFF	(LVL_START(LVL_DEPTH))
#define WHEEL_TIMEOUT_MAX	(WHEEL_TIMEOUT_CUTOFF - LVL_GRAN(LVL_DEPTH - 1))

#define WHEEL_SIZE	(LVL_SIZE * LVL_DEPTH)

#ifdef CONFIG_NO_HZ_COMMON
# define NR_BASES	2
# define BASE_STD	0
# define BASE_DEF	1
#else
# define NR_BASES	1
# define BASE_STD	0
# define BASE_DEF	0
#endif

struct timer_base {
	raw_spinlock_t		lock;
	struct timer_list	*running_timer;
#ifdef CONFIG_PREEMPT_RT
	spinlock_t		expiry_lock;
	atomic_t		timer_waiters;
#endif
	unsigned long		clk;
	unsigned long		next_expiry;
	unsigned int		cpu;
	bool			next_expiry_recalc;
	bool			is_idle;
	bool			timers_pending;
	DECLARE_BITMAP(pending_map, WHEEL_SIZE);
	struct hlist_head	vectors[WHEEL_SIZE];
} ____cacheline_aligned;

static DEFINE_PER_CPU(struct timer_base, timer_bases[NR_BASES]);

#ifdef CONFIG_NO_HZ_COMMON

static DEFINE_STATIC_KEY_FALSE(timers_nohz_active);
static DEFINE_MUTEX(timer_keys_mutex);

static void timer_update_keys(struct work_struct *work);
static DECLARE_WORK(timer_update_work, timer_update_keys);

#ifdef CONFIG_SMP
static unsigned int sysctl_timer_migration = 1;

DEFINE_STATIC_KEY_FALSE(timers_migration_enabled);

static void timers_update_migration(void)
{
	if (sysctl_timer_migration && tick_nohz_active)
		static_branch_enable(&timers_migration_enabled);
	else
		static_branch_disable(&timers_migration_enabled);
}

#ifdef CONFIG_SYSCTL
static int timer_migration_handler(struct ctl_table *table, int write,
			    void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	mutex_lock(&timer_keys_mutex);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (!ret && write)
		timers_update_migration();
	mutex_unlock(&timer_keys_mutex);
	return ret;
}

static struct ctl_table timer_sysctl[] = {
	{
		.procname	= "timer_migration",
		.data		= &sysctl_timer_migration,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= timer_migration_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{}
};

static int __init timer_sysctl_init(void)
{
	register_sysctl("kernel", timer_sysctl);
	return 0;
}
device_initcall(timer_sysctl_init);
#endif /* CONFIG_SYSCTL */
#else /* CONFIG_SMP */
static inline void timers_update_migration(void) { }
#endif /* !CONFIG_SMP */

static void timer_update_keys(struct work_struct *work)
{
	mutex_lock(&timer_keys_mutex);
	timers_update_migration();
	static_branch_enable(&timers_nohz_active);
	mutex_unlock(&timer_keys_mutex);
}

void timers_update_nohz(void)
{
	schedule_work(&timer_update_work);
}

static inline bool is_timers_nohz_active(void)
{
	return static_branch_unlikely(&timers_nohz_active);
}
#else
static inline bool is_timers_nohz_active(void) { return false; }
#endif /* NO_HZ_COMMON */

static unsigned long round_jiffies_common(unsigned long j, int cpu,
		bool force_up)
{
	int rem;
	unsigned long original = j;

	/*
	j += cpu * 3;

	rem = j % HZ;

	/*
	if (rem < HZ/4 && !force_up) /* round down */
		j = j - rem;
	else /* round up */
		j = j - rem + HZ;

	/* now that we have rounded, subtract the extra skew again */
	j -= cpu * 3;

	/*
	return time_is_after_jiffies(j) ? j : original;
}

unsigned long __round_jiffies(unsigned long j, int cpu)
{
	return round_jiffies_common(j, cpu, false);
}
EXPORT_SYMBOL_GPL(__round_jiffies);

unsigned long __round_jiffies_relative(unsigned long j, int cpu)
{
	unsigned long j0 = jiffies;

	/* Use j0 because jiffies might change while we run */
	return round_jiffies_common(j + j0, cpu, false) - j0;
}
EXPORT_SYMBOL_GPL(__round_jiffies_relative);

unsigned long round_jiffies(unsigned long j)
{
	return round_jiffies_common(j, raw_smp_processor_id(), false);
}
EXPORT_SYMBOL_GPL(round_jiffies);

unsigned long round_jiffies_relative(unsigned long j)
{
	return __round_jiffies_relative(j, raw_smp_processor_id());
}
EXPORT_SYMBOL_GPL(round_jiffies_relative);

unsigned long __round_jiffies_up(unsigned long j, int cpu)
{
	return round_jiffies_common(j, cpu, true);
}
EXPORT_SYMBOL_GPL(__round_jiffies_up);

unsigned long __round_jiffies_up_relative(unsigned long j, int cpu)
{
	unsigned long j0 = jiffies;

	/* Use j0 because jiffies might change while we run */
	return round_jiffies_common(j + j0, cpu, true) - j0;
}
EXPORT_SYMBOL_GPL(__round_jiffies_up_relative);

unsigned long round_jiffies_up(unsigned long j)
{
	return round_jiffies_common(j, raw_smp_processor_id(), true);
}
EXPORT_SYMBOL_GPL(round_jiffies_up);

unsigned long round_jiffies_up_relative(unsigned long j)
{
	return __round_jiffies_up_relative(j, raw_smp_processor_id());
}
EXPORT_SYMBOL_GPL(round_jiffies_up_relative);


static inline unsigned int timer_get_idx(struct timer_list *timer)
{
	return (timer->flags & TIMER_ARRAYMASK) >> TIMER_ARRAYSHIFT;
}

static inline void timer_set_idx(struct timer_list *timer, unsigned int idx)
{
	timer->flags = (timer->flags & ~TIMER_ARRAYMASK) |
			idx << TIMER_ARRAYSHIFT;
}

static inline unsigned calc_index(unsigned long expires, unsigned lvl,
				  unsigned long *bucket_expiry)
{

	/*
	expires = (expires >> LVL_SHIFT(lvl)) + 1;
	return LVL_OFFS(lvl) + (expires & LVL_MASK);
}

static int calc_wheel_index(unsigned long expires, unsigned long clk,
			    unsigned long *bucket_expiry)
{
	unsigned long delta = expires - clk;
	unsigned int idx;

	if (delta < LVL_START(1)) {
		idx = calc_index(expires, 0, bucket_expiry);
	} else if (delta < LVL_START(2)) {
		idx = calc_index(expires, 1, bucket_expiry);
	} else if (delta < LVL_START(3)) {
		idx = calc_index(expires, 2, bucket_expiry);
	} else if (delta < LVL_START(4)) {
		idx = calc_index(expires, 3, bucket_expiry);
	} else if (delta < LVL_START(5)) {
		idx = calc_index(expires, 4, bucket_expiry);
	} else if (delta < LVL_START(6)) {
		idx = calc_index(expires, 5, bucket_expiry);
	} else if (delta < LVL_START(7)) {
		idx = calc_index(expires, 6, bucket_expiry);
	} else if (LVL_DEPTH > 8 && delta < LVL_START(8)) {
		idx = calc_index(expires, 7, bucket_expiry);
	} else if ((long) delta < 0) {
		idx = clk & LVL_MASK;
		*bucket_expiry = clk;
	} else {
		/*
		if (delta >= WHEEL_TIMEOUT_CUTOFF)
			expires = clk + WHEEL_TIMEOUT_MAX;

		idx = calc_index(expires, LVL_DEPTH - 1, bucket_expiry);
	}
	return idx;
}

static void
trigger_dyntick_cpu(struct timer_base *base, struct timer_list *timer)
{
	if (!is_timers_nohz_active())
		return;

	/*
	if (timer->flags & TIMER_DEFERRABLE) {
		if (tick_nohz_full_cpu(base->cpu))
			wake_up_nohz_cpu(base->cpu);
		return;
	}

	/*
	if (base->is_idle)
		wake_up_nohz_cpu(base->cpu);
}

static void enqueue_timer(struct timer_base *base, struct timer_list *timer,
			  unsigned int idx, unsigned long bucket_expiry)
{

	hlist_add_head(&timer->entry, base->vectors + idx);
	__set_bit(idx, base->pending_map);
	timer_set_idx(timer, idx);

	trace_timer_start(timer, timer->expires, timer->flags);

	/*
	if (time_before(bucket_expiry, base->next_expiry)) {
		/*
		base->next_expiry = bucket_expiry;
		base->timers_pending = true;
		base->next_expiry_recalc = false;
		trigger_dyntick_cpu(base, timer);
	}
}

static void internal_add_timer(struct timer_base *base, struct timer_list *timer)
{
	unsigned long bucket_expiry;
	unsigned int idx;

	idx = calc_wheel_index(timer->expires, base->clk, &bucket_expiry);
	enqueue_timer(base, timer, idx, bucket_expiry);
}

#ifdef CONFIG_DEBUG_OBJECTS_TIMERS

static const struct debug_obj_descr timer_debug_descr;

struct timer_hint {
	void	(*function)(struct timer_list *t);
	long	offset;
};

#define TIMER_HINT(fn, container, timr, hintfn)			\
	{							\
		.function = fn,					\
		.offset	  = offsetof(container, hintfn) -	\
			    offsetof(container, timr)		\
	}

static const struct timer_hint timer_hints[] = {
	TIMER_HINT(delayed_work_timer_fn,
		   struct delayed_work, timer, work.func),
	TIMER_HINT(kthread_delayed_work_timer_fn,
		   struct kthread_delayed_work, timer, work.func),
};

static void *timer_debug_hint(void *addr)
{
	struct timer_list *timer = addr;
	int i;

	for (i = 0; i < ARRAY_SIZE(timer_hints); i++) {
		if (timer_hints[i].function == timer->function) {
			void (**fn)(void) = addr + timer_hints[i].offset;

			return *fn;
		}
	}

	return timer->function;
}

static bool timer_is_static_object(void *addr)
{
	struct timer_list *timer = addr;

	return (timer->entry.pprev == NULL &&
		timer->entry.next == TIMER_ENTRY_STATIC);
}

static bool timer_fixup_init(void *addr, enum debug_obj_state state)
{
	struct timer_list *timer = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		del_timer_sync(timer);
		debug_object_init(timer, &timer_debug_descr);
		return true;
	default:
		return false;
	}
}

static void stub_timer(struct timer_list *unused)
{
	WARN_ON(1);
}

static bool timer_fixup_activate(void *addr, enum debug_obj_state state)
{
	struct timer_list *timer = addr;

	switch (state) {
	case ODEBUG_STATE_NOTAVAILABLE:
		timer_setup(timer, stub_timer, 0);
		return true;

	case ODEBUG_STATE_ACTIVE:
		WARN_ON(1);
		fallthrough;
	default:
		return false;
	}
}

static bool timer_fixup_free(void *addr, enum debug_obj_state state)
{
	struct timer_list *timer = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		del_timer_sync(timer);
		debug_object_free(timer, &timer_debug_descr);
		return true;
	default:
		return false;
	}
}

static bool timer_fixup_assert_init(void *addr, enum debug_obj_state state)
{
	struct timer_list *timer = addr;

	switch (state) {
	case ODEBUG_STATE_NOTAVAILABLE:
		timer_setup(timer, stub_timer, 0);
		return true;
	default:
		return false;
	}
}

static const struct debug_obj_descr timer_debug_descr = {
	.name			= "timer_list",
	.debug_hint		= timer_debug_hint,
	.is_static_object	= timer_is_static_object,
	.fixup_init		= timer_fixup_init,
	.fixup_activate		= timer_fixup_activate,
	.fixup_free		= timer_fixup_free,
	.fixup_assert_init	= timer_fixup_assert_init,
};

static inline void debug_timer_init(struct timer_list *timer)
{
	debug_object_init(timer, &timer_debug_descr);
}

static inline void debug_timer_activate(struct timer_list *timer)
{
	debug_object_activate(timer, &timer_debug_descr);
}

static inline void debug_timer_deactivate(struct timer_list *timer)
{
	debug_object_deactivate(timer, &timer_debug_descr);
}

static inline void debug_timer_assert_init(struct timer_list *timer)
{
	debug_object_assert_init(timer, &timer_debug_descr);
}

static void do_init_timer(struct timer_list *timer,
			  void (*func)(struct timer_list *),
			  unsigned int flags,
			  const char *name, struct lock_class_key *key);

void init_timer_on_stack_key(struct timer_list *timer,
			     void (*func)(struct timer_list *),
			     unsigned int flags,
			     const char *name, struct lock_class_key *key)
{
	debug_object_init_on_stack(timer, &timer_debug_descr);
	do_init_timer(timer, func, flags, name, key);
}
EXPORT_SYMBOL_GPL(init_timer_on_stack_key);

void destroy_timer_on_stack(struct timer_list *timer)
{
	debug_object_free(timer, &timer_debug_descr);
}
EXPORT_SYMBOL_GPL(destroy_timer_on_stack);

#else
static inline void debug_timer_init(struct timer_list *timer) { }
static inline void debug_timer_activate(struct timer_list *timer) { }
static inline void debug_timer_deactivate(struct timer_list *timer) { }
static inline void debug_timer_assert_init(struct timer_list *timer) { }
#endif

static inline void debug_init(struct timer_list *timer)
{
	debug_timer_init(timer);
	trace_timer_init(timer);
}

static inline void debug_deactivate(struct timer_list *timer)
{
	debug_timer_deactivate(timer);
	trace_timer_cancel(timer);
}

static inline void debug_assert_init(struct timer_list *timer)
{
	debug_timer_assert_init(timer);
}

static void do_init_timer(struct timer_list *timer,
			  void (*func)(struct timer_list *),
			  unsigned int flags,
			  const char *name, struct lock_class_key *key)
{
	timer->entry.pprev = NULL;
	timer->function = func;
	if (WARN_ON_ONCE(flags & ~TIMER_INIT_FLAGS))
		flags &= TIMER_INIT_FLAGS;
	timer->flags = flags | raw_smp_processor_id();
	lockdep_init_map(&timer->lockdep_map, name, key, 0);
}

void init_timer_key(struct timer_list *timer,
		    void (*func)(struct timer_list *), unsigned int flags,
		    const char *name, struct lock_class_key *key)
{
	debug_init(timer);
	do_init_timer(timer, func, flags, name, key);
}
EXPORT_SYMBOL(init_timer_key);

static inline void detach_timer(struct timer_list *timer, bool clear_pending)
{
	struct hlist_node *entry = &timer->entry;

	debug_deactivate(timer);

	__hlist_del(entry);
	if (clear_pending)
		entry->pprev = NULL;
	entry->next = LIST_POISON2;
}

static int detach_if_pending(struct timer_list *timer, struct timer_base *base,
			     bool clear_pending)
{
	unsigned idx = timer_get_idx(timer);

	if (!timer_pending(timer))
		return 0;

	if (hlist_is_singular_node(&timer->entry, base->vectors + idx)) {
		__clear_bit(idx, base->pending_map);
		base->next_expiry_recalc = true;
	}

	detach_timer(timer, clear_pending);
	return 1;
}

static inline struct timer_base *get_timer_cpu_base(u32 tflags, u32 cpu)
{
	struct timer_base *base = per_cpu_ptr(&timer_bases[BASE_STD], cpu);

	/*
	if (IS_ENABLED(CONFIG_NO_HZ_COMMON) && (tflags & TIMER_DEFERRABLE))
		base = per_cpu_ptr(&timer_bases[BASE_DEF], cpu);
	return base;
}

static inline struct timer_base *get_timer_this_cpu_base(u32 tflags)
{
	struct timer_base *base = this_cpu_ptr(&timer_bases[BASE_STD]);

	/*
	if (IS_ENABLED(CONFIG_NO_HZ_COMMON) && (tflags & TIMER_DEFERRABLE))
		base = this_cpu_ptr(&timer_bases[BASE_DEF]);
	return base;
}

static inline struct timer_base *get_timer_base(u32 tflags)
{
	return get_timer_cpu_base(tflags, tflags & TIMER_CPUMASK);
}

static inline struct timer_base *
get_target_base(struct timer_base *base, unsigned tflags)
{
#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
	if (static_branch_likely(&timers_migration_enabled) &&
	    !(tflags & TIMER_PINNED))
		return get_timer_cpu_base(tflags, get_nohz_timer_target());
#endif
	return get_timer_this_cpu_base(tflags);
}

static inline void forward_timer_base(struct timer_base *base)
{
	unsigned long jnow = READ_ONCE(jiffies);

	/*
	if ((long)(jnow - base->clk) < 1)
		return;

	/*
	if (time_after(base->next_expiry, jnow)) {
		base->clk = jnow;
	} else {
		if (WARN_ON_ONCE(time_before(base->next_expiry, base->clk)))
			return;
		base->clk = base->next_expiry;
	}
}


static struct timer_base *lock_timer_base(struct timer_list *timer,
					  unsigned long *flags)
	__acquires(timer->base->lock)
{
	for (;;) {
		struct timer_base *base;
		u32 tf;

		/*
		tf = READ_ONCE(timer->flags);

		if (!(tf & TIMER_MIGRATING)) {
			base = get_timer_base(tf);
			raw_spin_lock_irqsave(&base->lock, *flags);
			if (timer->flags == tf)
				return base;
			raw_spin_unlock_irqrestore(&base->lock, *flags);
		}
		cpu_relax();
	}
}

#define MOD_TIMER_PENDING_ONLY		0x01
#define MOD_TIMER_REDUCE		0x02
#define MOD_TIMER_NOTPENDING		0x04

static inline int
__mod_timer(struct timer_list *timer, unsigned long expires, unsigned int options)
{
	unsigned long clk = 0, flags, bucket_expiry;
	struct timer_base *base, *new_base;
	unsigned int idx = UINT_MAX;
	int ret = 0;

	BUG_ON(!timer->function);

	/*
	if (!(options & MOD_TIMER_NOTPENDING) && timer_pending(timer)) {
		/*
		long diff = timer->expires - expires;

		if (!diff)
			return 1;
		if (options & MOD_TIMER_REDUCE && diff <= 0)
			return 1;

		/*
		base = lock_timer_base(timer, &flags);
		forward_timer_base(base);

		if (timer_pending(timer) && (options & MOD_TIMER_REDUCE) &&
		    time_before_eq(timer->expires, expires)) {
			ret = 1;
			goto out_unlock;
		}

		clk = base->clk;
		idx = calc_wheel_index(expires, clk, &bucket_expiry);

		/*
		if (idx == timer_get_idx(timer)) {
			if (!(options & MOD_TIMER_REDUCE))
				timer->expires = expires;
			else if (time_after(timer->expires, expires))
				timer->expires = expires;
			ret = 1;
			goto out_unlock;
		}
	} else {
		base = lock_timer_base(timer, &flags);
		forward_timer_base(base);
	}

	ret = detach_if_pending(timer, base, false);
	if (!ret && (options & MOD_TIMER_PENDING_ONLY))
		goto out_unlock;

	new_base = get_target_base(base, timer->flags);

	if (base != new_base) {
		/*
		if (likely(base->running_timer != timer)) {
			/* See the comment in lock_timer_base() */
			timer->flags |= TIMER_MIGRATING;

			raw_spin_unlock(&base->lock);
			base = new_base;
			raw_spin_lock(&base->lock);
			WRITE_ONCE(timer->flags,
				   (timer->flags & ~TIMER_BASEMASK) | base->cpu);
			forward_timer_base(base);
		}
	}

	debug_timer_activate(timer);

	timer->expires = expires;
	/*
	if (idx != UINT_MAX && clk == base->clk)
		enqueue_timer(base, timer, idx, bucket_expiry);
	else
		internal_add_timer(base, timer);

out_unlock:
	raw_spin_unlock_irqrestore(&base->lock, flags);

	return ret;
}

int mod_timer_pending(struct timer_list *timer, unsigned long expires)
{
	return __mod_timer(timer, expires, MOD_TIMER_PENDING_ONLY);
}
EXPORT_SYMBOL(mod_timer_pending);

int mod_timer(struct timer_list *timer, unsigned long expires)
{
	return __mod_timer(timer, expires, 0);
}
EXPORT_SYMBOL(mod_timer);

int timer_reduce(struct timer_list *timer, unsigned long expires)
{
	return __mod_timer(timer, expires, MOD_TIMER_REDUCE);
}
EXPORT_SYMBOL(timer_reduce);

void add_timer(struct timer_list *timer)
{
	BUG_ON(timer_pending(timer));
	__mod_timer(timer, timer->expires, MOD_TIMER_NOTPENDING);
}
EXPORT_SYMBOL(add_timer);

void add_timer_on(struct timer_list *timer, int cpu)
{
	struct timer_base *new_base, *base;
	unsigned long flags;

	BUG_ON(timer_pending(timer) || !timer->function);

	new_base = get_timer_cpu_base(timer->flags, cpu);

	/*
	base = lock_timer_base(timer, &flags);
	if (base != new_base) {
		timer->flags |= TIMER_MIGRATING;

		raw_spin_unlock(&base->lock);
		base = new_base;
		raw_spin_lock(&base->lock);
		WRITE_ONCE(timer->flags,
			   (timer->flags & ~TIMER_BASEMASK) | cpu);
	}
	forward_timer_base(base);

	debug_timer_activate(timer);
	internal_add_timer(base, timer);
	raw_spin_unlock_irqrestore(&base->lock, flags);
}
EXPORT_SYMBOL_GPL(add_timer_on);

int del_timer(struct timer_list *timer)
{
	struct timer_base *base;
	unsigned long flags;
	int ret = 0;

	debug_assert_init(timer);

	if (timer_pending(timer)) {
		base = lock_timer_base(timer, &flags);
		ret = detach_if_pending(timer, base, true);
		raw_spin_unlock_irqrestore(&base->lock, flags);
	}

	return ret;
}
EXPORT_SYMBOL(del_timer);

int try_to_del_timer_sync(struct timer_list *timer)
{
	struct timer_base *base;
	unsigned long flags;
	int ret = -1;

	debug_assert_init(timer);

	base = lock_timer_base(timer, &flags);

	if (base->running_timer != timer)
		ret = detach_if_pending(timer, base, true);

	raw_spin_unlock_irqrestore(&base->lock, flags);

	return ret;
}
EXPORT_SYMBOL(try_to_del_timer_sync);

#ifdef CONFIG_PREEMPT_RT
static __init void timer_base_init_expiry_lock(struct timer_base *base)
{
	spin_lock_init(&base->expiry_lock);
}

static inline void timer_base_lock_expiry(struct timer_base *base)
{
	spin_lock(&base->expiry_lock);
}

static inline void timer_base_unlock_expiry(struct timer_base *base)
{
	spin_unlock(&base->expiry_lock);
}

static void timer_sync_wait_running(struct timer_base *base)
{
	if (atomic_read(&base->timer_waiters)) {
		raw_spin_unlock_irq(&base->lock);
		spin_unlock(&base->expiry_lock);
		spin_lock(&base->expiry_lock);
		raw_spin_lock_irq(&base->lock);
	}
}

static void del_timer_wait_running(struct timer_list *timer)
{
	u32 tf;

	tf = READ_ONCE(timer->flags);
	if (!(tf & (TIMER_MIGRATING | TIMER_IRQSAFE))) {
		struct timer_base *base = get_timer_base(tf);

		/*
		atomic_inc(&base->timer_waiters);
		spin_lock_bh(&base->expiry_lock);
		atomic_dec(&base->timer_waiters);
		spin_unlock_bh(&base->expiry_lock);
	}
}
#else
static inline void timer_base_init_expiry_lock(struct timer_base *base) { }
static inline void timer_base_lock_expiry(struct timer_base *base) { }
static inline void timer_base_unlock_expiry(struct timer_base *base) { }
static inline void timer_sync_wait_running(struct timer_base *base) { }
static inline void del_timer_wait_running(struct timer_list *timer) { }
#endif

#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPT_RT)
int del_timer_sync(struct timer_list *timer)
{
	int ret;

#ifdef CONFIG_LOCKDEP
	unsigned long flags;

	/*
	local_irq_save(flags);
	lock_map_acquire(&timer->lockdep_map);
	lock_map_release(&timer->lockdep_map);
	local_irq_restore(flags);
#endif
	/*
	WARN_ON(in_irq() && !(timer->flags & TIMER_IRQSAFE));

	/*
	if (IS_ENABLED(CONFIG_PREEMPT_RT) && !(timer->flags & TIMER_IRQSAFE))
		lockdep_assert_preemption_enabled();

	do {
		ret = try_to_del_timer_sync(timer);

		if (unlikely(ret < 0)) {
			del_timer_wait_running(timer);
			cpu_relax();
		}
	} while (ret < 0);

	return ret;
}
EXPORT_SYMBOL(del_timer_sync);
#endif

static void call_timer_fn(struct timer_list *timer,
			  void (*fn)(struct timer_list *),
			  unsigned long baseclk)
{
	int count = preempt_count();

#ifdef CONFIG_LOCKDEP
	/*
	struct lockdep_map lockdep_map;

	lockdep_copy_map(&lockdep_map, &timer->lockdep_map);
#endif
	/*
	lock_map_acquire(&lockdep_map);

	trace_timer_expire_entry(timer, baseclk);
	fn(timer);
	trace_timer_expire_exit(timer);

	lock_map_release(&lockdep_map);

	if (count != preempt_count()) {
		WARN_ONCE(1, "timer: %pS preempt leak: %08x -> %08x\n",
			  fn, count, preempt_count());
		/*
		preempt_count_set(count);
	}
}

static void expire_timers(struct timer_base *base, struct hlist_head *head)
{
	/*
	unsigned long baseclk = base->clk - 1;

	while (!hlist_empty(head)) {
		struct timer_list *timer;
		void (*fn)(struct timer_list *);

		timer = hlist_entry(head->first, struct timer_list, entry);

		base->running_timer = timer;
		detach_timer(timer, true);

		fn = timer->function;

		if (timer->flags & TIMER_IRQSAFE) {
			raw_spin_unlock(&base->lock);
			call_timer_fn(timer, fn, baseclk);
			raw_spin_lock(&base->lock);
			base->running_timer = NULL;
		} else {
			raw_spin_unlock_irq(&base->lock);
			call_timer_fn(timer, fn, baseclk);
			raw_spin_lock_irq(&base->lock);
			base->running_timer = NULL;
			timer_sync_wait_running(base);
		}
	}
}

static int collect_expired_timers(struct timer_base *base,
				  struct hlist_head *heads)
{
	unsigned long clk = base->clk = base->next_expiry;
	struct hlist_head *vec;
	int i, levels = 0;
	unsigned int idx;

	for (i = 0; i < LVL_DEPTH; i++) {
		idx = (clk & LVL_MASK) + i * LVL_SIZE;

		if (__test_and_clear_bit(idx, base->pending_map)) {
			vec = base->vectors + idx;
			hlist_move_list(vec, heads++);
			levels++;
		}
		/* Is it time to look at the next level? */
		if (clk & LVL_CLK_MASK)
			break;
		/* Shift clock for the next level granularity */
		clk >>= LVL_CLK_SHIFT;
	}
	return levels;
}

static int next_pending_bucket(struct timer_base *base, unsigned offset,
			       unsigned clk)
{
	unsigned pos, start = offset + clk;
	unsigned end = offset + LVL_SIZE;

	pos = find_next_bit(base->pending_map, end, start);
	if (pos < end)
		return pos - start;

	pos = find_next_bit(base->pending_map, start, offset);
	return pos < start ? pos + LVL_SIZE - start : -1;
}

static unsigned long __next_timer_interrupt(struct timer_base *base)
{
	unsigned long clk, next, adj;
	unsigned lvl, offset = 0;

	next = base->clk + NEXT_TIMER_MAX_DELTA;
	clk = base->clk;
	for (lvl = 0; lvl < LVL_DEPTH; lvl++, offset += LVL_SIZE) {
		int pos = next_pending_bucket(base, offset, clk & LVL_MASK);
		unsigned long lvl_clk = clk & LVL_CLK_MASK;

		if (pos >= 0) {
			unsigned long tmp = clk + (unsigned long) pos;

			tmp <<= LVL_SHIFT(lvl);
			if (time_before(tmp, next))
				next = tmp;

			/*
			if (pos <= ((LVL_CLK_DIV - lvl_clk) & LVL_CLK_MASK))
				break;
		}
		/*
		adj = lvl_clk ? 1 : 0;
		clk >>= LVL_CLK_SHIFT;
		clk += adj;
	}

	base->next_expiry_recalc = false;
	base->timers_pending = !(next == base->clk + NEXT_TIMER_MAX_DELTA);

	return next;
}

#ifdef CONFIG_NO_HZ_COMMON
static u64 cmp_next_hrtimer_event(u64 basem, u64 expires)
{
	u64 nextevt = hrtimer_get_next_event();

	/*
	if (expires <= nextevt)
		return expires;

	/*
	if (nextevt <= basem)
		return basem;

	/*
	return DIV_ROUND_UP_ULL(nextevt, TICK_NSEC) * TICK_NSEC;
}

u64 get_next_timer_interrupt(unsigned long basej, u64 basem)
{
	struct timer_base *base = this_cpu_ptr(&timer_bases[BASE_STD]);
	u64 expires = KTIME_MAX;
	unsigned long nextevt;

	/*
	if (cpu_is_offline(smp_processor_id()))
		return expires;

	raw_spin_lock(&base->lock);
	if (base->next_expiry_recalc)
		base->next_expiry = __next_timer_interrupt(base);
	nextevt = base->next_expiry;

	/*
	if (time_after(basej, base->clk)) {
		if (time_after(nextevt, basej))
			base->clk = basej;
		else if (time_after(nextevt, base->clk))
			base->clk = nextevt;
	}

	if (time_before_eq(nextevt, basej)) {
		expires = basem;
		base->is_idle = false;
	} else {
		if (base->timers_pending)
			expires = basem + (u64)(nextevt - basej) * TICK_NSEC;
		/*
		if ((expires - basem) > TICK_NSEC)
			base->is_idle = true;
	}
	raw_spin_unlock(&base->lock);

	return cmp_next_hrtimer_event(basem, expires);
}

void timer_clear_idle(void)
{
	struct timer_base *base = this_cpu_ptr(&timer_bases[BASE_STD]);

	/*
	base->is_idle = false;
}
#endif

static inline void __run_timers(struct timer_base *base)
{
	struct hlist_head heads[LVL_DEPTH];
	int levels;

	if (time_before(jiffies, base->next_expiry))
		return;

	timer_base_lock_expiry(base);
	raw_spin_lock_irq(&base->lock);

	while (time_after_eq(jiffies, base->clk) &&
	       time_after_eq(jiffies, base->next_expiry)) {
		levels = collect_expired_timers(base, heads);
		/*
		WARN_ON_ONCE(!levels && !base->next_expiry_recalc
			     && base->timers_pending);
		base->clk++;
		base->next_expiry = __next_timer_interrupt(base);

		while (levels--)
			expire_timers(base, heads + levels);
	}
	raw_spin_unlock_irq(&base->lock);
	timer_base_unlock_expiry(base);
}

static __latent_entropy void run_timer_softirq(struct softirq_action *h)
{
	struct timer_base *base = this_cpu_ptr(&timer_bases[BASE_STD]);

	__run_timers(base);
	if (IS_ENABLED(CONFIG_NO_HZ_COMMON))
		__run_timers(this_cpu_ptr(&timer_bases[BASE_DEF]));
}

static void run_local_timers(void)
{
	struct timer_base *base = this_cpu_ptr(&timer_bases[BASE_STD]);

	hrtimer_run_queues();
	/* Raise the softirq only if required. */
	if (time_before(jiffies, base->next_expiry)) {
		if (!IS_ENABLED(CONFIG_NO_HZ_COMMON))
			return;
		/* CPU is awake, so check the deferrable base. */
		base++;
		if (time_before(jiffies, base->next_expiry))
			return;
	}
	raise_softirq(TIMER_SOFTIRQ);
}

void update_process_times(int user_tick)
{
	struct task_struct *p = current;

	/* Note: this timer irq context must be accounted for as well. */
	account_process_tick(p, user_tick);
	run_local_timers();
	rcu_sched_clock_irq(user_tick);
#ifdef CONFIG_IRQ_WORK
	if (in_irq())
		irq_work_tick();
#endif
	scheduler_tick();
	if (IS_ENABLED(CONFIG_POSIX_TIMERS))
		run_posix_cpu_timers();
}

struct process_timer {
	struct timer_list timer;
	struct task_struct *task;
};

static void process_timeout(struct timer_list *t)
{
	struct process_timer *timeout = from_timer(timeout, t, timer);

	wake_up_process(timeout->task);
}

signed long __sched schedule_timeout(signed long timeout)
{
	struct process_timer timer;
	unsigned long expire;

	switch (timeout)
	{
	case MAX_SCHEDULE_TIMEOUT:
		/*
		schedule();
		goto out;
	default:
		/*
		if (timeout < 0) {
			printk(KERN_ERR "schedule_timeout: wrong timeout "
				"value %lx\n", timeout);
			dump_stack();
			__set_current_state(TASK_RUNNING);
			goto out;
		}
	}

	expire = timeout + jiffies;

	timer.task = current;
	timer_setup_on_stack(&timer.timer, process_timeout, 0);
	__mod_timer(&timer.timer, expire, MOD_TIMER_NOTPENDING);
	schedule();
	del_singleshot_timer_sync(&timer.timer);

	/* Remove the timer from the object tracker */
	destroy_timer_on_stack(&timer.timer);

	timeout = expire - jiffies;

 out:
	return timeout < 0 ? 0 : timeout;
}
EXPORT_SYMBOL(schedule_timeout);

signed long __sched schedule_timeout_interruptible(signed long timeout)
{
	__set_current_state(TASK_INTERRUPTIBLE);
	return schedule_timeout(timeout);
}
EXPORT_SYMBOL(schedule_timeout_interruptible);

signed long __sched schedule_timeout_killable(signed long timeout)
{
	__set_current_state(TASK_KILLABLE);
	return schedule_timeout(timeout);
}
EXPORT_SYMBOL(schedule_timeout_killable);

signed long __sched schedule_timeout_uninterruptible(signed long timeout)
{
	__set_current_state(TASK_UNINTERRUPTIBLE);
	return schedule_timeout(timeout);
}
EXPORT_SYMBOL(schedule_timeout_uninterruptible);

signed long __sched schedule_timeout_idle(signed long timeout)
{
	__set_current_state(TASK_IDLE);
	return schedule_timeout(timeout);
}
EXPORT_SYMBOL(schedule_timeout_idle);

#ifdef CONFIG_HOTPLUG_CPU
static void migrate_timer_list(struct timer_base *new_base, struct hlist_head *head)
{
	struct timer_list *timer;
	int cpu = new_base->cpu;

	while (!hlist_empty(head)) {
		timer = hlist_entry(head->first, struct timer_list, entry);
		detach_timer(timer, false);
		timer->flags = (timer->flags & ~TIMER_BASEMASK) | cpu;
		internal_add_timer(new_base, timer);
	}
}

int timers_prepare_cpu(unsigned int cpu)
{
	struct timer_base *base;
	int b;

	for (b = 0; b < NR_BASES; b++) {
		base = per_cpu_ptr(&timer_bases[b], cpu);
		base->clk = jiffies;
		base->next_expiry = base->clk + NEXT_TIMER_MAX_DELTA;
		base->next_expiry_recalc = false;
		base->timers_pending = false;
		base->is_idle = false;
	}
	return 0;
}

int timers_dead_cpu(unsigned int cpu)
{
	struct timer_base *old_base;
	struct timer_base *new_base;
	int b, i;

	BUG_ON(cpu_online(cpu));

	for (b = 0; b < NR_BASES; b++) {
		old_base = per_cpu_ptr(&timer_bases[b], cpu);
		new_base = get_cpu_ptr(&timer_bases[b]);
		/*
		raw_spin_lock_irq(&new_base->lock);
		raw_spin_lock_nested(&old_base->lock, SINGLE_DEPTH_NESTING);

		/*
		forward_timer_base(new_base);

		BUG_ON(old_base->running_timer);

		for (i = 0; i < WHEEL_SIZE; i++)
			migrate_timer_list(new_base, old_base->vectors + i);

		raw_spin_unlock(&old_base->lock);
		raw_spin_unlock_irq(&new_base->lock);
		put_cpu_ptr(&timer_bases);
	}
	return 0;
}

#endif /* CONFIG_HOTPLUG_CPU */

static void __init init_timer_cpu(int cpu)
{
	struct timer_base *base;
	int i;

	for (i = 0; i < NR_BASES; i++) {
		base = per_cpu_ptr(&timer_bases[i], cpu);
		base->cpu = cpu;
		raw_spin_lock_init(&base->lock);
		base->clk = jiffies;
		base->next_expiry = base->clk + NEXT_TIMER_MAX_DELTA;
		timer_base_init_expiry_lock(base);
	}
}

static void __init init_timer_cpus(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		init_timer_cpu(cpu);
}

void __init init_timers(void)
{
	init_timer_cpus();
	posix_cputimers_init_work();
	open_softirq(TIMER_SOFTIRQ, run_timer_softirq);
}

void msleep(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout)
		timeout = schedule_timeout_uninterruptible(timeout);
}

EXPORT_SYMBOL(msleep);

unsigned long msleep_interruptible(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout && !signal_pending(current))
		timeout = schedule_timeout_interruptible(timeout);
	return jiffies_to_msecs(timeout);
}

EXPORT_SYMBOL(msleep_interruptible);

void __sched usleep_range_state(unsigned long min, unsigned long max,
				unsigned int state)
{
	ktime_t exp = ktime_add_us(ktime_get(), min);
	u64 delta = (u64)(max - min) * NSEC_PER_USEC;

	for (;;) {
		__set_current_state(state);
		/* Do not return before the requested sleep time has elapsed */
		if (!schedule_hrtimeout_range(&exp, delta, HRTIMER_MODE_ABS))
			break;
	}
}
EXPORT_SYMBOL(usleep_range_state);
