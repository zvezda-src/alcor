
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/clocksource.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h> /* for spin_unlock_irq() using preempt_count() m68k */
#include <linux/tick.h>
#include <linux/kthread.h>
#include <linux/prandom.h>
#include <linux/cpu.h>

#include "tick-internal.h"
#include "timekeeping_internal.h"

void
clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 maxsec)
{
	u64 tmp;
	u32 sft, sftacc= 32;

	/*
	tmp = ((u64)maxsec * from) >> 32;
	while (tmp) {
		tmp >>=1;
		sftacc--;
	}

	/*
	for (sft = 32; sft > 0; sft--) {
		tmp = (u64) to << sft;
		tmp += from / 2;
		do_div(tmp, from);
		if ((tmp >> sftacc) == 0)
			break;
	}
}
EXPORT_SYMBOL_GPL(clocks_calc_mult_shift);

static struct clocksource *curr_clocksource;
static struct clocksource *suspend_clocksource;
static LIST_HEAD(clocksource_list);
static DEFINE_MUTEX(clocksource_mutex);
static char override_name[CS_NAME_LEN];
static int finished_booting;
static u64 suspend_start;

#define WATCHDOG_THRESHOLD (NSEC_PER_SEC >> 5)

#ifdef CONFIG_CLOCKSOURCE_WATCHDOG_MAX_SKEW_US
#define MAX_SKEW_USEC	CONFIG_CLOCKSOURCE_WATCHDOG_MAX_SKEW_US
#else
#define MAX_SKEW_USEC	100
#endif

#define WATCHDOG_MAX_SKEW (MAX_SKEW_USEC * NSEC_PER_USEC)

#ifdef CONFIG_CLOCKSOURCE_WATCHDOG
static void clocksource_watchdog_work(struct work_struct *work);
static void clocksource_select(void);

static LIST_HEAD(watchdog_list);
static struct clocksource *watchdog;
static struct timer_list watchdog_timer;
static DECLARE_WORK(watchdog_work, clocksource_watchdog_work);
static DEFINE_SPINLOCK(watchdog_lock);
static int watchdog_running;
static atomic_t watchdog_reset_pending;

static inline void clocksource_watchdog_lock(unsigned long *flags)
{
	spin_lock_irqsave(&watchdog_lock, *flags);
}

static inline void clocksource_watchdog_unlock(unsigned long *flags)
{
	spin_unlock_irqrestore(&watchdog_lock, *flags);
}

static int clocksource_watchdog_kthread(void *data);
static void __clocksource_change_rating(struct clocksource *cs, int rating);

#define WATCHDOG_INTERVAL (HZ >> 1)

static void clocksource_watchdog_work(struct work_struct *work)
{
	/*
	kthread_run(clocksource_watchdog_kthread, NULL, "kwatchdog");
}

static void __clocksource_unstable(struct clocksource *cs)
{
	cs->flags &= ~(CLOCK_SOURCE_VALID_FOR_HRES | CLOCK_SOURCE_WATCHDOG);
	cs->flags |= CLOCK_SOURCE_UNSTABLE;

	/*
	if (list_empty(&cs->list)) {
		cs->rating = 0;
		return;
	}

	if (cs->mark_unstable)
		cs->mark_unstable(cs);

	/* kick clocksource_watchdog_kthread() */
	if (finished_booting)
		schedule_work(&watchdog_work);
}

void clocksource_mark_unstable(struct clocksource *cs)
{
	unsigned long flags;

	spin_lock_irqsave(&watchdog_lock, flags);
	if (!(cs->flags & CLOCK_SOURCE_UNSTABLE)) {
		if (!list_empty(&cs->list) && list_empty(&cs->wd_list))
			list_add(&cs->wd_list, &watchdog_list);
		__clocksource_unstable(cs);
	}
	spin_unlock_irqrestore(&watchdog_lock, flags);
}

ulong max_cswd_read_retries = 2;
module_param(max_cswd_read_retries, ulong, 0644);
EXPORT_SYMBOL_GPL(max_cswd_read_retries);
static int verify_n_cpus = 8;
module_param(verify_n_cpus, int, 0644);

enum wd_read_status {
	WD_READ_SUCCESS,
	WD_READ_UNSTABLE,
	WD_READ_SKIP
};

static enum wd_read_status cs_watchdog_read(struct clocksource *cs, u64 *csnow, u64 *wdnow)
{
	unsigned int nretries;
	u64 wd_end, wd_end2, wd_delta;
	int64_t wd_delay, wd_seq_delay;

	for (nretries = 0; nretries <= max_cswd_read_retries; nretries++) {
		local_irq_disable();
		*wdnow = watchdog->read(watchdog);
		*csnow = cs->read(cs);
		wd_end = watchdog->read(watchdog);
		wd_end2 = watchdog->read(watchdog);
		local_irq_enable();

		wd_delta = clocksource_delta(wd_end, *wdnow, watchdog->mask);
		wd_delay = clocksource_cyc2ns(wd_delta, watchdog->mult,
					      watchdog->shift);
		if (wd_delay <= WATCHDOG_MAX_SKEW) {
			if (nretries > 1 || nretries >= max_cswd_read_retries) {
				pr_warn("timekeeping watchdog on CPU%d: %s retried %d times before success\n",
					smp_processor_id(), watchdog->name, nretries);
			}
			return WD_READ_SUCCESS;
		}

		/*
		wd_delta = clocksource_delta(wd_end2, wd_end, watchdog->mask);
		wd_seq_delay = clocksource_cyc2ns(wd_delta, watchdog->mult, watchdog->shift);
		if (wd_seq_delay > WATCHDOG_MAX_SKEW/2)
			goto skip_test;
	}

	pr_warn("timekeeping watchdog on CPU%d: %s read-back delay of %lldns, attempt %d, marking unstable\n",
		smp_processor_id(), watchdog->name, wd_delay, nretries);
	return WD_READ_UNSTABLE;

skip_test:
	pr_info("timekeeping watchdog on CPU%d: %s wd-wd read-back delay of %lldns\n",
		smp_processor_id(), watchdog->name, wd_seq_delay);
	pr_info("wd-%s-wd read-back delay of %lldns, clock-skew test skipped!\n",
		cs->name, wd_delay);
	return WD_READ_SKIP;
}

static u64 csnow_mid;
static cpumask_t cpus_ahead;
static cpumask_t cpus_behind;
static cpumask_t cpus_chosen;

static void clocksource_verify_choose_cpus(void)
{
	int cpu, i, n = verify_n_cpus;

	if (n < 0) {
		/* Check all of the CPUs. */
		cpumask_copy(&cpus_chosen, cpu_online_mask);
		cpumask_clear_cpu(smp_processor_id(), &cpus_chosen);
		return;
	}

	/* If no checking desired, or no other CPU to check, leave. */
	cpumask_clear(&cpus_chosen);
	if (n == 0 || num_online_cpus() <= 1)
		return;

	/* Make sure to select at least one CPU other than the current CPU. */
	cpu = cpumask_first(cpu_online_mask);
	if (cpu == smp_processor_id())
		cpu = cpumask_next(cpu, cpu_online_mask);
	if (WARN_ON_ONCE(cpu >= nr_cpu_ids))
		return;
	cpumask_set_cpu(cpu, &cpus_chosen);

	/* Force a sane value for the boot parameter. */
	if (n > nr_cpu_ids)
		n = nr_cpu_ids;

	/*
	for (i = 1; i < n; i++) {
		cpu = prandom_u32() % nr_cpu_ids;
		cpu = cpumask_next(cpu - 1, cpu_online_mask);
		if (cpu >= nr_cpu_ids)
			cpu = cpumask_first(cpu_online_mask);
		if (!WARN_ON_ONCE(cpu >= nr_cpu_ids))
			cpumask_set_cpu(cpu, &cpus_chosen);
	}

	/* Don't verify ourselves. */
	cpumask_clear_cpu(smp_processor_id(), &cpus_chosen);
}

static void clocksource_verify_one_cpu(void *csin)
{
	struct clocksource *cs = (struct clocksource *)csin;

	csnow_mid = cs->read(cs);
}

void clocksource_verify_percpu(struct clocksource *cs)
{
	int64_t cs_nsec, cs_nsec_max = 0, cs_nsec_min = LLONG_MAX;
	u64 csnow_begin, csnow_end;
	int cpu, testcpu;
	s64 delta;

	if (verify_n_cpus == 0)
		return;
	cpumask_clear(&cpus_ahead);
	cpumask_clear(&cpus_behind);
	cpus_read_lock();
	preempt_disable();
	clocksource_verify_choose_cpus();
	if (cpumask_empty(&cpus_chosen)) {
		preempt_enable();
		cpus_read_unlock();
		pr_warn("Not enough CPUs to check clocksource '%s'.\n", cs->name);
		return;
	}
	testcpu = smp_processor_id();
	pr_warn("Checking clocksource %s synchronization from CPU %d to CPUs %*pbl.\n", cs->name, testcpu, cpumask_pr_args(&cpus_chosen));
	for_each_cpu(cpu, &cpus_chosen) {
		if (cpu == testcpu)
			continue;
		csnow_begin = cs->read(cs);
		smp_call_function_single(cpu, clocksource_verify_one_cpu, cs, 1);
		csnow_end = cs->read(cs);
		delta = (s64)((csnow_mid - csnow_begin) & cs->mask);
		if (delta < 0)
			cpumask_set_cpu(cpu, &cpus_behind);
		delta = (csnow_end - csnow_mid) & cs->mask;
		if (delta < 0)
			cpumask_set_cpu(cpu, &cpus_ahead);
		delta = clocksource_delta(csnow_end, csnow_begin, cs->mask);
		cs_nsec = clocksource_cyc2ns(delta, cs->mult, cs->shift);
		if (cs_nsec > cs_nsec_max)
			cs_nsec_max = cs_nsec;
		if (cs_nsec < cs_nsec_min)
			cs_nsec_min = cs_nsec;
	}
	preempt_enable();
	cpus_read_unlock();
	if (!cpumask_empty(&cpus_ahead))
		pr_warn("        CPUs %*pbl ahead of CPU %d for clocksource %s.\n",
			cpumask_pr_args(&cpus_ahead), testcpu, cs->name);
	if (!cpumask_empty(&cpus_behind))
		pr_warn("        CPUs %*pbl behind CPU %d for clocksource %s.\n",
			cpumask_pr_args(&cpus_behind), testcpu, cs->name);
	if (!cpumask_empty(&cpus_ahead) || !cpumask_empty(&cpus_behind))
		pr_warn("        CPU %d check durations %lldns - %lldns for clocksource %s.\n",
			testcpu, cs_nsec_min, cs_nsec_max, cs->name);
}
EXPORT_SYMBOL_GPL(clocksource_verify_percpu);

static void clocksource_watchdog(struct timer_list *unused)
{
	u64 csnow, wdnow, cslast, wdlast, delta;
	int next_cpu, reset_pending;
	int64_t wd_nsec, cs_nsec;
	struct clocksource *cs;
	enum wd_read_status read_ret;
	u32 md;

	spin_lock(&watchdog_lock);
	if (!watchdog_running)
		goto out;

	reset_pending = atomic_read(&watchdog_reset_pending);

	list_for_each_entry(cs, &watchdog_list, wd_list) {

		/* Clocksource already marked unstable? */
		if (cs->flags & CLOCK_SOURCE_UNSTABLE) {
			if (finished_booting)
				schedule_work(&watchdog_work);
			continue;
		}

		read_ret = cs_watchdog_read(cs, &csnow, &wdnow);

		if (read_ret != WD_READ_SUCCESS) {
			if (read_ret == WD_READ_UNSTABLE)
				/* Clock readout unreliable, so give it up. */
				__clocksource_unstable(cs);
			continue;
		}

		/* Clocksource initialized ? */
		if (!(cs->flags & CLOCK_SOURCE_WATCHDOG) ||
		    atomic_read(&watchdog_reset_pending)) {
			cs->flags |= CLOCK_SOURCE_WATCHDOG;
			cs->wd_last = wdnow;
			cs->cs_last = csnow;
			continue;
		}

		delta = clocksource_delta(wdnow, cs->wd_last, watchdog->mask);
		wd_nsec = clocksource_cyc2ns(delta, watchdog->mult,
					     watchdog->shift);

		delta = clocksource_delta(csnow, cs->cs_last, cs->mask);
		cs_nsec = clocksource_cyc2ns(delta, cs->mult, cs->shift);
		wdlast = cs->wd_last; /* save these in case we print them */
		cslast = cs->cs_last;
		cs->cs_last = csnow;
		cs->wd_last = wdnow;

		if (atomic_read(&watchdog_reset_pending))
			continue;

		/* Check the deviation from the watchdog clocksource. */
		md = cs->uncertainty_margin + watchdog->uncertainty_margin;
		if (abs(cs_nsec - wd_nsec) > md) {
			pr_warn("timekeeping watchdog on CPU%d: Marking clocksource '%s' as unstable because the skew is too large:\n",
				smp_processor_id(), cs->name);
			pr_warn("                      '%s' wd_nsec: %lld wd_now: %llx wd_last: %llx mask: %llx\n",
				watchdog->name, wd_nsec, wdnow, wdlast, watchdog->mask);
			pr_warn("                      '%s' cs_nsec: %lld cs_now: %llx cs_last: %llx mask: %llx\n",
				cs->name, cs_nsec, csnow, cslast, cs->mask);
			if (curr_clocksource == cs)
				pr_warn("                      '%s' is current clocksource.\n", cs->name);
			else if (curr_clocksource)
				pr_warn("                      '%s' (not '%s') is current clocksource.\n", curr_clocksource->name, cs->name);
			else
				pr_warn("                      No current clocksource.\n");
			__clocksource_unstable(cs);
			continue;
		}

		if (cs == curr_clocksource && cs->tick_stable)
			cs->tick_stable(cs);

		if (!(cs->flags & CLOCK_SOURCE_VALID_FOR_HRES) &&
		    (cs->flags & CLOCK_SOURCE_IS_CONTINUOUS) &&
		    (watchdog->flags & CLOCK_SOURCE_IS_CONTINUOUS)) {
			/* Mark it valid for high-res. */
			cs->flags |= CLOCK_SOURCE_VALID_FOR_HRES;

			/*
			if (!finished_booting)
				continue;

			/*
			if (cs != curr_clocksource) {
				cs->flags |= CLOCK_SOURCE_RESELECT;
				schedule_work(&watchdog_work);
			} else {
				tick_clock_notify();
			}
		}
	}

	/*
	if (reset_pending)
		atomic_dec(&watchdog_reset_pending);

	/*
	next_cpu = cpumask_next(raw_smp_processor_id(), cpu_online_mask);
	if (next_cpu >= nr_cpu_ids)
		next_cpu = cpumask_first(cpu_online_mask);

	/*
	if (!timer_pending(&watchdog_timer)) {
		watchdog_timer.expires += WATCHDOG_INTERVAL;
		add_timer_on(&watchdog_timer, next_cpu);
	}
out:
	spin_unlock(&watchdog_lock);
}

static inline void clocksource_start_watchdog(void)
{
	if (watchdog_running || !watchdog || list_empty(&watchdog_list))
		return;
	timer_setup(&watchdog_timer, clocksource_watchdog, 0);
	watchdog_timer.expires = jiffies + WATCHDOG_INTERVAL;
	add_timer_on(&watchdog_timer, cpumask_first(cpu_online_mask));
	watchdog_running = 1;
}

static inline void clocksource_stop_watchdog(void)
{
	if (!watchdog_running || (watchdog && !list_empty(&watchdog_list)))
		return;
	del_timer(&watchdog_timer);
	watchdog_running = 0;
}

static inline void clocksource_reset_watchdog(void)
{
	struct clocksource *cs;

	list_for_each_entry(cs, &watchdog_list, wd_list)
		cs->flags &= ~CLOCK_SOURCE_WATCHDOG;
}

static void clocksource_resume_watchdog(void)
{
	atomic_inc(&watchdog_reset_pending);
}

static void clocksource_enqueue_watchdog(struct clocksource *cs)
{
	INIT_LIST_HEAD(&cs->wd_list);

	if (cs->flags & CLOCK_SOURCE_MUST_VERIFY) {
		/* cs is a clocksource to be watched. */
		list_add(&cs->wd_list, &watchdog_list);
		cs->flags &= ~CLOCK_SOURCE_WATCHDOG;
	} else {
		/* cs is a watchdog. */
		if (cs->flags & CLOCK_SOURCE_IS_CONTINUOUS)
			cs->flags |= CLOCK_SOURCE_VALID_FOR_HRES;
	}
}

static void clocksource_select_watchdog(bool fallback)
{
	struct clocksource *cs, *old_wd;
	unsigned long flags;

	spin_lock_irqsave(&watchdog_lock, flags);
	/* save current watchdog */
	old_wd = watchdog;
	if (fallback)
		watchdog = NULL;

	list_for_each_entry(cs, &clocksource_list, list) {
		/* cs is a clocksource to be watched. */
		if (cs->flags & CLOCK_SOURCE_MUST_VERIFY)
			continue;

		/* Skip current if we were requested for a fallback. */
		if (fallback && cs == old_wd)
			continue;

		/* Pick the best watchdog. */
		if (!watchdog || cs->rating > watchdog->rating)
			watchdog = cs;
	}
	/* If we failed to find a fallback restore the old one. */
	if (!watchdog)
		watchdog = old_wd;

	/* If we changed the watchdog we need to reset cycles. */
	if (watchdog != old_wd)
		clocksource_reset_watchdog();

	/* Check if the watchdog timer needs to be started. */
	clocksource_start_watchdog();
	spin_unlock_irqrestore(&watchdog_lock, flags);
}

static void clocksource_dequeue_watchdog(struct clocksource *cs)
{
	if (cs != watchdog) {
		if (cs->flags & CLOCK_SOURCE_MUST_VERIFY) {
			/* cs is a watched clocksource. */
			list_del_init(&cs->wd_list);
			/* Check if the watchdog timer needs to be stopped. */
			clocksource_stop_watchdog();
		}
	}
}

static int __clocksource_watchdog_kthread(void)
{
	struct clocksource *cs, *tmp;
	unsigned long flags;
	int select = 0;

	/* Do any required per-CPU skew verification. */
	if (curr_clocksource &&
	    curr_clocksource->flags & CLOCK_SOURCE_UNSTABLE &&
	    curr_clocksource->flags & CLOCK_SOURCE_VERIFY_PERCPU)
		clocksource_verify_percpu(curr_clocksource);

	spin_lock_irqsave(&watchdog_lock, flags);
	list_for_each_entry_safe(cs, tmp, &watchdog_list, wd_list) {
		if (cs->flags & CLOCK_SOURCE_UNSTABLE) {
			list_del_init(&cs->wd_list);
			__clocksource_change_rating(cs, 0);
			select = 1;
		}
		if (cs->flags & CLOCK_SOURCE_RESELECT) {
			cs->flags &= ~CLOCK_SOURCE_RESELECT;
			select = 1;
		}
	}
	/* Check if the watchdog timer needs to be stopped. */
	clocksource_stop_watchdog();
	spin_unlock_irqrestore(&watchdog_lock, flags);

	return select;
}

static int clocksource_watchdog_kthread(void *data)
{
	mutex_lock(&clocksource_mutex);
	if (__clocksource_watchdog_kthread())
		clocksource_select();
	mutex_unlock(&clocksource_mutex);
	return 0;
}

static bool clocksource_is_watchdog(struct clocksource *cs)
{
	return cs == watchdog;
}

#else /* CONFIG_CLOCKSOURCE_WATCHDOG */

static void clocksource_enqueue_watchdog(struct clocksource *cs)
{
	if (cs->flags & CLOCK_SOURCE_IS_CONTINUOUS)
		cs->flags |= CLOCK_SOURCE_VALID_FOR_HRES;
}

static void clocksource_select_watchdog(bool fallback) { }
static inline void clocksource_dequeue_watchdog(struct clocksource *cs) { }
static inline void clocksource_resume_watchdog(void) { }
static inline int __clocksource_watchdog_kthread(void) { return 0; }
static bool clocksource_is_watchdog(struct clocksource *cs) { return false; }
void clocksource_mark_unstable(struct clocksource *cs) { }

static inline void clocksource_watchdog_lock(unsigned long *flags) { }
static inline void clocksource_watchdog_unlock(unsigned long *flags) { }

#endif /* CONFIG_CLOCKSOURCE_WATCHDOG */

static bool clocksource_is_suspend(struct clocksource *cs)
{
	return cs == suspend_clocksource;
}

static void __clocksource_suspend_select(struct clocksource *cs)
{
	/*
	if (!(cs->flags & CLOCK_SOURCE_SUSPEND_NONSTOP))
		return;

	/*
	if (cs->suspend || cs->resume) {
		pr_warn("Nonstop clocksource %s should not supply suspend/resume interfaces\n",
			cs->name);
	}

	/* Pick the best rating. */
	if (!suspend_clocksource || cs->rating > suspend_clocksource->rating)
		suspend_clocksource = cs;
}

static void clocksource_suspend_select(bool fallback)
{
	struct clocksource *cs, *old_suspend;

	old_suspend = suspend_clocksource;
	if (fallback)
		suspend_clocksource = NULL;

	list_for_each_entry(cs, &clocksource_list, list) {
		/* Skip current if we were requested for a fallback. */
		if (fallback && cs == old_suspend)
			continue;

		__clocksource_suspend_select(cs);
	}
}

void clocksource_start_suspend_timing(struct clocksource *cs, u64 start_cycles)
{
	if (!suspend_clocksource)
		return;

	/*
	if (clocksource_is_suspend(cs)) {
		suspend_start = start_cycles;
		return;
	}

	if (suspend_clocksource->enable &&
	    suspend_clocksource->enable(suspend_clocksource)) {
		pr_warn_once("Failed to enable the non-suspend-able clocksource.\n");
		return;
	}

	suspend_start = suspend_clocksource->read(suspend_clocksource);
}

u64 clocksource_stop_suspend_timing(struct clocksource *cs, u64 cycle_now)
{
	u64 now, delta, nsec = 0;

	if (!suspend_clocksource)
		return 0;

	/*
	if (clocksource_is_suspend(cs))
		now = cycle_now;
	else
		now = suspend_clocksource->read(suspend_clocksource);

	if (now > suspend_start) {
		delta = clocksource_delta(now, suspend_start,
					  suspend_clocksource->mask);
		nsec = mul_u64_u32_shr(delta, suspend_clocksource->mult,
				       suspend_clocksource->shift);
	}

	/*
	if (!clocksource_is_suspend(cs) && suspend_clocksource->disable)
		suspend_clocksource->disable(suspend_clocksource);

	return nsec;
}

void clocksource_suspend(void)
{
	struct clocksource *cs;

	list_for_each_entry_reverse(cs, &clocksource_list, list)
		if (cs->suspend)
			cs->suspend(cs);
}

void clocksource_resume(void)
{
	struct clocksource *cs;

	list_for_each_entry(cs, &clocksource_list, list)
		if (cs->resume)
			cs->resume(cs);

	clocksource_resume_watchdog();
}

void clocksource_touch_watchdog(void)
{
	clocksource_resume_watchdog();
}

static u32 clocksource_max_adjustment(struct clocksource *cs)
{
	u64 ret;
	/*
	ret = (u64)cs->mult * 11;
	do_div(ret,100);
	return (u32)ret;
}

u64 clocks_calc_max_nsecs(u32 mult, u32 shift, u32 maxadj, u64 mask, u64 *max_cyc)
{
	u64 max_nsecs, max_cycles;

	/*
	max_cycles = ULLONG_MAX;
	do_div(max_cycles, mult+maxadj);

	/*
	max_cycles = min(max_cycles, mask);
	max_nsecs = clocksource_cyc2ns(max_cycles, mult - maxadj, shift);

	/* return the max_cycles value as well if requested */
	if (max_cyc)
		*max_cyc = max_cycles;

	/* Return 50% of the actual maximum, so we can detect bad values */
	max_nsecs >>= 1;

	return max_nsecs;
}

static inline void clocksource_update_max_deferment(struct clocksource *cs)
{
	cs->max_idle_ns = clocks_calc_max_nsecs(cs->mult, cs->shift,
						cs->maxadj, cs->mask,
						&cs->max_cycles);
}

static struct clocksource *clocksource_find_best(bool oneshot, bool skipcur)
{
	struct clocksource *cs;

	if (!finished_booting || list_empty(&clocksource_list))
		return NULL;

	/*
	list_for_each_entry(cs, &clocksource_list, list) {
		if (skipcur && cs == curr_clocksource)
			continue;
		if (oneshot && !(cs->flags & CLOCK_SOURCE_VALID_FOR_HRES))
			continue;
		return cs;
	}
	return NULL;
}

static void __clocksource_select(bool skipcur)
{
	bool oneshot = tick_oneshot_mode_active();
	struct clocksource *best, *cs;

	/* Find the best suitable clocksource */
	best = clocksource_find_best(oneshot, skipcur);
	if (!best)
		return;

	if (!strlen(override_name))
		goto found;

	/* Check for the override clocksource. */
	list_for_each_entry(cs, &clocksource_list, list) {
		if (skipcur && cs == curr_clocksource)
			continue;
		if (strcmp(cs->name, override_name) != 0)
			continue;
		/*
		if (!(cs->flags & CLOCK_SOURCE_VALID_FOR_HRES) && oneshot) {
			/* Override clocksource cannot be used. */
			if (cs->flags & CLOCK_SOURCE_UNSTABLE) {
				pr_warn("Override clocksource %s is unstable and not HRT compatible - cannot switch while in HRT/NOHZ mode\n",
					cs->name);
				override_name[0] = 0;
			} else {
				/*
				pr_info("Override clocksource %s is not currently HRT compatible - deferring\n",
					cs->name);
			}
		} else
			/* Override clocksource can be used. */
			best = cs;
		break;
	}

found:
	if (curr_clocksource != best && !timekeeping_notify(best)) {
		pr_info("Switched to clocksource %s\n", best->name);
		curr_clocksource = best;
	}
}

static void clocksource_select(void)
{
	__clocksource_select(false);
}

static void clocksource_select_fallback(void)
{
	__clocksource_select(true);
}

static int __init clocksource_done_booting(void)
{
	mutex_lock(&clocksource_mutex);
	curr_clocksource = clocksource_default_clock();
	finished_booting = 1;
	/*
	__clocksource_watchdog_kthread();
	clocksource_select();
	mutex_unlock(&clocksource_mutex);
	return 0;
}
fs_initcall(clocksource_done_booting);

static void clocksource_enqueue(struct clocksource *cs)
{
	struct list_head *entry = &clocksource_list;
	struct clocksource *tmp;

	list_for_each_entry(tmp, &clocksource_list, list) {
		/* Keep track of the place, where to insert */
		if (tmp->rating < cs->rating)
			break;
		entry = &tmp->list;
	}
	list_add(&cs->list, entry);
}

void __clocksource_update_freq_scale(struct clocksource *cs, u32 scale, u32 freq)
{
	u64 sec;

	/*
	if (freq) {
		/*
		sec = cs->mask;
		do_div(sec, freq);
		do_div(sec, scale);
		if (!sec)
			sec = 1;
		else if (sec > 600 && cs->mask > UINT_MAX)
			sec = 600;

		clocks_calc_mult_shift(&cs->mult, &cs->shift, freq,
				       NSEC_PER_SEC / scale, sec * scale);
	}

	/*
	if (scale && freq && !cs->uncertainty_margin) {
		cs->uncertainty_margin = NSEC_PER_SEC / (scale * freq);
		if (cs->uncertainty_margin < 2 * WATCHDOG_MAX_SKEW)
			cs->uncertainty_margin = 2 * WATCHDOG_MAX_SKEW;
	} else if (!cs->uncertainty_margin) {
		cs->uncertainty_margin = WATCHDOG_THRESHOLD;
	}
	WARN_ON_ONCE(cs->uncertainty_margin < 2 * WATCHDOG_MAX_SKEW);

	/*
	cs->maxadj = clocksource_max_adjustment(cs);
	while (freq && ((cs->mult + cs->maxadj < cs->mult)
		|| (cs->mult - cs->maxadj > cs->mult))) {
		cs->mult >>= 1;
		cs->shift--;
		cs->maxadj = clocksource_max_adjustment(cs);
	}

	/*
	WARN_ONCE(cs->mult + cs->maxadj < cs->mult,
		"timekeeping: Clocksource %s might overflow on 11%% adjustment\n",
		cs->name);

	clocksource_update_max_deferment(cs);

	pr_info("%s: mask: 0x%llx max_cycles: 0x%llx, max_idle_ns: %lld ns\n",
		cs->name, cs->mask, cs->max_cycles, cs->max_idle_ns);
}
EXPORT_SYMBOL_GPL(__clocksource_update_freq_scale);

int __clocksource_register_scale(struct clocksource *cs, u32 scale, u32 freq)
{
	unsigned long flags;

	clocksource_arch_init(cs);

	if (WARN_ON_ONCE((unsigned int)cs->id >= CSID_MAX))
		cs->id = CSID_GENERIC;
	if (cs->vdso_clock_mode < 0 ||
	    cs->vdso_clock_mode >= VDSO_CLOCKMODE_MAX) {
		pr_warn("clocksource %s registered with invalid VDSO mode %d. Disabling VDSO support.\n",
			cs->name, cs->vdso_clock_mode);
		cs->vdso_clock_mode = VDSO_CLOCKMODE_NONE;
	}

	/* Initialize mult/shift and max_idle_ns */
	__clocksource_update_freq_scale(cs, scale, freq);

	/* Add clocksource to the clocksource list */
	mutex_lock(&clocksource_mutex);

	clocksource_watchdog_lock(&flags);
	clocksource_enqueue(cs);
	clocksource_enqueue_watchdog(cs);
	clocksource_watchdog_unlock(&flags);

	clocksource_select();
	clocksource_select_watchdog(false);
	__clocksource_suspend_select(cs);
	mutex_unlock(&clocksource_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(__clocksource_register_scale);

static void __clocksource_change_rating(struct clocksource *cs, int rating)
{
	list_del(&cs->list);
	cs->rating = rating;
	clocksource_enqueue(cs);
}

void clocksource_change_rating(struct clocksource *cs, int rating)
{
	unsigned long flags;

	mutex_lock(&clocksource_mutex);
	clocksource_watchdog_lock(&flags);
	__clocksource_change_rating(cs, rating);
	clocksource_watchdog_unlock(&flags);

	clocksource_select();
	clocksource_select_watchdog(false);
	clocksource_suspend_select(false);
	mutex_unlock(&clocksource_mutex);
}
EXPORT_SYMBOL(clocksource_change_rating);

static int clocksource_unbind(struct clocksource *cs)
{
	unsigned long flags;

	if (clocksource_is_watchdog(cs)) {
		/* Select and try to install a replacement watchdog. */
		clocksource_select_watchdog(true);
		if (clocksource_is_watchdog(cs))
			return -EBUSY;
	}

	if (cs == curr_clocksource) {
		/* Select and try to install a replacement clock source */
		clocksource_select_fallback();
		if (curr_clocksource == cs)
			return -EBUSY;
	}

	if (clocksource_is_suspend(cs)) {
		/*
		clocksource_suspend_select(true);
	}

	clocksource_watchdog_lock(&flags);
	clocksource_dequeue_watchdog(cs);
	list_del_init(&cs->list);
	clocksource_watchdog_unlock(&flags);

	return 0;
}

int clocksource_unregister(struct clocksource *cs)
{
	int ret = 0;

	mutex_lock(&clocksource_mutex);
	if (!list_empty(&cs->list))
		ret = clocksource_unbind(cs);
	mutex_unlock(&clocksource_mutex);
	return ret;
}
EXPORT_SYMBOL(clocksource_unregister);

#ifdef CONFIG_SYSFS
static ssize_t current_clocksource_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	ssize_t count = 0;

	mutex_lock(&clocksource_mutex);
	count = snprintf(buf, PAGE_SIZE, "%s\n", curr_clocksource->name);
	mutex_unlock(&clocksource_mutex);

	return count;
}

ssize_t sysfs_get_uname(const char *buf, char *dst, size_t cnt)
{
	size_t ret = cnt;

	/* strings from sysfs write are not 0 terminated! */
	if (!cnt || cnt >= CS_NAME_LEN)
		return -EINVAL;

	/* strip of \n: */
	if (buf[cnt-1] == '\n')
		cnt--;
	if (cnt > 0)
		memcpy(dst, buf, cnt);
	dst[cnt] = 0;
	return ret;
}

static ssize_t current_clocksource_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	ssize_t ret;

	mutex_lock(&clocksource_mutex);

	ret = sysfs_get_uname(buf, override_name, count);
	if (ret >= 0)
		clocksource_select();

	mutex_unlock(&clocksource_mutex);

	return ret;
}
static DEVICE_ATTR_RW(current_clocksource);

static ssize_t unbind_clocksource_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct clocksource *cs;
	char name[CS_NAME_LEN];
	ssize_t ret;

	ret = sysfs_get_uname(buf, name, count);
	if (ret < 0)
		return ret;

	ret = -ENODEV;
	mutex_lock(&clocksource_mutex);
	list_for_each_entry(cs, &clocksource_list, list) {
		if (strcmp(cs->name, name))
			continue;
		ret = clocksource_unbind(cs);
		break;
	}
	mutex_unlock(&clocksource_mutex);

	return ret ? ret : count;
}
static DEVICE_ATTR_WO(unbind_clocksource);

static ssize_t available_clocksource_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct clocksource *src;
	ssize_t count = 0;

	mutex_lock(&clocksource_mutex);
	list_for_each_entry(src, &clocksource_list, list) {
		/*
		if (!tick_oneshot_mode_active() ||
		    (src->flags & CLOCK_SOURCE_VALID_FOR_HRES))
			count += snprintf(buf + count,
				  max((ssize_t)PAGE_SIZE - count, (ssize_t)0),
				  "%s ", src->name);
	}
	mutex_unlock(&clocksource_mutex);

	count += snprintf(buf + count,
			  max((ssize_t)PAGE_SIZE - count, (ssize_t)0), "\n");

	return count;
}
static DEVICE_ATTR_RO(available_clocksource);

static struct attribute *clocksource_attrs[] = {
	&dev_attr_current_clocksource.attr,
	&dev_attr_unbind_clocksource.attr,
	&dev_attr_available_clocksource.attr,
	NULL
};
ATTRIBUTE_GROUPS(clocksource);

static struct bus_type clocksource_subsys = {
	.name = "clocksource",
	.dev_name = "clocksource",
};

static struct device device_clocksource = {
	.id	= 0,
	.bus	= &clocksource_subsys,
	.groups	= clocksource_groups,
};

static int __init init_clocksource_sysfs(void)
{
	int error = subsys_system_register(&clocksource_subsys, NULL);

	if (!error)
		error = device_register(&device_clocksource);

	return error;
}

device_initcall(init_clocksource_sysfs);
#endif /* CONFIG_SYSFS */

static int __init boot_override_clocksource(char* str)
{
	mutex_lock(&clocksource_mutex);
	if (str)
		strlcpy(override_name, str, sizeof(override_name));
	mutex_unlock(&clocksource_mutex);
	return 1;
}

__setup("clocksource=", boot_override_clocksource);

static int __init boot_override_clock(char* str)
{
	if (!strcmp(str, "pmtmr")) {
		pr_warn("clock=pmtmr is deprecated - use clocksource=acpi_pm\n");
		return boot_override_clocksource("acpi_pm");
	}
	pr_warn("clock= boot option is deprecated - use clocksource=xyz\n");
	return boot_override_clocksource(str);
}

__setup("clock=", boot_override_clock);
