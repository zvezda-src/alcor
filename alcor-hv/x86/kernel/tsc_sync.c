#include <linux/topology.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/nmi.h>
#include <asm/tsc.h>

struct tsc_adjust {
	s64		bootval;
	s64		adjusted;
	unsigned long	nextcheck;
	bool		warned;
};

static DEFINE_PER_CPU(struct tsc_adjust, tsc_adjust);
static struct timer_list tsc_sync_check_timer;

bool __read_mostly tsc_async_resets;

void mark_tsc_async_resets(char *reason)
{
	if (tsc_async_resets)
		return;
	tsc_async_resets = true;
	pr_info("tsc: Marking TSC async resets true due to %s\n", reason);
}

void tsc_verify_tsc_adjust(bool resume)
{
	struct tsc_adjust *adj = this_cpu_ptr(&tsc_adjust);
	s64 curval;

	if (!boot_cpu_has(X86_FEATURE_TSC_ADJUST))
		return;

	/* Skip unnecessary error messages if TSC already unstable */
	if (check_tsc_unstable())
		return;

	/* Rate limit the MSR check */
	if (!resume && time_before(jiffies, adj->nextcheck))
		return;

	adj->nextcheck = jiffies + HZ;

	rdmsrl(MSR_IA32_TSC_ADJUST, curval);
	if (adj->adjusted == curval)
		return;

	/* Restore the original value */
	wrmsrl(MSR_IA32_TSC_ADJUST, adj->adjusted);

	if (!adj->warned || resume) {
		pr_warn(FW_BUG "TSC ADJUST differs: CPU%u %lld --> %lld. Restoring\n",
			smp_processor_id(), adj->adjusted, curval);
		adj->warned = true;
	}
}


#define SYNC_CHECK_INTERVAL		(HZ * 600)

static void tsc_sync_check_timer_fn(struct timer_list *unused)
{
	int next_cpu;

	tsc_verify_tsc_adjust(false);

	/* Run the check for all onlined CPUs in turn */
	next_cpu = cpumask_next(raw_smp_processor_id(), cpu_online_mask);
	if (next_cpu >= nr_cpu_ids)
		next_cpu = cpumask_first(cpu_online_mask);

	tsc_sync_check_timer.expires += SYNC_CHECK_INTERVAL;
	add_timer_on(&tsc_sync_check_timer, next_cpu);
}

static int __init start_sync_check_timer(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_TSC_ADJUST) || tsc_clocksource_reliable)
		return 0;

	timer_setup(&tsc_sync_check_timer, tsc_sync_check_timer_fn, 0);
	tsc_sync_check_timer.expires = jiffies + SYNC_CHECK_INTERVAL;
	add_timer(&tsc_sync_check_timer);

	return 0;
}
late_initcall(start_sync_check_timer);

static void tsc_sanitize_first_cpu(struct tsc_adjust *cur, s64 bootval,
				   unsigned int cpu, bool bootcpu)
{
	/*
	if (bootcpu && bootval != 0) {
		if (likely(!tsc_async_resets)) {
			pr_warn(FW_BUG "TSC ADJUST: CPU%u: %lld force to 0\n",
				cpu, bootval);
			wrmsrl(MSR_IA32_TSC_ADJUST, 0);
			bootval = 0;
		} else {
			pr_info("TSC ADJUST: CPU%u: %lld NOT forced to 0\n",
				cpu, bootval);
		}
	}
	cur->adjusted = bootval;
}

#ifndef CONFIG_SMP
bool __init tsc_store_and_check_tsc_adjust(bool bootcpu)
{
	struct tsc_adjust *cur = this_cpu_ptr(&tsc_adjust);
	s64 bootval;

	if (!boot_cpu_has(X86_FEATURE_TSC_ADJUST))
		return false;

	/* Skip unnecessary error messages if TSC already unstable */
	if (check_tsc_unstable())
		return false;

	rdmsrl(MSR_IA32_TSC_ADJUST, bootval);
	cur->bootval = bootval;
	cur->nextcheck = jiffies + HZ;
	tsc_sanitize_first_cpu(cur, bootval, smp_processor_id(), bootcpu);
	return false;
}

#else /* !CONFIG_SMP */

bool tsc_store_and_check_tsc_adjust(bool bootcpu)
{
	struct tsc_adjust *ref, *cur = this_cpu_ptr(&tsc_adjust);
	unsigned int refcpu, cpu = smp_processor_id();
	struct cpumask *mask;
	s64 bootval;

	if (!boot_cpu_has(X86_FEATURE_TSC_ADJUST))
		return false;

	rdmsrl(MSR_IA32_TSC_ADJUST, bootval);
	cur->bootval = bootval;
	cur->nextcheck = jiffies + HZ;
	cur->warned = false;

	/*
	if (tsc_async_resets)
		cur->adjusted = bootval;

	/*
	mask = topology_core_cpumask(cpu);
	refcpu = mask ? cpumask_any_but(mask, cpu) : nr_cpu_ids;

	if (refcpu >= nr_cpu_ids) {
		tsc_sanitize_first_cpu(cur, bootval, smp_processor_id(),
				       bootcpu);
		return false;
	}

	ref = per_cpu_ptr(&tsc_adjust, refcpu);
	/*
	if (bootval != ref->bootval)
		printk_once(FW_BUG "TSC ADJUST differs within socket(s), fixing all errors\n");

	/*
	if (bootval != ref->adjusted) {
		cur->adjusted = ref->adjusted;
		wrmsrl(MSR_IA32_TSC_ADJUST, ref->adjusted);
	}
	/*
	return true;
}

static atomic_t start_count;
static atomic_t stop_count;
static atomic_t skip_test;
static atomic_t test_runs;

static arch_spinlock_t sync_lock = __ARCH_SPIN_LOCK_UNLOCKED;

static cycles_t last_tsc;
static cycles_t max_warp;
static int nr_warps;
static int random_warps;

static cycles_t check_tsc_warp(unsigned int timeout)
{
	cycles_t start, now, prev, end, cur_max_warp = 0;
	int i, cur_warps = 0;

	start = rdtsc_ordered();
	/*
	end = start + (cycles_t) tsc_khz * timeout;

	for (i = 0; ; i++) {
		/*
		arch_spin_lock(&sync_lock);
		prev = last_tsc;
		now = rdtsc_ordered();
		last_tsc = now;
		arch_spin_unlock(&sync_lock);

		/*
		if (unlikely(!(i & 7))) {
			if (now > end || i > 10000000)
				break;
			cpu_relax();
			touch_nmi_watchdog();
		}
		/*
		if (unlikely(prev > now)) {
			arch_spin_lock(&sync_lock);
			max_warp = max(max_warp, prev - now);
			cur_max_warp = max_warp;
			/*
			if (cur_warps != nr_warps)
				random_warps++;
			nr_warps++;
			cur_warps = nr_warps;
			arch_spin_unlock(&sync_lock);
		}
	}
	WARN(!(now-start),
		"Warning: zero tsc calibration delta: %Ld [max: %Ld]\n",
			now-start, end-start);
	return cur_max_warp;
}

static inline unsigned int loop_timeout(int cpu)
{
	return (cpumask_weight(topology_core_cpumask(cpu)) > 1) ? 2 : 20;
}

void check_tsc_sync_source(int cpu)
{
	int cpus = 2;

	/*
	if (unsynchronized_tsc())
		return;

	/*
	if (!boot_cpu_has(X86_FEATURE_TSC_ADJUST))
		atomic_set(&test_runs, 1);
	else
		atomic_set(&test_runs, 3);
retry:
	/*
	while (atomic_read(&start_count) != cpus - 1) {
		if (atomic_read(&skip_test) > 0) {
			atomic_set(&skip_test, 0);
			return;
		}
		cpu_relax();
	}

	/*
	atomic_inc(&start_count);

	check_tsc_warp(loop_timeout(cpu));

	while (atomic_read(&stop_count) != cpus-1)
		cpu_relax();

	/*
	if (!nr_warps) {
		atomic_set(&test_runs, 0);

		pr_debug("TSC synchronization [CPU#%d -> CPU#%d]: passed\n",
			smp_processor_id(), cpu);

	} else if (atomic_dec_and_test(&test_runs) || random_warps) {
		/* Force it to 0 if random warps brought us here */
		atomic_set(&test_runs, 0);

		pr_warn("TSC synchronization [CPU#%d -> CPU#%d]:\n",
			smp_processor_id(), cpu);
		pr_warn("Measured %Ld cycles TSC warp between CPUs, "
			"turning off TSC clock.\n", max_warp);
		if (random_warps)
			pr_warn("TSC warped randomly between CPUs\n");
		mark_tsc_unstable("check_tsc_sync_source failed");
	}

	/*
	atomic_set(&start_count, 0);
	random_warps = 0;
	nr_warps = 0;
	max_warp = 0;
	last_tsc = 0;

	/*
	atomic_inc(&stop_count);

	/*
	if (atomic_read(&test_runs) > 0)
		goto retry;
}

void check_tsc_sync_target(void)
{
	struct tsc_adjust *cur = this_cpu_ptr(&tsc_adjust);
	unsigned int cpu = smp_processor_id();
	cycles_t cur_max_warp, gbl_max_warp;
	int cpus = 2;

	/* Also aborts if there is no TSC. */
	if (unsynchronized_tsc())
		return;

	/*
	if (tsc_store_and_check_tsc_adjust(false) || tsc_clocksource_reliable) {
		atomic_inc(&skip_test);
		return;
	}

retry:
	/*
	atomic_inc(&start_count);
	while (atomic_read(&start_count) != cpus)
		cpu_relax();

	cur_max_warp = check_tsc_warp(loop_timeout(cpu));

	/*
	gbl_max_warp = max_warp;

	/*
	atomic_inc(&stop_count);

	/*
	while (atomic_read(&stop_count) != cpus)
		cpu_relax();

	/*
	atomic_set(&stop_count, 0);

	/*
	if (!atomic_read(&test_runs))
		return;

	/*
	if (!cur_max_warp)
		cur_max_warp = -gbl_max_warp;

	/*
	cur->adjusted += cur_max_warp;

	pr_warn("TSC ADJUST compensate: CPU%u observed %lld warp. Adjust: %lld\n",
		cpu, cur_max_warp, cur->adjusted);

	wrmsrl(MSR_IA32_TSC_ADJUST, cur->adjusted);
	goto retry;

}

#endif /* CONFIG_SMP */
