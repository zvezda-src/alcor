#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/timer.h>
#include <linux/acpi_pmtmr.h>
#include <linux/cpufreq.h>
#include <linux/delay.h>
#include <linux/clocksource.h>
#include <linux/percpu.h>
#include <linux/timex.h>
#include <linux/static_key.h>
#include <linux/static_call.h>

#include <asm/hpet.h>
#include <asm/timer.h>
#include <asm/vgtod.h>
#include <asm/time.h>
#include <asm/delay.h>
#include <asm/hypervisor.h>
#include <asm/nmi.h>
#include <asm/x86_init.h>
#include <asm/geode.h>
#include <asm/apic.h>
#include <asm/intel-family.h>
#include <asm/i8259.h>
#include <asm/uv/uv.h>

unsigned int __read_mostly cpu_khz;	/* TSC clocks / usec, not used here */
EXPORT_SYMBOL(cpu_khz);

unsigned int __read_mostly tsc_khz;
EXPORT_SYMBOL(tsc_khz);

#define KHZ	1000

static int __read_mostly tsc_unstable;
static unsigned int __initdata tsc_early_khz;

static DEFINE_STATIC_KEY_FALSE(__use_tsc);

int tsc_clocksource_reliable;

static u32 art_to_tsc_numerator;
static u32 art_to_tsc_denominator;
static u64 art_to_tsc_offset;
struct clocksource *art_related_clocksource;

struct cyc2ns {
	struct cyc2ns_data data[2];	/*  0 + 2*16 = 32 */
	seqcount_latch_t   seq;		/* 32 + 4    = 36 */

}; /* fits one cacheline */

static DEFINE_PER_CPU_ALIGNED(struct cyc2ns, cyc2ns);

static int __init tsc_early_khz_setup(char *buf)
{
	return kstrtouint(buf, 0, &tsc_early_khz);
}
early_param("tsc_early_khz", tsc_early_khz_setup);

__always_inline void cyc2ns_read_begin(struct cyc2ns_data *data)
{
	int seq, idx;

	preempt_disable_notrace();

	do {
		seq = this_cpu_read(cyc2ns.seq.seqcount.sequence);
		idx = seq & 1;

		data->cyc2ns_offset = this_cpu_read(cyc2ns.data[idx].cyc2ns_offset);
		data->cyc2ns_mul    = this_cpu_read(cyc2ns.data[idx].cyc2ns_mul);
		data->cyc2ns_shift  = this_cpu_read(cyc2ns.data[idx].cyc2ns_shift);

	} while (unlikely(seq != this_cpu_read(cyc2ns.seq.seqcount.sequence)));
}

__always_inline void cyc2ns_read_end(void)
{
	preempt_enable_notrace();
}


static __always_inline unsigned long long cycles_2_ns(unsigned long long cyc)
{
	struct cyc2ns_data data;
	unsigned long long ns;

	cyc2ns_read_begin(&data);

	ns = data.cyc2ns_offset;
	ns += mul_u64_u32_shr(cyc, data.cyc2ns_mul, data.cyc2ns_shift);

	cyc2ns_read_end();

	return ns;
}

static void __set_cyc2ns_scale(unsigned long khz, int cpu, unsigned long long tsc_now)
{
	unsigned long long ns_now;
	struct cyc2ns_data data;
	struct cyc2ns *c2n;

	ns_now = cycles_2_ns(tsc_now);

	/*
	clocks_calc_mult_shift(&data.cyc2ns_mul, &data.cyc2ns_shift, khz,
			       NSEC_PER_MSEC, 0);

	/*
	if (data.cyc2ns_shift == 32) {
		data.cyc2ns_shift = 31;
		data.cyc2ns_mul >>= 1;
	}

	data.cyc2ns_offset = ns_now -
		mul_u64_u32_shr(tsc_now, data.cyc2ns_mul, data.cyc2ns_shift);

	c2n = per_cpu_ptr(&cyc2ns, cpu);

	raw_write_seqcount_latch(&c2n->seq);
	c2n->data[0] = data;
	raw_write_seqcount_latch(&c2n->seq);
	c2n->data[1] = data;
}

static void set_cyc2ns_scale(unsigned long khz, int cpu, unsigned long long tsc_now)
{
	unsigned long flags;

	local_irq_save(flags);
	sched_clock_idle_sleep_event();

	if (khz)
		__set_cyc2ns_scale(khz, cpu, tsc_now);

	sched_clock_idle_wakeup_event();
	local_irq_restore(flags);
}

static void __init cyc2ns_init_boot_cpu(void)
{
	struct cyc2ns *c2n = this_cpu_ptr(&cyc2ns);

	seqcount_latch_init(&c2n->seq);
	__set_cyc2ns_scale(tsc_khz, smp_processor_id(), rdtsc());
}

static void __init cyc2ns_init_secondary_cpus(void)
{
	unsigned int cpu, this_cpu = smp_processor_id();
	struct cyc2ns *c2n = this_cpu_ptr(&cyc2ns);
	struct cyc2ns_data *data = c2n->data;

	for_each_possible_cpu(cpu) {
		if (cpu != this_cpu) {
			seqcount_latch_init(&c2n->seq);
			c2n = per_cpu_ptr(&cyc2ns, cpu);
			c2n->data[0] = data[0];
			c2n->data[1] = data[1];
		}
	}
}

u64 native_sched_clock(void)
{
	if (static_branch_likely(&__use_tsc)) {
		u64 tsc_now = rdtsc();

		/* return the value in ns */
		return cycles_2_ns(tsc_now);
	}

	/*

	/* No locking but a rare wrong value is not a big deal: */
	return (jiffies_64 - INITIAL_JIFFIES) * (1000000000 / HZ);
}

u64 native_sched_clock_from_tsc(u64 tsc)
{
	return cycles_2_ns(tsc);
}

   weak default version */
#ifdef CONFIG_PARAVIRT
unsigned long long sched_clock(void)
{
	return paravirt_sched_clock();
}

bool using_native_sched_clock(void)
{
	return static_call_query(pv_sched_clock) == native_sched_clock;
}
#else
unsigned long long
sched_clock(void) __attribute__((alias("native_sched_clock")));

bool using_native_sched_clock(void) { return true; }
#endif

int check_tsc_unstable(void)
{
	return tsc_unstable;
}
EXPORT_SYMBOL_GPL(check_tsc_unstable);

#ifdef CONFIG_X86_TSC
int __init notsc_setup(char *str)
{
	mark_tsc_unstable("boot parameter notsc");
	return 1;
}
#else
int __init notsc_setup(char *str)
{
	setup_clear_cpu_cap(X86_FEATURE_TSC);
	return 1;
}
#endif

__setup("notsc", notsc_setup);

static int no_sched_irq_time;
static int no_tsc_watchdog;

static int __init tsc_setup(char *str)
{
	if (!strcmp(str, "reliable"))
		tsc_clocksource_reliable = 1;
	if (!strncmp(str, "noirqtime", 9))
		no_sched_irq_time = 1;
	if (!strcmp(str, "unstable"))
		mark_tsc_unstable("boot parameter");
	if (!strcmp(str, "nowatchdog"))
		no_tsc_watchdog = 1;
	return 1;
}

__setup("tsc=", tsc_setup);

#define MAX_RETRIES		5
#define TSC_DEFAULT_THRESHOLD	0x20000

static u64 tsc_read_refs(u64 *p, int hpet)
{
	u64 t1, t2;
	u64 thresh = tsc_khz ? tsc_khz >> 5 : TSC_DEFAULT_THRESHOLD;
	int i;

	for (i = 0; i < MAX_RETRIES; i++) {
		t1 = get_cycles();
		if (hpet)
			*p = hpet_readl(HPET_COUNTER) & 0xFFFFFFFF;
		else
			*p = acpi_pm_read_early();
		t2 = get_cycles();
		if ((t2 - t1) < thresh)
			return t2;
	}
	return ULLONG_MAX;
}

static unsigned long calc_hpet_ref(u64 deltatsc, u64 hpet1, u64 hpet2)
{
	u64 tmp;

	if (hpet2 < hpet1)
		hpet2 += 0x100000000ULL;
	hpet2 -= hpet1;
	tmp = ((u64)hpet2 * hpet_readl(HPET_PERIOD));
	do_div(tmp, 1000000);
	deltatsc = div64_u64(deltatsc, tmp);

	return (unsigned long) deltatsc;
}

static unsigned long calc_pmtimer_ref(u64 deltatsc, u64 pm1, u64 pm2)
{
	u64 tmp;

	if (!pm1 && !pm2)
		return ULONG_MAX;

	if (pm2 < pm1)
		pm2 += (u64)ACPI_PM_OVRRUN;
	pm2 -= pm1;
	tmp = pm2 * 1000000000LL;
	do_div(tmp, PMTMR_TICKS_PER_SEC);
	do_div(deltatsc, tmp);

	return (unsigned long) deltatsc;
}

#define CAL_MS		10
#define CAL_LATCH	(PIT_TICK_RATE / (1000 / CAL_MS))
#define CAL_PIT_LOOPS	1000

#define CAL2_MS		50
#define CAL2_LATCH	(PIT_TICK_RATE / (1000 / CAL2_MS))
#define CAL2_PIT_LOOPS	5000


static unsigned long pit_calibrate_tsc(u32 latch, unsigned long ms, int loopmin)
{
	u64 tsc, t1, t2, delta;
	unsigned long tscmin, tscmax;
	int pitcnt;

	if (!has_legacy_pic()) {
		/*
		udelay(10 * USEC_PER_MSEC);
		udelay(10 * USEC_PER_MSEC);
		udelay(10 * USEC_PER_MSEC);
		udelay(10 * USEC_PER_MSEC);
		udelay(10 * USEC_PER_MSEC);
		return ULONG_MAX;
	}

	/* Set the Gate high, disable speaker */
	outb((inb(0x61) & ~0x02) | 0x01, 0x61);

	/*
	outb(0xb0, 0x43);
	outb(latch & 0xff, 0x42);
	outb(latch >> 8, 0x42);

	tsc = t1 = t2 = get_cycles();

	pitcnt = 0;
	tscmax = 0;
	tscmin = ULONG_MAX;
	while ((inb(0x61) & 0x20) == 0) {
		t2 = get_cycles();
		delta = t2 - tsc;
		tsc = t2;
		if ((unsigned long) delta < tscmin)
			tscmin = (unsigned int) delta;
		if ((unsigned long) delta > tscmax)
			tscmax = (unsigned int) delta;
		pitcnt++;
	}

	/*
	if (pitcnt < loopmin || tscmax > 10 * tscmin)
		return ULONG_MAX;

	/* Calculate the PIT value */
	delta = t2 - t1;
	do_div(delta, ms);
	return delta;
}

static inline int pit_verify_msb(unsigned char val)
{
	/* Ignore LSB */
	inb(0x42);
	return inb(0x42) == val;
}

static inline int pit_expect_msb(unsigned char val, u64 *tscp, unsigned long *deltap)
{
	int count;
	u64 tsc = 0, prev_tsc = 0;

	for (count = 0; count < 50000; count++) {
		if (!pit_verify_msb(val))
			break;
		prev_tsc = tsc;
		tsc = get_cycles();
	}

	/*
	return count > 5;
}

#define MAX_QUICK_PIT_MS 50
#define MAX_QUICK_PIT_ITERATIONS (MAX_QUICK_PIT_MS * PIT_TICK_RATE / 1000 / 256)

static unsigned long quick_pit_calibrate(void)
{
	int i;
	u64 tsc, delta;
	unsigned long d1, d2;

	if (!has_legacy_pic())
		return 0;

	/* Set the Gate high, disable speaker */
	outb((inb(0x61) & ~0x02) | 0x01, 0x61);

	/*
	outb(0xb0, 0x43);

	/* Start at 0xffff */
	outb(0xff, 0x42);
	outb(0xff, 0x42);

	/*
	pit_verify_msb(0);

	if (pit_expect_msb(0xff, &tsc, &d1)) {
		for (i = 1; i <= MAX_QUICK_PIT_ITERATIONS; i++) {
			if (!pit_expect_msb(0xff-i, &delta, &d2))
				break;

			delta -= tsc;

			/*
			if (i == 1 &&
			    d1 + d2 >= (delta * MAX_QUICK_PIT_ITERATIONS) >> 11)
				return 0;

			/*
			if (d1+d2 >= delta >> 11)
				continue;

			/*
			if (!pit_verify_msb(0xfe - i))
				break;
			goto success;
		}
	}
	pr_info("Fast TSC calibration failed\n");
	return 0;

success:
	/*
	delta *= PIT_TICK_RATE;
	do_div(delta, i*256*1000);
	pr_info("Fast TSC calibration using PIT\n");
	return delta;
}

unsigned long native_calibrate_tsc(void)
{
	unsigned int eax_denominator, ebx_numerator, ecx_hz, edx;
	unsigned int crystal_khz;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return 0;

	if (boot_cpu_data.cpuid_level < 0x15)
		return 0;

	eax_denominator = ebx_numerator = ecx_hz = edx = 0;

	/* CPUID 15H TSC/Crystal ratio, plus optionally Crystal Hz */
	cpuid(0x15, &eax_denominator, &ebx_numerator, &ecx_hz, &edx);

	if (ebx_numerator == 0 || eax_denominator == 0)
		return 0;

	crystal_khz = ecx_hz / 1000;

	/*
	if (crystal_khz == 0 &&
			boot_cpu_data.x86_model == INTEL_FAM6_ATOM_GOLDMONT_D)
		crystal_khz = 25000;

	/*
	if (crystal_khz != 0)
		setup_force_cpu_cap(X86_FEATURE_TSC_KNOWN_FREQ);

	/*
	if (crystal_khz == 0 && boot_cpu_data.cpuid_level >= 0x16) {
		unsigned int eax_base_mhz, ebx, ecx, edx;

		cpuid(0x16, &eax_base_mhz, &ebx, &ecx, &edx);
		crystal_khz = eax_base_mhz * 1000 *
			eax_denominator / ebx_numerator;
	}

	if (crystal_khz == 0)
		return 0;

	/*
	if (boot_cpu_data.x86_model == INTEL_FAM6_ATOM_GOLDMONT)
		setup_force_cpu_cap(X86_FEATURE_TSC_RELIABLE);

#ifdef CONFIG_X86_LOCAL_APIC
	/*
	lapic_timer_period = crystal_khz * 1000 / HZ;
#endif

	return crystal_khz * ebx_numerator / eax_denominator;
}

static unsigned long cpu_khz_from_cpuid(void)
{
	unsigned int eax_base_mhz, ebx_max_mhz, ecx_bus_mhz, edx;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return 0;

	if (boot_cpu_data.cpuid_level < 0x16)
		return 0;

	eax_base_mhz = ebx_max_mhz = ecx_bus_mhz = edx = 0;

	cpuid(0x16, &eax_base_mhz, &ebx_max_mhz, &ecx_bus_mhz, &edx);

	return eax_base_mhz * 1000;
}

static unsigned long pit_hpet_ptimer_calibrate_cpu(void)
{
	u64 tsc1, tsc2, delta, ref1, ref2;
	unsigned long tsc_pit_min = ULONG_MAX, tsc_ref_min = ULONG_MAX;
	unsigned long flags, latch, ms;
	int hpet = is_hpet_enabled(), i, loopmin;

	/*

	/* Preset PIT loop values */
	latch = CAL_LATCH;
	ms = CAL_MS;
	loopmin = CAL_PIT_LOOPS;

	for (i = 0; i < 3; i++) {
		unsigned long tsc_pit_khz;

		/*
		local_irq_save(flags);
		tsc1 = tsc_read_refs(&ref1, hpet);
		tsc_pit_khz = pit_calibrate_tsc(latch, ms, loopmin);
		tsc2 = tsc_read_refs(&ref2, hpet);
		local_irq_restore(flags);

		/* Pick the lowest PIT TSC calibration so far */
		tsc_pit_min = min(tsc_pit_min, tsc_pit_khz);

		/* hpet or pmtimer available ? */
		if (ref1 == ref2)
			continue;

		/* Check, whether the sampling was disturbed */
		if (tsc1 == ULLONG_MAX || tsc2 == ULLONG_MAX)
			continue;

		tsc2 = (tsc2 - tsc1) * 1000000LL;
		if (hpet)
			tsc2 = calc_hpet_ref(tsc2, ref1, ref2);
		else
			tsc2 = calc_pmtimer_ref(tsc2, ref1, ref2);

		tsc_ref_min = min(tsc_ref_min, (unsigned long) tsc2);

		/* Check the reference deviation */
		delta = ((u64) tsc_pit_min) * 100;
		do_div(delta, tsc_ref_min);

		/*
		if (delta >= 90 && delta <= 110) {
			pr_info("PIT calibration matches %s. %d loops\n",
				hpet ? "HPET" : "PMTIMER", i + 1);
			return tsc_ref_min;
		}

		/*
		if (i == 1 && tsc_pit_min == ULONG_MAX) {
			latch = CAL2_LATCH;
			ms = CAL2_MS;
			loopmin = CAL2_PIT_LOOPS;
		}
	}

	/*
	if (tsc_pit_min == ULONG_MAX) {
		/* PIT gave no useful value */
		pr_warn("Unable to calibrate against PIT\n");

		/* We don't have an alternative source, disable TSC */
		if (!hpet && !ref1 && !ref2) {
			pr_notice("No reference (HPET/PMTIMER) available\n");
			return 0;
		}

		/* The alternative source failed as well, disable TSC */
		if (tsc_ref_min == ULONG_MAX) {
			pr_warn("HPET/PMTIMER calibration failed\n");
			return 0;
		}

		/* Use the alternative source */
		pr_info("using %s reference calibration\n",
			hpet ? "HPET" : "PMTIMER");

		return tsc_ref_min;
	}

	/* We don't have an alternative source, use the PIT calibration value */
	if (!hpet && !ref1 && !ref2) {
		pr_info("Using PIT calibration value\n");
		return tsc_pit_min;
	}

	/* The alternative source failed, use the PIT calibration value */
	if (tsc_ref_min == ULONG_MAX) {
		pr_warn("HPET/PMTIMER calibration failed. Using PIT calibration.\n");
		return tsc_pit_min;
	}

	/*
	pr_warn("PIT calibration deviates from %s: %lu %lu\n",
		hpet ? "HPET" : "PMTIMER", tsc_pit_min, tsc_ref_min);
	pr_info("Using PIT calibration value\n");
	return tsc_pit_min;
}

unsigned long native_calibrate_cpu_early(void)
{
	unsigned long flags, fast_calibrate = cpu_khz_from_cpuid();

	if (!fast_calibrate)
		fast_calibrate = cpu_khz_from_msr();
	if (!fast_calibrate) {
		local_irq_save(flags);
		fast_calibrate = quick_pit_calibrate();
		local_irq_restore(flags);
	}
	return fast_calibrate;
}


static unsigned long native_calibrate_cpu(void)
{
	unsigned long tsc_freq = native_calibrate_cpu_early();

	if (!tsc_freq)
		tsc_freq = pit_hpet_ptimer_calibrate_cpu();

	return tsc_freq;
}

void recalibrate_cpu_khz(void)
{
#ifndef CONFIG_SMP
	unsigned long cpu_khz_old = cpu_khz;

	if (!boot_cpu_has(X86_FEATURE_TSC))
		return;

	cpu_khz = x86_platform.calibrate_cpu();
	tsc_khz = x86_platform.calibrate_tsc();
	if (tsc_khz == 0)
		tsc_khz = cpu_khz;
	else if (abs(cpu_khz - tsc_khz) * 10 > tsc_khz)
		cpu_khz = tsc_khz;
	cpu_data(0).loops_per_jiffy = cpufreq_scale(cpu_data(0).loops_per_jiffy,
						    cpu_khz_old, cpu_khz);
#endif
}

EXPORT_SYMBOL(recalibrate_cpu_khz);


static unsigned long long cyc2ns_suspend;

void tsc_save_sched_clock_state(void)
{
	if (!sched_clock_stable())
		return;

	cyc2ns_suspend = sched_clock();
}

void tsc_restore_sched_clock_state(void)
{
	unsigned long long offset;
	unsigned long flags;
	int cpu;

	if (!sched_clock_stable())
		return;

	local_irq_save(flags);

	/*

	this_cpu_write(cyc2ns.data[0].cyc2ns_offset, 0);
	this_cpu_write(cyc2ns.data[1].cyc2ns_offset, 0);

	offset = cyc2ns_suspend - sched_clock();

	for_each_possible_cpu(cpu) {
		per_cpu(cyc2ns.data[0].cyc2ns_offset, cpu) = offset;
		per_cpu(cyc2ns.data[1].cyc2ns_offset, cpu) = offset;
	}

	local_irq_restore(flags);
}

#ifdef CONFIG_CPU_FREQ

static unsigned int  ref_freq;
static unsigned long loops_per_jiffy_ref;
static unsigned long tsc_khz_ref;

static int time_cpufreq_notifier(struct notifier_block *nb, unsigned long val,
				void *data)
{
	struct cpufreq_freqs *freq = data;

	if (num_online_cpus() > 1) {
		mark_tsc_unstable("cpufreq changes on SMP");
		return 0;
	}

	if (!ref_freq) {
		ref_freq = freq->old;
		loops_per_jiffy_ref = boot_cpu_data.loops_per_jiffy;
		tsc_khz_ref = tsc_khz;
	}

	if ((val == CPUFREQ_PRECHANGE  && freq->old < freq->new) ||
	    (val == CPUFREQ_POSTCHANGE && freq->old > freq->new)) {
		boot_cpu_data.loops_per_jiffy =
			cpufreq_scale(loops_per_jiffy_ref, ref_freq, freq->new);

		tsc_khz = cpufreq_scale(tsc_khz_ref, ref_freq, freq->new);
		if (!(freq->flags & CPUFREQ_CONST_LOOPS))
			mark_tsc_unstable("cpufreq changes");

		set_cyc2ns_scale(tsc_khz, freq->policy->cpu, rdtsc());
	}

	return 0;
}

static struct notifier_block time_cpufreq_notifier_block = {
	.notifier_call  = time_cpufreq_notifier
};

static int __init cpufreq_register_tsc_scaling(void)
{
	if (!boot_cpu_has(X86_FEATURE_TSC))
		return 0;
	if (boot_cpu_has(X86_FEATURE_CONSTANT_TSC))
		return 0;
	cpufreq_register_notifier(&time_cpufreq_notifier_block,
				CPUFREQ_TRANSITION_NOTIFIER);
	return 0;
}

core_initcall(cpufreq_register_tsc_scaling);

#endif /* CONFIG_CPU_FREQ */

#define ART_CPUID_LEAF (0x15)
#define ART_MIN_DENOMINATOR (1)


static void __init detect_art(void)
{
	unsigned int unused[2];

	if (boot_cpu_data.cpuid_level < ART_CPUID_LEAF)
		return;

	/*
	if (boot_cpu_has(X86_FEATURE_HYPERVISOR) ||
	    !boot_cpu_has(X86_FEATURE_NONSTOP_TSC) ||
	    !boot_cpu_has(X86_FEATURE_TSC_ADJUST) ||
	    tsc_async_resets)
		return;

	cpuid(ART_CPUID_LEAF, &art_to_tsc_denominator,
	      &art_to_tsc_numerator, unused, unused+1);

	if (art_to_tsc_denominator < ART_MIN_DENOMINATOR)
		return;

	rdmsrl(MSR_IA32_TSC_ADJUST, art_to_tsc_offset);

	/* Make this sticky over multiple CPU init calls */
	setup_force_cpu_cap(X86_FEATURE_ART);
}



static void tsc_resume(struct clocksource *cs)
{
	tsc_verify_tsc_adjust(true);
}

static u64 read_tsc(struct clocksource *cs)
{
	return (u64)rdtsc_ordered();
}

static void tsc_cs_mark_unstable(struct clocksource *cs)
{
	if (tsc_unstable)
		return;

	tsc_unstable = 1;
	if (using_native_sched_clock())
		clear_sched_clock_stable();
	disable_sched_clock_irqtime();
	pr_info("Marking TSC unstable due to clocksource watchdog\n");
}

static void tsc_cs_tick_stable(struct clocksource *cs)
{
	if (tsc_unstable)
		return;

	if (using_native_sched_clock())
		sched_clock_tick_stable();
}

static int tsc_cs_enable(struct clocksource *cs)
{
	vclocks_set_used(VDSO_CLOCKMODE_TSC);
	return 0;
}

static struct clocksource clocksource_tsc_early = {
	.name			= "tsc-early",
	.rating			= 299,
	.uncertainty_margin	= 32 * NSEC_PER_MSEC,
	.read			= read_tsc,
	.mask			= CLOCKSOURCE_MASK(64),
	.flags			= CLOCK_SOURCE_IS_CONTINUOUS |
				  CLOCK_SOURCE_MUST_VERIFY,
	.vdso_clock_mode	= VDSO_CLOCKMODE_TSC,
	.enable			= tsc_cs_enable,
	.resume			= tsc_resume,
	.mark_unstable		= tsc_cs_mark_unstable,
	.tick_stable		= tsc_cs_tick_stable,
	.list			= LIST_HEAD_INIT(clocksource_tsc_early.list),
};

static struct clocksource clocksource_tsc = {
	.name			= "tsc",
	.rating			= 300,
	.read			= read_tsc,
	.mask			= CLOCKSOURCE_MASK(64),
	.flags			= CLOCK_SOURCE_IS_CONTINUOUS |
				  CLOCK_SOURCE_VALID_FOR_HRES |
				  CLOCK_SOURCE_MUST_VERIFY |
				  CLOCK_SOURCE_VERIFY_PERCPU,
	.vdso_clock_mode	= VDSO_CLOCKMODE_TSC,
	.enable			= tsc_cs_enable,
	.resume			= tsc_resume,
	.mark_unstable		= tsc_cs_mark_unstable,
	.tick_stable		= tsc_cs_tick_stable,
	.list			= LIST_HEAD_INIT(clocksource_tsc.list),
};

void mark_tsc_unstable(char *reason)
{
	if (tsc_unstable)
		return;

	tsc_unstable = 1;
	if (using_native_sched_clock())
		clear_sched_clock_stable();
	disable_sched_clock_irqtime();
	pr_info("Marking TSC unstable due to %s\n", reason);

	clocksource_mark_unstable(&clocksource_tsc_early);
	clocksource_mark_unstable(&clocksource_tsc);
}

EXPORT_SYMBOL_GPL(mark_tsc_unstable);

static void __init tsc_disable_clocksource_watchdog(void)
{
	clocksource_tsc_early.flags &= ~CLOCK_SOURCE_MUST_VERIFY;
	clocksource_tsc.flags &= ~CLOCK_SOURCE_MUST_VERIFY;
}

static void __init check_system_tsc_reliable(void)
{
#if defined(CONFIG_MGEODEGX1) || defined(CONFIG_MGEODE_LX) || defined(CONFIG_X86_GENERIC)
	if (is_geode_lx()) {
		/* RTSC counts during suspend */
#define RTSC_SUSP 0x100
		unsigned long res_low, res_high;

		rdmsr_safe(MSR_GEODE_BUSCONT_CONF0, &res_low, &res_high);
		/* Geode_LX - the OLPC CPU has a very reliable TSC */
		if (res_low & RTSC_SUSP)
			tsc_clocksource_reliable = 1;
	}
#endif
	if (boot_cpu_has(X86_FEATURE_TSC_RELIABLE))
		tsc_clocksource_reliable = 1;

	/*
	if (boot_cpu_has(X86_FEATURE_CONSTANT_TSC) &&
	    boot_cpu_has(X86_FEATURE_NONSTOP_TSC) &&
	    boot_cpu_has(X86_FEATURE_TSC_ADJUST) &&
	    nr_online_nodes <= 2)
		tsc_disable_clocksource_watchdog();
}

int unsynchronized_tsc(void)
{
	if (!boot_cpu_has(X86_FEATURE_TSC) || tsc_unstable)
		return 1;

#ifdef CONFIG_SMP
	if (apic_is_clustered_box())
		return 1;
#endif

	if (boot_cpu_has(X86_FEATURE_CONSTANT_TSC))
		return 0;

	if (tsc_clocksource_reliable)
		return 0;
	/*
	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL) {
		/* assume multi socket systems are not synchronized: */
		if (num_possible_cpus() > 1)
			return 1;
	}

	return 0;
}

struct system_counterval_t convert_art_to_tsc(u64 art)
{
	u64 tmp, res, rem;

	rem = do_div(art, art_to_tsc_denominator);

	res = art * art_to_tsc_numerator;
	tmp = rem * art_to_tsc_numerator;

	do_div(tmp, art_to_tsc_denominator);
	res += tmp + art_to_tsc_offset;

	return (struct system_counterval_t) {.cs = art_related_clocksource,
			.cycles = res};
}
EXPORT_SYMBOL(convert_art_to_tsc);


struct system_counterval_t convert_art_ns_to_tsc(u64 art_ns)
{
	u64 tmp, res, rem;

	rem = do_div(art_ns, USEC_PER_SEC);

	res = art_ns * tsc_khz;
	tmp = rem * tsc_khz;

	do_div(tmp, USEC_PER_SEC);
	res += tmp;

	return (struct system_counterval_t) { .cs = art_related_clocksource,
					      .cycles = res};
}
EXPORT_SYMBOL(convert_art_ns_to_tsc);


static void tsc_refine_calibration_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(tsc_irqwork, tsc_refine_calibration_work);
static void tsc_refine_calibration_work(struct work_struct *work)
{
	static u64 tsc_start = ULLONG_MAX, ref_start;
	static int hpet;
	u64 tsc_stop, ref_stop, delta;
	unsigned long freq;
	int cpu;

	/* Don't bother refining TSC on unstable systems */
	if (tsc_unstable)
		goto unreg;

	/*
	if (tsc_start == ULLONG_MAX) {
restart:
		/*
		hpet = is_hpet_enabled();
		tsc_start = tsc_read_refs(&ref_start, hpet);
		schedule_delayed_work(&tsc_irqwork, HZ);
		return;
	}

	tsc_stop = tsc_read_refs(&ref_stop, hpet);

	/* hpet or pmtimer available ? */
	if (ref_start == ref_stop)
		goto out;

	/* Check, whether the sampling was disturbed */
	if (tsc_stop == ULLONG_MAX)
		goto restart;

	delta = tsc_stop - tsc_start;
	delta *= 1000000LL;
	if (hpet)
		freq = calc_hpet_ref(delta, ref_start, ref_stop);
	else
		freq = calc_pmtimer_ref(delta, ref_start, ref_stop);

	/* Make sure we're within 1% */
	if (abs(tsc_khz - freq) > tsc_khz/100)
		goto out;

	tsc_khz = freq;
	pr_info("Refined TSC clocksource calibration: %lu.%03lu MHz\n",
		(unsigned long)tsc_khz / 1000,
		(unsigned long)tsc_khz % 1000);

	/* Inform the TSC deadline clockevent devices about the recalibration */
	lapic_update_tsc_freq();

	/* Update the sched_clock() rate to match the clocksource one */
	for_each_possible_cpu(cpu)
		set_cyc2ns_scale(tsc_khz, cpu, tsc_stop);

out:
	if (tsc_unstable)
		goto unreg;

	if (boot_cpu_has(X86_FEATURE_ART))
		art_related_clocksource = &clocksource_tsc;
	clocksource_register_khz(&clocksource_tsc, tsc_khz);
unreg:
	clocksource_unregister(&clocksource_tsc_early);
}


static int __init init_tsc_clocksource(void)
{
	if (!boot_cpu_has(X86_FEATURE_TSC) || !tsc_khz)
		return 0;

	if (tsc_unstable)
		goto unreg;

	if (boot_cpu_has(X86_FEATURE_NONSTOP_TSC_S3))
		clocksource_tsc.flags |= CLOCK_SOURCE_SUSPEND_NONSTOP;

	/*
	if (boot_cpu_has(X86_FEATURE_TSC_KNOWN_FREQ)) {
		if (boot_cpu_has(X86_FEATURE_ART))
			art_related_clocksource = &clocksource_tsc;
		clocksource_register_khz(&clocksource_tsc, tsc_khz);
unreg:
		clocksource_unregister(&clocksource_tsc_early);
		return 0;
	}

	schedule_delayed_work(&tsc_irqwork, 0);
	return 0;
}
device_initcall(init_tsc_clocksource);

static bool __init determine_cpu_tsc_frequencies(bool early)
{
	/* Make sure that cpu and tsc are not already calibrated */
	WARN_ON(cpu_khz || tsc_khz);

	if (early) {
		cpu_khz = x86_platform.calibrate_cpu();
		if (tsc_early_khz)
			tsc_khz = tsc_early_khz;
		else
			tsc_khz = x86_platform.calibrate_tsc();
	} else {
		/* We should not be here with non-native cpu calibration */
		WARN_ON(x86_platform.calibrate_cpu != native_calibrate_cpu);
		cpu_khz = pit_hpet_ptimer_calibrate_cpu();
	}

	/*
	if (tsc_khz == 0)
		tsc_khz = cpu_khz;
	else if (abs(cpu_khz - tsc_khz) * 10 > tsc_khz)
		cpu_khz = tsc_khz;

	if (tsc_khz == 0)
		return false;

	pr_info("Detected %lu.%03lu MHz processor\n",
		(unsigned long)cpu_khz / KHZ,
		(unsigned long)cpu_khz % KHZ);

	if (cpu_khz != tsc_khz) {
		pr_info("Detected %lu.%03lu MHz TSC",
			(unsigned long)tsc_khz / KHZ,
			(unsigned long)tsc_khz % KHZ);
	}
	return true;
}

static unsigned long __init get_loops_per_jiffy(void)
{
	u64 lpj = (u64)tsc_khz * KHZ;

	do_div(lpj, HZ);
	return lpj;
}

static void __init tsc_enable_sched_clock(void)
{
	loops_per_jiffy = get_loops_per_jiffy();
	use_tsc_delay();

	/* Sanitize TSC ADJUST before cyc2ns gets initialized */
	tsc_store_and_check_tsc_adjust(true);
	cyc2ns_init_boot_cpu();
	static_branch_enable(&__use_tsc);
}

void __init tsc_early_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_TSC))
		return;
	/* Don't change UV TSC multi-chassis synchronization */
	if (is_early_uv_system())
		return;
	if (!determine_cpu_tsc_frequencies(true))
		return;
	tsc_enable_sched_clock();
}

void __init tsc_init(void)
{
	/*
	if (x86_platform.calibrate_cpu == native_calibrate_cpu_early)
		x86_platform.calibrate_cpu = native_calibrate_cpu;

	if (!boot_cpu_has(X86_FEATURE_TSC)) {
		setup_clear_cpu_cap(X86_FEATURE_TSC_DEADLINE_TIMER);
		return;
	}

	if (!tsc_khz) {
		/* We failed to determine frequencies earlier, try again */
		if (!determine_cpu_tsc_frequencies(false)) {
			mark_tsc_unstable("could not calculate TSC khz");
			setup_clear_cpu_cap(X86_FEATURE_TSC_DEADLINE_TIMER);
			return;
		}
		tsc_enable_sched_clock();
	}

	cyc2ns_init_secondary_cpus();

	if (!no_sched_irq_time)
		enable_sched_clock_irqtime();

	lpj_fine = get_loops_per_jiffy();

	check_system_tsc_reliable();

	if (unsynchronized_tsc()) {
		mark_tsc_unstable("TSCs unsynchronized");
		return;
	}

	if (tsc_clocksource_reliable || no_tsc_watchdog)
		tsc_disable_clocksource_watchdog();

	clocksource_register_khz(&clocksource_tsc_early, tsc_khz);
	detect_art();
}

#ifdef CONFIG_SMP
unsigned long calibrate_delay_is_known(void)
{
	int sibling, cpu = smp_processor_id();
	int constant_tsc = cpu_has(&cpu_data(cpu), X86_FEATURE_CONSTANT_TSC);
	const struct cpumask *mask = topology_core_cpumask(cpu);

	if (!constant_tsc || !mask)
		return 0;

	sibling = cpumask_any_but(mask, cpu);
	if (sibling < nr_cpu_ids)
		return cpu_data(sibling).loops_per_jiffy;
	return 0;
}
#endif
