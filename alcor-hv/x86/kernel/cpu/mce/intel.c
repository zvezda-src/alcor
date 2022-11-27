
#include <linux/gfp.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <asm/apic.h>
#include <asm/cpufeature.h>
#include <asm/intel-family.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/mce.h>

#include "internal.h"


static DEFINE_PER_CPU(mce_banks_t, mce_banks_owned);

static DEFINE_PER_CPU(int, cmci_backoff_cnt);

static DEFINE_RAW_SPINLOCK(cmci_discover_lock);

#define CMCI_THRESHOLD		1
#define CMCI_POLL_INTERVAL	(30 * HZ)
#define CMCI_STORM_INTERVAL	(HZ)
#define CMCI_STORM_THRESHOLD	15

static DEFINE_PER_CPU(unsigned long, cmci_time_stamp);
static DEFINE_PER_CPU(unsigned int, cmci_storm_cnt);
static DEFINE_PER_CPU(unsigned int, cmci_storm_state);

enum {
	CMCI_STORM_NONE,
	CMCI_STORM_ACTIVE,
	CMCI_STORM_SUBSIDED,
};

static atomic_t cmci_storm_on_cpus;

static int cmci_supported(int *banks)
{
	u64 cap;

	if (mca_cfg.cmci_disabled || mca_cfg.ignore_ce)
		return 0;

	/*
	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL &&
	    boot_cpu_data.x86_vendor != X86_VENDOR_ZHAOXIN)
		return 0;

	if (!boot_cpu_has(X86_FEATURE_APIC) || lapic_get_maxlvt() < 6)
		return 0;
	rdmsrl(MSR_IA32_MCG_CAP, cap);
	return !!(cap & MCG_CMCI_P);
}

static bool lmce_supported(void)
{
	u64 tmp;

	if (mca_cfg.lmce_disabled)
		return false;

	rdmsrl(MSR_IA32_MCG_CAP, tmp);

	/*
	if ((tmp & (MCG_SER_P | MCG_LMCE_P)) !=
		   (MCG_SER_P | MCG_LMCE_P))
		return false;

	/*
	rdmsrl(MSR_IA32_FEAT_CTL, tmp);
	if (WARN_ON_ONCE(!(tmp & FEAT_CTL_LOCKED)))
		return false;

	return tmp & FEAT_CTL_LMCE_ENABLED;
}

bool mce_intel_cmci_poll(void)
{
	if (__this_cpu_read(cmci_storm_state) == CMCI_STORM_NONE)
		return false;

	/*
	if (machine_check_poll(0, this_cpu_ptr(&mce_banks_owned)))
		this_cpu_write(cmci_backoff_cnt, INITIAL_CHECK_INTERVAL);
	else
		this_cpu_dec(cmci_backoff_cnt);

	return true;
}

void mce_intel_hcpu_update(unsigned long cpu)
{
	if (per_cpu(cmci_storm_state, cpu) == CMCI_STORM_ACTIVE)
		atomic_dec(&cmci_storm_on_cpus);

	per_cpu(cmci_storm_state, cpu) = CMCI_STORM_NONE;
}

static void cmci_toggle_interrupt_mode(bool on)
{
	unsigned long flags, *owned;
	int bank;
	u64 val;

	raw_spin_lock_irqsave(&cmci_discover_lock, flags);
	owned = this_cpu_ptr(mce_banks_owned);
	for_each_set_bit(bank, owned, MAX_NR_BANKS) {
		rdmsrl(MSR_IA32_MCx_CTL2(bank), val);

		if (on)
			val |= MCI_CTL2_CMCI_EN;
		else
			val &= ~MCI_CTL2_CMCI_EN;

		wrmsrl(MSR_IA32_MCx_CTL2(bank), val);
	}
	raw_spin_unlock_irqrestore(&cmci_discover_lock, flags);
}

unsigned long cmci_intel_adjust_timer(unsigned long interval)
{
	if ((this_cpu_read(cmci_backoff_cnt) > 0) &&
	    (__this_cpu_read(cmci_storm_state) == CMCI_STORM_ACTIVE)) {
		mce_notify_irq();
		return CMCI_STORM_INTERVAL;
	}

	switch (__this_cpu_read(cmci_storm_state)) {
	case CMCI_STORM_ACTIVE:

		/*
		__this_cpu_write(cmci_storm_state, CMCI_STORM_SUBSIDED);
		if (!atomic_sub_return(1, &cmci_storm_on_cpus))
			pr_notice("CMCI storm subsided: switching to interrupt mode\n");

		fallthrough;

	case CMCI_STORM_SUBSIDED:
		/*
		if (!atomic_read(&cmci_storm_on_cpus)) {
			__this_cpu_write(cmci_storm_state, CMCI_STORM_NONE);
			cmci_toggle_interrupt_mode(true);
			cmci_recheck();
		}
		return CMCI_POLL_INTERVAL;
	default:

		/* We have shiny weather. Let the poll do whatever it thinks. */
		return interval;
	}
}

static bool cmci_storm_detect(void)
{
	unsigned int cnt = __this_cpu_read(cmci_storm_cnt);
	unsigned long ts = __this_cpu_read(cmci_time_stamp);
	unsigned long now = jiffies;
	int r;

	if (__this_cpu_read(cmci_storm_state) != CMCI_STORM_NONE)
		return true;

	if (time_before_eq(now, ts + CMCI_STORM_INTERVAL)) {
		cnt++;
	} else {
		cnt = 1;
		__this_cpu_write(cmci_time_stamp, now);
	}
	__this_cpu_write(cmci_storm_cnt, cnt);

	if (cnt <= CMCI_STORM_THRESHOLD)
		return false;

	cmci_toggle_interrupt_mode(false);
	__this_cpu_write(cmci_storm_state, CMCI_STORM_ACTIVE);
	r = atomic_add_return(1, &cmci_storm_on_cpus);
	mce_timer_kick(CMCI_STORM_INTERVAL);
	this_cpu_write(cmci_backoff_cnt, INITIAL_CHECK_INTERVAL);

	if (r == 1)
		pr_notice("CMCI storm detected: switching to poll mode\n");
	return true;
}

static void intel_threshold_interrupt(void)
{
	if (cmci_storm_detect())
		return;

	machine_check_poll(MCP_TIMESTAMP, this_cpu_ptr(&mce_banks_owned));
}

static void cmci_discover(int banks)
{
	unsigned long *owned = (void *)this_cpu_ptr(&mce_banks_owned);
	unsigned long flags;
	int i;
	int bios_wrong_thresh = 0;

	raw_spin_lock_irqsave(&cmci_discover_lock, flags);
	for (i = 0; i < banks; i++) {
		u64 val;
		int bios_zero_thresh = 0;

		if (test_bit(i, owned))
			continue;

		/* Skip banks in firmware first mode */
		if (test_bit(i, mce_banks_ce_disabled))
			continue;

		rdmsrl(MSR_IA32_MCx_CTL2(i), val);

		/* Already owned by someone else? */
		if (val & MCI_CTL2_CMCI_EN) {
			clear_bit(i, owned);
			__clear_bit(i, this_cpu_ptr(mce_poll_banks));
			continue;
		}

		if (!mca_cfg.bios_cmci_threshold) {
			val &= ~MCI_CTL2_CMCI_THRESHOLD_MASK;
			val |= CMCI_THRESHOLD;
		} else if (!(val & MCI_CTL2_CMCI_THRESHOLD_MASK)) {
			/*
			bios_zero_thresh = 1;
			val |= CMCI_THRESHOLD;
		}

		val |= MCI_CTL2_CMCI_EN;
		wrmsrl(MSR_IA32_MCx_CTL2(i), val);
		rdmsrl(MSR_IA32_MCx_CTL2(i), val);

		/* Did the enable bit stick? -- the bank supports CMCI */
		if (val & MCI_CTL2_CMCI_EN) {
			set_bit(i, owned);
			__clear_bit(i, this_cpu_ptr(mce_poll_banks));
			/*
			if (mca_cfg.bios_cmci_threshold && bios_zero_thresh &&
					(val & MCI_CTL2_CMCI_THRESHOLD_MASK))
				bios_wrong_thresh = 1;
		} else {
			WARN_ON(!test_bit(i, this_cpu_ptr(mce_poll_banks)));
		}
	}
	raw_spin_unlock_irqrestore(&cmci_discover_lock, flags);
	if (mca_cfg.bios_cmci_threshold && bios_wrong_thresh) {
		pr_info_once(
			"bios_cmci_threshold: Some banks do not have valid thresholds set\n");
		pr_info_once(
			"bios_cmci_threshold: Make sure your BIOS supports this boot option\n");
	}
}

void cmci_recheck(void)
{
	unsigned long flags;
	int banks;

	if (!mce_available(raw_cpu_ptr(&cpu_info)) || !cmci_supported(&banks))
		return;

	local_irq_save(flags);
	machine_check_poll(0, this_cpu_ptr(&mce_banks_owned));
	local_irq_restore(flags);
}

static void __cmci_disable_bank(int bank)
{
	u64 val;

	if (!test_bit(bank, this_cpu_ptr(mce_banks_owned)))
		return;
	rdmsrl(MSR_IA32_MCx_CTL2(bank), val);
	val &= ~MCI_CTL2_CMCI_EN;
	wrmsrl(MSR_IA32_MCx_CTL2(bank), val);
	__clear_bit(bank, this_cpu_ptr(mce_banks_owned));
}

void cmci_clear(void)
{
	unsigned long flags;
	int i;
	int banks;

	if (!cmci_supported(&banks))
		return;
	raw_spin_lock_irqsave(&cmci_discover_lock, flags);
	for (i = 0; i < banks; i++)
		__cmci_disable_bank(i);
	raw_spin_unlock_irqrestore(&cmci_discover_lock, flags);
}

static void cmci_rediscover_work_func(void *arg)
{
	int banks;

	/* Recheck banks in case CPUs don't all have the same */
	if (cmci_supported(&banks))
		cmci_discover(banks);
}

void cmci_rediscover(void)
{
	int banks;

	if (!cmci_supported(&banks))
		return;

	on_each_cpu(cmci_rediscover_work_func, NULL, 1);
}

void cmci_reenable(void)
{
	int banks;
	if (cmci_supported(&banks))
		cmci_discover(banks);
}

void cmci_disable_bank(int bank)
{
	int banks;
	unsigned long flags;

	if (!cmci_supported(&banks))
		return;

	raw_spin_lock_irqsave(&cmci_discover_lock, flags);
	__cmci_disable_bank(bank);
	raw_spin_unlock_irqrestore(&cmci_discover_lock, flags);
}

void intel_init_cmci(void)
{
	int banks;

	if (!cmci_supported(&banks))
		return;

	mce_threshold_vector = intel_threshold_interrupt;
	cmci_discover(banks);
	/*
	apic_write(APIC_LVTCMCI, THRESHOLD_APIC_VECTOR|APIC_DM_FIXED);
	cmci_recheck();
}

void intel_init_lmce(void)
{
	u64 val;

	if (!lmce_supported())
		return;

	rdmsrl(MSR_IA32_MCG_EXT_CTL, val);

	if (!(val & MCG_EXT_CTL_LMCE_EN))
		wrmsrl(MSR_IA32_MCG_EXT_CTL, val | MCG_EXT_CTL_LMCE_EN);
}

void intel_clear_lmce(void)
{
	u64 val;

	if (!lmce_supported())
		return;

	rdmsrl(MSR_IA32_MCG_EXT_CTL, val);
	val &= ~MCG_EXT_CTL_LMCE_EN;
	wrmsrl(MSR_IA32_MCG_EXT_CTL, val);
}

static void intel_imc_init(struct cpuinfo_x86 *c)
{
	u64 error_control;

	switch (c->x86_model) {
	case INTEL_FAM6_SANDYBRIDGE_X:
	case INTEL_FAM6_IVYBRIDGE_X:
	case INTEL_FAM6_HASWELL_X:
		if (rdmsrl_safe(MSR_ERROR_CONTROL, &error_control))
			return;
		error_control |= 2;
		wrmsrl_safe(MSR_ERROR_CONTROL, error_control);
		break;
	}
}

void mce_intel_feature_init(struct cpuinfo_x86 *c)
{
	intel_init_cmci();
	intel_init_lmce();
	intel_imc_init(c);
}

void mce_intel_feature_clear(struct cpuinfo_x86 *c)
{
	intel_clear_lmce();
}

bool intel_filter_mce(struct mce *m)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	/* MCE errata HSD131, HSM142, HSW131, BDM48, HSM142 and SKX37 */
	if ((c->x86 == 6) &&
	    ((c->x86_model == INTEL_FAM6_HASWELL) ||
	     (c->x86_model == INTEL_FAM6_HASWELL_L) ||
	     (c->x86_model == INTEL_FAM6_BROADWELL) ||
	     (c->x86_model == INTEL_FAM6_HASWELL_G) ||
	     (c->x86_model == INTEL_FAM6_SKYLAKE_X)) &&
	    (m->bank == 0) &&
	    ((m->status & 0xa0000000ffffffff) == 0x80000000000f0005))
		return true;

	return false;
}
