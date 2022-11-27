
#include <linux/kernel.h>
#include <linux/thread_info.h>

#include <asm/apic.h>
#include <asm/cpu_device_id.h>
#include <asm/intel-family.h>
#include <asm/msr.h>
#include <asm/param.h>
#include <asm/tsc.h>

#define MAX_NUM_FREQS	16 /* 4 bits to select the frequency */

#define TSC_REFERENCE_KHZ 100000

struct muldiv {
	u32 multiplier;
	u32 divider;
};

struct freq_desc {
	bool use_msr_plat;
	struct muldiv muldiv[MAX_NUM_FREQS];
	/*
	u32 freqs[MAX_NUM_FREQS];
	u32 mask;
};

static const struct freq_desc freq_desc_pnw = {
	.use_msr_plat = false,
	.freqs = { 0, 0, 0, 0, 0, 99840, 0, 83200 },
	.mask = 0x07,
};

static const struct freq_desc freq_desc_clv = {
	.use_msr_plat = false,
	.freqs = { 0, 133200, 0, 0, 0, 99840, 0, 83200 },
	.mask = 0x07,
};

static const struct freq_desc freq_desc_byt = {
	.use_msr_plat = true,
	.muldiv = { { 5, 6 }, { 1, 1 }, { 4, 3 }, { 7, 6 },
		    { 4, 5 } },
	.mask = 0x07,
};

static const struct freq_desc freq_desc_cht = {
	.use_msr_plat = true,
	.muldiv = { { 5, 6 }, {  1,  1 }, { 4,  3 }, { 7, 6 },
		    { 4, 5 }, { 14, 15 }, { 9, 10 }, { 8, 9 },
		    { 7, 8 } },
	.mask = 0x0f,
};

static const struct freq_desc freq_desc_tng = {
	.use_msr_plat = true,
	.muldiv = { { 0, 0 }, { 1, 1 }, { 4, 3 } },
	.mask = 0x07,
};

static const struct freq_desc freq_desc_ann = {
	.use_msr_plat = true,
	.muldiv = { { 5, 6 }, { 1, 1 }, { 4, 3 }, { 1, 1 } },
	.mask = 0x0f,
};

static const struct freq_desc freq_desc_lgm = {
	.use_msr_plat = true,
	.freqs = { 78000, 78000, 78000, 78000, 78000, 78000, 78000, 78000,
		   78000, 78000, 78000, 78000, 78000, 78000, 78000, 78000 },
	.mask = 0x0f,
};

static const struct x86_cpu_id tsc_msr_cpu_ids[] = {
	X86_MATCH_INTEL_FAM6_MODEL(ATOM_SALTWELL_MID,	&freq_desc_pnw),
	X86_MATCH_INTEL_FAM6_MODEL(ATOM_SALTWELL_TABLET,&freq_desc_clv),
	X86_MATCH_INTEL_FAM6_MODEL(ATOM_SILVERMONT,	&freq_desc_byt),
	X86_MATCH_INTEL_FAM6_MODEL(ATOM_SILVERMONT_MID,	&freq_desc_tng),
	X86_MATCH_INTEL_FAM6_MODEL(ATOM_AIRMONT,	&freq_desc_cht),
	X86_MATCH_INTEL_FAM6_MODEL(ATOM_AIRMONT_MID,	&freq_desc_ann),
	X86_MATCH_INTEL_FAM6_MODEL(ATOM_AIRMONT_NP,	&freq_desc_lgm),
	{}
};

unsigned long cpu_khz_from_msr(void)
{
	u32 lo, hi, ratio, freq, tscref;
	const struct freq_desc *freq_desc;
	const struct x86_cpu_id *id;
	const struct muldiv *md;
	unsigned long res;
	int index;

	id = x86_match_cpu(tsc_msr_cpu_ids);
	if (!id)
		return 0;

	freq_desc = (struct freq_desc *)id->driver_data;
	if (freq_desc->use_msr_plat) {
		rdmsr(MSR_PLATFORM_INFO, lo, hi);
		ratio = (lo >> 8) & 0xff;
	} else {
		rdmsr(MSR_IA32_PERF_STATUS, lo, hi);
		ratio = (hi >> 8) & 0x1f;
	}

	/* Get FSB FREQ ID */
	rdmsr(MSR_FSB_FREQ, lo, hi);
	index = lo & freq_desc->mask;
	md = &freq_desc->muldiv[index];

	/*
	if (md->divider) {
		tscref = TSC_REFERENCE_KHZ * md->multiplier;
		freq = DIV_ROUND_CLOSEST(tscref, md->divider);
		/*
		res = DIV_ROUND_CLOSEST(tscref * ratio, md->divider);
	} else {
		freq = freq_desc->freqs[index];
		res = freq * ratio;
	}

	if (freq == 0)
		pr_err("Error MSR_FSB_FREQ index %d is unknown\n", index);

#ifdef CONFIG_X86_LOCAL_APIC
	lapic_timer_period = (freq * 1000) / HZ;
#endif

	/*
	setup_force_cpu_cap(X86_FEATURE_TSC_KNOWN_FREQ);

	/*
	setup_force_cpu_cap(X86_FEATURE_TSC_RELIABLE);

	return res;
}
