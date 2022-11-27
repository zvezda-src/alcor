#include <linux/perf_event.h>
#include <linux/jump_label.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <asm/apicdef.h>
#include <asm/apic.h>
#include <asm/nmi.h>

#include "../perf_event.h"

static DEFINE_PER_CPU(unsigned long, perf_nmi_tstamp);
static unsigned long perf_nmi_window;

#define AMD_MERGE_EVENT ((0xFULL << 32) | 0xFFULL)
#define AMD_MERGE_EVENT_ENABLE (AMD_MERGE_EVENT | ARCH_PERFMON_EVENTSEL_ENABLE)

static u64 amd_pmu_global_cntr_mask __read_mostly;

static __initconst const u64 amd_hw_cache_event_ids
				[PERF_COUNT_HW_CACHE_MAX]
				[PERF_COUNT_HW_CACHE_OP_MAX]
				[PERF_COUNT_HW_CACHE_RESULT_MAX] =
{
 [ C(L1D) ] = {
	[ C(OP_READ) ] = {
		[ C(RESULT_ACCESS) ] = 0x0040, /* Data Cache Accesses        */
		[ C(RESULT_MISS)   ] = 0x0141, /* Data Cache Misses          */
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = 0,
		[ C(RESULT_MISS)   ] = 0,
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = 0x0267, /* Data Prefetcher :attempts  */
		[ C(RESULT_MISS)   ] = 0x0167, /* Data Prefetcher :cancelled */
	},
 },
 [ C(L1I ) ] = {
	[ C(OP_READ) ] = {
		[ C(RESULT_ACCESS) ] = 0x0080, /* Instruction cache fetches  */
		[ C(RESULT_MISS)   ] = 0x0081, /* Instruction cache misses   */
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = -1,
		[ C(RESULT_MISS)   ] = -1,
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = 0x014B, /* Prefetch Instructions :Load */
		[ C(RESULT_MISS)   ] = 0,
	},
 },
 [ C(LL  ) ] = {
	[ C(OP_READ) ] = {
		[ C(RESULT_ACCESS) ] = 0x037D, /* Requests to L2 Cache :IC+DC */
		[ C(RESULT_MISS)   ] = 0x037E, /* L2 Cache Misses : IC+DC     */
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = 0x017F, /* L2 Fill/Writeback           */
		[ C(RESULT_MISS)   ] = 0,
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = 0,
		[ C(RESULT_MISS)   ] = 0,
	},
 },
 [ C(DTLB) ] = {
	[ C(OP_READ) ] = {
		[ C(RESULT_ACCESS) ] = 0x0040, /* Data Cache Accesses        */
		[ C(RESULT_MISS)   ] = 0x0746, /* L1_DTLB_AND_L2_DLTB_MISS.ALL */
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = 0,
		[ C(RESULT_MISS)   ] = 0,
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = 0,
		[ C(RESULT_MISS)   ] = 0,
	},
 },
 [ C(ITLB) ] = {
	[ C(OP_READ) ] = {
		[ C(RESULT_ACCESS) ] = 0x0080, /* Instruction fecthes        */
		[ C(RESULT_MISS)   ] = 0x0385, /* L1_ITLB_AND_L2_ITLB_MISS.ALL */
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = -1,
		[ C(RESULT_MISS)   ] = -1,
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = -1,
		[ C(RESULT_MISS)   ] = -1,
	},
 },
 [ C(BPU ) ] = {
	[ C(OP_READ) ] = {
		[ C(RESULT_ACCESS) ] = 0x00c2, /* Retired Branch Instr.      */
		[ C(RESULT_MISS)   ] = 0x00c3, /* Retired Mispredicted BI    */
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = -1,
		[ C(RESULT_MISS)   ] = -1,
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = -1,
		[ C(RESULT_MISS)   ] = -1,
	},
 },
 [ C(NODE) ] = {
	[ C(OP_READ) ] = {
		[ C(RESULT_ACCESS) ] = 0xb8e9, /* CPU Request to Memory, l+r */
		[ C(RESULT_MISS)   ] = 0x98e9, /* CPU Request to Memory, r   */
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = -1,
		[ C(RESULT_MISS)   ] = -1,
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = -1,
		[ C(RESULT_MISS)   ] = -1,
	},
 },
};

static __initconst const u64 amd_hw_cache_event_ids_f17h
				[PERF_COUNT_HW_CACHE_MAX]
				[PERF_COUNT_HW_CACHE_OP_MAX]
				[PERF_COUNT_HW_CACHE_RESULT_MAX] = {
[C(L1D)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = 0x0040, /* Data Cache Accesses */
		[C(RESULT_MISS)]   = 0xc860, /* L2$ access from DC Miss */
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = 0,
		[C(RESULT_MISS)]   = 0,
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = 0xff5a, /* h/w prefetch DC Fills */
		[C(RESULT_MISS)]   = 0,
	},
},
[C(L1I)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = 0x0080, /* Instruction cache fetches  */
		[C(RESULT_MISS)]   = 0x0081, /* Instruction cache misses   */
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = -1,
		[C(RESULT_MISS)]   = -1,
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = 0,
		[C(RESULT_MISS)]   = 0,
	},
},
[C(LL)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = 0,
		[C(RESULT_MISS)]   = 0,
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = 0,
		[C(RESULT_MISS)]   = 0,
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = 0,
		[C(RESULT_MISS)]   = 0,
	},
},
[C(DTLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = 0xff45, /* All L2 DTLB accesses */
		[C(RESULT_MISS)]   = 0xf045, /* L2 DTLB misses (PT walks) */
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = 0,
		[C(RESULT_MISS)]   = 0,
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = 0,
		[C(RESULT_MISS)]   = 0,
	},
},
[C(ITLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = 0x0084, /* L1 ITLB misses, L2 ITLB hits */
		[C(RESULT_MISS)]   = 0xff85, /* L1 ITLB misses, L2 misses */
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = -1,
		[C(RESULT_MISS)]   = -1,
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = -1,
		[C(RESULT_MISS)]   = -1,
	},
},
[C(BPU)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = 0x00c2, /* Retired Branch Instr.      */
		[C(RESULT_MISS)]   = 0x00c3, /* Retired Mispredicted BI    */
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = -1,
		[C(RESULT_MISS)]   = -1,
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = -1,
		[C(RESULT_MISS)]   = -1,
	},
},
[C(NODE)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = 0,
		[C(RESULT_MISS)]   = 0,
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = -1,
		[C(RESULT_MISS)]   = -1,
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = -1,
		[C(RESULT_MISS)]   = -1,
	},
},
};

static const u64 amd_perfmon_event_map[PERF_COUNT_HW_MAX] =
{
	[PERF_COUNT_HW_CPU_CYCLES]		= 0x0076,
	[PERF_COUNT_HW_INSTRUCTIONS]		= 0x00c0,
	[PERF_COUNT_HW_CACHE_REFERENCES]	= 0x077d,
	[PERF_COUNT_HW_CACHE_MISSES]		= 0x077e,
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS]	= 0x00c2,
	[PERF_COUNT_HW_BRANCH_MISSES]		= 0x00c3,
	[PERF_COUNT_HW_STALLED_CYCLES_FRONTEND]	= 0x00d0, /* "Decoder empty" event */
	[PERF_COUNT_HW_STALLED_CYCLES_BACKEND]	= 0x00d1, /* "Dispatch stalls" event */
};

static const u64 amd_f17h_perfmon_event_map[PERF_COUNT_HW_MAX] =
{
	[PERF_COUNT_HW_CPU_CYCLES]		= 0x0076,
	[PERF_COUNT_HW_INSTRUCTIONS]		= 0x00c0,
	[PERF_COUNT_HW_CACHE_REFERENCES]	= 0xff60,
	[PERF_COUNT_HW_CACHE_MISSES]		= 0x0964,
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS]	= 0x00c2,
	[PERF_COUNT_HW_BRANCH_MISSES]		= 0x00c3,
	[PERF_COUNT_HW_STALLED_CYCLES_FRONTEND]	= 0x0287,
	[PERF_COUNT_HW_STALLED_CYCLES_BACKEND]	= 0x0187,
};

static u64 amd_pmu_event_map(int hw_event)
{
	if (boot_cpu_data.x86 >= 0x17)
		return amd_f17h_perfmon_event_map[hw_event];

	return amd_perfmon_event_map[hw_event];
}

static unsigned int event_offsets[X86_PMC_IDX_MAX] __read_mostly;
static unsigned int count_offsets[X86_PMC_IDX_MAX] __read_mostly;

static inline int amd_pmu_addr_offset(int index, bool eventsel)
{
	int offset;

	if (!index)
		return index;

	if (eventsel)
		offset = event_offsets[index];
	else
		offset = count_offsets[index];

	if (offset)
		return offset;

	if (!boot_cpu_has(X86_FEATURE_PERFCTR_CORE))
		offset = index;
	else
		offset = index << 1;

	if (eventsel)
		event_offsets[index] = offset;
	else
		count_offsets[index] = offset;

	return offset;
}

static inline unsigned int amd_get_event_code(struct hw_perf_event *hwc)
{
	return ((hwc->config >> 24) & 0x0f00) | (hwc->config & 0x00ff);
}

static inline bool amd_is_pair_event_code(struct hw_perf_event *hwc)
{
	if (!(x86_pmu.flags & PMU_FL_PAIR))
		return false;

	switch (amd_get_event_code(hwc)) {
	case 0x003:	return true;	/* Retired SSE/AVX FLOPs */
	default:	return false;
	}
}

#define AMD_FAM19H_BRS_EVENT 0xc4 /* RETIRED_TAKEN_BRANCH_INSTRUCTIONS */
static inline int amd_is_brs_event(struct perf_event *e)
{
	return (e->hw.config & AMD64_RAW_EVENT_MASK) == AMD_FAM19H_BRS_EVENT;
}

static int amd_core_hw_config(struct perf_event *event)
{
	int ret = 0;

	if (event->attr.exclude_host && event->attr.exclude_guest)
		/*
		event->hw.config &= ~(ARCH_PERFMON_EVENTSEL_USR |
				      ARCH_PERFMON_EVENTSEL_OS);
	else if (event->attr.exclude_host)
		event->hw.config |= AMD64_EVENTSEL_GUESTONLY;
	else if (event->attr.exclude_guest)
		event->hw.config |= AMD64_EVENTSEL_HOSTONLY;

	if ((x86_pmu.flags & PMU_FL_PAIR) && amd_is_pair_event_code(&event->hw))
		event->hw.flags |= PERF_X86_EVENT_PAIR;

	/*
	if (has_branch_stack(event)) {
		/*
		if (!is_sampling_event(event))
			return -EINVAL;

		/*
		if (!amd_is_brs_event(event))
			return -EINVAL;

		/*
		if (event->attr.freq)
			return -EINVAL;
		/*
		if (event->attr.sample_period <= x86_pmu.lbr_nr)
			return -EINVAL;

		/*
		ret = amd_brs_setup_filter(event);

		/* only set in case of success */
		if (!ret)
			event->hw.flags |= PERF_X86_EVENT_AMD_BRS;
	}
	return ret;
}

static inline int amd_is_nb_event(struct hw_perf_event *hwc)
{
	return (hwc->config & 0xe0) == 0xe0;
}

static inline int amd_has_nb(struct cpu_hw_events *cpuc)
{
	struct amd_nb *nb = cpuc->amd_nb;

	return nb && nb->nb_id != -1;
}

static int amd_pmu_hw_config(struct perf_event *event)
{
	int ret;

	/* pass precise event sampling to ibs: */
	if (event->attr.precise_ip && get_ibs_caps())
		return -ENOENT;

	if (has_branch_stack(event) && !x86_pmu.lbr_nr)
		return -EOPNOTSUPP;

	ret = x86_pmu_hw_config(event);
	if (ret)
		return ret;

	if (event->attr.type == PERF_TYPE_RAW)
		event->hw.config |= event->attr.config & AMD64_RAW_EVENT_MASK;

	return amd_core_hw_config(event);
}

static void __amd_put_nb_event_constraints(struct cpu_hw_events *cpuc,
					   struct perf_event *event)
{
	struct amd_nb *nb = cpuc->amd_nb;
	int i;

	/*
	for (i = 0; i < x86_pmu.num_counters; i++) {
		if (cmpxchg(nb->owners + i, event, NULL) == event)
			break;
	}
}

 /*
static struct event_constraint *
__amd_get_nb_event_constraints(struct cpu_hw_events *cpuc, struct perf_event *event,
			       struct event_constraint *c)
{
	struct hw_perf_event *hwc = &event->hw;
	struct amd_nb *nb = cpuc->amd_nb;
	struct perf_event *old;
	int idx, new = -1;

	if (!c)
		c = &unconstrained;

	if (cpuc->is_fake)
		return c;

	/*
	for_each_set_bit(idx, c->idxmsk, x86_pmu.num_counters) {
		if (new == -1 || hwc->idx == idx)
			/* assign free slot, prefer hwc->idx */
			old = cmpxchg(nb->owners + idx, NULL, event);
		else if (nb->owners[idx] == event)
			/* event already present */
			old = event;
		else
			continue;

		if (old && old != event)
			continue;

		/* reassign to this slot */
		if (new != -1)
			cmpxchg(nb->owners + new, event, NULL);
		new = idx;

		/* already present, reuse */
		if (old == event)
			break;
	}

	if (new == -1)
		return &emptyconstraint;

	return &nb->event_constraints[new];
}

static struct amd_nb *amd_alloc_nb(int cpu)
{
	struct amd_nb *nb;
	int i;

	nb = kzalloc_node(sizeof(struct amd_nb), GFP_KERNEL, cpu_to_node(cpu));
	if (!nb)
		return NULL;

	nb->nb_id = -1;

	/*
	for (i = 0; i < x86_pmu.num_counters; i++) {
		__set_bit(i, nb->event_constraints[i].idxmsk);
		nb->event_constraints[i].weight = 1;
	}
	return nb;
}

static void amd_pmu_cpu_reset(int cpu)
{
	if (x86_pmu.version < 2)
		return;

	/* Clear enable bits i.e. PerfCntrGlobalCtl.PerfCntrEn */
	wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_CTL, 0);

	/* Clear overflow bits i.e. PerfCntrGLobalStatus.PerfCntrOvfl */
	wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR, amd_pmu_global_cntr_mask);
}

static int amd_pmu_cpu_prepare(int cpu)
{
	struct cpu_hw_events *cpuc = &per_cpu(cpu_hw_events, cpu);

	WARN_ON_ONCE(cpuc->amd_nb);

	if (!x86_pmu.amd_nb_constraints)
		return 0;

	cpuc->amd_nb = amd_alloc_nb(cpu);
	if (!cpuc->amd_nb)
		return -ENOMEM;

	return 0;
}

static void amd_pmu_cpu_starting(int cpu)
{
	struct cpu_hw_events *cpuc = &per_cpu(cpu_hw_events, cpu);
	void **onln = &cpuc->kfree_on_online[X86_PERF_KFREE_SHARED];
	struct amd_nb *nb;
	int i, nb_id;

	cpuc->perf_ctr_virt_mask = AMD64_EVENTSEL_HOSTONLY;

	if (!x86_pmu.amd_nb_constraints)
		return;

	nb_id = topology_die_id(cpu);
	WARN_ON_ONCE(nb_id == BAD_APICID);

	for_each_online_cpu(i) {
		nb = per_cpu(cpu_hw_events, i).amd_nb;
		if (WARN_ON_ONCE(!nb))
			continue;

		if (nb->nb_id == nb_id) {
			*onln = cpuc->amd_nb;
			cpuc->amd_nb = nb;
			break;
		}
	}

	cpuc->amd_nb->nb_id = nb_id;
	cpuc->amd_nb->refcnt++;

	amd_brs_reset();
	amd_pmu_cpu_reset(cpu);
}

static void amd_pmu_cpu_dead(int cpu)
{
	struct cpu_hw_events *cpuhw;

	if (!x86_pmu.amd_nb_constraints)
		return;

	cpuhw = &per_cpu(cpu_hw_events, cpu);

	if (cpuhw->amd_nb) {
		struct amd_nb *nb = cpuhw->amd_nb;

		if (nb->nb_id == -1 || --nb->refcnt == 0)
			kfree(nb);

		cpuhw->amd_nb = NULL;
	}

	amd_pmu_cpu_reset(cpu);
}

static inline void amd_pmu_set_global_ctl(u64 ctl)
{
	wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_CTL, ctl);
}

static inline u64 amd_pmu_get_global_status(void)
{
	u64 status;

	/* PerfCntrGlobalStatus is read-only */
	rdmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS, status);

	return status & amd_pmu_global_cntr_mask;
}

static inline void amd_pmu_ack_global_status(u64 status)
{
	/*

	/* Only allow modifications to PerfCntrGlobalStatus.PerfCntrOvfl */
	status &= amd_pmu_global_cntr_mask;
	wrmsrl(MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR, status);
}

static bool amd_pmu_test_overflow_topbit(int idx)
{
	u64 counter;

	rdmsrl(x86_pmu_event_addr(idx), counter);

	return !(counter & BIT_ULL(x86_pmu.cntval_bits - 1));
}

static bool amd_pmu_test_overflow_status(int idx)
{
	return amd_pmu_get_global_status() & BIT_ULL(idx);
}

DEFINE_STATIC_CALL(amd_pmu_test_overflow, amd_pmu_test_overflow_topbit);

#define OVERFLOW_WAIT_COUNT	50

static void amd_pmu_wait_on_overflow(int idx)
{
	unsigned int i;

	/*
	for (i = 0; i < OVERFLOW_WAIT_COUNT; i++) {
		if (!static_call(amd_pmu_test_overflow)(idx))
			break;

		/* Might be in IRQ context, so can't sleep */
		udelay(1);
	}
}

static void amd_pmu_check_overflow(void)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	int idx;

	/*
	if (in_nmi())
		return;

	/*
	for (idx = 0; idx < x86_pmu.num_counters; idx++) {
		if (!test_bit(idx, cpuc->active_mask))
			continue;

		amd_pmu_wait_on_overflow(idx);
	}
}

static void amd_pmu_enable_event(struct perf_event *event)
{
	x86_pmu_enable_event(event);
}

static void amd_pmu_enable_all(int added)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	int idx;

	amd_brs_enable_all();

	for (idx = 0; idx < x86_pmu.num_counters; idx++) {
		/* only activate events which are marked as active */
		if (!test_bit(idx, cpuc->active_mask))
			continue;

		amd_pmu_enable_event(cpuc->events[idx]);
	}
}

static void amd_pmu_v2_enable_event(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	/*
	__x86_pmu_enable_event(hwc, ARCH_PERFMON_EVENTSEL_ENABLE);
}

static void amd_pmu_v2_enable_all(int added)
{
	amd_pmu_set_global_ctl(amd_pmu_global_cntr_mask);
}

static void amd_pmu_disable_event(struct perf_event *event)
{
	x86_pmu_disable_event(event);

	/*
	if (in_nmi())
		return;

	amd_pmu_wait_on_overflow(event->hw.idx);
}

static void amd_pmu_disable_all(void)
{
	amd_brs_disable_all();
	x86_pmu_disable_all();
	amd_pmu_check_overflow();
}

static void amd_pmu_v2_disable_all(void)
{
	/* Disable all PMCs */
	amd_pmu_set_global_ctl(0);
	amd_pmu_check_overflow();
}

static void amd_pmu_add_event(struct perf_event *event)
{
	if (needs_branch_stack(event))
		amd_pmu_brs_add(event);
}

static void amd_pmu_del_event(struct perf_event *event)
{
	if (needs_branch_stack(event))
		amd_pmu_brs_del(event);
}

static inline int amd_pmu_adjust_nmi_window(int handled)
{
	/*
	if (handled) {
		this_cpu_write(perf_nmi_tstamp, jiffies + perf_nmi_window);

		return handled;
	}

	if (time_after(jiffies, this_cpu_read(perf_nmi_tstamp)))
		return NMI_DONE;

	return NMI_HANDLED;
}

static int amd_pmu_handle_irq(struct pt_regs *regs)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	int handled;
	int pmu_enabled;

	/*
	pmu_enabled = cpuc->enabled;
	cpuc->enabled = 0;

	/* stop everything (includes BRS) */
	amd_pmu_disable_all();

	/* Drain BRS is in use (could be inactive) */
	if (cpuc->lbr_users)
		amd_brs_drain();

	/* Process any counter overflows */
	handled = x86_pmu_handle_irq(regs);

	cpuc->enabled = pmu_enabled;
	if (pmu_enabled)
		amd_pmu_enable_all(0);

	return amd_pmu_adjust_nmi_window(handled);
}

static int amd_pmu_v2_handle_irq(struct pt_regs *regs)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	struct perf_sample_data data;
	struct hw_perf_event *hwc;
	struct perf_event *event;
	int handled = 0, idx;
	u64 status, mask;
	bool pmu_enabled;

	/*
	pmu_enabled = cpuc->enabled;
	cpuc->enabled = 0;

	/* Stop counting */
	amd_pmu_v2_disable_all();

	status = amd_pmu_get_global_status();

	/* Check if any overflows are pending */
	if (!status)
		goto done;

	for (idx = 0; idx < x86_pmu.num_counters; idx++) {
		if (!test_bit(idx, cpuc->active_mask))
			continue;

		event = cpuc->events[idx];
		hwc = &event->hw;
		x86_perf_event_update(event);
		mask = BIT_ULL(idx);

		if (!(status & mask))
			continue;

		/* Event overflow */
		handled++;
		perf_sample_data_init(&data, 0, hwc->last_period);

		if (!x86_perf_event_set_period(event))
			continue;

		if (perf_event_overflow(event, &data, regs))
			x86_pmu_stop(event, 0);

		status &= ~mask;
	}

	/*
	WARN_ON(status > 0);

	/* Clear overflow bits */
	amd_pmu_ack_global_status(~status);

	/*
	inc_irq_stat(apic_perf_irqs);

done:
	cpuc->enabled = pmu_enabled;

	/* Resume counting only if PMU is active */
	if (pmu_enabled)
		amd_pmu_v2_enable_all(0);

	return amd_pmu_adjust_nmi_window(handled);
}

static struct event_constraint *
amd_get_event_constraints(struct cpu_hw_events *cpuc, int idx,
			  struct perf_event *event)
{
	/*
	if (!(amd_has_nb(cpuc) && amd_is_nb_event(&event->hw)))
		return &unconstrained;

	return __amd_get_nb_event_constraints(cpuc, event, NULL);
}

static void amd_put_event_constraints(struct cpu_hw_events *cpuc,
				      struct perf_event *event)
{
	if (amd_has_nb(cpuc) && amd_is_nb_event(&event->hw))
		__amd_put_nb_event_constraints(cpuc, event);
}

PMU_FORMAT_ATTR(event,	"config:0-7,32-35");
PMU_FORMAT_ATTR(umask,	"config:8-15"	);
PMU_FORMAT_ATTR(edge,	"config:18"	);
PMU_FORMAT_ATTR(inv,	"config:23"	);
PMU_FORMAT_ATTR(cmask,	"config:24-31"	);

static struct attribute *amd_format_attr[] = {
	&format_attr_event.attr,
	&format_attr_umask.attr,
	&format_attr_edge.attr,
	&format_attr_inv.attr,
	&format_attr_cmask.attr,
	NULL,
};


#define AMD_EVENT_TYPE_MASK	0x000000F0ULL

#define AMD_EVENT_FP		0x00000000ULL ... 0x00000010ULL
#define AMD_EVENT_LS		0x00000020ULL ... 0x00000030ULL
#define AMD_EVENT_DC		0x00000040ULL ... 0x00000050ULL
#define AMD_EVENT_CU		0x00000060ULL ... 0x00000070ULL
#define AMD_EVENT_IC_DE		0x00000080ULL ... 0x00000090ULL
#define AMD_EVENT_EX_LS		0x000000C0ULL
#define AMD_EVENT_DE		0x000000D0ULL
#define AMD_EVENT_NB		0x000000E0ULL ... 0x000000F0ULL


static struct event_constraint amd_f15_PMC0  = EVENT_CONSTRAINT(0, 0x01, 0);
static struct event_constraint amd_f15_PMC20 = EVENT_CONSTRAINT(0, 0x07, 0);
static struct event_constraint amd_f15_PMC3  = EVENT_CONSTRAINT(0, 0x08, 0);
static struct event_constraint amd_f15_PMC30 = EVENT_CONSTRAINT_OVERLAP(0, 0x09, 0);
static struct event_constraint amd_f15_PMC50 = EVENT_CONSTRAINT(0, 0x3F, 0);
static struct event_constraint amd_f15_PMC53 = EVENT_CONSTRAINT(0, 0x38, 0);

static struct event_constraint *
amd_get_event_constraints_f15h(struct cpu_hw_events *cpuc, int idx,
			       struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	unsigned int event_code = amd_get_event_code(hwc);

	switch (event_code & AMD_EVENT_TYPE_MASK) {
	case AMD_EVENT_FP:
		switch (event_code) {
		case 0x000:
			if (!(hwc->config & 0x0000F000ULL))
				break;
			if (!(hwc->config & 0x00000F00ULL))
				break;
			return &amd_f15_PMC3;
		case 0x004:
			if (hweight_long(hwc->config & ARCH_PERFMON_EVENTSEL_UMASK) <= 1)
				break;
			return &amd_f15_PMC3;
		case 0x003:
		case 0x00B:
		case 0x00D:
			return &amd_f15_PMC3;
		}
		return &amd_f15_PMC53;
	case AMD_EVENT_LS:
	case AMD_EVENT_DC:
	case AMD_EVENT_EX_LS:
		switch (event_code) {
		case 0x023:
		case 0x043:
		case 0x045:
		case 0x046:
		case 0x054:
		case 0x055:
			return &amd_f15_PMC20;
		case 0x02D:
			return &amd_f15_PMC3;
		case 0x02E:
			return &amd_f15_PMC30;
		case 0x031:
			if (hweight_long(hwc->config & ARCH_PERFMON_EVENTSEL_UMASK) <= 1)
				return &amd_f15_PMC20;
			return &emptyconstraint;
		case 0x1C0:
			return &amd_f15_PMC53;
		default:
			return &amd_f15_PMC50;
		}
	case AMD_EVENT_CU:
	case AMD_EVENT_IC_DE:
	case AMD_EVENT_DE:
		switch (event_code) {
		case 0x08F:
		case 0x187:
		case 0x188:
			return &amd_f15_PMC0;
		case 0x0DB ... 0x0DF:
		case 0x1D6:
		case 0x1D8:
			return &amd_f15_PMC50;
		default:
			return &amd_f15_PMC20;
		}
	case AMD_EVENT_NB:
		/* moved to uncore.c */
		return &emptyconstraint;
	default:
		return &emptyconstraint;
	}
}

static struct event_constraint pair_constraint;

static struct event_constraint *
amd_get_event_constraints_f17h(struct cpu_hw_events *cpuc, int idx,
			       struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	if (amd_is_pair_event_code(hwc))
		return &pair_constraint;

	return &unconstrained;
}

static void amd_put_event_constraints_f17h(struct cpu_hw_events *cpuc,
					   struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	if (is_counter_pair(hwc))
		--cpuc->n_pair;
}

static struct event_constraint amd_fam19h_brs_cntr0_constraint =
	EVENT_CONSTRAINT(0, 0x1, AMD64_RAW_EVENT_MASK);

static struct event_constraint amd_fam19h_brs_pair_cntr0_constraint =
	__EVENT_CONSTRAINT(0, 0x1, AMD64_RAW_EVENT_MASK, 1, 0, PERF_X86_EVENT_PAIR);

static struct event_constraint *
amd_get_event_constraints_f19h(struct cpu_hw_events *cpuc, int idx,
			  struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	bool has_brs = has_amd_brs(hwc);

	/*
	if (amd_is_pair_event_code(hwc)) {
		return has_brs ? &amd_fam19h_brs_pair_cntr0_constraint
			       : &pair_constraint;
	}

	if (has_brs)
		return &amd_fam19h_brs_cntr0_constraint;

	return &unconstrained;
}


static ssize_t amd_event_sysfs_show(char *page, u64 config)
{
	u64 event = (config & ARCH_PERFMON_EVENTSEL_EVENT) |
		    (config & AMD64_EVENTSEL_EVENT) >> 24;

	return x86_event_sysfs_show(page, config, event);
}

static void amd_pmu_sched_task(struct perf_event_context *ctx,
				 bool sched_in)
{
	if (sched_in && x86_pmu.lbr_nr)
		amd_pmu_brs_sched_task(ctx, sched_in);
}

static u64 amd_pmu_limit_period(struct perf_event *event, u64 left)
{
	/*
	if (has_branch_stack(event) && left > x86_pmu.lbr_nr)
		left -= x86_pmu.lbr_nr;

	return left;
}

static __initconst const struct x86_pmu amd_pmu = {
	.name			= "AMD",
	.handle_irq		= amd_pmu_handle_irq,
	.disable_all		= amd_pmu_disable_all,
	.enable_all		= amd_pmu_enable_all,
	.enable			= amd_pmu_enable_event,
	.disable		= amd_pmu_disable_event,
	.hw_config		= amd_pmu_hw_config,
	.schedule_events	= x86_schedule_events,
	.eventsel		= MSR_K7_EVNTSEL0,
	.perfctr		= MSR_K7_PERFCTR0,
	.addr_offset            = amd_pmu_addr_offset,
	.event_map		= amd_pmu_event_map,
	.max_events		= ARRAY_SIZE(amd_perfmon_event_map),
	.num_counters		= AMD64_NUM_COUNTERS,
	.add			= amd_pmu_add_event,
	.del			= amd_pmu_del_event,
	.cntval_bits		= 48,
	.cntval_mask		= (1ULL << 48) - 1,
	.apic			= 1,
	/* use highest bit to detect overflow */
	.max_period		= (1ULL << 47) - 1,
	.get_event_constraints	= amd_get_event_constraints,
	.put_event_constraints	= amd_put_event_constraints,

	.format_attrs		= amd_format_attr,
	.events_sysfs_show	= amd_event_sysfs_show,

	.cpu_prepare		= amd_pmu_cpu_prepare,
	.cpu_starting		= amd_pmu_cpu_starting,
	.cpu_dead		= amd_pmu_cpu_dead,

	.amd_nb_constraints	= 1,
};

static ssize_t branches_show(struct device *cdev,
			      struct device_attribute *attr,
			      char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", x86_pmu.lbr_nr);
}

static DEVICE_ATTR_RO(branches);

static struct attribute *amd_pmu_brs_attrs[] = {
	&dev_attr_branches.attr,
	NULL,
};

static umode_t
amd_brs_is_visible(struct kobject *kobj, struct attribute *attr, int i)
{
	return x86_pmu.lbr_nr ? attr->mode : 0;
}

static struct attribute_group group_caps_amd_brs = {
	.name  = "caps",
	.attrs = amd_pmu_brs_attrs,
	.is_visible = amd_brs_is_visible,
};

EVENT_ATTR_STR(branch-brs, amd_branch_brs,
	       "event=" __stringify(AMD_FAM19H_BRS_EVENT)"\n");

static struct attribute *amd_brs_events_attrs[] = {
	EVENT_PTR(amd_branch_brs),
	NULL,
};

static struct attribute_group group_events_amd_brs = {
	.name       = "events",
	.attrs      = amd_brs_events_attrs,
	.is_visible = amd_brs_is_visible,
};

static const struct attribute_group *amd_attr_update[] = {
	&group_caps_amd_brs,
	&group_events_amd_brs,
	NULL,
};

static int __init amd_core_pmu_init(void)
{
	union cpuid_0x80000022_ebx ebx;
	u64 even_ctr_mask = 0ULL;
	int i;

	if (!boot_cpu_has(X86_FEATURE_PERFCTR_CORE))
		return 0;

	/* Avoid calculating the value each time in the NMI handler */
	perf_nmi_window = msecs_to_jiffies(100);

	/*
	x86_pmu.eventsel	= MSR_F15H_PERF_CTL;
	x86_pmu.perfctr		= MSR_F15H_PERF_CTR;
	x86_pmu.num_counters	= AMD64_NUM_COUNTERS_CORE;

	/* Check for Performance Monitoring v2 support */
	if (boot_cpu_has(X86_FEATURE_PERFMON_V2)) {
		ebx.full = cpuid_ebx(EXT_PERFMON_DEBUG_FEATURES);

		/* Update PMU version for later usage */
		x86_pmu.version = 2;

		/* Find the number of available Core PMCs */
		x86_pmu.num_counters = ebx.split.num_core_pmc;

		amd_pmu_global_cntr_mask = (1ULL << x86_pmu.num_counters) - 1;

		/* Update PMC handling functions */
		x86_pmu.enable_all = amd_pmu_v2_enable_all;
		x86_pmu.disable_all = amd_pmu_v2_disable_all;
		x86_pmu.enable = amd_pmu_v2_enable_event;
		x86_pmu.handle_irq = amd_pmu_v2_handle_irq;
		static_call_update(amd_pmu_test_overflow, amd_pmu_test_overflow_status);
	}

	/*
	x86_pmu.amd_nb_constraints = 0;

	if (boot_cpu_data.x86 == 0x15) {
		pr_cont("Fam15h ");
		x86_pmu.get_event_constraints = amd_get_event_constraints_f15h;
	}
	if (boot_cpu_data.x86 >= 0x17) {
		pr_cont("Fam17h+ ");
		/*
		for (i = 0; i < x86_pmu.num_counters - 1; i += 2)
			even_ctr_mask |= 1 << i;

		pair_constraint = (struct event_constraint)
				    __EVENT_CONSTRAINT(0, even_ctr_mask, 0,
				    x86_pmu.num_counters / 2, 0,
				    PERF_X86_EVENT_PAIR);

		x86_pmu.get_event_constraints = amd_get_event_constraints_f17h;
		x86_pmu.put_event_constraints = amd_put_event_constraints_f17h;
		x86_pmu.perf_ctr_pair_en = AMD_MERGE_EVENT_ENABLE;
		x86_pmu.flags |= PMU_FL_PAIR;
	}

	/*
	if (boot_cpu_data.x86 >= 0x19 && !amd_brs_init()) {
		x86_pmu.get_event_constraints = amd_get_event_constraints_f19h;
		x86_pmu.sched_task = amd_pmu_sched_task;
		x86_pmu.limit_period = amd_pmu_limit_period;
		/*

		/* branch sampling must be stopped when entering low power */
		amd_brs_lopwr_init();
	}

	x86_pmu.attr_update = amd_attr_update;

	pr_cont("core perfctr, ");
	return 0;
}

__init int amd_pmu_init(void)
{
	int ret;

	/* Performance-monitoring supported from K7 and later: */
	if (boot_cpu_data.x86 < 6)
		return -ENODEV;

	x86_pmu = amd_pmu;

	ret = amd_core_pmu_init();
	if (ret)
		return ret;

	if (num_possible_cpus() == 1) {
		/*
		x86_pmu.amd_nb_constraints = 0;
	}

	if (boot_cpu_data.x86 >= 0x17)
		memcpy(hw_cache_event_ids, amd_hw_cache_event_ids_f17h, sizeof(hw_cache_event_ids));
	else
		memcpy(hw_cache_event_ids, amd_hw_cache_event_ids, sizeof(hw_cache_event_ids));

	return 0;
}

static inline void amd_pmu_reload_virt(void)
{
	if (x86_pmu.version >= 2) {
		/*
		amd_pmu_v2_disable_all();
		amd_pmu_enable_all(0);
		amd_pmu_v2_enable_all(0);
		return;
	}

	amd_pmu_disable_all();
	amd_pmu_enable_all(0);
}

void amd_pmu_enable_virt(void)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);

	cpuc->perf_ctr_virt_mask = 0;

	/* Reload all events */
	amd_pmu_reload_virt();
}
EXPORT_SYMBOL_GPL(amd_pmu_enable_virt);

void amd_pmu_disable_virt(void)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);

	/*
	cpuc->perf_ctr_virt_mask = AMD64_EVENTSEL_HOSTONLY;

	/* Reload all events */
	amd_pmu_reload_virt();
}
EXPORT_SYMBOL_GPL(amd_pmu_disable_virt);
