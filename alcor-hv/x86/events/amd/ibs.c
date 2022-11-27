
#include <linux/perf_event.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/pci.h>
#include <linux/ptrace.h>
#include <linux/syscore_ops.h>
#include <linux/sched/clock.h>

#include <asm/apic.h>

#include "../perf_event.h"

static u32 ibs_caps;

#if defined(CONFIG_PERF_EVENTS) && defined(CONFIG_CPU_SUP_AMD)

#include <linux/kprobes.h>
#include <linux/hardirq.h>

#include <asm/nmi.h>
#include <asm/amd-ibs.h>

#define IBS_FETCH_CONFIG_MASK	(IBS_FETCH_RAND_EN | IBS_FETCH_MAX_CNT)
#define IBS_OP_CONFIG_MASK	IBS_OP_MAX_CNT



enum ibs_states {
	IBS_ENABLED	= 0,
	IBS_STARTED	= 1,
	IBS_STOPPING	= 2,
	IBS_STOPPED	= 3,

	IBS_MAX_STATES,
};

struct cpu_perf_ibs {
	struct perf_event	*event;
	unsigned long		state[BITS_TO_LONGS(IBS_MAX_STATES)];
};

struct perf_ibs {
	struct pmu			pmu;
	unsigned int			msr;
	u64				config_mask;
	u64				cnt_mask;
	u64				enable_mask;
	u64				valid_mask;
	u64				max_period;
	unsigned long			offset_mask[1];
	int				offset_max;
	unsigned int			fetch_count_reset_broken : 1;
	unsigned int			fetch_ignore_if_zero_rip : 1;
	struct cpu_perf_ibs __percpu	*pcpu;

	u64				(*get_count)(u64 config);
};

static int
perf_event_set_period(struct hw_perf_event *hwc, u64 min, u64 max, u64 *hw_period)
{
	s64 left = local64_read(&hwc->period_left);
	s64 period = hwc->sample_period;
	int overflow = 0;

	/*
	if (unlikely(left <= -period)) {
		left = period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		overflow = 1;
	}

	if (unlikely(left < (s64)min)) {
		left += period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		overflow = 1;
	}

	/*
	if (left > max) {
		left -= max;
		if (left > max)
			left = max;
		else if (left < min)
			left = min;
	}


	return overflow;
}

static  int
perf_event_try_update(struct perf_event *event, u64 new_raw_count, int width)
{
	struct hw_perf_event *hwc = &event->hw;
	int shift = 64 - width;
	u64 prev_raw_count;
	u64 delta;

	/*
	prev_raw_count = local64_read(&hwc->prev_count);
	if (local64_cmpxchg(&hwc->prev_count, prev_raw_count,
					new_raw_count) != prev_raw_count)
		return 0;

	/*
	delta = (new_raw_count << shift) - (prev_raw_count << shift);
	delta >>= shift;

	local64_add(delta, &event->count);
	local64_sub(delta, &hwc->period_left);

	return 1;
}

static struct perf_ibs perf_ibs_fetch;
static struct perf_ibs perf_ibs_op;

static struct perf_ibs *get_ibs_pmu(int type)
{
	if (perf_ibs_fetch.pmu.type == type)
		return &perf_ibs_fetch;
	if (perf_ibs_op.pmu.type == type)
		return &perf_ibs_op;
	return NULL;
}

static int perf_ibs_precise_event(struct perf_event *event, u64 *config)
{
	switch (event->attr.precise_ip) {
	case 0:
		return -ENOENT;
	case 1:
	case 2:
		break;
	default:
		return -EOPNOTSUPP;
	}

	switch (event->attr.type) {
	case PERF_TYPE_HARDWARE:
		switch (event->attr.config) {
		case PERF_COUNT_HW_CPU_CYCLES:
			*config = 0;
			return 0;
		}
		break;
	case PERF_TYPE_RAW:
		switch (event->attr.config) {
		case 0x0076:
			*config = 0;
			return 0;
		case 0x00C1:
			*config = IBS_OP_CNT_CTL;
			return 0;
		}
		break;
	default:
		return -ENOENT;
	}

	return -EOPNOTSUPP;
}

static int perf_ibs_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct perf_ibs *perf_ibs;
	u64 max_cnt, config;
	int ret;

	perf_ibs = get_ibs_pmu(event->attr.type);
	if (perf_ibs) {
		config = event->attr.config;
	} else {
		perf_ibs = &perf_ibs_op;
		ret = perf_ibs_precise_event(event, &config);
		if (ret)
			return ret;
	}

	if (event->pmu != &perf_ibs->pmu)
		return -ENOENT;

	if (config & ~perf_ibs->config_mask)
		return -EINVAL;

	if (hwc->sample_period) {
		if (config & perf_ibs->cnt_mask)
			/* raw max_cnt may not be set */
			return -EINVAL;
		if (!event->attr.sample_freq && hwc->sample_period & 0x0f)
			/*
			return -EINVAL;
		hwc->sample_period &= ~0x0FULL;
		if (!hwc->sample_period)
			hwc->sample_period = 0x10;
	} else {
		max_cnt = config & perf_ibs->cnt_mask;
		config &= ~perf_ibs->cnt_mask;
		event->attr.sample_period = max_cnt << 4;
		hwc->sample_period = event->attr.sample_period;
	}

	if (!hwc->sample_period)
		return -EINVAL;

	/*
	hwc->last_period = hwc->sample_period;
	local64_set(&hwc->period_left, hwc->sample_period);

	hwc->config_base = perf_ibs->msr;
	hwc->config = config;

	/*
	if (event->attr.sample_type & PERF_SAMPLE_CALLCHAIN)
		event->attr.sample_type |= __PERF_SAMPLE_CALLCHAIN_EARLY;

	return 0;
}

static int perf_ibs_set_period(struct perf_ibs *perf_ibs,
			       struct hw_perf_event *hwc, u64 *period)
{
	int overflow;

	/* ignore lower 4 bits in min count: */
	overflow = perf_event_set_period(hwc, 1<<4, perf_ibs->max_period, period);
	local64_set(&hwc->prev_count, 0);

	return overflow;
}

static u64 get_ibs_fetch_count(u64 config)
{
	union ibs_fetch_ctl fetch_ctl = (union ibs_fetch_ctl)config;

	return fetch_ctl.fetch_cnt << 4;
}

static u64 get_ibs_op_count(u64 config)
{
	union ibs_op_ctl op_ctl = (union ibs_op_ctl)config;
	u64 count = 0;

	/*
	if (op_ctl.op_val) {
		count = op_ctl.opmaxcnt << 4;
		if (ibs_caps & IBS_CAPS_OPCNTEXT)
			count += op_ctl.opmaxcnt_ext << 20;
	} else if (ibs_caps & IBS_CAPS_RDWROPCNT) {
		count = op_ctl.opcurcnt;
	}

	return count;
}

static void
perf_ibs_event_update(struct perf_ibs *perf_ibs, struct perf_event *event,
		      u64 *config)
{
	u64 count = perf_ibs->get_count(*config);

	/*
	while (!perf_event_try_update(event, count, 64)) {
		rdmsrl(event->hw.config_base, *config);
		count = perf_ibs->get_count(*config);
	}
}

static inline void perf_ibs_enable_event(struct perf_ibs *perf_ibs,
					 struct hw_perf_event *hwc, u64 config)
{
	u64 tmp = hwc->config | config;

	if (perf_ibs->fetch_count_reset_broken)
		wrmsrl(hwc->config_base, tmp & ~perf_ibs->enable_mask);

	wrmsrl(hwc->config_base, tmp | perf_ibs->enable_mask);
}

static inline void perf_ibs_disable_event(struct perf_ibs *perf_ibs,
					  struct hw_perf_event *hwc, u64 config)
{
	config &= ~perf_ibs->cnt_mask;
	if (boot_cpu_data.x86 == 0x10)
		wrmsrl(hwc->config_base, config);
	config &= ~perf_ibs->enable_mask;
	wrmsrl(hwc->config_base, config);
}

static void perf_ibs_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct perf_ibs *perf_ibs = container_of(event->pmu, struct perf_ibs, pmu);
	struct cpu_perf_ibs *pcpu = this_cpu_ptr(perf_ibs->pcpu);
	u64 period, config = 0;

	if (WARN_ON_ONCE(!(hwc->state & PERF_HES_STOPPED)))
		return;

	WARN_ON_ONCE(!(hwc->state & PERF_HES_UPTODATE));
	hwc->state = 0;

	perf_ibs_set_period(perf_ibs, hwc, &period);
	if (perf_ibs == &perf_ibs_op && (ibs_caps & IBS_CAPS_OPCNTEXT)) {
		config |= period & IBS_OP_MAX_CNT_EXT_MASK;
		period &= ~IBS_OP_MAX_CNT_EXT_MASK;
	}
	config |= period >> 4;

	/*
	set_bit(IBS_STARTED,    pcpu->state);
	clear_bit(IBS_STOPPING, pcpu->state);
	perf_ibs_enable_event(perf_ibs, hwc, config);

	perf_event_update_userpage(event);
}

static void perf_ibs_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct perf_ibs *perf_ibs = container_of(event->pmu, struct perf_ibs, pmu);
	struct cpu_perf_ibs *pcpu = this_cpu_ptr(perf_ibs->pcpu);
	u64 config;
	int stopping;

	if (test_and_set_bit(IBS_STOPPING, pcpu->state))
		return;

	stopping = test_bit(IBS_STARTED, pcpu->state);

	if (!stopping && (hwc->state & PERF_HES_UPTODATE))
		return;

	rdmsrl(hwc->config_base, config);

	if (stopping) {
		/*
		set_bit(IBS_STOPPED, pcpu->state);
		perf_ibs_disable_event(perf_ibs, hwc, config);
		/*
		clear_bit(IBS_STARTED, pcpu->state);
		WARN_ON_ONCE(hwc->state & PERF_HES_STOPPED);
		hwc->state |= PERF_HES_STOPPED;
	}

	if (hwc->state & PERF_HES_UPTODATE)
		return;

	/*
	config &= ~perf_ibs->valid_mask;

	perf_ibs_event_update(perf_ibs, event, &config);
	hwc->state |= PERF_HES_UPTODATE;
}

static int perf_ibs_add(struct perf_event *event, int flags)
{
	struct perf_ibs *perf_ibs = container_of(event->pmu, struct perf_ibs, pmu);
	struct cpu_perf_ibs *pcpu = this_cpu_ptr(perf_ibs->pcpu);

	if (test_and_set_bit(IBS_ENABLED, pcpu->state))
		return -ENOSPC;

	event->hw.state = PERF_HES_UPTODATE | PERF_HES_STOPPED;

	pcpu->event = event;

	if (flags & PERF_EF_START)
		perf_ibs_start(event, PERF_EF_RELOAD);

	return 0;
}

static void perf_ibs_del(struct perf_event *event, int flags)
{
	struct perf_ibs *perf_ibs = container_of(event->pmu, struct perf_ibs, pmu);
	struct cpu_perf_ibs *pcpu = this_cpu_ptr(perf_ibs->pcpu);

	if (!test_and_clear_bit(IBS_ENABLED, pcpu->state))
		return;

	perf_ibs_stop(event, PERF_EF_UPDATE);

	pcpu->event = NULL;

	perf_event_update_userpage(event);
}

static void perf_ibs_read(struct perf_event *event) { }

static struct attribute *attrs_empty[] = {
	NULL,
};

static struct attribute_group empty_format_group = {
	.name = "format",
	.attrs = attrs_empty,
};

static struct attribute_group empty_caps_group = {
	.name = "caps",
	.attrs = attrs_empty,
};

static const struct attribute_group *empty_attr_groups[] = {
	&empty_format_group,
	&empty_caps_group,
	NULL,
};

PMU_FORMAT_ATTR(rand_en,	"config:57");
PMU_FORMAT_ATTR(cnt_ctl,	"config:19");
PMU_EVENT_ATTR_STRING(l3missonly, fetch_l3missonly, "config:59");
PMU_EVENT_ATTR_STRING(l3missonly, op_l3missonly, "config:16");
PMU_EVENT_ATTR_STRING(zen4_ibs_extensions, zen4_ibs_extensions, "1");

static umode_t
zen4_ibs_extensions_is_visible(struct kobject *kobj, struct attribute *attr, int i)
{
	return ibs_caps & IBS_CAPS_ZEN4 ? attr->mode : 0;
}

static struct attribute *rand_en_attrs[] = {
	&format_attr_rand_en.attr,
	NULL,
};

static struct attribute *fetch_l3missonly_attrs[] = {
	&fetch_l3missonly.attr.attr,
	NULL,
};

static struct attribute *zen4_ibs_extensions_attrs[] = {
	&zen4_ibs_extensions.attr.attr,
	NULL,
};

static struct attribute_group group_rand_en = {
	.name = "format",
	.attrs = rand_en_attrs,
};

static struct attribute_group group_fetch_l3missonly = {
	.name = "format",
	.attrs = fetch_l3missonly_attrs,
	.is_visible = zen4_ibs_extensions_is_visible,
};

static struct attribute_group group_zen4_ibs_extensions = {
	.name = "caps",
	.attrs = zen4_ibs_extensions_attrs,
	.is_visible = zen4_ibs_extensions_is_visible,
};

static const struct attribute_group *fetch_attr_groups[] = {
	&group_rand_en,
	&empty_caps_group,
	NULL,
};

static const struct attribute_group *fetch_attr_update[] = {
	&group_fetch_l3missonly,
	&group_zen4_ibs_extensions,
	NULL,
};

static umode_t
cnt_ctl_is_visible(struct kobject *kobj, struct attribute *attr, int i)
{
	return ibs_caps & IBS_CAPS_OPCNT ? attr->mode : 0;
}

static struct attribute *cnt_ctl_attrs[] = {
	&format_attr_cnt_ctl.attr,
	NULL,
};

static struct attribute *op_l3missonly_attrs[] = {
	&op_l3missonly.attr.attr,
	NULL,
};

static struct attribute_group group_cnt_ctl = {
	.name = "format",
	.attrs = cnt_ctl_attrs,
	.is_visible = cnt_ctl_is_visible,
};

static struct attribute_group group_op_l3missonly = {
	.name = "format",
	.attrs = op_l3missonly_attrs,
	.is_visible = zen4_ibs_extensions_is_visible,
};

static const struct attribute_group *op_attr_update[] = {
	&group_cnt_ctl,
	&group_op_l3missonly,
	&group_zen4_ibs_extensions,
	NULL,
};

static struct perf_ibs perf_ibs_fetch = {
	.pmu = {
		.task_ctx_nr	= perf_invalid_context,

		.event_init	= perf_ibs_init,
		.add		= perf_ibs_add,
		.del		= perf_ibs_del,
		.start		= perf_ibs_start,
		.stop		= perf_ibs_stop,
		.read		= perf_ibs_read,
		.capabilities	= PERF_PMU_CAP_NO_EXCLUDE,
	},
	.msr			= MSR_AMD64_IBSFETCHCTL,
	.config_mask		= IBS_FETCH_CONFIG_MASK,
	.cnt_mask		= IBS_FETCH_MAX_CNT,
	.enable_mask		= IBS_FETCH_ENABLE,
	.valid_mask		= IBS_FETCH_VAL,
	.max_period		= IBS_FETCH_MAX_CNT << 4,
	.offset_mask		= { MSR_AMD64_IBSFETCH_REG_MASK },
	.offset_max		= MSR_AMD64_IBSFETCH_REG_COUNT,

	.get_count		= get_ibs_fetch_count,
};

static struct perf_ibs perf_ibs_op = {
	.pmu = {
		.task_ctx_nr	= perf_invalid_context,

		.event_init	= perf_ibs_init,
		.add		= perf_ibs_add,
		.del		= perf_ibs_del,
		.start		= perf_ibs_start,
		.stop		= perf_ibs_stop,
		.read		= perf_ibs_read,
		.capabilities	= PERF_PMU_CAP_NO_EXCLUDE,
	},
	.msr			= MSR_AMD64_IBSOPCTL,
	.config_mask		= IBS_OP_CONFIG_MASK,
	.cnt_mask		= IBS_OP_MAX_CNT | IBS_OP_CUR_CNT |
				  IBS_OP_CUR_CNT_RAND,
	.enable_mask		= IBS_OP_ENABLE,
	.valid_mask		= IBS_OP_VAL,
	.max_period		= IBS_OP_MAX_CNT << 4,
	.offset_mask		= { MSR_AMD64_IBSOP_REG_MASK },
	.offset_max		= MSR_AMD64_IBSOP_REG_COUNT,

	.get_count		= get_ibs_op_count,
};

static int perf_ibs_handle_irq(struct perf_ibs *perf_ibs, struct pt_regs *iregs)
{
	struct cpu_perf_ibs *pcpu = this_cpu_ptr(perf_ibs->pcpu);
	struct perf_event *event = pcpu->event;
	struct hw_perf_event *hwc;
	struct perf_sample_data data;
	struct perf_raw_record raw;
	struct pt_regs regs;
	struct perf_ibs_data ibs_data;
	int offset, size, check_rip, offset_max, throttle = 0;
	unsigned int msr;
	u64 *buf, *config, period, new_config = 0;

	if (!test_bit(IBS_STARTED, pcpu->state)) {
fail:
		/*
		if (test_and_clear_bit(IBS_STOPPED, pcpu->state))
			return 1;

		return 0;
	}

	if (WARN_ON_ONCE(!event))
		goto fail;

	hwc = &event->hw;
	msr = hwc->config_base;
	buf = ibs_data.regs;
	rdmsrl(msr, *buf);
	if (!(*buf++ & perf_ibs->valid_mask))
		goto fail;

	config = &ibs_data.regs[0];
	perf_ibs_event_update(perf_ibs, event, config);
	perf_sample_data_init(&data, 0, hwc->last_period);
	if (!perf_ibs_set_period(perf_ibs, hwc, &period))
		goto out;	/* no sw counter overflow */

	ibs_data.caps = ibs_caps;
	size = 1;
	offset = 1;
	check_rip = (perf_ibs == &perf_ibs_op && (ibs_caps & IBS_CAPS_RIPINVALIDCHK));
	if (event->attr.sample_type & PERF_SAMPLE_RAW)
		offset_max = perf_ibs->offset_max;
	else if (check_rip)
		offset_max = 3;
	else
		offset_max = 1;
	do {
		rdmsrl(msr + offset, *buf++);
		size++;
		offset = find_next_bit(perf_ibs->offset_mask,
				       perf_ibs->offset_max,
				       offset + 1);
	} while (offset < offset_max);
	/*
	if (event->attr.sample_type & PERF_SAMPLE_RAW) {
		if (perf_ibs == &perf_ibs_op) {
			if (ibs_caps & IBS_CAPS_BRNTRGT) {
				rdmsrl(MSR_AMD64_IBSBRTARGET, *buf++);
				size++;
			}
			if (ibs_caps & IBS_CAPS_OPDATA4) {
				rdmsrl(MSR_AMD64_IBSOPDATA4, *buf++);
				size++;
			}
		}
		if (perf_ibs == &perf_ibs_fetch && (ibs_caps & IBS_CAPS_FETCHCTLEXTD)) {
			rdmsrl(MSR_AMD64_ICIBSEXTDCTL, *buf++);
			size++;
		}
	}
	ibs_data.size = sizeof(u64) * size;

	regs = *iregs;
	if (check_rip && (ibs_data.regs[2] & IBS_RIP_INVALID)) {
		regs.flags &= ~PERF_EFLAGS_EXACT;
	} else {
		/* Workaround for erratum #1197 */
		if (perf_ibs->fetch_ignore_if_zero_rip && !(ibs_data.regs[1]))
			goto out;

		set_linear_ip(&regs, ibs_data.regs[1]);
		regs.flags |= PERF_EFLAGS_EXACT;
	}

	if (event->attr.sample_type & PERF_SAMPLE_RAW) {
		raw = (struct perf_raw_record){
			.frag = {
				.size = sizeof(u32) + ibs_data.size,
				.data = ibs_data.data,
			},
		};
		data.raw = &raw;
	}

	/*
	if (event->attr.sample_type & PERF_SAMPLE_CALLCHAIN)
		data.callchain = perf_callchain(event, iregs);

	throttle = perf_event_overflow(event, &data, &regs);
out:
	if (throttle) {
		perf_ibs_stop(event, 0);
	} else {
		if (perf_ibs == &perf_ibs_op) {
			if (ibs_caps & IBS_CAPS_OPCNTEXT) {
				new_config = period & IBS_OP_MAX_CNT_EXT_MASK;
				period &= ~IBS_OP_MAX_CNT_EXT_MASK;
			}
			if ((ibs_caps & IBS_CAPS_RDWROPCNT) && (*config & IBS_OP_CNT_CTL))
				new_config |= *config & IBS_OP_CUR_CNT_RAND;
		}
		new_config |= period >> 4;

		perf_ibs_enable_event(perf_ibs, hwc, new_config);
	}

	perf_event_update_userpage(event);

	return 1;
}

static int
perf_ibs_nmi_handler(unsigned int cmd, struct pt_regs *regs)
{
	u64 stamp = sched_clock();
	int handled = 0;

	handled += perf_ibs_handle_irq(&perf_ibs_fetch, regs);
	handled += perf_ibs_handle_irq(&perf_ibs_op, regs);

	if (handled)
		inc_irq_stat(apic_perf_irqs);

	perf_sample_event_took(sched_clock() - stamp);

	return handled;
}
NOKPROBE_SYMBOL(perf_ibs_nmi_handler);

static __init int perf_ibs_pmu_init(struct perf_ibs *perf_ibs, char *name)
{
	struct cpu_perf_ibs __percpu *pcpu;
	int ret;

	pcpu = alloc_percpu(struct cpu_perf_ibs);
	if (!pcpu)
		return -ENOMEM;

	perf_ibs->pcpu = pcpu;

	ret = perf_pmu_register(&perf_ibs->pmu, name, -1);
	if (ret) {
		perf_ibs->pcpu = NULL;
		free_percpu(pcpu);
	}

	return ret;
}

static __init int perf_ibs_fetch_init(void)
{
	/*
	if (boot_cpu_data.x86 >= 0x16 && boot_cpu_data.x86 <= 0x18)
		perf_ibs_fetch.fetch_count_reset_broken = 1;

	if (boot_cpu_data.x86 == 0x19 && boot_cpu_data.x86_model < 0x10)
		perf_ibs_fetch.fetch_ignore_if_zero_rip = 1;

	if (ibs_caps & IBS_CAPS_ZEN4)
		perf_ibs_fetch.config_mask |= IBS_FETCH_L3MISSONLY;

	perf_ibs_fetch.pmu.attr_groups = fetch_attr_groups;
	perf_ibs_fetch.pmu.attr_update = fetch_attr_update;

	return perf_ibs_pmu_init(&perf_ibs_fetch, "ibs_fetch");
}

static __init int perf_ibs_op_init(void)
{
	if (ibs_caps & IBS_CAPS_OPCNT)
		perf_ibs_op.config_mask |= IBS_OP_CNT_CTL;

	if (ibs_caps & IBS_CAPS_OPCNTEXT) {
		perf_ibs_op.max_period  |= IBS_OP_MAX_CNT_EXT_MASK;
		perf_ibs_op.config_mask	|= IBS_OP_MAX_CNT_EXT_MASK;
		perf_ibs_op.cnt_mask    |= IBS_OP_MAX_CNT_EXT_MASK;
	}

	if (ibs_caps & IBS_CAPS_ZEN4)
		perf_ibs_op.config_mask |= IBS_OP_L3MISSONLY;

	perf_ibs_op.pmu.attr_groups = empty_attr_groups;
	perf_ibs_op.pmu.attr_update = op_attr_update;

	return perf_ibs_pmu_init(&perf_ibs_op, "ibs_op");
}

static __init int perf_event_ibs_init(void)
{
	int ret;

	ret = perf_ibs_fetch_init();
	if (ret)
		return ret;

	ret = perf_ibs_op_init();
	if (ret)
		goto err_op;

	ret = register_nmi_handler(NMI_LOCAL, perf_ibs_nmi_handler, 0, "perf_ibs");
	if (ret)
		goto err_nmi;

	pr_info("perf: AMD IBS detected (0x%08x)\n", ibs_caps);
	return 0;

err_nmi:
	perf_pmu_unregister(&perf_ibs_op.pmu);
	free_percpu(perf_ibs_op.pcpu);
	perf_ibs_op.pcpu = NULL;
err_op:
	perf_pmu_unregister(&perf_ibs_fetch.pmu);
	free_percpu(perf_ibs_fetch.pcpu);
	perf_ibs_fetch.pcpu = NULL;

	return ret;
}

#else /* defined(CONFIG_PERF_EVENTS) && defined(CONFIG_CPU_SUP_AMD) */

static __init int perf_event_ibs_init(void)
{
	return 0;
}

#endif


static __init u32 __get_ibs_caps(void)
{
	u32 caps;
	unsigned int max_level;

	if (!boot_cpu_has(X86_FEATURE_IBS))
		return 0;

	/* check IBS cpuid feature flags */
	max_level = cpuid_eax(0x80000000);
	if (max_level < IBS_CPUID_FEATURES)
		return IBS_CAPS_DEFAULT;

	caps = cpuid_eax(IBS_CPUID_FEATURES);
	if (!(caps & IBS_CAPS_AVAIL))
		/* cpuid flags not valid */
		return IBS_CAPS_DEFAULT;

	return caps;
}

u32 get_ibs_caps(void)
{
	return ibs_caps;
}

EXPORT_SYMBOL(get_ibs_caps);

static inline int get_eilvt(int offset)
{
	return !setup_APIC_eilvt(offset, 0, APIC_EILVT_MSG_NMI, 1);
}

static inline int put_eilvt(int offset)
{
	return !setup_APIC_eilvt(offset, 0, 0, 1);
}

static inline int ibs_eilvt_valid(void)
{
	int offset;
	u64 val;
	int valid = 0;

	preempt_disable();

	rdmsrl(MSR_AMD64_IBSCTL, val);
	offset = val & IBSCTL_LVT_OFFSET_MASK;

	if (!(val & IBSCTL_LVT_OFFSET_VALID)) {
		pr_err(FW_BUG "cpu %d, invalid IBS interrupt offset %d (MSR%08X=0x%016llx)\n",
		       smp_processor_id(), offset, MSR_AMD64_IBSCTL, val);
		goto out;
	}

	if (!get_eilvt(offset)) {
		pr_err(FW_BUG "cpu %d, IBS interrupt offset %d not available (MSR%08X=0x%016llx)\n",
		       smp_processor_id(), offset, MSR_AMD64_IBSCTL, val);
		goto out;
	}

	valid = 1;
out:
	preempt_enable();

	return valid;
}

static int setup_ibs_ctl(int ibs_eilvt_off)
{
	struct pci_dev *cpu_cfg;
	int nodes;
	u32 value = 0;

	nodes = 0;
	cpu_cfg = NULL;
	do {
		cpu_cfg = pci_get_device(PCI_VENDOR_ID_AMD,
					 PCI_DEVICE_ID_AMD_10H_NB_MISC,
					 cpu_cfg);
		if (!cpu_cfg)
			break;
		++nodes;
		pci_write_config_dword(cpu_cfg, IBSCTL, ibs_eilvt_off
				       | IBSCTL_LVT_OFFSET_VALID);
		pci_read_config_dword(cpu_cfg, IBSCTL, &value);
		if (value != (ibs_eilvt_off | IBSCTL_LVT_OFFSET_VALID)) {
			pci_dev_put(cpu_cfg);
			pr_debug("Failed to setup IBS LVT offset, IBSCTL = 0x%08x\n",
				 value);
			return -EINVAL;
		}
	} while (1);

	if (!nodes) {
		pr_debug("No CPU node configured for IBS\n");
		return -ENODEV;
	}

	return 0;
}

static void force_ibs_eilvt_setup(void)
{
	int offset;
	int ret;

	preempt_disable();
	/* find the next free available EILVT entry, skip offset 0 */
	for (offset = 1; offset < APIC_EILVT_NR_MAX; offset++) {
		if (get_eilvt(offset))
			break;
	}
	preempt_enable();

	if (offset == APIC_EILVT_NR_MAX) {
		pr_debug("No EILVT entry available\n");
		return;
	}

	ret = setup_ibs_ctl(offset);
	if (ret)
		goto out;

	if (!ibs_eilvt_valid())
		goto out;

	pr_info("LVT offset %d assigned\n", offset);

	return;
out:
	preempt_disable();
	put_eilvt(offset);
	preempt_enable();
	return;
}

static void ibs_eilvt_setup(void)
{
	/*
	if (boot_cpu_data.x86 == 0x10)
		force_ibs_eilvt_setup();
}

static inline int get_ibs_lvt_offset(void)
{
	u64 val;

	rdmsrl(MSR_AMD64_IBSCTL, val);
	if (!(val & IBSCTL_LVT_OFFSET_VALID))
		return -EINVAL;

	return val & IBSCTL_LVT_OFFSET_MASK;
}

static void setup_APIC_ibs(void)
{
	int offset;

	offset = get_ibs_lvt_offset();
	if (offset < 0)
		goto failed;

	if (!setup_APIC_eilvt(offset, 0, APIC_EILVT_MSG_NMI, 0))
		return;
failed:
	pr_warn("perf: IBS APIC setup failed on cpu #%d\n",
		smp_processor_id());
}

static void clear_APIC_ibs(void)
{
	int offset;

	offset = get_ibs_lvt_offset();
	if (offset >= 0)
		setup_APIC_eilvt(offset, 0, APIC_EILVT_MSG_FIX, 1);
}

static int x86_pmu_amd_ibs_starting_cpu(unsigned int cpu)
{
	setup_APIC_ibs();
	return 0;
}

#ifdef CONFIG_PM

static int perf_ibs_suspend(void)
{
	clear_APIC_ibs();
	return 0;
}

static void perf_ibs_resume(void)
{
	ibs_eilvt_setup();
	setup_APIC_ibs();
}

static struct syscore_ops perf_ibs_syscore_ops = {
	.resume		= perf_ibs_resume,
	.suspend	= perf_ibs_suspend,
};

static void perf_ibs_pm_init(void)
{
	register_syscore_ops(&perf_ibs_syscore_ops);
}

#else

static inline void perf_ibs_pm_init(void) { }

#endif

static int x86_pmu_amd_ibs_dying_cpu(unsigned int cpu)
{
	clear_APIC_ibs();
	return 0;
}

static __init int amd_ibs_init(void)
{
	u32 caps;

	caps = __get_ibs_caps();
	if (!caps)
		return -ENODEV;	/* ibs not supported by the cpu */

	ibs_eilvt_setup();

	if (!ibs_eilvt_valid())
		return -EINVAL;

	perf_ibs_pm_init();

	ibs_caps = caps;
	/* make ibs_caps visible to other cpus: */
	smp_mb();
	/*
	cpuhp_setup_state(CPUHP_AP_PERF_X86_AMD_IBS_STARTING,
			  "perf/x86/amd/ibs:starting",
			  x86_pmu_amd_ibs_starting_cpu,
			  x86_pmu_amd_ibs_dying_cpu);

	return perf_event_ibs_init();
}

device_initcall(amd_ibs_init);
