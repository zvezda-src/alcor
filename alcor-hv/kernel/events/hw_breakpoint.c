

#include <linux/irqflags.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/bug.h>

#include <linux/hw_breakpoint.h>
struct bp_cpuinfo {
	/* Number of pinned cpu breakpoints in a cpu */
	unsigned int	cpu_pinned;
	/* tsk_pinned[n] is the number of tasks having n+1 breakpoints */
	unsigned int	*tsk_pinned;
	/* Number of non-pinned cpu/task breakpoints in a cpu */
	unsigned int	flexible; /* XXX: placeholder, see fetch_this_slot() */
};

static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
static int nr_slots[TYPE_MAX];

static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
{
	return per_cpu_ptr(bp_cpuinfo + type, cpu);
}

static LIST_HEAD(bp_task_head);

static int constraints_initialized;

struct bp_busy_slots {
	unsigned int pinned;
	unsigned int flexible;
};

static DEFINE_MUTEX(nr_bp_mutex);

__weak int hw_breakpoint_weight(struct perf_event *bp)
{
	return 1;
}

static inline enum bp_type_idx find_slot_idx(u64 bp_type)
{
	if (bp_type & HW_BREAKPOINT_RW)
		return TYPE_DATA;

	return TYPE_INST;
}

static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
{
	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
	int i;

	for (i = nr_slots[type] - 1; i >= 0; i--) {
		if (tsk_pinned[i] > 0)
			return i + 1;
	}

	return 0;
}

static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
{
	struct task_struct *tsk = bp->hw.target;
	struct perf_event *iter;
	int count = 0;

	list_for_each_entry(iter, &bp_task_head, hw.bp_list) {
		if (iter->hw.target == tsk &&
		    find_slot_idx(iter->attr.bp_type) == type &&
		    (iter->cpu < 0 || cpu == iter->cpu))
			count += hw_breakpoint_weight(iter);
	}

	return count;
}

static const struct cpumask *cpumask_of_bp(struct perf_event *bp)
{
	if (bp->cpu >= 0)
		return cpumask_of(bp->cpu);
	return cpu_possible_mask;
}

static void
fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
		    enum bp_type_idx type)
{
	const struct cpumask *cpumask = cpumask_of_bp(bp);
	int cpu;

	for_each_cpu(cpu, cpumask) {
		struct bp_cpuinfo *info = get_bp_info(cpu, type);
		int nr;

		nr = info->cpu_pinned;
		if (!bp->hw.target)
			nr += max_task_bp_pinned(cpu, type);
		else
			nr += task_bp_pinned(cpu, bp, type);

		if (nr > slots->pinned)
			slots->pinned = nr;

		nr = info->flexible;
		if (nr > slots->flexible)
			slots->flexible = nr;
	}
}

static void
fetch_this_slot(struct bp_busy_slots *slots, int weight)
{
	slots->pinned += weight;
}

static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
				enum bp_type_idx type, int weight)
{
	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
	int old_idx, new_idx;

	old_idx = task_bp_pinned(cpu, bp, type) - 1;
	new_idx = old_idx + weight;

	if (old_idx >= 0)
		tsk_pinned[old_idx]--;
	if (new_idx >= 0)
		tsk_pinned[new_idx]++;
}

static void
toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
	       int weight)
{
	const struct cpumask *cpumask = cpumask_of_bp(bp);
	int cpu;

	if (!enable)
		weight = -weight;

	/* Pinned counter cpu profiling */
	if (!bp->hw.target) {
		get_bp_info(bp->cpu, type)->cpu_pinned += weight;
		return;
	}

	/* Pinned counter task profiling */
	for_each_cpu(cpu, cpumask)
		toggle_bp_task_slot(bp, cpu, type, weight);

	if (enable)
		list_add_tail(&bp->hw.bp_list, &bp_task_head);
	else
		list_del(&bp->hw.bp_list);
}

__weak int arch_reserve_bp_slot(struct perf_event *bp)
{
	return 0;
}

__weak void arch_release_bp_slot(struct perf_event *bp)
{
}

__weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
{
	/*
}

static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
{
	struct bp_busy_slots slots = {0};
	enum bp_type_idx type;
	int weight;
	int ret;

	/* We couldn't initialize breakpoint constraints on boot */
	if (!constraints_initialized)
		return -ENOMEM;

	/* Basic checks */
	if (bp_type == HW_BREAKPOINT_EMPTY ||
	    bp_type == HW_BREAKPOINT_INVALID)
		return -EINVAL;

	type = find_slot_idx(bp_type);
	weight = hw_breakpoint_weight(bp);

	fetch_bp_busy_slots(&slots, bp, type);
	/*
	fetch_this_slot(&slots, weight);

	/* Flexible counters need to keep at least one slot */
	if (slots.pinned + (!!slots.flexible) > nr_slots[type])
		return -ENOSPC;

	ret = arch_reserve_bp_slot(bp);
	if (ret)
		return ret;

	toggle_bp_slot(bp, true, type, weight);

	return 0;
}

int reserve_bp_slot(struct perf_event *bp)
{
	int ret;

	mutex_lock(&nr_bp_mutex);

	ret = __reserve_bp_slot(bp, bp->attr.bp_type);

	mutex_unlock(&nr_bp_mutex);

	return ret;
}

static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
{
	enum bp_type_idx type;
	int weight;

	arch_release_bp_slot(bp);

	type = find_slot_idx(bp_type);
	weight = hw_breakpoint_weight(bp);
	toggle_bp_slot(bp, false, type, weight);
}

void release_bp_slot(struct perf_event *bp)
{
	mutex_lock(&nr_bp_mutex);

	arch_unregister_hw_breakpoint(bp);
	__release_bp_slot(bp, bp->attr.bp_type);

	mutex_unlock(&nr_bp_mutex);
}

static int __modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
{
	int err;

	__release_bp_slot(bp, old_type);

	err = __reserve_bp_slot(bp, new_type);
	if (err) {
		/*
		WARN_ON(__reserve_bp_slot(bp, old_type));
	}

	return err;
}

static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
{
	int ret;

	mutex_lock(&nr_bp_mutex);
	ret = __modify_bp_slot(bp, old_type, new_type);
	mutex_unlock(&nr_bp_mutex);
	return ret;
}

int dbg_reserve_bp_slot(struct perf_event *bp)
{
	if (mutex_is_locked(&nr_bp_mutex))
		return -1;

	return __reserve_bp_slot(bp, bp->attr.bp_type);
}

int dbg_release_bp_slot(struct perf_event *bp)
{
	if (mutex_is_locked(&nr_bp_mutex))
		return -1;

	__release_bp_slot(bp, bp->attr.bp_type);

	return 0;
}

static int hw_breakpoint_parse(struct perf_event *bp,
			       const struct perf_event_attr *attr,
			       struct arch_hw_breakpoint *hw)
{
	int err;

	err = hw_breakpoint_arch_parse(bp, attr, hw);
	if (err)
		return err;

	if (arch_check_bp_in_kernelspace(hw)) {
		if (attr->exclude_kernel)
			return -EINVAL;
		/*
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
	}

	return 0;
}

int register_perf_hw_breakpoint(struct perf_event *bp)
{
	struct arch_hw_breakpoint hw = { };
	int err;

	err = reserve_bp_slot(bp);
	if (err)
		return err;

	err = hw_breakpoint_parse(bp, &bp->attr, &hw);
	if (err) {
		release_bp_slot(bp);
		return err;
	}

	bp->hw.info = hw;

	return 0;
}

struct perf_event *
register_user_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context,
			    struct task_struct *tsk)
{
	return perf_event_create_kernel_counter(attr, -1, tsk, triggered,
						context);
}
EXPORT_SYMBOL_GPL(register_user_hw_breakpoint);

static void hw_breakpoint_copy_attr(struct perf_event_attr *to,
				    struct perf_event_attr *from)
{
	to->bp_addr = from->bp_addr;
	to->bp_type = from->bp_type;
	to->bp_len  = from->bp_len;
	to->disabled = from->disabled;
}

int
modify_user_hw_breakpoint_check(struct perf_event *bp, struct perf_event_attr *attr,
			        bool check)
{
	struct arch_hw_breakpoint hw = { };
	int err;

	err = hw_breakpoint_parse(bp, attr, &hw);
	if (err)
		return err;

	if (check) {
		struct perf_event_attr old_attr;

		old_attr = bp->attr;
		hw_breakpoint_copy_attr(&old_attr, attr);
		if (memcmp(&old_attr, attr, sizeof(*attr)))
			return -EINVAL;
	}

	if (bp->attr.bp_type != attr->bp_type) {
		err = modify_bp_slot(bp, bp->attr.bp_type, attr->bp_type);
		if (err)
			return err;
	}

	hw_breakpoint_copy_attr(&bp->attr, attr);
	bp->hw.info = hw;

	return 0;
}

int modify_user_hw_breakpoint(struct perf_event *bp, struct perf_event_attr *attr)
{
	int err;

	/*
	if (irqs_disabled() && bp->ctx && bp->ctx->task == current)
		perf_event_disable_local(bp);
	else
		perf_event_disable(bp);

	err = modify_user_hw_breakpoint_check(bp, attr, false);

	if (!bp->attr.disabled)
		perf_event_enable(bp);

	return err;
}
EXPORT_SYMBOL_GPL(modify_user_hw_breakpoint);

void unregister_hw_breakpoint(struct perf_event *bp)
{
	if (!bp)
		return;
	perf_event_release_kernel(bp);
}
EXPORT_SYMBOL_GPL(unregister_hw_breakpoint);

struct perf_event * __percpu *
register_wide_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context)
{
	struct perf_event * __percpu *cpu_events, *bp;
	long err = 0;
	int cpu;

	cpu_events = alloc_percpu(typeof(*cpu_events));
	if (!cpu_events)
		return (void __percpu __force *)ERR_PTR(-ENOMEM);

	cpus_read_lock();
	for_each_online_cpu(cpu) {
		bp = perf_event_create_kernel_counter(attr, cpu, NULL,
						      triggered, context);
		if (IS_ERR(bp)) {
			err = PTR_ERR(bp);
			break;
		}

		per_cpu(*cpu_events, cpu) = bp;
	}
	cpus_read_unlock();

	if (likely(!err))
		return cpu_events;

	unregister_wide_hw_breakpoint(cpu_events);
	return (void __percpu __force *)ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(register_wide_hw_breakpoint);

void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
{
	int cpu;

	for_each_possible_cpu(cpu)
		unregister_hw_breakpoint(per_cpu(*cpu_events, cpu));

	free_percpu(cpu_events);
}
EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);

static struct notifier_block hw_breakpoint_exceptions_nb = {
	.notifier_call = hw_breakpoint_exceptions_notify,
	/* we need to be notified first */
	.priority = 0x7fffffff
};

static void bp_perf_event_destroy(struct perf_event *event)
{
	release_bp_slot(event);
}

static int hw_breakpoint_event_init(struct perf_event *bp)
{
	int err;

	if (bp->attr.type != PERF_TYPE_BREAKPOINT)
		return -ENOENT;

	/*
	if (has_branch_stack(bp))
		return -EOPNOTSUPP;

	err = register_perf_hw_breakpoint(bp);
	if (err)
		return err;

	bp->destroy = bp_perf_event_destroy;

	return 0;
}

static int hw_breakpoint_add(struct perf_event *bp, int flags)
{
	if (!(flags & PERF_EF_START))
		bp->hw.state = PERF_HES_STOPPED;

	if (is_sampling_event(bp)) {
		bp->hw.last_period = bp->hw.sample_period;
		perf_swevent_set_period(bp);
	}

	return arch_install_hw_breakpoint(bp);
}

static void hw_breakpoint_del(struct perf_event *bp, int flags)
{
	arch_uninstall_hw_breakpoint(bp);
}

static void hw_breakpoint_start(struct perf_event *bp, int flags)
{
	bp->hw.state = 0;
}

static void hw_breakpoint_stop(struct perf_event *bp, int flags)
{
	bp->hw.state = PERF_HES_STOPPED;
}

static struct pmu perf_breakpoint = {
	.task_ctx_nr	= perf_sw_context, /* could eventually get its own */

	.event_init	= hw_breakpoint_event_init,
	.add		= hw_breakpoint_add,
	.del		= hw_breakpoint_del,
	.start		= hw_breakpoint_start,
	.stop		= hw_breakpoint_stop,
	.read		= hw_breakpoint_pmu_read,
};

int __init init_hw_breakpoint(void)
{
	int cpu, err_cpu;
	int i;

	for (i = 0; i < TYPE_MAX; i++)
		nr_slots[i] = hw_breakpoint_slots(i);

	for_each_possible_cpu(cpu) {
		for (i = 0; i < TYPE_MAX; i++) {
			struct bp_cpuinfo *info = get_bp_info(cpu, i);

			info->tsk_pinned = kcalloc(nr_slots[i], sizeof(int),
							GFP_KERNEL);
			if (!info->tsk_pinned)
				goto err_alloc;
		}
	}

	constraints_initialized = 1;

	perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);

	return register_die_notifier(&hw_breakpoint_exceptions_nb);

 err_alloc:
	for_each_possible_cpu(err_cpu) {
		for (i = 0; i < TYPE_MAX; i++)
			kfree(get_bp_info(err_cpu, i)->tsk_pinned);
		if (err_cpu == cpu)
			break;
	}

	return -ENOMEM;
}


