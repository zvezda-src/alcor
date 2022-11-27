
#define pr_fmt(fmt) "rcu: " fmt

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/rcupdate_wait.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/nmi.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/export.h>
#include <linux/completion.h>
#include <linux/moduleparam.h>
#include <linux/panic.h>
#include <linux/panic_notifier.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/mutex.h>
#include <linux/time.h>
#include <linux/kernel_stat.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <uapi/linux/sched/types.h>
#include <linux/prefetch.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/trace_events.h>
#include <linux/suspend.h>
#include <linux/ftrace.h>
#include <linux/tick.h>
#include <linux/sysrq.h>
#include <linux/kprobes.h>
#include <linux/gfp.h>
#include <linux/oom.h>
#include <linux/smpboot.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/sched/isolation.h>
#include <linux/sched/clock.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kasan.h>
#include <linux/context_tracking.h>
#include "../time/tick-internal.h"

#include "tree.h"
#include "rcu.h"

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "rcutree."


static DEFINE_PER_CPU_SHARED_ALIGNED(struct rcu_data, rcu_data) = {
#ifdef CONFIG_RCU_NOCB_CPU
	.cblist.flags = SEGCBLIST_RCU_CORE,
#endif
};
static struct rcu_state rcu_state = {
	.level = { &rcu_state.node[0] },
	.gp_state = RCU_GP_IDLE,
	.gp_seq = (0UL - 300UL) << RCU_SEQ_CTR_SHIFT,
	.barrier_mutex = __MUTEX_INITIALIZER(rcu_state.barrier_mutex),
	.barrier_lock = __RAW_SPIN_LOCK_UNLOCKED(rcu_state.barrier_lock),
	.name = RCU_NAME,
	.abbr = RCU_ABBR,
	.exp_mutex = __MUTEX_INITIALIZER(rcu_state.exp_mutex),
	.exp_wake_mutex = __MUTEX_INITIALIZER(rcu_state.exp_wake_mutex),
	.ofl_lock = __ARCH_SPIN_LOCK_UNLOCKED,
};

static bool dump_tree;
module_param(dump_tree, bool, 0444);
static bool use_softirq = !IS_ENABLED(CONFIG_PREEMPT_RT);
#ifndef CONFIG_PREEMPT_RT
module_param(use_softirq, bool, 0444);
#endif
static bool rcu_fanout_exact;
module_param(rcu_fanout_exact, bool, 0444);
static int rcu_fanout_leaf = RCU_FANOUT_LEAF;
module_param(rcu_fanout_leaf, int, 0444);
int rcu_num_lvls __read_mostly = RCU_NUM_LVLS;
int num_rcu_lvl[] = NUM_RCU_LVL_INIT;
int rcu_num_nodes __read_mostly = NUM_RCU_NODES; /* Total # rcu_nodes in use. */

int rcu_scheduler_active __read_mostly;
EXPORT_SYMBOL_GPL(rcu_scheduler_active);

static int rcu_scheduler_fully_active __read_mostly;

static void rcu_report_qs_rnp(unsigned long mask, struct rcu_node *rnp,
			      unsigned long gps, unsigned long flags);
static void rcu_init_new_rnp(struct rcu_node *rnp_leaf);
static void rcu_cleanup_dead_rnp(struct rcu_node *rnp_leaf);
static void rcu_boost_kthread_setaffinity(struct rcu_node *rnp, int outgoingcpu);
static void invoke_rcu_core(void);
static void rcu_report_exp_rdp(struct rcu_data *rdp);
static void sync_sched_exp_online_cleanup(int cpu);
static void check_cb_ovld_locked(struct rcu_data *rdp, struct rcu_node *rnp);
static bool rcu_rdp_is_offloaded(struct rcu_data *rdp);

static int kthread_prio = IS_ENABLED(CONFIG_RCU_BOOST) ? 1 : 0;
module_param(kthread_prio, int, 0444);


static int gp_preinit_delay;
module_param(gp_preinit_delay, int, 0444);
static int gp_init_delay;
module_param(gp_init_delay, int, 0444);
static int gp_cleanup_delay;
module_param(gp_cleanup_delay, int, 0444);

// Add delay to rcu_read_unlock() for strict grace periods.
static int rcu_unlock_delay;
#ifdef CONFIG_RCU_STRICT_GRACE_PERIOD
module_param(rcu_unlock_delay, int, 0444);
#endif

static int rcu_min_cached_objs = 5;
module_param(rcu_min_cached_objs, int, 0444);

// A page shrinker can ask for pages to be freed to make them
// available for other parts of the system. This usually happens
// under low memory conditions, and in that case we should also
// defer page-cache filling for a short time period.
//
// The default value is 5 seconds, which is long enough to reduce
// interference with the shrinker while it asks other systems to
// drain their caches.
static int rcu_delay_page_cache_fill_msec = 5000;
module_param(rcu_delay_page_cache_fill_msec, int, 0444);

int rcu_get_gp_kthreads_prio(void)
{
	return kthread_prio;
}
EXPORT_SYMBOL_GPL(rcu_get_gp_kthreads_prio);

#define PER_RCU_NODE_PERIOD 3	/* Number of grace periods between delays for debugging. */

static unsigned long rcu_rnp_online_cpus(struct rcu_node *rnp)
{
	return READ_ONCE(rnp->qsmaskinitnext);
}

static bool rcu_rdp_cpu_online(struct rcu_data *rdp)
{
	return !!(rdp->grpmask & rcu_rnp_online_cpus(rdp->mynode));
}

static int rcu_gp_in_progress(void)
{
	return rcu_seq_state(rcu_seq_current(&rcu_state.gp_seq));
}

static long rcu_get_n_cbs_cpu(int cpu)
{
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);

	if (rcu_segcblist_is_enabled(&rdp->cblist))
		return rcu_segcblist_n_cbs(&rdp->cblist);
	return 0;
}

void rcu_softirq_qs(void)
{
	rcu_qs();
	rcu_preempt_deferred_qs(current);
	rcu_tasks_qs(current, false);
}

static void rcu_dynticks_eqs_online(void)
{
	if (ct_dynticks() & RCU_DYNTICKS_IDX)
		return;
	ct_state_inc(RCU_DYNTICKS_IDX);
}

static int rcu_dynticks_snap(int cpu)
{
	smp_mb();  // Fundamental RCU ordering guarantee.
	return ct_dynticks_cpu_acquire(cpu);
}

static bool rcu_dynticks_in_eqs(int snap)
{
	return !(snap & RCU_DYNTICKS_IDX);
}

bool rcu_is_idle_cpu(int cpu)
{
	return rcu_dynticks_in_eqs(rcu_dynticks_snap(cpu));
}

static bool rcu_dynticks_in_eqs_since(struct rcu_data *rdp, int snap)
{
	return snap != rcu_dynticks_snap(rdp->cpu);
}

bool rcu_dynticks_zero_in_eqs(int cpu, int *vp)
{
	int snap;

	// If not quiescent, force back to earlier extended quiescent state.
	snap = ct_dynticks_cpu(cpu) & ~RCU_DYNTICKS_IDX;
	smp_rmb(); // Order ->dynticks and *vp reads.
	if (READ_ONCE(*vp))
		return false;  // Non-zero, so report failure;
	smp_rmb(); // Order *vp read and ->dynticks re-read.

	// If still in the same extended quiescent state, we are good!
	return snap == ct_dynticks_cpu(cpu);
}

notrace void rcu_momentary_dyntick_idle(void)
{
	int seq;

	raw_cpu_write(rcu_data.rcu_need_heavy_qs, false);
	seq = ct_state_inc(2 * RCU_DYNTICKS_IDX);
	/* It is illegal to call this from idle state. */
	WARN_ON_ONCE(!(seq & RCU_DYNTICKS_IDX));
	rcu_preempt_deferred_qs(current);
}
EXPORT_SYMBOL_GPL(rcu_momentary_dyntick_idle);

static int rcu_is_cpu_rrupt_from_idle(void)
{
	long nesting;

	/*
	lockdep_assert_irqs_disabled();

	/* Check for counter underflows */
	RCU_LOCKDEP_WARN(ct_dynticks_nesting() < 0,
			 "RCU dynticks_nesting counter underflow!");
	RCU_LOCKDEP_WARN(ct_dynticks_nmi_nesting() <= 0,
			 "RCU dynticks_nmi_nesting counter underflow/zero!");

	/* Are we at first interrupt nesting level? */
	nesting = ct_dynticks_nmi_nesting();
	if (nesting > 1)
		return false;

	/*
	WARN_ON_ONCE(!nesting && !is_idle_task(current));

	/* Does CPU appear to be idle from an RCU standpoint? */
	return ct_dynticks_nesting() == 0;
}

#define DEFAULT_RCU_BLIMIT (IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD) ? 1000 : 10)
				// Maximum callbacks per rcu_do_batch ...
#define DEFAULT_MAX_RCU_BLIMIT 10000 // ... even during callback flood.
static long blimit = DEFAULT_RCU_BLIMIT;
#define DEFAULT_RCU_QHIMARK 10000 // If this many pending, ignore blimit.
static long qhimark = DEFAULT_RCU_QHIMARK;
#define DEFAULT_RCU_QLOMARK 100   // Once only this many pending, use blimit.
static long qlowmark = DEFAULT_RCU_QLOMARK;
#define DEFAULT_RCU_QOVLD_MULT 2
#define DEFAULT_RCU_QOVLD (DEFAULT_RCU_QOVLD_MULT * DEFAULT_RCU_QHIMARK)
static long qovld = DEFAULT_RCU_QOVLD; // If this many pending, hammer QS.
static long qovld_calc = -1;	  // No pre-initialization lock acquisitions!

module_param(blimit, long, 0444);
module_param(qhimark, long, 0444);
module_param(qlowmark, long, 0444);
module_param(qovld, long, 0444);

static ulong jiffies_till_first_fqs = IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD) ? 0 : ULONG_MAX;
static ulong jiffies_till_next_fqs = ULONG_MAX;
static bool rcu_kick_kthreads;
static int rcu_divisor = 7;
module_param(rcu_divisor, int, 0644);

static long rcu_resched_ns = 3 * NSEC_PER_MSEC;
module_param(rcu_resched_ns, long, 0644);

static ulong jiffies_till_sched_qs = ULONG_MAX;
module_param(jiffies_till_sched_qs, ulong, 0444);
static ulong jiffies_to_sched_qs; /* See adjust_jiffies_till_sched_qs(). */
module_param(jiffies_to_sched_qs, ulong, 0444); /* Display only! */

static void adjust_jiffies_till_sched_qs(void)
{
	unsigned long j;

	/* If jiffies_till_sched_qs was specified, respect the request. */
	if (jiffies_till_sched_qs != ULONG_MAX) {
		WRITE_ONCE(jiffies_to_sched_qs, jiffies_till_sched_qs);
		return;
	}
	/* Otherwise, set to third fqs scan, but bound below on large system. */
	j = READ_ONCE(jiffies_till_first_fqs) +
		      2 * READ_ONCE(jiffies_till_next_fqs);
	if (j < HZ / 10 + nr_cpu_ids / RCU_JIFFIES_FQS_DIV)
		j = HZ / 10 + nr_cpu_ids / RCU_JIFFIES_FQS_DIV;
	pr_info("RCU calculated value of scheduler-enlistment delay is %ld jiffies.\n", j);
	WRITE_ONCE(jiffies_to_sched_qs, j);
}

static int param_set_first_fqs_jiffies(const char *val, const struct kernel_param *kp)
{
	ulong j;
	int ret = kstrtoul(val, 0, &j);

	if (!ret) {
		WRITE_ONCE(*(ulong *)kp->arg, (j > HZ) ? HZ : j);
		adjust_jiffies_till_sched_qs();
	}
	return ret;
}

static int param_set_next_fqs_jiffies(const char *val, const struct kernel_param *kp)
{
	ulong j;
	int ret = kstrtoul(val, 0, &j);

	if (!ret) {
		WRITE_ONCE(*(ulong *)kp->arg, (j > HZ) ? HZ : (j ?: 1));
		adjust_jiffies_till_sched_qs();
	}
	return ret;
}

static const struct kernel_param_ops first_fqs_jiffies_ops = {
	.set = param_set_first_fqs_jiffies,
	.get = param_get_ulong,
};

static const struct kernel_param_ops next_fqs_jiffies_ops = {
	.set = param_set_next_fqs_jiffies,
	.get = param_get_ulong,
};

module_param_cb(jiffies_till_first_fqs, &first_fqs_jiffies_ops, &jiffies_till_first_fqs, 0644);
module_param_cb(jiffies_till_next_fqs, &next_fqs_jiffies_ops, &jiffies_till_next_fqs, 0644);
module_param(rcu_kick_kthreads, bool, 0644);

static void force_qs_rnp(int (*f)(struct rcu_data *rdp));
static int rcu_pending(int user);

unsigned long rcu_get_gp_seq(void)
{
	return READ_ONCE(rcu_state.gp_seq);
}
EXPORT_SYMBOL_GPL(rcu_get_gp_seq);

unsigned long rcu_exp_batches_completed(void)
{
	return rcu_state.expedited_sequence;
}
EXPORT_SYMBOL_GPL(rcu_exp_batches_completed);

static struct rcu_node *rcu_get_root(void)
{
	return &rcu_state.node[0];
}

void rcutorture_get_gp_data(enum rcutorture_type test_type, int *flags,
			    unsigned long *gp_seq)
{
	switch (test_type) {
	case RCU_FLAVOR:
		*flags = READ_ONCE(rcu_state.gp_flags);
		*gp_seq = rcu_seq_current(&rcu_state.gp_seq);
		break;
	default:
		break;
	}
}
EXPORT_SYMBOL_GPL(rcutorture_get_gp_data);

#if defined(CONFIG_NO_HZ_FULL) && (!defined(CONFIG_GENERIC_ENTRY) || !defined(CONFIG_KVM_XFER_TO_GUEST_WORK))
static void late_wakeup_func(struct irq_work *work)
{
}

static DEFINE_PER_CPU(struct irq_work, late_wakeup_work) =
	IRQ_WORK_INIT(late_wakeup_func);

noinstr void rcu_irq_work_resched(void)
{
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);

	if (IS_ENABLED(CONFIG_GENERIC_ENTRY) && !(current->flags & PF_VCPU))
		return;

	if (IS_ENABLED(CONFIG_KVM_XFER_TO_GUEST_WORK) && (current->flags & PF_VCPU))
		return;

	instrumentation_begin();
	if (do_nocb_deferred_wakeup(rdp) && need_resched()) {
		irq_work_queue(this_cpu_ptr(&late_wakeup_work));
	}
	instrumentation_end();
}
#endif /* #if defined(CONFIG_NO_HZ_FULL) && (!defined(CONFIG_GENERIC_ENTRY) || !defined(CONFIG_KVM_XFER_TO_GUEST_WORK)) */

#ifdef CONFIG_PROVE_RCU
void rcu_irq_exit_check_preempt(void)
{
	lockdep_assert_irqs_disabled();

	RCU_LOCKDEP_WARN(ct_dynticks_nesting() <= 0,
			 "RCU dynticks_nesting counter underflow/zero!");
	RCU_LOCKDEP_WARN(ct_dynticks_nmi_nesting() !=
			 DYNTICK_IRQ_NONIDLE,
			 "Bad RCU  dynticks_nmi_nesting counter\n");
	RCU_LOCKDEP_WARN(rcu_dynticks_curr_cpu_in_eqs(),
			 "RCU in extended quiescent state!");
}
#endif /* #ifdef CONFIG_PROVE_RCU */

#ifdef CONFIG_NO_HZ_FULL
void __rcu_irq_enter_check_tick(void)
{
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);

	// If we're here from NMI there's nothing to do.
	if (in_nmi())
		return;

	RCU_LOCKDEP_WARN(rcu_dynticks_curr_cpu_in_eqs(),
			 "Illegal rcu_irq_enter_check_tick() from extended quiescent state");

	if (!tick_nohz_full_cpu(rdp->cpu) ||
	    !READ_ONCE(rdp->rcu_urgent_qs) ||
	    READ_ONCE(rdp->rcu_forced_tick)) {
		// RCU doesn't need nohz_full help from this CPU, or it is
		// already getting that help.
		return;
	}

	// We get here only when not in an extended quiescent state and
	// from interrupts (as opposed to NMIs).  Therefore, (1) RCU is
	// already watching and (2) The fact that we are in an interrupt
	// handler and that the rcu_node lock is an irq-disabled lock
	// prevents self-deadlock.  So we can safely recheck under the lock.
	// Note that the nohz_full state currently cannot change.
	raw_spin_lock_rcu_node(rdp->mynode);
	if (rdp->rcu_urgent_qs && !rdp->rcu_forced_tick) {
		// A nohz_full CPU is in the kernel and RCU needs a
		// quiescent state.  Turn on the tick!
		WRITE_ONCE(rdp->rcu_forced_tick, true);
		tick_dep_set_cpu(rdp->cpu, TICK_DEP_BIT_RCU);
	}
	raw_spin_unlock_rcu_node(rdp->mynode);
}
#endif /* CONFIG_NO_HZ_FULL */

int rcu_needs_cpu(void)
{
	return !rcu_segcblist_empty(&this_cpu_ptr(&rcu_data)->cblist) &&
		!rcu_rdp_is_offloaded(this_cpu_ptr(&rcu_data));
}

static void rcu_disable_urgency_upon_qs(struct rcu_data *rdp)
{
	raw_lockdep_assert_held_rcu_node(rdp->mynode);
	WRITE_ONCE(rdp->rcu_urgent_qs, false);
	WRITE_ONCE(rdp->rcu_need_heavy_qs, false);
	if (tick_nohz_full_cpu(rdp->cpu) && rdp->rcu_forced_tick) {
		tick_dep_clear_cpu(rdp->cpu, TICK_DEP_BIT_RCU);
		WRITE_ONCE(rdp->rcu_forced_tick, false);
	}
}

notrace bool rcu_is_watching(void)
{
	bool ret;

	preempt_disable_notrace();
	ret = !rcu_dynticks_curr_cpu_in_eqs();
	preempt_enable_notrace();
	return ret;
}
EXPORT_SYMBOL_GPL(rcu_is_watching);

void rcu_request_urgent_qs_task(struct task_struct *t)
{
	int cpu;

	barrier();
	cpu = task_cpu(t);
	if (!task_curr(t))
		return; /* This task is not running on that CPU. */
	smp_store_release(per_cpu_ptr(&rcu_data.rcu_urgent_qs, cpu), true);
}

#if defined(CONFIG_PROVE_RCU) && defined(CONFIG_HOTPLUG_CPU)

bool rcu_lockdep_current_cpu_online(void)
{
	struct rcu_data *rdp;
	bool ret = false;

	if (in_nmi() || !rcu_scheduler_fully_active)
		return true;
	preempt_disable_notrace();
	rdp = this_cpu_ptr(&rcu_data);
	/*
	if (rcu_rdp_cpu_online(rdp) || arch_spin_is_locked(&rcu_state.ofl_lock))
		ret = true;
	preempt_enable_notrace();
	return ret;
}
EXPORT_SYMBOL_GPL(rcu_lockdep_current_cpu_online);

#endif /* #if defined(CONFIG_PROVE_RCU) && defined(CONFIG_HOTPLUG_CPU) */

static void rcu_gpnum_ovf(struct rcu_node *rnp, struct rcu_data *rdp)
{
	raw_lockdep_assert_held_rcu_node(rnp);
	if (ULONG_CMP_LT(rcu_seq_current(&rdp->gp_seq) + ULONG_MAX / 4,
			 rnp->gp_seq))
		WRITE_ONCE(rdp->gpwrap, true);
	if (ULONG_CMP_LT(rdp->rcu_iw_gp_seq + ULONG_MAX / 4, rnp->gp_seq))
		rdp->rcu_iw_gp_seq = rnp->gp_seq + ULONG_MAX / 4;
}

static int dyntick_save_progress_counter(struct rcu_data *rdp)
{
	rdp->dynticks_snap = rcu_dynticks_snap(rdp->cpu);
	if (rcu_dynticks_in_eqs(rdp->dynticks_snap)) {
		trace_rcu_fqs(rcu_state.name, rdp->gp_seq, rdp->cpu, TPS("dti"));
		rcu_gpnum_ovf(rdp->mynode, rdp);
		return 1;
	}
	return 0;
}

static int rcu_implicit_dynticks_qs(struct rcu_data *rdp)
{
	unsigned long jtsq;
	struct rcu_node *rnp = rdp->mynode;

	/*
	if (rcu_dynticks_in_eqs_since(rdp, rdp->dynticks_snap)) {
		trace_rcu_fqs(rcu_state.name, rdp->gp_seq, rdp->cpu, TPS("dti"));
		rcu_gpnum_ovf(rnp, rdp);
		return 1;
	}

	/*
	if (WARN_ON_ONCE(!rcu_rdp_cpu_online(rdp))) {
		struct rcu_node *rnp1;

		pr_info("%s: grp: %d-%d level: %d ->gp_seq %ld ->completedqs %ld\n",
			__func__, rnp->grplo, rnp->grphi, rnp->level,
			(long)rnp->gp_seq, (long)rnp->completedqs);
		for (rnp1 = rnp; rnp1; rnp1 = rnp1->parent)
			pr_info("%s: %d:%d ->qsmask %#lx ->qsmaskinit %#lx ->qsmaskinitnext %#lx ->rcu_gp_init_mask %#lx\n",
				__func__, rnp1->grplo, rnp1->grphi, rnp1->qsmask, rnp1->qsmaskinit, rnp1->qsmaskinitnext, rnp1->rcu_gp_init_mask);
		pr_info("%s %d: %c online: %ld(%d) offline: %ld(%d)\n",
			__func__, rdp->cpu, ".o"[rcu_rdp_cpu_online(rdp)],
			(long)rdp->rcu_onl_gp_seq, rdp->rcu_onl_gp_flags,
			(long)rdp->rcu_ofl_gp_seq, rdp->rcu_ofl_gp_flags);
		return 1; /* Break things loose after complaining. */
	}

	/*
	jtsq = READ_ONCE(jiffies_to_sched_qs);
	if (!READ_ONCE(rdp->rcu_need_heavy_qs) &&
	    (time_after(jiffies, rcu_state.gp_start + jtsq * 2) ||
	     time_after(jiffies, rcu_state.jiffies_resched) ||
	     rcu_state.cbovld)) {
		WRITE_ONCE(rdp->rcu_need_heavy_qs, true);
		/* Store rcu_need_heavy_qs before rcu_urgent_qs. */
		smp_store_release(&rdp->rcu_urgent_qs, true);
	} else if (time_after(jiffies, rcu_state.gp_start + jtsq)) {
		WRITE_ONCE(rdp->rcu_urgent_qs, true);
	}

	/*
	if (tick_nohz_full_cpu(rdp->cpu) &&
	    (time_after(jiffies, READ_ONCE(rdp->last_fqs_resched) + jtsq * 3) ||
	     rcu_state.cbovld)) {
		WRITE_ONCE(rdp->rcu_urgent_qs, true);
		resched_cpu(rdp->cpu);
		WRITE_ONCE(rdp->last_fqs_resched, jiffies);
	}

	/*
	if (time_after(jiffies, rcu_state.jiffies_resched)) {
		if (time_after(jiffies,
			       READ_ONCE(rdp->last_fqs_resched) + jtsq)) {
			resched_cpu(rdp->cpu);
			WRITE_ONCE(rdp->last_fqs_resched, jiffies);
		}
		if (IS_ENABLED(CONFIG_IRQ_WORK) &&
		    !rdp->rcu_iw_pending && rdp->rcu_iw_gp_seq != rnp->gp_seq &&
		    (rnp->ffmask & rdp->grpmask)) {
			rdp->rcu_iw_pending = true;
			rdp->rcu_iw_gp_seq = rnp->gp_seq;
			irq_work_queue_on(&rdp->rcu_iw, rdp->cpu);
		}
	}

	return 0;
}

static void trace_rcu_this_gp(struct rcu_node *rnp, struct rcu_data *rdp,
			      unsigned long gp_seq_req, const char *s)
{
	trace_rcu_future_grace_period(rcu_state.name, READ_ONCE(rnp->gp_seq),
				      gp_seq_req, rnp->level,
				      rnp->grplo, rnp->grphi, s);
}

static bool rcu_start_this_gp(struct rcu_node *rnp_start, struct rcu_data *rdp,
			      unsigned long gp_seq_req)
{
	bool ret = false;
	struct rcu_node *rnp;

	/*
	raw_lockdep_assert_held_rcu_node(rnp_start);
	trace_rcu_this_gp(rnp_start, rdp, gp_seq_req, TPS("Startleaf"));
	for (rnp = rnp_start; 1; rnp = rnp->parent) {
		if (rnp != rnp_start)
			raw_spin_lock_rcu_node(rnp);
		if (ULONG_CMP_GE(rnp->gp_seq_needed, gp_seq_req) ||
		    rcu_seq_started(&rnp->gp_seq, gp_seq_req) ||
		    (rnp != rnp_start &&
		     rcu_seq_state(rcu_seq_current(&rnp->gp_seq)))) {
			trace_rcu_this_gp(rnp, rdp, gp_seq_req,
					  TPS("Prestarted"));
			goto unlock_out;
		}
		WRITE_ONCE(rnp->gp_seq_needed, gp_seq_req);
		if (rcu_seq_state(rcu_seq_current(&rnp->gp_seq))) {
			/*
			trace_rcu_this_gp(rnp_start, rdp, gp_seq_req,
					  TPS("Startedleaf"));
			goto unlock_out;
		}
		if (rnp != rnp_start && rnp->parent != NULL)
			raw_spin_unlock_rcu_node(rnp);
		if (!rnp->parent)
			break;  /* At root, and perhaps also leaf. */
	}

	/* If GP already in progress, just leave, otherwise start one. */
	if (rcu_gp_in_progress()) {
		trace_rcu_this_gp(rnp, rdp, gp_seq_req, TPS("Startedleafroot"));
		goto unlock_out;
	}
	trace_rcu_this_gp(rnp, rdp, gp_seq_req, TPS("Startedroot"));
	WRITE_ONCE(rcu_state.gp_flags, rcu_state.gp_flags | RCU_GP_FLAG_INIT);
	WRITE_ONCE(rcu_state.gp_req_activity, jiffies);
	if (!READ_ONCE(rcu_state.gp_kthread)) {
		trace_rcu_this_gp(rnp, rdp, gp_seq_req, TPS("NoGPkthread"));
		goto unlock_out;
	}
	trace_rcu_grace_period(rcu_state.name, data_race(rcu_state.gp_seq), TPS("newreq"));
	ret = true;  /* Caller must wake GP kthread. */
unlock_out:
	/* Push furthest requested GP to leaf node and rcu_data structure. */
	if (ULONG_CMP_LT(gp_seq_req, rnp->gp_seq_needed)) {
		WRITE_ONCE(rnp_start->gp_seq_needed, rnp->gp_seq_needed);
		WRITE_ONCE(rdp->gp_seq_needed, rnp->gp_seq_needed);
	}
	if (rnp != rnp_start)
		raw_spin_unlock_rcu_node(rnp);
	return ret;
}

static bool rcu_future_gp_cleanup(struct rcu_node *rnp)
{
	bool needmore;
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);

	needmore = ULONG_CMP_LT(rnp->gp_seq, rnp->gp_seq_needed);
	if (!needmore)
		rnp->gp_seq_needed = rnp->gp_seq; /* Avoid counter wrap. */
	trace_rcu_this_gp(rnp, rdp, rnp->gp_seq,
			  needmore ? TPS("CleanupMore") : TPS("Cleanup"));
	return needmore;
}

static void rcu_gp_kthread_wake(void)
{
	struct task_struct *t = READ_ONCE(rcu_state.gp_kthread);

	if ((current == t && !in_hardirq() && !in_serving_softirq()) ||
	    !READ_ONCE(rcu_state.gp_flags) || !t)
		return;
	WRITE_ONCE(rcu_state.gp_wake_time, jiffies);
	WRITE_ONCE(rcu_state.gp_wake_seq, READ_ONCE(rcu_state.gp_seq));
	swake_up_one(&rcu_state.gp_wq);
}

static bool rcu_accelerate_cbs(struct rcu_node *rnp, struct rcu_data *rdp)
{
	unsigned long gp_seq_req;
	bool ret = false;

	rcu_lockdep_assert_cblist_protected(rdp);
	raw_lockdep_assert_held_rcu_node(rnp);

	/* If no pending (not yet ready to invoke) callbacks, nothing to do. */
	if (!rcu_segcblist_pend_cbs(&rdp->cblist))
		return false;

	trace_rcu_segcb_stats(&rdp->cblist, TPS("SegCbPreAcc"));

	/*
	gp_seq_req = rcu_seq_snap(&rcu_state.gp_seq);
	if (rcu_segcblist_accelerate(&rdp->cblist, gp_seq_req))
		ret = rcu_start_this_gp(rnp, rdp, gp_seq_req);

	/* Trace depending on how much we were able to accelerate. */
	if (rcu_segcblist_restempty(&rdp->cblist, RCU_WAIT_TAIL))
		trace_rcu_grace_period(rcu_state.name, gp_seq_req, TPS("AccWaitCB"));
	else
		trace_rcu_grace_period(rcu_state.name, gp_seq_req, TPS("AccReadyCB"));

	trace_rcu_segcb_stats(&rdp->cblist, TPS("SegCbPostAcc"));

	return ret;
}

static void rcu_accelerate_cbs_unlocked(struct rcu_node *rnp,
					struct rcu_data *rdp)
{
	unsigned long c;
	bool needwake;

	rcu_lockdep_assert_cblist_protected(rdp);
	c = rcu_seq_snap(&rcu_state.gp_seq);
	if (!READ_ONCE(rdp->gpwrap) && ULONG_CMP_GE(rdp->gp_seq_needed, c)) {
		/* Old request still live, so mark recent callbacks. */
		(void)rcu_segcblist_accelerate(&rdp->cblist, c);
		return;
	}
	raw_spin_lock_rcu_node(rnp); /* irqs already disabled. */
	needwake = rcu_accelerate_cbs(rnp, rdp);
	raw_spin_unlock_rcu_node(rnp); /* irqs remain disabled. */
	if (needwake)
		rcu_gp_kthread_wake();
}

static bool rcu_advance_cbs(struct rcu_node *rnp, struct rcu_data *rdp)
{
	rcu_lockdep_assert_cblist_protected(rdp);
	raw_lockdep_assert_held_rcu_node(rnp);

	/* If no pending (not yet ready to invoke) callbacks, nothing to do. */
	if (!rcu_segcblist_pend_cbs(&rdp->cblist))
		return false;

	/*
	rcu_segcblist_advance(&rdp->cblist, rnp->gp_seq);

	/* Classify any remaining callbacks. */
	return rcu_accelerate_cbs(rnp, rdp);
}

static void __maybe_unused rcu_advance_cbs_nowake(struct rcu_node *rnp,
						  struct rcu_data *rdp)
{
	rcu_lockdep_assert_cblist_protected(rdp);
	if (!rcu_seq_state(rcu_seq_current(&rnp->gp_seq)) || !raw_spin_trylock_rcu_node(rnp))
		return;
	// The grace period cannot end while we hold the rcu_node lock.
	if (rcu_seq_state(rcu_seq_current(&rnp->gp_seq)))
		WARN_ON_ONCE(rcu_advance_cbs(rnp, rdp));
	raw_spin_unlock_rcu_node(rnp);
}

static void rcu_strict_gp_check_qs(void)
{
	if (IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD)) {
		rcu_read_lock();
		rcu_read_unlock();
	}
}

static bool __note_gp_changes(struct rcu_node *rnp, struct rcu_data *rdp)
{
	bool ret = false;
	bool need_qs;
	const bool offloaded = rcu_rdp_is_offloaded(rdp);

	raw_lockdep_assert_held_rcu_node(rnp);

	if (rdp->gp_seq == rnp->gp_seq)
		return false; /* Nothing to do. */

	/* Handle the ends of any preceding grace periods first. */
	if (rcu_seq_completed_gp(rdp->gp_seq, rnp->gp_seq) ||
	    unlikely(READ_ONCE(rdp->gpwrap))) {
		if (!offloaded)
			ret = rcu_advance_cbs(rnp, rdp); /* Advance CBs. */
		rdp->core_needs_qs = false;
		trace_rcu_grace_period(rcu_state.name, rdp->gp_seq, TPS("cpuend"));
	} else {
		if (!offloaded)
			ret = rcu_accelerate_cbs(rnp, rdp); /* Recent CBs. */
		if (rdp->core_needs_qs)
			rdp->core_needs_qs = !!(rnp->qsmask & rdp->grpmask);
	}

	/* Now handle the beginnings of any new-to-this-CPU grace periods. */
	if (rcu_seq_new_gp(rdp->gp_seq, rnp->gp_seq) ||
	    unlikely(READ_ONCE(rdp->gpwrap))) {
		/*
		trace_rcu_grace_period(rcu_state.name, rnp->gp_seq, TPS("cpustart"));
		need_qs = !!(rnp->qsmask & rdp->grpmask);
		rdp->cpu_no_qs.b.norm = need_qs;
		rdp->core_needs_qs = need_qs;
		zero_cpu_stall_ticks(rdp);
	}
	rdp->gp_seq = rnp->gp_seq;  /* Remember new grace-period state. */
	if (ULONG_CMP_LT(rdp->gp_seq_needed, rnp->gp_seq_needed) || rdp->gpwrap)
		WRITE_ONCE(rdp->gp_seq_needed, rnp->gp_seq_needed);
	if (IS_ENABLED(CONFIG_PROVE_RCU) && READ_ONCE(rdp->gpwrap))
		WRITE_ONCE(rdp->last_sched_clock, jiffies);
	WRITE_ONCE(rdp->gpwrap, false);
	rcu_gpnum_ovf(rnp, rdp);
	return ret;
}

static void note_gp_changes(struct rcu_data *rdp)
{
	unsigned long flags;
	bool needwake;
	struct rcu_node *rnp;

	local_irq_save(flags);
	rnp = rdp->mynode;
	if ((rdp->gp_seq == rcu_seq_current(&rnp->gp_seq) &&
	     !unlikely(READ_ONCE(rdp->gpwrap))) || /* w/out lock. */
	    !raw_spin_trylock_rcu_node(rnp)) { /* irqs already off, so later. */
		local_irq_restore(flags);
		return;
	}
	needwake = __note_gp_changes(rnp, rdp);
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	rcu_strict_gp_check_qs();
	if (needwake)
		rcu_gp_kthread_wake();
}

static atomic_t *rcu_gp_slow_suppress;

void rcu_gp_slow_register(atomic_t *rgssp)
{
	WARN_ON_ONCE(rcu_gp_slow_suppress);

	WRITE_ONCE(rcu_gp_slow_suppress, rgssp);
}
EXPORT_SYMBOL_GPL(rcu_gp_slow_register);

void rcu_gp_slow_unregister(atomic_t *rgssp)
{
	WARN_ON_ONCE(rgssp && rgssp != rcu_gp_slow_suppress);

	WRITE_ONCE(rcu_gp_slow_suppress, NULL);
}
EXPORT_SYMBOL_GPL(rcu_gp_slow_unregister);

static bool rcu_gp_slow_is_suppressed(void)
{
	atomic_t *rgssp = READ_ONCE(rcu_gp_slow_suppress);

	return rgssp && atomic_read(rgssp);
}

static void rcu_gp_slow(int delay)
{
	if (!rcu_gp_slow_is_suppressed() && delay > 0 &&
	    !(rcu_seq_ctr(rcu_state.gp_seq) % (rcu_num_nodes * PER_RCU_NODE_PERIOD * delay)))
		schedule_timeout_idle(delay);
}

static unsigned long sleep_duration;

void rcu_gp_set_torture_wait(int duration)
{
	if (IS_ENABLED(CONFIG_RCU_TORTURE_TEST) && duration > 0)
		WRITE_ONCE(sleep_duration, duration);
}
EXPORT_SYMBOL_GPL(rcu_gp_set_torture_wait);

static void rcu_gp_torture_wait(void)
{
	unsigned long duration;

	if (!IS_ENABLED(CONFIG_RCU_TORTURE_TEST))
		return;
	duration = xchg(&sleep_duration, 0UL);
	if (duration > 0) {
		pr_alert("%s: Waiting %lu jiffies\n", __func__, duration);
		schedule_timeout_idle(duration);
		pr_alert("%s: Wait complete\n", __func__);
	}
}

static void rcu_strict_gp_boundary(void *unused)
{
	invoke_rcu_core();
}

// Has rcu_init() been invoked?  This is used (for example) to determine
// whether spinlocks may be acquired safely.
static bool rcu_init_invoked(void)
{
	return !!rcu_state.n_online_cpus;
}

// Make the polled API aware of the beginning of a grace period.
static void rcu_poll_gp_seq_start(unsigned long *snap)
{
	struct rcu_node *rnp = rcu_get_root();

	if (rcu_init_invoked())
		raw_lockdep_assert_held_rcu_node(rnp);

	// If RCU was idle, note beginning of GP.
	if (!rcu_seq_state(rcu_state.gp_seq_polled))
		rcu_seq_start(&rcu_state.gp_seq_polled);

	// Either way, record current state.
}

// Make the polled API aware of the end of a grace period.
static void rcu_poll_gp_seq_end(unsigned long *snap)
{
	struct rcu_node *rnp = rcu_get_root();

	if (rcu_init_invoked())
		raw_lockdep_assert_held_rcu_node(rnp);

	// If the previously noted GP is still in effect, record the
	// end of that GP.  Either way, zero counter to avoid counter-wrap
	// problems.
	if (*snap && *snap == rcu_state.gp_seq_polled) {
		rcu_seq_end(&rcu_state.gp_seq_polled);
		rcu_state.gp_seq_polled_snap = 0;
		rcu_state.gp_seq_polled_exp_snap = 0;
	} else {
		*snap = 0;
	}
}

// Make the polled API aware of the beginning of a grace period, but
// where caller does not hold the root rcu_node structure's lock.
static void rcu_poll_gp_seq_start_unlocked(unsigned long *snap)
{
	struct rcu_node *rnp = rcu_get_root();

	if (rcu_init_invoked()) {
		lockdep_assert_irqs_enabled();
		raw_spin_lock_irq_rcu_node(rnp);
	}
	rcu_poll_gp_seq_start(snap);
	if (rcu_init_invoked())
		raw_spin_unlock_irq_rcu_node(rnp);
}

// Make the polled API aware of the end of a grace period, but where
// caller does not hold the root rcu_node structure's lock.
static void rcu_poll_gp_seq_end_unlocked(unsigned long *snap)
{
	struct rcu_node *rnp = rcu_get_root();

	if (rcu_init_invoked()) {
		lockdep_assert_irqs_enabled();
		raw_spin_lock_irq_rcu_node(rnp);
	}
	rcu_poll_gp_seq_end(snap);
	if (rcu_init_invoked())
		raw_spin_unlock_irq_rcu_node(rnp);
}

static noinline_for_stack bool rcu_gp_init(void)
{
	unsigned long flags;
	unsigned long oldmask;
	unsigned long mask;
	struct rcu_data *rdp;
	struct rcu_node *rnp = rcu_get_root();

	WRITE_ONCE(rcu_state.gp_activity, jiffies);
	raw_spin_lock_irq_rcu_node(rnp);
	if (!READ_ONCE(rcu_state.gp_flags)) {
		/* Spurious wakeup, tell caller to go back to sleep.  */
		raw_spin_unlock_irq_rcu_node(rnp);
		return false;
	}
	WRITE_ONCE(rcu_state.gp_flags, 0); /* Clear all flags: New GP. */

	if (WARN_ON_ONCE(rcu_gp_in_progress())) {
		/*
		raw_spin_unlock_irq_rcu_node(rnp);
		return false;
	}

	/* Advance to a new grace period and initialize state. */
	record_gp_stall_check_time();
	/* Record GP times before starting GP, hence rcu_seq_start(). */
	rcu_seq_start(&rcu_state.gp_seq);
	ASSERT_EXCLUSIVE_WRITER(rcu_state.gp_seq);
	trace_rcu_grace_period(rcu_state.name, rcu_state.gp_seq, TPS("start"));
	rcu_poll_gp_seq_start(&rcu_state.gp_seq_polled_snap);
	raw_spin_unlock_irq_rcu_node(rnp);

	/*
	WRITE_ONCE(rcu_state.gp_state, RCU_GP_ONOFF);
	/* Exclude CPU hotplug operations. */
	rcu_for_each_leaf_node(rnp) {
		local_irq_save(flags);
		arch_spin_lock(&rcu_state.ofl_lock);
		raw_spin_lock_rcu_node(rnp);
		if (rnp->qsmaskinit == rnp->qsmaskinitnext &&
		    !rnp->wait_blkd_tasks) {
			/* Nothing to do on this leaf rcu_node structure. */
			raw_spin_unlock_rcu_node(rnp);
			arch_spin_unlock(&rcu_state.ofl_lock);
			local_irq_restore(flags);
			continue;
		}

		/* Record old state, apply changes to ->qsmaskinit field. */
		oldmask = rnp->qsmaskinit;
		rnp->qsmaskinit = rnp->qsmaskinitnext;

		/* If zero-ness of ->qsmaskinit changed, propagate up tree. */
		if (!oldmask != !rnp->qsmaskinit) {
			if (!oldmask) { /* First online CPU for rcu_node. */
				if (!rnp->wait_blkd_tasks) /* Ever offline? */
					rcu_init_new_rnp(rnp);
			} else if (rcu_preempt_has_tasks(rnp)) {
				rnp->wait_blkd_tasks = true; /* blocked tasks */
			} else { /* Last offline CPU and can propagate. */
				rcu_cleanup_dead_rnp(rnp);
			}
		}

		/*
		if (rnp->wait_blkd_tasks &&
		    (!rcu_preempt_has_tasks(rnp) || rnp->qsmaskinit)) {
			rnp->wait_blkd_tasks = false;
			if (!rnp->qsmaskinit)
				rcu_cleanup_dead_rnp(rnp);
		}

		raw_spin_unlock_rcu_node(rnp);
		arch_spin_unlock(&rcu_state.ofl_lock);
		local_irq_restore(flags);
	}
	rcu_gp_slow(gp_preinit_delay); /* Races with CPU hotplug. */

	/*
	WRITE_ONCE(rcu_state.gp_state, RCU_GP_INIT);
	rcu_for_each_node_breadth_first(rnp) {
		rcu_gp_slow(gp_init_delay);
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		rdp = this_cpu_ptr(&rcu_data);
		rcu_preempt_check_blocked_tasks(rnp);
		rnp->qsmask = rnp->qsmaskinit;
		WRITE_ONCE(rnp->gp_seq, rcu_state.gp_seq);
		if (rnp == rdp->mynode)
			(void)__note_gp_changes(rnp, rdp);
		rcu_preempt_boost_start_gp(rnp);
		trace_rcu_grace_period_init(rcu_state.name, rnp->gp_seq,
					    rnp->level, rnp->grplo,
					    rnp->grphi, rnp->qsmask);
		/* Quiescent states for tasks on any now-offline CPUs. */
		mask = rnp->qsmask & ~rnp->qsmaskinitnext;
		rnp->rcu_gp_init_mask = mask;
		if ((mask || rnp->wait_blkd_tasks) && rcu_is_leaf_node(rnp))
			rcu_report_qs_rnp(mask, rnp, rnp->gp_seq, flags);
		else
			raw_spin_unlock_irq_rcu_node(rnp);
		cond_resched_tasks_rcu_qs();
		WRITE_ONCE(rcu_state.gp_activity, jiffies);
	}

	// If strict, make all CPUs aware of new grace period.
	if (IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD))
		on_each_cpu(rcu_strict_gp_boundary, NULL, 0);

	return true;
}

static bool rcu_gp_fqs_check_wake(int *gfp)
{
	struct rcu_node *rnp = rcu_get_root();

	// If under overload conditions, force an immediate FQS scan.
	if (*gfp & RCU_GP_FLAG_OVLD)
		return true;

	// Someone like call_rcu() requested a force-quiescent-state scan.
	if (*gfp & RCU_GP_FLAG_FQS)
		return true;

	// The current grace period has completed.
	if (!READ_ONCE(rnp->qsmask) && !rcu_preempt_blocked_readers_cgp(rnp))
		return true;

	return false;
}

static void rcu_gp_fqs(bool first_time)
{
	struct rcu_node *rnp = rcu_get_root();

	WRITE_ONCE(rcu_state.gp_activity, jiffies);
	WRITE_ONCE(rcu_state.n_force_qs, rcu_state.n_force_qs + 1);
	if (first_time) {
		/* Collect dyntick-idle snapshots. */
		force_qs_rnp(dyntick_save_progress_counter);
	} else {
		/* Handle dyntick-idle and offline CPUs. */
		force_qs_rnp(rcu_implicit_dynticks_qs);
	}
	/* Clear flag to prevent immediate re-entry. */
	if (READ_ONCE(rcu_state.gp_flags) & RCU_GP_FLAG_FQS) {
		raw_spin_lock_irq_rcu_node(rnp);
		WRITE_ONCE(rcu_state.gp_flags,
			   READ_ONCE(rcu_state.gp_flags) & ~RCU_GP_FLAG_FQS);
		raw_spin_unlock_irq_rcu_node(rnp);
	}
}

static noinline_for_stack void rcu_gp_fqs_loop(void)
{
	bool first_gp_fqs = true;
	int gf = 0;
	unsigned long j;
	int ret;
	struct rcu_node *rnp = rcu_get_root();

	j = READ_ONCE(jiffies_till_first_fqs);
	if (rcu_state.cbovld)
		gf = RCU_GP_FLAG_OVLD;
	ret = 0;
	for (;;) {
		if (rcu_state.cbovld) {
			j = (j + 2) / 3;
			if (j <= 0)
				j = 1;
		}
		if (!ret || time_before(jiffies + j, rcu_state.jiffies_force_qs)) {
			WRITE_ONCE(rcu_state.jiffies_force_qs, jiffies + j);
			/*
			smp_wmb();
			WRITE_ONCE(rcu_state.jiffies_kick_kthreads,
				   jiffies + (j ? 3 * j : 2));
		}
		trace_rcu_grace_period(rcu_state.name, rcu_state.gp_seq,
				       TPS("fqswait"));
		WRITE_ONCE(rcu_state.gp_state, RCU_GP_WAIT_FQS);
		(void)swait_event_idle_timeout_exclusive(rcu_state.gp_wq,
				 rcu_gp_fqs_check_wake(&gf), j);
		rcu_gp_torture_wait();
		WRITE_ONCE(rcu_state.gp_state, RCU_GP_DOING_FQS);
		/* Locking provides needed memory barriers. */
		/*
		if (!READ_ONCE(rnp->qsmask) &&
		    !rcu_preempt_blocked_readers_cgp(rnp))
			break;
		/* If time for quiescent-state forcing, do it. */
		if (!time_after(rcu_state.jiffies_force_qs, jiffies) ||
		    (gf & (RCU_GP_FLAG_FQS | RCU_GP_FLAG_OVLD))) {
			trace_rcu_grace_period(rcu_state.name, rcu_state.gp_seq,
					       TPS("fqsstart"));
			rcu_gp_fqs(first_gp_fqs);
			gf = 0;
			if (first_gp_fqs) {
				first_gp_fqs = false;
				gf = rcu_state.cbovld ? RCU_GP_FLAG_OVLD : 0;
			}
			trace_rcu_grace_period(rcu_state.name, rcu_state.gp_seq,
					       TPS("fqsend"));
			cond_resched_tasks_rcu_qs();
			WRITE_ONCE(rcu_state.gp_activity, jiffies);
			ret = 0; /* Force full wait till next FQS. */
			j = READ_ONCE(jiffies_till_next_fqs);
		} else {
			/* Deal with stray signal. */
			cond_resched_tasks_rcu_qs();
			WRITE_ONCE(rcu_state.gp_activity, jiffies);
			WARN_ON(signal_pending(current));
			trace_rcu_grace_period(rcu_state.name, rcu_state.gp_seq,
					       TPS("fqswaitsig"));
			ret = 1; /* Keep old FQS timing. */
			j = jiffies;
			if (time_after(jiffies, rcu_state.jiffies_force_qs))
				j = 1;
			else
				j = rcu_state.jiffies_force_qs - j;
			gf = 0;
		}
	}
}

static noinline void rcu_gp_cleanup(void)
{
	int cpu;
	bool needgp = false;
	unsigned long gp_duration;
	unsigned long new_gp_seq;
	bool offloaded;
	struct rcu_data *rdp;
	struct rcu_node *rnp = rcu_get_root();
	struct swait_queue_head *sq;

	WRITE_ONCE(rcu_state.gp_activity, jiffies);
	raw_spin_lock_irq_rcu_node(rnp);
	rcu_state.gp_end = jiffies;
	gp_duration = rcu_state.gp_end - rcu_state.gp_start;
	if (gp_duration > rcu_state.gp_max)
		rcu_state.gp_max = gp_duration;

	/*
	rcu_poll_gp_seq_end(&rcu_state.gp_seq_polled_snap);
	raw_spin_unlock_irq_rcu_node(rnp);

	/*
	new_gp_seq = rcu_state.gp_seq;
	rcu_seq_end(&new_gp_seq);
	rcu_for_each_node_breadth_first(rnp) {
		raw_spin_lock_irq_rcu_node(rnp);
		if (WARN_ON_ONCE(rcu_preempt_blocked_readers_cgp(rnp)))
			dump_blkd_tasks(rnp, 10);
		WARN_ON_ONCE(rnp->qsmask);
		WRITE_ONCE(rnp->gp_seq, new_gp_seq);
		rdp = this_cpu_ptr(&rcu_data);
		if (rnp == rdp->mynode)
			needgp = __note_gp_changes(rnp, rdp) || needgp;
		/* smp_mb() provided by prior unlock-lock pair. */
		needgp = rcu_future_gp_cleanup(rnp) || needgp;
		// Reset overload indication for CPUs no longer overloaded
		if (rcu_is_leaf_node(rnp))
			for_each_leaf_node_cpu_mask(rnp, cpu, rnp->cbovldmask) {
				rdp = per_cpu_ptr(&rcu_data, cpu);
				check_cb_ovld_locked(rdp, rnp);
			}
		sq = rcu_nocb_gp_get(rnp);
		raw_spin_unlock_irq_rcu_node(rnp);
		rcu_nocb_gp_cleanup(sq);
		cond_resched_tasks_rcu_qs();
		WRITE_ONCE(rcu_state.gp_activity, jiffies);
		rcu_gp_slow(gp_cleanup_delay);
	}
	rnp = rcu_get_root();
	raw_spin_lock_irq_rcu_node(rnp); /* GP before ->gp_seq update. */

	/* Declare grace period done, trace first to use old GP number. */
	trace_rcu_grace_period(rcu_state.name, rcu_state.gp_seq, TPS("end"));
	rcu_seq_end(&rcu_state.gp_seq);
	ASSERT_EXCLUSIVE_WRITER(rcu_state.gp_seq);
	WRITE_ONCE(rcu_state.gp_state, RCU_GP_IDLE);
	/* Check for GP requests since above loop. */
	rdp = this_cpu_ptr(&rcu_data);
	if (!needgp && ULONG_CMP_LT(rnp->gp_seq, rnp->gp_seq_needed)) {
		trace_rcu_this_gp(rnp, rdp, rnp->gp_seq_needed,
				  TPS("CleanupMore"));
		needgp = true;
	}
	/* Advance CBs to reduce false positives below. */
	offloaded = rcu_rdp_is_offloaded(rdp);
	if ((offloaded || !rcu_accelerate_cbs(rnp, rdp)) && needgp) {

		// We get here if a grace period was needed (“needgp”)
		// and the above call to rcu_accelerate_cbs() did not set
		// the RCU_GP_FLAG_INIT bit in ->gp_state (which records
		// the need for another grace period).  The purpose
		// of the “offloaded” check is to avoid invoking
		// rcu_accelerate_cbs() on an offloaded CPU because we do not
		// hold the ->nocb_lock needed to safely access an offloaded
		// ->cblist.  We do not want to acquire that lock because
		// it can be heavily contended during callback floods.

		WRITE_ONCE(rcu_state.gp_flags, RCU_GP_FLAG_INIT);
		WRITE_ONCE(rcu_state.gp_req_activity, jiffies);
		trace_rcu_grace_period(rcu_state.name, rcu_state.gp_seq, TPS("newreq"));
	} else {

		// We get here either if there is no need for an
		// additional grace period or if rcu_accelerate_cbs() has
		// already set the RCU_GP_FLAG_INIT bit in ->gp_flags. 
		// So all we need to do is to clear all of the other
		// ->gp_flags bits.

		WRITE_ONCE(rcu_state.gp_flags, rcu_state.gp_flags & RCU_GP_FLAG_INIT);
	}
	raw_spin_unlock_irq_rcu_node(rnp);

	// If strict, make all CPUs aware of the end of the old grace period.
	if (IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD))
		on_each_cpu(rcu_strict_gp_boundary, NULL, 0);
}

static int __noreturn rcu_gp_kthread(void *unused)
{
	rcu_bind_gp_kthread();
	for (;;) {

		/* Handle grace-period start. */
		for (;;) {
			trace_rcu_grace_period(rcu_state.name, rcu_state.gp_seq,
					       TPS("reqwait"));
			WRITE_ONCE(rcu_state.gp_state, RCU_GP_WAIT_GPS);
			swait_event_idle_exclusive(rcu_state.gp_wq,
					 READ_ONCE(rcu_state.gp_flags) &
					 RCU_GP_FLAG_INIT);
			rcu_gp_torture_wait();
			WRITE_ONCE(rcu_state.gp_state, RCU_GP_DONE_GPS);
			/* Locking provides needed memory barrier. */
			if (rcu_gp_init())
				break;
			cond_resched_tasks_rcu_qs();
			WRITE_ONCE(rcu_state.gp_activity, jiffies);
			WARN_ON(signal_pending(current));
			trace_rcu_grace_period(rcu_state.name, rcu_state.gp_seq,
					       TPS("reqwaitsig"));
		}

		/* Handle quiescent-state forcing. */
		rcu_gp_fqs_loop();

		/* Handle grace-period end. */
		WRITE_ONCE(rcu_state.gp_state, RCU_GP_CLEANUP);
		rcu_gp_cleanup();
		WRITE_ONCE(rcu_state.gp_state, RCU_GP_CLEANED);
	}
}

static void rcu_report_qs_rsp(unsigned long flags)
	__releases(rcu_get_root()->lock)
{
	raw_lockdep_assert_held_rcu_node(rcu_get_root());
	WARN_ON_ONCE(!rcu_gp_in_progress());
	WRITE_ONCE(rcu_state.gp_flags,
		   READ_ONCE(rcu_state.gp_flags) | RCU_GP_FLAG_FQS);
	raw_spin_unlock_irqrestore_rcu_node(rcu_get_root(), flags);
	rcu_gp_kthread_wake();
}

static void rcu_report_qs_rnp(unsigned long mask, struct rcu_node *rnp,
			      unsigned long gps, unsigned long flags)
	__releases(rnp->lock)
{
	unsigned long oldmask = 0;
	struct rcu_node *rnp_c;

	raw_lockdep_assert_held_rcu_node(rnp);

	/* Walk up the rcu_node hierarchy. */
	for (;;) {
		if ((!(rnp->qsmask & mask) && mask) || rnp->gp_seq != gps) {

			/*
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			return;
		}
		WARN_ON_ONCE(oldmask); /* Any child must be all zeroed! */
		WARN_ON_ONCE(!rcu_is_leaf_node(rnp) &&
			     rcu_preempt_blocked_readers_cgp(rnp));
		WRITE_ONCE(rnp->qsmask, rnp->qsmask & ~mask);
		trace_rcu_quiescent_state_report(rcu_state.name, rnp->gp_seq,
						 mask, rnp->qsmask, rnp->level,
						 rnp->grplo, rnp->grphi,
						 !!rnp->gp_tasks);
		if (rnp->qsmask != 0 || rcu_preempt_blocked_readers_cgp(rnp)) {

			/* Other bits still set at this level, so done. */
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			return;
		}
		rnp->completedqs = rnp->gp_seq;
		mask = rnp->grpmask;
		if (rnp->parent == NULL) {

			/* No more levels.  Exit loop holding root lock. */

			break;
		}
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		rnp_c = rnp;
		rnp = rnp->parent;
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		oldmask = READ_ONCE(rnp_c->qsmask);
	}

	/*
	rcu_report_qs_rsp(flags); /* releases rnp->lock. */
}

static void __maybe_unused
rcu_report_unblock_qs_rnp(struct rcu_node *rnp, unsigned long flags)
	__releases(rnp->lock)
{
	unsigned long gps;
	unsigned long mask;
	struct rcu_node *rnp_p;

	raw_lockdep_assert_held_rcu_node(rnp);
	if (WARN_ON_ONCE(!IS_ENABLED(CONFIG_PREEMPT_RCU)) ||
	    WARN_ON_ONCE(rcu_preempt_blocked_readers_cgp(rnp)) ||
	    rnp->qsmask != 0) {
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return;  /* Still need more quiescent states! */
	}

	rnp->completedqs = rnp->gp_seq;
	rnp_p = rnp->parent;
	if (rnp_p == NULL) {
		/*
		rcu_report_qs_rsp(flags);
		return;
	}

	/* Report up the rest of the hierarchy, tracking current ->gp_seq. */
	gps = rnp->gp_seq;
	mask = rnp->grpmask;
	raw_spin_unlock_rcu_node(rnp);	/* irqs remain disabled. */
	raw_spin_lock_rcu_node(rnp_p);	/* irqs already disabled. */
	rcu_report_qs_rnp(mask, rnp_p, gps, flags);
}

static void
rcu_report_qs_rdp(struct rcu_data *rdp)
{
	unsigned long flags;
	unsigned long mask;
	bool needwake = false;
	bool needacc = false;
	struct rcu_node *rnp;

	WARN_ON_ONCE(rdp->cpu != smp_processor_id());
	rnp = rdp->mynode;
	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	if (rdp->cpu_no_qs.b.norm || rdp->gp_seq != rnp->gp_seq ||
	    rdp->gpwrap) {

		/*
		rdp->cpu_no_qs.b.norm = true;	/* need qs for new gp. */
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return;
	}
	mask = rdp->grpmask;
	rdp->core_needs_qs = false;
	if ((rnp->qsmask & mask) == 0) {
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	} else {
		/*
		if (!rcu_rdp_is_offloaded(rdp)) {
			needwake = rcu_accelerate_cbs(rnp, rdp);
		} else if (!rcu_segcblist_completely_offloaded(&rdp->cblist)) {
			/*
			needacc = true;
		}

		rcu_disable_urgency_upon_qs(rdp);
		rcu_report_qs_rnp(mask, rnp, rnp->gp_seq, flags);
		/* ^^^ Released rnp->lock */
		if (needwake)
			rcu_gp_kthread_wake();

		if (needacc) {
			rcu_nocb_lock_irqsave(rdp, flags);
			rcu_accelerate_cbs_unlocked(rnp, rdp);
			rcu_nocb_unlock_irqrestore(rdp, flags);
		}
	}
}

static void
rcu_check_quiescent_state(struct rcu_data *rdp)
{
	/* Check for grace-period ends and beginnings. */
	note_gp_changes(rdp);

	/*
	if (!rdp->core_needs_qs)
		return;

	/*
	if (rdp->cpu_no_qs.b.norm)
		return;

	/*
	rcu_report_qs_rdp(rdp);
}

int rcutree_dying_cpu(unsigned int cpu)
{
	bool blkd;
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
	struct rcu_node *rnp = rdp->mynode;

	if (!IS_ENABLED(CONFIG_HOTPLUG_CPU))
		return 0;

	blkd = !!(rnp->qsmask & rdp->grpmask);
	trace_rcu_grace_period(rcu_state.name, READ_ONCE(rnp->gp_seq),
			       blkd ? TPS("cpuofl-bgp") : TPS("cpuofl"));
	return 0;
}

static void rcu_cleanup_dead_rnp(struct rcu_node *rnp_leaf)
{
	long mask;
	struct rcu_node *rnp = rnp_leaf;

	raw_lockdep_assert_held_rcu_node(rnp_leaf);
	if (!IS_ENABLED(CONFIG_HOTPLUG_CPU) ||
	    WARN_ON_ONCE(rnp_leaf->qsmaskinit) ||
	    WARN_ON_ONCE(rcu_preempt_has_tasks(rnp_leaf)))
		return;
	for (;;) {
		mask = rnp->grpmask;
		rnp = rnp->parent;
		if (!rnp)
			break;
		raw_spin_lock_rcu_node(rnp); /* irqs already disabled. */
		rnp->qsmaskinit &= ~mask;
		/* Between grace periods, so better already be zero! */
		WARN_ON_ONCE(rnp->qsmask);
		if (rnp->qsmaskinit) {
			raw_spin_unlock_rcu_node(rnp);
			/* irqs remain disabled. */
			return;
		}
		raw_spin_unlock_rcu_node(rnp); /* irqs remain disabled. */
	}
}

int rcutree_dead_cpu(unsigned int cpu)
{
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
	struct rcu_node *rnp = rdp->mynode;  /* Outgoing CPU's rdp & rnp. */

	if (!IS_ENABLED(CONFIG_HOTPLUG_CPU))
		return 0;

	WRITE_ONCE(rcu_state.n_online_cpus, rcu_state.n_online_cpus - 1);
	/* Adjust any no-longer-needed kthreads. */
	rcu_boost_kthread_setaffinity(rnp, -1);
	// Stop-machine done, so allow nohz_full to disable tick.
	tick_dep_clear(TICK_DEP_BIT_RCU);
	return 0;
}

static void rcu_do_batch(struct rcu_data *rdp)
{
	int div;
	bool __maybe_unused empty;
	unsigned long flags;
	struct rcu_head *rhp;
	struct rcu_cblist rcl = RCU_CBLIST_INITIALIZER(rcl);
	long bl, count = 0;
	long pending, tlimit = 0;

	/* If no callbacks are ready, just return. */
	if (!rcu_segcblist_ready_cbs(&rdp->cblist)) {
		trace_rcu_batch_start(rcu_state.name,
				      rcu_segcblist_n_cbs(&rdp->cblist), 0);
		trace_rcu_batch_end(rcu_state.name, 0,
				    !rcu_segcblist_empty(&rdp->cblist),
				    need_resched(), is_idle_task(current),
				    rcu_is_callbacks_kthread(rdp));
		return;
	}

	/*
	rcu_nocb_lock_irqsave(rdp, flags);
	WARN_ON_ONCE(cpu_is_offline(smp_processor_id()));
	pending = rcu_segcblist_n_cbs(&rdp->cblist);
	div = READ_ONCE(rcu_divisor);
	div = div < 0 ? 7 : div > sizeof(long) * 8 - 2 ? sizeof(long) * 8 - 2 : div;
	bl = max(rdp->blimit, pending >> div);
	if (in_serving_softirq() && unlikely(bl > 100)) {
		long rrn = READ_ONCE(rcu_resched_ns);

		rrn = rrn < NSEC_PER_MSEC ? NSEC_PER_MSEC : rrn > NSEC_PER_SEC ? NSEC_PER_SEC : rrn;
		tlimit = local_clock() + rrn;
	}
	trace_rcu_batch_start(rcu_state.name,
			      rcu_segcblist_n_cbs(&rdp->cblist), bl);
	rcu_segcblist_extract_done_cbs(&rdp->cblist, &rcl);
	if (rcu_rdp_is_offloaded(rdp))
		rdp->qlen_last_fqs_check = rcu_segcblist_n_cbs(&rdp->cblist);

	trace_rcu_segcb_stats(&rdp->cblist, TPS("SegCbDequeued"));
	rcu_nocb_unlock_irqrestore(rdp, flags);

	/* Invoke callbacks. */
	tick_dep_set_task(current, TICK_DEP_BIT_RCU);
	rhp = rcu_cblist_dequeue(&rcl);

	for (; rhp; rhp = rcu_cblist_dequeue(&rcl)) {
		rcu_callback_t f;

		count++;
		debug_rcu_head_unqueue(rhp);

		rcu_lock_acquire(&rcu_callback_map);
		trace_rcu_invoke_callback(rcu_state.name, rhp);

		f = rhp->func;
		WRITE_ONCE(rhp->func, (rcu_callback_t)0L);
		f(rhp);

		rcu_lock_release(&rcu_callback_map);

		/*
		if (in_serving_softirq()) {
			if (count >= bl && (need_resched() || !is_idle_task(current)))
				break;
			/*
			if (unlikely(tlimit)) {
				/* only call local_clock() every 32 callbacks */
				if (likely((count & 31) || local_clock() < tlimit))
					continue;
				/* Exceeded the time limit, so leave. */
				break;
			}
		} else {
			local_bh_enable();
			lockdep_assert_irqs_enabled();
			cond_resched_tasks_rcu_qs();
			lockdep_assert_irqs_enabled();
			local_bh_disable();
		}
	}

	rcu_nocb_lock_irqsave(rdp, flags);
	rdp->n_cbs_invoked += count;
	trace_rcu_batch_end(rcu_state.name, count, !!rcl.head, need_resched(),
			    is_idle_task(current), rcu_is_callbacks_kthread(rdp));

	/* Update counts and requeue any remaining callbacks. */
	rcu_segcblist_insert_done_cbs(&rdp->cblist, &rcl);
	rcu_segcblist_add_len(&rdp->cblist, -count);

	/* Reinstate batch limit if we have worked down the excess. */
	count = rcu_segcblist_n_cbs(&rdp->cblist);
	if (rdp->blimit >= DEFAULT_MAX_RCU_BLIMIT && count <= qlowmark)
		rdp->blimit = blimit;

	/* Reset ->qlen_last_fqs_check trigger if enough CBs have drained. */
	if (count == 0 && rdp->qlen_last_fqs_check != 0) {
		rdp->qlen_last_fqs_check = 0;
		rdp->n_force_qs_snap = READ_ONCE(rcu_state.n_force_qs);
	} else if (count < rdp->qlen_last_fqs_check - qhimark)
		rdp->qlen_last_fqs_check = count;

	/*
	empty = rcu_segcblist_empty(&rdp->cblist);
	WARN_ON_ONCE(count == 0 && !empty);
	WARN_ON_ONCE(!IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
		     count != 0 && empty);
	WARN_ON_ONCE(count == 0 && rcu_segcblist_n_segment_cbs(&rdp->cblist) != 0);
	WARN_ON_ONCE(!empty && rcu_segcblist_n_segment_cbs(&rdp->cblist) == 0);

	rcu_nocb_unlock_irqrestore(rdp, flags);

	tick_dep_clear_task(current, TICK_DEP_BIT_RCU);
}

void rcu_sched_clock_irq(int user)
{
	unsigned long j;

	if (IS_ENABLED(CONFIG_PROVE_RCU)) {
		j = jiffies;
		WARN_ON_ONCE(time_before(j, __this_cpu_read(rcu_data.last_sched_clock)));
		__this_cpu_write(rcu_data.last_sched_clock, j);
	}
	trace_rcu_utilization(TPS("Start scheduler-tick"));
	lockdep_assert_irqs_disabled();
	raw_cpu_inc(rcu_data.ticks_this_gp);
	/* The load-acquire pairs with the store-release setting to true. */
	if (smp_load_acquire(this_cpu_ptr(&rcu_data.rcu_urgent_qs))) {
		/* Idle and userspace execution already are quiescent states. */
		if (!rcu_is_cpu_rrupt_from_idle() && !user) {
			set_tsk_need_resched(current);
			set_preempt_need_resched();
		}
		__this_cpu_write(rcu_data.rcu_urgent_qs, false);
	}
	rcu_flavor_sched_clock_irq(user);
	if (rcu_pending(user))
		invoke_rcu_core();
	if (user)
		rcu_tasks_classic_qs(current, false);
	lockdep_assert_irqs_disabled();

	trace_rcu_utilization(TPS("End scheduler-tick"));
}

static void force_qs_rnp(int (*f)(struct rcu_data *rdp))
{
	int cpu;
	unsigned long flags;
	unsigned long mask;
	struct rcu_data *rdp;
	struct rcu_node *rnp;

	rcu_state.cbovld = rcu_state.cbovldnext;
	rcu_state.cbovldnext = false;
	rcu_for_each_leaf_node(rnp) {
		cond_resched_tasks_rcu_qs();
		mask = 0;
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		rcu_state.cbovldnext |= !!rnp->cbovldmask;
		if (rnp->qsmask == 0) {
			if (rcu_preempt_blocked_readers_cgp(rnp)) {
				/*
				rcu_initiate_boost(rnp, flags);
				/* rcu_initiate_boost() releases rnp->lock */
				continue;
			}
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			continue;
		}
		for_each_leaf_node_cpu_mask(rnp, cpu, rnp->qsmask) {
			rdp = per_cpu_ptr(&rcu_data, cpu);
			if (f(rdp)) {
				mask |= rdp->grpmask;
				rcu_disable_urgency_upon_qs(rdp);
			}
		}
		if (mask != 0) {
			/* Idle/offline CPUs, report (releases rnp->lock). */
			rcu_report_qs_rnp(mask, rnp, rnp->gp_seq, flags);
		} else {
			/* Nothing to do here, so just drop the lock. */
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		}
	}
}

void rcu_force_quiescent_state(void)
{
	unsigned long flags;
	bool ret;
	struct rcu_node *rnp;
	struct rcu_node *rnp_old = NULL;

	/* Funnel through hierarchy to reduce memory contention. */
	rnp = __this_cpu_read(rcu_data.mynode);
	for (; rnp != NULL; rnp = rnp->parent) {
		ret = (READ_ONCE(rcu_state.gp_flags) & RCU_GP_FLAG_FQS) ||
		       !raw_spin_trylock(&rnp->fqslock);
		if (rnp_old != NULL)
			raw_spin_unlock(&rnp_old->fqslock);
		if (ret)
			return;
		rnp_old = rnp;
	}
	/* rnp_old == rcu_get_root(), rnp == NULL. */

	/* Reached the root of the rcu_node tree, acquire lock. */
	raw_spin_lock_irqsave_rcu_node(rnp_old, flags);
	raw_spin_unlock(&rnp_old->fqslock);
	if (READ_ONCE(rcu_state.gp_flags) & RCU_GP_FLAG_FQS) {
		raw_spin_unlock_irqrestore_rcu_node(rnp_old, flags);
		return;  /* Someone beat us to it. */
	}
	WRITE_ONCE(rcu_state.gp_flags,
		   READ_ONCE(rcu_state.gp_flags) | RCU_GP_FLAG_FQS);
	raw_spin_unlock_irqrestore_rcu_node(rnp_old, flags);
	rcu_gp_kthread_wake();
}
EXPORT_SYMBOL_GPL(rcu_force_quiescent_state);

// Workqueue handler for an RCU reader for kernels enforcing struct RCU
// grace periods.
static void strict_work_handler(struct work_struct *work)
{
	rcu_read_lock();
	rcu_read_unlock();
}

static __latent_entropy void rcu_core(void)
{
	unsigned long flags;
	struct rcu_data *rdp = raw_cpu_ptr(&rcu_data);
	struct rcu_node *rnp = rdp->mynode;
	/*
	const bool do_batch = !rcu_segcblist_completely_offloaded(&rdp->cblist);

	if (cpu_is_offline(smp_processor_id()))
		return;
	trace_rcu_utilization(TPS("Start RCU core"));
	WARN_ON_ONCE(!rdp->beenonline);

	/* Report any deferred quiescent states if preemption enabled. */
	if (IS_ENABLED(CONFIG_PREEMPT_COUNT) && (!(preempt_count() & PREEMPT_MASK))) {
		rcu_preempt_deferred_qs(current);
	} else if (rcu_preempt_need_deferred_qs(current)) {
		set_tsk_need_resched(current);
		set_preempt_need_resched();
	}

	/* Update RCU state based on any recent quiescent states. */
	rcu_check_quiescent_state(rdp);

	/* No grace period and unregistered callbacks? */
	if (!rcu_gp_in_progress() &&
	    rcu_segcblist_is_enabled(&rdp->cblist) && do_batch) {
		rcu_nocb_lock_irqsave(rdp, flags);
		if (!rcu_segcblist_restempty(&rdp->cblist, RCU_NEXT_READY_TAIL))
			rcu_accelerate_cbs_unlocked(rnp, rdp);
		rcu_nocb_unlock_irqrestore(rdp, flags);
	}

	rcu_check_gp_start_stall(rnp, rdp, rcu_jiffies_till_stall_check());

	/* If there are callbacks ready, invoke them. */
	if (do_batch && rcu_segcblist_ready_cbs(&rdp->cblist) &&
	    likely(READ_ONCE(rcu_scheduler_fully_active))) {
		rcu_do_batch(rdp);
		/* Re-invoke RCU core processing if there are callbacks remaining. */
		if (rcu_segcblist_ready_cbs(&rdp->cblist))
			invoke_rcu_core();
	}

	/* Do any needed deferred wakeups of rcuo kthreads. */
	do_nocb_deferred_wakeup(rdp);
	trace_rcu_utilization(TPS("End RCU core"));

	// If strict GPs, schedule an RCU reader in a clean environment.
	if (IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD))
		queue_work_on(rdp->cpu, rcu_gp_wq, &rdp->strict_work);
}

static void rcu_core_si(struct softirq_action *h)
{
	rcu_core();
}

static void rcu_wake_cond(struct task_struct *t, int status)
{
	/*
	if (t && (status != RCU_KTHREAD_YIELDING || is_idle_task(current)))
		wake_up_process(t);
}

static void invoke_rcu_core_kthread(void)
{
	struct task_struct *t;
	unsigned long flags;

	local_irq_save(flags);
	__this_cpu_write(rcu_data.rcu_cpu_has_work, 1);
	t = __this_cpu_read(rcu_data.rcu_cpu_kthread_task);
	if (t != NULL && t != current)
		rcu_wake_cond(t, __this_cpu_read(rcu_data.rcu_cpu_kthread_status));
	local_irq_restore(flags);
}

static void invoke_rcu_core(void)
{
	if (!cpu_online(smp_processor_id()))
		return;
	if (use_softirq)
		raise_softirq(RCU_SOFTIRQ);
	else
		invoke_rcu_core_kthread();
}

static void rcu_cpu_kthread_park(unsigned int cpu)
{
	per_cpu(rcu_data.rcu_cpu_kthread_status, cpu) = RCU_KTHREAD_OFFCPU;
}

static int rcu_cpu_kthread_should_run(unsigned int cpu)
{
	return __this_cpu_read(rcu_data.rcu_cpu_has_work);
}

static void rcu_cpu_kthread(unsigned int cpu)
{
	unsigned int *statusp = this_cpu_ptr(&rcu_data.rcu_cpu_kthread_status);
	char work, *workp = this_cpu_ptr(&rcu_data.rcu_cpu_has_work);
	unsigned long *j = this_cpu_ptr(&rcu_data.rcuc_activity);
	int spincnt;

	trace_rcu_utilization(TPS("Start CPU kthread@rcu_run"));
	for (spincnt = 0; spincnt < 10; spincnt++) {
		WRITE_ONCE(*j, jiffies);
		local_bh_disable();
		*statusp = RCU_KTHREAD_RUNNING;
		local_irq_disable();
		work = *workp;
		*workp = 0;
		local_irq_enable();
		if (work)
			rcu_core();
		local_bh_enable();
		if (*workp == 0) {
			trace_rcu_utilization(TPS("End CPU kthread@rcu_wait"));
			*statusp = RCU_KTHREAD_WAITING;
			return;
		}
	}
	trace_rcu_utilization(TPS("Start CPU kthread@rcu_yield"));
	schedule_timeout_idle(2);
	trace_rcu_utilization(TPS("End CPU kthread@rcu_yield"));
	WRITE_ONCE(*j, jiffies);
}

static struct smp_hotplug_thread rcu_cpu_thread_spec = {
	.store			= &rcu_data.rcu_cpu_kthread_task,
	.thread_should_run	= rcu_cpu_kthread_should_run,
	.thread_fn		= rcu_cpu_kthread,
	.thread_comm		= "rcuc/%u",
	.setup			= rcu_cpu_kthread_setup,
	.park			= rcu_cpu_kthread_park,
};

static int __init rcu_spawn_core_kthreads(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		per_cpu(rcu_data.rcu_cpu_has_work, cpu) = 0;
	if (use_softirq)
		return 0;
	WARN_ONCE(smpboot_register_percpu_thread(&rcu_cpu_thread_spec),
		  "%s: Could not start rcuc kthread, OOM is now expected behavior\n", __func__);
	return 0;
}

static void __call_rcu_core(struct rcu_data *rdp, struct rcu_head *head,
			    unsigned long flags)
{
	/*
	if (!rcu_is_watching())
		invoke_rcu_core();

	/* If interrupts were disabled or CPU offline, don't invoke RCU core. */
	if (irqs_disabled_flags(flags) || cpu_is_offline(smp_processor_id()))
		return;

	/*
	if (unlikely(rcu_segcblist_n_cbs(&rdp->cblist) >
		     rdp->qlen_last_fqs_check + qhimark)) {

		/* Are we ignoring a completed grace period? */
		note_gp_changes(rdp);

		/* Start a new grace period if one not already started. */
		if (!rcu_gp_in_progress()) {
			rcu_accelerate_cbs_unlocked(rdp->mynode, rdp);
		} else {
			/* Give the grace period a kick. */
			rdp->blimit = DEFAULT_MAX_RCU_BLIMIT;
			if (READ_ONCE(rcu_state.n_force_qs) == rdp->n_force_qs_snap &&
			    rcu_segcblist_first_pend_cb(&rdp->cblist) != head)
				rcu_force_quiescent_state();
			rdp->n_force_qs_snap = READ_ONCE(rcu_state.n_force_qs);
			rdp->qlen_last_fqs_check = rcu_segcblist_n_cbs(&rdp->cblist);
		}
	}
}

static void rcu_leak_callback(struct rcu_head *rhp)
{
}

static void check_cb_ovld_locked(struct rcu_data *rdp, struct rcu_node *rnp)
{
	raw_lockdep_assert_held_rcu_node(rnp);
	if (qovld_calc <= 0)
		return; // Early boot and wildcard value set.
	if (rcu_segcblist_n_cbs(&rdp->cblist) >= qovld_calc)
		WRITE_ONCE(rnp->cbovldmask, rnp->cbovldmask | rdp->grpmask);
	else
		WRITE_ONCE(rnp->cbovldmask, rnp->cbovldmask & ~rdp->grpmask);
}

static void check_cb_ovld(struct rcu_data *rdp)
{
	struct rcu_node *const rnp = rdp->mynode;

	if (qovld_calc <= 0 ||
	    ((rcu_segcblist_n_cbs(&rdp->cblist) >= qovld_calc) ==
	     !!(READ_ONCE(rnp->cbovldmask) & rdp->grpmask)))
		return; // Early boot wildcard value or already set correctly.
	raw_spin_lock_rcu_node(rnp);
	check_cb_ovld_locked(rdp, rnp);
	raw_spin_unlock_rcu_node(rnp);
}

void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	static atomic_t doublefrees;
	unsigned long flags;
	struct rcu_data *rdp;
	bool was_alldone;

	/* Misaligned rcu_head! */
	WARN_ON_ONCE((unsigned long)head & (sizeof(void *) - 1));

	if (debug_rcu_head_queue(head)) {
		/*
		if (atomic_inc_return(&doublefrees) < 4) {
			pr_err("%s(): Double-freed CB %p->%pS()!!!  ", __func__, head, head->func);
			mem_dump_obj(head);
		}
		WRITE_ONCE(head->func, rcu_leak_callback);
		return;
	}
	head->func = func;
	head->next = NULL;
	kasan_record_aux_stack_noalloc(head);
	local_irq_save(flags);
	rdp = this_cpu_ptr(&rcu_data);

	/* Add the callback to our list. */
	if (unlikely(!rcu_segcblist_is_enabled(&rdp->cblist))) {
		// This can trigger due to call_rcu() from offline CPU:
		WARN_ON_ONCE(rcu_scheduler_active != RCU_SCHEDULER_INACTIVE);
		WARN_ON_ONCE(!rcu_is_watching());
		// Very early boot, before rcu_init().  Initialize if needed
		// and then drop through to queue the callback.
		if (rcu_segcblist_empty(&rdp->cblist))
			rcu_segcblist_init(&rdp->cblist);
	}

	check_cb_ovld(rdp);
	if (rcu_nocb_try_bypass(rdp, head, &was_alldone, flags))
		return; // Enqueued onto ->nocb_bypass, so just leave.
	// If no-CBs CPU gets here, rcu_nocb_try_bypass() acquired ->nocb_lock.
	rcu_segcblist_enqueue(&rdp->cblist, head);
	if (__is_kvfree_rcu_offset((unsigned long)func))
		trace_rcu_kvfree_callback(rcu_state.name, head,
					 (unsigned long)func,
					 rcu_segcblist_n_cbs(&rdp->cblist));
	else
		trace_rcu_callback(rcu_state.name, head,
				   rcu_segcblist_n_cbs(&rdp->cblist));

	trace_rcu_segcb_stats(&rdp->cblist, TPS("SegCBQueued"));

	/* Go handle any RCU core processing required. */
	if (unlikely(rcu_rdp_is_offloaded(rdp))) {
		__call_rcu_nocb_wake(rdp, was_alldone, flags); /* unlocks */
	} else {
		__call_rcu_core(rdp, head, flags);
		local_irq_restore(flags);
	}
}
EXPORT_SYMBOL_GPL(call_rcu);


#define KFREE_DRAIN_JIFFIES (HZ / 50)
#define KFREE_N_BATCHES 2
#define FREE_N_CHANNELS 2

struct kvfree_rcu_bulk_data {
	unsigned long nr_records;
	struct kvfree_rcu_bulk_data *next;
	void *records[];
};

#define KVFREE_BULK_MAX_ENTR \
	((PAGE_SIZE - sizeof(struct kvfree_rcu_bulk_data)) / sizeof(void *))


struct kfree_rcu_cpu_work {
	struct rcu_work rcu_work;
	struct rcu_head *head_free;
	struct kvfree_rcu_bulk_data *bkvhead_free[FREE_N_CHANNELS];
	struct kfree_rcu_cpu *krcp;
};

struct kfree_rcu_cpu {
	struct rcu_head *head;
	struct kvfree_rcu_bulk_data *bkvhead[FREE_N_CHANNELS];
	struct kfree_rcu_cpu_work krw_arr[KFREE_N_BATCHES];
	raw_spinlock_t lock;
	struct delayed_work monitor_work;
	bool initialized;
	int count;

	struct delayed_work page_cache_work;
	atomic_t backoff_page_cache_fill;
	atomic_t work_in_progress;
	struct hrtimer hrtimer;

	struct llist_head bkvcache;
	int nr_bkv_objs;
};

static DEFINE_PER_CPU(struct kfree_rcu_cpu, krc) = {
	.lock = __RAW_SPIN_LOCK_UNLOCKED(krc.lock),
};

static __always_inline void
debug_rcu_bhead_unqueue(struct kvfree_rcu_bulk_data *bhead)
{
#ifdef CONFIG_DEBUG_OBJECTS_RCU_HEAD
	int i;

	for (i = 0; i < bhead->nr_records; i++)
		debug_rcu_head_unqueue((struct rcu_head *)(bhead->records[i]));
#endif
}

static inline struct kfree_rcu_cpu *
krc_this_cpu_lock(unsigned long *flags)
{
	struct kfree_rcu_cpu *krcp;

	local_irq_save(*flags);	// For safely calling this_cpu_ptr().
	krcp = this_cpu_ptr(&krc);
	raw_spin_lock(&krcp->lock);

	return krcp;
}

static inline void
krc_this_cpu_unlock(struct kfree_rcu_cpu *krcp, unsigned long flags)
{
	raw_spin_unlock_irqrestore(&krcp->lock, flags);
}

static inline struct kvfree_rcu_bulk_data *
get_cached_bnode(struct kfree_rcu_cpu *krcp)
{
	if (!krcp->nr_bkv_objs)
		return NULL;

	WRITE_ONCE(krcp->nr_bkv_objs, krcp->nr_bkv_objs - 1);
	return (struct kvfree_rcu_bulk_data *)
		llist_del_first(&krcp->bkvcache);
}

static inline bool
put_cached_bnode(struct kfree_rcu_cpu *krcp,
	struct kvfree_rcu_bulk_data *bnode)
{
	// Check the limit.
	if (krcp->nr_bkv_objs >= rcu_min_cached_objs)
		return false;

	llist_add((struct llist_node *) bnode, &krcp->bkvcache);
	WRITE_ONCE(krcp->nr_bkv_objs, krcp->nr_bkv_objs + 1);
	return true;
}

static int
drain_page_cache(struct kfree_rcu_cpu *krcp)
{
	unsigned long flags;
	struct llist_node *page_list, *pos, *n;
	int freed = 0;

	raw_spin_lock_irqsave(&krcp->lock, flags);
	page_list = llist_del_all(&krcp->bkvcache);
	WRITE_ONCE(krcp->nr_bkv_objs, 0);
	raw_spin_unlock_irqrestore(&krcp->lock, flags);

	llist_for_each_safe(pos, n, page_list) {
		free_page((unsigned long)pos);
		freed++;
	}

	return freed;
}

static void kfree_rcu_work(struct work_struct *work)
{
	unsigned long flags;
	struct kvfree_rcu_bulk_data *bkvhead[FREE_N_CHANNELS], *bnext;
	struct rcu_head *head, *next;
	struct kfree_rcu_cpu *krcp;
	struct kfree_rcu_cpu_work *krwp;
	int i, j;

	krwp = container_of(to_rcu_work(work),
			    struct kfree_rcu_cpu_work, rcu_work);
	krcp = krwp->krcp;

	raw_spin_lock_irqsave(&krcp->lock, flags);
	// Channels 1 and 2.
	for (i = 0; i < FREE_N_CHANNELS; i++) {
		bkvhead[i] = krwp->bkvhead_free[i];
		krwp->bkvhead_free[i] = NULL;
	}

	// Channel 3.
	head = krwp->head_free;
	krwp->head_free = NULL;
	raw_spin_unlock_irqrestore(&krcp->lock, flags);

	// Handle the first two channels.
	for (i = 0; i < FREE_N_CHANNELS; i++) {
		for (; bkvhead[i]; bkvhead[i] = bnext) {
			bnext = bkvhead[i]->next;
			debug_rcu_bhead_unqueue(bkvhead[i]);

			rcu_lock_acquire(&rcu_callback_map);
			if (i == 0) { // kmalloc() / kfree().
				trace_rcu_invoke_kfree_bulk_callback(
					rcu_state.name, bkvhead[i]->nr_records,
					bkvhead[i]->records);

				kfree_bulk(bkvhead[i]->nr_records,
					bkvhead[i]->records);
			} else { // vmalloc() / vfree().
				for (j = 0; j < bkvhead[i]->nr_records; j++) {
					trace_rcu_invoke_kvfree_callback(
						rcu_state.name,
						bkvhead[i]->records[j], 0);

					vfree(bkvhead[i]->records[j]);
				}
			}
			rcu_lock_release(&rcu_callback_map);

			raw_spin_lock_irqsave(&krcp->lock, flags);
			if (put_cached_bnode(krcp, bkvhead[i]))
				bkvhead[i] = NULL;
			raw_spin_unlock_irqrestore(&krcp->lock, flags);

			if (bkvhead[i])
				free_page((unsigned long) bkvhead[i]);

			cond_resched_tasks_rcu_qs();
		}
	}

	/*
	for (; head; head = next) {
		unsigned long offset = (unsigned long)head->func;
		void *ptr = (void *)head - offset;

		next = head->next;
		debug_rcu_head_unqueue((struct rcu_head *)ptr);
		rcu_lock_acquire(&rcu_callback_map);
		trace_rcu_invoke_kvfree_callback(rcu_state.name, head, offset);

		if (!WARN_ON_ONCE(!__is_kvfree_rcu_offset(offset)))
			kvfree(ptr);

		rcu_lock_release(&rcu_callback_map);
		cond_resched_tasks_rcu_qs();
	}
}

static bool
need_offload_krc(struct kfree_rcu_cpu *krcp)
{
	int i;

	for (i = 0; i < FREE_N_CHANNELS; i++)
		if (krcp->bkvhead[i])
			return true;

	return !!krcp->head;
}

static void kfree_rcu_monitor(struct work_struct *work)
{
	struct kfree_rcu_cpu *krcp = container_of(work,
		struct kfree_rcu_cpu, monitor_work.work);
	unsigned long flags;
	int i, j;

	raw_spin_lock_irqsave(&krcp->lock, flags);

	// Attempt to start a new batch.
	for (i = 0; i < KFREE_N_BATCHES; i++) {
		struct kfree_rcu_cpu_work *krwp = &(krcp->krw_arr[i]);

		// Try to detach bkvhead or head and attach it over any
		// available corresponding free channel. It can be that
		// a previous RCU batch is in progress, it means that
		// immediately to queue another one is not possible so
		// in that case the monitor work is rearmed.
		if ((krcp->bkvhead[0] && !krwp->bkvhead_free[0]) ||
			(krcp->bkvhead[1] && !krwp->bkvhead_free[1]) ||
				(krcp->head && !krwp->head_free)) {
			// Channel 1 corresponds to the SLAB-pointer bulk path.
			// Channel 2 corresponds to vmalloc-pointer bulk path.
			for (j = 0; j < FREE_N_CHANNELS; j++) {
				if (!krwp->bkvhead_free[j]) {
					krwp->bkvhead_free[j] = krcp->bkvhead[j];
					krcp->bkvhead[j] = NULL;
				}
			}

			// Channel 3 corresponds to both SLAB and vmalloc
			// objects queued on the linked list.
			if (!krwp->head_free) {
				krwp->head_free = krcp->head;
				krcp->head = NULL;
			}

			WRITE_ONCE(krcp->count, 0);

			// One work is per one batch, so there are three
			// "free channels", the batch can handle. It can
			// be that the work is in the pending state when
			// channels have been detached following by each
			// other.
			queue_rcu_work(system_wq, &krwp->rcu_work);
		}
	}

	// If there is nothing to detach, it means that our job is
	// successfully done here. In case of having at least one
	// of the channels that is still busy we should rearm the
	// work to repeat an attempt. Because previous batches are
	// still in progress.
	if (need_offload_krc(krcp))
		schedule_delayed_work(&krcp->monitor_work, KFREE_DRAIN_JIFFIES);

	raw_spin_unlock_irqrestore(&krcp->lock, flags);
}

static enum hrtimer_restart
schedule_page_work_fn(struct hrtimer *t)
{
	struct kfree_rcu_cpu *krcp =
		container_of(t, struct kfree_rcu_cpu, hrtimer);

	queue_delayed_work(system_highpri_wq, &krcp->page_cache_work, 0);
	return HRTIMER_NORESTART;
}

static void fill_page_cache_func(struct work_struct *work)
{
	struct kvfree_rcu_bulk_data *bnode;
	struct kfree_rcu_cpu *krcp =
		container_of(work, struct kfree_rcu_cpu,
			page_cache_work.work);
	unsigned long flags;
	int nr_pages;
	bool pushed;
	int i;

	nr_pages = atomic_read(&krcp->backoff_page_cache_fill) ?
		1 : rcu_min_cached_objs;

	for (i = 0; i < nr_pages; i++) {
		bnode = (struct kvfree_rcu_bulk_data *)
			__get_free_page(GFP_KERNEL | __GFP_NORETRY | __GFP_NOMEMALLOC | __GFP_NOWARN);

		if (bnode) {
			raw_spin_lock_irqsave(&krcp->lock, flags);
			pushed = put_cached_bnode(krcp, bnode);
			raw_spin_unlock_irqrestore(&krcp->lock, flags);

			if (!pushed) {
				free_page((unsigned long) bnode);
				break;
			}
		}
	}

	atomic_set(&krcp->work_in_progress, 0);
	atomic_set(&krcp->backoff_page_cache_fill, 0);
}

static void
run_page_cache_worker(struct kfree_rcu_cpu *krcp)
{
	if (rcu_scheduler_active == RCU_SCHEDULER_RUNNING &&
			!atomic_xchg(&krcp->work_in_progress, 1)) {
		if (atomic_read(&krcp->backoff_page_cache_fill)) {
			queue_delayed_work(system_wq,
				&krcp->page_cache_work,
					msecs_to_jiffies(rcu_delay_page_cache_fill_msec));
		} else {
			hrtimer_init(&krcp->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
			krcp->hrtimer.function = schedule_page_work_fn;
			hrtimer_start(&krcp->hrtimer, 0, HRTIMER_MODE_REL);
		}
	}
}

// Record ptr in a page managed by krcp, with the pre-krc_this_cpu_lock()
// state specified by flags.  If can_alloc is true, the caller must
// be schedulable and not be holding any locks or mutexes that might be
// acquired by the memory allocator or anything that it might invoke.
// Returns true if ptr was successfully recorded, else the caller must
// use a fallback.
static inline bool
add_ptr_to_bulk_krc_lock(struct kfree_rcu_cpu **krcp,
	unsigned long *flags, void *ptr, bool can_alloc)
{
	struct kvfree_rcu_bulk_data *bnode;
	int idx;

	if (unlikely(!(*krcp)->initialized))
		return false;

	idx = !!is_vmalloc_addr(ptr);

	/* Check if a new block is required. */
	if (!(*krcp)->bkvhead[idx] ||
			(*krcp)->bkvhead[idx]->nr_records == KVFREE_BULK_MAX_ENTR) {
		bnode = get_cached_bnode(*krcp);
		if (!bnode && can_alloc) {
			krc_this_cpu_unlock(*krcp, *flags);

			// __GFP_NORETRY - allows a light-weight direct reclaim
			// what is OK from minimizing of fallback hitting point of
			// view. Apart of that it forbids any OOM invoking what is
			// also beneficial since we are about to release memory soon.
			//
			// __GFP_NOMEMALLOC - prevents from consuming of all the
			// memory reserves. Please note we have a fallback path.
			//
			// __GFP_NOWARN - it is supposed that an allocation can
			// be failed under low memory or high memory pressure
			// scenarios.
			bnode = (struct kvfree_rcu_bulk_data *)
				__get_free_page(GFP_KERNEL | __GFP_NORETRY | __GFP_NOMEMALLOC | __GFP_NOWARN);
			*krcp = krc_this_cpu_lock(flags);
		}

		if (!bnode)
			return false;

		/* Initialize the new block. */
		bnode->nr_records = 0;
		bnode->next = (*krcp)->bkvhead[idx];

		/* Attach it to the head. */
		(*krcp)->bkvhead[idx] = bnode;
	}

	/* Finally insert. */
	(*krcp)->bkvhead[idx]->records
		[(*krcp)->bkvhead[idx]->nr_records++] = ptr;

	return true;
}

void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	unsigned long flags;
	struct kfree_rcu_cpu *krcp;
	bool success;
	void *ptr;

	if (head) {
		ptr = (void *) head - (unsigned long) func;
	} else {
		/*
		might_sleep();
		ptr = (unsigned long *) func;
	}

	// Queue the object but don't yet schedule the batch.
	if (debug_rcu_head_queue(ptr)) {
		// Probable double kfree_rcu(), just leak.
		WARN_ONCE(1, "%s(): Double-freed call. rcu_head %p\n",
			  __func__, head);

		// Mark as success and leave.
		return;
	}

	kasan_record_aux_stack_noalloc(ptr);
	success = add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
	if (!success) {
		run_page_cache_worker(krcp);

		if (head == NULL)
			// Inline if kvfree_rcu(one_arg) call.
			goto unlock_return;

		head->func = func;
		head->next = krcp->head;
		krcp->head = head;
		success = true;
	}

	WRITE_ONCE(krcp->count, krcp->count + 1);

	// Set timer to drain after KFREE_DRAIN_JIFFIES.
	if (rcu_scheduler_active == RCU_SCHEDULER_RUNNING)
		schedule_delayed_work(&krcp->monitor_work, KFREE_DRAIN_JIFFIES);

unlock_return:
	krc_this_cpu_unlock(krcp, flags);

	/*
	if (!success) {
		debug_rcu_head_unqueue((struct rcu_head *) ptr);
		synchronize_rcu();
		kvfree(ptr);
	}
}
EXPORT_SYMBOL_GPL(kvfree_call_rcu);

static unsigned long
kfree_rcu_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	int cpu;
	unsigned long count = 0;

	/* Snapshot count of all CPUs */
	for_each_possible_cpu(cpu) {
		struct kfree_rcu_cpu *krcp = per_cpu_ptr(&krc, cpu);

		count += READ_ONCE(krcp->count);
		count += READ_ONCE(krcp->nr_bkv_objs);
		atomic_set(&krcp->backoff_page_cache_fill, 1);
	}

	return count;
}

static unsigned long
kfree_rcu_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	int cpu, freed = 0;

	for_each_possible_cpu(cpu) {
		int count;
		struct kfree_rcu_cpu *krcp = per_cpu_ptr(&krc, cpu);

		count = krcp->count;
		count += drain_page_cache(krcp);
		kfree_rcu_monitor(&krcp->monitor_work.work);

		sc->nr_to_scan -= count;
		freed += count;

		if (sc->nr_to_scan <= 0)
			break;
	}

	return freed == 0 ? SHRINK_STOP : freed;
}

static struct shrinker kfree_rcu_shrinker = {
	.count_objects = kfree_rcu_shrink_count,
	.scan_objects = kfree_rcu_shrink_scan,
	.batch = 0,
	.seeks = DEFAULT_SEEKS,
};

void __init kfree_rcu_scheduler_running(void)
{
	int cpu;
	unsigned long flags;

	for_each_possible_cpu(cpu) {
		struct kfree_rcu_cpu *krcp = per_cpu_ptr(&krc, cpu);

		raw_spin_lock_irqsave(&krcp->lock, flags);
		if (need_offload_krc(krcp))
			schedule_delayed_work_on(cpu, &krcp->monitor_work, KFREE_DRAIN_JIFFIES);
		raw_spin_unlock_irqrestore(&krcp->lock, flags);
	}
}

static int rcu_blocking_is_gp(void)
{
	int ret;

	// Invoking preempt_model_*() too early gets a splat.
	if (rcu_scheduler_active == RCU_SCHEDULER_INACTIVE ||
	    preempt_model_full() || preempt_model_rt())
		return rcu_scheduler_active == RCU_SCHEDULER_INACTIVE;
	might_sleep();  /* Check for RCU read-side critical section. */
	preempt_disable();
	/*
	ret = READ_ONCE(rcu_state.n_online_cpus) <= 1;
	preempt_enable();
	return ret;
}

void synchronize_rcu(void)
{
	RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map) ||
			 lock_is_held(&rcu_lock_map) ||
			 lock_is_held(&rcu_sched_lock_map),
			 "Illegal synchronize_rcu() in RCU read-side critical section");
	if (rcu_blocking_is_gp()) {
		// Note well that this code runs with !PREEMPT && !SMP.
		// In addition, all code that advances grace periods runs at
		// process level.  Therefore, this normal GP overlaps with
		// other normal GPs only by being fully nested within them,
		// which allows reuse of ->gp_seq_polled_snap.
		rcu_poll_gp_seq_start_unlocked(&rcu_state.gp_seq_polled_snap);
		rcu_poll_gp_seq_end_unlocked(&rcu_state.gp_seq_polled_snap);
		if (rcu_init_invoked())
			cond_resched_tasks_rcu_qs();
		return;  // Context allows vacuous grace periods.
	}
	if (rcu_gp_is_expedited())
		synchronize_rcu_expedited();
	else
		wait_rcu_gp(call_rcu);
}
EXPORT_SYMBOL_GPL(synchronize_rcu);

unsigned long get_state_synchronize_rcu(void)
{
	/*
	smp_mb();  /* ^^^ */
	return rcu_seq_snap(&rcu_state.gp_seq_polled);
}
EXPORT_SYMBOL_GPL(get_state_synchronize_rcu);

unsigned long start_poll_synchronize_rcu(void)
{
	unsigned long flags;
	unsigned long gp_seq = get_state_synchronize_rcu();
	bool needwake;
	struct rcu_data *rdp;
	struct rcu_node *rnp;

	lockdep_assert_irqs_enabled();
	local_irq_save(flags);
	rdp = this_cpu_ptr(&rcu_data);
	rnp = rdp->mynode;
	raw_spin_lock_rcu_node(rnp); // irqs already disabled.
	// Note it is possible for a grace period to have elapsed between
	// the above call to get_state_synchronize_rcu() and the below call
	// to rcu_seq_snap.  This is OK, the worst that happens is that we
	// get a grace period that no one needed.  These accesses are ordered
	// by smp_mb(), and we are accessing them in the opposite order
	// from which they are updated at grace-period start, as required.
	needwake = rcu_start_this_gp(rnp, rdp, rcu_seq_snap(&rcu_state.gp_seq));
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	if (needwake)
		rcu_gp_kthread_wake();
	return gp_seq;
}
EXPORT_SYMBOL_GPL(start_poll_synchronize_rcu);

bool poll_state_synchronize_rcu(unsigned long oldstate)
{
	if (oldstate == RCU_GET_STATE_COMPLETED ||
	    rcu_seq_done_exact(&rcu_state.gp_seq_polled, oldstate)) {
		smp_mb(); /* Ensure GP ends before subsequent accesses. */
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);

void cond_synchronize_rcu(unsigned long oldstate)
{
	if (!poll_state_synchronize_rcu(oldstate))
		synchronize_rcu();
}
EXPORT_SYMBOL_GPL(cond_synchronize_rcu);

static int rcu_pending(int user)
{
	bool gp_in_progress;
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
	struct rcu_node *rnp = rdp->mynode;

	lockdep_assert_irqs_disabled();

	/* Check for CPU stalls, if enabled. */
	check_cpu_stall(rdp);

	/* Does this CPU need a deferred NOCB wakeup? */
	if (rcu_nocb_need_deferred_wakeup(rdp, RCU_NOCB_WAKE))
		return 1;

	/* Is this a nohz_full CPU in userspace or idle?  (Ignore RCU if so.) */
	if ((user || rcu_is_cpu_rrupt_from_idle()) && rcu_nohz_full_cpu())
		return 0;

	/* Is the RCU core waiting for a quiescent state from this CPU? */
	gp_in_progress = rcu_gp_in_progress();
	if (rdp->core_needs_qs && !rdp->cpu_no_qs.b.norm && gp_in_progress)
		return 1;

	/* Does this CPU have callbacks ready to invoke? */
	if (!rcu_rdp_is_offloaded(rdp) &&
	    rcu_segcblist_ready_cbs(&rdp->cblist))
		return 1;

	/* Has RCU gone idle with this CPU needing another grace period? */
	if (!gp_in_progress && rcu_segcblist_is_enabled(&rdp->cblist) &&
	    !rcu_rdp_is_offloaded(rdp) &&
	    !rcu_segcblist_restempty(&rdp->cblist, RCU_NEXT_READY_TAIL))
		return 1;

	/* Have RCU grace period completed or started?  */
	if (rcu_seq_current(&rnp->gp_seq) != rdp->gp_seq ||
	    unlikely(READ_ONCE(rdp->gpwrap))) /* outside lock */
		return 1;

	/* nothing to do */
	return 0;
}

static void rcu_barrier_trace(const char *s, int cpu, unsigned long done)
{
	trace_rcu_barrier(rcu_state.name, s, cpu,
			  atomic_read(&rcu_state.barrier_cpu_count), done);
}

static void rcu_barrier_callback(struct rcu_head *rhp)
{
	unsigned long __maybe_unused s = rcu_state.barrier_sequence;

	if (atomic_dec_and_test(&rcu_state.barrier_cpu_count)) {
		rcu_barrier_trace(TPS("LastCB"), -1, s);
		complete(&rcu_state.barrier_completion);
	} else {
		rcu_barrier_trace(TPS("CB"), -1, s);
	}
}

static void rcu_barrier_entrain(struct rcu_data *rdp)
{
	unsigned long gseq = READ_ONCE(rcu_state.barrier_sequence);
	unsigned long lseq = READ_ONCE(rdp->barrier_seq_snap);

	lockdep_assert_held(&rcu_state.barrier_lock);
	if (rcu_seq_state(lseq) || !rcu_seq_state(gseq) || rcu_seq_ctr(lseq) != rcu_seq_ctr(gseq))
		return;
	rcu_barrier_trace(TPS("IRQ"), -1, rcu_state.barrier_sequence);
	rdp->barrier_head.func = rcu_barrier_callback;
	debug_rcu_head_queue(&rdp->barrier_head);
	rcu_nocb_lock(rdp);
	WARN_ON_ONCE(!rcu_nocb_flush_bypass(rdp, NULL, jiffies));
	if (rcu_segcblist_entrain(&rdp->cblist, &rdp->barrier_head)) {
		atomic_inc(&rcu_state.barrier_cpu_count);
	} else {
		debug_rcu_head_unqueue(&rdp->barrier_head);
		rcu_barrier_trace(TPS("IRQNQ"), -1, rcu_state.barrier_sequence);
	}
	rcu_nocb_unlock(rdp);
	smp_store_release(&rdp->barrier_seq_snap, gseq);
}

static void rcu_barrier_handler(void *cpu_in)
{
	uintptr_t cpu = (uintptr_t)cpu_in;
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);

	lockdep_assert_irqs_disabled();
	WARN_ON_ONCE(cpu != rdp->cpu);
	WARN_ON_ONCE(cpu != smp_processor_id());
	raw_spin_lock(&rcu_state.barrier_lock);
	rcu_barrier_entrain(rdp);
	raw_spin_unlock(&rcu_state.barrier_lock);
}

void rcu_barrier(void)
{
	uintptr_t cpu;
	unsigned long flags;
	unsigned long gseq;
	struct rcu_data *rdp;
	unsigned long s = rcu_seq_snap(&rcu_state.barrier_sequence);

	rcu_barrier_trace(TPS("Begin"), -1, s);

	/* Take mutex to serialize concurrent rcu_barrier() requests. */
	mutex_lock(&rcu_state.barrier_mutex);

	/* Did someone else do our work for us? */
	if (rcu_seq_done(&rcu_state.barrier_sequence, s)) {
		rcu_barrier_trace(TPS("EarlyExit"), -1, rcu_state.barrier_sequence);
		smp_mb(); /* caller's subsequent code after above check. */
		mutex_unlock(&rcu_state.barrier_mutex);
		return;
	}

	/* Mark the start of the barrier operation. */
	raw_spin_lock_irqsave(&rcu_state.barrier_lock, flags);
	rcu_seq_start(&rcu_state.barrier_sequence);
	gseq = rcu_state.barrier_sequence;
	rcu_barrier_trace(TPS("Inc1"), -1, rcu_state.barrier_sequence);

	/*
	init_completion(&rcu_state.barrier_completion);
	atomic_set(&rcu_state.barrier_cpu_count, 2);
	raw_spin_unlock_irqrestore(&rcu_state.barrier_lock, flags);

	/*
	for_each_possible_cpu(cpu) {
		rdp = per_cpu_ptr(&rcu_data, cpu);
retry:
		if (smp_load_acquire(&rdp->barrier_seq_snap) == gseq)
			continue;
		raw_spin_lock_irqsave(&rcu_state.barrier_lock, flags);
		if (!rcu_segcblist_n_cbs(&rdp->cblist)) {
			WRITE_ONCE(rdp->barrier_seq_snap, gseq);
			raw_spin_unlock_irqrestore(&rcu_state.barrier_lock, flags);
			rcu_barrier_trace(TPS("NQ"), cpu, rcu_state.barrier_sequence);
			continue;
		}
		if (!rcu_rdp_cpu_online(rdp)) {
			rcu_barrier_entrain(rdp);
			WARN_ON_ONCE(READ_ONCE(rdp->barrier_seq_snap) != gseq);
			raw_spin_unlock_irqrestore(&rcu_state.barrier_lock, flags);
			rcu_barrier_trace(TPS("OfflineNoCBQ"), cpu, rcu_state.barrier_sequence);
			continue;
		}
		raw_spin_unlock_irqrestore(&rcu_state.barrier_lock, flags);
		if (smp_call_function_single(cpu, rcu_barrier_handler, (void *)cpu, 1)) {
			schedule_timeout_uninterruptible(1);
			goto retry;
		}
		WARN_ON_ONCE(READ_ONCE(rdp->barrier_seq_snap) != gseq);
		rcu_barrier_trace(TPS("OnlineQ"), cpu, rcu_state.barrier_sequence);
	}

	/*
	if (atomic_sub_and_test(2, &rcu_state.barrier_cpu_count))
		complete(&rcu_state.barrier_completion);

	/* Wait for all rcu_barrier_callback() callbacks to be invoked. */
	wait_for_completion(&rcu_state.barrier_completion);

	/* Mark the end of the barrier operation. */
	rcu_barrier_trace(TPS("Inc2"), -1, rcu_state.barrier_sequence);
	rcu_seq_end(&rcu_state.barrier_sequence);
	gseq = rcu_state.barrier_sequence;
	for_each_possible_cpu(cpu) {
		rdp = per_cpu_ptr(&rcu_data, cpu);

		WRITE_ONCE(rdp->barrier_seq_snap, gseq);
	}

	/* Other rcu_barrier() invocations can now safely proceed. */
	mutex_unlock(&rcu_state.barrier_mutex);
}
EXPORT_SYMBOL_GPL(rcu_barrier);

static void rcu_init_new_rnp(struct rcu_node *rnp_leaf)
{
	long mask;
	long oldmask;
	struct rcu_node *rnp = rnp_leaf;

	raw_lockdep_assert_held_rcu_node(rnp_leaf);
	WARN_ON_ONCE(rnp->wait_blkd_tasks);
	for (;;) {
		mask = rnp->grpmask;
		rnp = rnp->parent;
		if (rnp == NULL)
			return;
		raw_spin_lock_rcu_node(rnp); /* Interrupts already disabled. */
		oldmask = rnp->qsmaskinit;
		rnp->qsmaskinit |= mask;
		raw_spin_unlock_rcu_node(rnp); /* Interrupts remain disabled. */
		if (oldmask)
			return;
	}
}

static void __init
rcu_boot_init_percpu_data(int cpu)
{
	struct context_tracking *ct = this_cpu_ptr(&context_tracking);
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);

	/* Set up local state, ensuring consistent view of global state. */
	rdp->grpmask = leaf_node_cpu_bit(rdp->mynode, cpu);
	INIT_WORK(&rdp->strict_work, strict_work_handler);
	WARN_ON_ONCE(ct->dynticks_nesting != 1);
	WARN_ON_ONCE(rcu_dynticks_in_eqs(rcu_dynticks_snap(cpu)));
	rdp->barrier_seq_snap = rcu_state.barrier_sequence;
	rdp->rcu_ofl_gp_seq = rcu_state.gp_seq;
	rdp->rcu_ofl_gp_flags = RCU_GP_CLEANED;
	rdp->rcu_onl_gp_seq = rcu_state.gp_seq;
	rdp->rcu_onl_gp_flags = RCU_GP_CLEANED;
	rdp->last_sched_clock = jiffies;
	rdp->cpu = cpu;
	rcu_boot_init_nocb_percpu_data(rdp);
}

int rcutree_prepare_cpu(unsigned int cpu)
{
	unsigned long flags;
	struct context_tracking *ct = per_cpu_ptr(&context_tracking, cpu);
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
	struct rcu_node *rnp = rcu_get_root();

	/* Set up local state, ensuring consistent view of global state. */
	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	rdp->qlen_last_fqs_check = 0;
	rdp->n_force_qs_snap = READ_ONCE(rcu_state.n_force_qs);
	rdp->blimit = blimit;
	ct->dynticks_nesting = 1;	/* CPU not up, no tearing. */
	raw_spin_unlock_rcu_node(rnp);		/* irqs remain disabled. */

	/*
	if (!rcu_segcblist_is_enabled(&rdp->cblist))
		rcu_segcblist_init(&rdp->cblist);  /* Re-enable callbacks. */

	/*
	rnp = rdp->mynode;
	raw_spin_lock_rcu_node(rnp);		/* irqs already disabled. */
	rdp->beenonline = true;	 /* We have now been online. */
	rdp->gp_seq = READ_ONCE(rnp->gp_seq);
	rdp->gp_seq_needed = rdp->gp_seq;
	rdp->cpu_no_qs.b.norm = true;
	rdp->core_needs_qs = false;
	rdp->rcu_iw_pending = false;
	rdp->rcu_iw = IRQ_WORK_INIT_HARD(rcu_iw_handler);
	rdp->rcu_iw_gp_seq = rdp->gp_seq - 1;
	trace_rcu_grace_period(rcu_state.name, rdp->gp_seq, TPS("cpuonl"));
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	rcu_spawn_one_boost_kthread(rnp);
	rcu_spawn_cpu_nocb_kthread(cpu);
	WRITE_ONCE(rcu_state.n_online_cpus, rcu_state.n_online_cpus + 1);

	return 0;
}

static void rcutree_affinity_setting(unsigned int cpu, int outgoing)
{
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);

	rcu_boost_kthread_setaffinity(rdp->mynode, outgoing);
}

int rcutree_online_cpu(unsigned int cpu)
{
	unsigned long flags;
	struct rcu_data *rdp;
	struct rcu_node *rnp;

	rdp = per_cpu_ptr(&rcu_data, cpu);
	rnp = rdp->mynode;
	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	rnp->ffmask |= rdp->grpmask;
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	if (rcu_scheduler_active == RCU_SCHEDULER_INACTIVE)
		return 0; /* Too early in boot for scheduler work. */
	sync_sched_exp_online_cleanup(cpu);
	rcutree_affinity_setting(cpu, -1);

	// Stop-machine done, so allow nohz_full to disable tick.
	tick_dep_clear(TICK_DEP_BIT_RCU);
	return 0;
}

int rcutree_offline_cpu(unsigned int cpu)
{
	unsigned long flags;
	struct rcu_data *rdp;
	struct rcu_node *rnp;

	rdp = per_cpu_ptr(&rcu_data, cpu);
	rnp = rdp->mynode;
	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	rnp->ffmask &= ~rdp->grpmask;
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);

	rcutree_affinity_setting(cpu, cpu);

	// nohz_full CPUs need the tick for stop-machine to work quickly
	tick_dep_set(TICK_DEP_BIT_RCU);
	return 0;
}

void rcu_cpu_starting(unsigned int cpu)
{
	unsigned long flags;
	unsigned long mask;
	struct rcu_data *rdp;
	struct rcu_node *rnp;
	bool newcpu;

	rdp = per_cpu_ptr(&rcu_data, cpu);
	if (rdp->cpu_started)
		return;
	rdp->cpu_started = true;

	rnp = rdp->mynode;
	mask = rdp->grpmask;
	local_irq_save(flags);
	arch_spin_lock(&rcu_state.ofl_lock);
	rcu_dynticks_eqs_online();
	raw_spin_lock(&rcu_state.barrier_lock);
	raw_spin_lock_rcu_node(rnp);
	WRITE_ONCE(rnp->qsmaskinitnext, rnp->qsmaskinitnext | mask);
	raw_spin_unlock(&rcu_state.barrier_lock);
	newcpu = !(rnp->expmaskinitnext & mask);
	rnp->expmaskinitnext |= mask;
	/* Allow lockless access for expedited grace periods. */
	smp_store_release(&rcu_state.ncpus, rcu_state.ncpus + newcpu); /* ^^^ */
	ASSERT_EXCLUSIVE_WRITER(rcu_state.ncpus);
	rcu_gpnum_ovf(rnp, rdp); /* Offline-induced counter wrap? */
	rdp->rcu_onl_gp_seq = READ_ONCE(rcu_state.gp_seq);
	rdp->rcu_onl_gp_flags = READ_ONCE(rcu_state.gp_flags);

	/* An incoming CPU should never be blocking a grace period. */
	if (WARN_ON_ONCE(rnp->qsmask & mask)) { /* RCU waiting on incoming CPU? */
		/* rcu_report_qs_rnp() *really* wants some flags to restore */
		unsigned long flags2;

		local_irq_save(flags2);
		rcu_disable_urgency_upon_qs(rdp);
		/* Report QS -after- changing ->qsmaskinitnext! */
		rcu_report_qs_rnp(mask, rnp, rnp->gp_seq, flags2);
	} else {
		raw_spin_unlock_rcu_node(rnp);
	}
	arch_spin_unlock(&rcu_state.ofl_lock);
	local_irq_restore(flags);
	smp_mb(); /* Ensure RCU read-side usage follows above initialization. */
}

void rcu_report_dead(unsigned int cpu)
{
	unsigned long flags, seq_flags;
	unsigned long mask;
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
	struct rcu_node *rnp = rdp->mynode;  /* Outgoing CPU's rdp & rnp. */

	// Do any dangling deferred wakeups.
	do_nocb_deferred_wakeup(rdp);

	/* QS for any half-done expedited grace period. */
	rcu_report_exp_rdp(rdp);
	rcu_preempt_deferred_qs(current);

	/* Remove outgoing CPU from mask in the leaf rcu_node structure. */
	mask = rdp->grpmask;
	local_irq_save(seq_flags);
	arch_spin_lock(&rcu_state.ofl_lock);
	raw_spin_lock_irqsave_rcu_node(rnp, flags); /* Enforce GP memory-order guarantee. */
	rdp->rcu_ofl_gp_seq = READ_ONCE(rcu_state.gp_seq);
	rdp->rcu_ofl_gp_flags = READ_ONCE(rcu_state.gp_flags);
	if (rnp->qsmask & mask) { /* RCU waiting on outgoing CPU? */
		/* Report quiescent state -before- changing ->qsmaskinitnext! */
		rcu_disable_urgency_upon_qs(rdp);
		rcu_report_qs_rnp(mask, rnp, rnp->gp_seq, flags);
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
	}
	WRITE_ONCE(rnp->qsmaskinitnext, rnp->qsmaskinitnext & ~mask);
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	arch_spin_unlock(&rcu_state.ofl_lock);
	local_irq_restore(seq_flags);

	rdp->cpu_started = false;
}

#ifdef CONFIG_HOTPLUG_CPU
void rcutree_migrate_callbacks(int cpu)
{
	unsigned long flags;
	struct rcu_data *my_rdp;
	struct rcu_node *my_rnp;
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
	bool needwake;

	if (rcu_rdp_is_offloaded(rdp) ||
	    rcu_segcblist_empty(&rdp->cblist))
		return;  /* No callbacks to migrate. */

	raw_spin_lock_irqsave(&rcu_state.barrier_lock, flags);
	WARN_ON_ONCE(rcu_rdp_cpu_online(rdp));
	rcu_barrier_entrain(rdp);
	my_rdp = this_cpu_ptr(&rcu_data);
	my_rnp = my_rdp->mynode;
	rcu_nocb_lock(my_rdp); /* irqs already disabled. */
	WARN_ON_ONCE(!rcu_nocb_flush_bypass(my_rdp, NULL, jiffies));
	raw_spin_lock_rcu_node(my_rnp); /* irqs already disabled. */
	/* Leverage recent GPs and set GP for new callbacks. */
	needwake = rcu_advance_cbs(my_rnp, rdp) ||
		   rcu_advance_cbs(my_rnp, my_rdp);
	rcu_segcblist_merge(&my_rdp->cblist, &rdp->cblist);
	raw_spin_unlock(&rcu_state.barrier_lock); /* irqs remain disabled. */
	needwake = needwake || rcu_advance_cbs(my_rnp, my_rdp);
	rcu_segcblist_disable(&rdp->cblist);
	WARN_ON_ONCE(rcu_segcblist_empty(&my_rdp->cblist) != !rcu_segcblist_n_cbs(&my_rdp->cblist));
	check_cb_ovld_locked(my_rdp, my_rnp);
	if (rcu_rdp_is_offloaded(my_rdp)) {
		raw_spin_unlock_rcu_node(my_rnp); /* irqs remain disabled. */
		__call_rcu_nocb_wake(my_rdp, true, flags);
	} else {
		rcu_nocb_unlock(my_rdp); /* irqs remain disabled. */
		raw_spin_unlock_irqrestore_rcu_node(my_rnp, flags);
	}
	if (needwake)
		rcu_gp_kthread_wake();
	lockdep_assert_irqs_enabled();
	WARN_ONCE(rcu_segcblist_n_cbs(&rdp->cblist) != 0 ||
		  !rcu_segcblist_empty(&rdp->cblist),
		  "rcu_cleanup_dead_cpu: Callbacks on offline CPU %d: qlen=%lu, 1stCB=%p\n",
		  cpu, rcu_segcblist_n_cbs(&rdp->cblist),
		  rcu_segcblist_first_cb(&rdp->cblist));
}
#endif

static int rcu_pm_notify(struct notifier_block *self,
			 unsigned long action, void *hcpu)
{
	switch (action) {
	case PM_HIBERNATION_PREPARE:
	case PM_SUSPEND_PREPARE:
		rcu_expedite_gp();
		break;
	case PM_POST_HIBERNATION:
	case PM_POST_SUSPEND:
		rcu_unexpedite_gp();
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

#ifdef CONFIG_RCU_EXP_KTHREAD
struct kthread_worker *rcu_exp_gp_kworker;
struct kthread_worker *rcu_exp_par_gp_kworker;

static void __init rcu_start_exp_gp_kworkers(void)
{
	const char *par_gp_kworker_name = "rcu_exp_par_gp_kthread_worker";
	const char *gp_kworker_name = "rcu_exp_gp_kthread_worker";
	struct sched_param param = { .sched_priority = kthread_prio };

	rcu_exp_gp_kworker = kthread_create_worker(0, gp_kworker_name);
	if (IS_ERR_OR_NULL(rcu_exp_gp_kworker)) {
		pr_err("Failed to create %s!\n", gp_kworker_name);
		return;
	}

	rcu_exp_par_gp_kworker = kthread_create_worker(0, par_gp_kworker_name);
	if (IS_ERR_OR_NULL(rcu_exp_par_gp_kworker)) {
		pr_err("Failed to create %s!\n", par_gp_kworker_name);
		kthread_destroy_worker(rcu_exp_gp_kworker);
		return;
	}

	sched_setscheduler_nocheck(rcu_exp_gp_kworker->task, SCHED_FIFO, &param);
	sched_setscheduler_nocheck(rcu_exp_par_gp_kworker->task, SCHED_FIFO,
				   &param);
}

static inline void rcu_alloc_par_gp_wq(void)
{
}
#else /* !CONFIG_RCU_EXP_KTHREAD */
struct workqueue_struct *rcu_par_gp_wq;

static void __init rcu_start_exp_gp_kworkers(void)
{
}

static inline void rcu_alloc_par_gp_wq(void)
{
	rcu_par_gp_wq = alloc_workqueue("rcu_par_gp", WQ_MEM_RECLAIM, 0);
	WARN_ON(!rcu_par_gp_wq);
}
#endif /* CONFIG_RCU_EXP_KTHREAD */

static int __init rcu_spawn_gp_kthread(void)
{
	unsigned long flags;
	struct rcu_node *rnp;
	struct sched_param sp;
	struct task_struct *t;
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);

	rcu_scheduler_fully_active = 1;
	t = kthread_create(rcu_gp_kthread, NULL, "%s", rcu_state.name);
	if (WARN_ONCE(IS_ERR(t), "%s: Could not start grace-period kthread, OOM is now expected behavior\n", __func__))
		return 0;
	if (kthread_prio) {
		sp.sched_priority = kthread_prio;
		sched_setscheduler_nocheck(t, SCHED_FIFO, &sp);
	}
	rnp = rcu_get_root();
	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	WRITE_ONCE(rcu_state.gp_activity, jiffies);
	WRITE_ONCE(rcu_state.gp_req_activity, jiffies);
	// Reset .gp_activity and .gp_req_activity before setting .gp_kthread.
	smp_store_release(&rcu_state.gp_kthread, t);  /* ^^^ */
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	wake_up_process(t);
	/* This is a pre-SMP initcall, we expect a single CPU */
	WARN_ON(num_online_cpus() > 1);
	/*
	rcu_spawn_cpu_nocb_kthread(smp_processor_id());
	rcu_spawn_one_boost_kthread(rdp->mynode);
	rcu_spawn_core_kthreads();
	/* Create kthread worker for expedited GPs */
	rcu_start_exp_gp_kworkers();
	return 0;
}
early_initcall(rcu_spawn_gp_kthread);

void rcu_scheduler_starting(void)
{
	WARN_ON(num_online_cpus() != 1);
	WARN_ON(nr_context_switches() > 0);
	rcu_test_sync_prims();
	rcu_scheduler_active = RCU_SCHEDULER_INIT;
	rcu_test_sync_prims();
}

static void __init rcu_init_one(void)
{
	static const char * const buf[] = RCU_NODE_NAME_INIT;
	static const char * const fqs[] = RCU_FQS_NAME_INIT;
	static struct lock_class_key rcu_node_class[RCU_NUM_LVLS];
	static struct lock_class_key rcu_fqs_class[RCU_NUM_LVLS];

	int levelspread[RCU_NUM_LVLS];		/* kids/node in each level. */
	int cpustride = 1;
	int i;
	int j;
	struct rcu_node *rnp;

	BUILD_BUG_ON(RCU_NUM_LVLS > ARRAY_SIZE(buf));  /* Fix buf[] init! */

	/* Silence gcc 4.8 false positive about array index out of range. */
	if (rcu_num_lvls <= 0 || rcu_num_lvls > RCU_NUM_LVLS)
		panic("rcu_init_one: rcu_num_lvls out of range");

	/* Initialize the level-tracking arrays. */

	for (i = 1; i < rcu_num_lvls; i++)
		rcu_state.level[i] =
			rcu_state.level[i - 1] + num_rcu_lvl[i - 1];
	rcu_init_levelspread(levelspread, num_rcu_lvl);

	/* Initialize the elements themselves, starting from the leaves. */

	for (i = rcu_num_lvls - 1; i >= 0; i--) {
		cpustride *= levelspread[i];
		rnp = rcu_state.level[i];
		for (j = 0; j < num_rcu_lvl[i]; j++, rnp++) {
			raw_spin_lock_init(&ACCESS_PRIVATE(rnp, lock));
			lockdep_set_class_and_name(&ACCESS_PRIVATE(rnp, lock),
						   &rcu_node_class[i], buf[i]);
			raw_spin_lock_init(&rnp->fqslock);
			lockdep_set_class_and_name(&rnp->fqslock,
						   &rcu_fqs_class[i], fqs[i]);
			rnp->gp_seq = rcu_state.gp_seq;
			rnp->gp_seq_needed = rcu_state.gp_seq;
			rnp->completedqs = rcu_state.gp_seq;
			rnp->qsmask = 0;
			rnp->qsmaskinit = 0;
			rnp->grplo = j * cpustride;
			rnp->grphi = (j + 1) * cpustride - 1;
			if (rnp->grphi >= nr_cpu_ids)
				rnp->grphi = nr_cpu_ids - 1;
			if (i == 0) {
				rnp->grpnum = 0;
				rnp->grpmask = 0;
				rnp->parent = NULL;
			} else {
				rnp->grpnum = j % levelspread[i - 1];
				rnp->grpmask = BIT(rnp->grpnum);
				rnp->parent = rcu_state.level[i - 1] +
					      j / levelspread[i - 1];
			}
			rnp->level = i;
			INIT_LIST_HEAD(&rnp->blkd_tasks);
			rcu_init_one_nocb(rnp);
			init_waitqueue_head(&rnp->exp_wq[0]);
			init_waitqueue_head(&rnp->exp_wq[1]);
			init_waitqueue_head(&rnp->exp_wq[2]);
			init_waitqueue_head(&rnp->exp_wq[3]);
			spin_lock_init(&rnp->exp_lock);
			mutex_init(&rnp->boost_kthread_mutex);
			raw_spin_lock_init(&rnp->exp_poll_lock);
			rnp->exp_seq_poll_rq = RCU_GET_STATE_COMPLETED;
			INIT_WORK(&rnp->exp_poll_wq, sync_rcu_do_polled_gp);
		}
	}

	init_swait_queue_head(&rcu_state.gp_wq);
	init_swait_queue_head(&rcu_state.expedited_wq);
	rnp = rcu_first_leaf_node();
	for_each_possible_cpu(i) {
		while (i > rnp->grphi)
			rnp++;
		per_cpu_ptr(&rcu_data, i)->mynode = rnp;
		rcu_boot_init_percpu_data(i);
	}
}

static void __init sanitize_kthread_prio(void)
{
	int kthread_prio_in = kthread_prio;

	if (IS_ENABLED(CONFIG_RCU_BOOST) && kthread_prio < 2
	    && IS_BUILTIN(CONFIG_RCU_TORTURE_TEST))
		kthread_prio = 2;
	else if (IS_ENABLED(CONFIG_RCU_BOOST) && kthread_prio < 1)
		kthread_prio = 1;
	else if (kthread_prio < 0)
		kthread_prio = 0;
	else if (kthread_prio > 99)
		kthread_prio = 99;

	if (kthread_prio != kthread_prio_in)
		pr_alert("%s: Limited prio to %d from %d\n",
			 __func__, kthread_prio, kthread_prio_in);
}

void rcu_init_geometry(void)
{
	ulong d;
	int i;
	static unsigned long old_nr_cpu_ids;
	int rcu_capacity[RCU_NUM_LVLS];
	static bool initialized;

	if (initialized) {
		/*
		WARN_ON_ONCE(old_nr_cpu_ids != nr_cpu_ids);
		return;
	}

	old_nr_cpu_ids = nr_cpu_ids;
	initialized = true;

	/*
	d = RCU_JIFFIES_TILL_FORCE_QS + nr_cpu_ids / RCU_JIFFIES_FQS_DIV;
	if (jiffies_till_first_fqs == ULONG_MAX)
		jiffies_till_first_fqs = d;
	if (jiffies_till_next_fqs == ULONG_MAX)
		jiffies_till_next_fqs = d;
	adjust_jiffies_till_sched_qs();

	/* If the compile-time values are accurate, just leave. */
	if (rcu_fanout_leaf == RCU_FANOUT_LEAF &&
	    nr_cpu_ids == NR_CPUS)
		return;
	pr_info("Adjusting geometry for rcu_fanout_leaf=%d, nr_cpu_ids=%u\n",
		rcu_fanout_leaf, nr_cpu_ids);

	/*
	if (rcu_fanout_leaf < 2 ||
	    rcu_fanout_leaf > sizeof(unsigned long) * 8) {
		rcu_fanout_leaf = RCU_FANOUT_LEAF;
		WARN_ON(1);
		return;
	}

	/*
	rcu_capacity[0] = rcu_fanout_leaf;
	for (i = 1; i < RCU_NUM_LVLS; i++)
		rcu_capacity[i] = rcu_capacity[i - 1] * RCU_FANOUT;

	/*
	if (nr_cpu_ids > rcu_capacity[RCU_NUM_LVLS - 1]) {
		rcu_fanout_leaf = RCU_FANOUT_LEAF;
		WARN_ON(1);
		return;
	}

	/* Calculate the number of levels in the tree. */
	for (i = 0; nr_cpu_ids > rcu_capacity[i]; i++) {
	}
	rcu_num_lvls = i + 1;

	/* Calculate the number of rcu_nodes at each level of the tree. */
	for (i = 0; i < rcu_num_lvls; i++) {
		int cap = rcu_capacity[(rcu_num_lvls - 1) - i];
		num_rcu_lvl[i] = DIV_ROUND_UP(nr_cpu_ids, cap);
	}

	/* Calculate the total number of rcu_node structures. */
	rcu_num_nodes = 0;
	for (i = 0; i < rcu_num_lvls; i++)
		rcu_num_nodes += num_rcu_lvl[i];
}

static void __init rcu_dump_rcu_node_tree(void)
{
	int level = 0;
	struct rcu_node *rnp;

	pr_info("rcu_node tree layout dump\n");
	pr_info(" ");
	rcu_for_each_node_breadth_first(rnp) {
		if (rnp->level != level) {
			pr_cont("\n");
			pr_info(" ");
			level = rnp->level;
		}
		pr_cont("%d:%d ^%d  ", rnp->grplo, rnp->grphi, rnp->grpnum);
	}
	pr_cont("\n");
}

struct workqueue_struct *rcu_gp_wq;

static void __init kfree_rcu_batch_init(void)
{
	int cpu;
	int i;

	/* Clamp it to [0:100] seconds interval. */
	if (rcu_delay_page_cache_fill_msec < 0 ||
		rcu_delay_page_cache_fill_msec > 100 * MSEC_PER_SEC) {

		rcu_delay_page_cache_fill_msec =
			clamp(rcu_delay_page_cache_fill_msec, 0,
				(int) (100 * MSEC_PER_SEC));

		pr_info("Adjusting rcutree.rcu_delay_page_cache_fill_msec to %d ms.\n",
			rcu_delay_page_cache_fill_msec);
	}

	for_each_possible_cpu(cpu) {
		struct kfree_rcu_cpu *krcp = per_cpu_ptr(&krc, cpu);

		for (i = 0; i < KFREE_N_BATCHES; i++) {
			INIT_RCU_WORK(&krcp->krw_arr[i].rcu_work, kfree_rcu_work);
			krcp->krw_arr[i].krcp = krcp;
		}

		INIT_DELAYED_WORK(&krcp->monitor_work, kfree_rcu_monitor);
		INIT_DELAYED_WORK(&krcp->page_cache_work, fill_page_cache_func);
		krcp->initialized = true;
	}
	if (register_shrinker(&kfree_rcu_shrinker, "rcu-kfree"))
		pr_err("Failed to register kfree_rcu() shrinker!\n");
}

void __init rcu_init(void)
{
	int cpu = smp_processor_id();

	rcu_early_boot_tests();

	kfree_rcu_batch_init();
	rcu_bootup_announce();
	sanitize_kthread_prio();
	rcu_init_geometry();
	rcu_init_one();
	if (dump_tree)
		rcu_dump_rcu_node_tree();
	if (use_softirq)
		open_softirq(RCU_SOFTIRQ, rcu_core_si);

	/*
	pm_notifier(rcu_pm_notify, 0);
	WARN_ON(num_online_cpus() > 1); // Only one CPU this early in boot.
	rcutree_prepare_cpu(cpu);
	rcu_cpu_starting(cpu);
	rcutree_online_cpu(cpu);

	/* Create workqueue for Tree SRCU and for expedited GPs. */
	rcu_gp_wq = alloc_workqueue("rcu_gp", WQ_MEM_RECLAIM, 0);
	WARN_ON(!rcu_gp_wq);
	rcu_alloc_par_gp_wq();

	/* Fill in default value for rcutree.qovld boot parameter. */
	/* -After- the rcu_node ->lock fields are initialized! */
	if (qovld < 0)
		qovld_calc = DEFAULT_RCU_QOVLD_MULT * qhimark;
	else
		qovld_calc = qovld;

	// Kick-start any polled grace periods that started early.
	if (!(per_cpu_ptr(&rcu_data, cpu)->mynode->exp_seq_poll_rq & 0x1))
		(void)start_poll_synchronize_rcu_expedited();
}

#include "tree_stall.h"
#include "tree_exp.h"
#include "tree_nocb.h"
#include "tree_plugin.h"
