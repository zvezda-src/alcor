#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/sched/signal.h>
#include <linux/sched/debug.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/mutex.h>
#include <linux/export.h>
#include <linux/hardirq.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/tick.h>
#include <linux/rcupdate_wait.h>
#include <linux/sched/isolation.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/irq_work.h>
#include <linux/rcupdate_trace.h>

#define CREATE_TRACE_POINTS

#include "rcu.h"

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "rcupdate."

#ifndef CONFIG_TINY_RCU
module_param(rcu_expedited, int, 0444);
module_param(rcu_normal, int, 0444);
static int rcu_normal_after_boot = IS_ENABLED(CONFIG_PREEMPT_RT);
#if !defined(CONFIG_PREEMPT_RT) || defined(CONFIG_NO_HZ_FULL)
module_param(rcu_normal_after_boot, int, 0444);
#endif
#endif /* #ifndef CONFIG_TINY_RCU */

#ifdef CONFIG_DEBUG_LOCK_ALLOC
static bool rcu_read_lock_held_common(bool *ret)
{
	if (!debug_lockdep_rcu_enabled()) {
		*ret = true;
		return true;
	}
	if (!rcu_is_watching()) {
		*ret = false;
		return true;
	}
	if (!rcu_lockdep_current_cpu_online()) {
		*ret = false;
		return true;
	}
	return false;
}

int rcu_read_lock_sched_held(void)
{
	bool ret;

	if (rcu_read_lock_held_common(&ret))
		return ret;
	return lock_is_held(&rcu_sched_lock_map) || !preemptible();
}
EXPORT_SYMBOL(rcu_read_lock_sched_held);
#endif

#ifndef CONFIG_TINY_RCU

bool rcu_gp_is_normal(void)
{
	return READ_ONCE(rcu_normal) &&
	       rcu_scheduler_active != RCU_SCHEDULER_INIT;
}
EXPORT_SYMBOL_GPL(rcu_gp_is_normal);

static atomic_t rcu_expedited_nesting = ATOMIC_INIT(1);

bool rcu_gp_is_expedited(void)
{
	return rcu_expedited || atomic_read(&rcu_expedited_nesting);
}
EXPORT_SYMBOL_GPL(rcu_gp_is_expedited);

void rcu_expedite_gp(void)
{
	atomic_inc(&rcu_expedited_nesting);
}
EXPORT_SYMBOL_GPL(rcu_expedite_gp);

void rcu_unexpedite_gp(void)
{
	atomic_dec(&rcu_expedited_nesting);
}
EXPORT_SYMBOL_GPL(rcu_unexpedite_gp);

static bool rcu_boot_ended __read_mostly;

void rcu_end_inkernel_boot(void)
{
	rcu_unexpedite_gp();
	if (rcu_normal_after_boot)
		WRITE_ONCE(rcu_normal, 1);
	rcu_boot_ended = true;
}

bool rcu_inkernel_boot_has_ended(void)
{
	return rcu_boot_ended;
}
EXPORT_SYMBOL_GPL(rcu_inkernel_boot_has_ended);

#endif /* #ifndef CONFIG_TINY_RCU */

void rcu_test_sync_prims(void)
{
	if (!IS_ENABLED(CONFIG_PROVE_RCU))
		return;
	synchronize_rcu();
	synchronize_rcu_expedited();
}

#if !defined(CONFIG_TINY_RCU) || defined(CONFIG_SRCU)

static int __init rcu_set_runtime_mode(void)
{
	rcu_test_sync_prims();
	rcu_scheduler_active = RCU_SCHEDULER_RUNNING;
	kfree_rcu_scheduler_running();
	rcu_test_sync_prims();
	return 0;
}
core_initcall(rcu_set_runtime_mode);

#endif /* #if !defined(CONFIG_TINY_RCU) || defined(CONFIG_SRCU) */

#ifdef CONFIG_DEBUG_LOCK_ALLOC
static struct lock_class_key rcu_lock_key;
struct lockdep_map rcu_lock_map = {
	.name = "rcu_read_lock",
	.key = &rcu_lock_key,
	.wait_type_outer = LD_WAIT_FREE,
	.wait_type_inner = LD_WAIT_CONFIG, /* PREEMPT_RT implies PREEMPT_RCU */
};
EXPORT_SYMBOL_GPL(rcu_lock_map);

static struct lock_class_key rcu_bh_lock_key;
struct lockdep_map rcu_bh_lock_map = {
	.name = "rcu_read_lock_bh",
	.key = &rcu_bh_lock_key,
	.wait_type_outer = LD_WAIT_FREE,
	.wait_type_inner = LD_WAIT_CONFIG, /* PREEMPT_RT makes BH preemptible. */
};
EXPORT_SYMBOL_GPL(rcu_bh_lock_map);

static struct lock_class_key rcu_sched_lock_key;
struct lockdep_map rcu_sched_lock_map = {
	.name = "rcu_read_lock_sched",
	.key = &rcu_sched_lock_key,
	.wait_type_outer = LD_WAIT_FREE,
	.wait_type_inner = LD_WAIT_SPIN,
};
EXPORT_SYMBOL_GPL(rcu_sched_lock_map);

// Tell lockdep when RCU callbacks are being invoked.
static struct lock_class_key rcu_callback_key;
struct lockdep_map rcu_callback_map =
	STATIC_LOCKDEP_MAP_INIT("rcu_callback", &rcu_callback_key);
EXPORT_SYMBOL_GPL(rcu_callback_map);

noinstr int notrace debug_lockdep_rcu_enabled(void)
{
	return rcu_scheduler_active != RCU_SCHEDULER_INACTIVE && READ_ONCE(debug_locks) &&
	       current->lockdep_recursion == 0;
}
EXPORT_SYMBOL_GPL(debug_lockdep_rcu_enabled);

int rcu_read_lock_held(void)
{
	bool ret;

	if (rcu_read_lock_held_common(&ret))
		return ret;
	return lock_is_held(&rcu_lock_map);
}
EXPORT_SYMBOL_GPL(rcu_read_lock_held);

int rcu_read_lock_bh_held(void)
{
	bool ret;

	if (rcu_read_lock_held_common(&ret))
		return ret;
	return in_softirq() || irqs_disabled();
}
EXPORT_SYMBOL_GPL(rcu_read_lock_bh_held);

int rcu_read_lock_any_held(void)
{
	bool ret;

	if (rcu_read_lock_held_common(&ret))
		return ret;
	if (lock_is_held(&rcu_lock_map) ||
	    lock_is_held(&rcu_bh_lock_map) ||
	    lock_is_held(&rcu_sched_lock_map))
		return 1;
	return !preemptible();
}
EXPORT_SYMBOL_GPL(rcu_read_lock_any_held);

#endif /* #ifdef CONFIG_DEBUG_LOCK_ALLOC */

void wakeme_after_rcu(struct rcu_head *head)
{
	struct rcu_synchronize *rcu;

	rcu = container_of(head, struct rcu_synchronize, head);
	complete(&rcu->completion);
}
EXPORT_SYMBOL_GPL(wakeme_after_rcu);

void __wait_rcu_gp(bool checktiny, int n, call_rcu_func_t *crcu_array,
		   struct rcu_synchronize *rs_array)
{
	int i;
	int j;

	/* Initialize and register callbacks for each crcu_array element. */
	for (i = 0; i < n; i++) {
		if (checktiny &&
		    (crcu_array[i] == call_rcu)) {
			might_sleep();
			continue;
		}
		for (j = 0; j < i; j++)
			if (crcu_array[j] == crcu_array[i])
				break;
		if (j == i) {
			init_rcu_head_on_stack(&rs_array[i].head);
			init_completion(&rs_array[i].completion);
			(crcu_array[i])(&rs_array[i].head, wakeme_after_rcu);
		}
	}

	/* Wait for all callbacks to be invoked. */
	for (i = 0; i < n; i++) {
		if (checktiny &&
		    (crcu_array[i] == call_rcu))
			continue;
		for (j = 0; j < i; j++)
			if (crcu_array[j] == crcu_array[i])
				break;
		if (j == i) {
			wait_for_completion(&rs_array[i].completion);
			destroy_rcu_head_on_stack(&rs_array[i].head);
		}
	}
}
EXPORT_SYMBOL_GPL(__wait_rcu_gp);

void finish_rcuwait(struct rcuwait *w)
{
	rcu_assign_pointer(w->task, NULL);
	__set_current_state(TASK_RUNNING);
}
EXPORT_SYMBOL_GPL(finish_rcuwait);

#ifdef CONFIG_DEBUG_OBJECTS_RCU_HEAD
void init_rcu_head(struct rcu_head *head)
{
	debug_object_init(head, &rcuhead_debug_descr);
}
EXPORT_SYMBOL_GPL(init_rcu_head);

void destroy_rcu_head(struct rcu_head *head)
{
	debug_object_free(head, &rcuhead_debug_descr);
}
EXPORT_SYMBOL_GPL(destroy_rcu_head);

static bool rcuhead_is_static_object(void *addr)
{
	return true;
}

void init_rcu_head_on_stack(struct rcu_head *head)
{
	debug_object_init_on_stack(head, &rcuhead_debug_descr);
}
EXPORT_SYMBOL_GPL(init_rcu_head_on_stack);

void destroy_rcu_head_on_stack(struct rcu_head *head)
{
	debug_object_free(head, &rcuhead_debug_descr);
}
EXPORT_SYMBOL_GPL(destroy_rcu_head_on_stack);

const struct debug_obj_descr rcuhead_debug_descr = {
	.name = "rcu_head",
	.is_static_object = rcuhead_is_static_object,
};
EXPORT_SYMBOL_GPL(rcuhead_debug_descr);
#endif /* #ifdef CONFIG_DEBUG_OBJECTS_RCU_HEAD */

#if defined(CONFIG_TREE_RCU) || defined(CONFIG_RCU_TRACE)
void do_trace_rcu_torture_read(const char *rcutorturename, struct rcu_head *rhp,
			       unsigned long secs,
			       unsigned long c_old, unsigned long c)
{
	trace_rcu_torture_read(rcutorturename, rhp, secs, c_old, c);
}
EXPORT_SYMBOL_GPL(do_trace_rcu_torture_read);
#else
#define do_trace_rcu_torture_read(rcutorturename, rhp, secs, c_old, c) \
	do { } while (0)
#endif

#if IS_ENABLED(CONFIG_RCU_TORTURE_TEST) || IS_MODULE(CONFIG_RCU_TORTURE_TEST)
long rcutorture_sched_setaffinity(pid_t pid, const struct cpumask *in_mask)
{
	int ret;

	ret = sched_setaffinity(pid, in_mask);
	WARN_ONCE(ret, "%s: sched_setaffinity() returned %d\n", __func__, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(rcutorture_sched_setaffinity);
#endif

#ifdef CONFIG_RCU_STALL_COMMON
int rcu_cpu_stall_ftrace_dump __read_mostly;
module_param(rcu_cpu_stall_ftrace_dump, int, 0644);
int rcu_cpu_stall_suppress __read_mostly; // !0 = suppress stall warnings.
EXPORT_SYMBOL_GPL(rcu_cpu_stall_suppress);
module_param(rcu_cpu_stall_suppress, int, 0644);
int rcu_cpu_stall_timeout __read_mostly = CONFIG_RCU_CPU_STALL_TIMEOUT;
module_param(rcu_cpu_stall_timeout, int, 0644);
int rcu_exp_cpu_stall_timeout __read_mostly = CONFIG_RCU_EXP_CPU_STALL_TIMEOUT;
module_param(rcu_exp_cpu_stall_timeout, int, 0644);
#endif /* #ifdef CONFIG_RCU_STALL_COMMON */

// Suppress boot-time RCU CPU stall warnings and rcutorture writer stall
// warnings.  Also used by rcutorture even if stall warnings are excluded.
int rcu_cpu_stall_suppress_at_boot __read_mostly; // !0 = suppress boot stalls.
EXPORT_SYMBOL_GPL(rcu_cpu_stall_suppress_at_boot);
module_param(rcu_cpu_stall_suppress_at_boot, int, 0444);

unsigned long get_completed_synchronize_rcu(void)
{
	return RCU_GET_STATE_COMPLETED;
}
EXPORT_SYMBOL_GPL(get_completed_synchronize_rcu);

#ifdef CONFIG_PROVE_RCU

static bool rcu_self_test;
module_param(rcu_self_test, bool, 0444);

static int rcu_self_test_counter;

static void test_callback(struct rcu_head *r)
{
	rcu_self_test_counter++;
	pr_info("RCU test callback executed %d\n", rcu_self_test_counter);
}

DEFINE_STATIC_SRCU(early_srcu);
static unsigned long early_srcu_cookie;

struct early_boot_kfree_rcu {
	struct rcu_head rh;
};

static void early_boot_test_call_rcu(void)
{
	static struct rcu_head head;
	static struct rcu_head shead;
	struct early_boot_kfree_rcu *rhp;

	call_rcu(&head, test_callback);
	if (IS_ENABLED(CONFIG_SRCU)) {
		early_srcu_cookie = start_poll_synchronize_srcu(&early_srcu);
		call_srcu(&early_srcu, &shead, test_callback);
	}
	rhp = kmalloc(sizeof(*rhp), GFP_KERNEL);
	if (!WARN_ON_ONCE(!rhp))
		kfree_rcu(rhp, rh);
}

void rcu_early_boot_tests(void)
{
	pr_info("Running RCU self tests\n");

	if (rcu_self_test)
		early_boot_test_call_rcu();
	rcu_test_sync_prims();
}

static int rcu_verify_early_boot_tests(void)
{
	int ret = 0;
	int early_boot_test_counter = 0;

	if (rcu_self_test) {
		early_boot_test_counter++;
		rcu_barrier();
		if (IS_ENABLED(CONFIG_SRCU)) {
			early_boot_test_counter++;
			srcu_barrier(&early_srcu);
			WARN_ON_ONCE(!poll_state_synchronize_srcu(&early_srcu, early_srcu_cookie));
		}
	}
	if (rcu_self_test_counter != early_boot_test_counter) {
		WARN_ON(1);
		ret = -1;
	}

	return ret;
}
late_initcall(rcu_verify_early_boot_tests);
#else
void rcu_early_boot_tests(void) {}
#endif /* CONFIG_PROVE_RCU */

#include "tasks.h"

#ifndef CONFIG_TINY_RCU

void __init rcupdate_announce_bootup_oddness(void)
{
	if (rcu_normal)
		pr_info("\tNo expedited grace period (rcu_normal).\n");
	else if (rcu_normal_after_boot)
		pr_info("\tNo expedited grace period (rcu_normal_after_boot).\n");
	else if (rcu_expedited)
		pr_info("\tAll grace periods are expedited (rcu_expedited).\n");
	if (rcu_cpu_stall_suppress)
		pr_info("\tRCU CPU stall warnings suppressed (rcu_cpu_stall_suppress).\n");
	if (rcu_cpu_stall_timeout != CONFIG_RCU_CPU_STALL_TIMEOUT)
		pr_info("\tRCU CPU stall warnings timeout set to %d (rcu_cpu_stall_timeout).\n", rcu_cpu_stall_timeout);
	rcu_tasks_bootup_oddness();
}

#endif /* #ifndef CONFIG_TINY_RCU */
