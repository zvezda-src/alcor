#ifndef _KERNEL_SCHED_SCHED_H
#define _KERNEL_SCHED_SCHED_H

#include <linux/sched/affinity.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/cpufreq.h>
#include <linux/sched/deadline.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/mm.h>
#include <linux/sched/rseq_api.h>
#include <linux/sched/signal.h>
#include <linux/sched/smt.h>
#include <linux/sched/stat.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/task_flags.h>
#include <linux/sched/task.h>
#include <linux/sched/topology.h>

#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/capability.h>
#include <linux/cgroup_api.h>
#include <linux/cgroup.h>
#include <linux/context_tracking.h>
#include <linux/cpufreq.h>
#include <linux/cpumask_api.h>
#include <linux/ctype.h>
#include <linux/file.h>
#include <linux/fs_api.h>
#include <linux/hrtimer_api.h>
#include <linux/interrupt.h>
#include <linux/irq_work.h>
#include <linux/jiffies.h>
#include <linux/kref_api.h>
#include <linux/kthread.h>
#include <linux/ktime_api.h>
#include <linux/lockdep_api.h>
#include <linux/lockdep.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex_api.h>
#include <linux/plist.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/profile.h>
#include <linux/psi.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/softirq.h>
#include <linux/spinlock_api.h>
#include <linux/static_key.h>
#include <linux/stop_machine.h>
#include <linux/syscalls_api.h>
#include <linux/syscalls.h>
#include <linux/tick.h>
#include <linux/topology.h>
#include <linux/types.h>
#include <linux/u64_stats_sync_api.h>
#include <linux/uaccess.h>
#include <linux/wait_api.h>
#include <linux/wait_bit.h>
#include <linux/workqueue_api.h>

#include <trace/events/power.h>
#include <trace/events/sched.h>

#include "../workqueue_internal.h"

#ifdef CONFIG_CGROUP_SCHED
#include <linux/cgroup.h>
#include <linux/psi.h>
#endif

#ifdef CONFIG_SCHED_DEBUG
# include <linux/static_key.h>
#endif

#ifdef CONFIG_PARAVIRT
# include <asm/paravirt.h>
# include <asm/paravirt_api_clock.h>
#endif

#include "cpupri.h"
#include "cpudeadline.h"

#ifdef CONFIG_SCHED_DEBUG
# define SCHED_WARN_ON(x)      WARN_ONCE(x, #x)
#else
# define SCHED_WARN_ON(x)      ({ (void)(x), 0; })
#endif

struct rq;
struct cpuidle_state;

#define TASK_ON_RQ_QUEUED	1
#define TASK_ON_RQ_MIGRATING	2

extern __read_mostly int scheduler_running;

extern unsigned long calc_load_update;
extern atomic_long_t calc_load_tasks;

extern unsigned int sysctl_sched_child_runs_first;

extern void calc_global_load_tick(struct rq *this_rq);
extern long calc_load_fold_active(struct rq *this_rq, long adjust);

extern void call_trace_sched_update_nr_running(struct rq *rq, int count);

extern unsigned int sysctl_sched_rt_period;
extern int sysctl_sched_rt_runtime;
extern int sched_rr_timeslice;

#define NS_TO_JIFFIES(TIME)	((unsigned long)(TIME) / (NSEC_PER_SEC / HZ))

#ifdef CONFIG_64BIT
# define NICE_0_LOAD_SHIFT	(SCHED_FIXEDPOINT_SHIFT + SCHED_FIXEDPOINT_SHIFT)
# define scale_load(w)		((w) << SCHED_FIXEDPOINT_SHIFT)
# define scale_load_down(w) \
({ \
	unsigned long __w = (w); \
	if (__w) \
		__w = max(2UL, __w >> SCHED_FIXEDPOINT_SHIFT); \
	__w; \
})
#else
# define NICE_0_LOAD_SHIFT	(SCHED_FIXEDPOINT_SHIFT)
# define scale_load(w)		(w)
# define scale_load_down(w)	(w)
#endif

#define NICE_0_LOAD		(1L << NICE_0_LOAD_SHIFT)

#define DL_SCALE		10

#define RUNTIME_INF		((u64)~0ULL)

static inline int idle_policy(int policy)
{
	return policy == SCHED_IDLE;
}
static inline int fair_policy(int policy)
{
	return policy == SCHED_NORMAL || policy == SCHED_BATCH;
}

static inline int rt_policy(int policy)
{
	return policy == SCHED_FIFO || policy == SCHED_RR;
}

static inline int dl_policy(int policy)
{
	return policy == SCHED_DEADLINE;
}
static inline bool valid_policy(int policy)
{
	return idle_policy(policy) || fair_policy(policy) ||
		rt_policy(policy) || dl_policy(policy);
}

static inline int task_has_idle_policy(struct task_struct *p)
{
	return idle_policy(p->policy);
}

static inline int task_has_rt_policy(struct task_struct *p)
{
	return rt_policy(p->policy);
}

static inline int task_has_dl_policy(struct task_struct *p)
{
	return dl_policy(p->policy);
}

#define cap_scale(v, s) ((v)*(s) >> SCHED_CAPACITY_SHIFT)

static inline void update_avg(u64 *avg, u64 sample)
{
	s64 diff = sample - *avg;
}

#define shr_bound(val, shift)							\
	(val >> min_t(typeof(shift), shift, BITS_PER_TYPE(typeof(val)) - 1))

#define SCHED_FLAG_SUGOV	0x10000000

#define SCHED_DL_FLAGS (SCHED_FLAG_RECLAIM | SCHED_FLAG_DL_OVERRUN | SCHED_FLAG_SUGOV)

static inline bool dl_entity_is_special(struct sched_dl_entity *dl_se)
{
#ifdef CONFIG_CPU_FREQ_GOV_SCHEDUTIL
	return unlikely(dl_se->flags & SCHED_FLAG_SUGOV);
#else
	return false;
#endif
}

static inline bool
dl_entity_preempt(struct sched_dl_entity *a, struct sched_dl_entity *b)
{
	return dl_entity_is_special(a) ||
	       dl_time_before(a->deadline, b->deadline);
}

struct rt_prio_array {
	DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
	struct list_head queue[MAX_RT_PRIO];
};

struct rt_bandwidth {
	/* nests inside the rq lock: */
	raw_spinlock_t		rt_runtime_lock;
	ktime_t			rt_period;
	u64			rt_runtime;
	struct hrtimer		rt_period_timer;
	unsigned int		rt_period_active;
};

void __dl_clear_params(struct task_struct *p);

struct dl_bandwidth {
	raw_spinlock_t		dl_runtime_lock;
	u64			dl_runtime;
	u64			dl_period;
};

static inline int dl_bandwidth_enabled(void)
{
	return sysctl_sched_rt_runtime >= 0;
}

struct dl_bw {
	raw_spinlock_t		lock;
	u64			bw;
	u64			total_bw;
};

static inline bool dl_task_fits_capacity(struct task_struct *p, int cpu)
{
	unsigned long cap = arch_scale_cpu_capacity(cpu);

	return cap_scale(p->dl.dl_deadline, cap) >= p->dl.dl_runtime;
}

extern void init_dl_bw(struct dl_bw *dl_b);
extern int  sched_dl_global_validate(void);
extern void sched_dl_do_global(void);
extern int  sched_dl_overflow(struct task_struct *p, int policy, const struct sched_attr *attr);
extern void __setparam_dl(struct task_struct *p, const struct sched_attr *attr);
extern void __getparam_dl(struct task_struct *p, struct sched_attr *attr);
extern bool __checkparam_dl(const struct sched_attr *attr);
extern bool dl_param_changed(struct task_struct *p, const struct sched_attr *attr);
extern int  dl_cpuset_cpumask_can_shrink(const struct cpumask *cur, const struct cpumask *trial);
extern int  dl_cpu_busy(int cpu, struct task_struct *p);

#ifdef CONFIG_CGROUP_SCHED

struct cfs_rq;
struct rt_rq;

extern struct list_head task_groups;

struct cfs_bandwidth {
#ifdef CONFIG_CFS_BANDWIDTH
	raw_spinlock_t		lock;
	ktime_t			period;
	u64			quota;
	u64			runtime;
	u64			burst;
	u64			runtime_snap;
	s64			hierarchical_quota;

	u8			idle;
	u8			period_active;
	u8			slack_started;
	struct hrtimer		period_timer;
	struct hrtimer		slack_timer;
	struct list_head	throttled_cfs_rq;

	/* Statistics: */
	int			nr_periods;
	int			nr_throttled;
	int			nr_burst;
	u64			throttled_time;
	u64			burst_time;
#endif
};

struct task_group {
	struct cgroup_subsys_state css;

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* schedulable entities of this group on each CPU */
	struct sched_entity	**se;
	/* runqueue "owned" by this group on each CPU */
	struct cfs_rq		**cfs_rq;
	unsigned long		shares;

	/* A positive value indicates that this is a SCHED_IDLE group. */
	int			idle;

#ifdef	CONFIG_SMP
	/*
	atomic_long_t		load_avg ____cacheline_aligned;
#endif
#endif

#ifdef CONFIG_RT_GROUP_SCHED
	struct sched_rt_entity	**rt_se;
	struct rt_rq		**rt_rq;

	struct rt_bandwidth	rt_bandwidth;
#endif

	struct rcu_head		rcu;
	struct list_head	list;

	struct task_group	*parent;
	struct list_head	siblings;
	struct list_head	children;

#ifdef CONFIG_SCHED_AUTOGROUP
	struct autogroup	*autogroup;
#endif

	struct cfs_bandwidth	cfs_bandwidth;

#ifdef CONFIG_UCLAMP_TASK_GROUP
	/* The two decimal precision [%] value requested from user-space */
	unsigned int		uclamp_pct[UCLAMP_CNT];
	/* Clamp values requested for a task group */
	struct uclamp_se	uclamp_req[UCLAMP_CNT];
	/* Effective clamp values used for a task group */
	struct uclamp_se	uclamp[UCLAMP_CNT];
#endif

};

#ifdef CONFIG_FAIR_GROUP_SCHED
#define ROOT_TASK_GROUP_LOAD	NICE_0_LOAD

#define MIN_SHARES		(1UL <<  1)
#define MAX_SHARES		(1UL << 18)
#endif

typedef int (*tg_visitor)(struct task_group *, void *);

extern int walk_tg_tree_from(struct task_group *from,
			     tg_visitor down, tg_visitor up, void *data);

static inline int walk_tg_tree(tg_visitor down, tg_visitor up, void *data)
{
	return walk_tg_tree_from(&root_task_group, down, up, data);
}

extern int tg_nop(struct task_group *tg, void *data);

extern void free_fair_sched_group(struct task_group *tg);
extern int alloc_fair_sched_group(struct task_group *tg, struct task_group *parent);
extern void online_fair_sched_group(struct task_group *tg);
extern void unregister_fair_sched_group(struct task_group *tg);
extern void init_tg_cfs_entry(struct task_group *tg, struct cfs_rq *cfs_rq,
			struct sched_entity *se, int cpu,
			struct sched_entity *parent);
extern void init_cfs_bandwidth(struct cfs_bandwidth *cfs_b);

extern void __refill_cfs_bandwidth_runtime(struct cfs_bandwidth *cfs_b);
extern void start_cfs_bandwidth(struct cfs_bandwidth *cfs_b);
extern void unthrottle_cfs_rq(struct cfs_rq *cfs_rq);

extern void unregister_rt_sched_group(struct task_group *tg);
extern void free_rt_sched_group(struct task_group *tg);
extern int alloc_rt_sched_group(struct task_group *tg, struct task_group *parent);
extern void init_tg_rt_entry(struct task_group *tg, struct rt_rq *rt_rq,
		struct sched_rt_entity *rt_se, int cpu,
		struct sched_rt_entity *parent);
extern int sched_group_set_rt_runtime(struct task_group *tg, long rt_runtime_us);
extern int sched_group_set_rt_period(struct task_group *tg, u64 rt_period_us);
extern long sched_group_rt_runtime(struct task_group *tg);
extern long sched_group_rt_period(struct task_group *tg);
extern int sched_rt_can_attach(struct task_group *tg, struct task_struct *tsk);

extern struct task_group *sched_create_group(struct task_group *parent);
extern void sched_online_group(struct task_group *tg,
			       struct task_group *parent);
extern void sched_destroy_group(struct task_group *tg);
extern void sched_release_group(struct task_group *tg);

extern void sched_move_task(struct task_struct *tsk);

#ifdef CONFIG_FAIR_GROUP_SCHED
extern int sched_group_set_shares(struct task_group *tg, unsigned long shares);

extern int sched_group_set_idle(struct task_group *tg, long idle);

#ifdef CONFIG_SMP
extern void set_task_rq_fair(struct sched_entity *se,
			     struct cfs_rq *prev, struct cfs_rq *next);
#else /* !CONFIG_SMP */
static inline void set_task_rq_fair(struct sched_entity *se,
			     struct cfs_rq *prev, struct cfs_rq *next) { }
#endif /* CONFIG_SMP */
#endif /* CONFIG_FAIR_GROUP_SCHED */

#else /* CONFIG_CGROUP_SCHED */

struct cfs_bandwidth { };

#endif	/* CONFIG_CGROUP_SCHED */

#ifdef CONFIG_64BIT
# define u64_u32_load_copy(var, copy)       var
# define u64_u32_store_copy(var, copy, val) (var = val)
#else
# define u64_u32_load_copy(var, copy)					\
({									\
	u64 __val, __val_copy;						\
	do {								\
		__val_copy = copy;					\
		/*							\
		 * paired with u64_u32_store_copy(), ordering access	\
		 * to var and copy.					\
		 */							\
		smp_rmb();						\
		__val = var;						\
	} while (__val != __val_copy);					\
	__val;								\
})
# define u64_u32_store_copy(var, copy, val)				\
do {									\
	typeof(val) __val = (val);					\
	var = __val;							\
	/*								\
	 * paired with u64_u32_load_copy(), ordering access to var and	\
	 * copy.							\
	 */								\
	smp_wmb();							\
	copy = __val;							\
} while (0)
#endif
# define u64_u32_load(var)      u64_u32_load_copy(var, var##_copy)
# define u64_u32_store(var, val) u64_u32_store_copy(var, var##_copy, val)

struct cfs_rq {
	struct load_weight	load;
	unsigned int		nr_running;
	unsigned int		h_nr_running;      /* SCHED_{NORMAL,BATCH,IDLE} */
	unsigned int		idle_nr_running;   /* SCHED_IDLE */
	unsigned int		idle_h_nr_running; /* SCHED_IDLE */

	u64			exec_clock;
	u64			min_vruntime;
#ifdef CONFIG_SCHED_CORE
	unsigned int		forceidle_seq;
	u64			min_vruntime_fi;
#endif

#ifndef CONFIG_64BIT
	u64			min_vruntime_copy;
#endif

	struct rb_root_cached	tasks_timeline;

	/*
	struct sched_entity	*curr;
	struct sched_entity	*next;
	struct sched_entity	*last;
	struct sched_entity	*skip;

#ifdef	CONFIG_SCHED_DEBUG
	unsigned int		nr_spread_over;
#endif

#ifdef CONFIG_SMP
	/*
	struct sched_avg	avg;
#ifndef CONFIG_64BIT
	u64			last_update_time_copy;
#endif
	struct {
		raw_spinlock_t	lock ____cacheline_aligned;
		int		nr;
		unsigned long	load_avg;
		unsigned long	util_avg;
		unsigned long	runnable_avg;
	} removed;

#ifdef CONFIG_FAIR_GROUP_SCHED
	unsigned long		tg_load_avg_contrib;
	long			propagate;
	long			prop_runnable_sum;

	/*
	unsigned long		h_load;
	u64			last_h_load_update;
	struct sched_entity	*h_load_next;
#endif /* CONFIG_FAIR_GROUP_SCHED */
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct rq		*rq;	/* CPU runqueue to which this cfs_rq is attached */

	/*
	int			on_list;
	struct list_head	leaf_cfs_rq_list;
	struct task_group	*tg;	/* group that "owns" this runqueue */

	/* Locally cached copy of our task_group's idle value */
	int			idle;

#ifdef CONFIG_CFS_BANDWIDTH
	int			runtime_enabled;
	s64			runtime_remaining;

	u64			throttled_pelt_idle;
#ifndef CONFIG_64BIT
	u64                     throttled_pelt_idle_copy;
#endif
	u64			throttled_clock;
	u64			throttled_clock_pelt;
	u64			throttled_clock_pelt_time;
	int			throttled;
	int			throttle_count;
	struct list_head	throttled_list;
#endif /* CONFIG_CFS_BANDWIDTH */
#endif /* CONFIG_FAIR_GROUP_SCHED */
};

static inline int rt_bandwidth_enabled(void)
{
	return sysctl_sched_rt_runtime >= 0;
}

#if defined(CONFIG_IRQ_WORK) && defined(CONFIG_SMP)
# define HAVE_RT_PUSH_IPI
#endif

struct rt_rq {
	struct rt_prio_array	active;
	unsigned int		rt_nr_running;
	unsigned int		rr_nr_running;
#if defined CONFIG_SMP || defined CONFIG_RT_GROUP_SCHED
	struct {
		int		curr; /* highest queued rt task prio */
#ifdef CONFIG_SMP
		int		next; /* next highest */
#endif
	} highest_prio;
#endif
#ifdef CONFIG_SMP
	unsigned int		rt_nr_migratory;
	unsigned int		rt_nr_total;
	int			overloaded;
	struct plist_head	pushable_tasks;

#endif /* CONFIG_SMP */
	int			rt_queued;

	int			rt_throttled;
	u64			rt_time;
	u64			rt_runtime;
	/* Nests inside the rq lock: */
	raw_spinlock_t		rt_runtime_lock;

#ifdef CONFIG_RT_GROUP_SCHED
	unsigned int		rt_nr_boosted;

	struct rq		*rq;
	struct task_group	*tg;
#endif
};

static inline bool rt_rq_is_runnable(struct rt_rq *rt_rq)
{
	return rt_rq->rt_queued && rt_rq->rt_nr_running;
}

struct dl_rq {
	/* runqueue is an rbtree, ordered by deadline */
	struct rb_root_cached	root;

	unsigned int		dl_nr_running;

#ifdef CONFIG_SMP
	/*
	struct {
		u64		curr;
		u64		next;
	} earliest_dl;

	unsigned int		dl_nr_migratory;
	int			overloaded;

	/*
	struct rb_root_cached	pushable_dl_tasks_root;
#else
	struct dl_bw		dl_bw;
#endif
	/*
	u64			running_bw;

	/*
	u64			this_bw;
	u64			extra_bw;

	/*
	u64			bw_ratio;
};

#ifdef CONFIG_FAIR_GROUP_SCHED
#define entity_is_task(se)	(!se->my_q)

static inline void se_update_runnable(struct sched_entity *se)
{
	if (!entity_is_task(se))
		se->runnable_weight = se->my_q->h_nr_running;
}

static inline long se_runnable(struct sched_entity *se)
{
	if (entity_is_task(se))
		return !!se->on_rq;
	else
		return se->runnable_weight;
}

#else
#define entity_is_task(se)	1

static inline void se_update_runnable(struct sched_entity *se) {}

static inline long se_runnable(struct sched_entity *se)
{
	return !!se->on_rq;
}
#endif

#ifdef CONFIG_SMP
static inline long se_weight(struct sched_entity *se)
{
	return scale_load_down(se->load.weight);
}


static inline bool sched_asym_prefer(int a, int b)
{
	return arch_asym_cpu_priority(a) > arch_asym_cpu_priority(b);
}

struct perf_domain {
	struct em_perf_domain *em_pd;
	struct perf_domain *next;
	struct rcu_head rcu;
};

#define SG_OVERLOAD		0x1 /* More than one runnable task on a CPU. */
#define SG_OVERUTILIZED		0x2 /* One or more CPUs are over-utilized. */

struct root_domain {
	atomic_t		refcount;
	atomic_t		rto_count;
	struct rcu_head		rcu;
	cpumask_var_t		span;
	cpumask_var_t		online;

	/*
	int			overload;

	/* Indicate one or more cpus over-utilized (tipping point) */
	int			overutilized;

	/*
	cpumask_var_t		dlo_mask;
	atomic_t		dlo_count;
	struct dl_bw		dl_bw;
	struct cpudl		cpudl;

	/*
	u64 visit_gen;

#ifdef HAVE_RT_PUSH_IPI
	/*
	struct irq_work		rto_push_work;
	raw_spinlock_t		rto_lock;
	/* These are only updated and read within rto_lock */
	int			rto_loop;
	int			rto_cpu;
	/* These atomics are updated outside of a lock */
	atomic_t		rto_loop_next;
	atomic_t		rto_loop_start;
#endif
	/*
	cpumask_var_t		rto_mask;
	struct cpupri		cpupri;

	unsigned long		max_cpu_capacity;

	/*
	struct perf_domain __rcu *pd;
};

extern void init_defrootdomain(void);
extern int sched_init_domains(const struct cpumask *cpu_map);
extern void rq_attach_root(struct rq *rq, struct root_domain *rd);
extern void sched_get_rd(struct root_domain *rd);
extern void sched_put_rd(struct root_domain *rd);

#ifdef HAVE_RT_PUSH_IPI
extern void rto_push_irq_work_func(struct irq_work *work);
#endif
#endif /* CONFIG_SMP */

#ifdef CONFIG_UCLAMP_TASK
struct uclamp_bucket {
	unsigned long value : bits_per(SCHED_CAPACITY_SCALE);
	unsigned long tasks : BITS_PER_LONG - bits_per(SCHED_CAPACITY_SCALE);
};

struct uclamp_rq {
	unsigned int value;
	struct uclamp_bucket bucket[UCLAMP_BUCKETS];
};

DECLARE_STATIC_KEY_FALSE(sched_uclamp_used);
#endif /* CONFIG_UCLAMP_TASK */

struct rq {
	/* runqueue lock: */
	raw_spinlock_t		__lock;

	/*
	unsigned int		nr_running;
#ifdef CONFIG_NUMA_BALANCING
	unsigned int		nr_numa_running;
	unsigned int		nr_preferred_running;
	unsigned int		numa_migrate_on;
#endif
#ifdef CONFIG_NO_HZ_COMMON
#ifdef CONFIG_SMP
	unsigned long		last_blocked_load_update_tick;
	unsigned int		has_blocked_load;
	call_single_data_t	nohz_csd;
#endif /* CONFIG_SMP */
	unsigned int		nohz_tick_stopped;
	atomic_t		nohz_flags;
#endif /* CONFIG_NO_HZ_COMMON */

#ifdef CONFIG_SMP
	unsigned int		ttwu_pending;
#endif
	u64			nr_switches;

#ifdef CONFIG_UCLAMP_TASK
	/* Utilization clamp values based on CPU's RUNNABLE tasks */
	struct uclamp_rq	uclamp[UCLAMP_CNT] ____cacheline_aligned;
	unsigned int		uclamp_flags;
#define UCLAMP_FLAG_IDLE 0x01
#endif

	struct cfs_rq		cfs;
	struct rt_rq		rt;
	struct dl_rq		dl;

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* list of leaf cfs_rq on this CPU: */
	struct list_head	leaf_cfs_rq_list;
	struct list_head	*tmp_alone_branch;
#endif /* CONFIG_FAIR_GROUP_SCHED */

	/*
	unsigned int		nr_uninterruptible;

	struct task_struct __rcu	*curr;
	struct task_struct	*idle;
	struct task_struct	*stop;
	unsigned long		next_balance;
	struct mm_struct	*prev_mm;

	unsigned int		clock_update_flags;
	u64			clock;
	/* Ensure that all clocks are in the same cache line */
	u64			clock_task ____cacheline_aligned;
	u64			clock_pelt;
	unsigned long		lost_idle_time;
	u64			clock_pelt_idle;
	u64			clock_idle;
#ifndef CONFIG_64BIT
	u64			clock_pelt_idle_copy;
	u64			clock_idle_copy;
#endif

	atomic_t		nr_iowait;

#ifdef CONFIG_SCHED_DEBUG
	u64 last_seen_need_resched_ns;
	int ticks_without_resched;
#endif

#ifdef CONFIG_MEMBARRIER
	int membarrier_state;
#endif

#ifdef CONFIG_SMP
	struct root_domain		*rd;
	struct sched_domain __rcu	*sd;

	unsigned long		cpu_capacity;
	unsigned long		cpu_capacity_orig;

	struct callback_head	*balance_callback;

	unsigned char		nohz_idle_balance;
	unsigned char		idle_balance;

	unsigned long		misfit_task_load;

	/* For active balancing */
	int			active_balance;
	int			push_cpu;
	struct cpu_stop_work	active_balance_work;

	/* CPU of this runqueue: */
	int			cpu;
	int			online;

	struct list_head cfs_tasks;

	struct sched_avg	avg_rt;
	struct sched_avg	avg_dl;
#ifdef CONFIG_HAVE_SCHED_AVG_IRQ
	struct sched_avg	avg_irq;
#endif
#ifdef CONFIG_SCHED_THERMAL_PRESSURE
	struct sched_avg	avg_thermal;
#endif
	u64			idle_stamp;
	u64			avg_idle;

	unsigned long		wake_stamp;
	u64			wake_avg_idle;

	/* This is used to determine avg_idle's max value */
	u64			max_idle_balance_cost;

#ifdef CONFIG_HOTPLUG_CPU
	struct rcuwait		hotplug_wait;
#endif
#endif /* CONFIG_SMP */

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	u64			prev_irq_time;
#endif
#ifdef CONFIG_PARAVIRT
	u64			prev_steal_time;
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	u64			prev_steal_time_rq;
#endif

	/* calc_load related fields */
	unsigned long		calc_load_update;
	long			calc_load_active;

#ifdef CONFIG_SCHED_HRTICK
#ifdef CONFIG_SMP
	call_single_data_t	hrtick_csd;
#endif
	struct hrtimer		hrtick_timer;
	ktime_t 		hrtick_time;
#endif

#ifdef CONFIG_SCHEDSTATS
	/* latency stats */
	struct sched_info	rq_sched_info;
	unsigned long long	rq_cpu_time;
	/* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

	/* sys_sched_yield() stats */
	unsigned int		yld_count;

	/* schedule() stats */
	unsigned int		sched_count;
	unsigned int		sched_goidle;

	/* try_to_wake_up() stats */
	unsigned int		ttwu_count;
	unsigned int		ttwu_local;
#endif

#ifdef CONFIG_CPU_IDLE
	/* Must be inspected within a rcu lock section */
	struct cpuidle_state	*idle_state;
#endif

#ifdef CONFIG_SMP
	unsigned int		nr_pinned;
#endif
	unsigned int		push_busy;
	struct cpu_stop_work	push_work;

#ifdef CONFIG_SCHED_CORE
	/* per rq */
	struct rq		*core;
	struct task_struct	*core_pick;
	unsigned int		core_enabled;
	unsigned int		core_sched_seq;
	struct rb_root		core_tree;

	/* shared state -- careful with sched_core_cpu_deactivate() */
	unsigned int		core_task_seq;
	unsigned int		core_pick_seq;
	unsigned long		core_cookie;
	unsigned int		core_forceidle_count;
	unsigned int		core_forceidle_seq;
	unsigned int		core_forceidle_occupation;
	u64			core_forceidle_start;
#endif
};

#ifdef CONFIG_FAIR_GROUP_SCHED

static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
{
	return cfs_rq->rq;
}

#else

static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
{
	return container_of(cfs_rq, struct rq, cfs);
}
#endif

static inline int cpu_of(struct rq *rq)
{
#ifdef CONFIG_SMP
	return rq->cpu;
#else
	return 0;
#endif
}

#define MDF_PUSH	0x01

static inline bool is_migration_disabled(struct task_struct *p)
{
#ifdef CONFIG_SMP
	return p->migration_disabled;
#else
	return false;
#endif
}

struct sched_group;
#ifdef CONFIG_SCHED_CORE
static inline struct cpumask *sched_group_span(struct sched_group *sg);

DECLARE_STATIC_KEY_FALSE(__sched_core_enabled);

static inline bool sched_core_enabled(struct rq *rq)
{
	return static_branch_unlikely(&__sched_core_enabled) && rq->core_enabled;
}

static inline bool sched_core_disabled(void)
{
	return !static_branch_unlikely(&__sched_core_enabled);
}

static inline raw_spinlock_t *rq_lockp(struct rq *rq)
{
	if (sched_core_enabled(rq))
		return &rq->core->__lock;

	return &rq->__lock;
}

static inline raw_spinlock_t *__rq_lockp(struct rq *rq)
{
	if (rq->core_enabled)
		return &rq->core->__lock;

	return &rq->__lock;
}

bool cfs_prio_less(struct task_struct *a, struct task_struct *b, bool fi);

static inline bool sched_cpu_cookie_match(struct rq *rq, struct task_struct *p)
{
	/* Ignore cookie match if core scheduler is not enabled on the CPU. */
	if (!sched_core_enabled(rq))
		return true;

	return rq->core->core_cookie == p->core_cookie;
}

static inline bool sched_core_cookie_match(struct rq *rq, struct task_struct *p)
{
	bool idle_core = true;
	int cpu;

	/* Ignore cookie match if core scheduler is not enabled on the CPU. */
	if (!sched_core_enabled(rq))
		return true;

	for_each_cpu(cpu, cpu_smt_mask(cpu_of(rq))) {
		if (!available_idle_cpu(cpu)) {
			idle_core = false;
			break;
		}
	}

	/*
	return idle_core || rq->core->core_cookie == p->core_cookie;
}

static inline bool sched_group_cookie_match(struct rq *rq,
					    struct task_struct *p,
					    struct sched_group *group)
{
	int cpu;

	/* Ignore cookie match if core scheduler is not enabled on the CPU. */
	if (!sched_core_enabled(rq))
		return true;

	for_each_cpu_and(cpu, sched_group_span(group), p->cpus_ptr) {
		if (sched_core_cookie_match(rq, p))
			return true;
	}
	return false;
}

static inline bool sched_core_enqueued(struct task_struct *p)
{
	return !RB_EMPTY_NODE(&p->core_node);
}

extern void sched_core_enqueue(struct rq *rq, struct task_struct *p);
extern void sched_core_dequeue(struct rq *rq, struct task_struct *p, int flags);

extern void sched_core_get(void);
extern void sched_core_put(void);

#else /* !CONFIG_SCHED_CORE */

static inline bool sched_core_enabled(struct rq *rq)
{
	return false;
}

static inline bool sched_core_disabled(void)
{
	return true;
}

static inline raw_spinlock_t *rq_lockp(struct rq *rq)
{
	return &rq->__lock;
}

static inline raw_spinlock_t *__rq_lockp(struct rq *rq)
{
	return &rq->__lock;
}

static inline bool sched_cpu_cookie_match(struct rq *rq, struct task_struct *p)
{
	return true;
}

static inline bool sched_core_cookie_match(struct rq *rq, struct task_struct *p)
{
	return true;
}

static inline bool sched_group_cookie_match(struct rq *rq,
					    struct task_struct *p,
					    struct sched_group *group)
{
	return true;
}
#endif /* CONFIG_SCHED_CORE */

static inline void lockdep_assert_rq_held(struct rq *rq)
{
	lockdep_assert_held(__rq_lockp(rq));
}

extern void raw_spin_rq_lock_nested(struct rq *rq, int subclass);
extern bool raw_spin_rq_trylock(struct rq *rq);
extern void raw_spin_rq_unlock(struct rq *rq);

static inline void raw_spin_rq_lock(struct rq *rq)
{
	raw_spin_rq_lock_nested(rq, 0);
}

static inline void raw_spin_rq_lock_irq(struct rq *rq)
{
	local_irq_disable();
	raw_spin_rq_lock(rq);
}

static inline void raw_spin_rq_unlock_irq(struct rq *rq)
{
	raw_spin_rq_unlock(rq);
	local_irq_enable();
}

static inline unsigned long _raw_spin_rq_lock_irqsave(struct rq *rq)
{
	unsigned long flags;
	local_irq_save(flags);
	raw_spin_rq_lock(rq);
	return flags;
}

static inline void raw_spin_rq_unlock_irqrestore(struct rq *rq, unsigned long flags)
{
	raw_spin_rq_unlock(rq);
	local_irq_restore(flags);
}

#define raw_spin_rq_lock_irqsave(rq, flags)	\
do {						\
	flags = _raw_spin_rq_lock_irqsave(rq);	\
} while (0)

#ifdef CONFIG_SCHED_SMT
extern void __update_idle_core(struct rq *rq);

static inline void update_idle_core(struct rq *rq)
{
	if (static_branch_unlikely(&sched_smt_present))
		__update_idle_core(rq);
}

#else
static inline void update_idle_core(struct rq *rq) { }
#endif

DECLARE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

#define cpu_rq(cpu)		(&per_cpu(runqueues, (cpu)))
#define this_rq()		this_cpu_ptr(&runqueues)
#define task_rq(p)		cpu_rq(task_cpu(p))
#define cpu_curr(cpu)		(cpu_rq(cpu)->curr)
#define raw_rq()		raw_cpu_ptr(&runqueues)

#ifdef CONFIG_FAIR_GROUP_SCHED
static inline struct task_struct *task_of(struct sched_entity *se)
{
	SCHED_WARN_ON(!entity_is_task(se));
	return container_of(se, struct task_struct, se);
}

static inline struct cfs_rq *task_cfs_rq(struct task_struct *p)
{
	return p->se.cfs_rq;
}

static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
{
	return se->cfs_rq;
}

static inline struct cfs_rq *group_cfs_rq(struct sched_entity *grp)
{
	return grp->my_q;
}

#else

static inline struct task_struct *task_of(struct sched_entity *se)
{
	return container_of(se, struct task_struct, se);
}

static inline struct cfs_rq *task_cfs_rq(struct task_struct *p)
{
	return &task_rq(p)->cfs;
}

static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
{
	struct task_struct *p = task_of(se);
	struct rq *rq = task_rq(p);

	return &rq->cfs;
}

static inline struct cfs_rq *group_cfs_rq(struct sched_entity *grp)
{
	return NULL;
}
#endif

extern void update_rq_clock(struct rq *rq);

#define RQCF_REQ_SKIP		0x01
#define RQCF_ACT_SKIP		0x02
#define RQCF_UPDATED		0x04

static inline void assert_clock_updated(struct rq *rq)
{
	/*
	SCHED_WARN_ON(rq->clock_update_flags < RQCF_ACT_SKIP);
}

static inline u64 rq_clock(struct rq *rq)
{
	lockdep_assert_rq_held(rq);
	assert_clock_updated(rq);

	return rq->clock;
}

static inline u64 rq_clock_task(struct rq *rq)
{
	lockdep_assert_rq_held(rq);
	assert_clock_updated(rq);

	return rq->clock_task;
}

extern int sched_thermal_decay_shift;

static inline u64 rq_clock_thermal(struct rq *rq)
{
	return rq_clock_task(rq) >> sched_thermal_decay_shift;
}

static inline void rq_clock_skip_update(struct rq *rq)
{
	lockdep_assert_rq_held(rq);
	rq->clock_update_flags |= RQCF_REQ_SKIP;
}

static inline void rq_clock_cancel_skipupdate(struct rq *rq)
{
	lockdep_assert_rq_held(rq);
	rq->clock_update_flags &= ~RQCF_REQ_SKIP;
}

struct rq_flags {
	unsigned long flags;
	struct pin_cookie cookie;
#ifdef CONFIG_SCHED_DEBUG
	/*
	unsigned int clock_update_flags;
#endif
};

extern struct callback_head balance_push_callback;

static inline void rq_pin_lock(struct rq *rq, struct rq_flags *rf)
{
	rf->cookie = lockdep_pin_lock(__rq_lockp(rq));

#ifdef CONFIG_SCHED_DEBUG
	rq->clock_update_flags &= (RQCF_REQ_SKIP|RQCF_ACT_SKIP);
	rf->clock_update_flags = 0;
#ifdef CONFIG_SMP
	SCHED_WARN_ON(rq->balance_callback && rq->balance_callback != &balance_push_callback);
#endif
#endif
}

static inline void rq_unpin_lock(struct rq *rq, struct rq_flags *rf)
{
#ifdef CONFIG_SCHED_DEBUG
	if (rq->clock_update_flags > RQCF_ACT_SKIP)
		rf->clock_update_flags = RQCF_UPDATED;
#endif

	lockdep_unpin_lock(__rq_lockp(rq), rf->cookie);
}

static inline void rq_repin_lock(struct rq *rq, struct rq_flags *rf)
{
	lockdep_repin_lock(__rq_lockp(rq), rf->cookie);

#ifdef CONFIG_SCHED_DEBUG
	/*
	rq->clock_update_flags |= rf->clock_update_flags;
#endif
}

struct rq *__task_rq_lock(struct task_struct *p, struct rq_flags *rf)
	__acquires(rq->lock);

struct rq *task_rq_lock(struct task_struct *p, struct rq_flags *rf)
	__acquires(p->pi_lock)
	__acquires(rq->lock);

static inline void __task_rq_unlock(struct rq *rq, struct rq_flags *rf)
	__releases(rq->lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_rq_unlock(rq);
}

static inline void
task_rq_unlock(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
	__releases(rq->lock)
	__releases(p->pi_lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_rq_unlock(rq);
	raw_spin_unlock_irqrestore(&p->pi_lock, rf->flags);
}

static inline void
rq_lock_irqsave(struct rq *rq, struct rq_flags *rf)
	__acquires(rq->lock)
{
	raw_spin_rq_lock_irqsave(rq, rf->flags);
	rq_pin_lock(rq, rf);
}

static inline void
rq_lock_irq(struct rq *rq, struct rq_flags *rf)
	__acquires(rq->lock)
{
	raw_spin_rq_lock_irq(rq);
	rq_pin_lock(rq, rf);
}

static inline void
rq_lock(struct rq *rq, struct rq_flags *rf)
	__acquires(rq->lock)
{
	raw_spin_rq_lock(rq);
	rq_pin_lock(rq, rf);
}

static inline void
rq_unlock_irqrestore(struct rq *rq, struct rq_flags *rf)
	__releases(rq->lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_rq_unlock_irqrestore(rq, rf->flags);
}

static inline void
rq_unlock_irq(struct rq *rq, struct rq_flags *rf)
	__releases(rq->lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_rq_unlock_irq(rq);
}

static inline void
rq_unlock(struct rq *rq, struct rq_flags *rf)
	__releases(rq->lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_rq_unlock(rq);
}

static inline struct rq *
this_rq_lock_irq(struct rq_flags *rf)
	__acquires(rq->lock)
{
	struct rq *rq;

	local_irq_disable();
	rq = this_rq();
	rq_lock(rq, rf);
	return rq;
}

#ifdef CONFIG_NUMA
enum numa_topology_type {
	NUMA_DIRECT,
	NUMA_GLUELESS_MESH,
	NUMA_BACKPLANE,
};
extern enum numa_topology_type sched_numa_topology_type;
extern int sched_max_numa_distance;
extern bool find_numa_distance(int distance);
extern void sched_init_numa(int offline_node);
extern void sched_update_numa(int cpu, bool online);
extern void sched_domains_numa_masks_set(unsigned int cpu);
extern void sched_domains_numa_masks_clear(unsigned int cpu);
extern int sched_numa_find_closest(const struct cpumask *cpus, int cpu);
#else
static inline void sched_init_numa(int offline_node) { }
static inline void sched_update_numa(int cpu, bool online) { }
static inline void sched_domains_numa_masks_set(unsigned int cpu) { }
static inline void sched_domains_numa_masks_clear(unsigned int cpu) { }
static inline int sched_numa_find_closest(const struct cpumask *cpus, int cpu)
{
	return nr_cpu_ids;
}
#endif

#ifdef CONFIG_NUMA_BALANCING
enum numa_faults_stats {
	NUMA_MEM = 0,
	NUMA_CPU,
	NUMA_MEMBUF,
	NUMA_CPUBUF
};
extern void sched_setnuma(struct task_struct *p, int node);
extern int migrate_task_to(struct task_struct *p, int cpu);
extern int migrate_swap(struct task_struct *p, struct task_struct *t,
			int cpu, int scpu);
extern void init_numa_balancing(unsigned long clone_flags, struct task_struct *p);
#else
static inline void
init_numa_balancing(unsigned long clone_flags, struct task_struct *p)
{
}
#endif /* CONFIG_NUMA_BALANCING */

#ifdef CONFIG_SMP

static inline void
queue_balance_callback(struct rq *rq,
		       struct callback_head *head,
		       void (*func)(struct rq *rq))
{
	lockdep_assert_rq_held(rq);

	/*
	if (unlikely(head->next || rq->balance_callback == &balance_push_callback))
		return;

	head->func = (void (*)(struct callback_head *))func;
	head->next = rq->balance_callback;
	rq->balance_callback = head;
}

#define rcu_dereference_check_sched_domain(p) \
	rcu_dereference_check((p), \
			      lockdep_is_held(&sched_domains_mutex))

#define for_each_domain(cpu, __sd) \
	for (__sd = rcu_dereference_check_sched_domain(cpu_rq(cpu)->sd); \
			__sd; __sd = __sd->parent)

static inline struct sched_domain *highest_flag_domain(int cpu, int flag)
{
	struct sched_domain *sd, *hsd = NULL;

	for_each_domain(cpu, sd) {
		if (!(sd->flags & flag))
			break;
		hsd = sd;
	}

	return hsd;
}

static inline struct sched_domain *lowest_flag_domain(int cpu, int flag)
{
	struct sched_domain *sd;

	for_each_domain(cpu, sd) {
		if (sd->flags & flag)
			break;
	}

	return sd;
}

DECLARE_PER_CPU(struct sched_domain __rcu *, sd_llc);
DECLARE_PER_CPU(int, sd_llc_size);
DECLARE_PER_CPU(int, sd_llc_id);
DECLARE_PER_CPU(struct sched_domain_shared __rcu *, sd_llc_shared);
DECLARE_PER_CPU(struct sched_domain __rcu *, sd_numa);
DECLARE_PER_CPU(struct sched_domain __rcu *, sd_asym_packing);
DECLARE_PER_CPU(struct sched_domain __rcu *, sd_asym_cpucapacity);
extern struct static_key_false sched_asym_cpucapacity;

struct sched_group_capacity {
	atomic_t		ref;
	/*
	unsigned long		capacity;
	unsigned long		min_capacity;		/* Min per-CPU capacity in group */
	unsigned long		max_capacity;		/* Max per-CPU capacity in group */
	unsigned long		next_update;
	int			imbalance;		/* XXX unrelated to capacity but shared group state */

#ifdef CONFIG_SCHED_DEBUG
	int			id;
#endif

	unsigned long		cpumask[];		/* Balance mask */
};

struct sched_group {
	struct sched_group	*next;			/* Must be a circular list */
	atomic_t		ref;

	unsigned int		group_weight;
	struct sched_group_capacity *sgc;
	int			asym_prefer_cpu;	/* CPU of highest priority in group */
	int			flags;

	/*
	unsigned long		cpumask[];
};

static inline struct cpumask *sched_group_span(struct sched_group *sg)
{
	return to_cpumask(sg->cpumask);
}

static inline struct cpumask *group_balance_mask(struct sched_group *sg)
{
	return to_cpumask(sg->sgc->cpumask);
}

extern int group_balance_cpu(struct sched_group *sg);

#ifdef CONFIG_SCHED_DEBUG
void update_sched_domain_debugfs(void);
void dirty_sched_domain_sysctl(int cpu);
#else
static inline void update_sched_domain_debugfs(void)
{
}
static inline void dirty_sched_domain_sysctl(int cpu)
{
}
#endif

extern int sched_update_scaling(void);
#endif /* CONFIG_SMP */

#include "stats.h"

#if defined(CONFIG_SCHED_CORE) && defined(CONFIG_SCHEDSTATS)

extern void __sched_core_account_forceidle(struct rq *rq);

static inline void sched_core_account_forceidle(struct rq *rq)
{
	if (schedstat_enabled())
		__sched_core_account_forceidle(rq);
}

extern void __sched_core_tick(struct rq *rq);

static inline void sched_core_tick(struct rq *rq)
{
	if (sched_core_enabled(rq) && schedstat_enabled())
		__sched_core_tick(rq);
}

#else

static inline void sched_core_account_forceidle(struct rq *rq) {}

static inline void sched_core_tick(struct rq *rq) {}

#endif /* CONFIG_SCHED_CORE && CONFIG_SCHEDSTATS */

#ifdef CONFIG_CGROUP_SCHED

static inline struct task_group *task_group(struct task_struct *p)
{
	return p->sched_task_group;
}

static inline void set_task_rq(struct task_struct *p, unsigned int cpu)
{
#if defined(CONFIG_FAIR_GROUP_SCHED) || defined(CONFIG_RT_GROUP_SCHED)
	struct task_group *tg = task_group(p);
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	set_task_rq_fair(&p->se, p->se.cfs_rq, tg->cfs_rq[cpu]);
	p->se.cfs_rq = tg->cfs_rq[cpu];
	p->se.parent = tg->se[cpu];
#endif

#ifdef CONFIG_RT_GROUP_SCHED
	p->rt.rt_rq  = tg->rt_rq[cpu];
	p->rt.parent = tg->rt_se[cpu];
#endif
}

#else /* CONFIG_CGROUP_SCHED */

static inline void set_task_rq(struct task_struct *p, unsigned int cpu) { }
static inline struct task_group *task_group(struct task_struct *p)
{
	return NULL;
}

#endif /* CONFIG_CGROUP_SCHED */

static inline void __set_task_cpu(struct task_struct *p, unsigned int cpu)
{
	set_task_rq(p, cpu);
#ifdef CONFIG_SMP
	/*
	smp_wmb();
	WRITE_ONCE(task_thread_info(p)->cpu, cpu);
	p->wake_cpu = cpu;
#endif
}

#ifdef CONFIG_SCHED_DEBUG
# define const_debug __read_mostly
#else
# define const_debug const
#endif

#define SCHED_FEAT(name, enabled)	\
	__SCHED_FEAT_##name ,

enum {
#include "features.h"
	__SCHED_FEAT_NR,
};

#undef SCHED_FEAT

#ifdef CONFIG_SCHED_DEBUG

extern const_debug unsigned int sysctl_sched_features;

#ifdef CONFIG_JUMP_LABEL
#define SCHED_FEAT(name, enabled)					\
static __always_inline bool static_branch_##name(struct static_key *key) \
{									\
	return static_key_##enabled(key);				\
}

#include "features.h"
#undef SCHED_FEAT

extern struct static_key sched_feat_keys[__SCHED_FEAT_NR];
#define sched_feat(x) (static_branch_##x(&sched_feat_keys[__SCHED_FEAT_##x]))

#else /* !CONFIG_JUMP_LABEL */

#define sched_feat(x) (sysctl_sched_features & (1UL << __SCHED_FEAT_##x))

#endif /* CONFIG_JUMP_LABEL */

#else /* !SCHED_DEBUG */

#define SCHED_FEAT(name, enabled)	\
	(1UL << __SCHED_FEAT_##name) * enabled |
static const_debug __maybe_unused unsigned int sysctl_sched_features =
#include "features.h"
	0;
#undef SCHED_FEAT

#define sched_feat(x) !!(sysctl_sched_features & (1UL << __SCHED_FEAT_##x))

#endif /* SCHED_DEBUG */

extern struct static_key_false sched_numa_balancing;
extern struct static_key_false sched_schedstats;

static inline u64 global_rt_period(void)
{
	return (u64)sysctl_sched_rt_period * NSEC_PER_USEC;
}

static inline u64 global_rt_runtime(void)
{
	if (sysctl_sched_rt_runtime < 0)
		return RUNTIME_INF;

	return (u64)sysctl_sched_rt_runtime * NSEC_PER_USEC;
}

static inline int task_current(struct rq *rq, struct task_struct *p)
{
	return rq->curr == p;
}

static inline int task_running(struct rq *rq, struct task_struct *p)
{
#ifdef CONFIG_SMP
	return p->on_cpu;
#else
	return task_current(rq, p);
#endif
}

static inline int task_on_rq_queued(struct task_struct *p)
{
	return p->on_rq == TASK_ON_RQ_QUEUED;
}

static inline int task_on_rq_migrating(struct task_struct *p)
{
	return READ_ONCE(p->on_rq) == TASK_ON_RQ_MIGRATING;
}

#define WF_EXEC     0x02 /* Wakeup after exec; maps to SD_BALANCE_EXEC */
#define WF_FORK     0x04 /* Wakeup after fork; maps to SD_BALANCE_FORK */
#define WF_TTWU     0x08 /* Wakeup;            maps to SD_BALANCE_WAKE */

#define WF_SYNC     0x10 /* Waker goes to sleep after wakeup */
#define WF_MIGRATED 0x20 /* Internal use, task got migrated */

#ifdef CONFIG_SMP
static_assert(WF_EXEC == SD_BALANCE_EXEC);
static_assert(WF_FORK == SD_BALANCE_FORK);
static_assert(WF_TTWU == SD_BALANCE_WAKE);
#endif


#define WEIGHT_IDLEPRIO		3
#define WMULT_IDLEPRIO		1431655765

extern const int		sched_prio_to_weight[40];
extern const u32		sched_prio_to_wmult[40];


#define DEQUEUE_SLEEP		0x01
#define DEQUEUE_SAVE		0x02 /* Matches ENQUEUE_RESTORE */
#define DEQUEUE_MOVE		0x04 /* Matches ENQUEUE_MOVE */
#define DEQUEUE_NOCLOCK		0x08 /* Matches ENQUEUE_NOCLOCK */

#define ENQUEUE_WAKEUP		0x01
#define ENQUEUE_RESTORE		0x02
#define ENQUEUE_MOVE		0x04
#define ENQUEUE_NOCLOCK		0x08

#define ENQUEUE_HEAD		0x10
#define ENQUEUE_REPLENISH	0x20
#ifdef CONFIG_SMP
#define ENQUEUE_MIGRATED	0x40
#else
#define ENQUEUE_MIGRATED	0x00
#endif

#define RETRY_TASK		((void *)-1UL)

struct sched_class {

#ifdef CONFIG_UCLAMP_TASK
	int uclamp_enabled;
#endif

	void (*enqueue_task) (struct rq *rq, struct task_struct *p, int flags);
	void (*dequeue_task) (struct rq *rq, struct task_struct *p, int flags);
	void (*yield_task)   (struct rq *rq);
	bool (*yield_to_task)(struct rq *rq, struct task_struct *p);

	void (*check_preempt_curr)(struct rq *rq, struct task_struct *p, int flags);

	struct task_struct *(*pick_next_task)(struct rq *rq);

	void (*put_prev_task)(struct rq *rq, struct task_struct *p);
	void (*set_next_task)(struct rq *rq, struct task_struct *p, bool first);

#ifdef CONFIG_SMP
	int (*balance)(struct rq *rq, struct task_struct *prev, struct rq_flags *rf);
	int  (*select_task_rq)(struct task_struct *p, int task_cpu, int flags);

	struct task_struct * (*pick_task)(struct rq *rq);

	void (*migrate_task_rq)(struct task_struct *p, int new_cpu);

	void (*task_woken)(struct rq *this_rq, struct task_struct *task);

	void (*set_cpus_allowed)(struct task_struct *p,
				 const struct cpumask *newmask,
				 u32 flags);

	void (*rq_online)(struct rq *rq);
	void (*rq_offline)(struct rq *rq);

	struct rq *(*find_lock_rq)(struct task_struct *p, struct rq *rq);
#endif

	void (*task_tick)(struct rq *rq, struct task_struct *p, int queued);
	void (*task_fork)(struct task_struct *p);
	void (*task_dead)(struct task_struct *p);

	/*
	void (*switched_from)(struct rq *this_rq, struct task_struct *task);
	void (*switched_to)  (struct rq *this_rq, struct task_struct *task);
	void (*prio_changed) (struct rq *this_rq, struct task_struct *task,
			      int oldprio);

	unsigned int (*get_rr_interval)(struct rq *rq,
					struct task_struct *task);

	void (*update_curr)(struct rq *rq);

#define TASK_SET_GROUP		0
#define TASK_MOVE_GROUP		1

#ifdef CONFIG_FAIR_GROUP_SCHED
	void (*task_change_group)(struct task_struct *p, int type);
#endif
};

static inline void put_prev_task(struct rq *rq, struct task_struct *prev)
{
	WARN_ON_ONCE(rq->curr != prev);
	prev->sched_class->put_prev_task(rq, prev);
}

static inline void set_next_task(struct rq *rq, struct task_struct *next)
{
	next->sched_class->set_next_task(rq, next, false);
}


#define DEFINE_SCHED_CLASS(name) \
const struct sched_class name##_sched_class \
	__aligned(__alignof__(struct sched_class)) \
	__section("__" #name "_sched_class")

extern struct sched_class __sched_class_highest[];
extern struct sched_class __sched_class_lowest[];

#define for_class_range(class, _from, _to) \
	for (class = (_from); class < (_to); class++)

#define for_each_class(class) \
	for_class_range(class, __sched_class_highest, __sched_class_lowest)

#define sched_class_above(_a, _b)	((_a) < (_b))

extern const struct sched_class stop_sched_class;
extern const struct sched_class dl_sched_class;
extern const struct sched_class rt_sched_class;
extern const struct sched_class fair_sched_class;
extern const struct sched_class idle_sched_class;

static inline bool sched_stop_runnable(struct rq *rq)
{
	return rq->stop && task_on_rq_queued(rq->stop);
}

static inline bool sched_dl_runnable(struct rq *rq)
{
	return rq->dl.dl_nr_running > 0;
}

static inline bool sched_rt_runnable(struct rq *rq)
{
	return rq->rt.rt_queued > 0;
}

static inline bool sched_fair_runnable(struct rq *rq)
{
	return rq->cfs.nr_running > 0;
}

extern struct task_struct *pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf);
extern struct task_struct *pick_next_task_idle(struct rq *rq);

#define SCA_CHECK		0x01
#define SCA_MIGRATE_DISABLE	0x02
#define SCA_MIGRATE_ENABLE	0x04
#define SCA_USER		0x08

#ifdef CONFIG_SMP

extern void update_group_capacity(struct sched_domain *sd, int cpu);

extern void trigger_load_balance(struct rq *rq);

extern void set_cpus_allowed_common(struct task_struct *p, const struct cpumask *new_mask, u32 flags);

static inline struct task_struct *get_push_task(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	lockdep_assert_rq_held(rq);

	if (rq->push_busy)
		return NULL;

	if (p->nr_cpus_allowed == 1)
		return NULL;

	if (p->migration_disabled)
		return NULL;

	rq->push_busy = true;
	return get_task_struct(p);
}

extern int push_cpu_stop(void *arg);

#endif

#ifdef CONFIG_CPU_IDLE
static inline void idle_set_state(struct rq *rq,
				  struct cpuidle_state *idle_state)
{
	rq->idle_state = idle_state;
}

static inline struct cpuidle_state *idle_get_state(struct rq *rq)
{
	SCHED_WARN_ON(!rcu_read_lock_held());

	return rq->idle_state;
}
#else
static inline void idle_set_state(struct rq *rq,
				  struct cpuidle_state *idle_state)
{
}

static inline struct cpuidle_state *idle_get_state(struct rq *rq)
{
	return NULL;
}
#endif

extern void schedule_idle(void);

extern void sysrq_sched_debug_show(void);
extern void sched_init_granularity(void);
extern void update_max_interval(void);

extern void init_sched_dl_class(void);
extern void init_sched_rt_class(void);
extern void init_sched_fair_class(void);

extern void reweight_task(struct task_struct *p, int prio);

extern void resched_curr(struct rq *rq);
extern void resched_cpu(int cpu);

extern struct rt_bandwidth def_rt_bandwidth;
extern void init_rt_bandwidth(struct rt_bandwidth *rt_b, u64 period, u64 runtime);
extern bool sched_rt_bandwidth_account(struct rt_rq *rt_rq);

extern void init_dl_bandwidth(struct dl_bandwidth *dl_b, u64 period, u64 runtime);
extern void init_dl_task_timer(struct sched_dl_entity *dl_se);
extern void init_dl_inactive_task_timer(struct sched_dl_entity *dl_se);

#define BW_SHIFT		20
#define BW_UNIT			(1 << BW_SHIFT)
#define RATIO_SHIFT		8
#define MAX_BW_BITS		(64 - BW_SHIFT)
#define MAX_BW			((1ULL << MAX_BW_BITS) - 1)
unsigned long to_ratio(u64 period, u64 runtime);

extern void init_entity_runnable_average(struct sched_entity *se);
extern void post_init_entity_util_avg(struct task_struct *p);

#ifdef CONFIG_NO_HZ_FULL
extern bool sched_can_stop_tick(struct rq *rq);
extern int __init sched_tick_offload_init(void);

static inline void sched_update_tick_dependency(struct rq *rq)
{
	int cpu = cpu_of(rq);

	if (!tick_nohz_full_cpu(cpu))
		return;

	if (sched_can_stop_tick(rq))
		tick_nohz_dep_clear_cpu(cpu, TICK_DEP_BIT_SCHED);
	else
		tick_nohz_dep_set_cpu(cpu, TICK_DEP_BIT_SCHED);
}
#else
static inline int sched_tick_offload_init(void) { return 0; }
static inline void sched_update_tick_dependency(struct rq *rq) { }
#endif

static inline void add_nr_running(struct rq *rq, unsigned count)
{
	unsigned prev_nr = rq->nr_running;

	rq->nr_running = prev_nr + count;
	if (trace_sched_update_nr_running_tp_enabled()) {
		call_trace_sched_update_nr_running(rq, count);
	}

#ifdef CONFIG_SMP
	if (prev_nr < 2 && rq->nr_running >= 2) {
		if (!READ_ONCE(rq->rd->overload))
			WRITE_ONCE(rq->rd->overload, 1);
	}
#endif

	sched_update_tick_dependency(rq);
}

static inline void sub_nr_running(struct rq *rq, unsigned count)
{
	rq->nr_running -= count;
	if (trace_sched_update_nr_running_tp_enabled()) {
		call_trace_sched_update_nr_running(rq, -count);
	}

	/* Check if we still need preemption */
	sched_update_tick_dependency(rq);
}

extern void activate_task(struct rq *rq, struct task_struct *p, int flags);
extern void deactivate_task(struct rq *rq, struct task_struct *p, int flags);

extern void check_preempt_curr(struct rq *rq, struct task_struct *p, int flags);

extern const_debug unsigned int sysctl_sched_nr_migrate;
extern const_debug unsigned int sysctl_sched_migration_cost;

#ifdef CONFIG_SCHED_DEBUG
extern unsigned int sysctl_sched_latency;
extern unsigned int sysctl_sched_min_granularity;
extern unsigned int sysctl_sched_idle_min_granularity;
extern unsigned int sysctl_sched_wakeup_granularity;
extern int sysctl_resched_latency_warn_ms;
extern int sysctl_resched_latency_warn_once;

extern unsigned int sysctl_sched_tunable_scaling;

extern unsigned int sysctl_numa_balancing_scan_delay;
extern unsigned int sysctl_numa_balancing_scan_period_min;
extern unsigned int sysctl_numa_balancing_scan_period_max;
extern unsigned int sysctl_numa_balancing_scan_size;
#endif

#ifdef CONFIG_SCHED_HRTICK

static inline int hrtick_enabled(struct rq *rq)
{
	if (!cpu_active(cpu_of(rq)))
		return 0;
	return hrtimer_is_hres_active(&rq->hrtick_timer);
}

static inline int hrtick_enabled_fair(struct rq *rq)
{
	if (!sched_feat(HRTICK))
		return 0;
	return hrtick_enabled(rq);
}

static inline int hrtick_enabled_dl(struct rq *rq)
{
	if (!sched_feat(HRTICK_DL))
		return 0;
	return hrtick_enabled(rq);
}

void hrtick_start(struct rq *rq, u64 delay);

#else

static inline int hrtick_enabled_fair(struct rq *rq)
{
	return 0;
}

static inline int hrtick_enabled_dl(struct rq *rq)
{
	return 0;
}

static inline int hrtick_enabled(struct rq *rq)
{
	return 0;
}

#endif /* CONFIG_SCHED_HRTICK */

#ifndef arch_scale_freq_tick
static __always_inline
void arch_scale_freq_tick(void)
{
}
#endif

#ifndef arch_scale_freq_capacity
static __always_inline
unsigned long arch_scale_freq_capacity(int cpu)
{
	return SCHED_CAPACITY_SCALE;
}
#endif

#ifdef CONFIG_SCHED_DEBUG
static inline void double_rq_clock_clear_update(struct rq *rq1, struct rq *rq2)
{
	rq1->clock_update_flags &= (RQCF_REQ_SKIP|RQCF_ACT_SKIP);
	/* rq1 == rq2 for !CONFIG_SMP, so just clear RQCF_UPDATED once. */
#ifdef CONFIG_SMP
	rq2->clock_update_flags &= (RQCF_REQ_SKIP|RQCF_ACT_SKIP);
#endif
}
#else
static inline void double_rq_clock_clear_update(struct rq *rq1, struct rq *rq2) {}
#endif

#ifdef CONFIG_SMP

static inline bool rq_order_less(struct rq *rq1, struct rq *rq2)
{
#ifdef CONFIG_SCHED_CORE
	/*
	if (rq1->core->cpu < rq2->core->cpu)
		return true;
	if (rq1->core->cpu > rq2->core->cpu)
		return false;

	/*
#endif
	return rq1->cpu < rq2->cpu;
}

extern void double_rq_lock(struct rq *rq1, struct rq *rq2);

#ifdef CONFIG_PREEMPTION

static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
	__releases(this_rq->lock)
	__acquires(busiest->lock)
	__acquires(this_rq->lock)
{
	raw_spin_rq_unlock(this_rq);
	double_rq_lock(this_rq, busiest);

	return 1;
}

#else
static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
	__releases(this_rq->lock)
	__acquires(busiest->lock)
	__acquires(this_rq->lock)
{
	if (__rq_lockp(this_rq) == __rq_lockp(busiest) ||
	    likely(raw_spin_rq_trylock(busiest))) {
		double_rq_clock_clear_update(this_rq, busiest);
		return 0;
	}

	if (rq_order_less(this_rq, busiest)) {
		raw_spin_rq_lock_nested(busiest, SINGLE_DEPTH_NESTING);
		double_rq_clock_clear_update(this_rq, busiest);
		return 0;
	}

	raw_spin_rq_unlock(this_rq);
	double_rq_lock(this_rq, busiest);

	return 1;
}

#endif /* CONFIG_PREEMPTION */

static inline int double_lock_balance(struct rq *this_rq, struct rq *busiest)
{
	lockdep_assert_irqs_disabled();

	return _double_lock_balance(this_rq, busiest);
}

static inline void double_unlock_balance(struct rq *this_rq, struct rq *busiest)
	__releases(busiest->lock)
{
	if (__rq_lockp(this_rq) != __rq_lockp(busiest))
		raw_spin_rq_unlock(busiest);
	lock_set_subclass(&__rq_lockp(this_rq)->dep_map, 0, _RET_IP_);
}

static inline void double_lock(spinlock_t *l1, spinlock_t *l2)
{
	if (l1 > l2)
		swap(l1, l2);

	spin_lock(l1);
	spin_lock_nested(l2, SINGLE_DEPTH_NESTING);
}

static inline void double_lock_irq(spinlock_t *l1, spinlock_t *l2)
{
	if (l1 > l2)
		swap(l1, l2);

	spin_lock_irq(l1);
	spin_lock_nested(l2, SINGLE_DEPTH_NESTING);
}

static inline void double_raw_lock(raw_spinlock_t *l1, raw_spinlock_t *l2)
{
	if (l1 > l2)
		swap(l1, l2);

	raw_spin_lock(l1);
	raw_spin_lock_nested(l2, SINGLE_DEPTH_NESTING);
}

static inline void double_rq_unlock(struct rq *rq1, struct rq *rq2)
	__releases(rq1->lock)
	__releases(rq2->lock)
{
	if (__rq_lockp(rq1) != __rq_lockp(rq2))
		raw_spin_rq_unlock(rq2);
	else
		__release(rq2->lock);
	raw_spin_rq_unlock(rq1);
}

extern void set_rq_online (struct rq *rq);
extern void set_rq_offline(struct rq *rq);
extern bool sched_smp_initialized;

#else /* CONFIG_SMP */

static inline void double_rq_lock(struct rq *rq1, struct rq *rq2)
	__acquires(rq1->lock)
	__acquires(rq2->lock)
{
	BUG_ON(!irqs_disabled());
	BUG_ON(rq1 != rq2);
	raw_spin_rq_lock(rq1);
	__acquire(rq2->lock);	/* Fake it out ;) */
	double_rq_clock_clear_update(rq1, rq2);
}

static inline void double_rq_unlock(struct rq *rq1, struct rq *rq2)
	__releases(rq1->lock)
	__releases(rq2->lock)
{
	BUG_ON(rq1 != rq2);
	raw_spin_rq_unlock(rq1);
	__release(rq2->lock);
}

#endif

extern struct sched_entity *__pick_first_entity(struct cfs_rq *cfs_rq);
extern struct sched_entity *__pick_last_entity(struct cfs_rq *cfs_rq);

#ifdef	CONFIG_SCHED_DEBUG
extern bool sched_debug_verbose;

extern void print_cfs_stats(struct seq_file *m, int cpu);
extern void print_rt_stats(struct seq_file *m, int cpu);
extern void print_dl_stats(struct seq_file *m, int cpu);
extern void print_cfs_rq(struct seq_file *m, int cpu, struct cfs_rq *cfs_rq);
extern void print_rt_rq(struct seq_file *m, int cpu, struct rt_rq *rt_rq);
extern void print_dl_rq(struct seq_file *m, int cpu, struct dl_rq *dl_rq);

extern void resched_latency_warn(int cpu, u64 latency);
#ifdef CONFIG_NUMA_BALANCING
extern void
show_numa_stats(struct task_struct *p, struct seq_file *m);
extern void
print_numa_stats(struct seq_file *m, int node, unsigned long tsf,
	unsigned long tpf, unsigned long gsf, unsigned long gpf);
#endif /* CONFIG_NUMA_BALANCING */
#else
static inline void resched_latency_warn(int cpu, u64 latency) {}
#endif /* CONFIG_SCHED_DEBUG */

extern void init_cfs_rq(struct cfs_rq *cfs_rq);
extern void init_rt_rq(struct rt_rq *rt_rq);
extern void init_dl_rq(struct dl_rq *dl_rq);

extern void cfs_bandwidth_usage_inc(void);
extern void cfs_bandwidth_usage_dec(void);

#ifdef CONFIG_NO_HZ_COMMON
#define NOHZ_BALANCE_KICK_BIT	0
#define NOHZ_STATS_KICK_BIT	1
#define NOHZ_NEWILB_KICK_BIT	2
#define NOHZ_NEXT_KICK_BIT	3

#define NOHZ_BALANCE_KICK	BIT(NOHZ_BALANCE_KICK_BIT)
#define NOHZ_STATS_KICK		BIT(NOHZ_STATS_KICK_BIT)
#define NOHZ_NEWILB_KICK	BIT(NOHZ_NEWILB_KICK_BIT)
#define NOHZ_NEXT_KICK		BIT(NOHZ_NEXT_KICK_BIT)

#define NOHZ_KICK_MASK	(NOHZ_BALANCE_KICK | NOHZ_STATS_KICK | NOHZ_NEXT_KICK)

#define nohz_flags(cpu)	(&cpu_rq(cpu)->nohz_flags)

extern void nohz_balance_exit_idle(struct rq *rq);
#else
static inline void nohz_balance_exit_idle(struct rq *rq) { }
#endif

#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
extern void nohz_run_idle_balance(int cpu);
#else
static inline void nohz_run_idle_balance(int cpu) { }
#endif

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
struct irqtime {
	u64			total;
	u64			tick_delta;
	u64			irq_start_time;
	struct u64_stats_sync	sync;
};

DECLARE_PER_CPU(struct irqtime, cpu_irqtime);

static inline u64 irq_time_read(int cpu)
{
	struct irqtime *irqtime = &per_cpu(cpu_irqtime, cpu);
	unsigned int seq;
	u64 total;

	do {
		seq = __u64_stats_fetch_begin(&irqtime->sync);
		total = irqtime->total;
	} while (__u64_stats_fetch_retry(&irqtime->sync, seq));

	return total;
}
#endif /* CONFIG_IRQ_TIME_ACCOUNTING */

#ifdef CONFIG_CPU_FREQ
DECLARE_PER_CPU(struct update_util_data __rcu *, cpufreq_update_util_data);

static inline void cpufreq_update_util(struct rq *rq, unsigned int flags)
{
	struct update_util_data *data;

	data = rcu_dereference_sched(*per_cpu_ptr(&cpufreq_update_util_data,
						  cpu_of(rq)));
	if (data)
		data->func(data, rq_clock(rq), flags);
}
#else
static inline void cpufreq_update_util(struct rq *rq, unsigned int flags) {}
#endif /* CONFIG_CPU_FREQ */

#ifdef arch_scale_freq_capacity
# ifndef arch_scale_freq_invariant
#  define arch_scale_freq_invariant()	true
# endif
#else
# define arch_scale_freq_invariant()	false
#endif

#ifdef CONFIG_SMP
static inline unsigned long capacity_orig_of(int cpu)
{
	return cpu_rq(cpu)->cpu_capacity_orig;
}

enum cpu_util_type {
	FREQUENCY_UTIL,
	ENERGY_UTIL,
};

unsigned long effective_cpu_util(int cpu, unsigned long util_cfs,
				 enum cpu_util_type type,
				 struct task_struct *p);

static inline unsigned long cpu_bw_dl(struct rq *rq)
{
	return (rq->dl.running_bw * SCHED_CAPACITY_SCALE) >> BW_SHIFT;
}

static inline unsigned long cpu_util_dl(struct rq *rq)
{
	return READ_ONCE(rq->avg_dl.util_avg);
}

static inline unsigned long cpu_util_cfs(int cpu)
{
	struct cfs_rq *cfs_rq;
	unsigned long util;

	cfs_rq = &cpu_rq(cpu)->cfs;
	util = READ_ONCE(cfs_rq->avg.util_avg);

	if (sched_feat(UTIL_EST)) {
		util = max_t(unsigned long, util,
			     READ_ONCE(cfs_rq->avg.util_est.enqueued));
	}

	return min(util, capacity_orig_of(cpu));
}

static inline unsigned long cpu_util_rt(struct rq *rq)
{
	return READ_ONCE(rq->avg_rt.util_avg);
}
#endif

#ifdef CONFIG_UCLAMP_TASK
unsigned long uclamp_eff_value(struct task_struct *p, enum uclamp_id clamp_id);

static __always_inline
unsigned long uclamp_rq_util_with(struct rq *rq, unsigned long util,
				  struct task_struct *p)
{
	unsigned long min_util = 0;
	unsigned long max_util = 0;

	if (!static_branch_likely(&sched_uclamp_used))
		return util;

	if (p) {
		min_util = uclamp_eff_value(p, UCLAMP_MIN);
		max_util = uclamp_eff_value(p, UCLAMP_MAX);

		/*
		if (rq->uclamp_flags & UCLAMP_FLAG_IDLE)
			goto out;
	}

	min_util = max_t(unsigned long, min_util, READ_ONCE(rq->uclamp[UCLAMP_MIN].value));
	max_util = max_t(unsigned long, max_util, READ_ONCE(rq->uclamp[UCLAMP_MAX].value));
out:
	/*
	if (unlikely(min_util >= max_util))
		return min_util;

	return clamp(util, min_util, max_util);
}

static inline bool uclamp_rq_is_capped(struct rq *rq)
{
	unsigned long rq_util;
	unsigned long max_util;

	if (!static_branch_likely(&sched_uclamp_used))
		return false;

	rq_util = cpu_util_cfs(cpu_of(rq)) + cpu_util_rt(rq);
	max_util = READ_ONCE(rq->uclamp[UCLAMP_MAX].value);

	return max_util != SCHED_CAPACITY_SCALE && rq_util >= max_util;
}

static inline bool uclamp_is_used(void)
{
	return static_branch_likely(&sched_uclamp_used);
}
#else /* CONFIG_UCLAMP_TASK */
static inline
unsigned long uclamp_rq_util_with(struct rq *rq, unsigned long util,
				  struct task_struct *p)
{
	return util;
}

static inline bool uclamp_rq_is_capped(struct rq *rq) { return false; }

static inline bool uclamp_is_used(void)
{
	return false;
}
#endif /* CONFIG_UCLAMP_TASK */

#ifdef CONFIG_HAVE_SCHED_AVG_IRQ
static inline unsigned long cpu_util_irq(struct rq *rq)
{
	return rq->avg_irq.util_avg;
}

static inline
unsigned long scale_irq_capacity(unsigned long util, unsigned long irq, unsigned long max)
{
	util *= (max - irq);
	util /= max;

	return util;

}
#else
static inline unsigned long cpu_util_irq(struct rq *rq)
{
	return 0;
}

static inline
unsigned long scale_irq_capacity(unsigned long util, unsigned long irq, unsigned long max)
{
	return util;
}
#endif

#if defined(CONFIG_ENERGY_MODEL) && defined(CONFIG_CPU_FREQ_GOV_SCHEDUTIL)

#define perf_domain_span(pd) (to_cpumask(((pd)->em_pd->cpus)))

DECLARE_STATIC_KEY_FALSE(sched_energy_present);

static inline bool sched_energy_enabled(void)
{
	return static_branch_unlikely(&sched_energy_present);
}

#else /* ! (CONFIG_ENERGY_MODEL && CONFIG_CPU_FREQ_GOV_SCHEDUTIL) */

#define perf_domain_span(pd) NULL
static inline bool sched_energy_enabled(void) { return false; }

#endif /* CONFIG_ENERGY_MODEL && CONFIG_CPU_FREQ_GOV_SCHEDUTIL */

#ifdef CONFIG_MEMBARRIER
static inline void membarrier_switch_mm(struct rq *rq,
					struct mm_struct *prev_mm,
					struct mm_struct *next_mm)
{
	int membarrier_state;

	if (prev_mm == next_mm)
		return;

	membarrier_state = atomic_read(&next_mm->membarrier_state);
	if (READ_ONCE(rq->membarrier_state) == membarrier_state)
		return;

	WRITE_ONCE(rq->membarrier_state, membarrier_state);
}
#else
static inline void membarrier_switch_mm(struct rq *rq,
					struct mm_struct *prev_mm,
					struct mm_struct *next_mm)
{
}
#endif

#ifdef CONFIG_SMP
static inline bool is_per_cpu_kthread(struct task_struct *p)
{
	if (!(p->flags & PF_KTHREAD))
		return false;

	if (p->nr_cpus_allowed != 1)
		return false;

	return true;
}
#endif

extern void swake_up_all_locked(struct swait_queue_head *q);
extern void __prepare_to_swait(struct swait_queue_head *q, struct swait_queue *wait);

#ifdef CONFIG_PREEMPT_DYNAMIC
extern int preempt_dynamic_mode;
extern int sched_dynamic_mode(const char *str);
extern void sched_dynamic_update(int mode);
#endif

#endif /* _KERNEL_SCHED_SCHED_H */
