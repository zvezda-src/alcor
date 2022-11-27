
#define pr_fmt(fmt) "rcu: " fmt

#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate_wait.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/srcu.h>

#include "rcu.h"
#include "rcu_segcblist.h"

#define DEFAULT_SRCU_EXP_HOLDOFF (25 * 1000)
static ulong exp_holdoff = DEFAULT_SRCU_EXP_HOLDOFF;
module_param(exp_holdoff, ulong, 0444);

static ulong counter_wrap_check = (ULONG_MAX >> 2);
module_param(counter_wrap_check, ulong, 0444);

#define SRCU_SIZING_NONE	0
#define SRCU_SIZING_INIT	1
#define SRCU_SIZING_TORTURE	2
#define SRCU_SIZING_AUTO	3
#define SRCU_SIZING_CONTEND	0x10
#define SRCU_SIZING_IS(x) ((convert_to_big & ~SRCU_SIZING_CONTEND) == x)
#define SRCU_SIZING_IS_NONE() (SRCU_SIZING_IS(SRCU_SIZING_NONE))
#define SRCU_SIZING_IS_INIT() (SRCU_SIZING_IS(SRCU_SIZING_INIT))
#define SRCU_SIZING_IS_TORTURE() (SRCU_SIZING_IS(SRCU_SIZING_TORTURE))
#define SRCU_SIZING_IS_CONTEND() (convert_to_big & SRCU_SIZING_CONTEND)
static int convert_to_big = SRCU_SIZING_AUTO;
module_param(convert_to_big, int, 0444);

static int big_cpu_lim __read_mostly = 128;
module_param(big_cpu_lim, int, 0444);

static int small_contention_lim __read_mostly = 100;
module_param(small_contention_lim, int, 0444);

static LIST_HEAD(srcu_boot_list);
static bool __read_mostly srcu_init_done;

static void srcu_invoke_callbacks(struct work_struct *work);
static void srcu_reschedule(struct srcu_struct *ssp, unsigned long delay);
static void process_srcu(struct work_struct *work);
static void srcu_delay_timer(struct timer_list *t);

#define spin_lock_rcu_node(p)							\
do {										\
	spin_lock(&ACCESS_PRIVATE(p, lock));					\
	smp_mb__after_unlock_lock();						\
} while (0)

#define spin_unlock_rcu_node(p) spin_unlock(&ACCESS_PRIVATE(p, lock))

#define spin_lock_irq_rcu_node(p)						\
do {										\
	spin_lock_irq(&ACCESS_PRIVATE(p, lock));				\
	smp_mb__after_unlock_lock();						\
} while (0)

#define spin_unlock_irq_rcu_node(p)						\
	spin_unlock_irq(&ACCESS_PRIVATE(p, lock))

#define spin_lock_irqsave_rcu_node(p, flags)					\
do {										\
	spin_lock_irqsave(&ACCESS_PRIVATE(p, lock), flags);			\
	smp_mb__after_unlock_lock();						\
} while (0)

#define spin_trylock_irqsave_rcu_node(p, flags)					\
({										\
	bool ___locked = spin_trylock_irqsave(&ACCESS_PRIVATE(p, lock), flags);	\
										\
	if (___locked)								\
		smp_mb__after_unlock_lock();					\
	___locked;								\
})

#define spin_unlock_irqrestore_rcu_node(p, flags)				\
	spin_unlock_irqrestore(&ACCESS_PRIVATE(p, lock), flags)			\

static void init_srcu_struct_data(struct srcu_struct *ssp)
{
	int cpu;
	struct srcu_data *sdp;

	/*
	WARN_ON_ONCE(ARRAY_SIZE(sdp->srcu_lock_count) !=
		     ARRAY_SIZE(sdp->srcu_unlock_count));
	for_each_possible_cpu(cpu) {
		sdp = per_cpu_ptr(ssp->sda, cpu);
		spin_lock_init(&ACCESS_PRIVATE(sdp, lock));
		rcu_segcblist_init(&sdp->srcu_cblist);
		sdp->srcu_cblist_invoking = false;
		sdp->srcu_gp_seq_needed = ssp->srcu_gp_seq;
		sdp->srcu_gp_seq_needed_exp = ssp->srcu_gp_seq;
		sdp->mynode = NULL;
		sdp->cpu = cpu;
		INIT_WORK(&sdp->work, srcu_invoke_callbacks);
		timer_setup(&sdp->delay_work, srcu_delay_timer, 0);
		sdp->ssp = ssp;
	}
}

#define SRCU_SNP_INIT_SEQ		0x2

static inline bool srcu_invl_snp_seq(unsigned long s)
{
	return rcu_seq_state(s) == SRCU_SNP_INIT_SEQ;
}

static bool init_srcu_struct_nodes(struct srcu_struct *ssp, gfp_t gfp_flags)
{
	int cpu;
	int i;
	int level = 0;
	int levelspread[RCU_NUM_LVLS];
	struct srcu_data *sdp;
	struct srcu_node *snp;
	struct srcu_node *snp_first;

	/* Initialize geometry if it has not already been initialized. */
	rcu_init_geometry();
	ssp->node = kcalloc(rcu_num_nodes, sizeof(*ssp->node), gfp_flags);
	if (!ssp->node)
		return false;

	/* Work out the overall tree geometry. */
	ssp->level[0] = &ssp->node[0];
	for (i = 1; i < rcu_num_lvls; i++)
		ssp->level[i] = ssp->level[i - 1] + num_rcu_lvl[i - 1];
	rcu_init_levelspread(levelspread, num_rcu_lvl);

	/* Each pass through this loop initializes one srcu_node structure. */
	srcu_for_each_node_breadth_first(ssp, snp) {
		spin_lock_init(&ACCESS_PRIVATE(snp, lock));
		WARN_ON_ONCE(ARRAY_SIZE(snp->srcu_have_cbs) !=
			     ARRAY_SIZE(snp->srcu_data_have_cbs));
		for (i = 0; i < ARRAY_SIZE(snp->srcu_have_cbs); i++) {
			snp->srcu_have_cbs[i] = SRCU_SNP_INIT_SEQ;
			snp->srcu_data_have_cbs[i] = 0;
		}
		snp->srcu_gp_seq_needed_exp = SRCU_SNP_INIT_SEQ;
		snp->grplo = -1;
		snp->grphi = -1;
		if (snp == &ssp->node[0]) {
			/* Root node, special case. */
			snp->srcu_parent = NULL;
			continue;
		}

		/* Non-root node. */
		if (snp == ssp->level[level + 1])
			level++;
		snp->srcu_parent = ssp->level[level - 1] +
				   (snp - ssp->level[level]) /
				   levelspread[level - 1];
	}

	/*
	level = rcu_num_lvls - 1;
	snp_first = ssp->level[level];
	for_each_possible_cpu(cpu) {
		sdp = per_cpu_ptr(ssp->sda, cpu);
		sdp->mynode = &snp_first[cpu / levelspread[level]];
		for (snp = sdp->mynode; snp != NULL; snp = snp->srcu_parent) {
			if (snp->grplo < 0)
				snp->grplo = cpu;
			snp->grphi = cpu;
		}
		sdp->grpmask = 1 << (cpu - sdp->mynode->grplo);
	}
	smp_store_release(&ssp->srcu_size_state, SRCU_SIZE_WAIT_BARRIER);
	return true;
}

static int init_srcu_struct_fields(struct srcu_struct *ssp, bool is_static)
{
	ssp->srcu_size_state = SRCU_SIZE_SMALL;
	ssp->node = NULL;
	mutex_init(&ssp->srcu_cb_mutex);
	mutex_init(&ssp->srcu_gp_mutex);
	ssp->srcu_idx = 0;
	ssp->srcu_gp_seq = 0;
	ssp->srcu_barrier_seq = 0;
	mutex_init(&ssp->srcu_barrier_mutex);
	atomic_set(&ssp->srcu_barrier_cpu_cnt, 0);
	INIT_DELAYED_WORK(&ssp->work, process_srcu);
	ssp->sda_is_static = is_static;
	if (!is_static)
		ssp->sda = alloc_percpu(struct srcu_data);
	if (!ssp->sda)
		return -ENOMEM;
	init_srcu_struct_data(ssp);
	ssp->srcu_gp_seq_needed_exp = 0;
	ssp->srcu_last_gp_end = ktime_get_mono_fast_ns();
	if (READ_ONCE(ssp->srcu_size_state) == SRCU_SIZE_SMALL && SRCU_SIZING_IS_INIT()) {
		if (!init_srcu_struct_nodes(ssp, GFP_ATOMIC)) {
			if (!ssp->sda_is_static) {
				free_percpu(ssp->sda);
				ssp->sda = NULL;
				return -ENOMEM;
			}
		} else {
			WRITE_ONCE(ssp->srcu_size_state, SRCU_SIZE_BIG);
		}
	}
	smp_store_release(&ssp->srcu_gp_seq_needed, 0); /* Init done. */
	return 0;
}

#ifdef CONFIG_DEBUG_LOCK_ALLOC

int __init_srcu_struct(struct srcu_struct *ssp, const char *name,
		       struct lock_class_key *key)
{
	/* Don't re-initialize a lock while it is held. */
	debug_check_no_locks_freed((void *)ssp, sizeof(*ssp));
	lockdep_init_map(&ssp->dep_map, name, key, 0);
	spin_lock_init(&ACCESS_PRIVATE(ssp, lock));
	return init_srcu_struct_fields(ssp, false);
}
EXPORT_SYMBOL_GPL(__init_srcu_struct);

#else /* #ifdef CONFIG_DEBUG_LOCK_ALLOC */

int init_srcu_struct(struct srcu_struct *ssp)
{
	spin_lock_init(&ACCESS_PRIVATE(ssp, lock));
	return init_srcu_struct_fields(ssp, false);
}
EXPORT_SYMBOL_GPL(init_srcu_struct);

#endif /* #else #ifdef CONFIG_DEBUG_LOCK_ALLOC */

static void __srcu_transition_to_big(struct srcu_struct *ssp)
{
	lockdep_assert_held(&ACCESS_PRIVATE(ssp, lock));
	smp_store_release(&ssp->srcu_size_state, SRCU_SIZE_ALLOC);
}

static void srcu_transition_to_big(struct srcu_struct *ssp)
{
	unsigned long flags;

	/* Double-checked locking on ->srcu_size-state. */
	if (smp_load_acquire(&ssp->srcu_size_state) != SRCU_SIZE_SMALL)
		return;
	spin_lock_irqsave_rcu_node(ssp, flags);
	if (smp_load_acquire(&ssp->srcu_size_state) != SRCU_SIZE_SMALL) {
		spin_unlock_irqrestore_rcu_node(ssp, flags);
		return;
	}
	__srcu_transition_to_big(ssp);
	spin_unlock_irqrestore_rcu_node(ssp, flags);
}

static void spin_lock_irqsave_check_contention(struct srcu_struct *ssp)
{
	unsigned long j;

	if (!SRCU_SIZING_IS_CONTEND() || ssp->srcu_size_state)
		return;
	j = jiffies;
	if (ssp->srcu_size_jiffies != j) {
		ssp->srcu_size_jiffies = j;
		ssp->srcu_n_lock_retries = 0;
	}
	if (++ssp->srcu_n_lock_retries <= small_contention_lim)
		return;
	__srcu_transition_to_big(ssp);
}

static void spin_lock_irqsave_sdp_contention(struct srcu_data *sdp, unsigned long *flags)
{
	struct srcu_struct *ssp = sdp->ssp;

	if (spin_trylock_irqsave_rcu_node(sdp, *flags))
		return;
	spin_lock_irqsave_rcu_node(ssp, *flags);
	spin_lock_irqsave_check_contention(ssp);
	spin_unlock_irqrestore_rcu_node(ssp, *flags);
	spin_lock_irqsave_rcu_node(sdp, *flags);
}

static void spin_lock_irqsave_ssp_contention(struct srcu_struct *ssp, unsigned long *flags)
{
	if (spin_trylock_irqsave_rcu_node(ssp, *flags))
		return;
	spin_lock_irqsave_rcu_node(ssp, *flags);
	spin_lock_irqsave_check_contention(ssp);
}

static void check_init_srcu_struct(struct srcu_struct *ssp)
{
	unsigned long flags;

	/* The smp_load_acquire() pairs with the smp_store_release(). */
	if (!rcu_seq_state(smp_load_acquire(&ssp->srcu_gp_seq_needed))) /*^^^*/
		return; /* Already initialized. */
	spin_lock_irqsave_rcu_node(ssp, flags);
	if (!rcu_seq_state(ssp->srcu_gp_seq_needed)) {
		spin_unlock_irqrestore_rcu_node(ssp, flags);
		return;
	}
	init_srcu_struct_fields(ssp, true);
	spin_unlock_irqrestore_rcu_node(ssp, flags);
}

static unsigned long srcu_readers_lock_idx(struct srcu_struct *ssp, int idx)
{
	int cpu;
	unsigned long sum = 0;

	for_each_possible_cpu(cpu) {
		struct srcu_data *cpuc = per_cpu_ptr(ssp->sda, cpu);

		sum += READ_ONCE(cpuc->srcu_lock_count[idx]);
	}
	return sum;
}

static unsigned long srcu_readers_unlock_idx(struct srcu_struct *ssp, int idx)
{
	int cpu;
	unsigned long sum = 0;

	for_each_possible_cpu(cpu) {
		struct srcu_data *cpuc = per_cpu_ptr(ssp->sda, cpu);

		sum += READ_ONCE(cpuc->srcu_unlock_count[idx]);
	}
	return sum;
}

static bool srcu_readers_active_idx_check(struct srcu_struct *ssp, int idx)
{
	unsigned long unlocks;

	unlocks = srcu_readers_unlock_idx(ssp, idx);

	/*
	smp_mb(); /* A */

	/*
	return srcu_readers_lock_idx(ssp, idx) == unlocks;
}

static bool srcu_readers_active(struct srcu_struct *ssp)
{
	int cpu;
	unsigned long sum = 0;

	for_each_possible_cpu(cpu) {
		struct srcu_data *cpuc = per_cpu_ptr(ssp->sda, cpu);

		sum += READ_ONCE(cpuc->srcu_lock_count[0]);
		sum += READ_ONCE(cpuc->srcu_lock_count[1]);
		sum -= READ_ONCE(cpuc->srcu_unlock_count[0]);
		sum -= READ_ONCE(cpuc->srcu_unlock_count[1]);
	}
	return sum;
}

#define SRCU_DEFAULT_RETRY_CHECK_DELAY		5

static ulong srcu_retry_check_delay = SRCU_DEFAULT_RETRY_CHECK_DELAY;
module_param(srcu_retry_check_delay, ulong, 0444);

#define SRCU_INTERVAL		1		// Base delay if no expedited GPs pending.
#define SRCU_MAX_INTERVAL	10		// Maximum incremental delay from slow readers.

#define SRCU_DEFAULT_MAX_NODELAY_PHASE_LO	3UL	// Lowmark on default per-GP-phase
							// no-delay instances.
#define SRCU_DEFAULT_MAX_NODELAY_PHASE_HI	1000UL	// Highmark on default per-GP-phase
							// no-delay instances.

#define SRCU_UL_CLAMP_LO(val, low)	((val) > (low) ? (val) : (low))
#define SRCU_UL_CLAMP_HI(val, high)	((val) < (high) ? (val) : (high))
#define SRCU_UL_CLAMP(val, low, high)	SRCU_UL_CLAMP_HI(SRCU_UL_CLAMP_LO((val), (low)), (high))
// per-GP-phase no-delay instances adjusted to allow non-sleeping poll upto
// one jiffies time duration. Mult by 2 is done to factor in the srcu_get_delay()
// called from process_srcu().
#define SRCU_DEFAULT_MAX_NODELAY_PHASE_ADJUSTED	\
	(2UL * USEC_PER_SEC / HZ / SRCU_DEFAULT_RETRY_CHECK_DELAY)

// Maximum per-GP-phase consecutive no-delay instances.
#define SRCU_DEFAULT_MAX_NODELAY_PHASE	\
	SRCU_UL_CLAMP(SRCU_DEFAULT_MAX_NODELAY_PHASE_ADJUSTED,	\
		      SRCU_DEFAULT_MAX_NODELAY_PHASE_LO,	\
		      SRCU_DEFAULT_MAX_NODELAY_PHASE_HI)

static ulong srcu_max_nodelay_phase = SRCU_DEFAULT_MAX_NODELAY_PHASE;
module_param(srcu_max_nodelay_phase, ulong, 0444);

// Maximum consecutive no-delay instances.
#define SRCU_DEFAULT_MAX_NODELAY	(SRCU_DEFAULT_MAX_NODELAY_PHASE > 100 ?	\
					 SRCU_DEFAULT_MAX_NODELAY_PHASE : 100)

static ulong srcu_max_nodelay = SRCU_DEFAULT_MAX_NODELAY;
module_param(srcu_max_nodelay, ulong, 0444);

static unsigned long srcu_get_delay(struct srcu_struct *ssp)
{
	unsigned long gpstart;
	unsigned long j;
	unsigned long jbase = SRCU_INTERVAL;

	if (ULONG_CMP_LT(READ_ONCE(ssp->srcu_gp_seq), READ_ONCE(ssp->srcu_gp_seq_needed_exp)))
		jbase = 0;
	if (rcu_seq_state(READ_ONCE(ssp->srcu_gp_seq))) {
		j = jiffies - 1;
		gpstart = READ_ONCE(ssp->srcu_gp_start);
		if (time_after(j, gpstart))
			jbase += j - gpstart;
		if (!jbase) {
			WRITE_ONCE(ssp->srcu_n_exp_nodelay, READ_ONCE(ssp->srcu_n_exp_nodelay) + 1);
			if (READ_ONCE(ssp->srcu_n_exp_nodelay) > srcu_max_nodelay_phase)
				jbase = 1;
		}
	}
	return jbase > SRCU_MAX_INTERVAL ? SRCU_MAX_INTERVAL : jbase;
}

void cleanup_srcu_struct(struct srcu_struct *ssp)
{
	int cpu;

	if (WARN_ON(!srcu_get_delay(ssp)))
		return; /* Just leak it! */
	if (WARN_ON(srcu_readers_active(ssp)))
		return; /* Just leak it! */
	flush_delayed_work(&ssp->work);
	for_each_possible_cpu(cpu) {
		struct srcu_data *sdp = per_cpu_ptr(ssp->sda, cpu);

		del_timer_sync(&sdp->delay_work);
		flush_work(&sdp->work);
		if (WARN_ON(rcu_segcblist_n_cbs(&sdp->srcu_cblist)))
			return; /* Forgot srcu_barrier(), so just leak it! */
	}
	if (WARN_ON(rcu_seq_state(READ_ONCE(ssp->srcu_gp_seq)) != SRCU_STATE_IDLE) ||
	    WARN_ON(rcu_seq_current(&ssp->srcu_gp_seq) != ssp->srcu_gp_seq_needed) ||
	    WARN_ON(srcu_readers_active(ssp))) {
		pr_info("%s: Active srcu_struct %p read state: %d gp state: %lu/%lu\n",
			__func__, ssp, rcu_seq_state(READ_ONCE(ssp->srcu_gp_seq)),
			rcu_seq_current(&ssp->srcu_gp_seq), ssp->srcu_gp_seq_needed);
		return; /* Caller forgot to stop doing call_srcu()? */
	}
	if (!ssp->sda_is_static) {
		free_percpu(ssp->sda);
		ssp->sda = NULL;
	}
	kfree(ssp->node);
	ssp->node = NULL;
	ssp->srcu_size_state = SRCU_SIZE_SMALL;
}
EXPORT_SYMBOL_GPL(cleanup_srcu_struct);

int __srcu_read_lock(struct srcu_struct *ssp)
{
	int idx;

	idx = READ_ONCE(ssp->srcu_idx) & 0x1;
	this_cpu_inc(ssp->sda->srcu_lock_count[idx]);
	smp_mb(); /* B */  /* Avoid leaking the critical section. */
	return idx;
}
EXPORT_SYMBOL_GPL(__srcu_read_lock);

void __srcu_read_unlock(struct srcu_struct *ssp, int idx)
{
	smp_mb(); /* C */  /* Avoid leaking the critical section. */
	this_cpu_inc(ssp->sda->srcu_unlock_count[idx]);
}
EXPORT_SYMBOL_GPL(__srcu_read_unlock);

static void srcu_gp_start(struct srcu_struct *ssp)
{
	struct srcu_data *sdp;
	int state;

	if (smp_load_acquire(&ssp->srcu_size_state) < SRCU_SIZE_WAIT_BARRIER)
		sdp = per_cpu_ptr(ssp->sda, 0);
	else
		sdp = this_cpu_ptr(ssp->sda);
	lockdep_assert_held(&ACCESS_PRIVATE(ssp, lock));
	WARN_ON_ONCE(ULONG_CMP_GE(ssp->srcu_gp_seq, ssp->srcu_gp_seq_needed));
	spin_lock_rcu_node(sdp);  /* Interrupts already disabled. */
	rcu_segcblist_advance(&sdp->srcu_cblist,
			      rcu_seq_current(&ssp->srcu_gp_seq));
	(void)rcu_segcblist_accelerate(&sdp->srcu_cblist,
				       rcu_seq_snap(&ssp->srcu_gp_seq));
	spin_unlock_rcu_node(sdp);  /* Interrupts remain disabled. */
	WRITE_ONCE(ssp->srcu_gp_start, jiffies);
	WRITE_ONCE(ssp->srcu_n_exp_nodelay, 0);
	smp_mb(); /* Order prior store to ->srcu_gp_seq_needed vs. GP start. */
	rcu_seq_start(&ssp->srcu_gp_seq);
	state = rcu_seq_state(ssp->srcu_gp_seq);
	WARN_ON_ONCE(state != SRCU_STATE_SCAN1);
}


static void srcu_delay_timer(struct timer_list *t)
{
	struct srcu_data *sdp = container_of(t, struct srcu_data, delay_work);

	queue_work_on(sdp->cpu, rcu_gp_wq, &sdp->work);
}

static void srcu_queue_delayed_work_on(struct srcu_data *sdp,
				       unsigned long delay)
{
	if (!delay) {
		queue_work_on(sdp->cpu, rcu_gp_wq, &sdp->work);
		return;
	}

	timer_reduce(&sdp->delay_work, jiffies + delay);
}

static void srcu_schedule_cbs_sdp(struct srcu_data *sdp, unsigned long delay)
{
	srcu_queue_delayed_work_on(sdp, delay);
}

static void srcu_schedule_cbs_snp(struct srcu_struct *ssp, struct srcu_node *snp,
				  unsigned long mask, unsigned long delay)
{
	int cpu;

	for (cpu = snp->grplo; cpu <= snp->grphi; cpu++) {
		if (!(mask & (1 << (cpu - snp->grplo))))
			continue;
		srcu_schedule_cbs_sdp(per_cpu_ptr(ssp->sda, cpu), delay);
	}
}

static void srcu_gp_end(struct srcu_struct *ssp)
{
	unsigned long cbdelay = 1;
	bool cbs;
	bool last_lvl;
	int cpu;
	unsigned long flags;
	unsigned long gpseq;
	int idx;
	unsigned long mask;
	struct srcu_data *sdp;
	unsigned long sgsne;
	struct srcu_node *snp;
	int ss_state;

	/* Prevent more than one additional grace period. */
	mutex_lock(&ssp->srcu_cb_mutex);

	/* End the current grace period. */
	spin_lock_irq_rcu_node(ssp);
	idx = rcu_seq_state(ssp->srcu_gp_seq);
	WARN_ON_ONCE(idx != SRCU_STATE_SCAN2);
	if (ULONG_CMP_LT(READ_ONCE(ssp->srcu_gp_seq), READ_ONCE(ssp->srcu_gp_seq_needed_exp)))
		cbdelay = 0;

	WRITE_ONCE(ssp->srcu_last_gp_end, ktime_get_mono_fast_ns());
	rcu_seq_end(&ssp->srcu_gp_seq);
	gpseq = rcu_seq_current(&ssp->srcu_gp_seq);
	if (ULONG_CMP_LT(ssp->srcu_gp_seq_needed_exp, gpseq))
		WRITE_ONCE(ssp->srcu_gp_seq_needed_exp, gpseq);
	spin_unlock_irq_rcu_node(ssp);
	mutex_unlock(&ssp->srcu_gp_mutex);
	/* A new grace period can start at this point.  But only one. */

	/* Initiate callback invocation as needed. */
	ss_state = smp_load_acquire(&ssp->srcu_size_state);
	if (ss_state < SRCU_SIZE_WAIT_BARRIER) {
		srcu_schedule_cbs_sdp(per_cpu_ptr(ssp->sda, 0), cbdelay);
	} else {
		idx = rcu_seq_ctr(gpseq) % ARRAY_SIZE(snp->srcu_have_cbs);
		srcu_for_each_node_breadth_first(ssp, snp) {
			spin_lock_irq_rcu_node(snp);
			cbs = false;
			last_lvl = snp >= ssp->level[rcu_num_lvls - 1];
			if (last_lvl)
				cbs = ss_state < SRCU_SIZE_BIG || snp->srcu_have_cbs[idx] == gpseq;
			snp->srcu_have_cbs[idx] = gpseq;
			rcu_seq_set_state(&snp->srcu_have_cbs[idx], 1);
			sgsne = snp->srcu_gp_seq_needed_exp;
			if (srcu_invl_snp_seq(sgsne) || ULONG_CMP_LT(sgsne, gpseq))
				WRITE_ONCE(snp->srcu_gp_seq_needed_exp, gpseq);
			if (ss_state < SRCU_SIZE_BIG)
				mask = ~0;
			else
				mask = snp->srcu_data_have_cbs[idx];
			snp->srcu_data_have_cbs[idx] = 0;
			spin_unlock_irq_rcu_node(snp);
			if (cbs)
				srcu_schedule_cbs_snp(ssp, snp, mask, cbdelay);
		}
	}

	/* Occasionally prevent srcu_data counter wrap. */
	if (!(gpseq & counter_wrap_check))
		for_each_possible_cpu(cpu) {
			sdp = per_cpu_ptr(ssp->sda, cpu);
			spin_lock_irqsave_rcu_node(sdp, flags);
			if (ULONG_CMP_GE(gpseq, sdp->srcu_gp_seq_needed + 100))
				sdp->srcu_gp_seq_needed = gpseq;
			if (ULONG_CMP_GE(gpseq, sdp->srcu_gp_seq_needed_exp + 100))
				sdp->srcu_gp_seq_needed_exp = gpseq;
			spin_unlock_irqrestore_rcu_node(sdp, flags);
		}

	/* Callback initiation done, allow grace periods after next. */
	mutex_unlock(&ssp->srcu_cb_mutex);

	/* Start a new grace period if needed. */
	spin_lock_irq_rcu_node(ssp);
	gpseq = rcu_seq_current(&ssp->srcu_gp_seq);
	if (!rcu_seq_state(gpseq) &&
	    ULONG_CMP_LT(gpseq, ssp->srcu_gp_seq_needed)) {
		srcu_gp_start(ssp);
		spin_unlock_irq_rcu_node(ssp);
		srcu_reschedule(ssp, 0);
	} else {
		spin_unlock_irq_rcu_node(ssp);
	}

	/* Transition to big if needed. */
	if (ss_state != SRCU_SIZE_SMALL && ss_state != SRCU_SIZE_BIG) {
		if (ss_state == SRCU_SIZE_ALLOC)
			init_srcu_struct_nodes(ssp, GFP_KERNEL);
		else
			smp_store_release(&ssp->srcu_size_state, ss_state + 1);
	}
}

static void srcu_funnel_exp_start(struct srcu_struct *ssp, struct srcu_node *snp,
				  unsigned long s)
{
	unsigned long flags;
	unsigned long sgsne;

	if (snp)
		for (; snp != NULL; snp = snp->srcu_parent) {
			sgsne = READ_ONCE(snp->srcu_gp_seq_needed_exp);
			if (rcu_seq_done(&ssp->srcu_gp_seq, s) ||
			    (!srcu_invl_snp_seq(sgsne) && ULONG_CMP_GE(sgsne, s)))
				return;
			spin_lock_irqsave_rcu_node(snp, flags);
			sgsne = snp->srcu_gp_seq_needed_exp;
			if (!srcu_invl_snp_seq(sgsne) && ULONG_CMP_GE(sgsne, s)) {
				spin_unlock_irqrestore_rcu_node(snp, flags);
				return;
			}
			WRITE_ONCE(snp->srcu_gp_seq_needed_exp, s);
			spin_unlock_irqrestore_rcu_node(snp, flags);
		}
	spin_lock_irqsave_ssp_contention(ssp, &flags);
	if (ULONG_CMP_LT(ssp->srcu_gp_seq_needed_exp, s))
		WRITE_ONCE(ssp->srcu_gp_seq_needed_exp, s);
	spin_unlock_irqrestore_rcu_node(ssp, flags);
}

static void srcu_funnel_gp_start(struct srcu_struct *ssp, struct srcu_data *sdp,
				 unsigned long s, bool do_norm)
{
	unsigned long flags;
	int idx = rcu_seq_ctr(s) % ARRAY_SIZE(sdp->mynode->srcu_have_cbs);
	unsigned long sgsne;
	struct srcu_node *snp;
	struct srcu_node *snp_leaf;
	unsigned long snp_seq;

	/* Ensure that snp node tree is fully initialized before traversing it */
	if (smp_load_acquire(&ssp->srcu_size_state) < SRCU_SIZE_WAIT_BARRIER)
		snp_leaf = NULL;
	else
		snp_leaf = sdp->mynode;

	if (snp_leaf)
		/* Each pass through the loop does one level of the srcu_node tree. */
		for (snp = snp_leaf; snp != NULL; snp = snp->srcu_parent) {
			if (rcu_seq_done(&ssp->srcu_gp_seq, s) && snp != snp_leaf)
				return; /* GP already done and CBs recorded. */
			spin_lock_irqsave_rcu_node(snp, flags);
			snp_seq = snp->srcu_have_cbs[idx];
			if (!srcu_invl_snp_seq(snp_seq) && ULONG_CMP_GE(snp_seq, s)) {
				if (snp == snp_leaf && snp_seq == s)
					snp->srcu_data_have_cbs[idx] |= sdp->grpmask;
				spin_unlock_irqrestore_rcu_node(snp, flags);
				if (snp == snp_leaf && snp_seq != s) {
					srcu_schedule_cbs_sdp(sdp, do_norm ? SRCU_INTERVAL : 0);
					return;
				}
				if (!do_norm)
					srcu_funnel_exp_start(ssp, snp, s);
				return;
			}
			snp->srcu_have_cbs[idx] = s;
			if (snp == snp_leaf)
				snp->srcu_data_have_cbs[idx] |= sdp->grpmask;
			sgsne = snp->srcu_gp_seq_needed_exp;
			if (!do_norm && (srcu_invl_snp_seq(sgsne) || ULONG_CMP_LT(sgsne, s)))
				WRITE_ONCE(snp->srcu_gp_seq_needed_exp, s);
			spin_unlock_irqrestore_rcu_node(snp, flags);
		}

	/* Top of tree, must ensure the grace period will be started. */
	spin_lock_irqsave_ssp_contention(ssp, &flags);
	if (ULONG_CMP_LT(ssp->srcu_gp_seq_needed, s)) {
		/*
		smp_store_release(&ssp->srcu_gp_seq_needed, s); /*^^^*/
	}
	if (!do_norm && ULONG_CMP_LT(ssp->srcu_gp_seq_needed_exp, s))
		WRITE_ONCE(ssp->srcu_gp_seq_needed_exp, s);

	/* If grace period not already done and none in progress, start it. */
	if (!rcu_seq_done(&ssp->srcu_gp_seq, s) &&
	    rcu_seq_state(ssp->srcu_gp_seq) == SRCU_STATE_IDLE) {
		WARN_ON_ONCE(ULONG_CMP_GE(ssp->srcu_gp_seq, ssp->srcu_gp_seq_needed));
		srcu_gp_start(ssp);

		// And how can that list_add() in the "else" clause
		// possibly be safe for concurrent execution?  Well,
		// it isn't.  And it does not have to be.  After all, it
		// can only be executed during early boot when there is only
		// the one boot CPU running with interrupts still disabled.
		if (likely(srcu_init_done))
			queue_delayed_work(rcu_gp_wq, &ssp->work,
					   !!srcu_get_delay(ssp));
		else if (list_empty(&ssp->work.work.entry))
			list_add(&ssp->work.work.entry, &srcu_boot_list);
	}
	spin_unlock_irqrestore_rcu_node(ssp, flags);
}

static bool try_check_zero(struct srcu_struct *ssp, int idx, int trycount)
{
	unsigned long curdelay;

	curdelay = !srcu_get_delay(ssp);

	for (;;) {
		if (srcu_readers_active_idx_check(ssp, idx))
			return true;
		if ((--trycount + curdelay) <= 0)
			return false;
		udelay(srcu_retry_check_delay);
	}
}

static void srcu_flip(struct srcu_struct *ssp)
{
	/*
	smp_mb(); /* E */  /* Pairs with B and C. */

	WRITE_ONCE(ssp->srcu_idx, ssp->srcu_idx + 1);

	/*
	smp_mb(); /* D */  /* Pairs with C. */
}

static bool srcu_might_be_idle(struct srcu_struct *ssp)
{
	unsigned long curseq;
	unsigned long flags;
	struct srcu_data *sdp;
	unsigned long t;
	unsigned long tlast;

	check_init_srcu_struct(ssp);
	/* If the local srcu_data structure has callbacks, not idle.  */
	sdp = raw_cpu_ptr(ssp->sda);
	spin_lock_irqsave_rcu_node(sdp, flags);
	if (rcu_segcblist_pend_cbs(&sdp->srcu_cblist)) {
		spin_unlock_irqrestore_rcu_node(sdp, flags);
		return false; /* Callbacks already present, so not idle. */
	}
	spin_unlock_irqrestore_rcu_node(sdp, flags);

	/*

	/* First, see if enough time has passed since the last GP. */
	t = ktime_get_mono_fast_ns();
	tlast = READ_ONCE(ssp->srcu_last_gp_end);
	if (exp_holdoff == 0 ||
	    time_in_range_open(t, tlast, tlast + exp_holdoff))
		return false; /* Too soon after last GP. */

	/* Next, check for probable idleness. */
	curseq = rcu_seq_current(&ssp->srcu_gp_seq);
	smp_mb(); /* Order ->srcu_gp_seq with ->srcu_gp_seq_needed. */
	if (ULONG_CMP_LT(curseq, READ_ONCE(ssp->srcu_gp_seq_needed)))
		return false; /* Grace period in progress, so not idle. */
	smp_mb(); /* Order ->srcu_gp_seq with prior access. */
	if (curseq != rcu_seq_current(&ssp->srcu_gp_seq))
		return false; /* GP # changed, so not idle. */
	return true; /* With reasonable probability, idle! */
}

static void srcu_leak_callback(struct rcu_head *rhp)
{
}

static unsigned long srcu_gp_start_if_needed(struct srcu_struct *ssp,
					     struct rcu_head *rhp, bool do_norm)
{
	unsigned long flags;
	int idx;
	bool needexp = false;
	bool needgp = false;
	unsigned long s;
	struct srcu_data *sdp;
	struct srcu_node *sdp_mynode;
	int ss_state;

	check_init_srcu_struct(ssp);
	idx = srcu_read_lock(ssp);
	ss_state = smp_load_acquire(&ssp->srcu_size_state);
	if (ss_state < SRCU_SIZE_WAIT_CALL)
		sdp = per_cpu_ptr(ssp->sda, 0);
	else
		sdp = raw_cpu_ptr(ssp->sda);
	spin_lock_irqsave_sdp_contention(sdp, &flags);
	if (rhp)
		rcu_segcblist_enqueue(&sdp->srcu_cblist, rhp);
	rcu_segcblist_advance(&sdp->srcu_cblist,
			      rcu_seq_current(&ssp->srcu_gp_seq));
	s = rcu_seq_snap(&ssp->srcu_gp_seq);
	(void)rcu_segcblist_accelerate(&sdp->srcu_cblist, s);
	if (ULONG_CMP_LT(sdp->srcu_gp_seq_needed, s)) {
		sdp->srcu_gp_seq_needed = s;
		needgp = true;
	}
	if (!do_norm && ULONG_CMP_LT(sdp->srcu_gp_seq_needed_exp, s)) {
		sdp->srcu_gp_seq_needed_exp = s;
		needexp = true;
	}
	spin_unlock_irqrestore_rcu_node(sdp, flags);

	/* Ensure that snp node tree is fully initialized before traversing it */
	if (ss_state < SRCU_SIZE_WAIT_BARRIER)
		sdp_mynode = NULL;
	else
		sdp_mynode = sdp->mynode;

	if (needgp)
		srcu_funnel_gp_start(ssp, sdp, s, do_norm);
	else if (needexp)
		srcu_funnel_exp_start(ssp, sdp_mynode, s);
	srcu_read_unlock(ssp, idx);
	return s;
}

static void __call_srcu(struct srcu_struct *ssp, struct rcu_head *rhp,
			rcu_callback_t func, bool do_norm)
{
	if (debug_rcu_head_queue(rhp)) {
		/* Probable double call_srcu(), so leak the callback. */
		WRITE_ONCE(rhp->func, srcu_leak_callback);
		WARN_ONCE(1, "call_srcu(): Leaked duplicate callback\n");
		return;
	}
	rhp->func = func;
	(void)srcu_gp_start_if_needed(ssp, rhp, do_norm);
}

void call_srcu(struct srcu_struct *ssp, struct rcu_head *rhp,
	       rcu_callback_t func)
{
	__call_srcu(ssp, rhp, func, true);
}
EXPORT_SYMBOL_GPL(call_srcu);

static void __synchronize_srcu(struct srcu_struct *ssp, bool do_norm)
{
	struct rcu_synchronize rcu;

	RCU_LOCKDEP_WARN(lockdep_is_held(ssp) ||
			 lock_is_held(&rcu_bh_lock_map) ||
			 lock_is_held(&rcu_lock_map) ||
			 lock_is_held(&rcu_sched_lock_map),
			 "Illegal synchronize_srcu() in same-type SRCU (or in RCU) read-side critical section");

	if (rcu_scheduler_active == RCU_SCHEDULER_INACTIVE)
		return;
	might_sleep();
	check_init_srcu_struct(ssp);
	init_completion(&rcu.completion);
	init_rcu_head_on_stack(&rcu.head);
	__call_srcu(ssp, &rcu.head, wakeme_after_rcu, do_norm);
	wait_for_completion(&rcu.completion);
	destroy_rcu_head_on_stack(&rcu.head);

	/*
	smp_mb();
}

void synchronize_srcu_expedited(struct srcu_struct *ssp)
{
	__synchronize_srcu(ssp, rcu_gp_is_normal());
}
EXPORT_SYMBOL_GPL(synchronize_srcu_expedited);

void synchronize_srcu(struct srcu_struct *ssp)
{
	if (srcu_might_be_idle(ssp) || rcu_gp_is_expedited())
		synchronize_srcu_expedited(ssp);
	else
		__synchronize_srcu(ssp, true);
}
EXPORT_SYMBOL_GPL(synchronize_srcu);

unsigned long get_state_synchronize_srcu(struct srcu_struct *ssp)
{
	// Any prior manipulation of SRCU-protected data must happen
	// before the load from ->srcu_gp_seq.
	smp_mb();
	return rcu_seq_snap(&ssp->srcu_gp_seq);
}
EXPORT_SYMBOL_GPL(get_state_synchronize_srcu);

unsigned long start_poll_synchronize_srcu(struct srcu_struct *ssp)
{
	return srcu_gp_start_if_needed(ssp, NULL, true);
}
EXPORT_SYMBOL_GPL(start_poll_synchronize_srcu);

bool poll_state_synchronize_srcu(struct srcu_struct *ssp, unsigned long cookie)
{
	if (!rcu_seq_done(&ssp->srcu_gp_seq, cookie))
		return false;
	// Ensure that the end of the SRCU grace period happens before
	// any subsequent code that the caller might execute.
	smp_mb(); // ^^^
	return true;
}
EXPORT_SYMBOL_GPL(poll_state_synchronize_srcu);

static void srcu_barrier_cb(struct rcu_head *rhp)
{
	struct srcu_data *sdp;
	struct srcu_struct *ssp;

	sdp = container_of(rhp, struct srcu_data, srcu_barrier_head);
	ssp = sdp->ssp;
	if (atomic_dec_and_test(&ssp->srcu_barrier_cpu_cnt))
		complete(&ssp->srcu_barrier_completion);
}

static void srcu_barrier_one_cpu(struct srcu_struct *ssp, struct srcu_data *sdp)
{
	spin_lock_irq_rcu_node(sdp);
	atomic_inc(&ssp->srcu_barrier_cpu_cnt);
	sdp->srcu_barrier_head.func = srcu_barrier_cb;
	debug_rcu_head_queue(&sdp->srcu_barrier_head);
	if (!rcu_segcblist_entrain(&sdp->srcu_cblist,
				   &sdp->srcu_barrier_head)) {
		debug_rcu_head_unqueue(&sdp->srcu_barrier_head);
		atomic_dec(&ssp->srcu_barrier_cpu_cnt);
	}
	spin_unlock_irq_rcu_node(sdp);
}

void srcu_barrier(struct srcu_struct *ssp)
{
	int cpu;
	int idx;
	unsigned long s = rcu_seq_snap(&ssp->srcu_barrier_seq);

	check_init_srcu_struct(ssp);
	mutex_lock(&ssp->srcu_barrier_mutex);
	if (rcu_seq_done(&ssp->srcu_barrier_seq, s)) {
		smp_mb(); /* Force ordering following return. */
		mutex_unlock(&ssp->srcu_barrier_mutex);
		return; /* Someone else did our work for us. */
	}
	rcu_seq_start(&ssp->srcu_barrier_seq);
	init_completion(&ssp->srcu_barrier_completion);

	/* Initial count prevents reaching zero until all CBs are posted. */
	atomic_set(&ssp->srcu_barrier_cpu_cnt, 1);

	idx = srcu_read_lock(ssp);
	if (smp_load_acquire(&ssp->srcu_size_state) < SRCU_SIZE_WAIT_BARRIER)
		srcu_barrier_one_cpu(ssp, per_cpu_ptr(ssp->sda, 0));
	else
		for_each_possible_cpu(cpu)
			srcu_barrier_one_cpu(ssp, per_cpu_ptr(ssp->sda, cpu));
	srcu_read_unlock(ssp, idx);

	/* Remove the initial count, at which point reaching zero can happen. */
	if (atomic_dec_and_test(&ssp->srcu_barrier_cpu_cnt))
		complete(&ssp->srcu_barrier_completion);
	wait_for_completion(&ssp->srcu_barrier_completion);

	rcu_seq_end(&ssp->srcu_barrier_seq);
	mutex_unlock(&ssp->srcu_barrier_mutex);
}
EXPORT_SYMBOL_GPL(srcu_barrier);

unsigned long srcu_batches_completed(struct srcu_struct *ssp)
{
	return READ_ONCE(ssp->srcu_idx);
}
EXPORT_SYMBOL_GPL(srcu_batches_completed);

static void srcu_advance_state(struct srcu_struct *ssp)
{
	int idx;

	mutex_lock(&ssp->srcu_gp_mutex);

	/*
	idx = rcu_seq_state(smp_load_acquire(&ssp->srcu_gp_seq)); /* ^^^ */
	if (idx == SRCU_STATE_IDLE) {
		spin_lock_irq_rcu_node(ssp);
		if (ULONG_CMP_GE(ssp->srcu_gp_seq, ssp->srcu_gp_seq_needed)) {
			WARN_ON_ONCE(rcu_seq_state(ssp->srcu_gp_seq));
			spin_unlock_irq_rcu_node(ssp);
			mutex_unlock(&ssp->srcu_gp_mutex);
			return;
		}
		idx = rcu_seq_state(READ_ONCE(ssp->srcu_gp_seq));
		if (idx == SRCU_STATE_IDLE)
			srcu_gp_start(ssp);
		spin_unlock_irq_rcu_node(ssp);
		if (idx != SRCU_STATE_IDLE) {
			mutex_unlock(&ssp->srcu_gp_mutex);
			return; /* Someone else started the grace period. */
		}
	}

	if (rcu_seq_state(READ_ONCE(ssp->srcu_gp_seq)) == SRCU_STATE_SCAN1) {
		idx = 1 ^ (ssp->srcu_idx & 1);
		if (!try_check_zero(ssp, idx, 1)) {
			mutex_unlock(&ssp->srcu_gp_mutex);
			return; /* readers present, retry later. */
		}
		srcu_flip(ssp);
		spin_lock_irq_rcu_node(ssp);
		rcu_seq_set_state(&ssp->srcu_gp_seq, SRCU_STATE_SCAN2);
		ssp->srcu_n_exp_nodelay = 0;
		spin_unlock_irq_rcu_node(ssp);
	}

	if (rcu_seq_state(READ_ONCE(ssp->srcu_gp_seq)) == SRCU_STATE_SCAN2) {

		/*
		idx = 1 ^ (ssp->srcu_idx & 1);
		if (!try_check_zero(ssp, idx, 2)) {
			mutex_unlock(&ssp->srcu_gp_mutex);
			return; /* readers present, retry later. */
		}
		ssp->srcu_n_exp_nodelay = 0;
		srcu_gp_end(ssp);  /* Releases ->srcu_gp_mutex. */
	}
}

static void srcu_invoke_callbacks(struct work_struct *work)
{
	long len;
	bool more;
	struct rcu_cblist ready_cbs;
	struct rcu_head *rhp;
	struct srcu_data *sdp;
	struct srcu_struct *ssp;

	sdp = container_of(work, struct srcu_data, work);

	ssp = sdp->ssp;
	rcu_cblist_init(&ready_cbs);
	spin_lock_irq_rcu_node(sdp);
	rcu_segcblist_advance(&sdp->srcu_cblist,
			      rcu_seq_current(&ssp->srcu_gp_seq));
	if (sdp->srcu_cblist_invoking ||
	    !rcu_segcblist_ready_cbs(&sdp->srcu_cblist)) {
		spin_unlock_irq_rcu_node(sdp);
		return;  /* Someone else on the job or nothing to do. */
	}

	/* We are on the job!  Extract and invoke ready callbacks. */
	sdp->srcu_cblist_invoking = true;
	rcu_segcblist_extract_done_cbs(&sdp->srcu_cblist, &ready_cbs);
	len = ready_cbs.len;
	spin_unlock_irq_rcu_node(sdp);
	rhp = rcu_cblist_dequeue(&ready_cbs);
	for (; rhp != NULL; rhp = rcu_cblist_dequeue(&ready_cbs)) {
		debug_rcu_head_unqueue(rhp);
		local_bh_disable();
		rhp->func(rhp);
		local_bh_enable();
	}
	WARN_ON_ONCE(ready_cbs.len);

	/*
	spin_lock_irq_rcu_node(sdp);
	rcu_segcblist_add_len(&sdp->srcu_cblist, -len);
	(void)rcu_segcblist_accelerate(&sdp->srcu_cblist,
				       rcu_seq_snap(&ssp->srcu_gp_seq));
	sdp->srcu_cblist_invoking = false;
	more = rcu_segcblist_ready_cbs(&sdp->srcu_cblist);
	spin_unlock_irq_rcu_node(sdp);
	if (more)
		srcu_schedule_cbs_sdp(sdp, 0);
}

static void srcu_reschedule(struct srcu_struct *ssp, unsigned long delay)
{
	bool pushgp = true;

	spin_lock_irq_rcu_node(ssp);
	if (ULONG_CMP_GE(ssp->srcu_gp_seq, ssp->srcu_gp_seq_needed)) {
		if (!WARN_ON_ONCE(rcu_seq_state(ssp->srcu_gp_seq))) {
			/* All requests fulfilled, time to go idle. */
			pushgp = false;
		}
	} else if (!rcu_seq_state(ssp->srcu_gp_seq)) {
		/* Outstanding request and no GP.  Start one. */
		srcu_gp_start(ssp);
	}
	spin_unlock_irq_rcu_node(ssp);

	if (pushgp)
		queue_delayed_work(rcu_gp_wq, &ssp->work, delay);
}

static void process_srcu(struct work_struct *work)
{
	unsigned long curdelay;
	unsigned long j;
	struct srcu_struct *ssp;

	ssp = container_of(work, struct srcu_struct, work.work);

	srcu_advance_state(ssp);
	curdelay = srcu_get_delay(ssp);
	if (curdelay) {
		WRITE_ONCE(ssp->reschedule_count, 0);
	} else {
		j = jiffies;
		if (READ_ONCE(ssp->reschedule_jiffies) == j) {
			WRITE_ONCE(ssp->reschedule_count, READ_ONCE(ssp->reschedule_count) + 1);
			if (READ_ONCE(ssp->reschedule_count) > srcu_max_nodelay)
				curdelay = 1;
		} else {
			WRITE_ONCE(ssp->reschedule_count, 1);
			WRITE_ONCE(ssp->reschedule_jiffies, j);
		}
	}
	srcu_reschedule(ssp, curdelay);
}

void srcutorture_get_gp_data(enum rcutorture_type test_type,
			     struct srcu_struct *ssp, int *flags,
			     unsigned long *gp_seq)
{
	if (test_type != SRCU_FLAVOR)
		return;
}
EXPORT_SYMBOL_GPL(srcutorture_get_gp_data);

static const char * const srcu_size_state_name[] = {
	"SRCU_SIZE_SMALL",
	"SRCU_SIZE_ALLOC",
	"SRCU_SIZE_WAIT_BARRIER",
	"SRCU_SIZE_WAIT_CALL",
	"SRCU_SIZE_WAIT_CBS1",
	"SRCU_SIZE_WAIT_CBS2",
	"SRCU_SIZE_WAIT_CBS3",
	"SRCU_SIZE_WAIT_CBS4",
	"SRCU_SIZE_BIG",
	"SRCU_SIZE_???",
};

void srcu_torture_stats_print(struct srcu_struct *ssp, char *tt, char *tf)
{
	int cpu;
	int idx;
	unsigned long s0 = 0, s1 = 0;
	int ss_state = READ_ONCE(ssp->srcu_size_state);
	int ss_state_idx = ss_state;

	idx = ssp->srcu_idx & 0x1;
	if (ss_state < 0 || ss_state >= ARRAY_SIZE(srcu_size_state_name))
		ss_state_idx = ARRAY_SIZE(srcu_size_state_name) - 1;
	pr_alert("%s%s Tree SRCU g%ld state %d (%s)",
		 tt, tf, rcu_seq_current(&ssp->srcu_gp_seq), ss_state,
		 srcu_size_state_name[ss_state_idx]);
	if (!ssp->sda) {
		// Called after cleanup_srcu_struct(), perhaps.
		pr_cont(" No per-CPU srcu_data structures (->sda == NULL).\n");
	} else {
		pr_cont(" per-CPU(idx=%d):", idx);
		for_each_possible_cpu(cpu) {
			unsigned long l0, l1;
			unsigned long u0, u1;
			long c0, c1;
			struct srcu_data *sdp;

			sdp = per_cpu_ptr(ssp->sda, cpu);
			u0 = data_race(sdp->srcu_unlock_count[!idx]);
			u1 = data_race(sdp->srcu_unlock_count[idx]);

			/*
			smp_rmb();

			l0 = data_race(sdp->srcu_lock_count[!idx]);
			l1 = data_race(sdp->srcu_lock_count[idx]);

			c0 = l0 - u0;
			c1 = l1 - u1;
			pr_cont(" %d(%ld,%ld %c)",
				cpu, c0, c1,
				"C."[rcu_segcblist_empty(&sdp->srcu_cblist)]);
			s0 += c0;
			s1 += c1;
		}
		pr_cont(" T(%ld,%ld)\n", s0, s1);
	}
	if (SRCU_SIZING_IS_TORTURE())
		srcu_transition_to_big(ssp);
}
EXPORT_SYMBOL_GPL(srcu_torture_stats_print);

static int __init srcu_bootup_announce(void)
{
	pr_info("Hierarchical SRCU implementation.\n");
	if (exp_holdoff != DEFAULT_SRCU_EXP_HOLDOFF)
		pr_info("\tNon-default auto-expedite holdoff of %lu ns.\n", exp_holdoff);
	if (srcu_retry_check_delay != SRCU_DEFAULT_RETRY_CHECK_DELAY)
		pr_info("\tNon-default retry check delay of %lu us.\n", srcu_retry_check_delay);
	if (srcu_max_nodelay != SRCU_DEFAULT_MAX_NODELAY)
		pr_info("\tNon-default max no-delay of %lu.\n", srcu_max_nodelay);
	pr_info("\tMax phase no-delay instances is %lu.\n", srcu_max_nodelay_phase);
	return 0;
}
early_initcall(srcu_bootup_announce);

void __init srcu_init(void)
{
	struct srcu_struct *ssp;

	/* Decide on srcu_struct-size strategy. */
	if (SRCU_SIZING_IS(SRCU_SIZING_AUTO)) {
		if (nr_cpu_ids >= big_cpu_lim) {
			convert_to_big = SRCU_SIZING_INIT; // Don't bother waiting for contention.
			pr_info("%s: Setting srcu_struct sizes to big.\n", __func__);
		} else {
			convert_to_big = SRCU_SIZING_NONE | SRCU_SIZING_CONTEND;
			pr_info("%s: Setting srcu_struct sizes based on contention.\n", __func__);
		}
	}

	/*
	srcu_init_done = true;
	while (!list_empty(&srcu_boot_list)) {
		ssp = list_first_entry(&srcu_boot_list, struct srcu_struct,
				      work.work.entry);
		list_del_init(&ssp->work.work.entry);
		if (SRCU_SIZING_IS(SRCU_SIZING_INIT) && ssp->srcu_size_state == SRCU_SIZE_SMALL)
			ssp->srcu_size_state = SRCU_SIZE_ALLOC;
		queue_work(rcu_gp_wq, &ssp->work.work);
	}
}

#ifdef CONFIG_MODULES

static int srcu_module_coming(struct module *mod)
{
	int i;
	struct srcu_struct **sspp = mod->srcu_struct_ptrs;
	int ret;

	for (i = 0; i < mod->num_srcu_structs; i++) {
		ret = init_srcu_struct(*(sspp++));
		if (WARN_ON_ONCE(ret))
			return ret;
	}
	return 0;
}

static void srcu_module_going(struct module *mod)
{
	int i;
	struct srcu_struct **sspp = mod->srcu_struct_ptrs;

	for (i = 0; i < mod->num_srcu_structs; i++)
		cleanup_srcu_struct(*(sspp++));
}

static int srcu_module_notify(struct notifier_block *self,
			      unsigned long val, void *data)
{
	struct module *mod = data;
	int ret = 0;

	switch (val) {
	case MODULE_STATE_COMING:
		ret = srcu_module_coming(mod);
		break;
	case MODULE_STATE_GOING:
		srcu_module_going(mod);
		break;
	default:
		break;
	}
	return ret;
}

static struct notifier_block srcu_module_nb = {
	.notifier_call = srcu_module_notify,
	.priority = 0,
};

static __init int init_srcu_module_notifier(void)
{
	int ret;

	ret = register_module_notifier(&srcu_module_nb);
	if (ret)
		pr_warn("Failed to register srcu module notifier\n");
	return ret;
}
late_initcall(init_srcu_module_notifier);

#endif /* #ifdef CONFIG_MODULES */
