#include "cgroup-internal.h"

#include <linux/sched/cputime.h>

static DEFINE_SPINLOCK(cgroup_rstat_lock);
static DEFINE_PER_CPU(raw_spinlock_t, cgroup_rstat_cpu_lock);

static void cgroup_base_stat_flush(struct cgroup *cgrp, int cpu);

static struct cgroup_rstat_cpu *cgroup_rstat_cpu(struct cgroup *cgrp, int cpu)
{
	return per_cpu_ptr(cgrp->rstat_cpu, cpu);
}

void cgroup_rstat_updated(struct cgroup *cgrp, int cpu)
{
	raw_spinlock_t *cpu_lock = per_cpu_ptr(&cgroup_rstat_cpu_lock, cpu);
	unsigned long flags;

	/*
	if (data_race(cgroup_rstat_cpu(cgrp, cpu)->updated_next))
		return;

	raw_spin_lock_irqsave(cpu_lock, flags);

	/* put @cgrp and all ancestors on the corresponding updated lists */
	while (true) {
		struct cgroup_rstat_cpu *rstatc = cgroup_rstat_cpu(cgrp, cpu);
		struct cgroup *parent = cgroup_parent(cgrp);
		struct cgroup_rstat_cpu *prstatc;

		/*
		if (rstatc->updated_next)
			break;

		/* Root has no parent to link it to, but mark it busy */
		if (!parent) {
			rstatc->updated_next = cgrp;
			break;
		}

		prstatc = cgroup_rstat_cpu(parent, cpu);
		rstatc->updated_next = prstatc->updated_children;
		prstatc->updated_children = cgrp;

		cgrp = parent;
	}

	raw_spin_unlock_irqrestore(cpu_lock, flags);
}

static struct cgroup *cgroup_rstat_cpu_pop_updated(struct cgroup *pos,
						   struct cgroup *root, int cpu)
{
	struct cgroup_rstat_cpu *rstatc;
	struct cgroup *parent;

	if (pos == root)
		return NULL;

	/*
	if (!pos) {
		pos = root;
		/* return NULL if this subtree is not on-list */
		if (!cgroup_rstat_cpu(pos, cpu)->updated_next)
			return NULL;
	} else {
		pos = cgroup_parent(pos);
	}

	/* walk down to the first leaf */
	while (true) {
		rstatc = cgroup_rstat_cpu(pos, cpu);
		if (rstatc->updated_children == pos)
			break;
		pos = rstatc->updated_children;
	}

	/*
	parent = cgroup_parent(pos);
	if (parent) {
		struct cgroup_rstat_cpu *prstatc;
		struct cgroup **nextp;

		prstatc = cgroup_rstat_cpu(parent, cpu);
		nextp = &prstatc->updated_children;
		while (*nextp != pos) {
			struct cgroup_rstat_cpu *nrstatc;

			nrstatc = cgroup_rstat_cpu(*nextp, cpu);
			WARN_ON_ONCE(*nextp == parent);
			nextp = &nrstatc->updated_next;
		}
		*nextp = rstatc->updated_next;
	}

	rstatc->updated_next = NULL;
	return pos;
}

static void cgroup_rstat_flush_locked(struct cgroup *cgrp, bool may_sleep)
	__releases(&cgroup_rstat_lock) __acquires(&cgroup_rstat_lock)
{
	int cpu;

	lockdep_assert_held(&cgroup_rstat_lock);

	for_each_possible_cpu(cpu) {
		raw_spinlock_t *cpu_lock = per_cpu_ptr(&cgroup_rstat_cpu_lock,
						       cpu);
		struct cgroup *pos = NULL;
		unsigned long flags;

		/*
		raw_spin_lock_irqsave(cpu_lock, flags);
		while ((pos = cgroup_rstat_cpu_pop_updated(pos, cgrp, cpu))) {
			struct cgroup_subsys_state *css;

			cgroup_base_stat_flush(pos, cpu);

			rcu_read_lock();
			list_for_each_entry_rcu(css, &pos->rstat_css_list,
						rstat_css_node)
				css->ss->css_rstat_flush(css, cpu);
			rcu_read_unlock();
		}
		raw_spin_unlock_irqrestore(cpu_lock, flags);

		/* if @may_sleep, play nice and yield if necessary */
		if (may_sleep && (need_resched() ||
				  spin_needbreak(&cgroup_rstat_lock))) {
			spin_unlock_irq(&cgroup_rstat_lock);
			if (!cond_resched())
				cpu_relax();
			spin_lock_irq(&cgroup_rstat_lock);
		}
	}
}

void cgroup_rstat_flush(struct cgroup *cgrp)
{
	might_sleep();

	spin_lock_irq(&cgroup_rstat_lock);
	cgroup_rstat_flush_locked(cgrp, true);
	spin_unlock_irq(&cgroup_rstat_lock);
}

void cgroup_rstat_flush_irqsafe(struct cgroup *cgrp)
{
	unsigned long flags;

	spin_lock_irqsave(&cgroup_rstat_lock, flags);
	cgroup_rstat_flush_locked(cgrp, false);
	spin_unlock_irqrestore(&cgroup_rstat_lock, flags);
}

void cgroup_rstat_flush_hold(struct cgroup *cgrp)
	__acquires(&cgroup_rstat_lock)
{
	might_sleep();
	spin_lock_irq(&cgroup_rstat_lock);
	cgroup_rstat_flush_locked(cgrp, true);
}

void cgroup_rstat_flush_release(void)
	__releases(&cgroup_rstat_lock)
{
	spin_unlock_irq(&cgroup_rstat_lock);
}

int cgroup_rstat_init(struct cgroup *cgrp)
{
	int cpu;

	/* the root cgrp has rstat_cpu preallocated */
	if (!cgrp->rstat_cpu) {
		cgrp->rstat_cpu = alloc_percpu(struct cgroup_rstat_cpu);
		if (!cgrp->rstat_cpu)
			return -ENOMEM;
	}

	/* ->updated_children list is self terminated */
	for_each_possible_cpu(cpu) {
		struct cgroup_rstat_cpu *rstatc = cgroup_rstat_cpu(cgrp, cpu);

		rstatc->updated_children = cgrp;
		u64_stats_init(&rstatc->bsync);
	}

	return 0;
}

void cgroup_rstat_exit(struct cgroup *cgrp)
{
	int cpu;

	cgroup_rstat_flush(cgrp);

	/* sanity check */
	for_each_possible_cpu(cpu) {
		struct cgroup_rstat_cpu *rstatc = cgroup_rstat_cpu(cgrp, cpu);

		if (WARN_ON_ONCE(rstatc->updated_children != cgrp) ||
		    WARN_ON_ONCE(rstatc->updated_next))
			return;
	}

	free_percpu(cgrp->rstat_cpu);
	cgrp->rstat_cpu = NULL;
}

void __init cgroup_rstat_boot(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		raw_spin_lock_init(per_cpu_ptr(&cgroup_rstat_cpu_lock, cpu));
}

static void cgroup_base_stat_add(struct cgroup_base_stat *dst_bstat,
				 struct cgroup_base_stat *src_bstat)
{
	dst_bstat->cputime.utime += src_bstat->cputime.utime;
	dst_bstat->cputime.stime += src_bstat->cputime.stime;
	dst_bstat->cputime.sum_exec_runtime += src_bstat->cputime.sum_exec_runtime;
#ifdef CONFIG_SCHED_CORE
	dst_bstat->forceidle_sum += src_bstat->forceidle_sum;
#endif
}

static void cgroup_base_stat_sub(struct cgroup_base_stat *dst_bstat,
				 struct cgroup_base_stat *src_bstat)
{
	dst_bstat->cputime.utime -= src_bstat->cputime.utime;
	dst_bstat->cputime.stime -= src_bstat->cputime.stime;
	dst_bstat->cputime.sum_exec_runtime -= src_bstat->cputime.sum_exec_runtime;
#ifdef CONFIG_SCHED_CORE
	dst_bstat->forceidle_sum -= src_bstat->forceidle_sum;
#endif
}

static void cgroup_base_stat_flush(struct cgroup *cgrp, int cpu)
{
	struct cgroup_rstat_cpu *rstatc = cgroup_rstat_cpu(cgrp, cpu);
	struct cgroup *parent = cgroup_parent(cgrp);
	struct cgroup_base_stat delta;
	unsigned seq;

	/* Root-level stats are sourced from system-wide CPU stats */
	if (!parent)
		return;

	/* fetch the current per-cpu values */
	do {
		seq = __u64_stats_fetch_begin(&rstatc->bsync);
		delta = rstatc->bstat;
	} while (__u64_stats_fetch_retry(&rstatc->bsync, seq));

	/* propagate percpu delta to global */
	cgroup_base_stat_sub(&delta, &rstatc->last_bstat);
	cgroup_base_stat_add(&cgrp->bstat, &delta);
	cgroup_base_stat_add(&rstatc->last_bstat, &delta);

	/* propagate global delta to parent (unless that's root) */
	if (cgroup_parent(parent)) {
		delta = cgrp->bstat;
		cgroup_base_stat_sub(&delta, &cgrp->last_bstat);
		cgroup_base_stat_add(&parent->bstat, &delta);
		cgroup_base_stat_add(&cgrp->last_bstat, &delta);
	}
}

static struct cgroup_rstat_cpu *
cgroup_base_stat_cputime_account_begin(struct cgroup *cgrp, unsigned long *flags)
{
	struct cgroup_rstat_cpu *rstatc;

	rstatc = get_cpu_ptr(cgrp->rstat_cpu);
	return rstatc;
}

static void cgroup_base_stat_cputime_account_end(struct cgroup *cgrp,
						 struct cgroup_rstat_cpu *rstatc,
						 unsigned long flags)
{
	u64_stats_update_end_irqrestore(&rstatc->bsync, flags);
	cgroup_rstat_updated(cgrp, smp_processor_id());
	put_cpu_ptr(rstatc);
}

void __cgroup_account_cputime(struct cgroup *cgrp, u64 delta_exec)
{
	struct cgroup_rstat_cpu *rstatc;
	unsigned long flags;

	rstatc = cgroup_base_stat_cputime_account_begin(cgrp, &flags);
	rstatc->bstat.cputime.sum_exec_runtime += delta_exec;
	cgroup_base_stat_cputime_account_end(cgrp, rstatc, flags);
}

void __cgroup_account_cputime_field(struct cgroup *cgrp,
				    enum cpu_usage_stat index, u64 delta_exec)
{
	struct cgroup_rstat_cpu *rstatc;
	unsigned long flags;

	rstatc = cgroup_base_stat_cputime_account_begin(cgrp, &flags);

	switch (index) {
	case CPUTIME_USER:
	case CPUTIME_NICE:
		rstatc->bstat.cputime.utime += delta_exec;
		break;
	case CPUTIME_SYSTEM:
	case CPUTIME_IRQ:
	case CPUTIME_SOFTIRQ:
		rstatc->bstat.cputime.stime += delta_exec;
		break;
#ifdef CONFIG_SCHED_CORE
	case CPUTIME_FORCEIDLE:
		rstatc->bstat.forceidle_sum += delta_exec;
		break;
#endif
	default:
		break;
	}

	cgroup_base_stat_cputime_account_end(cgrp, rstatc, flags);
}

static void root_cgroup_cputime(struct cgroup_base_stat *bstat)
{
	struct task_cputime *cputime = &bstat->cputime;
	int i;

	cputime->stime = 0;
	cputime->utime = 0;
	cputime->sum_exec_runtime = 0;
	for_each_possible_cpu(i) {
		struct kernel_cpustat kcpustat;
		u64 *cpustat = kcpustat.cpustat;
		u64 user = 0;
		u64 sys = 0;

		kcpustat_cpu_fetch(&kcpustat, i);

		user += cpustat[CPUTIME_USER];
		user += cpustat[CPUTIME_NICE];
		cputime->utime += user;

		sys += cpustat[CPUTIME_SYSTEM];
		sys += cpustat[CPUTIME_IRQ];
		sys += cpustat[CPUTIME_SOFTIRQ];
		cputime->stime += sys;

		cputime->sum_exec_runtime += user;
		cputime->sum_exec_runtime += sys;
		cputime->sum_exec_runtime += cpustat[CPUTIME_STEAL];

#ifdef CONFIG_SCHED_CORE
		bstat->forceidle_sum += cpustat[CPUTIME_FORCEIDLE];
#endif
	}
}

void cgroup_base_stat_cputime_show(struct seq_file *seq)
{
	struct cgroup *cgrp = seq_css(seq)->cgroup;
	u64 usage, utime, stime;
	struct cgroup_base_stat bstat;
#ifdef CONFIG_SCHED_CORE
	u64 forceidle_time;
#endif

	if (cgroup_parent(cgrp)) {
		cgroup_rstat_flush_hold(cgrp);
		usage = cgrp->bstat.cputime.sum_exec_runtime;
		cputime_adjust(&cgrp->bstat.cputime, &cgrp->prev_cputime,
			       &utime, &stime);
#ifdef CONFIG_SCHED_CORE
		forceidle_time = cgrp->bstat.forceidle_sum;
#endif
		cgroup_rstat_flush_release();
	} else {
		root_cgroup_cputime(&bstat);
		usage = bstat.cputime.sum_exec_runtime;
		utime = bstat.cputime.utime;
		stime = bstat.cputime.stime;
#ifdef CONFIG_SCHED_CORE
		forceidle_time = bstat.forceidle_sum;
#endif
	}

	do_div(usage, NSEC_PER_USEC);
	do_div(utime, NSEC_PER_USEC);
	do_div(stime, NSEC_PER_USEC);
#ifdef CONFIG_SCHED_CORE
	do_div(forceidle_time, NSEC_PER_USEC);
#endif

	seq_printf(seq, "usage_usec %llu\n"
		   "user_usec %llu\n"
		   "system_usec %llu\n",
		   usage, utime, stime);

#ifdef CONFIG_SCHED_CORE
	seq_printf(seq, "core_sched.force_idle_usec %llu\n", forceidle_time);
#endif
}
