
#include "../locking/rtmutex_common.h"

static bool rcu_rdp_is_offloaded(struct rcu_data *rdp)
{
	/*
	RCU_LOCKDEP_WARN(
		!(lockdep_is_held(&rcu_state.barrier_mutex) ||
		  (IS_ENABLED(CONFIG_HOTPLUG_CPU) && lockdep_is_cpus_held()) ||
		  rcu_lockdep_is_held_nocb(rdp) ||
		  (rdp == this_cpu_ptr(&rcu_data) &&
		   !(IS_ENABLED(CONFIG_PREEMPT_COUNT) && preemptible())) ||
		  rcu_current_is_nocb_kthread(rdp)),
		"Unsafe read of RCU_NOCB offloaded state"
	);

	return rcu_segcblist_is_offloaded(&rdp->cblist);
}

static void __init rcu_bootup_announce_oddness(void)
{
	if (IS_ENABLED(CONFIG_RCU_TRACE))
		pr_info("\tRCU event tracing is enabled.\n");
	if ((IS_ENABLED(CONFIG_64BIT) && RCU_FANOUT != 64) ||
	    (!IS_ENABLED(CONFIG_64BIT) && RCU_FANOUT != 32))
		pr_info("\tCONFIG_RCU_FANOUT set to non-default value of %d.\n",
			RCU_FANOUT);
	if (rcu_fanout_exact)
		pr_info("\tHierarchical RCU autobalancing is disabled.\n");
	if (IS_ENABLED(CONFIG_PROVE_RCU))
		pr_info("\tRCU lockdep checking is enabled.\n");
	if (IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD))
		pr_info("\tRCU strict (and thus non-scalable) grace periods are enabled.\n");
	if (RCU_NUM_LVLS >= 4)
		pr_info("\tFour(or more)-level hierarchy is enabled.\n");
	if (RCU_FANOUT_LEAF != 16)
		pr_info("\tBuild-time adjustment of leaf fanout to %d.\n",
			RCU_FANOUT_LEAF);
	if (rcu_fanout_leaf != RCU_FANOUT_LEAF)
		pr_info("\tBoot-time adjustment of leaf fanout to %d.\n",
			rcu_fanout_leaf);
	if (nr_cpu_ids != NR_CPUS)
		pr_info("\tRCU restricting CPUs from NR_CPUS=%d to nr_cpu_ids=%u.\n", NR_CPUS, nr_cpu_ids);
#ifdef CONFIG_RCU_BOOST
	pr_info("\tRCU priority boosting: priority %d delay %d ms.\n",
		kthread_prio, CONFIG_RCU_BOOST_DELAY);
#endif
	if (blimit != DEFAULT_RCU_BLIMIT)
		pr_info("\tBoot-time adjustment of callback invocation limit to %ld.\n", blimit);
	if (qhimark != DEFAULT_RCU_QHIMARK)
		pr_info("\tBoot-time adjustment of callback high-water mark to %ld.\n", qhimark);
	if (qlowmark != DEFAULT_RCU_QLOMARK)
		pr_info("\tBoot-time adjustment of callback low-water mark to %ld.\n", qlowmark);
	if (qovld != DEFAULT_RCU_QOVLD)
		pr_info("\tBoot-time adjustment of callback overload level to %ld.\n", qovld);
	if (jiffies_till_first_fqs != ULONG_MAX)
		pr_info("\tBoot-time adjustment of first FQS scan delay to %ld jiffies.\n", jiffies_till_first_fqs);
	if (jiffies_till_next_fqs != ULONG_MAX)
		pr_info("\tBoot-time adjustment of subsequent FQS scan delay to %ld jiffies.\n", jiffies_till_next_fqs);
	if (jiffies_till_sched_qs != ULONG_MAX)
		pr_info("\tBoot-time adjustment of scheduler-enlistment delay to %ld jiffies.\n", jiffies_till_sched_qs);
	if (rcu_kick_kthreads)
		pr_info("\tKick kthreads if too-long grace period.\n");
	if (IS_ENABLED(CONFIG_DEBUG_OBJECTS_RCU_HEAD))
		pr_info("\tRCU callback double-/use-after-free debug is enabled.\n");
	if (gp_preinit_delay)
		pr_info("\tRCU debug GP pre-init slowdown %d jiffies.\n", gp_preinit_delay);
	if (gp_init_delay)
		pr_info("\tRCU debug GP init slowdown %d jiffies.\n", gp_init_delay);
	if (gp_cleanup_delay)
		pr_info("\tRCU debug GP cleanup slowdown %d jiffies.\n", gp_cleanup_delay);
	if (!use_softirq)
		pr_info("\tRCU_SOFTIRQ processing moved to rcuc kthreads.\n");
	if (IS_ENABLED(CONFIG_RCU_EQS_DEBUG))
		pr_info("\tRCU debug extended QS entry/exit.\n");
	rcupdate_announce_bootup_oddness();
}

#ifdef CONFIG_PREEMPT_RCU

static void rcu_report_exp_rnp(struct rcu_node *rnp, bool wake);
static void rcu_read_unlock_special(struct task_struct *t);

static void __init rcu_bootup_announce(void)
{
	pr_info("Preemptible hierarchical RCU implementation.\n");
	rcu_bootup_announce_oddness();
}

#define RCU_GP_TASKS	0x8
#define RCU_EXP_TASKS	0x4
#define RCU_GP_BLKD	0x2
#define RCU_EXP_BLKD	0x1

static void rcu_preempt_ctxt_queue(struct rcu_node *rnp, struct rcu_data *rdp)
	__releases(rnp->lock) /* But leaves rrupts disabled. */
{
	int blkd_state = (rnp->gp_tasks ? RCU_GP_TASKS : 0) +
			 (rnp->exp_tasks ? RCU_EXP_TASKS : 0) +
			 (rnp->qsmask & rdp->grpmask ? RCU_GP_BLKD : 0) +
			 (rnp->expmask & rdp->grpmask ? RCU_EXP_BLKD : 0);
	struct task_struct *t = current;

	raw_lockdep_assert_held_rcu_node(rnp);
	WARN_ON_ONCE(rdp->mynode != rnp);
	WARN_ON_ONCE(!rcu_is_leaf_node(rnp));
	/* RCU better not be waiting on newly onlined CPUs! */
	WARN_ON_ONCE(rnp->qsmaskinitnext & ~rnp->qsmaskinit & rnp->qsmask &
		     rdp->grpmask);

	/*
	switch (blkd_state) {
	case 0:
	case                RCU_EXP_TASKS:
	case                RCU_EXP_TASKS + RCU_GP_BLKD:
	case RCU_GP_TASKS:
	case RCU_GP_TASKS + RCU_EXP_TASKS:

		/*
		list_add(&t->rcu_node_entry, &rnp->blkd_tasks);
		break;

	case                                              RCU_EXP_BLKD:
	case                                RCU_GP_BLKD:
	case                                RCU_GP_BLKD + RCU_EXP_BLKD:
	case RCU_GP_TASKS +                               RCU_EXP_BLKD:
	case RCU_GP_TASKS +                 RCU_GP_BLKD + RCU_EXP_BLKD:
	case RCU_GP_TASKS + RCU_EXP_TASKS + RCU_GP_BLKD + RCU_EXP_BLKD:

		/*
		list_add_tail(&t->rcu_node_entry, &rnp->blkd_tasks);
		break;

	case                RCU_EXP_TASKS +               RCU_EXP_BLKD:
	case                RCU_EXP_TASKS + RCU_GP_BLKD + RCU_EXP_BLKD:
	case RCU_GP_TASKS + RCU_EXP_TASKS +               RCU_EXP_BLKD:

		/*
		list_add(&t->rcu_node_entry, rnp->exp_tasks);
		break;

	case RCU_GP_TASKS +                 RCU_GP_BLKD:
	case RCU_GP_TASKS + RCU_EXP_TASKS + RCU_GP_BLKD:

		/*
		list_add(&t->rcu_node_entry, rnp->gp_tasks);
		break;

	default:

		/* Yet another exercise in excessive paranoia. */
		WARN_ON_ONCE(1);
		break;
	}

	/*
	if (!rnp->gp_tasks && (blkd_state & RCU_GP_BLKD)) {
		WRITE_ONCE(rnp->gp_tasks, &t->rcu_node_entry);
		WARN_ON_ONCE(rnp->completedqs == rnp->gp_seq);
	}
	if (!rnp->exp_tasks && (blkd_state & RCU_EXP_BLKD))
		WRITE_ONCE(rnp->exp_tasks, &t->rcu_node_entry);
	WARN_ON_ONCE(!(blkd_state & RCU_GP_BLKD) !=
		     !(rnp->qsmask & rdp->grpmask));
	WARN_ON_ONCE(!(blkd_state & RCU_EXP_BLKD) !=
		     !(rnp->expmask & rdp->grpmask));
	raw_spin_unlock_rcu_node(rnp); /* interrupts remain disabled. */

	/*
	if (blkd_state & RCU_EXP_BLKD && rdp->cpu_no_qs.b.exp)
		rcu_report_exp_rdp(rdp);
	else
		WARN_ON_ONCE(rdp->cpu_no_qs.b.exp);
}

static void rcu_qs(void)
{
	RCU_LOCKDEP_WARN(preemptible(), "rcu_qs() invoked with preemption enabled!!!\n");
	if (__this_cpu_read(rcu_data.cpu_no_qs.b.norm)) {
		trace_rcu_grace_period(TPS("rcu_preempt"),
				       __this_cpu_read(rcu_data.gp_seq),
				       TPS("cpuqs"));
		__this_cpu_write(rcu_data.cpu_no_qs.b.norm, false);
		barrier(); /* Coordinate with rcu_flavor_sched_clock_irq(). */
		WRITE_ONCE(current->rcu_read_unlock_special.b.need_qs, false);
	}
}

void rcu_note_context_switch(bool preempt)
{
	struct task_struct *t = current;
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
	struct rcu_node *rnp;

	trace_rcu_utilization(TPS("Start context switch"));
	lockdep_assert_irqs_disabled();
	WARN_ONCE(!preempt && rcu_preempt_depth() > 0, "Voluntary context switch within RCU read-side critical section!");
	if (rcu_preempt_depth() > 0 &&
	    !t->rcu_read_unlock_special.b.blocked) {

		/* Possibly blocking in an RCU read-side critical section. */
		rnp = rdp->mynode;
		raw_spin_lock_rcu_node(rnp);
		t->rcu_read_unlock_special.b.blocked = true;
		t->rcu_blocked_node = rnp;

		/*
		WARN_ON_ONCE(!rcu_rdp_cpu_online(rdp));
		WARN_ON_ONCE(!list_empty(&t->rcu_node_entry));
		trace_rcu_preempt_task(rcu_state.name,
				       t->pid,
				       (rnp->qsmask & rdp->grpmask)
				       ? rnp->gp_seq
				       : rcu_seq_snap(&rnp->gp_seq));
		rcu_preempt_ctxt_queue(rnp, rdp);
	} else {
		rcu_preempt_deferred_qs(t);
	}

	/*
	rcu_qs();
	if (rdp->cpu_no_qs.b.exp)
		rcu_report_exp_rdp(rdp);
	rcu_tasks_qs(current, preempt);
	trace_rcu_utilization(TPS("End context switch"));
}
EXPORT_SYMBOL_GPL(rcu_note_context_switch);

static int rcu_preempt_blocked_readers_cgp(struct rcu_node *rnp)
{
	return READ_ONCE(rnp->gp_tasks) != NULL;
}

#define RCU_NEST_PMAX (INT_MAX / 2)

static void rcu_preempt_read_enter(void)
{
	WRITE_ONCE(current->rcu_read_lock_nesting, READ_ONCE(current->rcu_read_lock_nesting) + 1);
}

static int rcu_preempt_read_exit(void)
{
	int ret = READ_ONCE(current->rcu_read_lock_nesting) - 1;

	WRITE_ONCE(current->rcu_read_lock_nesting, ret);
	return ret;
}

static void rcu_preempt_depth_set(int val)
{
	WRITE_ONCE(current->rcu_read_lock_nesting, val);
}

void __rcu_read_lock(void)
{
	rcu_preempt_read_enter();
	if (IS_ENABLED(CONFIG_PROVE_LOCKING))
		WARN_ON_ONCE(rcu_preempt_depth() > RCU_NEST_PMAX);
	if (IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD) && rcu_state.gp_kthread)
		WRITE_ONCE(current->rcu_read_unlock_special.b.need_qs, true);
	barrier();  /* critical section after entry code. */
}
EXPORT_SYMBOL_GPL(__rcu_read_lock);

void __rcu_read_unlock(void)
{
	struct task_struct *t = current;

	barrier();  // critical section before exit code.
	if (rcu_preempt_read_exit() == 0) {
		barrier();  // critical-section exit before .s check.
		if (unlikely(READ_ONCE(t->rcu_read_unlock_special.s)))
			rcu_read_unlock_special(t);
	}
	if (IS_ENABLED(CONFIG_PROVE_LOCKING)) {
		int rrln = rcu_preempt_depth();

		WARN_ON_ONCE(rrln < 0 || rrln > RCU_NEST_PMAX);
	}
}
EXPORT_SYMBOL_GPL(__rcu_read_unlock);

static struct list_head *rcu_next_node_entry(struct task_struct *t,
					     struct rcu_node *rnp)
{
	struct list_head *np;

	np = t->rcu_node_entry.next;
	if (np == &rnp->blkd_tasks)
		np = NULL;
	return np;
}

static bool rcu_preempt_has_tasks(struct rcu_node *rnp)
{
	return !list_empty(&rnp->blkd_tasks);
}

static notrace void
rcu_preempt_deferred_qs_irqrestore(struct task_struct *t, unsigned long flags)
{
	bool empty_exp;
	bool empty_norm;
	bool empty_exp_now;
	struct list_head *np;
	bool drop_boost_mutex = false;
	struct rcu_data *rdp;
	struct rcu_node *rnp;
	union rcu_special special;

	/*
	special = t->rcu_read_unlock_special;
	rdp = this_cpu_ptr(&rcu_data);
	if (!special.s && !rdp->cpu_no_qs.b.exp) {
		local_irq_restore(flags);
		return;
	}
	t->rcu_read_unlock_special.s = 0;
	if (special.b.need_qs) {
		if (IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD)) {
			rdp->cpu_no_qs.b.norm = false;
			rcu_report_qs_rdp(rdp);
			udelay(rcu_unlock_delay);
		} else {
			rcu_qs();
		}
	}

	/*
	if (rdp->cpu_no_qs.b.exp)
		rcu_report_exp_rdp(rdp);

	/* Clean up if blocked during RCU read-side critical section. */
	if (special.b.blocked) {

		/*
		rnp = t->rcu_blocked_node;
		raw_spin_lock_rcu_node(rnp); /* irqs already disabled. */
		WARN_ON_ONCE(rnp != t->rcu_blocked_node);
		WARN_ON_ONCE(!rcu_is_leaf_node(rnp));
		empty_norm = !rcu_preempt_blocked_readers_cgp(rnp);
		WARN_ON_ONCE(rnp->completedqs == rnp->gp_seq &&
			     (!empty_norm || rnp->qsmask));
		empty_exp = sync_rcu_exp_done(rnp);
		smp_mb(); /* ensure expedited fastpath sees end of RCU c-s. */
		np = rcu_next_node_entry(t, rnp);
		list_del_init(&t->rcu_node_entry);
		t->rcu_blocked_node = NULL;
		trace_rcu_unlock_preempted_task(TPS("rcu_preempt"),
						rnp->gp_seq, t->pid);
		if (&t->rcu_node_entry == rnp->gp_tasks)
			WRITE_ONCE(rnp->gp_tasks, np);
		if (&t->rcu_node_entry == rnp->exp_tasks)
			WRITE_ONCE(rnp->exp_tasks, np);
		if (IS_ENABLED(CONFIG_RCU_BOOST)) {
			/* Snapshot ->boost_mtx ownership w/rnp->lock held. */
			drop_boost_mutex = rt_mutex_owner(&rnp->boost_mtx.rtmutex) == t;
			if (&t->rcu_node_entry == rnp->boost_tasks)
				WRITE_ONCE(rnp->boost_tasks, np);
		}

		/*
		empty_exp_now = sync_rcu_exp_done(rnp);
		if (!empty_norm && !rcu_preempt_blocked_readers_cgp(rnp)) {
			trace_rcu_quiescent_state_report(TPS("preempt_rcu"),
							 rnp->gp_seq,
							 0, rnp->qsmask,
							 rnp->level,
							 rnp->grplo,
							 rnp->grphi,
							 !!rnp->gp_tasks);
			rcu_report_unblock_qs_rnp(rnp, flags);
		} else {
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		}

		/*
		if (!empty_exp && empty_exp_now)
			rcu_report_exp_rnp(rnp, true);

		/* Unboost if we were boosted. */
		if (IS_ENABLED(CONFIG_RCU_BOOST) && drop_boost_mutex)
			rt_mutex_futex_unlock(&rnp->boost_mtx.rtmutex);
	} else {
		local_irq_restore(flags);
	}
}

static notrace bool rcu_preempt_need_deferred_qs(struct task_struct *t)
{
	return (__this_cpu_read(rcu_data.cpu_no_qs.b.exp) ||
		READ_ONCE(t->rcu_read_unlock_special.s)) &&
	       rcu_preempt_depth() == 0;
}

notrace void rcu_preempt_deferred_qs(struct task_struct *t)
{
	unsigned long flags;

	if (!rcu_preempt_need_deferred_qs(t))
		return;
	local_irq_save(flags);
	rcu_preempt_deferred_qs_irqrestore(t, flags);
}

static void rcu_preempt_deferred_qs_handler(struct irq_work *iwp)
{
	struct rcu_data *rdp;

	rdp = container_of(iwp, struct rcu_data, defer_qs_iw);
	rdp->defer_qs_iw_pending = false;
}

static void rcu_read_unlock_special(struct task_struct *t)
{
	unsigned long flags;
	bool irqs_were_disabled;
	bool preempt_bh_were_disabled =
			!!(preempt_count() & (PREEMPT_MASK | SOFTIRQ_MASK));

	/* NMI handlers cannot block and cannot safely manipulate state. */
	if (in_nmi())
		return;

	local_irq_save(flags);
	irqs_were_disabled = irqs_disabled_flags(flags);
	if (preempt_bh_were_disabled || irqs_were_disabled) {
		bool expboost; // Expedited GP in flight or possible boosting.
		struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
		struct rcu_node *rnp = rdp->mynode;

		expboost = (t->rcu_blocked_node && READ_ONCE(t->rcu_blocked_node->exp_tasks)) ||
			   (rdp->grpmask & READ_ONCE(rnp->expmask)) ||
			   IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD) ||
			   (IS_ENABLED(CONFIG_RCU_BOOST) && irqs_were_disabled &&
			    t->rcu_blocked_node);
		// Need to defer quiescent state until everything is enabled.
		if (use_softirq && (in_hardirq() || (expboost && !irqs_were_disabled))) {
			// Using softirq, safe to awaken, and either the
			// wakeup is free or there is either an expedited
			// GP in flight or a potential need to deboost.
			raise_softirq_irqoff(RCU_SOFTIRQ);
		} else {
			// Enabling BH or preempt does reschedule, so...
			// Also if no expediting and no possible deboosting,
			// slow is OK.  Plus nohz_full CPUs eventually get
			// tick enabled.
			set_tsk_need_resched(current);
			set_preempt_need_resched();
			if (IS_ENABLED(CONFIG_IRQ_WORK) && irqs_were_disabled &&
			    expboost && !rdp->defer_qs_iw_pending && cpu_online(rdp->cpu)) {
				// Get scheduler to re-evaluate and call hooks.
				// If !IRQ_WORK, FQS scan will eventually IPI.
				if (IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD) &&
				    IS_ENABLED(CONFIG_PREEMPT_RT))
					rdp->defer_qs_iw = IRQ_WORK_INIT_HARD(
								rcu_preempt_deferred_qs_handler);
				else
					init_irq_work(&rdp->defer_qs_iw,
						      rcu_preempt_deferred_qs_handler);
				rdp->defer_qs_iw_pending = true;
				irq_work_queue_on(&rdp->defer_qs_iw, rdp->cpu);
			}
		}
		local_irq_restore(flags);
		return;
	}
	rcu_preempt_deferred_qs_irqrestore(t, flags);
}

static void rcu_preempt_check_blocked_tasks(struct rcu_node *rnp)
{
	struct task_struct *t;

	RCU_LOCKDEP_WARN(preemptible(), "rcu_preempt_check_blocked_tasks() invoked with preemption enabled!!!\n");
	raw_lockdep_assert_held_rcu_node(rnp);
	if (WARN_ON_ONCE(rcu_preempt_blocked_readers_cgp(rnp)))
		dump_blkd_tasks(rnp, 10);
	if (rcu_preempt_has_tasks(rnp) &&
	    (rnp->qsmaskinit || rnp->wait_blkd_tasks)) {
		WRITE_ONCE(rnp->gp_tasks, rnp->blkd_tasks.next);
		t = container_of(rnp->gp_tasks, struct task_struct,
				 rcu_node_entry);
		trace_rcu_unlock_preempted_task(TPS("rcu_preempt-GPS"),
						rnp->gp_seq, t->pid);
	}
	WARN_ON_ONCE(rnp->qsmask);
}

static void rcu_flavor_sched_clock_irq(int user)
{
	struct task_struct *t = current;

	lockdep_assert_irqs_disabled();
	if (user || rcu_is_cpu_rrupt_from_idle()) {
		rcu_note_voluntary_context_switch(current);
	}
	if (rcu_preempt_depth() > 0 ||
	    (preempt_count() & (PREEMPT_MASK | SOFTIRQ_MASK))) {
		/* No QS, force context switch if deferred. */
		if (rcu_preempt_need_deferred_qs(t)) {
			set_tsk_need_resched(t);
			set_preempt_need_resched();
		}
	} else if (rcu_preempt_need_deferred_qs(t)) {
		rcu_preempt_deferred_qs(t); /* Report deferred QS. */
		return;
	} else if (!WARN_ON_ONCE(rcu_preempt_depth())) {
		rcu_qs(); /* Report immediate QS. */
		return;
	}

	/* If GP is oldish, ask for help from rcu_read_unlock_special(). */
	if (rcu_preempt_depth() > 0 &&
	    __this_cpu_read(rcu_data.core_needs_qs) &&
	    __this_cpu_read(rcu_data.cpu_no_qs.b.norm) &&
	    !t->rcu_read_unlock_special.b.need_qs &&
	    time_after(jiffies, rcu_state.gp_start + HZ))
		t->rcu_read_unlock_special.b.need_qs = true;
}

void exit_rcu(void)
{
	struct task_struct *t = current;

	if (unlikely(!list_empty(&current->rcu_node_entry))) {
		rcu_preempt_depth_set(1);
		barrier();
		WRITE_ONCE(t->rcu_read_unlock_special.b.blocked, true);
	} else if (unlikely(rcu_preempt_depth())) {
		rcu_preempt_depth_set(1);
	} else {
		return;
	}
	__rcu_read_unlock();
	rcu_preempt_deferred_qs(current);
}

static void
dump_blkd_tasks(struct rcu_node *rnp, int ncheck)
{
	int cpu;
	int i;
	struct list_head *lhp;
	struct rcu_data *rdp;
	struct rcu_node *rnp1;

	raw_lockdep_assert_held_rcu_node(rnp);
	pr_info("%s: grp: %d-%d level: %d ->gp_seq %ld ->completedqs %ld\n",
		__func__, rnp->grplo, rnp->grphi, rnp->level,
		(long)READ_ONCE(rnp->gp_seq), (long)rnp->completedqs);
	for (rnp1 = rnp; rnp1; rnp1 = rnp1->parent)
		pr_info("%s: %d:%d ->qsmask %#lx ->qsmaskinit %#lx ->qsmaskinitnext %#lx\n",
			__func__, rnp1->grplo, rnp1->grphi, rnp1->qsmask, rnp1->qsmaskinit, rnp1->qsmaskinitnext);
	pr_info("%s: ->gp_tasks %p ->boost_tasks %p ->exp_tasks %p\n",
		__func__, READ_ONCE(rnp->gp_tasks), data_race(rnp->boost_tasks),
		READ_ONCE(rnp->exp_tasks));
	pr_info("%s: ->blkd_tasks", __func__);
	i = 0;
	list_for_each(lhp, &rnp->blkd_tasks) {
		pr_cont(" %p", lhp);
		if (++i >= ncheck)
			break;
	}
	pr_cont("\n");
	for (cpu = rnp->grplo; cpu <= rnp->grphi; cpu++) {
		rdp = per_cpu_ptr(&rcu_data, cpu);
		pr_info("\t%d: %c online: %ld(%d) offline: %ld(%d)\n",
			cpu, ".o"[rcu_rdp_cpu_online(rdp)],
			(long)rdp->rcu_onl_gp_seq, rdp->rcu_onl_gp_flags,
			(long)rdp->rcu_ofl_gp_seq, rdp->rcu_ofl_gp_flags);
	}
}

#else /* #ifdef CONFIG_PREEMPT_RCU */

void rcu_read_unlock_strict(void)
{
	struct rcu_data *rdp;

	if (irqs_disabled() || preempt_count() || !rcu_state.gp_kthread)
		return;
	rdp = this_cpu_ptr(&rcu_data);
	rcu_report_qs_rdp(rdp);
	udelay(rcu_unlock_delay);
}
EXPORT_SYMBOL_GPL(rcu_read_unlock_strict);

static void __init rcu_bootup_announce(void)
{
	pr_info("Hierarchical RCU implementation.\n");
	rcu_bootup_announce_oddness();
}

static void rcu_qs(void)
{
	RCU_LOCKDEP_WARN(preemptible(), "rcu_qs() invoked with preemption enabled!!!");
	if (!__this_cpu_read(rcu_data.cpu_no_qs.s))
		return;
	trace_rcu_grace_period(TPS("rcu_sched"),
			       __this_cpu_read(rcu_data.gp_seq), TPS("cpuqs"));
	__this_cpu_write(rcu_data.cpu_no_qs.b.norm, false);
	if (__this_cpu_read(rcu_data.cpu_no_qs.b.exp))
		rcu_report_exp_rdp(this_cpu_ptr(&rcu_data));
}

void rcu_all_qs(void)
{
	unsigned long flags;

	if (!raw_cpu_read(rcu_data.rcu_urgent_qs))
		return;
	preempt_disable();
	/* Load rcu_urgent_qs before other flags. */
	if (!smp_load_acquire(this_cpu_ptr(&rcu_data.rcu_urgent_qs))) {
		preempt_enable();
		return;
	}
	this_cpu_write(rcu_data.rcu_urgent_qs, false);
	if (unlikely(raw_cpu_read(rcu_data.rcu_need_heavy_qs))) {
		local_irq_save(flags);
		rcu_momentary_dyntick_idle();
		local_irq_restore(flags);
	}
	rcu_qs();
	preempt_enable();
}
EXPORT_SYMBOL_GPL(rcu_all_qs);

void rcu_note_context_switch(bool preempt)
{
	trace_rcu_utilization(TPS("Start context switch"));
	rcu_qs();
	/* Load rcu_urgent_qs before other flags. */
	if (!smp_load_acquire(this_cpu_ptr(&rcu_data.rcu_urgent_qs)))
		goto out;
	this_cpu_write(rcu_data.rcu_urgent_qs, false);
	if (unlikely(raw_cpu_read(rcu_data.rcu_need_heavy_qs)))
		rcu_momentary_dyntick_idle();
out:
	rcu_tasks_qs(current, preempt);
	trace_rcu_utilization(TPS("End context switch"));
}
EXPORT_SYMBOL_GPL(rcu_note_context_switch);

static int rcu_preempt_blocked_readers_cgp(struct rcu_node *rnp)
{
	return 0;
}

static bool rcu_preempt_has_tasks(struct rcu_node *rnp)
{
	return false;
}

static notrace bool rcu_preempt_need_deferred_qs(struct task_struct *t)
{
	return false;
}

// Except that we do need to respond to a request by an expedited grace
// period for a quiescent state from this CPU.  Note that requests from
// tasks are handled when removing the task from the blocked-tasks list
// below.
notrace void rcu_preempt_deferred_qs(struct task_struct *t)
{
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);

	if (rdp->cpu_no_qs.b.exp)
		rcu_report_exp_rdp(rdp);
}

static void rcu_preempt_check_blocked_tasks(struct rcu_node *rnp)
{
	WARN_ON_ONCE(rnp->qsmask);
}

static void rcu_flavor_sched_clock_irq(int user)
{
	if (user || rcu_is_cpu_rrupt_from_idle()) {

		/*

		rcu_qs();
	}
}

void exit_rcu(void)
{
}

static void
dump_blkd_tasks(struct rcu_node *rnp, int ncheck)
{
	WARN_ON_ONCE(!list_empty(&rnp->blkd_tasks));
}

#endif /* #else #ifdef CONFIG_PREEMPT_RCU */

static void rcu_cpu_kthread_setup(unsigned int cpu)
{
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
#ifdef CONFIG_RCU_BOOST
	struct sched_param sp;

	sp.sched_priority = kthread_prio;
	sched_setscheduler_nocheck(current, SCHED_FIFO, &sp);
#endif /* #ifdef CONFIG_RCU_BOOST */

	WRITE_ONCE(rdp->rcuc_activity, jiffies);
}

static bool rcu_is_callbacks_nocb_kthread(struct rcu_data *rdp)
{
#ifdef CONFIG_RCU_NOCB_CPU
	return rdp->nocb_cb_kthread == current;
#else
	return false;
#endif
}

static bool rcu_is_callbacks_kthread(struct rcu_data *rdp)
{
	return rdp->rcu_cpu_kthread_task == current ||
			rcu_is_callbacks_nocb_kthread(rdp);
}

#ifdef CONFIG_RCU_BOOST

static int rcu_boost(struct rcu_node *rnp)
{
	unsigned long flags;
	struct task_struct *t;
	struct list_head *tb;

	if (READ_ONCE(rnp->exp_tasks) == NULL &&
	    READ_ONCE(rnp->boost_tasks) == NULL)
		return 0;  /* Nothing left to boost. */

	raw_spin_lock_irqsave_rcu_node(rnp, flags);

	/*
	if (rnp->exp_tasks == NULL && rnp->boost_tasks == NULL) {
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return 0;
	}

	/*
	if (rnp->exp_tasks != NULL)
		tb = rnp->exp_tasks;
	else
		tb = rnp->boost_tasks;

	/*
	t = container_of(tb, struct task_struct, rcu_node_entry);
	rt_mutex_init_proxy_locked(&rnp->boost_mtx.rtmutex, t);
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	/* Lock only for side effect: boosts task t's priority. */
	rt_mutex_lock(&rnp->boost_mtx);
	rt_mutex_unlock(&rnp->boost_mtx);  /* Then keep lockdep happy. */
	rnp->n_boosts++;

	return READ_ONCE(rnp->exp_tasks) != NULL ||
	       READ_ONCE(rnp->boost_tasks) != NULL;
}

static int rcu_boost_kthread(void *arg)
{
	struct rcu_node *rnp = (struct rcu_node *)arg;
	int spincnt = 0;
	int more2boost;

	trace_rcu_utilization(TPS("Start boost kthread@init"));
	for (;;) {
		WRITE_ONCE(rnp->boost_kthread_status, RCU_KTHREAD_WAITING);
		trace_rcu_utilization(TPS("End boost kthread@rcu_wait"));
		rcu_wait(READ_ONCE(rnp->boost_tasks) ||
			 READ_ONCE(rnp->exp_tasks));
		trace_rcu_utilization(TPS("Start boost kthread@rcu_wait"));
		WRITE_ONCE(rnp->boost_kthread_status, RCU_KTHREAD_RUNNING);
		more2boost = rcu_boost(rnp);
		if (more2boost)
			spincnt++;
		else
			spincnt = 0;
		if (spincnt > 10) {
			WRITE_ONCE(rnp->boost_kthread_status, RCU_KTHREAD_YIELDING);
			trace_rcu_utilization(TPS("End boost kthread@rcu_yield"));
			schedule_timeout_idle(2);
			trace_rcu_utilization(TPS("Start boost kthread@rcu_yield"));
			spincnt = 0;
		}
	}
	/* NOTREACHED */
	trace_rcu_utilization(TPS("End boost kthread@notreached"));
	return 0;
}

static void rcu_initiate_boost(struct rcu_node *rnp, unsigned long flags)
	__releases(rnp->lock)
{
	raw_lockdep_assert_held_rcu_node(rnp);
	if (!rnp->boost_kthread_task ||
	    (!rcu_preempt_blocked_readers_cgp(rnp) && !rnp->exp_tasks)) {
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return;
	}
	if (rnp->exp_tasks != NULL ||
	    (rnp->gp_tasks != NULL &&
	     rnp->boost_tasks == NULL &&
	     rnp->qsmask == 0 &&
	     (!time_after(rnp->boost_time, jiffies) || rcu_state.cbovld ||
	      IS_ENABLED(CONFIG_RCU_STRICT_GRACE_PERIOD)))) {
		if (rnp->exp_tasks == NULL)
			WRITE_ONCE(rnp->boost_tasks, rnp->gp_tasks);
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		rcu_wake_cond(rnp->boost_kthread_task,
			      READ_ONCE(rnp->boost_kthread_status));
	} else {
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	}
}

#define RCU_BOOST_DELAY_JIFFIES DIV_ROUND_UP(CONFIG_RCU_BOOST_DELAY * HZ, 1000)

static void rcu_preempt_boost_start_gp(struct rcu_node *rnp)
{
	rnp->boost_time = jiffies + RCU_BOOST_DELAY_JIFFIES;
}

static void rcu_spawn_one_boost_kthread(struct rcu_node *rnp)
{
	unsigned long flags;
	int rnp_index = rnp - rcu_get_root();
	struct sched_param sp;
	struct task_struct *t;

	mutex_lock(&rnp->boost_kthread_mutex);
	if (rnp->boost_kthread_task || !rcu_scheduler_fully_active)
		goto out;

	t = kthread_create(rcu_boost_kthread, (void *)rnp,
			   "rcub/%d", rnp_index);
	if (WARN_ON_ONCE(IS_ERR(t)))
		goto out;

	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	rnp->boost_kthread_task = t;
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	sp.sched_priority = kthread_prio;
	sched_setscheduler_nocheck(t, SCHED_FIFO, &sp);
	wake_up_process(t); /* get to TASK_INTERRUPTIBLE quickly. */

 out:
	mutex_unlock(&rnp->boost_kthread_mutex);
}

static void rcu_boost_kthread_setaffinity(struct rcu_node *rnp, int outgoingcpu)
{
	struct task_struct *t = rnp->boost_kthread_task;
	unsigned long mask = rcu_rnp_online_cpus(rnp);
	cpumask_var_t cm;
	int cpu;

	if (!t)
		return;
	if (!zalloc_cpumask_var(&cm, GFP_KERNEL))
		return;
	mutex_lock(&rnp->boost_kthread_mutex);
	for_each_leaf_node_possible_cpu(rnp, cpu)
		if ((mask & leaf_node_cpu_bit(rnp, cpu)) &&
		    cpu != outgoingcpu)
			cpumask_set_cpu(cpu, cm);
	cpumask_and(cm, cm, housekeeping_cpumask(HK_TYPE_RCU));
	if (cpumask_empty(cm))
		cpumask_copy(cm, housekeeping_cpumask(HK_TYPE_RCU));
	set_cpus_allowed_ptr(t, cm);
	mutex_unlock(&rnp->boost_kthread_mutex);
	free_cpumask_var(cm);
}

#else /* #ifdef CONFIG_RCU_BOOST */

static void rcu_initiate_boost(struct rcu_node *rnp, unsigned long flags)
	__releases(rnp->lock)
{
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
}

static void rcu_preempt_boost_start_gp(struct rcu_node *rnp)
{
}

static void rcu_spawn_one_boost_kthread(struct rcu_node *rnp)
{
}

static void rcu_boost_kthread_setaffinity(struct rcu_node *rnp, int outgoingcpu)
{
}

#endif /* #else #ifdef CONFIG_RCU_BOOST */

static bool rcu_nohz_full_cpu(void)
{
#ifdef CONFIG_NO_HZ_FULL
	if (tick_nohz_full_cpu(smp_processor_id()) &&
	    (!rcu_gp_in_progress() ||
	     time_before(jiffies, READ_ONCE(rcu_state.gp_start) + HZ)))
		return true;
#endif /* #ifdef CONFIG_NO_HZ_FULL */
	return false;
}

static void rcu_bind_gp_kthread(void)
{
	if (!tick_nohz_full_enabled())
		return;
	housekeeping_affine(current, HK_TYPE_RCU);
}
