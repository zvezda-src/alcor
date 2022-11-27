
#include <linux/lockdep.h>

static void rcu_exp_handler(void *unused);
static int rcu_print_task_exp_stall(struct rcu_node *rnp);

static void rcu_exp_gp_seq_start(void)
{
	rcu_seq_start(&rcu_state.expedited_sequence);
	rcu_poll_gp_seq_start_unlocked(&rcu_state.gp_seq_polled_exp_snap);
}

static __maybe_unused unsigned long rcu_exp_gp_seq_endval(void)
{
	return rcu_seq_endval(&rcu_state.expedited_sequence);
}

static void rcu_exp_gp_seq_end(void)
{
	rcu_poll_gp_seq_end_unlocked(&rcu_state.gp_seq_polled_exp_snap);
	rcu_seq_end(&rcu_state.expedited_sequence);
	smp_mb(); /* Ensure that consecutive grace periods serialize. */
}

static unsigned long rcu_exp_gp_seq_snap(void)
{
	unsigned long s;

	smp_mb(); /* Caller's modifications seen first by other CPUs. */
	s = rcu_seq_snap(&rcu_state.expedited_sequence);
	trace_rcu_exp_grace_period(rcu_state.name, s, TPS("snap"));
	return s;
}

static bool rcu_exp_gp_seq_done(unsigned long s)
{
	return rcu_seq_done(&rcu_state.expedited_sequence, s);
}

static void sync_exp_reset_tree_hotplug(void)
{
	bool done;
	unsigned long flags;
	unsigned long mask;
	unsigned long oldmask;
	int ncpus = smp_load_acquire(&rcu_state.ncpus); /* Order vs. locking. */
	struct rcu_node *rnp;
	struct rcu_node *rnp_up;

	/* If no new CPUs onlined since last time, nothing to do. */
	if (likely(ncpus == rcu_state.ncpus_snap))
		return;
	rcu_state.ncpus_snap = ncpus;

	/*
	rcu_for_each_leaf_node(rnp) {
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		if (rnp->expmaskinit == rnp->expmaskinitnext) {
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			continue;  /* No new CPUs, nothing to do. */
		}

		/* Update this node's mask, track old value for propagation. */
		oldmask = rnp->expmaskinit;
		rnp->expmaskinit = rnp->expmaskinitnext;
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);

		/* If was already nonzero, nothing to propagate. */
		if (oldmask)
			continue;

		/* Propagate the new CPU up the tree. */
		mask = rnp->grpmask;
		rnp_up = rnp->parent;
		done = false;
		while (rnp_up) {
			raw_spin_lock_irqsave_rcu_node(rnp_up, flags);
			if (rnp_up->expmaskinit)
				done = true;
			rnp_up->expmaskinit |= mask;
			raw_spin_unlock_irqrestore_rcu_node(rnp_up, flags);
			if (done)
				break;
			mask = rnp_up->grpmask;
			rnp_up = rnp_up->parent;
		}
	}
}

static void __maybe_unused sync_exp_reset_tree(void)
{
	unsigned long flags;
	struct rcu_node *rnp;

	sync_exp_reset_tree_hotplug();
	rcu_for_each_node_breadth_first(rnp) {
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		WARN_ON_ONCE(rnp->expmask);
		WRITE_ONCE(rnp->expmask, rnp->expmaskinit);
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	}
}

static bool sync_rcu_exp_done(struct rcu_node *rnp)
{
	raw_lockdep_assert_held_rcu_node(rnp);
	return READ_ONCE(rnp->exp_tasks) == NULL &&
	       READ_ONCE(rnp->expmask) == 0;
}

static bool sync_rcu_exp_done_unlocked(struct rcu_node *rnp)
{
	unsigned long flags;
	bool ret;

	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	ret = sync_rcu_exp_done(rnp);
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);

	return ret;
}


static void __rcu_report_exp_rnp(struct rcu_node *rnp,
				 bool wake, unsigned long flags)
	__releases(rnp->lock)
{
	unsigned long mask;

	raw_lockdep_assert_held_rcu_node(rnp);
	for (;;) {
		if (!sync_rcu_exp_done(rnp)) {
			if (!rnp->expmask)
				rcu_initiate_boost(rnp, flags);
			else
				raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			break;
		}
		if (rnp->parent == NULL) {
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			if (wake) {
				smp_mb(); /* EGP done before wake_up(). */
				swake_up_one(&rcu_state.expedited_wq);
			}
			break;
		}
		mask = rnp->grpmask;
		raw_spin_unlock_rcu_node(rnp); /* irqs remain disabled */
		rnp = rnp->parent;
		raw_spin_lock_rcu_node(rnp); /* irqs already disabled */
		WARN_ON_ONCE(!(rnp->expmask & mask));
		WRITE_ONCE(rnp->expmask, rnp->expmask & ~mask);
	}
}

static void __maybe_unused rcu_report_exp_rnp(struct rcu_node *rnp, bool wake)
{
	unsigned long flags;

	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	__rcu_report_exp_rnp(rnp, wake, flags);
}

static void rcu_report_exp_cpu_mult(struct rcu_node *rnp,
				    unsigned long mask, bool wake)
{
	int cpu;
	unsigned long flags;
	struct rcu_data *rdp;

	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	if (!(rnp->expmask & mask)) {
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return;
	}
	WRITE_ONCE(rnp->expmask, rnp->expmask & ~mask);
	for_each_leaf_node_cpu_mask(rnp, cpu, mask) {
		rdp = per_cpu_ptr(&rcu_data, cpu);
		if (!IS_ENABLED(CONFIG_NO_HZ_FULL) || !rdp->rcu_forced_tick_exp)
			continue;
		rdp->rcu_forced_tick_exp = false;
		tick_dep_clear_cpu(cpu, TICK_DEP_BIT_RCU_EXP);
	}
	__rcu_report_exp_rnp(rnp, wake, flags); /* Releases rnp->lock. */
}

static void rcu_report_exp_rdp(struct rcu_data *rdp)
{
	WRITE_ONCE(rdp->cpu_no_qs.b.exp, false);
	rcu_report_exp_cpu_mult(rdp->mynode, rdp->grpmask, true);
}

static bool sync_exp_work_done(unsigned long s)
{
	if (rcu_exp_gp_seq_done(s)) {
		trace_rcu_exp_grace_period(rcu_state.name, s, TPS("done"));
		smp_mb(); /* Ensure test happens before caller kfree(). */
		return true;
	}
	return false;
}

static bool exp_funnel_lock(unsigned long s)
{
	struct rcu_data *rdp = per_cpu_ptr(&rcu_data, raw_smp_processor_id());
	struct rcu_node *rnp = rdp->mynode;
	struct rcu_node *rnp_root = rcu_get_root();

	/* Low-contention fastpath. */
	if (ULONG_CMP_LT(READ_ONCE(rnp->exp_seq_rq), s) &&
	    (rnp == rnp_root ||
	     ULONG_CMP_LT(READ_ONCE(rnp_root->exp_seq_rq), s)) &&
	    mutex_trylock(&rcu_state.exp_mutex))
		goto fastpath;

	/*
	for (; rnp != NULL; rnp = rnp->parent) {
		if (sync_exp_work_done(s))
			return true;

		/* Work not done, either wait here or go up. */
		spin_lock(&rnp->exp_lock);
		if (ULONG_CMP_GE(rnp->exp_seq_rq, s)) {

			/* Someone else doing GP, so wait for them. */
			spin_unlock(&rnp->exp_lock);
			trace_rcu_exp_funnel_lock(rcu_state.name, rnp->level,
						  rnp->grplo, rnp->grphi,
						  TPS("wait"));
			wait_event(rnp->exp_wq[rcu_seq_ctr(s) & 0x3],
				   sync_exp_work_done(s));
			return true;
		}
		WRITE_ONCE(rnp->exp_seq_rq, s); /* Followers can wait on us. */
		spin_unlock(&rnp->exp_lock);
		trace_rcu_exp_funnel_lock(rcu_state.name, rnp->level,
					  rnp->grplo, rnp->grphi, TPS("nxtlvl"));
	}
	mutex_lock(&rcu_state.exp_mutex);
fastpath:
	if (sync_exp_work_done(s)) {
		mutex_unlock(&rcu_state.exp_mutex);
		return true;
	}
	rcu_exp_gp_seq_start();
	trace_rcu_exp_grace_period(rcu_state.name, s, TPS("start"));
	return false;
}

static void __sync_rcu_exp_select_node_cpus(struct rcu_exp_work *rewp)
{
	int cpu;
	unsigned long flags;
	unsigned long mask_ofl_test;
	unsigned long mask_ofl_ipi;
	int ret;
	struct rcu_node *rnp = container_of(rewp, struct rcu_node, rew);

	raw_spin_lock_irqsave_rcu_node(rnp, flags);

	/* Each pass checks a CPU for identity, offline, and idle. */
	mask_ofl_test = 0;
	for_each_leaf_node_cpu_mask(rnp, cpu, rnp->expmask) {
		struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
		unsigned long mask = rdp->grpmask;
		int snap;

		if (raw_smp_processor_id() == cpu ||
		    !(rnp->qsmaskinitnext & mask)) {
			mask_ofl_test |= mask;
		} else {
			snap = rcu_dynticks_snap(cpu);
			if (rcu_dynticks_in_eqs(snap))
				mask_ofl_test |= mask;
			else
				rdp->exp_dynticks_snap = snap;
		}
	}
	mask_ofl_ipi = rnp->expmask & ~mask_ofl_test;

	/*
	if (rcu_preempt_has_tasks(rnp))
		WRITE_ONCE(rnp->exp_tasks, rnp->blkd_tasks.next);
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);

	/* IPI the remaining CPUs for expedited quiescent state. */
	for_each_leaf_node_cpu_mask(rnp, cpu, mask_ofl_ipi) {
		struct rcu_data *rdp = per_cpu_ptr(&rcu_data, cpu);
		unsigned long mask = rdp->grpmask;

retry_ipi:
		if (rcu_dynticks_in_eqs_since(rdp, rdp->exp_dynticks_snap)) {
			mask_ofl_test |= mask;
			continue;
		}
		if (get_cpu() == cpu) {
			mask_ofl_test |= mask;
			put_cpu();
			continue;
		}
		ret = smp_call_function_single(cpu, rcu_exp_handler, NULL, 0);
		put_cpu();
		/* The CPU will report the QS in response to the IPI. */
		if (!ret)
			continue;

		/* Failed, raced with CPU hotplug operation. */
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		if ((rnp->qsmaskinitnext & mask) &&
		    (rnp->expmask & mask)) {
			/* Online, so delay for a bit and try again. */
			raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
			trace_rcu_exp_grace_period(rcu_state.name, rcu_exp_gp_seq_endval(), TPS("selectofl"));
			schedule_timeout_idle(1);
			goto retry_ipi;
		}
		/* CPU really is offline, so we must report its QS. */
		if (rnp->expmask & mask)
			mask_ofl_test |= mask;
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	}
	/* Report quiescent states for those that went offline. */
	if (mask_ofl_test)
		rcu_report_exp_cpu_mult(rnp, mask_ofl_test, false);
}

static void rcu_exp_sel_wait_wake(unsigned long s);

#ifdef CONFIG_RCU_EXP_KTHREAD
static void sync_rcu_exp_select_node_cpus(struct kthread_work *wp)
{
	struct rcu_exp_work *rewp =
		container_of(wp, struct rcu_exp_work, rew_work);

	__sync_rcu_exp_select_node_cpus(rewp);
}

static inline bool rcu_gp_par_worker_started(void)
{
	return !!READ_ONCE(rcu_exp_par_gp_kworker);
}

static inline void sync_rcu_exp_select_cpus_queue_work(struct rcu_node *rnp)
{
	kthread_init_work(&rnp->rew.rew_work, sync_rcu_exp_select_node_cpus);
	/*
	kthread_queue_work(rcu_exp_par_gp_kworker, &rnp->rew.rew_work);
}

static inline void sync_rcu_exp_select_cpus_flush_work(struct rcu_node *rnp)
{
	kthread_flush_work(&rnp->rew.rew_work);
}

static void wait_rcu_exp_gp(struct kthread_work *wp)
{
	struct rcu_exp_work *rewp;

	rewp = container_of(wp, struct rcu_exp_work, rew_work);
	rcu_exp_sel_wait_wake(rewp->rew_s);
}

static inline void synchronize_rcu_expedited_queue_work(struct rcu_exp_work *rew)
{
	kthread_init_work(&rew->rew_work, wait_rcu_exp_gp);
	kthread_queue_work(rcu_exp_gp_kworker, &rew->rew_work);
}

static inline void synchronize_rcu_expedited_destroy_work(struct rcu_exp_work *rew)
{
}
#else /* !CONFIG_RCU_EXP_KTHREAD */
static void sync_rcu_exp_select_node_cpus(struct work_struct *wp)
{
	struct rcu_exp_work *rewp =
		container_of(wp, struct rcu_exp_work, rew_work);

	__sync_rcu_exp_select_node_cpus(rewp);
}

static inline bool rcu_gp_par_worker_started(void)
{
	return !!READ_ONCE(rcu_par_gp_wq);
}

static inline void sync_rcu_exp_select_cpus_queue_work(struct rcu_node *rnp)
{
	int cpu = find_next_bit(&rnp->ffmask, BITS_PER_LONG, -1);

	INIT_WORK(&rnp->rew.rew_work, sync_rcu_exp_select_node_cpus);
	/* If all offline, queue the work on an unbound CPU. */
	if (unlikely(cpu > rnp->grphi - rnp->grplo))
		cpu = WORK_CPU_UNBOUND;
	else
		cpu += rnp->grplo;
	queue_work_on(cpu, rcu_par_gp_wq, &rnp->rew.rew_work);
}

static inline void sync_rcu_exp_select_cpus_flush_work(struct rcu_node *rnp)
{
	flush_work(&rnp->rew.rew_work);
}

static void wait_rcu_exp_gp(struct work_struct *wp)
{
	struct rcu_exp_work *rewp;

	rewp = container_of(wp, struct rcu_exp_work, rew_work);
	rcu_exp_sel_wait_wake(rewp->rew_s);
}

static inline void synchronize_rcu_expedited_queue_work(struct rcu_exp_work *rew)
{
	INIT_WORK_ONSTACK(&rew->rew_work, wait_rcu_exp_gp);
	queue_work(rcu_gp_wq, &rew->rew_work);
}

static inline void synchronize_rcu_expedited_destroy_work(struct rcu_exp_work *rew)
{
	destroy_work_on_stack(&rew->rew_work);
}
#endif /* CONFIG_RCU_EXP_KTHREAD */

static void sync_rcu_exp_select_cpus(void)
{
	struct rcu_node *rnp;

	trace_rcu_exp_grace_period(rcu_state.name, rcu_exp_gp_seq_endval(), TPS("reset"));
	sync_exp_reset_tree();
	trace_rcu_exp_grace_period(rcu_state.name, rcu_exp_gp_seq_endval(), TPS("select"));

	/* Schedule work for each leaf rcu_node structure. */
	rcu_for_each_leaf_node(rnp) {
		rnp->exp_need_flush = false;
		if (!READ_ONCE(rnp->expmask))
			continue; /* Avoid early boot non-existent wq. */
		if (!rcu_gp_par_worker_started() ||
		    rcu_scheduler_active != RCU_SCHEDULER_RUNNING ||
		    rcu_is_last_leaf_node(rnp)) {
			/* No worker started yet or last leaf, do direct call. */
			sync_rcu_exp_select_node_cpus(&rnp->rew.rew_work);
			continue;
		}
		sync_rcu_exp_select_cpus_queue_work(rnp);
		rnp->exp_need_flush = true;
	}

	/* Wait for jobs (if any) to complete. */
	rcu_for_each_leaf_node(rnp)
		if (rnp->exp_need_flush)
			sync_rcu_exp_select_cpus_flush_work(rnp);
}

static bool synchronize_rcu_expedited_wait_once(long tlimit)
{
	int t;
	struct rcu_node *rnp_root = rcu_get_root();

	t = swait_event_timeout_exclusive(rcu_state.expedited_wq,
					  sync_rcu_exp_done_unlocked(rnp_root),
					  tlimit);
	// Workqueues should not be signaled.
	if (t > 0 || sync_rcu_exp_done_unlocked(rnp_root))
		return true;
	WARN_ON(t < 0);  /* workqueues should not be signaled. */
	return false;
}

static void synchronize_rcu_expedited_wait(void)
{
	int cpu;
	unsigned long j;
	unsigned long jiffies_stall;
	unsigned long jiffies_start;
	unsigned long mask;
	int ndetected;
	struct rcu_data *rdp;
	struct rcu_node *rnp;
	struct rcu_node *rnp_root = rcu_get_root();

	trace_rcu_exp_grace_period(rcu_state.name, rcu_exp_gp_seq_endval(), TPS("startwait"));
	jiffies_stall = rcu_exp_jiffies_till_stall_check();
	jiffies_start = jiffies;
	if (tick_nohz_full_enabled() && rcu_inkernel_boot_has_ended()) {
		if (synchronize_rcu_expedited_wait_once(1))
			return;
		rcu_for_each_leaf_node(rnp) {
			mask = READ_ONCE(rnp->expmask);
			for_each_leaf_node_cpu_mask(rnp, cpu, mask) {
				rdp = per_cpu_ptr(&rcu_data, cpu);
				if (rdp->rcu_forced_tick_exp)
					continue;
				rdp->rcu_forced_tick_exp = true;
				preempt_disable();
				if (cpu_online(cpu))
					tick_dep_set_cpu(cpu, TICK_DEP_BIT_RCU_EXP);
				preempt_enable();
			}
		}
		j = READ_ONCE(jiffies_till_first_fqs);
		if (synchronize_rcu_expedited_wait_once(j + HZ))
			return;
	}

	for (;;) {
		if (synchronize_rcu_expedited_wait_once(jiffies_stall))
			return;
		if (rcu_stall_is_suppressed())
			continue;
		trace_rcu_stall_warning(rcu_state.name, TPS("ExpeditedStall"));
		pr_err("INFO: %s detected expedited stalls on CPUs/tasks: {",
		       rcu_state.name);
		ndetected = 0;
		rcu_for_each_leaf_node(rnp) {
			ndetected += rcu_print_task_exp_stall(rnp);
			for_each_leaf_node_possible_cpu(rnp, cpu) {
				struct rcu_data *rdp;

				mask = leaf_node_cpu_bit(rnp, cpu);
				if (!(READ_ONCE(rnp->expmask) & mask))
					continue;
				ndetected++;
				rdp = per_cpu_ptr(&rcu_data, cpu);
				pr_cont(" %d-%c%c%c%c", cpu,
					"O."[!!cpu_online(cpu)],
					"o."[!!(rdp->grpmask & rnp->expmaskinit)],
					"N."[!!(rdp->grpmask & rnp->expmaskinitnext)],
					"D."[!!(rdp->cpu_no_qs.b.exp)]);
			}
		}
		pr_cont(" } %lu jiffies s: %lu root: %#lx/%c\n",
			jiffies - jiffies_start, rcu_state.expedited_sequence,
			data_race(rnp_root->expmask),
			".T"[!!data_race(rnp_root->exp_tasks)]);
		if (ndetected) {
			pr_err("blocking rcu_node structures (internal RCU debug):");
			rcu_for_each_node_breadth_first(rnp) {
				if (rnp == rnp_root)
					continue; /* printed unconditionally */
				if (sync_rcu_exp_done_unlocked(rnp))
					continue;
				pr_cont(" l=%u:%d-%d:%#lx/%c",
					rnp->level, rnp->grplo, rnp->grphi,
					data_race(rnp->expmask),
					".T"[!!data_race(rnp->exp_tasks)]);
			}
			pr_cont("\n");
		}
		rcu_for_each_leaf_node(rnp) {
			for_each_leaf_node_possible_cpu(rnp, cpu) {
				mask = leaf_node_cpu_bit(rnp, cpu);
				if (!(READ_ONCE(rnp->expmask) & mask))
					continue;
				dump_cpu_task(cpu);
			}
		}
		jiffies_stall = 3 * rcu_exp_jiffies_till_stall_check() + 3;
		panic_on_rcu_stall();
	}
}

static void rcu_exp_wait_wake(unsigned long s)
{
	struct rcu_node *rnp;

	synchronize_rcu_expedited_wait();

	// Switch over to wakeup mode, allowing the next GP to proceed.
	// End the previous grace period only after acquiring the mutex
	// to ensure that only one GP runs concurrently with wakeups.
	mutex_lock(&rcu_state.exp_wake_mutex);
	rcu_exp_gp_seq_end();
	trace_rcu_exp_grace_period(rcu_state.name, s, TPS("end"));

	rcu_for_each_node_breadth_first(rnp) {
		if (ULONG_CMP_LT(READ_ONCE(rnp->exp_seq_rq), s)) {
			spin_lock(&rnp->exp_lock);
			/* Recheck, avoid hang in case someone just arrived. */
			if (ULONG_CMP_LT(rnp->exp_seq_rq, s))
				WRITE_ONCE(rnp->exp_seq_rq, s);
			spin_unlock(&rnp->exp_lock);
		}
		smp_mb(); /* All above changes before wakeup. */
		wake_up_all(&rnp->exp_wq[rcu_seq_ctr(s) & 0x3]);
	}
	trace_rcu_exp_grace_period(rcu_state.name, s, TPS("endwake"));
	mutex_unlock(&rcu_state.exp_wake_mutex);
}

static void rcu_exp_sel_wait_wake(unsigned long s)
{
	/* Initialize the rcu_node tree in preparation for the wait. */
	sync_rcu_exp_select_cpus();

	/* Wait and clean up, including waking everyone. */
	rcu_exp_wait_wake(s);
}

#ifdef CONFIG_PREEMPT_RCU

static void rcu_exp_handler(void *unused)
{
	int depth = rcu_preempt_depth();
	unsigned long flags;
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
	struct rcu_node *rnp = rdp->mynode;
	struct task_struct *t = current;

	/*
	if (!depth) {
		if (!(preempt_count() & (PREEMPT_MASK | SOFTIRQ_MASK)) ||
		    rcu_is_cpu_rrupt_from_idle()) {
			rcu_report_exp_rdp(rdp);
		} else {
			WRITE_ONCE(rdp->cpu_no_qs.b.exp, true);
			set_tsk_need_resched(t);
			set_preempt_need_resched();
		}
		return;
	}

	/*
	if (depth > 0) {
		raw_spin_lock_irqsave_rcu_node(rnp, flags);
		if (rnp->expmask & rdp->grpmask) {
			WRITE_ONCE(rdp->cpu_no_qs.b.exp, true);
			t->rcu_read_unlock_special.b.exp_hint = true;
		}
		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
		return;
	}

	// Finally, negative nesting depth should not happen.
	WARN_ON_ONCE(1);
}

static void sync_sched_exp_online_cleanup(int cpu)
{
}

static int rcu_print_task_exp_stall(struct rcu_node *rnp)
{
	unsigned long flags;
	int ndetected = 0;
	struct task_struct *t;

	if (!READ_ONCE(rnp->exp_tasks))
		return 0;
	raw_spin_lock_irqsave_rcu_node(rnp, flags);
	t = list_entry(rnp->exp_tasks->prev,
		       struct task_struct, rcu_node_entry);
	list_for_each_entry_continue(t, &rnp->blkd_tasks, rcu_node_entry) {
		pr_cont(" P%d", t->pid);
		ndetected++;
	}
	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
	return ndetected;
}

#else /* #ifdef CONFIG_PREEMPT_RCU */

static void rcu_exp_need_qs(void)
{
	__this_cpu_write(rcu_data.cpu_no_qs.b.exp, true);
	/* Store .exp before .rcu_urgent_qs. */
	smp_store_release(this_cpu_ptr(&rcu_data.rcu_urgent_qs), true);
	set_tsk_need_resched(current);
	set_preempt_need_resched();
}

static void rcu_exp_handler(void *unused)
{
	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
	struct rcu_node *rnp = rdp->mynode;

	if (!(READ_ONCE(rnp->expmask) & rdp->grpmask) ||
	    __this_cpu_read(rcu_data.cpu_no_qs.b.exp))
		return;
	if (rcu_is_cpu_rrupt_from_idle()) {
		rcu_report_exp_rdp(this_cpu_ptr(&rcu_data));
		return;
	}
	rcu_exp_need_qs();
}

static void sync_sched_exp_online_cleanup(int cpu)
{
	unsigned long flags;
	int my_cpu;
	struct rcu_data *rdp;
	int ret;
	struct rcu_node *rnp;

	rdp = per_cpu_ptr(&rcu_data, cpu);
	rnp = rdp->mynode;
	my_cpu = get_cpu();
	/* Quiescent state either not needed or already requested, leave. */
	if (!(READ_ONCE(rnp->expmask) & rdp->grpmask) ||
	    READ_ONCE(rdp->cpu_no_qs.b.exp)) {
		put_cpu();
		return;
	}
	/* Quiescent state needed on current CPU, so set it up locally. */
	if (my_cpu == cpu) {
		local_irq_save(flags);
		rcu_exp_need_qs();
		local_irq_restore(flags);
		put_cpu();
		return;
	}
	/* Quiescent state needed on some other CPU, send IPI. */
	ret = smp_call_function_single(cpu, rcu_exp_handler, NULL, 0);
	put_cpu();
	WARN_ON_ONCE(ret);
}

static int rcu_print_task_exp_stall(struct rcu_node *rnp)
{
	return 0;
}

#endif /* #else #ifdef CONFIG_PREEMPT_RCU */

void synchronize_rcu_expedited(void)
{
	bool boottime = (rcu_scheduler_active == RCU_SCHEDULER_INIT);
	struct rcu_exp_work rew;
	struct rcu_node *rnp;
	unsigned long s;

	RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map) ||
			 lock_is_held(&rcu_lock_map) ||
			 lock_is_held(&rcu_sched_lock_map),
			 "Illegal synchronize_rcu_expedited() in RCU read-side critical section");

	/* Is the state is such that the call is a grace period? */
	if (rcu_blocking_is_gp()) {
		// Note well that this code runs with !PREEMPT && !SMP.
		// In addition, all code that advances grace periods runs
		// at process level.  Therefore, this expedited GP overlaps
		// with other expedited GPs only by being fully nested within
		// them, which allows reuse of ->gp_seq_polled_exp_snap.
		rcu_poll_gp_seq_start_unlocked(&rcu_state.gp_seq_polled_exp_snap);
		rcu_poll_gp_seq_end_unlocked(&rcu_state.gp_seq_polled_exp_snap);
		if (rcu_init_invoked())
			cond_resched();
		return;  // Context allows vacuous grace periods.
	}

	/* If expedited grace periods are prohibited, fall back to normal. */
	if (rcu_gp_is_normal()) {
		wait_rcu_gp(call_rcu);
		return;
	}

	/* Take a snapshot of the sequence number.  */
	s = rcu_exp_gp_seq_snap();
	if (exp_funnel_lock(s))
		return;  /* Someone else did our work for us. */

	/* Ensure that load happens before action based on it. */
	if (unlikely(boottime)) {
		/* Direct call during scheduler init and early_initcalls(). */
		rcu_exp_sel_wait_wake(s);
	} else {
		/* Marshall arguments & schedule the expedited grace period. */
		rew.rew_s = s;
		synchronize_rcu_expedited_queue_work(&rew);
	}

	/* Wait for expedited grace period to complete. */
	rnp = rcu_get_root();
	wait_event(rnp->exp_wq[rcu_seq_ctr(s) & 0x3],
		   sync_exp_work_done(s));
	smp_mb(); /* Work actions happen before return. */

	/* Let the next expedited grace period start. */
	mutex_unlock(&rcu_state.exp_mutex);

	if (likely(!boottime))
		synchronize_rcu_expedited_destroy_work(&rew);
}
EXPORT_SYMBOL_GPL(synchronize_rcu_expedited);

static void sync_rcu_do_polled_gp(struct work_struct *wp)
{
	unsigned long flags;
	int i = 0;
	struct rcu_node *rnp = container_of(wp, struct rcu_node, exp_poll_wq);
	unsigned long s;

	raw_spin_lock_irqsave(&rnp->exp_poll_lock, flags);
	s = rnp->exp_seq_poll_rq;
	rnp->exp_seq_poll_rq = RCU_GET_STATE_COMPLETED;
	raw_spin_unlock_irqrestore(&rnp->exp_poll_lock, flags);
	if (s == RCU_GET_STATE_COMPLETED)
		return;
	while (!poll_state_synchronize_rcu(s)) {
		synchronize_rcu_expedited();
		if (i == 10 || i == 20)
			pr_info("%s: i = %d s = %lx gp_seq_polled = %lx\n", __func__, i, s, READ_ONCE(rcu_state.gp_seq_polled));
		i++;
	}
	raw_spin_lock_irqsave(&rnp->exp_poll_lock, flags);
	s = rnp->exp_seq_poll_rq;
	if (poll_state_synchronize_rcu(s))
		rnp->exp_seq_poll_rq = RCU_GET_STATE_COMPLETED;
	raw_spin_unlock_irqrestore(&rnp->exp_poll_lock, flags);
}

unsigned long start_poll_synchronize_rcu_expedited(void)
{
	unsigned long flags;
	struct rcu_data *rdp;
	struct rcu_node *rnp;
	unsigned long s;

	s = get_state_synchronize_rcu();
	rdp = per_cpu_ptr(&rcu_data, raw_smp_processor_id());
	rnp = rdp->mynode;
	if (rcu_init_invoked())
		raw_spin_lock_irqsave(&rnp->exp_poll_lock, flags);
	if (!poll_state_synchronize_rcu(s)) {
		rnp->exp_seq_poll_rq = s;
		if (rcu_init_invoked())
			queue_work(rcu_gp_wq, &rnp->exp_poll_wq);
	}
	if (rcu_init_invoked())
		raw_spin_unlock_irqrestore(&rnp->exp_poll_lock, flags);

	return s;
}
EXPORT_SYMBOL_GPL(start_poll_synchronize_rcu_expedited);

void cond_synchronize_rcu_expedited(unsigned long oldstate)
{
	if (!poll_state_synchronize_rcu(oldstate))
		synchronize_rcu_expedited();
}
EXPORT_SYMBOL_GPL(cond_synchronize_rcu_expedited);
