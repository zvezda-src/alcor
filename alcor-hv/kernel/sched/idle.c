
extern char __cpuidle_text_start[], __cpuidle_text_end[];

void sched_idle_set_state(struct cpuidle_state *idle_state)
{
	idle_set_state(this_rq(), idle_state);
}

static int __read_mostly cpu_idle_force_poll;

void cpu_idle_poll_ctrl(bool enable)
{
	if (enable) {
		cpu_idle_force_poll++;
	} else {
		cpu_idle_force_poll--;
		WARN_ON_ONCE(cpu_idle_force_poll < 0);
	}
}

#ifdef CONFIG_GENERIC_IDLE_POLL_SETUP
static int __init cpu_idle_poll_setup(char *__unused)
{
	cpu_idle_force_poll = 1;

	return 1;
}
__setup("nohlt", cpu_idle_poll_setup);

static int __init cpu_idle_nopoll_setup(char *__unused)
{
	cpu_idle_force_poll = 0;

	return 1;
}
__setup("hlt", cpu_idle_nopoll_setup);
#endif

static noinline int __cpuidle cpu_idle_poll(void)
{
	trace_cpu_idle(0, smp_processor_id());
	stop_critical_timings();
	ct_idle_enter();
	local_irq_enable();

	while (!tif_need_resched() &&
	       (cpu_idle_force_poll || tick_check_broadcast_expired()))
		cpu_relax();

	ct_idle_exit();
	start_critical_timings();
	trace_cpu_idle(PWR_EVENT_EXIT, smp_processor_id());

	return 1;
}

void __weak arch_cpu_idle_prepare(void) { }
void __weak arch_cpu_idle_enter(void) { }
void __weak arch_cpu_idle_exit(void) { }
void __weak arch_cpu_idle_dead(void) { }
void __weak arch_cpu_idle(void)
{
	cpu_idle_force_poll = 1;
	raw_local_irq_enable();
}

void __cpuidle default_idle_call(void)
{
	if (current_clr_polling_and_test()) {
		local_irq_enable();
	} else {

		trace_cpu_idle(1, smp_processor_id());
		stop_critical_timings();

		/*
		trace_hardirqs_on_prepare();
		lockdep_hardirqs_on_prepare();
		ct_idle_enter();
		lockdep_hardirqs_on(_THIS_IP_);

		arch_cpu_idle();

		/*
		raw_local_irq_disable();
		lockdep_hardirqs_off(_THIS_IP_);
		ct_idle_exit();
		lockdep_hardirqs_on(_THIS_IP_);
		raw_local_irq_enable();

		start_critical_timings();
		trace_cpu_idle(PWR_EVENT_EXIT, smp_processor_id());
	}
}

static int call_cpuidle_s2idle(struct cpuidle_driver *drv,
			       struct cpuidle_device *dev)
{
	if (current_clr_polling_and_test())
		return -EBUSY;

	return cpuidle_enter_s2idle(drv, dev);
}

static int call_cpuidle(struct cpuidle_driver *drv, struct cpuidle_device *dev,
		      int next_state)
{
	/*
	if (current_clr_polling_and_test()) {
		dev->last_residency_ns = 0;
		local_irq_enable();
		return -EBUSY;
	}

	/*
	return cpuidle_enter(drv, dev, next_state);
}

static void cpuidle_idle_call(void)
{
	struct cpuidle_device *dev = cpuidle_get_device();
	struct cpuidle_driver *drv = cpuidle_get_cpu_driver(dev);
	int next_state, entered_state;

	/*
	if (need_resched()) {
		local_irq_enable();
		return;
	}

	/*

	if (cpuidle_not_available(drv, dev)) {
		tick_nohz_idle_stop_tick();

		default_idle_call();
		goto exit_idle;
	}

	/*

	if (idle_should_enter_s2idle() || dev->forced_idle_latency_limit_ns) {
		u64 max_latency_ns;

		if (idle_should_enter_s2idle()) {

			entered_state = call_cpuidle_s2idle(drv, dev);
			if (entered_state > 0)
				goto exit_idle;

			max_latency_ns = U64_MAX;
		} else {
			max_latency_ns = dev->forced_idle_latency_limit_ns;
		}

		tick_nohz_idle_stop_tick();

		next_state = cpuidle_find_deepest_state(drv, dev, max_latency_ns);
		call_cpuidle(drv, dev, next_state);
	} else {
		bool stop_tick = true;

		/*
		next_state = cpuidle_select(drv, dev, &stop_tick);

		if (stop_tick || tick_nohz_tick_stopped())
			tick_nohz_idle_stop_tick();
		else
			tick_nohz_idle_retain_tick();

		entered_state = call_cpuidle(drv, dev, next_state);
		/*
		cpuidle_reflect(dev, entered_state);
	}

exit_idle:
	__current_set_polling();

	/*
	if (WARN_ON_ONCE(irqs_disabled()))
		local_irq_enable();
}

static void do_idle(void)
{
	int cpu = smp_processor_id();

	/*
	nohz_run_idle_balance(cpu);

	/*

	__current_set_polling();
	tick_nohz_idle_enter();

	while (!need_resched()) {
		rmb();

		local_irq_disable();

		if (cpu_is_offline(cpu)) {
			tick_nohz_idle_stop_tick();
			cpuhp_report_idle_dead();
			arch_cpu_idle_dead();
		}

		arch_cpu_idle_enter();
		rcu_nocb_flush_deferred_wakeup();

		/*
		if (cpu_idle_force_poll || tick_check_broadcast_expired()) {
			tick_nohz_idle_restart_tick();
			cpu_idle_poll();
		} else {
			cpuidle_idle_call();
		}
		arch_cpu_idle_exit();
	}

	/*
	preempt_set_need_resched();
	tick_nohz_idle_exit();
	__current_clr_polling();

	/*
	smp_mb__after_atomic();

	/*
	flush_smp_call_function_queue();
	schedule_idle();

	if (unlikely(klp_patch_pending(current)))
		klp_update_patch_state(current);
}

bool cpu_in_idle(unsigned long pc)
{
	return pc >= (unsigned long)__cpuidle_text_start &&
		pc < (unsigned long)__cpuidle_text_end;
}

struct idle_timer {
	struct hrtimer timer;
	int done;
};

static enum hrtimer_restart idle_inject_timer_fn(struct hrtimer *timer)
{
	struct idle_timer *it = container_of(timer, struct idle_timer, timer);

	WRITE_ONCE(it->done, 1);
	set_tsk_need_resched(current);

	return HRTIMER_NORESTART;
}

void play_idle_precise(u64 duration_ns, u64 latency_ns)
{
	struct idle_timer it;

	/*
	WARN_ON_ONCE(current->policy != SCHED_FIFO);
	WARN_ON_ONCE(current->nr_cpus_allowed != 1);
	WARN_ON_ONCE(!(current->flags & PF_KTHREAD));
	WARN_ON_ONCE(!(current->flags & PF_NO_SETAFFINITY));
	WARN_ON_ONCE(!duration_ns);
	WARN_ON_ONCE(current->mm);

	rcu_sleep_check();
	preempt_disable();
	current->flags |= PF_IDLE;
	cpuidle_use_deepest_state(latency_ns);

	it.done = 0;
	hrtimer_init_on_stack(&it.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_HARD);
	it.timer.function = idle_inject_timer_fn;
	hrtimer_start(&it.timer, ns_to_ktime(duration_ns),
		      HRTIMER_MODE_REL_PINNED_HARD);

	while (!READ_ONCE(it.done))
		do_idle();

	cpuidle_use_deepest_state(0);
	current->flags &= ~PF_IDLE;

	preempt_fold_need_resched();
	preempt_enable();
}
EXPORT_SYMBOL_GPL(play_idle_precise);

void cpu_startup_entry(enum cpuhp_state state)
{
	arch_cpu_idle_prepare();
	cpuhp_online_idle(state);
	while (1)
		do_idle();
}


#ifdef CONFIG_SMP
static int
select_task_rq_idle(struct task_struct *p, int cpu, int flags)
{
	return task_cpu(p); /* IDLE tasks as never migrated */
}

static int
balance_idle(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	return WARN_ON_ONCE(1);
}
#endif

static void check_preempt_curr_idle(struct rq *rq, struct task_struct *p, int flags)
{
	resched_curr(rq);
}

static void put_prev_task_idle(struct rq *rq, struct task_struct *prev)
{
}

static void set_next_task_idle(struct rq *rq, struct task_struct *next, bool first)
{
	update_idle_core(rq);
	schedstat_inc(rq->sched_goidle);
}

#ifdef CONFIG_SMP
static struct task_struct *pick_task_idle(struct rq *rq)
{
	return rq->idle;
}
#endif

struct task_struct *pick_next_task_idle(struct rq *rq)
{
	struct task_struct *next = rq->idle;

	set_next_task_idle(rq, next, true);

	return next;
}

static void
dequeue_task_idle(struct rq *rq, struct task_struct *p, int flags)
{
	raw_spin_rq_unlock_irq(rq);
	printk(KERN_ERR "bad: scheduling from the idle thread!\n");
	dump_stack();
	raw_spin_rq_lock_irq(rq);
}

static void task_tick_idle(struct rq *rq, struct task_struct *curr, int queued)
{
}

static void switched_to_idle(struct rq *rq, struct task_struct *p)
{
	BUG();
}

static void
prio_changed_idle(struct rq *rq, struct task_struct *p, int oldprio)
{
	BUG();
}

static void update_curr_idle(struct rq *rq)
{
}

DEFINE_SCHED_CLASS(idle) = {

	/* no enqueue/yield_task for idle tasks */

	/* dequeue is not valid, we print a debug message there: */
	.dequeue_task		= dequeue_task_idle,

	.check_preempt_curr	= check_preempt_curr_idle,

	.pick_next_task		= pick_next_task_idle,
	.put_prev_task		= put_prev_task_idle,
	.set_next_task          = set_next_task_idle,

#ifdef CONFIG_SMP
	.balance		= balance_idle,
	.pick_task		= pick_task_idle,
	.select_task_rq		= select_task_rq_idle,
	.set_cpus_allowed	= set_cpus_allowed_common,
#endif

	.task_tick		= task_tick_idle,

	.prio_changed		= prio_changed_idle,
	.switched_to		= switched_to_idle,
	.update_curr		= update_curr_idle,
};
