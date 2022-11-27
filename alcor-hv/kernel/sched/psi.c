
static int psi_bug __read_mostly;

DEFINE_STATIC_KEY_FALSE(psi_disabled);
DEFINE_STATIC_KEY_TRUE(psi_cgroups_enabled);

#ifdef CONFIG_PSI_DEFAULT_DISABLED
static bool psi_enable;
#else
static bool psi_enable = true;
#endif
static int __init setup_psi(char *str)
{
	return kstrtobool(str, &psi_enable) == 0;
}
__setup("psi=", setup_psi);

#define PSI_FREQ	(2*HZ+1)	/* 2 sec intervals */
#define EXP_10s		1677		/* 1/exp(2s/10s) as fixed-point */
#define EXP_60s		1981		/* 1/exp(2s/60s) */
#define EXP_300s	2034		/* 1/exp(2s/300s) */

#define WINDOW_MIN_US 500000	/* Min window size is 500ms */
#define WINDOW_MAX_US 10000000	/* Max window size is 10s */
#define UPDATES_PER_WINDOW 10	/* 10 updates per window */

static u64 psi_period __read_mostly;

static DEFINE_PER_CPU(struct psi_group_cpu, system_group_pcpu);
struct psi_group psi_system = {
	.pcpu = &system_group_pcpu,
};

static void psi_avgs_work(struct work_struct *work);

static void poll_timer_fn(struct timer_list *t);

static void group_init(struct psi_group *group)
{
	int cpu;

	for_each_possible_cpu(cpu)
		seqcount_init(&per_cpu_ptr(group->pcpu, cpu)->seq);
	group->avg_last_update = sched_clock();
	group->avg_next_update = group->avg_last_update + psi_period;
	INIT_DELAYED_WORK(&group->avgs_work, psi_avgs_work);
	mutex_init(&group->avgs_lock);
	/* Init trigger-related members */
	mutex_init(&group->trigger_lock);
	INIT_LIST_HEAD(&group->triggers);
	memset(group->nr_triggers, 0, sizeof(group->nr_triggers));
	group->poll_states = 0;
	group->poll_min_period = U32_MAX;
	memset(group->polling_total, 0, sizeof(group->polling_total));
	group->polling_next_update = ULLONG_MAX;
	group->polling_until = 0;
	init_waitqueue_head(&group->poll_wait);
	timer_setup(&group->poll_timer, poll_timer_fn, 0);
	rcu_assign_pointer(group->poll_task, NULL);
}

void __init psi_init(void)
{
	if (!psi_enable) {
		static_branch_enable(&psi_disabled);
		return;
	}

	if (!cgroup_psi_enabled())
		static_branch_disable(&psi_cgroups_enabled);

	psi_period = jiffies_to_nsecs(PSI_FREQ);
	group_init(&psi_system);
}

static bool test_state(unsigned int *tasks, enum psi_states state)
{
	switch (state) {
	case PSI_IO_SOME:
		return unlikely(tasks[NR_IOWAIT]);
	case PSI_IO_FULL:
		return unlikely(tasks[NR_IOWAIT] && !tasks[NR_RUNNING]);
	case PSI_MEM_SOME:
		return unlikely(tasks[NR_MEMSTALL]);
	case PSI_MEM_FULL:
		return unlikely(tasks[NR_MEMSTALL] &&
			tasks[NR_RUNNING] == tasks[NR_MEMSTALL_RUNNING]);
	case PSI_CPU_SOME:
		return unlikely(tasks[NR_RUNNING] > tasks[NR_ONCPU]);
	case PSI_CPU_FULL:
		return unlikely(tasks[NR_RUNNING] && !tasks[NR_ONCPU]);
	case PSI_NONIDLE:
		return tasks[NR_IOWAIT] || tasks[NR_MEMSTALL] ||
			tasks[NR_RUNNING];
	default:
		return false;
	}
}

static void get_recent_times(struct psi_group *group, int cpu,
			     enum psi_aggregators aggregator, u32 *times,
			     u32 *pchanged_states)
{
	struct psi_group_cpu *groupc = per_cpu_ptr(group->pcpu, cpu);
	u64 now, state_start;
	enum psi_states s;
	unsigned int seq;
	u32 state_mask;


	/* Snapshot a coherent view of the CPU state */
	do {
		seq = read_seqcount_begin(&groupc->seq);
		now = cpu_clock(cpu);
		memcpy(times, groupc->times, sizeof(groupc->times));
		state_mask = groupc->state_mask;
		state_start = groupc->state_start;
	} while (read_seqcount_retry(&groupc->seq, seq));

	/* Calculate state time deltas against the previous snapshot */
	for (s = 0; s < NR_PSI_STATES; s++) {
		u32 delta;
		/*
		if (state_mask & (1 << s))
			times[s] += now - state_start;

		delta = times[s] - groupc->times_prev[aggregator][s];
		groupc->times_prev[aggregator][s] = times[s];

		times[s] = delta;
		if (delta)
			*pchanged_states |= (1 << s);
	}
}

static void calc_avgs(unsigned long avg[3], int missed_periods,
		      u64 time, u64 period)
{
	unsigned long pct;

	/* Fill in zeroes for periods of no activity */
	if (missed_periods) {
		avg[0] = calc_load_n(avg[0], EXP_10s, 0, missed_periods);
		avg[1] = calc_load_n(avg[1], EXP_60s, 0, missed_periods);
		avg[2] = calc_load_n(avg[2], EXP_300s, 0, missed_periods);
	}

	/* Sample the most recent active period */
	pct = div_u64(time * 100, period);
	pct *= FIXED_1;
	avg[0] = calc_load(avg[0], EXP_10s, pct);
	avg[1] = calc_load(avg[1], EXP_60s, pct);
	avg[2] = calc_load(avg[2], EXP_300s, pct);
}

static void collect_percpu_times(struct psi_group *group,
				 enum psi_aggregators aggregator,
				 u32 *pchanged_states)
{
	u64 deltas[NR_PSI_STATES - 1] = { 0, };
	unsigned long nonidle_total = 0;
	u32 changed_states = 0;
	int cpu;
	int s;

	/*
	for_each_possible_cpu(cpu) {
		u32 times[NR_PSI_STATES];
		u32 nonidle;
		u32 cpu_changed_states;

		get_recent_times(group, cpu, aggregator, times,
				&cpu_changed_states);
		changed_states |= cpu_changed_states;

		nonidle = nsecs_to_jiffies(times[PSI_NONIDLE]);
		nonidle_total += nonidle;

		for (s = 0; s < PSI_NONIDLE; s++)
			deltas[s] += (u64)times[s] * nonidle;
	}

	/*

	/* total= */
	for (s = 0; s < NR_PSI_STATES - 1; s++)
		group->total[aggregator][s] +=
				div_u64(deltas[s], max(nonidle_total, 1UL));

	if (pchanged_states)
		*pchanged_states = changed_states;
}

static u64 update_averages(struct psi_group *group, u64 now)
{
	unsigned long missed_periods = 0;
	u64 expires, period;
	u64 avg_next_update;
	int s;

	/* avgX= */
	expires = group->avg_next_update;
	if (now - expires >= psi_period)
		missed_periods = div_u64(now - expires, psi_period);

	/*
	avg_next_update = expires + ((1 + missed_periods) * psi_period);
	period = now - (group->avg_last_update + (missed_periods * psi_period));
	group->avg_last_update = now;

	for (s = 0; s < NR_PSI_STATES - 1; s++) {
		u32 sample;

		sample = group->total[PSI_AVGS][s] - group->avg_total[s];
		/*
		if (sample > period)
			sample = period;
		group->avg_total[s] += sample;
		calc_avgs(group->avg[s], missed_periods, sample, period);
	}

	return avg_next_update;
}

static void psi_avgs_work(struct work_struct *work)
{
	struct delayed_work *dwork;
	struct psi_group *group;
	u32 changed_states;
	bool nonidle;
	u64 now;

	dwork = to_delayed_work(work);
	group = container_of(dwork, struct psi_group, avgs_work);

	mutex_lock(&group->avgs_lock);

	now = sched_clock();

	collect_percpu_times(group, PSI_AVGS, &changed_states);
	nonidle = changed_states & (1 << PSI_NONIDLE);
	/*
	if (now >= group->avg_next_update)
		group->avg_next_update = update_averages(group, now);

	if (nonidle) {
		schedule_delayed_work(dwork, nsecs_to_jiffies(
				group->avg_next_update - now) + 1);
	}

	mutex_unlock(&group->avgs_lock);
}

static void window_reset(struct psi_window *win, u64 now, u64 value,
			 u64 prev_growth)
{
	win->start_time = now;
	win->start_value = value;
	win->prev_growth = prev_growth;
}

static u64 window_update(struct psi_window *win, u64 now, u64 value)
{
	u64 elapsed;
	u64 growth;

	elapsed = now - win->start_time;
	growth = value - win->start_value;
	/*
	if (elapsed > win->size)
		window_reset(win, now, value, growth);
	else {
		u32 remaining;

		remaining = win->size - elapsed;
		growth += div64_u64(win->prev_growth * remaining, win->size);
	}

	return growth;
}

static void init_triggers(struct psi_group *group, u64 now)
{
	struct psi_trigger *t;

	list_for_each_entry(t, &group->triggers, node)
		window_reset(&t->win, now,
				group->total[PSI_POLL][t->state], 0);
	memcpy(group->polling_total, group->total[PSI_POLL],
		   sizeof(group->polling_total));
	group->polling_next_update = now + group->poll_min_period;
}

static u64 update_triggers(struct psi_group *group, u64 now)
{
	struct psi_trigger *t;
	bool update_total = false;
	u64 *total = group->total[PSI_POLL];

	/*
	list_for_each_entry(t, &group->triggers, node) {
		u64 growth;
		bool new_stall;

		new_stall = group->polling_total[t->state] != total[t->state];

		/* Check for stall activity or a previous threshold breach */
		if (!new_stall && !t->pending_event)
			continue;
		/*
		if (new_stall) {
			/*
			update_total = true;

			/* Calculate growth since last update */
			growth = window_update(&t->win, now, total[t->state]);
			if (growth < t->threshold)
				continue;

			t->pending_event = true;
		}
		/* Limit event signaling to once per window */
		if (now < t->last_event_time + t->win.size)
			continue;

		/* Generate an event */
		if (cmpxchg(&t->event, 0, 1) == 0)
			wake_up_interruptible(&t->event_wait);
		t->last_event_time = now;
		/* Reset threshold breach flag once event got generated */
		t->pending_event = false;
	}

	if (update_total)
		memcpy(group->polling_total, total,
				sizeof(group->polling_total));

	return now + group->poll_min_period;
}

static void psi_schedule_poll_work(struct psi_group *group, unsigned long delay)
{
	struct task_struct *task;

	/*
	if (timer_pending(&group->poll_timer))
		return;

	rcu_read_lock();

	task = rcu_dereference(group->poll_task);
	/*
	if (likely(task))
		mod_timer(&group->poll_timer, jiffies + delay);

	rcu_read_unlock();
}

static void psi_poll_work(struct psi_group *group)
{
	u32 changed_states;
	u64 now;

	mutex_lock(&group->trigger_lock);

	now = sched_clock();

	collect_percpu_times(group, PSI_POLL, &changed_states);

	if (changed_states & group->poll_states) {
		/* Initialize trigger windows when entering polling mode */
		if (now > group->polling_until)
			init_triggers(group, now);

		/*
		group->polling_until = now +
			group->poll_min_period * UPDATES_PER_WINDOW;
	}

	if (now > group->polling_until) {
		group->polling_next_update = ULLONG_MAX;
		goto out;
	}

	if (now >= group->polling_next_update)
		group->polling_next_update = update_triggers(group, now);

	psi_schedule_poll_work(group,
		nsecs_to_jiffies(group->polling_next_update - now) + 1);

out:
	mutex_unlock(&group->trigger_lock);
}

static int psi_poll_worker(void *data)
{
	struct psi_group *group = (struct psi_group *)data;

	sched_set_fifo_low(current);

	while (true) {
		wait_event_interruptible(group->poll_wait,
				atomic_cmpxchg(&group->poll_wakeup, 1, 0) ||
				kthread_should_stop());
		if (kthread_should_stop())
			break;

		psi_poll_work(group);
	}
	return 0;
}

static void poll_timer_fn(struct timer_list *t)
{
	struct psi_group *group = from_timer(group, t, poll_timer);

	atomic_set(&group->poll_wakeup, 1);
	wake_up_interruptible(&group->poll_wait);
}

static void record_times(struct psi_group_cpu *groupc, u64 now)
{
	u32 delta;

	delta = now - groupc->state_start;
	groupc->state_start = now;

	if (groupc->state_mask & (1 << PSI_IO_SOME)) {
		groupc->times[PSI_IO_SOME] += delta;
		if (groupc->state_mask & (1 << PSI_IO_FULL))
			groupc->times[PSI_IO_FULL] += delta;
	}

	if (groupc->state_mask & (1 << PSI_MEM_SOME)) {
		groupc->times[PSI_MEM_SOME] += delta;
		if (groupc->state_mask & (1 << PSI_MEM_FULL))
			groupc->times[PSI_MEM_FULL] += delta;
	}

	if (groupc->state_mask & (1 << PSI_CPU_SOME)) {
		groupc->times[PSI_CPU_SOME] += delta;
		if (groupc->state_mask & (1 << PSI_CPU_FULL))
			groupc->times[PSI_CPU_FULL] += delta;
	}

	if (groupc->state_mask & (1 << PSI_NONIDLE))
		groupc->times[PSI_NONIDLE] += delta;
}

static void psi_group_change(struct psi_group *group, int cpu,
			     unsigned int clear, unsigned int set, u64 now,
			     bool wake_clock)
{
	struct psi_group_cpu *groupc;
	u32 state_mask = 0;
	unsigned int t, m;
	enum psi_states s;

	groupc = per_cpu_ptr(group->pcpu, cpu);

	/*
	write_seqcount_begin(&groupc->seq);

	record_times(groupc, now);

	for (t = 0, m = clear; m; m &= ~(1 << t), t++) {
		if (!(m & (1 << t)))
			continue;
		if (groupc->tasks[t]) {
			groupc->tasks[t]--;
		} else if (!psi_bug) {
			printk_deferred(KERN_ERR "psi: task underflow! cpu=%d t=%d tasks=[%u %u %u %u %u] clear=%x set=%x\n",
					cpu, t, groupc->tasks[0],
					groupc->tasks[1], groupc->tasks[2],
					groupc->tasks[3], groupc->tasks[4],
					clear, set);
			psi_bug = 1;
		}
	}

	for (t = 0; set; set &= ~(1 << t), t++)
		if (set & (1 << t))
			groupc->tasks[t]++;

	/* Calculate state mask representing active states */
	for (s = 0; s < NR_PSI_STATES; s++) {
		if (test_state(groupc->tasks, s))
			state_mask |= (1 << s);
	}

	/*
	if (unlikely(groupc->tasks[NR_ONCPU] && cpu_curr(cpu)->in_memstall))
		state_mask |= (1 << PSI_MEM_FULL);

	groupc->state_mask = state_mask;

	write_seqcount_end(&groupc->seq);

	if (state_mask & group->poll_states)
		psi_schedule_poll_work(group, 1);

	if (wake_clock && !delayed_work_pending(&group->avgs_work))
		schedule_delayed_work(&group->avgs_work, PSI_FREQ);
}

static struct psi_group *iterate_groups(struct task_struct *task, void **iter)
{
	if (*iter == &psi_system)
		return NULL;

#ifdef CONFIG_CGROUPS
	if (static_branch_likely(&psi_cgroups_enabled)) {
		struct cgroup *cgroup = NULL;

		if (!*iter)
			cgroup = task->cgroups->dfl_cgrp;
		else
			cgroup = cgroup_parent(*iter);

		if (cgroup && cgroup_parent(cgroup)) {
			*iter = cgroup;
			return cgroup_psi(cgroup);
		}
	}
#endif
	return &psi_system;
}

static void psi_flags_change(struct task_struct *task, int clear, int set)
{
	if (((task->psi_flags & set) ||
	     (task->psi_flags & clear) != clear) &&
	    !psi_bug) {
		printk_deferred(KERN_ERR "psi: inconsistent task state! task=%d:%s cpu=%d psi_flags=%x clear=%x set=%x\n",
				task->pid, task->comm, task_cpu(task),
				task->psi_flags, clear, set);
		psi_bug = 1;
	}

	task->psi_flags &= ~clear;
	task->psi_flags |= set;
}

void psi_task_change(struct task_struct *task, int clear, int set)
{
	int cpu = task_cpu(task);
	struct psi_group *group;
	bool wake_clock = true;
	void *iter = NULL;
	u64 now;

	if (!task->pid)
		return;

	psi_flags_change(task, clear, set);

	now = cpu_clock(cpu);
	/*
	if (unlikely((clear & TSK_RUNNING) &&
		     (task->flags & PF_WQ_WORKER) &&
		     wq_worker_last_func(task) == psi_avgs_work))
		wake_clock = false;

	while ((group = iterate_groups(task, &iter)))
		psi_group_change(group, cpu, clear, set, now, wake_clock);
}

void psi_task_switch(struct task_struct *prev, struct task_struct *next,
		     bool sleep)
{
	struct psi_group *group, *common = NULL;
	int cpu = task_cpu(prev);
	void *iter;
	u64 now = cpu_clock(cpu);

	if (next->pid) {
		bool identical_state;

		psi_flags_change(next, 0, TSK_ONCPU);
		/*
		identical_state = prev->psi_flags == next->psi_flags;
		iter = NULL;
		while ((group = iterate_groups(next, &iter))) {
			if (identical_state &&
			    per_cpu_ptr(group->pcpu, cpu)->tasks[NR_ONCPU]) {
				common = group;
				break;
			}

			psi_group_change(group, cpu, 0, TSK_ONCPU, now, true);
		}
	}

	if (prev->pid) {
		int clear = TSK_ONCPU, set = 0;

		/*
		if (sleep) {
			clear |= TSK_RUNNING;
			if (prev->in_memstall)
				clear |= TSK_MEMSTALL_RUNNING;
			if (prev->in_iowait)
				set |= TSK_IOWAIT;
		}

		psi_flags_change(prev, clear, set);

		iter = NULL;
		while ((group = iterate_groups(prev, &iter)) && group != common)
			psi_group_change(group, cpu, clear, set, now, true);

		/*
		if (sleep) {
			clear &= ~TSK_ONCPU;
			for (; group; group = iterate_groups(prev, &iter))
				psi_group_change(group, cpu, clear, set, now, true);
		}
	}
}

void psi_memstall_enter(unsigned long *flags)
{
	struct rq_flags rf;
	struct rq *rq;

	if (static_branch_likely(&psi_disabled))
		return;

	if (*flags)
		return;
	/*
	rq = this_rq_lock_irq(&rf);

	current->in_memstall = 1;
	psi_task_change(current, 0, TSK_MEMSTALL | TSK_MEMSTALL_RUNNING);

	rq_unlock_irq(rq, &rf);
}

void psi_memstall_leave(unsigned long *flags)
{
	struct rq_flags rf;
	struct rq *rq;

	if (static_branch_likely(&psi_disabled))
		return;

	if (*flags)
		return;
	/*
	rq = this_rq_lock_irq(&rf);

	current->in_memstall = 0;
	psi_task_change(current, TSK_MEMSTALL | TSK_MEMSTALL_RUNNING, 0);

	rq_unlock_irq(rq, &rf);
}

#ifdef CONFIG_CGROUPS
int psi_cgroup_alloc(struct cgroup *cgroup)
{
	if (static_branch_likely(&psi_disabled))
		return 0;

	cgroup->psi = kmalloc(sizeof(struct psi_group), GFP_KERNEL);
	if (!cgroup->psi)
		return -ENOMEM;

	cgroup->psi->pcpu = alloc_percpu(struct psi_group_cpu);
	if (!cgroup->psi->pcpu) {
		kfree(cgroup->psi);
		return -ENOMEM;
	}
	group_init(cgroup->psi);
	return 0;
}

void psi_cgroup_free(struct cgroup *cgroup)
{
	if (static_branch_likely(&psi_disabled))
		return;

	cancel_delayed_work_sync(&cgroup->psi->avgs_work);
	free_percpu(cgroup->psi->pcpu);
	/* All triggers must be removed by now */
	WARN_ONCE(cgroup->psi->poll_states, "psi: trigger leak\n");
	kfree(cgroup->psi);
}

void cgroup_move_task(struct task_struct *task, struct css_set *to)
{
	unsigned int task_flags;
	struct rq_flags rf;
	struct rq *rq;

	if (static_branch_likely(&psi_disabled)) {
		/*
		rcu_assign_pointer(task->cgroups, to);
		return;
	}

	rq = task_rq_lock(task, &rf);

	/*
	task_flags = task->psi_flags;

	if (task_flags)
		psi_task_change(task, task_flags, 0);

	/* See comment above */
	rcu_assign_pointer(task->cgroups, to);

	if (task_flags)
		psi_task_change(task, 0, task_flags);

	task_rq_unlock(rq, task, &rf);
}
#endif /* CONFIG_CGROUPS */

int psi_show(struct seq_file *m, struct psi_group *group, enum psi_res res)
{
	int full;
	u64 now;

	if (static_branch_likely(&psi_disabled))
		return -EOPNOTSUPP;

	/* Update averages before reporting them */
	mutex_lock(&group->avgs_lock);
	now = sched_clock();
	collect_percpu_times(group, PSI_AVGS, NULL);
	if (now >= group->avg_next_update)
		group->avg_next_update = update_averages(group, now);
	mutex_unlock(&group->avgs_lock);

	for (full = 0; full < 2; full++) {
		unsigned long avg[3] = { 0, };
		u64 total = 0;
		int w;

		/* CPU FULL is undefined at the system level */
		if (!(group == &psi_system && res == PSI_CPU && full)) {
			for (w = 0; w < 3; w++)
				avg[w] = group->avg[res * 2 + full][w];
			total = div_u64(group->total[PSI_AVGS][res * 2 + full],
					NSEC_PER_USEC);
		}

		seq_printf(m, "%s avg10=%lu.%02lu avg60=%lu.%02lu avg300=%lu.%02lu total=%llu\n",
			   full ? "full" : "some",
			   LOAD_INT(avg[0]), LOAD_FRAC(avg[0]),
			   LOAD_INT(avg[1]), LOAD_FRAC(avg[1]),
			   LOAD_INT(avg[2]), LOAD_FRAC(avg[2]),
			   total);
	}

	return 0;
}

struct psi_trigger *psi_trigger_create(struct psi_group *group,
			char *buf, size_t nbytes, enum psi_res res)
{
	struct psi_trigger *t;
	enum psi_states state;
	u32 threshold_us;
	u32 window_us;

	if (static_branch_likely(&psi_disabled))
		return ERR_PTR(-EOPNOTSUPP);

	if (sscanf(buf, "some %u %u", &threshold_us, &window_us) == 2)
		state = PSI_IO_SOME + res * 2;
	else if (sscanf(buf, "full %u %u", &threshold_us, &window_us) == 2)
		state = PSI_IO_FULL + res * 2;
	else
		return ERR_PTR(-EINVAL);

	if (state >= PSI_NONIDLE)
		return ERR_PTR(-EINVAL);

	if (window_us < WINDOW_MIN_US ||
		window_us > WINDOW_MAX_US)
		return ERR_PTR(-EINVAL);

	/* Check threshold */
	if (threshold_us == 0 || threshold_us > window_us)
		return ERR_PTR(-EINVAL);

	t = kmalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return ERR_PTR(-ENOMEM);

	t->group = group;
	t->state = state;
	t->threshold = threshold_us * NSEC_PER_USEC;
	t->win.size = window_us * NSEC_PER_USEC;
	window_reset(&t->win, sched_clock(),
			group->total[PSI_POLL][t->state], 0);

	t->event = 0;
	t->last_event_time = 0;
	init_waitqueue_head(&t->event_wait);
	t->pending_event = false;

	mutex_lock(&group->trigger_lock);

	if (!rcu_access_pointer(group->poll_task)) {
		struct task_struct *task;

		task = kthread_create(psi_poll_worker, group, "psimon");
		if (IS_ERR(task)) {
			kfree(t);
			mutex_unlock(&group->trigger_lock);
			return ERR_CAST(task);
		}
		atomic_set(&group->poll_wakeup, 0);
		wake_up_process(task);
		rcu_assign_pointer(group->poll_task, task);
	}

	list_add(&t->node, &group->triggers);
	group->poll_min_period = min(group->poll_min_period,
		div_u64(t->win.size, UPDATES_PER_WINDOW));
	group->nr_triggers[t->state]++;
	group->poll_states |= (1 << t->state);

	mutex_unlock(&group->trigger_lock);

	return t;
}

void psi_trigger_destroy(struct psi_trigger *t)
{
	struct psi_group *group;
	struct task_struct *task_to_destroy = NULL;

	/*
	if (!t)
		return;

	group = t->group;
	/*
	wake_up_interruptible(&t->event_wait);

	mutex_lock(&group->trigger_lock);

	if (!list_empty(&t->node)) {
		struct psi_trigger *tmp;
		u64 period = ULLONG_MAX;

		list_del(&t->node);
		group->nr_triggers[t->state]--;
		if (!group->nr_triggers[t->state])
			group->poll_states &= ~(1 << t->state);
		/* reset min update period for the remaining triggers */
		list_for_each_entry(tmp, &group->triggers, node)
			period = min(period, div_u64(tmp->win.size,
					UPDATES_PER_WINDOW));
		group->poll_min_period = period;
		/* Destroy poll_task when the last trigger is destroyed */
		if (group->poll_states == 0) {
			group->polling_until = 0;
			task_to_destroy = rcu_dereference_protected(
					group->poll_task,
					lockdep_is_held(&group->trigger_lock));
			rcu_assign_pointer(group->poll_task, NULL);
			del_timer(&group->poll_timer);
		}
	}

	mutex_unlock(&group->trigger_lock);

	/*
	synchronize_rcu();
	/*
	if (task_to_destroy) {
		/*
		kthread_stop(task_to_destroy);
	}
	kfree(t);
}

__poll_t psi_trigger_poll(void **trigger_ptr,
				struct file *file, poll_table *wait)
{
	__poll_t ret = DEFAULT_POLLMASK;
	struct psi_trigger *t;

	if (static_branch_likely(&psi_disabled))
		return DEFAULT_POLLMASK | EPOLLERR | EPOLLPRI;

	t = smp_load_acquire(trigger_ptr);
	if (!t)
		return DEFAULT_POLLMASK | EPOLLERR | EPOLLPRI;

	poll_wait(file, &t->event_wait, wait);

	if (cmpxchg(&t->event, 1, 0) == 1)
		ret |= EPOLLPRI;

	return ret;
}

#ifdef CONFIG_PROC_FS
static int psi_io_show(struct seq_file *m, void *v)
{
	return psi_show(m, &psi_system, PSI_IO);
}

static int psi_memory_show(struct seq_file *m, void *v)
{
	return psi_show(m, &psi_system, PSI_MEM);
}

static int psi_cpu_show(struct seq_file *m, void *v)
{
	return psi_show(m, &psi_system, PSI_CPU);
}

static int psi_open(struct file *file, int (*psi_show)(struct seq_file *, void *))
{
	if (file->f_mode & FMODE_WRITE && !capable(CAP_SYS_RESOURCE))
		return -EPERM;

	return single_open(file, psi_show, NULL);
}

static int psi_io_open(struct inode *inode, struct file *file)
{
	return psi_open(file, psi_io_show);
}

static int psi_memory_open(struct inode *inode, struct file *file)
{
	return psi_open(file, psi_memory_show);
}

static int psi_cpu_open(struct inode *inode, struct file *file)
{
	return psi_open(file, psi_cpu_show);
}

static ssize_t psi_write(struct file *file, const char __user *user_buf,
			 size_t nbytes, enum psi_res res)
{
	char buf[32];
	size_t buf_size;
	struct seq_file *seq;
	struct psi_trigger *new;

	if (static_branch_likely(&psi_disabled))
		return -EOPNOTSUPP;

	if (!nbytes)
		return -EINVAL;

	buf_size = min(nbytes, sizeof(buf));
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;

	buf[buf_size - 1] = '\0';

	seq = file->private_data;

	/* Take seq->lock to protect seq->private from concurrent writes */
	mutex_lock(&seq->lock);

	/* Allow only one trigger per file descriptor */
	if (seq->private) {
		mutex_unlock(&seq->lock);
		return -EBUSY;
	}

	new = psi_trigger_create(&psi_system, buf, nbytes, res);
	if (IS_ERR(new)) {
		mutex_unlock(&seq->lock);
		return PTR_ERR(new);
	}

	smp_store_release(&seq->private, new);
	mutex_unlock(&seq->lock);

	return nbytes;
}

static ssize_t psi_io_write(struct file *file, const char __user *user_buf,
			    size_t nbytes, loff_t *ppos)
{
	return psi_write(file, user_buf, nbytes, PSI_IO);
}

static ssize_t psi_memory_write(struct file *file, const char __user *user_buf,
				size_t nbytes, loff_t *ppos)
{
	return psi_write(file, user_buf, nbytes, PSI_MEM);
}

static ssize_t psi_cpu_write(struct file *file, const char __user *user_buf,
			     size_t nbytes, loff_t *ppos)
{
	return psi_write(file, user_buf, nbytes, PSI_CPU);
}

static __poll_t psi_fop_poll(struct file *file, poll_table *wait)
{
	struct seq_file *seq = file->private_data;

	return psi_trigger_poll(&seq->private, file, wait);
}

static int psi_fop_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;

	psi_trigger_destroy(seq->private);
	return single_release(inode, file);
}

static const struct proc_ops psi_io_proc_ops = {
	.proc_open	= psi_io_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= psi_io_write,
	.proc_poll	= psi_fop_poll,
	.proc_release	= psi_fop_release,
};

static const struct proc_ops psi_memory_proc_ops = {
	.proc_open	= psi_memory_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= psi_memory_write,
	.proc_poll	= psi_fop_poll,
	.proc_release	= psi_fop_release,
};

static const struct proc_ops psi_cpu_proc_ops = {
	.proc_open	= psi_cpu_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= psi_cpu_write,
	.proc_poll	= psi_fop_poll,
	.proc_release	= psi_fop_release,
};

static int __init psi_proc_init(void)
{
	if (psi_enable) {
		proc_mkdir("pressure", NULL);
		proc_create("pressure/io", 0666, NULL, &psi_io_proc_ops);
		proc_create("pressure/memory", 0666, NULL, &psi_memory_proc_ops);
		proc_create("pressure/cpu", 0666, NULL, &psi_cpu_proc_ops);
	}
	return 0;
}
module_init(psi_proc_init);

#endif /* CONFIG_PROC_FS */
