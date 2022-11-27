
#ifdef CONFIG_IRQ_TIME_ACCOUNTING

DEFINE_PER_CPU(struct irqtime, cpu_irqtime);

static int sched_clock_irqtime;

void enable_sched_clock_irqtime(void)
{
	sched_clock_irqtime = 1;
}

void disable_sched_clock_irqtime(void)
{
	sched_clock_irqtime = 0;
}

static void irqtime_account_delta(struct irqtime *irqtime, u64 delta,
				  enum cpu_usage_stat idx)
{
	u64 *cpustat = kcpustat_this_cpu->cpustat;

	u64_stats_update_begin(&irqtime->sync);
	cpustat[idx] += delta;
	irqtime->total += delta;
	irqtime->tick_delta += delta;
	u64_stats_update_end(&irqtime->sync);
}

void irqtime_account_irq(struct task_struct *curr, unsigned int offset)
{
	struct irqtime *irqtime = this_cpu_ptr(&cpu_irqtime);
	unsigned int pc;
	s64 delta;
	int cpu;

	if (!sched_clock_irqtime)
		return;

	cpu = smp_processor_id();
	delta = sched_clock_cpu(cpu) - irqtime->irq_start_time;
	irqtime->irq_start_time += delta;
	pc = irq_count() - offset;

	/*
	if (pc & HARDIRQ_MASK)
		irqtime_account_delta(irqtime, delta, CPUTIME_IRQ);
	else if ((pc & SOFTIRQ_OFFSET) && curr != this_cpu_ksoftirqd())
		irqtime_account_delta(irqtime, delta, CPUTIME_SOFTIRQ);
}

static u64 irqtime_tick_accounted(u64 maxtime)
{
	struct irqtime *irqtime = this_cpu_ptr(&cpu_irqtime);
	u64 delta;

	delta = min(irqtime->tick_delta, maxtime);
	irqtime->tick_delta -= delta;

	return delta;
}

#else /* CONFIG_IRQ_TIME_ACCOUNTING */

#define sched_clock_irqtime	(0)

static u64 irqtime_tick_accounted(u64 dummy)
{
	return 0;
}

#endif /* !CONFIG_IRQ_TIME_ACCOUNTING */

static inline void task_group_account_field(struct task_struct *p, int index,
					    u64 tmp)
{
	/*
	__this_cpu_add(kernel_cpustat.cpustat[index], tmp);

	cgroup_account_cputime_field(p, index, tmp);
}

void account_user_time(struct task_struct *p, u64 cputime)
{
	int index;

	/* Add user time to process. */
	p->utime += cputime;
	account_group_user_time(p, cputime);

	index = (task_nice(p) > 0) ? CPUTIME_NICE : CPUTIME_USER;

	/* Add user time to cpustat. */
	task_group_account_field(p, index, cputime);

	/* Account for user time used */
	acct_account_cputime(p);
}

void account_guest_time(struct task_struct *p, u64 cputime)
{
	u64 *cpustat = kcpustat_this_cpu->cpustat;

	/* Add guest time to process. */
	p->utime += cputime;
	account_group_user_time(p, cputime);
	p->gtime += cputime;

	/* Add guest time to cpustat. */
	if (task_nice(p) > 0) {
		task_group_account_field(p, CPUTIME_NICE, cputime);
		cpustat[CPUTIME_GUEST_NICE] += cputime;
	} else {
		task_group_account_field(p, CPUTIME_USER, cputime);
		cpustat[CPUTIME_GUEST] += cputime;
	}
}

void account_system_index_time(struct task_struct *p,
			       u64 cputime, enum cpu_usage_stat index)
{
	/* Add system time to process. */
	p->stime += cputime;
	account_group_system_time(p, cputime);

	/* Add system time to cpustat. */
	task_group_account_field(p, index, cputime);

	/* Account for system time used */
	acct_account_cputime(p);
}

void account_system_time(struct task_struct *p, int hardirq_offset, u64 cputime)
{
	int index;

	if ((p->flags & PF_VCPU) && (irq_count() - hardirq_offset == 0)) {
		account_guest_time(p, cputime);
		return;
	}

	if (hardirq_count() - hardirq_offset)
		index = CPUTIME_IRQ;
	else if (in_serving_softirq())
		index = CPUTIME_SOFTIRQ;
	else
		index = CPUTIME_SYSTEM;

	account_system_index_time(p, cputime, index);
}

void account_steal_time(u64 cputime)
{
	u64 *cpustat = kcpustat_this_cpu->cpustat;

	cpustat[CPUTIME_STEAL] += cputime;
}

void account_idle_time(u64 cputime)
{
	u64 *cpustat = kcpustat_this_cpu->cpustat;
	struct rq *rq = this_rq();

	if (atomic_read(&rq->nr_iowait) > 0)
		cpustat[CPUTIME_IOWAIT] += cputime;
	else
		cpustat[CPUTIME_IDLE] += cputime;
}


#ifdef CONFIG_SCHED_CORE
void __account_forceidle_time(struct task_struct *p, u64 delta)
{
	__schedstat_add(p->stats.core_forceidle_sum, delta);

	task_group_account_field(p, CPUTIME_FORCEIDLE, delta);
}
#endif

static __always_inline u64 steal_account_process_time(u64 maxtime)
{
#ifdef CONFIG_PARAVIRT
	if (static_key_false(&paravirt_steal_enabled)) {
		u64 steal;

		steal = paravirt_steal_clock(smp_processor_id());
		steal -= this_rq()->prev_steal_time;
		steal = min(steal, maxtime);
		account_steal_time(steal);
		this_rq()->prev_steal_time += steal;

		return steal;
	}
#endif
	return 0;
}

static inline u64 account_other_time(u64 max)
{
	u64 accounted;

	lockdep_assert_irqs_disabled();

	accounted = steal_account_process_time(max);

	if (accounted < max)
		accounted += irqtime_tick_accounted(max - accounted);

	return accounted;
}

#ifdef CONFIG_64BIT
static inline u64 read_sum_exec_runtime(struct task_struct *t)
{
	return t->se.sum_exec_runtime;
}
#else
static u64 read_sum_exec_runtime(struct task_struct *t)
{
	u64 ns;
	struct rq_flags rf;
	struct rq *rq;

	rq = task_rq_lock(t, &rf);
	ns = t->se.sum_exec_runtime;
	task_rq_unlock(rq, t, &rf);

	return ns;
}
#endif

void thread_group_cputime(struct task_struct *tsk, struct task_cputime *times)
{
	struct signal_struct *sig = tsk->signal;
	u64 utime, stime;
	struct task_struct *t;
	unsigned int seq, nextseq;
	unsigned long flags;

	/*
	if (same_thread_group(current, tsk))
		(void) task_sched_runtime(current);

	rcu_read_lock();
	/* Attempt a lockless read on the first round. */
	nextseq = 0;
	do {
		seq = nextseq;
		flags = read_seqbegin_or_lock_irqsave(&sig->stats_lock, &seq);
		times->utime = sig->utime;
		times->stime = sig->stime;
		times->sum_exec_runtime = sig->sum_sched_runtime;

		for_each_thread(tsk, t) {
			task_cputime(t, &utime, &stime);
			times->utime += utime;
			times->stime += stime;
			times->sum_exec_runtime += read_sum_exec_runtime(t);
		}
		/* If lockless access failed, take the lock. */
		nextseq = 1;
	} while (need_seqretry(&sig->stats_lock, seq));
	done_seqretry_irqrestore(&sig->stats_lock, seq, flags);
	rcu_read_unlock();
}

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
static void irqtime_account_process_tick(struct task_struct *p, int user_tick,
					 int ticks)
{
	u64 other, cputime = TICK_NSEC * ticks;

	/*
	other = account_other_time(ULONG_MAX);
	if (other >= cputime)
		return;

	cputime -= other;

	if (this_cpu_ksoftirqd() == p) {
		/*
		account_system_index_time(p, cputime, CPUTIME_SOFTIRQ);
	} else if (user_tick) {
		account_user_time(p, cputime);
	} else if (p == this_rq()->idle) {
		account_idle_time(cputime);
	} else if (p->flags & PF_VCPU) { /* System time or guest time */
		account_guest_time(p, cputime);
	} else {
		account_system_index_time(p, cputime, CPUTIME_SYSTEM);
	}
}

static void irqtime_account_idle_ticks(int ticks)
{
	irqtime_account_process_tick(current, 0, ticks);
}
#else /* CONFIG_IRQ_TIME_ACCOUNTING */
static inline void irqtime_account_idle_ticks(int ticks) { }
static inline void irqtime_account_process_tick(struct task_struct *p, int user_tick,
						int nr_ticks) { }
#endif /* CONFIG_IRQ_TIME_ACCOUNTING */

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE

# ifndef __ARCH_HAS_VTIME_TASK_SWITCH
void vtime_task_switch(struct task_struct *prev)
{
	if (is_idle_task(prev))
		vtime_account_idle(prev);
	else
		vtime_account_kernel(prev);

	vtime_flush(prev);
	arch_vtime_task_switch(prev);
}
# endif

void vtime_account_irq(struct task_struct *tsk, unsigned int offset)
{
	unsigned int pc = irq_count() - offset;

	if (pc & HARDIRQ_OFFSET) {
		vtime_account_hardirq(tsk);
	} else if (pc & SOFTIRQ_OFFSET) {
		vtime_account_softirq(tsk);
	} else if (!IS_ENABLED(CONFIG_HAVE_VIRT_CPU_ACCOUNTING_IDLE) &&
		   is_idle_task(tsk)) {
		vtime_account_idle(tsk);
	} else {
		vtime_account_kernel(tsk);
	}
}

void cputime_adjust(struct task_cputime *curr, struct prev_cputime *prev,
		    u64 *ut, u64 *st)
{
}

void task_cputime_adjusted(struct task_struct *p, u64 *ut, u64 *st)
{
}
EXPORT_SYMBOL_GPL(task_cputime_adjusted);

void thread_group_cputime_adjusted(struct task_struct *p, u64 *ut, u64 *st)
{
	struct task_cputime cputime;

	thread_group_cputime(p, &cputime);

}

#else /* !CONFIG_VIRT_CPU_ACCOUNTING_NATIVE: */

void account_process_tick(struct task_struct *p, int user_tick)
{
	u64 cputime, steal;

	if (vtime_accounting_enabled_this_cpu())
		return;

	if (sched_clock_irqtime) {
		irqtime_account_process_tick(p, user_tick, 1);
		return;
	}

	cputime = TICK_NSEC;
	steal = steal_account_process_time(ULONG_MAX);

	if (steal >= cputime)
		return;

	cputime -= steal;

	if (user_tick)
		account_user_time(p, cputime);
	else if ((p != this_rq()->idle) || (irq_count() != HARDIRQ_OFFSET))
		account_system_time(p, HARDIRQ_OFFSET, cputime);
	else
		account_idle_time(cputime);
}

void account_idle_ticks(unsigned long ticks)
{
	u64 cputime, steal;

	if (sched_clock_irqtime) {
		irqtime_account_idle_ticks(ticks);
		return;
	}

	cputime = ticks * TICK_NSEC;
	steal = steal_account_process_time(ULONG_MAX);

	if (steal >= cputime)
		return;

	cputime -= steal;
	account_idle_time(cputime);
}

void cputime_adjust(struct task_cputime *curr, struct prev_cputime *prev,
		    u64 *ut, u64 *st)
{
	u64 rtime, stime, utime;
	unsigned long flags;

	/* Serialize concurrent callers such that we can honour our guarantees */
	raw_spin_lock_irqsave(&prev->lock, flags);
	rtime = curr->sum_exec_runtime;

	/*
	if (prev->stime + prev->utime >= rtime)
		goto out;

	stime = curr->stime;
	utime = curr->utime;

	/*
	if (stime == 0) {
		utime = rtime;
		goto update;
	}

	if (utime == 0) {
		stime = rtime;
		goto update;
	}

	stime = mul_u64_u64_div_u64(stime, rtime, stime + utime);

update:
	/*
	if (stime < prev->stime)
		stime = prev->stime;
	utime = rtime - stime;

	/*
	if (utime < prev->utime) {
		utime = prev->utime;
		stime = rtime - utime;
	}

	prev->stime = stime;
	prev->utime = utime;
out:
	raw_spin_unlock_irqrestore(&prev->lock, flags);
}

void task_cputime_adjusted(struct task_struct *p, u64 *ut, u64 *st)
{
	struct task_cputime cputime = {
		.sum_exec_runtime = p->se.sum_exec_runtime,
	};

	if (task_cputime(p, &cputime.utime, &cputime.stime))
		cputime.sum_exec_runtime = task_sched_runtime(p);
	cputime_adjust(&cputime, &p->prev_cputime, ut, st);
}
EXPORT_SYMBOL_GPL(task_cputime_adjusted);

void thread_group_cputime_adjusted(struct task_struct *p, u64 *ut, u64 *st)
{
	struct task_cputime cputime;

	thread_group_cputime(p, &cputime);
	cputime_adjust(&cputime, &p->signal->prev_cputime, ut, st);
}
#endif /* !CONFIG_VIRT_CPU_ACCOUNTING_NATIVE */

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
static u64 vtime_delta(struct vtime *vtime)
{
	unsigned long long clock;

	clock = sched_clock();
	if (clock < vtime->starttime)
		return 0;

	return clock - vtime->starttime;
}

static u64 get_vtime_delta(struct vtime *vtime)
{
	u64 delta = vtime_delta(vtime);
	u64 other;

	/*
	other = account_other_time(delta);
	WARN_ON_ONCE(vtime->state == VTIME_INACTIVE);
	vtime->starttime += delta;

	return delta - other;
}

static void vtime_account_system(struct task_struct *tsk,
				 struct vtime *vtime)
{
	vtime->stime += get_vtime_delta(vtime);
	if (vtime->stime >= TICK_NSEC) {
		account_system_time(tsk, irq_count(), vtime->stime);
		vtime->stime = 0;
	}
}

static void vtime_account_guest(struct task_struct *tsk,
				struct vtime *vtime)
{
	vtime->gtime += get_vtime_delta(vtime);
	if (vtime->gtime >= TICK_NSEC) {
		account_guest_time(tsk, vtime->gtime);
		vtime->gtime = 0;
	}
}

static void __vtime_account_kernel(struct task_struct *tsk,
				   struct vtime *vtime)
{
	/* We might have scheduled out from guest path */
	if (vtime->state == VTIME_GUEST)
		vtime_account_guest(tsk, vtime);
	else
		vtime_account_system(tsk, vtime);
}

void vtime_account_kernel(struct task_struct *tsk)
{
	struct vtime *vtime = &tsk->vtime;

	if (!vtime_delta(vtime))
		return;

	write_seqcount_begin(&vtime->seqcount);
	__vtime_account_kernel(tsk, vtime);
	write_seqcount_end(&vtime->seqcount);
}

void vtime_user_enter(struct task_struct *tsk)
{
	struct vtime *vtime = &tsk->vtime;

	write_seqcount_begin(&vtime->seqcount);
	vtime_account_system(tsk, vtime);
	vtime->state = VTIME_USER;
	write_seqcount_end(&vtime->seqcount);
}

void vtime_user_exit(struct task_struct *tsk)
{
	struct vtime *vtime = &tsk->vtime;

	write_seqcount_begin(&vtime->seqcount);
	vtime->utime += get_vtime_delta(vtime);
	if (vtime->utime >= TICK_NSEC) {
		account_user_time(tsk, vtime->utime);
		vtime->utime = 0;
	}
	vtime->state = VTIME_SYS;
	write_seqcount_end(&vtime->seqcount);
}

void vtime_guest_enter(struct task_struct *tsk)
{
	struct vtime *vtime = &tsk->vtime;
	/*
	write_seqcount_begin(&vtime->seqcount);
	vtime_account_system(tsk, vtime);
	tsk->flags |= PF_VCPU;
	vtime->state = VTIME_GUEST;
	write_seqcount_end(&vtime->seqcount);
}
EXPORT_SYMBOL_GPL(vtime_guest_enter);

void vtime_guest_exit(struct task_struct *tsk)
{
	struct vtime *vtime = &tsk->vtime;

	write_seqcount_begin(&vtime->seqcount);
	vtime_account_guest(tsk, vtime);
	tsk->flags &= ~PF_VCPU;
	vtime->state = VTIME_SYS;
	write_seqcount_end(&vtime->seqcount);
}
EXPORT_SYMBOL_GPL(vtime_guest_exit);

void vtime_account_idle(struct task_struct *tsk)
{
	account_idle_time(get_vtime_delta(&tsk->vtime));
}

void vtime_task_switch_generic(struct task_struct *prev)
{
	struct vtime *vtime = &prev->vtime;

	write_seqcount_begin(&vtime->seqcount);
	if (vtime->state == VTIME_IDLE)
		vtime_account_idle(prev);
	else
		__vtime_account_kernel(prev, vtime);
	vtime->state = VTIME_INACTIVE;
	vtime->cpu = -1;
	write_seqcount_end(&vtime->seqcount);

	vtime = &current->vtime;

	write_seqcount_begin(&vtime->seqcount);
	if (is_idle_task(current))
		vtime->state = VTIME_IDLE;
	else if (current->flags & PF_VCPU)
		vtime->state = VTIME_GUEST;
	else
		vtime->state = VTIME_SYS;
	vtime->starttime = sched_clock();
	vtime->cpu = smp_processor_id();
	write_seqcount_end(&vtime->seqcount);
}

void vtime_init_idle(struct task_struct *t, int cpu)
{
	struct vtime *vtime = &t->vtime;
	unsigned long flags;

	local_irq_save(flags);
	write_seqcount_begin(&vtime->seqcount);
	vtime->state = VTIME_IDLE;
	vtime->starttime = sched_clock();
	vtime->cpu = cpu;
	write_seqcount_end(&vtime->seqcount);
	local_irq_restore(flags);
}

u64 task_gtime(struct task_struct *t)
{
	struct vtime *vtime = &t->vtime;
	unsigned int seq;
	u64 gtime;

	if (!vtime_accounting_enabled())
		return t->gtime;

	do {
		seq = read_seqcount_begin(&vtime->seqcount);

		gtime = t->gtime;
		if (vtime->state == VTIME_GUEST)
			gtime += vtime->gtime + vtime_delta(vtime);

	} while (read_seqcount_retry(&vtime->seqcount, seq));

	return gtime;
}

bool task_cputime(struct task_struct *t, u64 *utime, u64 *stime)
{
	struct vtime *vtime = &t->vtime;
	unsigned int seq;
	u64 delta;
	int ret;

	if (!vtime_accounting_enabled()) {
		*utime = t->utime;
		*stime = t->stime;
		return false;
	}

	do {
		ret = false;
		seq = read_seqcount_begin(&vtime->seqcount);

		*utime = t->utime;
		*stime = t->stime;

		/* Task is sleeping or idle, nothing to add */
		if (vtime->state < VTIME_SYS)
			continue;

		ret = true;
		delta = vtime_delta(vtime);

		/*
		if (vtime->state == VTIME_SYS)
			*stime += vtime->stime + delta;
		else
			*utime += vtime->utime + delta;
	} while (read_seqcount_retry(&vtime->seqcount, seq));

	return ret;
}

static int vtime_state_fetch(struct vtime *vtime, int cpu)
{
	int state = READ_ONCE(vtime->state);

	/*
	if (vtime->cpu != cpu && vtime->cpu != -1)
		return -EAGAIN;

	/*
	if (state == VTIME_INACTIVE)
		return -EAGAIN;

	return state;
}

static u64 kcpustat_user_vtime(struct vtime *vtime)
{
	if (vtime->state == VTIME_USER)
		return vtime->utime + vtime_delta(vtime);
	else if (vtime->state == VTIME_GUEST)
		return vtime->gtime + vtime_delta(vtime);
	return 0;
}

static int kcpustat_field_vtime(u64 *cpustat,
				struct task_struct *tsk,
				enum cpu_usage_stat usage,
				int cpu, u64 *val)
{
	struct vtime *vtime = &tsk->vtime;
	unsigned int seq;

	do {
		int state;

		seq = read_seqcount_begin(&vtime->seqcount);

		state = vtime_state_fetch(vtime, cpu);
		if (state < 0)
			return state;

		*val = cpustat[usage];

		/*
		switch (usage) {
		case CPUTIME_SYSTEM:
			if (state == VTIME_SYS)
				*val += vtime->stime + vtime_delta(vtime);
			break;
		case CPUTIME_USER:
			if (task_nice(tsk) <= 0)
				*val += kcpustat_user_vtime(vtime);
			break;
		case CPUTIME_NICE:
			if (task_nice(tsk) > 0)
				*val += kcpustat_user_vtime(vtime);
			break;
		case CPUTIME_GUEST:
			if (state == VTIME_GUEST && task_nice(tsk) <= 0)
				*val += vtime->gtime + vtime_delta(vtime);
			break;
		case CPUTIME_GUEST_NICE:
			if (state == VTIME_GUEST && task_nice(tsk) > 0)
				*val += vtime->gtime + vtime_delta(vtime);
			break;
		default:
			break;
		}
	} while (read_seqcount_retry(&vtime->seqcount, seq));

	return 0;
}

u64 kcpustat_field(struct kernel_cpustat *kcpustat,
		   enum cpu_usage_stat usage, int cpu)
{
	u64 *cpustat = kcpustat->cpustat;
	u64 val = cpustat[usage];
	struct rq *rq;
	int err;

	if (!vtime_accounting_enabled_cpu(cpu))
		return val;

	rq = cpu_rq(cpu);

	for (;;) {
		struct task_struct *curr;

		rcu_read_lock();
		curr = rcu_dereference(rq->curr);
		if (WARN_ON_ONCE(!curr)) {
			rcu_read_unlock();
			return cpustat[usage];
		}

		err = kcpustat_field_vtime(cpustat, curr, usage, cpu, &val);
		rcu_read_unlock();

		if (!err)
			return val;

		cpu_relax();
	}
}
EXPORT_SYMBOL_GPL(kcpustat_field);

static int kcpustat_cpu_fetch_vtime(struct kernel_cpustat *dst,
				    const struct kernel_cpustat *src,
				    struct task_struct *tsk, int cpu)
{
	struct vtime *vtime = &tsk->vtime;
	unsigned int seq;

	do {
		u64 *cpustat;
		u64 delta;
		int state;

		seq = read_seqcount_begin(&vtime->seqcount);

		state = vtime_state_fetch(vtime, cpu);
		if (state < 0)
			return state;

		*dst = *src;
		cpustat = dst->cpustat;

		/* Task is sleeping, dead or idle, nothing to add */
		if (state < VTIME_SYS)
			continue;

		delta = vtime_delta(vtime);

		/*
		if (state == VTIME_SYS) {
			cpustat[CPUTIME_SYSTEM] += vtime->stime + delta;
		} else if (state == VTIME_USER) {
			if (task_nice(tsk) > 0)
				cpustat[CPUTIME_NICE] += vtime->utime + delta;
			else
				cpustat[CPUTIME_USER] += vtime->utime + delta;
		} else {
			WARN_ON_ONCE(state != VTIME_GUEST);
			if (task_nice(tsk) > 0) {
				cpustat[CPUTIME_GUEST_NICE] += vtime->gtime + delta;
				cpustat[CPUTIME_NICE] += vtime->gtime + delta;
			} else {
				cpustat[CPUTIME_GUEST] += vtime->gtime + delta;
				cpustat[CPUTIME_USER] += vtime->gtime + delta;
			}
		}
	} while (read_seqcount_retry(&vtime->seqcount, seq));

	return 0;
}

void kcpustat_cpu_fetch(struct kernel_cpustat *dst, int cpu)
{
	const struct kernel_cpustat *src = &kcpustat_cpu(cpu);
	struct rq *rq;
	int err;

	if (!vtime_accounting_enabled_cpu(cpu)) {
		*dst = *src;
		return;
	}

	rq = cpu_rq(cpu);

	for (;;) {
		struct task_struct *curr;

		rcu_read_lock();
		curr = rcu_dereference(rq->curr);
		if (WARN_ON_ONCE(!curr)) {
			rcu_read_unlock();
			*dst = *src;
			return;
		}

		err = kcpustat_cpu_fetch_vtime(dst, src, curr, cpu);
		rcu_read_unlock();

		if (!err)
			return;

		cpu_relax();
	}
}
EXPORT_SYMBOL_GPL(kcpustat_cpu_fetch);

#endif /* CONFIG_VIRT_CPU_ACCOUNTING_GEN */
