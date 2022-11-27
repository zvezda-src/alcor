

#ifdef CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE
#define MEMBARRIER_PRIVATE_EXPEDITED_SYNC_CORE_BITMASK			\
	(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE			\
	| MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE)
#else
#define MEMBARRIER_PRIVATE_EXPEDITED_SYNC_CORE_BITMASK	0
#endif

#ifdef CONFIG_RSEQ
#define MEMBARRIER_PRIVATE_EXPEDITED_RSEQ_BITMASK		\
	(MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ			\
	| MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ)
#else
#define MEMBARRIER_PRIVATE_EXPEDITED_RSEQ_BITMASK	0
#endif

#define MEMBARRIER_CMD_BITMASK						\
	(MEMBARRIER_CMD_GLOBAL | MEMBARRIER_CMD_GLOBAL_EXPEDITED	\
	| MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED			\
	| MEMBARRIER_CMD_PRIVATE_EXPEDITED				\
	| MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED			\
	| MEMBARRIER_PRIVATE_EXPEDITED_SYNC_CORE_BITMASK		\
	| MEMBARRIER_PRIVATE_EXPEDITED_RSEQ_BITMASK)

static void ipi_mb(void *info)
{
	smp_mb();	/* IPIs should be serializing but paranoid. */
}

static void ipi_sync_core(void *info)
{
	/*
	smp_mb();	/* IPIs should be serializing but paranoid. */

	sync_core_before_usermode();
}

static void ipi_rseq(void *info)
{
	/*
	smp_mb();
	rseq_preempt(current);
}

static void ipi_sync_rq_state(void *info)
{
	struct mm_struct *mm = (struct mm_struct *) info;

	if (current->mm != mm)
		return;
	this_cpu_write(runqueues.membarrier_state,
		       atomic_read(&mm->membarrier_state));
	/*
	smp_mb();
}

void membarrier_exec_mmap(struct mm_struct *mm)
{
	/*
	smp_mb();
	atomic_set(&mm->membarrier_state, 0);
	/*
	this_cpu_write(runqueues.membarrier_state, 0);
}

void membarrier_update_current_mm(struct mm_struct *next_mm)
{
	struct rq *rq = this_rq();
	int membarrier_state = 0;

	if (next_mm)
		membarrier_state = atomic_read(&next_mm->membarrier_state);
	if (READ_ONCE(rq->membarrier_state) == membarrier_state)
		return;
	WRITE_ONCE(rq->membarrier_state, membarrier_state);
}

static int membarrier_global_expedited(void)
{
	int cpu;
	cpumask_var_t tmpmask;

	if (num_online_cpus() == 1)
		return 0;

	/*
	smp_mb();	/* system call entry is not a mb. */

	if (!zalloc_cpumask_var(&tmpmask, GFP_KERNEL))
		return -ENOMEM;

	cpus_read_lock();
	rcu_read_lock();
	for_each_online_cpu(cpu) {
		struct task_struct *p;

		/*
		if (cpu == raw_smp_processor_id())
			continue;

		if (!(READ_ONCE(cpu_rq(cpu)->membarrier_state) &
		    MEMBARRIER_STATE_GLOBAL_EXPEDITED))
			continue;

		/*
		p = rcu_dereference(cpu_rq(cpu)->curr);
		if (!p->mm)
			continue;

		__cpumask_set_cpu(cpu, tmpmask);
	}
	rcu_read_unlock();

	preempt_disable();
	smp_call_function_many(tmpmask, ipi_mb, NULL, 1);
	preempt_enable();

	free_cpumask_var(tmpmask);
	cpus_read_unlock();

	/*
	smp_mb();	/* exit from system call is not a mb */
	return 0;
}

static int membarrier_private_expedited(int flags, int cpu_id)
{
	cpumask_var_t tmpmask;
	struct mm_struct *mm = current->mm;
	smp_call_func_t ipi_func = ipi_mb;

	if (flags == MEMBARRIER_FLAG_SYNC_CORE) {
		if (!IS_ENABLED(CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE))
			return -EINVAL;
		if (!(atomic_read(&mm->membarrier_state) &
		      MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY))
			return -EPERM;
		ipi_func = ipi_sync_core;
	} else if (flags == MEMBARRIER_FLAG_RSEQ) {
		if (!IS_ENABLED(CONFIG_RSEQ))
			return -EINVAL;
		if (!(atomic_read(&mm->membarrier_state) &
		      MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ_READY))
			return -EPERM;
		ipi_func = ipi_rseq;
	} else {
		WARN_ON_ONCE(flags);
		if (!(atomic_read(&mm->membarrier_state) &
		      MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY))
			return -EPERM;
	}

	if (flags != MEMBARRIER_FLAG_SYNC_CORE &&
	    (atomic_read(&mm->mm_users) == 1 || num_online_cpus() == 1))
		return 0;

	/*
	smp_mb();	/* system call entry is not a mb. */

	if (cpu_id < 0 && !zalloc_cpumask_var(&tmpmask, GFP_KERNEL))
		return -ENOMEM;

	cpus_read_lock();

	if (cpu_id >= 0) {
		struct task_struct *p;

		if (cpu_id >= nr_cpu_ids || !cpu_online(cpu_id))
			goto out;
		rcu_read_lock();
		p = rcu_dereference(cpu_rq(cpu_id)->curr);
		if (!p || p->mm != mm) {
			rcu_read_unlock();
			goto out;
		}
		rcu_read_unlock();
	} else {
		int cpu;

		rcu_read_lock();
		for_each_online_cpu(cpu) {
			struct task_struct *p;

			p = rcu_dereference(cpu_rq(cpu)->curr);
			if (p && p->mm == mm)
				__cpumask_set_cpu(cpu, tmpmask);
		}
		rcu_read_unlock();
	}

	if (cpu_id >= 0) {
		/*
		smp_call_function_single(cpu_id, ipi_func, NULL, 1);
	} else {
		/*
		if (flags != MEMBARRIER_FLAG_SYNC_CORE) {
			preempt_disable();
			smp_call_function_many(tmpmask, ipi_func, NULL, true);
			preempt_enable();
		} else {
			on_each_cpu_mask(tmpmask, ipi_func, NULL, true);
		}
	}

out:
	if (cpu_id < 0)
		free_cpumask_var(tmpmask);
	cpus_read_unlock();

	/*
	smp_mb();	/* exit from system call is not a mb */

	return 0;
}

static int sync_runqueues_membarrier_state(struct mm_struct *mm)
{
	int membarrier_state = atomic_read(&mm->membarrier_state);
	cpumask_var_t tmpmask;
	int cpu;

	if (atomic_read(&mm->mm_users) == 1 || num_online_cpus() == 1) {
		this_cpu_write(runqueues.membarrier_state, membarrier_state);

		/*
		smp_mb();
		return 0;
	}

	if (!zalloc_cpumask_var(&tmpmask, GFP_KERNEL))
		return -ENOMEM;

	/*
	synchronize_rcu();

	/*
	cpus_read_lock();
	rcu_read_lock();
	for_each_online_cpu(cpu) {
		struct rq *rq = cpu_rq(cpu);
		struct task_struct *p;

		p = rcu_dereference(rq->curr);
		if (p && p->mm == mm)
			__cpumask_set_cpu(cpu, tmpmask);
	}
	rcu_read_unlock();

	on_each_cpu_mask(tmpmask, ipi_sync_rq_state, mm, true);

	free_cpumask_var(tmpmask);
	cpus_read_unlock();

	return 0;
}

static int membarrier_register_global_expedited(void)
{
	struct task_struct *p = current;
	struct mm_struct *mm = p->mm;
	int ret;

	if (atomic_read(&mm->membarrier_state) &
	    MEMBARRIER_STATE_GLOBAL_EXPEDITED_READY)
		return 0;
	atomic_or(MEMBARRIER_STATE_GLOBAL_EXPEDITED, &mm->membarrier_state);
	ret = sync_runqueues_membarrier_state(mm);
	if (ret)
		return ret;
	atomic_or(MEMBARRIER_STATE_GLOBAL_EXPEDITED_READY,
		  &mm->membarrier_state);

	return 0;
}

static int membarrier_register_private_expedited(int flags)
{
	struct task_struct *p = current;
	struct mm_struct *mm = p->mm;
	int ready_state = MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY,
	    set_state = MEMBARRIER_STATE_PRIVATE_EXPEDITED,
	    ret;

	if (flags == MEMBARRIER_FLAG_SYNC_CORE) {
		if (!IS_ENABLED(CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE))
			return -EINVAL;
		ready_state =
			MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY;
	} else if (flags == MEMBARRIER_FLAG_RSEQ) {
		if (!IS_ENABLED(CONFIG_RSEQ))
			return -EINVAL;
		ready_state =
			MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ_READY;
	} else {
		WARN_ON_ONCE(flags);
	}

	/*
	if ((atomic_read(&mm->membarrier_state) & ready_state) == ready_state)
		return 0;
	if (flags & MEMBARRIER_FLAG_SYNC_CORE)
		set_state |= MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE;
	if (flags & MEMBARRIER_FLAG_RSEQ)
		set_state |= MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ;
	atomic_or(set_state, &mm->membarrier_state);
	ret = sync_runqueues_membarrier_state(mm);
	if (ret)
		return ret;
	atomic_or(ready_state, &mm->membarrier_state);

	return 0;
}

SYSCALL_DEFINE3(membarrier, int, cmd, unsigned int, flags, int, cpu_id)
{
	switch (cmd) {
	case MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ:
		if (unlikely(flags && flags != MEMBARRIER_CMD_FLAG_CPU))
			return -EINVAL;
		break;
	default:
		if (unlikely(flags))
			return -EINVAL;
	}

	if (!(flags & MEMBARRIER_CMD_FLAG_CPU))
		cpu_id = -1;

	switch (cmd) {
	case MEMBARRIER_CMD_QUERY:
	{
		int cmd_mask = MEMBARRIER_CMD_BITMASK;

		if (tick_nohz_full_enabled())
			cmd_mask &= ~MEMBARRIER_CMD_GLOBAL;
		return cmd_mask;
	}
	case MEMBARRIER_CMD_GLOBAL:
		/* MEMBARRIER_CMD_GLOBAL is not compatible with nohz_full. */
		if (tick_nohz_full_enabled())
			return -EINVAL;
		if (num_online_cpus() > 1)
			synchronize_rcu();
		return 0;
	case MEMBARRIER_CMD_GLOBAL_EXPEDITED:
		return membarrier_global_expedited();
	case MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED:
		return membarrier_register_global_expedited();
	case MEMBARRIER_CMD_PRIVATE_EXPEDITED:
		return membarrier_private_expedited(0, cpu_id);
	case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED:
		return membarrier_register_private_expedited(0);
	case MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE:
		return membarrier_private_expedited(MEMBARRIER_FLAG_SYNC_CORE, cpu_id);
	case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE:
		return membarrier_register_private_expedited(MEMBARRIER_FLAG_SYNC_CORE);
	case MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ:
		return membarrier_private_expedited(MEMBARRIER_FLAG_RSEQ, cpu_id);
	case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ:
		return membarrier_register_private_expedited(MEMBARRIER_FLAG_RSEQ);
	default:
		return -EINVAL;
	}
}
