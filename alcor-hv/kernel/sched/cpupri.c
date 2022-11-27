
static int convert_prio(int prio)
{
	int cpupri;

	switch (prio) {
	case CPUPRI_INVALID:
		cpupri = CPUPRI_INVALID;	/* -1 */
		break;

	case 0 ... 98:
		cpupri = MAX_RT_PRIO-1 - prio;	/* 1 ... 99 */
		break;

	case MAX_RT_PRIO-1:
		cpupri = CPUPRI_NORMAL;		/*  0 */
		break;

	case MAX_RT_PRIO:
		cpupri = CPUPRI_HIGHER;		/* 100 */
		break;
	}

	return cpupri;
}

static inline int __cpupri_find(struct cpupri *cp, struct task_struct *p,
				struct cpumask *lowest_mask, int idx)
{
	struct cpupri_vec *vec  = &cp->pri_to_cpu[idx];
	int skip = 0;

	if (!atomic_read(&(vec)->count))
		skip = 1;
	/*
	smp_rmb();

	/* Need to do the rmb for every iteration */
	if (skip)
		return 0;

	if (cpumask_any_and(&p->cpus_mask, vec->mask) >= nr_cpu_ids)
		return 0;

	if (lowest_mask) {
		cpumask_and(lowest_mask, &p->cpus_mask, vec->mask);

		/*
		if (cpumask_empty(lowest_mask))
			return 0;
	}

	return 1;
}

int cpupri_find(struct cpupri *cp, struct task_struct *p,
		struct cpumask *lowest_mask)
{
	return cpupri_find_fitness(cp, p, lowest_mask, NULL);
}

int cpupri_find_fitness(struct cpupri *cp, struct task_struct *p,
		struct cpumask *lowest_mask,
		bool (*fitness_fn)(struct task_struct *p, int cpu))
{
	int task_pri = convert_prio(p->prio);
	int idx, cpu;

	BUG_ON(task_pri >= CPUPRI_NR_PRIORITIES);

	for (idx = 0; idx < task_pri; idx++) {

		if (!__cpupri_find(cp, p, lowest_mask, idx))
			continue;

		if (!lowest_mask || !fitness_fn)
			return 1;

		/* Ensure the capacity of the CPUs fit the task */
		for_each_cpu(cpu, lowest_mask) {
			if (!fitness_fn(p, cpu))
				cpumask_clear_cpu(cpu, lowest_mask);
		}

		/*
		if (cpumask_empty(lowest_mask))
			continue;

		return 1;
	}

	/*
	if (fitness_fn)
		return cpupri_find(cp, p, lowest_mask);

	return 0;
}

void cpupri_set(struct cpupri *cp, int cpu, int newpri)
{
	int *currpri = &cp->cpu_to_pri[cpu];
	int oldpri = *currpri;
	int do_mb = 0;

	newpri = convert_prio(newpri);

	BUG_ON(newpri >= CPUPRI_NR_PRIORITIES);

	if (newpri == oldpri)
		return;

	/*
	if (likely(newpri != CPUPRI_INVALID)) {
		struct cpupri_vec *vec = &cp->pri_to_cpu[newpri];

		cpumask_set_cpu(cpu, vec->mask);
		/*
		smp_mb__before_atomic();
		atomic_inc(&(vec)->count);
		do_mb = 1;
	}
	if (likely(oldpri != CPUPRI_INVALID)) {
		struct cpupri_vec *vec  = &cp->pri_to_cpu[oldpri];

		/*
		if (do_mb)
			smp_mb__after_atomic();

		/*
		atomic_dec(&(vec)->count);
		smp_mb__after_atomic();
		cpumask_clear_cpu(cpu, vec->mask);
	}

}

int cpupri_init(struct cpupri *cp)
{
	int i;

	for (i = 0; i < CPUPRI_NR_PRIORITIES; i++) {
		struct cpupri_vec *vec = &cp->pri_to_cpu[i];

		atomic_set(&vec->count, 0);
		if (!zalloc_cpumask_var(&vec->mask, GFP_KERNEL))
			goto cleanup;
	}

	cp->cpu_to_pri = kcalloc(nr_cpu_ids, sizeof(int), GFP_KERNEL);
	if (!cp->cpu_to_pri)
		goto cleanup;

	for_each_possible_cpu(i)
		cp->cpu_to_pri[i] = CPUPRI_INVALID;

	return 0;

cleanup:
	for (i--; i >= 0; i--)
		free_cpumask_var(cp->pri_to_cpu[i].mask);
	return -ENOMEM;
}

void cpupri_cleanup(struct cpupri *cp)
{
	int i;

	kfree(cp->cpu_to_pri);
	for (i = 0; i < CPUPRI_NR_PRIORITIES; i++)
		free_cpumask_var(cp->pri_to_cpu[i].mask);
}
