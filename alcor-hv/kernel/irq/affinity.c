#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/sort.h>

static void irq_spread_init_one(struct cpumask *irqmsk, struct cpumask *nmsk,
				unsigned int cpus_per_vec)
{
	const struct cpumask *siblmsk;
	int cpu, sibl;

	for ( ; cpus_per_vec > 0; ) {
		cpu = cpumask_first(nmsk);

		/* Should not happen, but I'm too lazy to think about it */
		if (cpu >= nr_cpu_ids)
			return;

		cpumask_clear_cpu(cpu, nmsk);
		cpumask_set_cpu(cpu, irqmsk);
		cpus_per_vec--;

		/* If the cpu has siblings, use them first */
		siblmsk = topology_sibling_cpumask(cpu);
		for (sibl = -1; cpus_per_vec > 0; ) {
			sibl = cpumask_next(sibl, siblmsk);
			if (sibl >= nr_cpu_ids)
				break;
			if (!cpumask_test_and_clear_cpu(sibl, nmsk))
				continue;
			cpumask_set_cpu(sibl, irqmsk);
			cpus_per_vec--;
		}
	}
}

static cpumask_var_t *alloc_node_to_cpumask(void)
{
	cpumask_var_t *masks;
	int node;

	masks = kcalloc(nr_node_ids, sizeof(cpumask_var_t), GFP_KERNEL);
	if (!masks)
		return NULL;

	for (node = 0; node < nr_node_ids; node++) {
		if (!zalloc_cpumask_var(&masks[node], GFP_KERNEL))
			goto out_unwind;
	}

	return masks;

out_unwind:
	while (--node >= 0)
		free_cpumask_var(masks[node]);
	kfree(masks);
	return NULL;
}

static void free_node_to_cpumask(cpumask_var_t *masks)
{
	int node;

	for (node = 0; node < nr_node_ids; node++)
		free_cpumask_var(masks[node]);
	kfree(masks);
}

static void build_node_to_cpumask(cpumask_var_t *masks)
{
	int cpu;

	for_each_possible_cpu(cpu)
		cpumask_set_cpu(cpu, masks[cpu_to_node(cpu)]);
}

static int get_nodes_in_cpumask(cpumask_var_t *node_to_cpumask,
				const struct cpumask *mask, nodemask_t *nodemsk)
{
	int n, nodes = 0;

	/* Calculate the number of nodes in the supplied affinity mask */
	for_each_node(n) {
		if (cpumask_intersects(mask, node_to_cpumask[n])) {
			node_set(n, *nodemsk);
			nodes++;
		}
	}
	return nodes;
}

struct node_vectors {
	unsigned id;

	union {
		unsigned nvectors;
		unsigned ncpus;
	};
};

static int ncpus_cmp_func(const void *l, const void *r)
{
	const struct node_vectors *ln = l;
	const struct node_vectors *rn = r;

	return ln->ncpus - rn->ncpus;
}

static void alloc_nodes_vectors(unsigned int numvecs,
				cpumask_var_t *node_to_cpumask,
				const struct cpumask *cpu_mask,
				const nodemask_t nodemsk,
				struct cpumask *nmsk,
				struct node_vectors *node_vectors)
{
	unsigned n, remaining_ncpus = 0;

	for (n = 0; n < nr_node_ids; n++) {
		node_vectors[n].id = n;
		node_vectors[n].ncpus = UINT_MAX;
	}

	for_each_node_mask(n, nodemsk) {
		unsigned ncpus;

		cpumask_and(nmsk, cpu_mask, node_to_cpumask[n]);
		ncpus = cpumask_weight(nmsk);

		if (!ncpus)
			continue;
		remaining_ncpus += ncpus;
		node_vectors[n].ncpus = ncpus;
	}

	numvecs = min_t(unsigned, remaining_ncpus, numvecs);

	sort(node_vectors, nr_node_ids, sizeof(node_vectors[0]),
	     ncpus_cmp_func, NULL);

	/*
	for (n = 0; n < nr_node_ids; n++) {
		unsigned nvectors, ncpus;

		if (node_vectors[n].ncpus == UINT_MAX)
			continue;

		WARN_ON_ONCE(numvecs == 0);

		ncpus = node_vectors[n].ncpus;
		nvectors = max_t(unsigned, 1,
				 numvecs * ncpus / remaining_ncpus);
		WARN_ON_ONCE(nvectors > ncpus);

		node_vectors[n].nvectors = nvectors;

		remaining_ncpus -= ncpus;
		numvecs -= nvectors;
	}
}

static int __irq_build_affinity_masks(unsigned int startvec,
				      unsigned int numvecs,
				      unsigned int firstvec,
				      cpumask_var_t *node_to_cpumask,
				      const struct cpumask *cpu_mask,
				      struct cpumask *nmsk,
				      struct irq_affinity_desc *masks)
{
	unsigned int i, n, nodes, cpus_per_vec, extra_vecs, done = 0;
	unsigned int last_affv = firstvec + numvecs;
	unsigned int curvec = startvec;
	nodemask_t nodemsk = NODE_MASK_NONE;
	struct node_vectors *node_vectors;

	if (cpumask_empty(cpu_mask))
		return 0;

	nodes = get_nodes_in_cpumask(node_to_cpumask, cpu_mask, &nodemsk);

	/*
	if (numvecs <= nodes) {
		for_each_node_mask(n, nodemsk) {
			/* Ensure that only CPUs which are in both masks are set */
			cpumask_and(nmsk, cpu_mask, node_to_cpumask[n]);
			cpumask_or(&masks[curvec].mask, &masks[curvec].mask, nmsk);
			if (++curvec == last_affv)
				curvec = firstvec;
		}
		return numvecs;
	}

	node_vectors = kcalloc(nr_node_ids,
			       sizeof(struct node_vectors),
			       GFP_KERNEL);
	if (!node_vectors)
		return -ENOMEM;

	/* allocate vector number for each node */
	alloc_nodes_vectors(numvecs, node_to_cpumask, cpu_mask,
			    nodemsk, nmsk, node_vectors);

	for (i = 0; i < nr_node_ids; i++) {
		unsigned int ncpus, v;
		struct node_vectors *nv = &node_vectors[i];

		if (nv->nvectors == UINT_MAX)
			continue;

		/* Get the cpus on this node which are in the mask */
		cpumask_and(nmsk, cpu_mask, node_to_cpumask[nv->id]);
		ncpus = cpumask_weight(nmsk);
		if (!ncpus)
			continue;

		WARN_ON_ONCE(nv->nvectors > ncpus);

		/* Account for rounding errors */
		extra_vecs = ncpus - nv->nvectors * (ncpus / nv->nvectors);

		/* Spread allocated vectors on CPUs of the current node */
		for (v = 0; v < nv->nvectors; v++, curvec++) {
			cpus_per_vec = ncpus / nv->nvectors;

			/* Account for extra vectors to compensate rounding errors */
			if (extra_vecs) {
				cpus_per_vec++;
				--extra_vecs;
			}

			/*
			if (curvec >= last_affv)
				curvec = firstvec;
			irq_spread_init_one(&masks[curvec].mask, nmsk,
						cpus_per_vec);
		}
		done += nv->nvectors;
	}
	kfree(node_vectors);
	return done;
}

static int irq_build_affinity_masks(unsigned int startvec, unsigned int numvecs,
				    unsigned int firstvec,
				    struct irq_affinity_desc *masks)
{
	unsigned int curvec = startvec, nr_present = 0, nr_others = 0;
	cpumask_var_t *node_to_cpumask;
	cpumask_var_t nmsk, npresmsk;
	int ret = -ENOMEM;

	if (!zalloc_cpumask_var(&nmsk, GFP_KERNEL))
		return ret;

	if (!zalloc_cpumask_var(&npresmsk, GFP_KERNEL))
		goto fail_nmsk;

	node_to_cpumask = alloc_node_to_cpumask();
	if (!node_to_cpumask)
		goto fail_npresmsk;

	/* Stabilize the cpumasks */
	cpus_read_lock();
	build_node_to_cpumask(node_to_cpumask);

	/* Spread on present CPUs starting from affd->pre_vectors */
	ret = __irq_build_affinity_masks(curvec, numvecs, firstvec,
					 node_to_cpumask, cpu_present_mask,
					 nmsk, masks);
	if (ret < 0)
		goto fail_build_affinity;
	nr_present = ret;

	/*
	if (nr_present >= numvecs)
		curvec = firstvec;
	else
		curvec = firstvec + nr_present;
	cpumask_andnot(npresmsk, cpu_possible_mask, cpu_present_mask);
	ret = __irq_build_affinity_masks(curvec, numvecs, firstvec,
					 node_to_cpumask, npresmsk, nmsk,
					 masks);
	if (ret >= 0)
		nr_others = ret;

 fail_build_affinity:
	cpus_read_unlock();

	if (ret >= 0)
		WARN_ON(nr_present + nr_others < numvecs);

	free_node_to_cpumask(node_to_cpumask);

 fail_npresmsk:
	free_cpumask_var(npresmsk);

 fail_nmsk:
	free_cpumask_var(nmsk);
	return ret < 0 ? ret : 0;
}

static void default_calc_sets(struct irq_affinity *affd, unsigned int affvecs)
{
	affd->nr_sets = 1;
	affd->set_size[0] = affvecs;
}

struct irq_affinity_desc *
irq_create_affinity_masks(unsigned int nvecs, struct irq_affinity *affd)
{
	unsigned int affvecs, curvec, usedvecs, i;
	struct irq_affinity_desc *masks = NULL;

	/*
	if (nvecs > affd->pre_vectors + affd->post_vectors)
		affvecs = nvecs - affd->pre_vectors - affd->post_vectors;
	else
		affvecs = 0;

	/*
	if (!affd->calc_sets)
		affd->calc_sets = default_calc_sets;

	/* Recalculate the sets */
	affd->calc_sets(affd, affvecs);

	if (WARN_ON_ONCE(affd->nr_sets > IRQ_AFFINITY_MAX_SETS))
		return NULL;

	/* Nothing to assign? */
	if (!affvecs)
		return NULL;

	masks = kcalloc(nvecs, sizeof(*masks), GFP_KERNEL);
	if (!masks)
		return NULL;

	/* Fill out vectors at the beginning that don't need affinity */
	for (curvec = 0; curvec < affd->pre_vectors; curvec++)
		cpumask_copy(&masks[curvec].mask, irq_default_affinity);

	/*
	for (i = 0, usedvecs = 0; i < affd->nr_sets; i++) {
		unsigned int this_vecs = affd->set_size[i];
		int ret;

		ret = irq_build_affinity_masks(curvec, this_vecs,
					       curvec, masks);
		if (ret) {
			kfree(masks);
			return NULL;
		}
		curvec += this_vecs;
		usedvecs += this_vecs;
	}

	/* Fill out vectors at the end that don't need affinity */
	if (usedvecs >= affvecs)
		curvec = affd->pre_vectors + affvecs;
	else
		curvec = affd->pre_vectors + usedvecs;
	for (; curvec < nvecs; curvec++)
		cpumask_copy(&masks[curvec].mask, irq_default_affinity);

	/* Mark the managed interrupts */
	for (i = affd->pre_vectors; i < nvecs - affd->post_vectors; i++)
		masks[i].is_managed = 1;

	return masks;
}

unsigned int irq_calc_affinity_vectors(unsigned int minvec, unsigned int maxvec,
				       const struct irq_affinity *affd)
{
	unsigned int resv = affd->pre_vectors + affd->post_vectors;
	unsigned int set_vecs;

	if (resv > minvec)
		return 0;

	if (affd->calc_sets) {
		set_vecs = maxvec - resv;
	} else {
		cpus_read_lock();
		set_vecs = cpumask_weight(cpu_possible_mask);
		cpus_read_unlock();
	}

	return resv + min(set_vecs, maxvec - resv);
}
