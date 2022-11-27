
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cpuset.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/export.h>
#include <linux/mount.h>
#include <linux/fs_context.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/deadline.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/time64.h>
#include <linux/backing-dev.h>
#include <linux/sort.h>
#include <linux/oom.h>
#include <linux/sched/isolation.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/cgroup.h>
#include <linux/wait.h>

DEFINE_STATIC_KEY_FALSE(cpusets_pre_enable_key);
DEFINE_STATIC_KEY_FALSE(cpusets_enabled_key);

DEFINE_STATIC_KEY_FALSE(cpusets_insane_config_key);


struct fmeter {
	int cnt;		/* unprocessed events count */
	int val;		/* most recent output value */
	time64_t time;		/* clock (secs) when val computed */
	spinlock_t lock;	/* guards read or write of above */
};

struct cpuset {
	struct cgroup_subsys_state css;

	unsigned long flags;		/* "unsigned long" so bitops work */

	/*

	/* user-configured CPUs and Memory Nodes allow to tasks */
	cpumask_var_t cpus_allowed;
	nodemask_t mems_allowed;

	/* effective CPUs and Memory Nodes allow to tasks */
	cpumask_var_t effective_cpus;
	nodemask_t effective_mems;

	/*
	cpumask_var_t subparts_cpus;

	/*
	nodemask_t old_mems_allowed;

	struct fmeter fmeter;		/* memory_pressure filter */

	/*
	int attach_in_progress;

	/* partition number for rebuild_sched_domains() */
	int pn;

	/* for custom sched domain */
	int relax_domain_level;

	/* number of CPUs in subparts_cpus */
	int nr_subparts_cpus;

	/* partition root state */
	int partition_root_state;

	/*
	int use_parent_ecpus;
	int child_ecpus_count;

	/* Handle for cpuset.cpus.partition */
	struct cgroup_file partition_file;
};

#define PRS_DISABLED		0
#define PRS_ENABLED		1
#define PRS_ERROR		-1

struct tmpmasks {
	cpumask_var_t addmask, delmask;	/* For partition root */
	cpumask_var_t new_cpus;		/* For update_cpumasks_hier() */
};

static inline struct cpuset *css_cs(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct cpuset, css) : NULL;
}

static inline struct cpuset *task_cs(struct task_struct *task)
{
	return css_cs(task_css(task, cpuset_cgrp_id));
}

static inline struct cpuset *parent_cs(struct cpuset *cs)
{
	return css_cs(cs->css.parent);
}

typedef enum {
	CS_ONLINE,
	CS_CPU_EXCLUSIVE,
	CS_MEM_EXCLUSIVE,
	CS_MEM_HARDWALL,
	CS_MEMORY_MIGRATE,
	CS_SCHED_LOAD_BALANCE,
	CS_SPREAD_PAGE,
	CS_SPREAD_SLAB,
} cpuset_flagbits_t;

static inline bool is_cpuset_online(struct cpuset *cs)
{
	return test_bit(CS_ONLINE, &cs->flags) && !css_is_dying(&cs->css);
}

static inline int is_cpu_exclusive(const struct cpuset *cs)
{
	return test_bit(CS_CPU_EXCLUSIVE, &cs->flags);
}

static inline int is_mem_exclusive(const struct cpuset *cs)
{
	return test_bit(CS_MEM_EXCLUSIVE, &cs->flags);
}

static inline int is_mem_hardwall(const struct cpuset *cs)
{
	return test_bit(CS_MEM_HARDWALL, &cs->flags);
}

static inline int is_sched_load_balance(const struct cpuset *cs)
{
	return test_bit(CS_SCHED_LOAD_BALANCE, &cs->flags);
}

static inline int is_memory_migrate(const struct cpuset *cs)
{
	return test_bit(CS_MEMORY_MIGRATE, &cs->flags);
}

static inline int is_spread_page(const struct cpuset *cs)
{
	return test_bit(CS_SPREAD_PAGE, &cs->flags);
}

static inline int is_spread_slab(const struct cpuset *cs)
{
	return test_bit(CS_SPREAD_SLAB, &cs->flags);
}

static inline int is_partition_root(const struct cpuset *cs)
{
	return cs->partition_root_state > 0;
}

static inline void notify_partition_change(struct cpuset *cs,
					   int old_prs, int new_prs)
{
	if (old_prs != new_prs)
		cgroup_file_notify(&cs->partition_file);
}

static struct cpuset top_cpuset = {
	.flags = ((1 << CS_ONLINE) | (1 << CS_CPU_EXCLUSIVE) |
		  (1 << CS_MEM_EXCLUSIVE)),
	.partition_root_state = PRS_ENABLED,
};

#define cpuset_for_each_child(child_cs, pos_css, parent_cs)		\
	css_for_each_child((pos_css), &(parent_cs)->css)		\
		if (is_cpuset_online(((child_cs) = css_cs((pos_css)))))

#define cpuset_for_each_descendant_pre(des_cs, pos_css, root_cs)	\
	css_for_each_descendant_pre((pos_css), &(root_cs)->css)		\
		if (is_cpuset_online(((des_cs) = css_cs((pos_css)))))


DEFINE_STATIC_PERCPU_RWSEM(cpuset_rwsem);

void cpuset_read_lock(void)
{
	percpu_down_read(&cpuset_rwsem);
}

void cpuset_read_unlock(void)
{
	percpu_up_read(&cpuset_rwsem);
}

static DEFINE_SPINLOCK(callback_lock);

static struct workqueue_struct *cpuset_migrate_mm_wq;

static void cpuset_hotplug_workfn(struct work_struct *work);
static DECLARE_WORK(cpuset_hotplug_work, cpuset_hotplug_workfn);

static DECLARE_WAIT_QUEUE_HEAD(cpuset_attach_wq);

static inline void check_insane_mems_config(nodemask_t *nodes)
{
	if (!cpusets_insane_config() &&
		movable_only_nodes(nodes)) {
		static_branch_enable(&cpusets_insane_config_key);
		pr_info("Unsupported (movable nodes only) cpuset configuration detected (nmask=%*pbl)!\n"
			"Cpuset allocations might fail even with a lot of memory available.\n",
			nodemask_pr_args(nodes));
	}
}

static inline bool is_in_v2_mode(void)
{
	return cgroup_subsys_on_dfl(cpuset_cgrp_subsys) ||
	      (cpuset_cgrp_subsys.root->flags & CGRP_ROOT_CPUSET_V2_MODE);
}

static void guarantee_online_cpus(struct task_struct *tsk,
				  struct cpumask *pmask)
{
	const struct cpumask *possible_mask = task_cpu_possible_mask(tsk);
	struct cpuset *cs;

	if (WARN_ON(!cpumask_and(pmask, possible_mask, cpu_online_mask)))
		cpumask_copy(pmask, cpu_online_mask);

	rcu_read_lock();
	cs = task_cs(tsk);

	while (!cpumask_intersects(cs->effective_cpus, pmask)) {
		cs = parent_cs(cs);
		if (unlikely(!cs)) {
			/*
			goto out_unlock;
		}
	}
	cpumask_and(pmask, pmask, cs->effective_cpus);

out_unlock:
	rcu_read_unlock();
}

static void guarantee_online_mems(struct cpuset *cs, nodemask_t *pmask)
{
	while (!nodes_intersects(cs->effective_mems, node_states[N_MEMORY]))
		cs = parent_cs(cs);
	nodes_and(*pmask, cs->effective_mems, node_states[N_MEMORY]);
}

static void cpuset_update_task_spread_flag(struct cpuset *cs,
					struct task_struct *tsk)
{
	if (is_spread_page(cs))
		task_set_spread_page(tsk);
	else
		task_clear_spread_page(tsk);

	if (is_spread_slab(cs))
		task_set_spread_slab(tsk);
	else
		task_clear_spread_slab(tsk);
}


static int is_cpuset_subset(const struct cpuset *p, const struct cpuset *q)
{
	return	cpumask_subset(p->cpus_allowed, q->cpus_allowed) &&
		nodes_subset(p->mems_allowed, q->mems_allowed) &&
		is_cpu_exclusive(p) <= is_cpu_exclusive(q) &&
		is_mem_exclusive(p) <= is_mem_exclusive(q);
}

static inline int alloc_cpumasks(struct cpuset *cs, struct tmpmasks *tmp)
{
	cpumask_var_t *pmask1, *pmask2, *pmask3;

	if (cs) {
		pmask1 = &cs->cpus_allowed;
		pmask2 = &cs->effective_cpus;
		pmask3 = &cs->subparts_cpus;
	} else {
		pmask1 = &tmp->new_cpus;
		pmask2 = &tmp->addmask;
		pmask3 = &tmp->delmask;
	}

	if (!zalloc_cpumask_var(pmask1, GFP_KERNEL))
		return -ENOMEM;

	if (!zalloc_cpumask_var(pmask2, GFP_KERNEL))
		goto free_one;

	if (!zalloc_cpumask_var(pmask3, GFP_KERNEL))
		goto free_two;

	return 0;

free_two:
	free_cpumask_var(*pmask2);
free_one:
	free_cpumask_var(*pmask1);
	return -ENOMEM;
}

static inline void free_cpumasks(struct cpuset *cs, struct tmpmasks *tmp)
{
	if (cs) {
		free_cpumask_var(cs->cpus_allowed);
		free_cpumask_var(cs->effective_cpus);
		free_cpumask_var(cs->subparts_cpus);
	}
	if (tmp) {
		free_cpumask_var(tmp->new_cpus);
		free_cpumask_var(tmp->addmask);
		free_cpumask_var(tmp->delmask);
	}
}

static struct cpuset *alloc_trial_cpuset(struct cpuset *cs)
{
	struct cpuset *trial;

	trial = kmemdup(cs, sizeof(*cs), GFP_KERNEL);
	if (!trial)
		return NULL;

	if (alloc_cpumasks(trial, NULL)) {
		kfree(trial);
		return NULL;
	}

	cpumask_copy(trial->cpus_allowed, cs->cpus_allowed);
	cpumask_copy(trial->effective_cpus, cs->effective_cpus);
	return trial;
}

static inline void free_cpuset(struct cpuset *cs)
{
	free_cpumasks(cs, NULL);
	kfree(cs);
}

static int validate_change_legacy(struct cpuset *cur, struct cpuset *trial)
{
	struct cgroup_subsys_state *css;
	struct cpuset *c, *par;
	int ret;

	WARN_ON_ONCE(!rcu_read_lock_held());

	/* Each of our child cpusets must be a subset of us */
	ret = -EBUSY;
	cpuset_for_each_child(c, css, cur)
		if (!is_cpuset_subset(c, trial))
			goto out;

	/* On legacy hierarchy, we must be a subset of our parent cpuset. */
	ret = -EACCES;
	par = parent_cs(cur);
	if (par && !is_cpuset_subset(trial, par))
		goto out;

	ret = 0;
out:
	return ret;
}


static int validate_change(struct cpuset *cur, struct cpuset *trial)
{
	struct cgroup_subsys_state *css;
	struct cpuset *c, *par;
	int ret = 0;

	rcu_read_lock();

	if (!is_in_v2_mode())
		ret = validate_change_legacy(cur, trial);
	if (ret)
		goto out;

	/* Remaining checks don't apply to root cpuset */
	if (cur == &top_cpuset)
		goto out;

	par = parent_cs(cur);

	/*
	ret = -EINVAL;
	cpuset_for_each_child(c, css, par) {
		if ((is_cpu_exclusive(trial) || is_cpu_exclusive(c)) &&
		    c != cur &&
		    cpumask_intersects(trial->cpus_allowed, c->cpus_allowed))
			goto out;
		if ((is_mem_exclusive(trial) || is_mem_exclusive(c)) &&
		    c != cur &&
		    nodes_intersects(trial->mems_allowed, c->mems_allowed))
			goto out;
	}

	/*
	ret = -ENOSPC;
	if ((cgroup_is_populated(cur->css.cgroup) || cur->attach_in_progress)) {
		if (!cpumask_empty(cur->cpus_allowed) &&
		    cpumask_empty(trial->cpus_allowed))
			goto out;
		if (!nodes_empty(cur->mems_allowed) &&
		    nodes_empty(trial->mems_allowed))
			goto out;
	}

	/*
	ret = -EBUSY;
	if (is_cpu_exclusive(cur) &&
	    !cpuset_cpumask_can_shrink(cur->cpus_allowed,
				       trial->cpus_allowed))
		goto out;

	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}

#ifdef CONFIG_SMP
static int cpusets_overlap(struct cpuset *a, struct cpuset *b)
{
	return cpumask_intersects(a->effective_cpus, b->effective_cpus);
}

static void
update_domain_attr(struct sched_domain_attr *dattr, struct cpuset *c)
{
	if (dattr->relax_domain_level < c->relax_domain_level)
		dattr->relax_domain_level = c->relax_domain_level;
	return;
}

static void update_domain_attr_tree(struct sched_domain_attr *dattr,
				    struct cpuset *root_cs)
{
	struct cpuset *cp;
	struct cgroup_subsys_state *pos_css;

	rcu_read_lock();
	cpuset_for_each_descendant_pre(cp, pos_css, root_cs) {
		/* skip the whole subtree if @cp doesn't have any CPU */
		if (cpumask_empty(cp->cpus_allowed)) {
			pos_css = css_rightmost_descendant(pos_css);
			continue;
		}

		if (is_sched_load_balance(cp))
			update_domain_attr(dattr, cp);
	}
	rcu_read_unlock();
}

static inline int nr_cpusets(void)
{
	/* jump label reference count + the top-level cpuset */
	return static_key_count(&cpusets_enabled_key.key) + 1;
}

static int generate_sched_domains(cpumask_var_t **domains,
			struct sched_domain_attr **attributes)
{
	struct cpuset *cp;	/* top-down scan of cpusets */
	struct cpuset **csa;	/* array of all cpuset ptrs */
	int csn;		/* how many cpuset ptrs in csa so far */
	int i, j, k;		/* indices for partition finding loops */
	cpumask_var_t *doms;	/* resulting partition; i.e. sched domains */
	struct sched_domain_attr *dattr;  /* attributes for custom domains */
	int ndoms = 0;		/* number of sched domains in result */
	int nslot;		/* next empty doms[] struct cpumask slot */
	struct cgroup_subsys_state *pos_css;
	bool root_load_balance = is_sched_load_balance(&top_cpuset);

	doms = NULL;
	dattr = NULL;
	csa = NULL;

	/* Special case for the 99% of systems with one, full, sched domain */
	if (root_load_balance && !top_cpuset.nr_subparts_cpus) {
		ndoms = 1;
		doms = alloc_sched_domains(ndoms);
		if (!doms)
			goto done;

		dattr = kmalloc(sizeof(struct sched_domain_attr), GFP_KERNEL);
		if (dattr) {
			*dattr = SD_ATTR_INIT;
			update_domain_attr_tree(dattr, &top_cpuset);
		}
		cpumask_and(doms[0], top_cpuset.effective_cpus,
			    housekeeping_cpumask(HK_TYPE_DOMAIN));

		goto done;
	}

	csa = kmalloc_array(nr_cpusets(), sizeof(cp), GFP_KERNEL);
	if (!csa)
		goto done;
	csn = 0;

	rcu_read_lock();
	if (root_load_balance)
		csa[csn++] = &top_cpuset;
	cpuset_for_each_descendant_pre(cp, pos_css, &top_cpuset) {
		if (cp == &top_cpuset)
			continue;
		/*
		if (!cpumask_empty(cp->cpus_allowed) &&
		    !(is_sched_load_balance(cp) &&
		      cpumask_intersects(cp->cpus_allowed,
					 housekeeping_cpumask(HK_TYPE_DOMAIN))))
			continue;

		if (root_load_balance &&
		    cpumask_subset(cp->cpus_allowed, top_cpuset.effective_cpus))
			continue;

		if (is_sched_load_balance(cp) &&
		    !cpumask_empty(cp->effective_cpus))
			csa[csn++] = cp;

		/* skip @cp's subtree if not a partition root */
		if (!is_partition_root(cp))
			pos_css = css_rightmost_descendant(pos_css);
	}
	rcu_read_unlock();

	for (i = 0; i < csn; i++)
		csa[i]->pn = i;
	ndoms = csn;

restart:
	/* Find the best partition (set of sched domains) */
	for (i = 0; i < csn; i++) {
		struct cpuset *a = csa[i];
		int apn = a->pn;

		for (j = 0; j < csn; j++) {
			struct cpuset *b = csa[j];
			int bpn = b->pn;

			if (apn != bpn && cpusets_overlap(a, b)) {
				for (k = 0; k < csn; k++) {
					struct cpuset *c = csa[k];

					if (c->pn == bpn)
						c->pn = apn;
				}
				ndoms--;	/* one less element */
				goto restart;
			}
		}
	}

	/*
	doms = alloc_sched_domains(ndoms);
	if (!doms)
		goto done;

	/*
	dattr = kmalloc_array(ndoms, sizeof(struct sched_domain_attr),
			      GFP_KERNEL);

	for (nslot = 0, i = 0; i < csn; i++) {
		struct cpuset *a = csa[i];
		struct cpumask *dp;
		int apn = a->pn;

		if (apn < 0) {
			/* Skip completed partitions */
			continue;
		}

		dp = doms[nslot];

		if (nslot == ndoms) {
			static int warnings = 10;
			if (warnings) {
				pr_warn("rebuild_sched_domains confused: nslot %d, ndoms %d, csn %d, i %d, apn %d\n",
					nslot, ndoms, csn, i, apn);
				warnings--;
			}
			continue;
		}

		cpumask_clear(dp);
		if (dattr)
			*(dattr + nslot) = SD_ATTR_INIT;
		for (j = i; j < csn; j++) {
			struct cpuset *b = csa[j];

			if (apn == b->pn) {
				cpumask_or(dp, dp, b->effective_cpus);
				cpumask_and(dp, dp, housekeeping_cpumask(HK_TYPE_DOMAIN));
				if (dattr)
					update_domain_attr_tree(dattr + nslot, b);

				/* Done with this partition */
				b->pn = -1;
			}
		}
		nslot++;
	}
	BUG_ON(nslot != ndoms);

done:
	kfree(csa);

	/*
	if (doms == NULL)
		ndoms = 1;

	return ndoms;
}

static void update_tasks_root_domain(struct cpuset *cs)
{
	struct css_task_iter it;
	struct task_struct *task;

	css_task_iter_start(&cs->css, 0, &it);

	while ((task = css_task_iter_next(&it)))
		dl_add_task_root_domain(task);

	css_task_iter_end(&it);
}

static void rebuild_root_domains(void)
{
	struct cpuset *cs = NULL;
	struct cgroup_subsys_state *pos_css;

	percpu_rwsem_assert_held(&cpuset_rwsem);
	lockdep_assert_cpus_held();
	lockdep_assert_held(&sched_domains_mutex);

	rcu_read_lock();

	/*
	dl_clear_root_domain(&def_root_domain);

	cpuset_for_each_descendant_pre(cs, pos_css, &top_cpuset) {

		if (cpumask_empty(cs->effective_cpus)) {
			pos_css = css_rightmost_descendant(pos_css);
			continue;
		}

		css_get(&cs->css);

		rcu_read_unlock();

		update_tasks_root_domain(cs);

		rcu_read_lock();
		css_put(&cs->css);
	}
	rcu_read_unlock();
}

static void
partition_and_rebuild_sched_domains(int ndoms_new, cpumask_var_t doms_new[],
				    struct sched_domain_attr *dattr_new)
{
	mutex_lock(&sched_domains_mutex);
	partition_sched_domains_locked(ndoms_new, doms_new, dattr_new);
	rebuild_root_domains();
	mutex_unlock(&sched_domains_mutex);
}

static void rebuild_sched_domains_locked(void)
{
	struct cgroup_subsys_state *pos_css;
	struct sched_domain_attr *attr;
	cpumask_var_t *doms;
	struct cpuset *cs;
	int ndoms;

	lockdep_assert_cpus_held();
	percpu_rwsem_assert_held(&cpuset_rwsem);

	/*
	if (!top_cpuset.nr_subparts_cpus &&
	    !cpumask_equal(top_cpuset.effective_cpus, cpu_active_mask))
		return;

	/*
	if (top_cpuset.nr_subparts_cpus) {
		rcu_read_lock();
		cpuset_for_each_descendant_pre(cs, pos_css, &top_cpuset) {
			if (!is_partition_root(cs)) {
				pos_css = css_rightmost_descendant(pos_css);
				continue;
			}
			if (!cpumask_subset(cs->effective_cpus,
					    cpu_active_mask)) {
				rcu_read_unlock();
				return;
			}
		}
		rcu_read_unlock();
	}

	/* Generate domain masks and attrs */
	ndoms = generate_sched_domains(&doms, &attr);

	/* Have scheduler rebuild the domains */
	partition_and_rebuild_sched_domains(ndoms, doms, attr);
}
#else /* !CONFIG_SMP */
static void rebuild_sched_domains_locked(void)
{
}
#endif /* CONFIG_SMP */

void rebuild_sched_domains(void)
{
	cpus_read_lock();
	percpu_down_write(&cpuset_rwsem);
	rebuild_sched_domains_locked();
	percpu_up_write(&cpuset_rwsem);
	cpus_read_unlock();
}

static void update_tasks_cpumask(struct cpuset *cs)
{
	struct css_task_iter it;
	struct task_struct *task;

	css_task_iter_start(&cs->css, 0, &it);
	while ((task = css_task_iter_next(&it)))
		set_cpus_allowed_ptr(task, cs->effective_cpus);
	css_task_iter_end(&it);
}

static void compute_effective_cpumask(struct cpumask *new_cpus,
				      struct cpuset *cs, struct cpuset *parent)
{
	if (parent->nr_subparts_cpus) {
		cpumask_or(new_cpus, parent->effective_cpus,
			   parent->subparts_cpus);
		cpumask_and(new_cpus, new_cpus, cs->cpus_allowed);
		cpumask_and(new_cpus, new_cpus, cpu_active_mask);
	} else {
		cpumask_and(new_cpus, cs->cpus_allowed, parent->effective_cpus);
	}
}

enum subparts_cmd {
	partcmd_enable,		/* Enable partition root	 */
	partcmd_disable,	/* Disable partition root	 */
	partcmd_update,		/* Update parent's subparts_cpus */
};

static int update_parent_subparts_cpumask(struct cpuset *cpuset, int cmd,
					  struct cpumask *newmask,
					  struct tmpmasks *tmp)
{
	struct cpuset *parent = parent_cs(cpuset);
	int adding;	/* Moving cpus from effective_cpus to subparts_cpus */
	int deleting;	/* Moving cpus from subparts_cpus to effective_cpus */
	int old_prs, new_prs;
	bool part_error = false;	/* Partition error? */

	percpu_rwsem_assert_held(&cpuset_rwsem);

	/*
	if (!is_partition_root(parent) ||
	   (newmask && cpumask_empty(newmask)) ||
	   (!newmask && cpumask_empty(cpuset->cpus_allowed)))
		return -EINVAL;

	/*
	if ((cmd != partcmd_update) && css_has_online_children(&cpuset->css))
		return -EBUSY;

	/*
	if ((cmd == partcmd_enable) &&
	   (!cpumask_subset(cpuset->cpus_allowed, parent->effective_cpus) ||
	     cpumask_equal(cpuset->cpus_allowed, parent->effective_cpus)))
		return -EINVAL;

	/*
	adding = deleting = false;
	old_prs = new_prs = cpuset->partition_root_state;
	if (cmd == partcmd_enable) {
		cpumask_copy(tmp->addmask, cpuset->cpus_allowed);
		adding = true;
	} else if (cmd == partcmd_disable) {
		deleting = cpumask_and(tmp->delmask, cpuset->cpus_allowed,
				       parent->subparts_cpus);
	} else if (newmask) {
		/*
		cpumask_andnot(tmp->delmask, cpuset->cpus_allowed, newmask);
		deleting = cpumask_and(tmp->delmask, tmp->delmask,
				       parent->subparts_cpus);

		cpumask_and(tmp->addmask, newmask, parent->effective_cpus);
		adding = cpumask_andnot(tmp->addmask, tmp->addmask,
					parent->subparts_cpus);
		/*
		if (adding &&
		    cpumask_equal(parent->effective_cpus, tmp->addmask)) {
			if (!deleting)
				return -EINVAL;
			/*
			if (!cpumask_and(tmp->addmask, tmp->delmask,
					 cpu_active_mask))
				return -EINVAL;
			cpumask_copy(tmp->addmask, parent->effective_cpus);
		}
	} else {
		/*
		adding = cpumask_and(tmp->addmask, cpuset->cpus_allowed,
				     parent->effective_cpus);
		part_error = cpumask_equal(tmp->addmask,
					   parent->effective_cpus);
	}

	if (cmd == partcmd_update) {
		int prev_prs = cpuset->partition_root_state;

		/*
		switch (cpuset->partition_root_state) {
		case PRS_ENABLED:
			if (part_error)
				new_prs = PRS_ERROR;
			break;
		case PRS_ERROR:
			if (!part_error)
				new_prs = PRS_ENABLED;
			break;
		}
		/*
		part_error = (prev_prs == PRS_ERROR);
	}

	if (!part_error && (new_prs == PRS_ERROR))
		return 0;	/* Nothing need to be done */

	if (new_prs == PRS_ERROR) {
		/*
		adding = false;
		deleting = cpumask_and(tmp->delmask, cpuset->cpus_allowed,
				       parent->subparts_cpus);
	}

	if (!adding && !deleting && (new_prs == old_prs))
		return 0;

	/*
	spin_lock_irq(&callback_lock);
	if (adding) {
		cpumask_or(parent->subparts_cpus,
			   parent->subparts_cpus, tmp->addmask);
		cpumask_andnot(parent->effective_cpus,
			       parent->effective_cpus, tmp->addmask);
	}
	if (deleting) {
		cpumask_andnot(parent->subparts_cpus,
			       parent->subparts_cpus, tmp->delmask);
		/*
		cpumask_and(tmp->delmask, tmp->delmask, cpu_active_mask);
		cpumask_or(parent->effective_cpus,
			   parent->effective_cpus, tmp->delmask);
	}

	parent->nr_subparts_cpus = cpumask_weight(parent->subparts_cpus);

	if (old_prs != new_prs)
		cpuset->partition_root_state = new_prs;

	spin_unlock_irq(&callback_lock);
	notify_partition_change(cpuset, old_prs, new_prs);

	return cmd == partcmd_update;
}

static void update_cpumasks_hier(struct cpuset *cs, struct tmpmasks *tmp)
{
	struct cpuset *cp;
	struct cgroup_subsys_state *pos_css;
	bool need_rebuild_sched_domains = false;
	int old_prs, new_prs;

	rcu_read_lock();
	cpuset_for_each_descendant_pre(cp, pos_css, cs) {
		struct cpuset *parent = parent_cs(cp);

		compute_effective_cpumask(tmp->new_cpus, cp, parent);

		/*
		if (is_in_v2_mode() && cpumask_empty(tmp->new_cpus)) {
			cpumask_copy(tmp->new_cpus, parent->effective_cpus);
			if (!cp->use_parent_ecpus) {
				cp->use_parent_ecpus = true;
				parent->child_ecpus_count++;
			}
		} else if (cp->use_parent_ecpus) {
			cp->use_parent_ecpus = false;
			WARN_ON_ONCE(!parent->child_ecpus_count);
			parent->child_ecpus_count--;
		}

		/*
		if (!cp->partition_root_state &&
		    cpumask_equal(tmp->new_cpus, cp->effective_cpus)) {
			pos_css = css_rightmost_descendant(pos_css);
			continue;
		}

		/*
		old_prs = new_prs = cp->partition_root_state;
		if ((cp != cs) && old_prs) {
			switch (parent->partition_root_state) {
			case PRS_DISABLED:
				/*
				WARN_ON_ONCE(cp->partition_root_state
					     != PRS_ERROR);
				new_prs = PRS_DISABLED;

				/*
				clear_bit(CS_CPU_EXCLUSIVE, &cp->flags);
				break;

			case PRS_ENABLED:
				if (update_parent_subparts_cpumask(cp, partcmd_update, NULL, tmp))
					update_tasks_cpumask(parent);
				break;

			case PRS_ERROR:
				/*
				new_prs = PRS_ERROR;
				break;
			}
		}

		if (!css_tryget_online(&cp->css))
			continue;
		rcu_read_unlock();

		spin_lock_irq(&callback_lock);

		cpumask_copy(cp->effective_cpus, tmp->new_cpus);
		if (cp->nr_subparts_cpus && (new_prs != PRS_ENABLED)) {
			cp->nr_subparts_cpus = 0;
			cpumask_clear(cp->subparts_cpus);
		} else if (cp->nr_subparts_cpus) {
			/*
			cpumask_andnot(cp->effective_cpus, cp->effective_cpus,
				       cp->subparts_cpus);
			if (cpumask_empty(cp->effective_cpus)) {
				cpumask_copy(cp->effective_cpus, tmp->new_cpus);
				cpumask_clear(cp->subparts_cpus);
				cp->nr_subparts_cpus = 0;
			} else if (!cpumask_subset(cp->subparts_cpus,
						   tmp->new_cpus)) {
				cpumask_andnot(cp->subparts_cpus,
					cp->subparts_cpus, tmp->new_cpus);
				cp->nr_subparts_cpus
					= cpumask_weight(cp->subparts_cpus);
			}
		}

		if (new_prs != old_prs)
			cp->partition_root_state = new_prs;

		spin_unlock_irq(&callback_lock);
		notify_partition_change(cp, old_prs, new_prs);

		WARN_ON(!is_in_v2_mode() &&
			!cpumask_equal(cp->cpus_allowed, cp->effective_cpus));

		update_tasks_cpumask(cp);

		/*
		if (!cpumask_empty(cp->cpus_allowed) &&
		    is_sched_load_balance(cp) &&
		   (!cgroup_subsys_on_dfl(cpuset_cgrp_subsys) ||
		    is_partition_root(cp)))
			need_rebuild_sched_domains = true;

		rcu_read_lock();
		css_put(&cp->css);
	}
	rcu_read_unlock();

	if (need_rebuild_sched_domains)
		rebuild_sched_domains_locked();
}

static void update_sibling_cpumasks(struct cpuset *parent, struct cpuset *cs,
				    struct tmpmasks *tmp)
{
	struct cpuset *sibling;
	struct cgroup_subsys_state *pos_css;

	percpu_rwsem_assert_held(&cpuset_rwsem);

	/*
	rcu_read_lock();
	cpuset_for_each_child(sibling, pos_css, parent) {
		if (sibling == cs)
			continue;
		if (!sibling->use_parent_ecpus)
			continue;
		if (!css_tryget_online(&sibling->css))
			continue;

		rcu_read_unlock();
		update_cpumasks_hier(sibling, tmp);
		rcu_read_lock();
		css_put(&sibling->css);
	}
	rcu_read_unlock();
}

static int update_cpumask(struct cpuset *cs, struct cpuset *trialcs,
			  const char *buf)
{
	int retval;
	struct tmpmasks tmp;

	/* top_cpuset.cpus_allowed tracks cpu_online_mask; it's read-only */
	if (cs == &top_cpuset)
		return -EACCES;

	/*
	if (!*buf) {
		cpumask_clear(trialcs->cpus_allowed);
	} else {
		retval = cpulist_parse(buf, trialcs->cpus_allowed);
		if (retval < 0)
			return retval;

		if (!cpumask_subset(trialcs->cpus_allowed,
				    top_cpuset.cpus_allowed))
			return -EINVAL;
	}

	/* Nothing to do if the cpus didn't change */
	if (cpumask_equal(cs->cpus_allowed, trialcs->cpus_allowed))
		return 0;

	retval = validate_change(cs, trialcs);
	if (retval < 0)
		return retval;

#ifdef CONFIG_CPUMASK_OFFSTACK
	/*
	tmp.addmask  = trialcs->subparts_cpus;
	tmp.delmask  = trialcs->effective_cpus;
	tmp.new_cpus = trialcs->cpus_allowed;
#endif

	if (cs->partition_root_state) {
		/* Cpumask of a partition root cannot be empty */
		if (cpumask_empty(trialcs->cpus_allowed))
			return -EINVAL;
		if (update_parent_subparts_cpumask(cs, partcmd_update,
					trialcs->cpus_allowed, &tmp) < 0)
			return -EINVAL;
	}

	spin_lock_irq(&callback_lock);
	cpumask_copy(cs->cpus_allowed, trialcs->cpus_allowed);

	/*
	if (cs->nr_subparts_cpus) {
		cpumask_and(cs->subparts_cpus, cs->subparts_cpus, cs->cpus_allowed);
		cs->nr_subparts_cpus = cpumask_weight(cs->subparts_cpus);
	}
	spin_unlock_irq(&callback_lock);

	update_cpumasks_hier(cs, &tmp);

	if (cs->partition_root_state) {
		struct cpuset *parent = parent_cs(cs);

		/*
		if (parent->child_ecpus_count)
			update_sibling_cpumasks(parent, cs, &tmp);
	}
	return 0;
}


struct cpuset_migrate_mm_work {
	struct work_struct	work;
	struct mm_struct	*mm;
	nodemask_t		from;
	nodemask_t		to;
};

static void cpuset_migrate_mm_workfn(struct work_struct *work)
{
	struct cpuset_migrate_mm_work *mwork =
		container_of(work, struct cpuset_migrate_mm_work, work);

	/* on a wq worker, no need to worry about %current's mems_allowed */
	do_migrate_pages(mwork->mm, &mwork->from, &mwork->to, MPOL_MF_MOVE_ALL);
	mmput(mwork->mm);
	kfree(mwork);
}

static void cpuset_migrate_mm(struct mm_struct *mm, const nodemask_t *from,
							const nodemask_t *to)
{
	struct cpuset_migrate_mm_work *mwork;

	if (nodes_equal(*from, *to)) {
		mmput(mm);
		return;
	}

	mwork = kzalloc(sizeof(*mwork), GFP_KERNEL);
	if (mwork) {
		mwork->mm = mm;
		mwork->from = *from;
		mwork->to = *to;
		INIT_WORK(&mwork->work, cpuset_migrate_mm_workfn);
		queue_work(cpuset_migrate_mm_wq, &mwork->work);
	} else {
		mmput(mm);
	}
}

static void cpuset_post_attach(void)
{
	flush_workqueue(cpuset_migrate_mm_wq);
}

static void cpuset_change_task_nodemask(struct task_struct *tsk,
					nodemask_t *newmems)
{
	task_lock(tsk);

	local_irq_disable();
	write_seqcount_begin(&tsk->mems_allowed_seq);

	nodes_or(tsk->mems_allowed, tsk->mems_allowed, *newmems);
	mpol_rebind_task(tsk, newmems);
	tsk->mems_allowed = *newmems;

	write_seqcount_end(&tsk->mems_allowed_seq);
	local_irq_enable();

	task_unlock(tsk);
}

static void *cpuset_being_rebound;

static void update_tasks_nodemask(struct cpuset *cs)
{
	static nodemask_t newmems;	/* protected by cpuset_rwsem */
	struct css_task_iter it;
	struct task_struct *task;

	cpuset_being_rebound = cs;		/* causes mpol_dup() rebind */

	guarantee_online_mems(cs, &newmems);

	/*
	css_task_iter_start(&cs->css, 0, &it);
	while ((task = css_task_iter_next(&it))) {
		struct mm_struct *mm;
		bool migrate;

		cpuset_change_task_nodemask(task, &newmems);

		mm = get_task_mm(task);
		if (!mm)
			continue;

		migrate = is_memory_migrate(cs);

		mpol_rebind_mm(mm, &cs->mems_allowed);
		if (migrate)
			cpuset_migrate_mm(mm, &cs->old_mems_allowed, &newmems);
		else
			mmput(mm);
	}
	css_task_iter_end(&it);

	/*
	cs->old_mems_allowed = newmems;

	/* We're done rebinding vmas to this cpuset's new mems_allowed. */
	cpuset_being_rebound = NULL;
}

static void update_nodemasks_hier(struct cpuset *cs, nodemask_t *new_mems)
{
	struct cpuset *cp;
	struct cgroup_subsys_state *pos_css;

	rcu_read_lock();
	cpuset_for_each_descendant_pre(cp, pos_css, cs) {
		struct cpuset *parent = parent_cs(cp);

		nodes_and(*new_mems, cp->mems_allowed, parent->effective_mems);

		/*
		if (is_in_v2_mode() && nodes_empty(*new_mems))
			*new_mems = parent->effective_mems;

		/* Skip the whole subtree if the nodemask remains the same. */
		if (nodes_equal(*new_mems, cp->effective_mems)) {
			pos_css = css_rightmost_descendant(pos_css);
			continue;
		}

		if (!css_tryget_online(&cp->css))
			continue;
		rcu_read_unlock();

		spin_lock_irq(&callback_lock);
		cp->effective_mems = *new_mems;
		spin_unlock_irq(&callback_lock);

		WARN_ON(!is_in_v2_mode() &&
			!nodes_equal(cp->mems_allowed, cp->effective_mems));

		update_tasks_nodemask(cp);

		rcu_read_lock();
		css_put(&cp->css);
	}
	rcu_read_unlock();
}

static int update_nodemask(struct cpuset *cs, struct cpuset *trialcs,
			   const char *buf)
{
	int retval;

	/*
	if (cs == &top_cpuset) {
		retval = -EACCES;
		goto done;
	}

	/*
	if (!*buf) {
		nodes_clear(trialcs->mems_allowed);
	} else {
		retval = nodelist_parse(buf, trialcs->mems_allowed);
		if (retval < 0)
			goto done;

		if (!nodes_subset(trialcs->mems_allowed,
				  top_cpuset.mems_allowed)) {
			retval = -EINVAL;
			goto done;
		}
	}

	if (nodes_equal(cs->mems_allowed, trialcs->mems_allowed)) {
		retval = 0;		/* Too easy - nothing to do */
		goto done;
	}
	retval = validate_change(cs, trialcs);
	if (retval < 0)
		goto done;

	check_insane_mems_config(&trialcs->mems_allowed);

	spin_lock_irq(&callback_lock);
	cs->mems_allowed = trialcs->mems_allowed;
	spin_unlock_irq(&callback_lock);

	/* use trialcs->mems_allowed as a temp variable */
	update_nodemasks_hier(cs, &trialcs->mems_allowed);
done:
	return retval;
}

bool current_cpuset_is_being_rebound(void)
{
	bool ret;

	rcu_read_lock();
	ret = task_cs(current) == cpuset_being_rebound;
	rcu_read_unlock();

	return ret;
}

static int update_relax_domain_level(struct cpuset *cs, s64 val)
{
#ifdef CONFIG_SMP
	if (val < -1 || val >= sched_domain_level_max)
		return -EINVAL;
#endif

	if (val != cs->relax_domain_level) {
		cs->relax_domain_level = val;
		if (!cpumask_empty(cs->cpus_allowed) &&
		    is_sched_load_balance(cs))
			rebuild_sched_domains_locked();
	}

	return 0;
}

static void update_tasks_flags(struct cpuset *cs)
{
	struct css_task_iter it;
	struct task_struct *task;

	css_task_iter_start(&cs->css, 0, &it);
	while ((task = css_task_iter_next(&it)))
		cpuset_update_task_spread_flag(cs, task);
	css_task_iter_end(&it);
}


static int update_flag(cpuset_flagbits_t bit, struct cpuset *cs,
		       int turning_on)
{
	struct cpuset *trialcs;
	int balance_flag_changed;
	int spread_flag_changed;
	int err;

	trialcs = alloc_trial_cpuset(cs);
	if (!trialcs)
		return -ENOMEM;

	if (turning_on)
		set_bit(bit, &trialcs->flags);
	else
		clear_bit(bit, &trialcs->flags);

	err = validate_change(cs, trialcs);
	if (err < 0)
		goto out;

	balance_flag_changed = (is_sched_load_balance(cs) !=
				is_sched_load_balance(trialcs));

	spread_flag_changed = ((is_spread_slab(cs) != is_spread_slab(trialcs))
			|| (is_spread_page(cs) != is_spread_page(trialcs)));

	spin_lock_irq(&callback_lock);
	cs->flags = trialcs->flags;
	spin_unlock_irq(&callback_lock);

	if (!cpumask_empty(trialcs->cpus_allowed) && balance_flag_changed)
		rebuild_sched_domains_locked();

	if (spread_flag_changed)
		update_tasks_flags(cs);
out:
	free_cpuset(trialcs);
	return err;
}

static int update_prstate(struct cpuset *cs, int new_prs)
{
	int err, old_prs = cs->partition_root_state;
	struct cpuset *parent = parent_cs(cs);
	struct tmpmasks tmpmask;

	if (old_prs == new_prs)
		return 0;

	/*
	if (new_prs && (old_prs == PRS_ERROR))
		return -EINVAL;

	if (alloc_cpumasks(NULL, &tmpmask))
		return -ENOMEM;

	err = -EINVAL;
	if (!old_prs) {
		/*
		if (cpumask_empty(cs->cpus_allowed))
			goto out;

		err = update_flag(CS_CPU_EXCLUSIVE, cs, 1);
		if (err)
			goto out;

		err = update_parent_subparts_cpumask(cs, partcmd_enable,
						     NULL, &tmpmask);
		if (err) {
			update_flag(CS_CPU_EXCLUSIVE, cs, 0);
			goto out;
		}
	} else {
		/*
		if (old_prs == PRS_ERROR) {
			update_flag(CS_CPU_EXCLUSIVE, cs, 0);
			err = 0;
			goto out;
		}

		err = update_parent_subparts_cpumask(cs, partcmd_disable,
						     NULL, &tmpmask);
		if (err)
			goto out;

		/* Turning off CS_CPU_EXCLUSIVE will not return error */
		update_flag(CS_CPU_EXCLUSIVE, cs, 0);
	}

	/*
	if (parent != &top_cpuset)
		update_tasks_cpumask(parent);

	if (parent->child_ecpus_count)
		update_sibling_cpumasks(parent, cs, &tmpmask);

	rebuild_sched_domains_locked();
out:
	if (!err) {
		spin_lock_irq(&callback_lock);
		cs->partition_root_state = new_prs;
		spin_unlock_irq(&callback_lock);
		notify_partition_change(cs, old_prs, new_prs);
	}

	free_cpumasks(NULL, &tmpmask);
	return err;
}


#define FM_COEF 933		/* coefficient for half-life of 10 secs */
#define FM_MAXTICKS ((u32)99)   /* useless computing more ticks than this */
#define FM_MAXCNT 1000000	/* limit cnt to avoid overflow */
#define FM_SCALE 1000		/* faux fixed point scale */

static void fmeter_init(struct fmeter *fmp)
{
	fmp->cnt = 0;
	fmp->val = 0;
	fmp->time = 0;
	spin_lock_init(&fmp->lock);
}

static void fmeter_update(struct fmeter *fmp)
{
	time64_t now;
	u32 ticks;

	now = ktime_get_seconds();
	ticks = now - fmp->time;

	if (ticks == 0)
		return;

	ticks = min(FM_MAXTICKS, ticks);
	while (ticks-- > 0)
		fmp->val = (FM_COEF * fmp->val) / FM_SCALE;
	fmp->time = now;

	fmp->val += ((FM_SCALE - FM_COEF) * fmp->cnt) / FM_SCALE;
	fmp->cnt = 0;
}

static void fmeter_markevent(struct fmeter *fmp)
{
	spin_lock(&fmp->lock);
	fmeter_update(fmp);
	fmp->cnt = min(FM_MAXCNT, fmp->cnt + FM_SCALE);
	spin_unlock(&fmp->lock);
}

static int fmeter_getrate(struct fmeter *fmp)
{
	int val;

	spin_lock(&fmp->lock);
	fmeter_update(fmp);
	val = fmp->val;
	spin_unlock(&fmp->lock);
	return val;
}

static struct cpuset *cpuset_attach_old_cs;

static int cpuset_can_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct cpuset *cs;
	struct task_struct *task;
	int ret;

	/* used later by cpuset_attach() */
	cpuset_attach_old_cs = task_cs(cgroup_taskset_first(tset, &css));
	cs = css_cs(css);

	percpu_down_write(&cpuset_rwsem);

	/* allow moving tasks into an empty cpuset if on default hierarchy */
	ret = -ENOSPC;
	if (!is_in_v2_mode() &&
	    (cpumask_empty(cs->cpus_allowed) || nodes_empty(cs->mems_allowed)))
		goto out_unlock;

	cgroup_taskset_for_each(task, css, tset) {
		ret = task_can_attach(task, cs->cpus_allowed);
		if (ret)
			goto out_unlock;
		ret = security_task_setscheduler(task);
		if (ret)
			goto out_unlock;
	}

	/*
	cs->attach_in_progress++;
	ret = 0;
out_unlock:
	percpu_up_write(&cpuset_rwsem);
	return ret;
}

static void cpuset_cancel_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;

	cgroup_taskset_first(tset, &css);

	percpu_down_write(&cpuset_rwsem);
	css_cs(css)->attach_in_progress--;
	percpu_up_write(&cpuset_rwsem);
}

static cpumask_var_t cpus_attach;

static void cpuset_attach(struct cgroup_taskset *tset)
{
	/* static buf protected by cpuset_rwsem */
	static nodemask_t cpuset_attach_nodemask_to;
	struct task_struct *task;
	struct task_struct *leader;
	struct cgroup_subsys_state *css;
	struct cpuset *cs;
	struct cpuset *oldcs = cpuset_attach_old_cs;

	cgroup_taskset_first(tset, &css);
	cs = css_cs(css);

	cpus_read_lock();
	percpu_down_write(&cpuset_rwsem);

	guarantee_online_mems(cs, &cpuset_attach_nodemask_to);

	cgroup_taskset_for_each(task, css, tset) {
		if (cs != &top_cpuset)
			guarantee_online_cpus(task, cpus_attach);
		else
			cpumask_copy(cpus_attach, task_cpu_possible_mask(task));
		/*
		WARN_ON_ONCE(set_cpus_allowed_ptr(task, cpus_attach));

		cpuset_change_task_nodemask(task, &cpuset_attach_nodemask_to);
		cpuset_update_task_spread_flag(cs, task);
	}

	/*
	cpuset_attach_nodemask_to = cs->effective_mems;
	cgroup_taskset_for_each_leader(leader, css, tset) {
		struct mm_struct *mm = get_task_mm(leader);

		if (mm) {
			mpol_rebind_mm(mm, &cpuset_attach_nodemask_to);

			/*
			if (is_memory_migrate(cs))
				cpuset_migrate_mm(mm, &oldcs->old_mems_allowed,
						  &cpuset_attach_nodemask_to);
			else
				mmput(mm);
		}
	}

	cs->old_mems_allowed = cpuset_attach_nodemask_to;

	cs->attach_in_progress--;
	if (!cs->attach_in_progress)
		wake_up(&cpuset_attach_wq);

	percpu_up_write(&cpuset_rwsem);
	cpus_read_unlock();
}


typedef enum {
	FILE_MEMORY_MIGRATE,
	FILE_CPULIST,
	FILE_MEMLIST,
	FILE_EFFECTIVE_CPULIST,
	FILE_EFFECTIVE_MEMLIST,
	FILE_SUBPARTS_CPULIST,
	FILE_CPU_EXCLUSIVE,
	FILE_MEM_EXCLUSIVE,
	FILE_MEM_HARDWALL,
	FILE_SCHED_LOAD_BALANCE,
	FILE_PARTITION_ROOT,
	FILE_SCHED_RELAX_DOMAIN_LEVEL,
	FILE_MEMORY_PRESSURE_ENABLED,
	FILE_MEMORY_PRESSURE,
	FILE_SPREAD_PAGE,
	FILE_SPREAD_SLAB,
} cpuset_filetype_t;

static int cpuset_write_u64(struct cgroup_subsys_state *css, struct cftype *cft,
			    u64 val)
{
	struct cpuset *cs = css_cs(css);
	cpuset_filetype_t type = cft->private;
	int retval = 0;

	cpus_read_lock();
	percpu_down_write(&cpuset_rwsem);
	if (!is_cpuset_online(cs)) {
		retval = -ENODEV;
		goto out_unlock;
	}

	switch (type) {
	case FILE_CPU_EXCLUSIVE:
		retval = update_flag(CS_CPU_EXCLUSIVE, cs, val);
		break;
	case FILE_MEM_EXCLUSIVE:
		retval = update_flag(CS_MEM_EXCLUSIVE, cs, val);
		break;
	case FILE_MEM_HARDWALL:
		retval = update_flag(CS_MEM_HARDWALL, cs, val);
		break;
	case FILE_SCHED_LOAD_BALANCE:
		retval = update_flag(CS_SCHED_LOAD_BALANCE, cs, val);
		break;
	case FILE_MEMORY_MIGRATE:
		retval = update_flag(CS_MEMORY_MIGRATE, cs, val);
		break;
	case FILE_MEMORY_PRESSURE_ENABLED:
		cpuset_memory_pressure_enabled = !!val;
		break;
	case FILE_SPREAD_PAGE:
		retval = update_flag(CS_SPREAD_PAGE, cs, val);
		break;
	case FILE_SPREAD_SLAB:
		retval = update_flag(CS_SPREAD_SLAB, cs, val);
		break;
	default:
		retval = -EINVAL;
		break;
	}
out_unlock:
	percpu_up_write(&cpuset_rwsem);
	cpus_read_unlock();
	return retval;
}

static int cpuset_write_s64(struct cgroup_subsys_state *css, struct cftype *cft,
			    s64 val)
{
	struct cpuset *cs = css_cs(css);
	cpuset_filetype_t type = cft->private;
	int retval = -ENODEV;

	cpus_read_lock();
	percpu_down_write(&cpuset_rwsem);
	if (!is_cpuset_online(cs))
		goto out_unlock;

	switch (type) {
	case FILE_SCHED_RELAX_DOMAIN_LEVEL:
		retval = update_relax_domain_level(cs, val);
		break;
	default:
		retval = -EINVAL;
		break;
	}
out_unlock:
	percpu_up_write(&cpuset_rwsem);
	cpus_read_unlock();
	return retval;
}

static ssize_t cpuset_write_resmask(struct kernfs_open_file *of,
				    char *buf, size_t nbytes, loff_t off)
{
	struct cpuset *cs = css_cs(of_css(of));
	struct cpuset *trialcs;
	int retval = -ENODEV;

	buf = strstrip(buf);

	/*
	css_get(&cs->css);
	kernfs_break_active_protection(of->kn);
	flush_work(&cpuset_hotplug_work);

	cpus_read_lock();
	percpu_down_write(&cpuset_rwsem);
	if (!is_cpuset_online(cs))
		goto out_unlock;

	trialcs = alloc_trial_cpuset(cs);
	if (!trialcs) {
		retval = -ENOMEM;
		goto out_unlock;
	}

	switch (of_cft(of)->private) {
	case FILE_CPULIST:
		retval = update_cpumask(cs, trialcs, buf);
		break;
	case FILE_MEMLIST:
		retval = update_nodemask(cs, trialcs, buf);
		break;
	default:
		retval = -EINVAL;
		break;
	}

	free_cpuset(trialcs);
out_unlock:
	percpu_up_write(&cpuset_rwsem);
	cpus_read_unlock();
	kernfs_unbreak_active_protection(of->kn);
	css_put(&cs->css);
	flush_workqueue(cpuset_migrate_mm_wq);
	return retval ?: nbytes;
}

static int cpuset_common_seq_show(struct seq_file *sf, void *v)
{
	struct cpuset *cs = css_cs(seq_css(sf));
	cpuset_filetype_t type = seq_cft(sf)->private;
	int ret = 0;

	spin_lock_irq(&callback_lock);

	switch (type) {
	case FILE_CPULIST:
		seq_printf(sf, "%*pbl\n", cpumask_pr_args(cs->cpus_allowed));
		break;
	case FILE_MEMLIST:
		seq_printf(sf, "%*pbl\n", nodemask_pr_args(&cs->mems_allowed));
		break;
	case FILE_EFFECTIVE_CPULIST:
		seq_printf(sf, "%*pbl\n", cpumask_pr_args(cs->effective_cpus));
		break;
	case FILE_EFFECTIVE_MEMLIST:
		seq_printf(sf, "%*pbl\n", nodemask_pr_args(&cs->effective_mems));
		break;
	case FILE_SUBPARTS_CPULIST:
		seq_printf(sf, "%*pbl\n", cpumask_pr_args(cs->subparts_cpus));
		break;
	default:
		ret = -EINVAL;
	}

	spin_unlock_irq(&callback_lock);
	return ret;
}

static u64 cpuset_read_u64(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct cpuset *cs = css_cs(css);
	cpuset_filetype_t type = cft->private;
	switch (type) {
	case FILE_CPU_EXCLUSIVE:
		return is_cpu_exclusive(cs);
	case FILE_MEM_EXCLUSIVE:
		return is_mem_exclusive(cs);
	case FILE_MEM_HARDWALL:
		return is_mem_hardwall(cs);
	case FILE_SCHED_LOAD_BALANCE:
		return is_sched_load_balance(cs);
	case FILE_MEMORY_MIGRATE:
		return is_memory_migrate(cs);
	case FILE_MEMORY_PRESSURE_ENABLED:
		return cpuset_memory_pressure_enabled;
	case FILE_MEMORY_PRESSURE:
		return fmeter_getrate(&cs->fmeter);
	case FILE_SPREAD_PAGE:
		return is_spread_page(cs);
	case FILE_SPREAD_SLAB:
		return is_spread_slab(cs);
	default:
		BUG();
	}

	/* Unreachable but makes gcc happy */
	return 0;
}

static s64 cpuset_read_s64(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct cpuset *cs = css_cs(css);
	cpuset_filetype_t type = cft->private;
	switch (type) {
	case FILE_SCHED_RELAX_DOMAIN_LEVEL:
		return cs->relax_domain_level;
	default:
		BUG();
	}

	/* Unreachable but makes gcc happy */
	return 0;
}

static int sched_partition_show(struct seq_file *seq, void *v)
{
	struct cpuset *cs = css_cs(seq_css(seq));

	switch (cs->partition_root_state) {
	case PRS_ENABLED:
		seq_puts(seq, "root\n");
		break;
	case PRS_DISABLED:
		seq_puts(seq, "member\n");
		break;
	case PRS_ERROR:
		seq_puts(seq, "root invalid\n");
		break;
	}
	return 0;
}

static ssize_t sched_partition_write(struct kernfs_open_file *of, char *buf,
				     size_t nbytes, loff_t off)
{
	struct cpuset *cs = css_cs(of_css(of));
	int val;
	int retval = -ENODEV;

	buf = strstrip(buf);

	/*
	if (!strcmp(buf, "root"))
		val = PRS_ENABLED;
	else if (!strcmp(buf, "member"))
		val = PRS_DISABLED;
	else
		return -EINVAL;

	css_get(&cs->css);
	cpus_read_lock();
	percpu_down_write(&cpuset_rwsem);
	if (!is_cpuset_online(cs))
		goto out_unlock;

	retval = update_prstate(cs, val);
out_unlock:
	percpu_up_write(&cpuset_rwsem);
	cpus_read_unlock();
	css_put(&cs->css);
	return retval ?: nbytes;
}


static struct cftype legacy_files[] = {
	{
		.name = "cpus",
		.seq_show = cpuset_common_seq_show,
		.write = cpuset_write_resmask,
		.max_write_len = (100U + 6 * NR_CPUS),
		.private = FILE_CPULIST,
	},

	{
		.name = "mems",
		.seq_show = cpuset_common_seq_show,
		.write = cpuset_write_resmask,
		.max_write_len = (100U + 6 * MAX_NUMNODES),
		.private = FILE_MEMLIST,
	},

	{
		.name = "effective_cpus",
		.seq_show = cpuset_common_seq_show,
		.private = FILE_EFFECTIVE_CPULIST,
	},

	{
		.name = "effective_mems",
		.seq_show = cpuset_common_seq_show,
		.private = FILE_EFFECTIVE_MEMLIST,
	},

	{
		.name = "cpu_exclusive",
		.read_u64 = cpuset_read_u64,
		.write_u64 = cpuset_write_u64,
		.private = FILE_CPU_EXCLUSIVE,
	},

	{
		.name = "mem_exclusive",
		.read_u64 = cpuset_read_u64,
		.write_u64 = cpuset_write_u64,
		.private = FILE_MEM_EXCLUSIVE,
	},

	{
		.name = "mem_hardwall",
		.read_u64 = cpuset_read_u64,
		.write_u64 = cpuset_write_u64,
		.private = FILE_MEM_HARDWALL,
	},

	{
		.name = "sched_load_balance",
		.read_u64 = cpuset_read_u64,
		.write_u64 = cpuset_write_u64,
		.private = FILE_SCHED_LOAD_BALANCE,
	},

	{
		.name = "sched_relax_domain_level",
		.read_s64 = cpuset_read_s64,
		.write_s64 = cpuset_write_s64,
		.private = FILE_SCHED_RELAX_DOMAIN_LEVEL,
	},

	{
		.name = "memory_migrate",
		.read_u64 = cpuset_read_u64,
		.write_u64 = cpuset_write_u64,
		.private = FILE_MEMORY_MIGRATE,
	},

	{
		.name = "memory_pressure",
		.read_u64 = cpuset_read_u64,
		.private = FILE_MEMORY_PRESSURE,
	},

	{
		.name = "memory_spread_page",
		.read_u64 = cpuset_read_u64,
		.write_u64 = cpuset_write_u64,
		.private = FILE_SPREAD_PAGE,
	},

	{
		.name = "memory_spread_slab",
		.read_u64 = cpuset_read_u64,
		.write_u64 = cpuset_write_u64,
		.private = FILE_SPREAD_SLAB,
	},

	{
		.name = "memory_pressure_enabled",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.read_u64 = cpuset_read_u64,
		.write_u64 = cpuset_write_u64,
		.private = FILE_MEMORY_PRESSURE_ENABLED,
	},

	{ }	/* terminate */
};

static struct cftype dfl_files[] = {
	{
		.name = "cpus",
		.seq_show = cpuset_common_seq_show,
		.write = cpuset_write_resmask,
		.max_write_len = (100U + 6 * NR_CPUS),
		.private = FILE_CPULIST,
		.flags = CFTYPE_NOT_ON_ROOT,
	},

	{
		.name = "mems",
		.seq_show = cpuset_common_seq_show,
		.write = cpuset_write_resmask,
		.max_write_len = (100U + 6 * MAX_NUMNODES),
		.private = FILE_MEMLIST,
		.flags = CFTYPE_NOT_ON_ROOT,
	},

	{
		.name = "cpus.effective",
		.seq_show = cpuset_common_seq_show,
		.private = FILE_EFFECTIVE_CPULIST,
	},

	{
		.name = "mems.effective",
		.seq_show = cpuset_common_seq_show,
		.private = FILE_EFFECTIVE_MEMLIST,
	},

	{
		.name = "cpus.partition",
		.seq_show = sched_partition_show,
		.write = sched_partition_write,
		.private = FILE_PARTITION_ROOT,
		.flags = CFTYPE_NOT_ON_ROOT,
		.file_offset = offsetof(struct cpuset, partition_file),
	},

	{
		.name = "cpus.subpartitions",
		.seq_show = cpuset_common_seq_show,
		.private = FILE_SUBPARTS_CPULIST,
		.flags = CFTYPE_DEBUG,
	},

	{ }	/* terminate */
};



static struct cgroup_subsys_state *
cpuset_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cpuset *cs;

	if (!parent_css)
		return &top_cpuset.css;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return ERR_PTR(-ENOMEM);

	if (alloc_cpumasks(cs, NULL)) {
		kfree(cs);
		return ERR_PTR(-ENOMEM);
	}

	__set_bit(CS_SCHED_LOAD_BALANCE, &cs->flags);
	nodes_clear(cs->mems_allowed);
	nodes_clear(cs->effective_mems);
	fmeter_init(&cs->fmeter);
	cs->relax_domain_level = -1;

	/* Set CS_MEMORY_MIGRATE for default hierarchy */
	if (cgroup_subsys_on_dfl(cpuset_cgrp_subsys))
		__set_bit(CS_MEMORY_MIGRATE, &cs->flags);

	return &cs->css;
}

static int cpuset_css_online(struct cgroup_subsys_state *css)
{
	struct cpuset *cs = css_cs(css);
	struct cpuset *parent = parent_cs(cs);
	struct cpuset *tmp_cs;
	struct cgroup_subsys_state *pos_css;

	if (!parent)
		return 0;

	cpus_read_lock();
	percpu_down_write(&cpuset_rwsem);

	set_bit(CS_ONLINE, &cs->flags);
	if (is_spread_page(parent))
		set_bit(CS_SPREAD_PAGE, &cs->flags);
	if (is_spread_slab(parent))
		set_bit(CS_SPREAD_SLAB, &cs->flags);

	cpuset_inc();

	spin_lock_irq(&callback_lock);
	if (is_in_v2_mode()) {
		cpumask_copy(cs->effective_cpus, parent->effective_cpus);
		cs->effective_mems = parent->effective_mems;
		cs->use_parent_ecpus = true;
		parent->child_ecpus_count++;
	}
	spin_unlock_irq(&callback_lock);

	if (!test_bit(CGRP_CPUSET_CLONE_CHILDREN, &css->cgroup->flags))
		goto out_unlock;

	/*
	rcu_read_lock();
	cpuset_for_each_child(tmp_cs, pos_css, parent) {
		if (is_mem_exclusive(tmp_cs) || is_cpu_exclusive(tmp_cs)) {
			rcu_read_unlock();
			goto out_unlock;
		}
	}
	rcu_read_unlock();

	spin_lock_irq(&callback_lock);
	cs->mems_allowed = parent->mems_allowed;
	cs->effective_mems = parent->mems_allowed;
	cpumask_copy(cs->cpus_allowed, parent->cpus_allowed);
	cpumask_copy(cs->effective_cpus, parent->cpus_allowed);
	spin_unlock_irq(&callback_lock);
out_unlock:
	percpu_up_write(&cpuset_rwsem);
	cpus_read_unlock();
	return 0;
}


static void cpuset_css_offline(struct cgroup_subsys_state *css)
{
	struct cpuset *cs = css_cs(css);

	cpus_read_lock();
	percpu_down_write(&cpuset_rwsem);

	if (is_partition_root(cs))
		update_prstate(cs, 0);

	if (!cgroup_subsys_on_dfl(cpuset_cgrp_subsys) &&
	    is_sched_load_balance(cs))
		update_flag(CS_SCHED_LOAD_BALANCE, cs, 0);

	if (cs->use_parent_ecpus) {
		struct cpuset *parent = parent_cs(cs);

		cs->use_parent_ecpus = false;
		parent->child_ecpus_count--;
	}

	cpuset_dec();
	clear_bit(CS_ONLINE, &cs->flags);

	percpu_up_write(&cpuset_rwsem);
	cpus_read_unlock();
}

static void cpuset_css_free(struct cgroup_subsys_state *css)
{
	struct cpuset *cs = css_cs(css);

	free_cpuset(cs);
}

static void cpuset_bind(struct cgroup_subsys_state *root_css)
{
	percpu_down_write(&cpuset_rwsem);
	spin_lock_irq(&callback_lock);

	if (is_in_v2_mode()) {
		cpumask_copy(top_cpuset.cpus_allowed, cpu_possible_mask);
		top_cpuset.mems_allowed = node_possible_map;
	} else {
		cpumask_copy(top_cpuset.cpus_allowed,
			     top_cpuset.effective_cpus);
		top_cpuset.mems_allowed = top_cpuset.effective_mems;
	}

	spin_unlock_irq(&callback_lock);
	percpu_up_write(&cpuset_rwsem);
}

static void cpuset_fork(struct task_struct *task)
{
	if (task_css_is_root(task, cpuset_cgrp_id))
		return;

	set_cpus_allowed_ptr(task, current->cpus_ptr);
	task->mems_allowed = current->mems_allowed;
}

struct cgroup_subsys cpuset_cgrp_subsys = {
	.css_alloc	= cpuset_css_alloc,
	.css_online	= cpuset_css_online,
	.css_offline	= cpuset_css_offline,
	.css_free	= cpuset_css_free,
	.can_attach	= cpuset_can_attach,
	.cancel_attach	= cpuset_cancel_attach,
	.attach		= cpuset_attach,
	.post_attach	= cpuset_post_attach,
	.bind		= cpuset_bind,
	.fork		= cpuset_fork,
	.legacy_cftypes	= legacy_files,
	.dfl_cftypes	= dfl_files,
	.early_init	= true,
	.threaded	= true,
};


int __init cpuset_init(void)
{
	BUG_ON(percpu_init_rwsem(&cpuset_rwsem));

	BUG_ON(!alloc_cpumask_var(&top_cpuset.cpus_allowed, GFP_KERNEL));
	BUG_ON(!alloc_cpumask_var(&top_cpuset.effective_cpus, GFP_KERNEL));
	BUG_ON(!zalloc_cpumask_var(&top_cpuset.subparts_cpus, GFP_KERNEL));

	cpumask_setall(top_cpuset.cpus_allowed);
	nodes_setall(top_cpuset.mems_allowed);
	cpumask_setall(top_cpuset.effective_cpus);
	nodes_setall(top_cpuset.effective_mems);

	fmeter_init(&top_cpuset.fmeter);
	set_bit(CS_SCHED_LOAD_BALANCE, &top_cpuset.flags);
	top_cpuset.relax_domain_level = -1;

	BUG_ON(!alloc_cpumask_var(&cpus_attach, GFP_KERNEL));

	return 0;
}

static void remove_tasks_in_empty_cpuset(struct cpuset *cs)
{
	struct cpuset *parent;

	/*
	parent = parent_cs(cs);
	while (cpumask_empty(parent->cpus_allowed) ||
			nodes_empty(parent->mems_allowed))
		parent = parent_cs(parent);

	if (cgroup_transfer_tasks(parent->css.cgroup, cs->css.cgroup)) {
		pr_err("cpuset: failed to transfer tasks out of empty cpuset ");
		pr_cont_cgroup_name(cs->css.cgroup);
		pr_cont("\n");
	}
}

static void
hotplug_update_tasks_legacy(struct cpuset *cs,
			    struct cpumask *new_cpus, nodemask_t *new_mems,
			    bool cpus_updated, bool mems_updated)
{
	bool is_empty;

	spin_lock_irq(&callback_lock);
	cpumask_copy(cs->cpus_allowed, new_cpus);
	cpumask_copy(cs->effective_cpus, new_cpus);
	cs->mems_allowed = *new_mems;
	cs->effective_mems = *new_mems;
	spin_unlock_irq(&callback_lock);

	/*
	if (cpus_updated && !cpumask_empty(cs->cpus_allowed))
		update_tasks_cpumask(cs);
	if (mems_updated && !nodes_empty(cs->mems_allowed))
		update_tasks_nodemask(cs);

	is_empty = cpumask_empty(cs->cpus_allowed) ||
		   nodes_empty(cs->mems_allowed);

	percpu_up_write(&cpuset_rwsem);

	/*
	if (is_empty)
		remove_tasks_in_empty_cpuset(cs);

	percpu_down_write(&cpuset_rwsem);
}

static void
hotplug_update_tasks(struct cpuset *cs,
		     struct cpumask *new_cpus, nodemask_t *new_mems,
		     bool cpus_updated, bool mems_updated)
{
	if (cpumask_empty(new_cpus))
		cpumask_copy(new_cpus, parent_cs(cs)->effective_cpus);
	if (nodes_empty(*new_mems))
		*new_mems = parent_cs(cs)->effective_mems;

	spin_lock_irq(&callback_lock);
	cpumask_copy(cs->effective_cpus, new_cpus);
	cs->effective_mems = *new_mems;
	spin_unlock_irq(&callback_lock);

	if (cpus_updated)
		update_tasks_cpumask(cs);
	if (mems_updated)
		update_tasks_nodemask(cs);
}

static bool force_rebuild;

void cpuset_force_rebuild(void)
{
	force_rebuild = true;
}

static void cpuset_hotplug_update_tasks(struct cpuset *cs, struct tmpmasks *tmp)
{
	static cpumask_t new_cpus;
	static nodemask_t new_mems;
	bool cpus_updated;
	bool mems_updated;
	struct cpuset *parent;
retry:
	wait_event(cpuset_attach_wq, cs->attach_in_progress == 0);

	percpu_down_write(&cpuset_rwsem);

	/*
	if (cs->attach_in_progress) {
		percpu_up_write(&cpuset_rwsem);
		goto retry;
	}

	parent = parent_cs(cs);
	compute_effective_cpumask(&new_cpus, cs, parent);
	nodes_and(new_mems, cs->mems_allowed, parent->effective_mems);

	if (cs->nr_subparts_cpus)
		/*
		cpumask_andnot(&new_cpus, &new_cpus, cs->subparts_cpus);

	if (!tmp || !cs->partition_root_state)
		goto update_tasks;

	/*
	if (is_partition_root(cs) && (cpumask_empty(&new_cpus) ||
	   (parent->partition_root_state == PRS_ERROR))) {
		if (cs->nr_subparts_cpus) {
			spin_lock_irq(&callback_lock);
			cs->nr_subparts_cpus = 0;
			cpumask_clear(cs->subparts_cpus);
			spin_unlock_irq(&callback_lock);
			compute_effective_cpumask(&new_cpus, cs, parent);
		}

		/*
		if ((parent->partition_root_state == PRS_ERROR) ||
		     cpumask_empty(&new_cpus)) {
			int old_prs;

			update_parent_subparts_cpumask(cs, partcmd_disable,
						       NULL, tmp);
			old_prs = cs->partition_root_state;
			if (old_prs != PRS_ERROR) {
				spin_lock_irq(&callback_lock);
				cs->partition_root_state = PRS_ERROR;
				spin_unlock_irq(&callback_lock);
				notify_partition_change(cs, old_prs, PRS_ERROR);
			}
		}
		cpuset_force_rebuild();
	}

	/*
	if (is_partition_root(parent) &&
	   ((cs->partition_root_state == PRS_ERROR) ||
	    !cpumask_intersects(&new_cpus, parent->subparts_cpus)) &&
	     update_parent_subparts_cpumask(cs, partcmd_update, NULL, tmp))
		cpuset_force_rebuild();

update_tasks:
	cpus_updated = !cpumask_equal(&new_cpus, cs->effective_cpus);
	mems_updated = !nodes_equal(new_mems, cs->effective_mems);

	if (mems_updated)
		check_insane_mems_config(&new_mems);

	if (is_in_v2_mode())
		hotplug_update_tasks(cs, &new_cpus, &new_mems,
				     cpus_updated, mems_updated);
	else
		hotplug_update_tasks_legacy(cs, &new_cpus, &new_mems,
					    cpus_updated, mems_updated);

	percpu_up_write(&cpuset_rwsem);
}

static void cpuset_hotplug_workfn(struct work_struct *work)
{
	static cpumask_t new_cpus;
	static nodemask_t new_mems;
	bool cpus_updated, mems_updated;
	bool on_dfl = is_in_v2_mode();
	struct tmpmasks tmp, *ptmp = NULL;

	if (on_dfl && !alloc_cpumasks(NULL, &tmp))
		ptmp = &tmp;

	percpu_down_write(&cpuset_rwsem);

	/* fetch the available cpus/mems and find out which changed how */
	cpumask_copy(&new_cpus, cpu_active_mask);
	new_mems = node_states[N_MEMORY];

	/*
	cpus_updated = !cpumask_equal(top_cpuset.effective_cpus, &new_cpus);
	mems_updated = !nodes_equal(top_cpuset.effective_mems, new_mems);

	/*
	if (!cpus_updated && top_cpuset.nr_subparts_cpus)
		cpus_updated = true;

	/* synchronize cpus_allowed to cpu_active_mask */
	if (cpus_updated) {
		spin_lock_irq(&callback_lock);
		if (!on_dfl)
			cpumask_copy(top_cpuset.cpus_allowed, &new_cpus);
		/*
		if (top_cpuset.nr_subparts_cpus) {
			if (cpumask_subset(&new_cpus,
					   top_cpuset.subparts_cpus)) {
				top_cpuset.nr_subparts_cpus = 0;
				cpumask_clear(top_cpuset.subparts_cpus);
			} else {
				cpumask_andnot(&new_cpus, &new_cpus,
					       top_cpuset.subparts_cpus);
			}
		}
		cpumask_copy(top_cpuset.effective_cpus, &new_cpus);
		spin_unlock_irq(&callback_lock);
		/* we don't mess with cpumasks of tasks in top_cpuset */
	}

	/* synchronize mems_allowed to N_MEMORY */
	if (mems_updated) {
		spin_lock_irq(&callback_lock);
		if (!on_dfl)
			top_cpuset.mems_allowed = new_mems;
		top_cpuset.effective_mems = new_mems;
		spin_unlock_irq(&callback_lock);
		update_tasks_nodemask(&top_cpuset);
	}

	percpu_up_write(&cpuset_rwsem);

	/* if cpus or mems changed, we need to propagate to descendants */
	if (cpus_updated || mems_updated) {
		struct cpuset *cs;
		struct cgroup_subsys_state *pos_css;

		rcu_read_lock();
		cpuset_for_each_descendant_pre(cs, pos_css, &top_cpuset) {
			if (cs == &top_cpuset || !css_tryget_online(&cs->css))
				continue;
			rcu_read_unlock();

			cpuset_hotplug_update_tasks(cs, ptmp);

			rcu_read_lock();
			css_put(&cs->css);
		}
		rcu_read_unlock();
	}

	/* rebuild sched domains if cpus_allowed has changed */
	if (cpus_updated || force_rebuild) {
		force_rebuild = false;
		rebuild_sched_domains();
	}

	free_cpumasks(NULL, ptmp);
}

void cpuset_update_active_cpus(void)
{
	/*
	schedule_work(&cpuset_hotplug_work);
}

void cpuset_wait_for_hotplug(void)
{
	flush_work(&cpuset_hotplug_work);
}

static int cpuset_track_online_nodes(struct notifier_block *self,
				unsigned long action, void *arg)
{
	schedule_work(&cpuset_hotplug_work);
	return NOTIFY_OK;
}

static struct notifier_block cpuset_track_online_nodes_nb = {
	.notifier_call = cpuset_track_online_nodes,
	.priority = 10,		/* ??! */
};

void __init cpuset_init_smp(void)
{
	/*
	top_cpuset.old_mems_allowed = top_cpuset.mems_allowed;

	cpumask_copy(top_cpuset.effective_cpus, cpu_active_mask);
	top_cpuset.effective_mems = node_states[N_MEMORY];

	register_hotmemory_notifier(&cpuset_track_online_nodes_nb);

	cpuset_migrate_mm_wq = alloc_ordered_workqueue("cpuset_migrate_mm", 0);
	BUG_ON(!cpuset_migrate_mm_wq);
}


void cpuset_cpus_allowed(struct task_struct *tsk, struct cpumask *pmask)
{
	unsigned long flags;

	spin_lock_irqsave(&callback_lock, flags);
	guarantee_online_cpus(tsk, pmask);
	spin_unlock_irqrestore(&callback_lock, flags);
}


bool cpuset_cpus_allowed_fallback(struct task_struct *tsk)
{
	const struct cpumask *possible_mask = task_cpu_possible_mask(tsk);
	const struct cpumask *cs_mask;
	bool changed = false;

	rcu_read_lock();
	cs_mask = task_cs(tsk)->cpus_allowed;
	if (is_in_v2_mode() && cpumask_subset(cs_mask, possible_mask)) {
		do_set_cpus_allowed(tsk, cs_mask);
		changed = true;
	}
	rcu_read_unlock();

	/*
	return changed;
}

void __init cpuset_init_current_mems_allowed(void)
{
	nodes_setall(current->mems_allowed);
}


nodemask_t cpuset_mems_allowed(struct task_struct *tsk)
{
	nodemask_t mask;
	unsigned long flags;

	spin_lock_irqsave(&callback_lock, flags);
	rcu_read_lock();
	guarantee_online_mems(task_cs(tsk), &mask);
	rcu_read_unlock();
	spin_unlock_irqrestore(&callback_lock, flags);

	return mask;
}

int cpuset_nodemask_valid_mems_allowed(nodemask_t *nodemask)
{
	return nodes_intersects(*nodemask, current->mems_allowed);
}

static struct cpuset *nearest_hardwall_ancestor(struct cpuset *cs)
{
	while (!(is_mem_exclusive(cs) || is_mem_hardwall(cs)) && parent_cs(cs))
		cs = parent_cs(cs);
	return cs;
}

bool __cpuset_node_allowed(int node, gfp_t gfp_mask)
{
	struct cpuset *cs;		/* current cpuset ancestors */
	bool allowed;			/* is allocation in zone z allowed? */
	unsigned long flags;

	if (in_interrupt())
		return true;
	if (node_isset(node, current->mems_allowed))
		return true;
	/*
	if (unlikely(tsk_is_oom_victim(current)))
		return true;
	if (gfp_mask & __GFP_HARDWALL)	/* If hardwall request, stop here */
		return false;

	if (current->flags & PF_EXITING) /* Let dying task have memory */
		return true;

	/* Not hardwall and node outside mems_allowed: scan up cpusets */
	spin_lock_irqsave(&callback_lock, flags);

	rcu_read_lock();
	cs = nearest_hardwall_ancestor(task_cs(current));
	allowed = node_isset(node, cs->mems_allowed);
	rcu_read_unlock();

	spin_unlock_irqrestore(&callback_lock, flags);
	return allowed;
}


static int cpuset_spread_node(int *rotor)
{
	return *rotor = next_node_in(*rotor, current->mems_allowed);
}

int cpuset_mem_spread_node(void)
{
	if (current->cpuset_mem_spread_rotor == NUMA_NO_NODE)
		current->cpuset_mem_spread_rotor =
			node_random(&current->mems_allowed);

	return cpuset_spread_node(&current->cpuset_mem_spread_rotor);
}

int cpuset_slab_spread_node(void)
{
	if (current->cpuset_slab_spread_rotor == NUMA_NO_NODE)
		current->cpuset_slab_spread_rotor =
			node_random(&current->mems_allowed);

	return cpuset_spread_node(&current->cpuset_slab_spread_rotor);
}

EXPORT_SYMBOL_GPL(cpuset_mem_spread_node);


int cpuset_mems_allowed_intersects(const struct task_struct *tsk1,
				   const struct task_struct *tsk2)
{
	return nodes_intersects(tsk1->mems_allowed, tsk2->mems_allowed);
}

void cpuset_print_current_mems_allowed(void)
{
	struct cgroup *cgrp;

	rcu_read_lock();

	cgrp = task_cs(current)->css.cgroup;
	pr_cont(",cpuset=");
	pr_cont_cgroup_name(cgrp);
	pr_cont(",mems_allowed=%*pbl",
		nodemask_pr_args(&current->mems_allowed));

	rcu_read_unlock();
}


int cpuset_memory_pressure_enabled __read_mostly;


void __cpuset_memory_pressure_bump(void)
{
	rcu_read_lock();
	fmeter_markevent(&task_cs(current)->fmeter);
	rcu_read_unlock();
}

#ifdef CONFIG_PROC_PID_CPUSET
int proc_cpuset_show(struct seq_file *m, struct pid_namespace *ns,
		     struct pid *pid, struct task_struct *tsk)
{
	char *buf;
	struct cgroup_subsys_state *css;
	int retval;

	retval = -ENOMEM;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		goto out;

	css = task_get_css(tsk, cpuset_cgrp_id);
	retval = cgroup_path_ns(css->cgroup, buf, PATH_MAX,
				current->nsproxy->cgroup_ns);
	css_put(css);
	if (retval >= PATH_MAX)
		retval = -ENAMETOOLONG;
	if (retval < 0)
		goto out_free;
	seq_puts(m, buf);
	seq_putc(m, '\n');
	retval = 0;
out_free:
	kfree(buf);
out:
	return retval;
}
#endif /* CONFIG_PROC_PID_CPUSET */

void cpuset_task_status_allowed(struct seq_file *m, struct task_struct *task)
{
	seq_printf(m, "Mems_allowed:\t%*pb\n",
		   nodemask_pr_args(&task->mems_allowed));
	seq_printf(m, "Mems_allowed_list:\t%*pbl\n",
		   nodemask_pr_args(&task->mems_allowed));
}
