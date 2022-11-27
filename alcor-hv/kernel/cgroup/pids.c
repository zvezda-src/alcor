
#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/sched/task.h>

#define PIDS_MAX (PID_MAX_LIMIT + 1ULL)
#define PIDS_MAX_STR "max"

struct pids_cgroup {
	struct cgroup_subsys_state	css;

	/*
	atomic64_t			counter;
	atomic64_t			limit;

	/* Handle for "pids.events" */
	struct cgroup_file		events_file;

	/* Number of times fork failed because limit was hit. */
	atomic64_t			events_limit;
};

static struct pids_cgroup *css_pids(struct cgroup_subsys_state *css)
{
	return container_of(css, struct pids_cgroup, css);
}

static struct pids_cgroup *parent_pids(struct pids_cgroup *pids)
{
	return css_pids(pids->css.parent);
}

static struct cgroup_subsys_state *
pids_css_alloc(struct cgroup_subsys_state *parent)
{
	struct pids_cgroup *pids;

	pids = kzalloc(sizeof(struct pids_cgroup), GFP_KERNEL);
	if (!pids)
		return ERR_PTR(-ENOMEM);

	atomic64_set(&pids->counter, 0);
	atomic64_set(&pids->limit, PIDS_MAX);
	atomic64_set(&pids->events_limit, 0);
	return &pids->css;
}

static void pids_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_pids(css));
}

static void pids_cancel(struct pids_cgroup *pids, int num)
{
	/*
	WARN_ON_ONCE(atomic64_add_negative(-num, &pids->counter));
}

static void pids_uncharge(struct pids_cgroup *pids, int num)
{
	struct pids_cgroup *p;

	for (p = pids; parent_pids(p); p = parent_pids(p))
		pids_cancel(p, num);
}

static void pids_charge(struct pids_cgroup *pids, int num)
{
	struct pids_cgroup *p;

	for (p = pids; parent_pids(p); p = parent_pids(p))
		atomic64_add(num, &p->counter);
}

static int pids_try_charge(struct pids_cgroup *pids, int num)
{
	struct pids_cgroup *p, *q;

	for (p = pids; parent_pids(p); p = parent_pids(p)) {
		int64_t new = atomic64_add_return(num, &p->counter);
		int64_t limit = atomic64_read(&p->limit);

		/*
		if (new > limit)
			goto revert;
	}

	return 0;

revert:
	for (q = pids; q != p; q = parent_pids(q))
		pids_cancel(q, num);
	pids_cancel(p, num);

	return -EAGAIN;
}

static int pids_can_attach(struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cgroup_subsys_state *dst_css;

	cgroup_taskset_for_each(task, dst_css, tset) {
		struct pids_cgroup *pids = css_pids(dst_css);
		struct cgroup_subsys_state *old_css;
		struct pids_cgroup *old_pids;

		/*
		old_css = task_css(task, pids_cgrp_id);
		old_pids = css_pids(old_css);

		pids_charge(pids, 1);
		pids_uncharge(old_pids, 1);
	}

	return 0;
}

static void pids_cancel_attach(struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cgroup_subsys_state *dst_css;

	cgroup_taskset_for_each(task, dst_css, tset) {
		struct pids_cgroup *pids = css_pids(dst_css);
		struct cgroup_subsys_state *old_css;
		struct pids_cgroup *old_pids;

		old_css = task_css(task, pids_cgrp_id);
		old_pids = css_pids(old_css);

		pids_charge(old_pids, 1);
		pids_uncharge(pids, 1);
	}
}

static int pids_can_fork(struct task_struct *task, struct css_set *cset)
{
	struct cgroup_subsys_state *css;
	struct pids_cgroup *pids;
	int err;

	if (cset)
		css = cset->subsys[pids_cgrp_id];
	else
		css = task_css_check(current, pids_cgrp_id, true);
	pids = css_pids(css);
	err = pids_try_charge(pids, 1);
	if (err) {
		/* Only log the first time events_limit is incremented. */
		if (atomic64_inc_return(&pids->events_limit) == 1) {
			pr_info("cgroup: fork rejected by pids controller in ");
			pr_cont_cgroup_path(css->cgroup);
			pr_cont("\n");
		}
		cgroup_file_notify(&pids->events_file);
	}
	return err;
}

static void pids_cancel_fork(struct task_struct *task, struct css_set *cset)
{
	struct cgroup_subsys_state *css;
	struct pids_cgroup *pids;

	if (cset)
		css = cset->subsys[pids_cgrp_id];
	else
		css = task_css_check(current, pids_cgrp_id, true);
	pids = css_pids(css);
	pids_uncharge(pids, 1);
}

static void pids_release(struct task_struct *task)
{
	struct pids_cgroup *pids = css_pids(task_css(task, pids_cgrp_id));

	pids_uncharge(pids, 1);
}

static ssize_t pids_max_write(struct kernfs_open_file *of, char *buf,
			      size_t nbytes, loff_t off)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct pids_cgroup *pids = css_pids(css);
	int64_t limit;
	int err;

	buf = strstrip(buf);
	if (!strcmp(buf, PIDS_MAX_STR)) {
		limit = PIDS_MAX;
		goto set_limit;
	}

	err = kstrtoll(buf, 0, &limit);
	if (err)
		return err;

	if (limit < 0 || limit >= PIDS_MAX)
		return -EINVAL;

set_limit:
	/*
	atomic64_set(&pids->limit, limit);
	return nbytes;
}

static int pids_max_show(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct pids_cgroup *pids = css_pids(css);
	int64_t limit = atomic64_read(&pids->limit);

	if (limit >= PIDS_MAX)
		seq_printf(sf, "%s\n", PIDS_MAX_STR);
	else
		seq_printf(sf, "%lld\n", limit);

	return 0;
}

static s64 pids_current_read(struct cgroup_subsys_state *css,
			     struct cftype *cft)
{
	struct pids_cgroup *pids = css_pids(css);

	return atomic64_read(&pids->counter);
}

static int pids_events_show(struct seq_file *sf, void *v)
{
	struct pids_cgroup *pids = css_pids(seq_css(sf));

	seq_printf(sf, "max %lld\n", (s64)atomic64_read(&pids->events_limit));
	return 0;
}

static struct cftype pids_files[] = {
	{
		.name = "max",
		.write = pids_max_write,
		.seq_show = pids_max_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "current",
		.read_s64 = pids_current_read,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "events",
		.seq_show = pids_events_show,
		.file_offset = offsetof(struct pids_cgroup, events_file),
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{ }	/* terminate */
};

struct cgroup_subsys pids_cgrp_subsys = {
	.css_alloc	= pids_css_alloc,
	.css_free	= pids_css_free,
	.can_attach 	= pids_can_attach,
	.cancel_attach 	= pids_cancel_attach,
	.can_fork	= pids_can_fork,
	.cancel_fork	= pids_cancel_fork,
	.release	= pids_release,
	.legacy_cftypes	= pids_files,
	.dfl_cftypes	= pids_files,
	.threaded	= true,
};
