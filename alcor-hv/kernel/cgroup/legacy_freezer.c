
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/freezer.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>

enum freezer_state_flags {
	CGROUP_FREEZER_ONLINE	= (1 << 0), /* freezer is fully online */
	CGROUP_FREEZING_SELF	= (1 << 1), /* this freezer is freezing */
	CGROUP_FREEZING_PARENT	= (1 << 2), /* the parent freezer is freezing */
	CGROUP_FROZEN		= (1 << 3), /* this and its descendants frozen */

	/* mask for all FREEZING flags */
	CGROUP_FREEZING		= CGROUP_FREEZING_SELF | CGROUP_FREEZING_PARENT,
};

struct freezer {
	struct cgroup_subsys_state	css;
	unsigned int			state;
};

static DEFINE_MUTEX(freezer_mutex);

static inline struct freezer *css_freezer(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct freezer, css) : NULL;
}

static inline struct freezer *task_freezer(struct task_struct *task)
{
	return css_freezer(task_css(task, freezer_cgrp_id));
}

static struct freezer *parent_freezer(struct freezer *freezer)
{
	return css_freezer(freezer->css.parent);
}

bool cgroup_freezing(struct task_struct *task)
{
	bool ret;

	rcu_read_lock();
	ret = task_freezer(task)->state & CGROUP_FREEZING;
	rcu_read_unlock();

	return ret;
}

static const char *freezer_state_strs(unsigned int state)
{
	if (state & CGROUP_FROZEN)
		return "FROZEN";
	if (state & CGROUP_FREEZING)
		return "FREEZING";
	return "THAWED";
};

static struct cgroup_subsys_state *
freezer_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct freezer *freezer;

	freezer = kzalloc(sizeof(struct freezer), GFP_KERNEL);
	if (!freezer)
		return ERR_PTR(-ENOMEM);

	return &freezer->css;
}

static int freezer_css_online(struct cgroup_subsys_state *css)
{
	struct freezer *freezer = css_freezer(css);
	struct freezer *parent = parent_freezer(freezer);

	mutex_lock(&freezer_mutex);

	freezer->state |= CGROUP_FREEZER_ONLINE;

	if (parent && (parent->state & CGROUP_FREEZING)) {
		freezer->state |= CGROUP_FREEZING_PARENT | CGROUP_FROZEN;
		atomic_inc(&system_freezing_cnt);
	}

	mutex_unlock(&freezer_mutex);
	return 0;
}

static void freezer_css_offline(struct cgroup_subsys_state *css)
{
	struct freezer *freezer = css_freezer(css);

	mutex_lock(&freezer_mutex);

	if (freezer->state & CGROUP_FREEZING)
		atomic_dec(&system_freezing_cnt);

	freezer->state = 0;

	mutex_unlock(&freezer_mutex);
}

static void freezer_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_freezer(css));
}

static void freezer_attach(struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cgroup_subsys_state *new_css;

	mutex_lock(&freezer_mutex);

	/*
	cgroup_taskset_for_each(task, new_css, tset) {
		struct freezer *freezer = css_freezer(new_css);

		if (!(freezer->state & CGROUP_FREEZING)) {
			__thaw_task(task);
		} else {
			freeze_task(task);
			/* clear FROZEN and propagate upwards */
			while (freezer && (freezer->state & CGROUP_FROZEN)) {
				freezer->state &= ~CGROUP_FROZEN;
				freezer = parent_freezer(freezer);
			}
		}
	}

	mutex_unlock(&freezer_mutex);
}

static void freezer_fork(struct task_struct *task)
{
	struct freezer *freezer;

	/*
	if (task_css_is_root(task, freezer_cgrp_id))
		return;

	mutex_lock(&freezer_mutex);
	rcu_read_lock();

	freezer = task_freezer(task);
	if (freezer->state & CGROUP_FREEZING)
		freeze_task(task);

	rcu_read_unlock();
	mutex_unlock(&freezer_mutex);
}

static void update_if_frozen(struct cgroup_subsys_state *css)
{
	struct freezer *freezer = css_freezer(css);
	struct cgroup_subsys_state *pos;
	struct css_task_iter it;
	struct task_struct *task;

	lockdep_assert_held(&freezer_mutex);

	if (!(freezer->state & CGROUP_FREEZING) ||
	    (freezer->state & CGROUP_FROZEN))
		return;

	/* are all (live) children frozen? */
	rcu_read_lock();
	css_for_each_child(pos, css) {
		struct freezer *child = css_freezer(pos);

		if ((child->state & CGROUP_FREEZER_ONLINE) &&
		    !(child->state & CGROUP_FROZEN)) {
			rcu_read_unlock();
			return;
		}
	}
	rcu_read_unlock();

	/* are all tasks frozen? */
	css_task_iter_start(css, 0, &it);

	while ((task = css_task_iter_next(&it))) {
		if (freezing(task)) {
			/*
			if (!frozen(task) && !freezer_should_skip(task))
				goto out_iter_end;
		}
	}

	freezer->state |= CGROUP_FROZEN;
out_iter_end:
	css_task_iter_end(&it);
}

static int freezer_read(struct seq_file *m, void *v)
{
	struct cgroup_subsys_state *css = seq_css(m), *pos;

	mutex_lock(&freezer_mutex);
	rcu_read_lock();

	/* update states bottom-up */
	css_for_each_descendant_post(pos, css) {
		if (!css_tryget_online(pos))
			continue;
		rcu_read_unlock();

		update_if_frozen(pos);

		rcu_read_lock();
		css_put(pos);
	}

	rcu_read_unlock();
	mutex_unlock(&freezer_mutex);

	seq_puts(m, freezer_state_strs(css_freezer(css)->state));
	seq_putc(m, '\n');
	return 0;
}

static void freeze_cgroup(struct freezer *freezer)
{
	struct css_task_iter it;
	struct task_struct *task;

	css_task_iter_start(&freezer->css, 0, &it);
	while ((task = css_task_iter_next(&it)))
		freeze_task(task);
	css_task_iter_end(&it);
}

static void unfreeze_cgroup(struct freezer *freezer)
{
	struct css_task_iter it;
	struct task_struct *task;

	css_task_iter_start(&freezer->css, 0, &it);
	while ((task = css_task_iter_next(&it)))
		__thaw_task(task);
	css_task_iter_end(&it);
}

static void freezer_apply_state(struct freezer *freezer, bool freeze,
				unsigned int state)
{
	/* also synchronizes against task migration, see freezer_attach() */
	lockdep_assert_held(&freezer_mutex);

	if (!(freezer->state & CGROUP_FREEZER_ONLINE))
		return;

	if (freeze) {
		if (!(freezer->state & CGROUP_FREEZING))
			atomic_inc(&system_freezing_cnt);
		freezer->state |= state;
		freeze_cgroup(freezer);
	} else {
		bool was_freezing = freezer->state & CGROUP_FREEZING;

		freezer->state &= ~state;

		if (!(freezer->state & CGROUP_FREEZING)) {
			if (was_freezing)
				atomic_dec(&system_freezing_cnt);
			freezer->state &= ~CGROUP_FROZEN;
			unfreeze_cgroup(freezer);
		}
	}
}

static void freezer_change_state(struct freezer *freezer, bool freeze)
{
	struct cgroup_subsys_state *pos;

	/*
	mutex_lock(&freezer_mutex);
	rcu_read_lock();
	css_for_each_descendant_pre(pos, &freezer->css) {
		struct freezer *pos_f = css_freezer(pos);
		struct freezer *parent = parent_freezer(pos_f);

		if (!css_tryget_online(pos))
			continue;
		rcu_read_unlock();

		if (pos_f == freezer)
			freezer_apply_state(pos_f, freeze,
					    CGROUP_FREEZING_SELF);
		else
			freezer_apply_state(pos_f,
					    parent->state & CGROUP_FREEZING,
					    CGROUP_FREEZING_PARENT);

		rcu_read_lock();
		css_put(pos);
	}
	rcu_read_unlock();
	mutex_unlock(&freezer_mutex);
}

static ssize_t freezer_write(struct kernfs_open_file *of,
			     char *buf, size_t nbytes, loff_t off)
{
	bool freeze;

	buf = strstrip(buf);

	if (strcmp(buf, freezer_state_strs(0)) == 0)
		freeze = false;
	else if (strcmp(buf, freezer_state_strs(CGROUP_FROZEN)) == 0)
		freeze = true;
	else
		return -EINVAL;

	freezer_change_state(css_freezer(of_css(of)), freeze);
	return nbytes;
}

static u64 freezer_self_freezing_read(struct cgroup_subsys_state *css,
				      struct cftype *cft)
{
	struct freezer *freezer = css_freezer(css);

	return (bool)(freezer->state & CGROUP_FREEZING_SELF);
}

static u64 freezer_parent_freezing_read(struct cgroup_subsys_state *css,
					struct cftype *cft)
{
	struct freezer *freezer = css_freezer(css);

	return (bool)(freezer->state & CGROUP_FREEZING_PARENT);
}

static struct cftype files[] = {
	{
		.name = "state",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = freezer_read,
		.write = freezer_write,
	},
	{
		.name = "self_freezing",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = freezer_self_freezing_read,
	},
	{
		.name = "parent_freezing",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = freezer_parent_freezing_read,
	},
	{ }	/* terminate */
};

struct cgroup_subsys freezer_cgrp_subsys = {
	.css_alloc	= freezer_css_alloc,
	.css_online	= freezer_css_online,
	.css_offline	= freezer_css_offline,
	.css_free	= freezer_css_free,
	.attach		= freezer_attach,
	.fork		= freezer_fork,
	.legacy_cftypes	= files,
};
