#include "cgroup-internal.h"

#include <linux/ctype.h>
#include <linux/kmod.h>
#include <linux/sort.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/delayacct.h>
#include <linux/pid_namespace.h>
#include <linux/cgroupstats.h>
#include <linux/fs_parser.h>

#include <trace/events/cgroup.h>

#define CGROUP_PIDLIST_DESTROY_DELAY	HZ

static u16 cgroup_no_v1_mask;

static bool cgroup_no_v1_named;

static struct workqueue_struct *cgroup_pidlist_destroy_wq;

static DEFINE_SPINLOCK(release_agent_path_lock);

bool cgroup1_ssid_disabled(int ssid)
{
	return cgroup_no_v1_mask & (1 << ssid);
}

int cgroup_attach_task_all(struct task_struct *from, struct task_struct *tsk)
{
	struct cgroup_root *root;
	int retval = 0;

	mutex_lock(&cgroup_mutex);
	percpu_down_write(&cgroup_threadgroup_rwsem);
	for_each_root(root) {
		struct cgroup *from_cgrp;

		spin_lock_irq(&css_set_lock);
		from_cgrp = task_cgroup_from_root(from, root);
		spin_unlock_irq(&css_set_lock);

		retval = cgroup_attach_task(from_cgrp, tsk, false);
		if (retval)
			break;
	}
	percpu_up_write(&cgroup_threadgroup_rwsem);
	mutex_unlock(&cgroup_mutex);

	return retval;
}
EXPORT_SYMBOL_GPL(cgroup_attach_task_all);

int cgroup_transfer_tasks(struct cgroup *to, struct cgroup *from)
{
	DEFINE_CGROUP_MGCTX(mgctx);
	struct cgrp_cset_link *link;
	struct css_task_iter it;
	struct task_struct *task;
	int ret;

	if (cgroup_on_dfl(to))
		return -EINVAL;

	ret = cgroup_migrate_vet_dst(to);
	if (ret)
		return ret;

	mutex_lock(&cgroup_mutex);

	percpu_down_write(&cgroup_threadgroup_rwsem);

	/* all tasks in @from are being moved, all csets are source */
	spin_lock_irq(&css_set_lock);
	list_for_each_entry(link, &from->cset_links, cset_link)
		cgroup_migrate_add_src(link->cset, to, &mgctx);
	spin_unlock_irq(&css_set_lock);

	ret = cgroup_migrate_prepare_dst(&mgctx);
	if (ret)
		goto out_err;

	/*
	do {
		css_task_iter_start(&from->self, 0, &it);

		do {
			task = css_task_iter_next(&it);
		} while (task && (task->flags & PF_EXITING));

		if (task)
			get_task_struct(task);
		css_task_iter_end(&it);

		if (task) {
			ret = cgroup_migrate(task, false, &mgctx);
			if (!ret)
				TRACE_CGROUP_PATH(transfer_tasks, to, task, false);
			put_task_struct(task);
		}
	} while (task && !ret);
out_err:
	cgroup_migrate_finish(&mgctx);
	percpu_up_write(&cgroup_threadgroup_rwsem);
	mutex_unlock(&cgroup_mutex);
	return ret;
}


enum cgroup_filetype {
	CGROUP_FILE_PROCS,
	CGROUP_FILE_TASKS,
};

struct cgroup_pidlist {
	/*
	struct { enum cgroup_filetype type; struct pid_namespace *ns; } key;
	/* array of xids */
	pid_t *list;
	/* how many elements the above list has */
	int length;
	/* each of these stored in a list by its cgroup */
	struct list_head links;
	/* pointer to the cgroup we belong to, for list removal purposes */
	struct cgroup *owner;
	/* for delayed destruction */
	struct delayed_work destroy_dwork;
};

void cgroup1_pidlist_destroy_all(struct cgroup *cgrp)
{
	struct cgroup_pidlist *l, *tmp_l;

	mutex_lock(&cgrp->pidlist_mutex);
	list_for_each_entry_safe(l, tmp_l, &cgrp->pidlists, links)
		mod_delayed_work(cgroup_pidlist_destroy_wq, &l->destroy_dwork, 0);
	mutex_unlock(&cgrp->pidlist_mutex);

	flush_workqueue(cgroup_pidlist_destroy_wq);
	BUG_ON(!list_empty(&cgrp->pidlists));
}

static void cgroup_pidlist_destroy_work_fn(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct cgroup_pidlist *l = container_of(dwork, struct cgroup_pidlist,
						destroy_dwork);
	struct cgroup_pidlist *tofree = NULL;

	mutex_lock(&l->owner->pidlist_mutex);

	/*
	if (!delayed_work_pending(dwork)) {
		list_del(&l->links);
		kvfree(l->list);
		put_pid_ns(l->key.ns);
		tofree = l;
	}

	mutex_unlock(&l->owner->pidlist_mutex);
	kfree(tofree);
}

static int pidlist_uniq(pid_t *list, int length)
{
	int src, dest = 1;

	/*
	if (length == 0 || length == 1)
		return length;
	/* src and dest walk down the list; dest counts unique elements */
	for (src = 1; src < length; src++) {
		/* find next unique element */
		while (list[src] == list[src-1]) {
			src++;
			if (src == length)
				goto after;
		}
		/* dest always points to where the next unique element goes */
		list[dest] = list[src];
		dest++;
	}
after:
	return dest;
}

static int cmppid(const void *a, const void *b)
{
	return *(pid_t *)a - *(pid_t *)b;
}

static struct cgroup_pidlist *cgroup_pidlist_find(struct cgroup *cgrp,
						  enum cgroup_filetype type)
{
	struct cgroup_pidlist *l;
	/* don't need task_nsproxy() if we're looking at ourself */
	struct pid_namespace *ns = task_active_pid_ns(current);

	lockdep_assert_held(&cgrp->pidlist_mutex);

	list_for_each_entry(l, &cgrp->pidlists, links)
		if (l->key.type == type && l->key.ns == ns)
			return l;
	return NULL;
}

static struct cgroup_pidlist *cgroup_pidlist_find_create(struct cgroup *cgrp,
						enum cgroup_filetype type)
{
	struct cgroup_pidlist *l;

	lockdep_assert_held(&cgrp->pidlist_mutex);

	l = cgroup_pidlist_find(cgrp, type);
	if (l)
		return l;

	/* entry not found; create a new one */
	l = kzalloc(sizeof(struct cgroup_pidlist), GFP_KERNEL);
	if (!l)
		return l;

	INIT_DELAYED_WORK(&l->destroy_dwork, cgroup_pidlist_destroy_work_fn);
	l->key.type = type;
	/* don't need task_nsproxy() if we're looking at ourself */
	l->key.ns = get_pid_ns(task_active_pid_ns(current));
	l->owner = cgrp;
	list_add(&l->links, &cgrp->pidlists);
	return l;
}

static int pidlist_array_load(struct cgroup *cgrp, enum cgroup_filetype type,
			      struct cgroup_pidlist **lp)
{
	pid_t *array;
	int length;
	int pid, n = 0; /* used for populating the array */
	struct css_task_iter it;
	struct task_struct *tsk;
	struct cgroup_pidlist *l;

	lockdep_assert_held(&cgrp->pidlist_mutex);

	/*
	length = cgroup_task_count(cgrp);
	array = kvmalloc_array(length, sizeof(pid_t), GFP_KERNEL);
	if (!array)
		return -ENOMEM;
	/* now, populate the array */
	css_task_iter_start(&cgrp->self, 0, &it);
	while ((tsk = css_task_iter_next(&it))) {
		if (unlikely(n == length))
			break;
		/* get tgid or pid for procs or tasks file respectively */
		if (type == CGROUP_FILE_PROCS)
			pid = task_tgid_vnr(tsk);
		else
			pid = task_pid_vnr(tsk);
		if (pid > 0) /* make sure to only use valid results */
			array[n++] = pid;
	}
	css_task_iter_end(&it);
	length = n;
	/* now sort & (if procs) strip out duplicates */
	sort(array, length, sizeof(pid_t), cmppid, NULL);
	if (type == CGROUP_FILE_PROCS)
		length = pidlist_uniq(array, length);

	l = cgroup_pidlist_find_create(cgrp, type);
	if (!l) {
		kvfree(array);
		return -ENOMEM;
	}

	/* store array, freeing old if necessary */
	kvfree(l->list);
	l->list = array;
	l->length = length;
	return 0;
}


static void *cgroup_pidlist_start(struct seq_file *s, loff_t *pos)
{
	/*
	struct kernfs_open_file *of = s->private;
	struct cgroup_file_ctx *ctx = of->priv;
	struct cgroup *cgrp = seq_css(s)->cgroup;
	struct cgroup_pidlist *l;
	enum cgroup_filetype type = seq_cft(s)->private;
	int index = 0, pid = *pos;
	int *iter, ret;

	mutex_lock(&cgrp->pidlist_mutex);

	/*
	if (ctx->procs1.pidlist)
		ctx->procs1.pidlist = cgroup_pidlist_find(cgrp, type);

	/*
	if (!ctx->procs1.pidlist) {
		ret = pidlist_array_load(cgrp, type, &ctx->procs1.pidlist);
		if (ret)
			return ERR_PTR(ret);
	}
	l = ctx->procs1.pidlist;

	if (pid) {
		int end = l->length;

		while (index < end) {
			int mid = (index + end) / 2;
			if (l->list[mid] == pid) {
				index = mid;
				break;
			} else if (l->list[mid] <= pid)
				index = mid + 1;
			else
				end = mid;
		}
	}
	/* If we're off the end of the array, we're done */
	if (index >= l->length)
		return NULL;
	/* Update the abstract position to be the actual pid that we found */
	iter = l->list + index;
	return iter;
}

static void cgroup_pidlist_stop(struct seq_file *s, void *v)
{
	struct kernfs_open_file *of = s->private;
	struct cgroup_file_ctx *ctx = of->priv;
	struct cgroup_pidlist *l = ctx->procs1.pidlist;

	if (l)
		mod_delayed_work(cgroup_pidlist_destroy_wq, &l->destroy_dwork,
				 CGROUP_PIDLIST_DESTROY_DELAY);
	mutex_unlock(&seq_css(s)->cgroup->pidlist_mutex);
}

static void *cgroup_pidlist_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct kernfs_open_file *of = s->private;
	struct cgroup_file_ctx *ctx = of->priv;
	struct cgroup_pidlist *l = ctx->procs1.pidlist;
	pid_t *p = v;
	pid_t *end = l->list + l->length;
	/*
	p++;
	if (p >= end) {
		(*pos)++;
		return NULL;
	} else {
		*pos = *p;
		return p;
	}
}

static int cgroup_pidlist_show(struct seq_file *s, void *v)
{
	seq_printf(s, "%d\n", *(int *)v);

	return 0;
}

static ssize_t __cgroup1_procs_write(struct kernfs_open_file *of,
				     char *buf, size_t nbytes, loff_t off,
				     bool threadgroup)
{
	struct cgroup *cgrp;
	struct task_struct *task;
	const struct cred *cred, *tcred;
	ssize_t ret;
	bool locked;

	cgrp = cgroup_kn_lock_live(of->kn, false);
	if (!cgrp)
		return -ENODEV;

	task = cgroup_procs_write_start(buf, threadgroup, &locked);
	ret = PTR_ERR_OR_ZERO(task);
	if (ret)
		goto out_unlock;

	/*
	cred = of->file->f_cred;
	tcred = get_task_cred(task);
	if (!uid_eq(cred->euid, GLOBAL_ROOT_UID) &&
	    !uid_eq(cred->euid, tcred->uid) &&
	    !uid_eq(cred->euid, tcred->suid))
		ret = -EACCES;
	put_cred(tcred);
	if (ret)
		goto out_finish;

	ret = cgroup_attach_task(cgrp, task, threadgroup);

out_finish:
	cgroup_procs_write_finish(task, locked);
out_unlock:
	cgroup_kn_unlock(of->kn);

	return ret ?: nbytes;
}

static ssize_t cgroup1_procs_write(struct kernfs_open_file *of,
				   char *buf, size_t nbytes, loff_t off)
{
	return __cgroup1_procs_write(of, buf, nbytes, off, true);
}

static ssize_t cgroup1_tasks_write(struct kernfs_open_file *of,
				   char *buf, size_t nbytes, loff_t off)
{
	return __cgroup1_procs_write(of, buf, nbytes, off, false);
}

static ssize_t cgroup_release_agent_write(struct kernfs_open_file *of,
					  char *buf, size_t nbytes, loff_t off)
{
	struct cgroup *cgrp;
	struct cgroup_file_ctx *ctx;

	BUILD_BUG_ON(sizeof(cgrp->root->release_agent_path) < PATH_MAX);

	/*
	ctx = of->priv;
	if ((ctx->ns->user_ns != &init_user_ns) ||
	    !file_ns_capable(of->file, &init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	cgrp = cgroup_kn_lock_live(of->kn, false);
	if (!cgrp)
		return -ENODEV;
	spin_lock(&release_agent_path_lock);
	strlcpy(cgrp->root->release_agent_path, strstrip(buf),
		sizeof(cgrp->root->release_agent_path));
	spin_unlock(&release_agent_path_lock);
	cgroup_kn_unlock(of->kn);
	return nbytes;
}

static int cgroup_release_agent_show(struct seq_file *seq, void *v)
{
	struct cgroup *cgrp = seq_css(seq)->cgroup;

	spin_lock(&release_agent_path_lock);
	seq_puts(seq, cgrp->root->release_agent_path);
	spin_unlock(&release_agent_path_lock);
	seq_putc(seq, '\n');
	return 0;
}

static int cgroup_sane_behavior_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, "0\n");
	return 0;
}

static u64 cgroup_read_notify_on_release(struct cgroup_subsys_state *css,
					 struct cftype *cft)
{
	return notify_on_release(css->cgroup);
}

static int cgroup_write_notify_on_release(struct cgroup_subsys_state *css,
					  struct cftype *cft, u64 val)
{
	if (val)
		set_bit(CGRP_NOTIFY_ON_RELEASE, &css->cgroup->flags);
	else
		clear_bit(CGRP_NOTIFY_ON_RELEASE, &css->cgroup->flags);
	return 0;
}

static u64 cgroup_clone_children_read(struct cgroup_subsys_state *css,
				      struct cftype *cft)
{
	return test_bit(CGRP_CPUSET_CLONE_CHILDREN, &css->cgroup->flags);
}

static int cgroup_clone_children_write(struct cgroup_subsys_state *css,
				       struct cftype *cft, u64 val)
{
	if (val)
		set_bit(CGRP_CPUSET_CLONE_CHILDREN, &css->cgroup->flags);
	else
		clear_bit(CGRP_CPUSET_CLONE_CHILDREN, &css->cgroup->flags);
	return 0;
}

struct cftype cgroup1_base_files[] = {
	{
		.name = "cgroup.procs",
		.seq_start = cgroup_pidlist_start,
		.seq_next = cgroup_pidlist_next,
		.seq_stop = cgroup_pidlist_stop,
		.seq_show = cgroup_pidlist_show,
		.private = CGROUP_FILE_PROCS,
		.write = cgroup1_procs_write,
	},
	{
		.name = "cgroup.clone_children",
		.read_u64 = cgroup_clone_children_read,
		.write_u64 = cgroup_clone_children_write,
	},
	{
		.name = "cgroup.sane_behavior",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = cgroup_sane_behavior_show,
	},
	{
		.name = "tasks",
		.seq_start = cgroup_pidlist_start,
		.seq_next = cgroup_pidlist_next,
		.seq_stop = cgroup_pidlist_stop,
		.seq_show = cgroup_pidlist_show,
		.private = CGROUP_FILE_TASKS,
		.write = cgroup1_tasks_write,
	},
	{
		.name = "notify_on_release",
		.read_u64 = cgroup_read_notify_on_release,
		.write_u64 = cgroup_write_notify_on_release,
	},
	{
		.name = "release_agent",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = cgroup_release_agent_show,
		.write = cgroup_release_agent_write,
		.max_write_len = PATH_MAX - 1,
	},
	{ }	/* terminate */
};

int proc_cgroupstats_show(struct seq_file *m, void *v)
{
	struct cgroup_subsys *ss;
	int i;

	seq_puts(m, "#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
	/*

	for_each_subsys(ss, i)
		seq_printf(m, "%s\t%d\t%d\t%d\n",
			   ss->legacy_name, ss->root->hierarchy_id,
			   atomic_read(&ss->root->nr_cgrps),
			   cgroup_ssid_enabled(i));

	return 0;
}

int cgroupstats_build(struct cgroupstats *stats, struct dentry *dentry)
{
	struct kernfs_node *kn = kernfs_node_from_dentry(dentry);
	struct cgroup *cgrp;
	struct css_task_iter it;
	struct task_struct *tsk;

	/* it should be kernfs_node belonging to cgroupfs and is a directory */
	if (dentry->d_sb->s_type != &cgroup_fs_type || !kn ||
	    kernfs_type(kn) != KERNFS_DIR)
		return -EINVAL;

	/*
	rcu_read_lock();
	cgrp = rcu_dereference(*(void __rcu __force **)&kn->priv);
	if (!cgrp || !cgroup_tryget(cgrp)) {
		rcu_read_unlock();
		return -ENOENT;
	}
	rcu_read_unlock();

	css_task_iter_start(&cgrp->self, 0, &it);
	while ((tsk = css_task_iter_next(&it))) {
		switch (READ_ONCE(tsk->__state)) {
		case TASK_RUNNING:
			stats->nr_running++;
			break;
		case TASK_INTERRUPTIBLE:
			stats->nr_sleeping++;
			break;
		case TASK_UNINTERRUPTIBLE:
			stats->nr_uninterruptible++;
			break;
		case TASK_STOPPED:
			stats->nr_stopped++;
			break;
		default:
			if (tsk->in_iowait)
				stats->nr_io_wait++;
			break;
		}
	}
	css_task_iter_end(&it);

	cgroup_put(cgrp);
	return 0;
}

void cgroup1_check_for_release(struct cgroup *cgrp)
{
	if (notify_on_release(cgrp) && !cgroup_is_populated(cgrp) &&
	    !css_has_online_children(&cgrp->self) && !cgroup_is_dead(cgrp))
		schedule_work(&cgrp->release_agent_work);
}

void cgroup1_release_agent(struct work_struct *work)
{
	struct cgroup *cgrp =
		container_of(work, struct cgroup, release_agent_work);
	char *pathbuf, *agentbuf;
	char *argv[3], *envp[3];
	int ret;

	/* snoop agent path and exit early if empty */
	if (!cgrp->root->release_agent_path[0])
		return;

	/* prepare argument buffers */
	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	agentbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf || !agentbuf)
		goto out_free;

	spin_lock(&release_agent_path_lock);
	strlcpy(agentbuf, cgrp->root->release_agent_path, PATH_MAX);
	spin_unlock(&release_agent_path_lock);
	if (!agentbuf[0])
		goto out_free;

	ret = cgroup_path_ns(cgrp, pathbuf, PATH_MAX, &init_cgroup_ns);
	if (ret < 0 || ret >= PATH_MAX)
		goto out_free;

	argv[0] = agentbuf;
	argv[1] = pathbuf;
	argv[2] = NULL;

	/* minimal command environment */
	envp[0] = "HOME=/";
	envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[2] = NULL;

	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
out_free:
	kfree(agentbuf);
	kfree(pathbuf);
}

static int cgroup1_rename(struct kernfs_node *kn, struct kernfs_node *new_parent,
			  const char *new_name_str)
{
	struct cgroup *cgrp = kn->priv;
	int ret;

	/* do not accept '\n' to prevent making /proc/<pid>/cgroup unparsable */
	if (strchr(new_name_str, '\n'))
		return -EINVAL;

	if (kernfs_type(kn) != KERNFS_DIR)
		return -ENOTDIR;
	if (kn->parent != new_parent)
		return -EIO;

	/*
	kernfs_break_active_protection(new_parent);
	kernfs_break_active_protection(kn);

	mutex_lock(&cgroup_mutex);

	ret = kernfs_rename(kn, new_parent, new_name_str);
	if (!ret)
		TRACE_CGROUP_PATH(rename, cgrp);

	mutex_unlock(&cgroup_mutex);

	kernfs_unbreak_active_protection(kn);
	kernfs_unbreak_active_protection(new_parent);
	return ret;
}

static int cgroup1_show_options(struct seq_file *seq, struct kernfs_root *kf_root)
{
	struct cgroup_root *root = cgroup_root_from_kf(kf_root);
	struct cgroup_subsys *ss;
	int ssid;

	for_each_subsys(ss, ssid)
		if (root->subsys_mask & (1 << ssid))
			seq_show_option(seq, ss->legacy_name, NULL);
	if (root->flags & CGRP_ROOT_NOPREFIX)
		seq_puts(seq, ",noprefix");
	if (root->flags & CGRP_ROOT_XATTR)
		seq_puts(seq, ",xattr");
	if (root->flags & CGRP_ROOT_CPUSET_V2_MODE)
		seq_puts(seq, ",cpuset_v2_mode");
	if (root->flags & CGRP_ROOT_FAVOR_DYNMODS)
		seq_puts(seq, ",favordynmods");

	spin_lock(&release_agent_path_lock);
	if (strlen(root->release_agent_path))
		seq_show_option(seq, "release_agent",
				root->release_agent_path);
	spin_unlock(&release_agent_path_lock);

	if (test_bit(CGRP_CPUSET_CLONE_CHILDREN, &root->cgrp.flags))
		seq_puts(seq, ",clone_children");
	if (strlen(root->name))
		seq_show_option(seq, "name", root->name);
	return 0;
}

enum cgroup1_param {
	Opt_all,
	Opt_clone_children,
	Opt_cpuset_v2_mode,
	Opt_name,
	Opt_none,
	Opt_noprefix,
	Opt_release_agent,
	Opt_xattr,
	Opt_favordynmods,
	Opt_nofavordynmods,
};

const struct fs_parameter_spec cgroup1_fs_parameters[] = {
	fsparam_flag  ("all",		Opt_all),
	fsparam_flag  ("clone_children", Opt_clone_children),
	fsparam_flag  ("cpuset_v2_mode", Opt_cpuset_v2_mode),
	fsparam_string("name",		Opt_name),
	fsparam_flag  ("none",		Opt_none),
	fsparam_flag  ("noprefix",	Opt_noprefix),
	fsparam_string("release_agent",	Opt_release_agent),
	fsparam_flag  ("xattr",		Opt_xattr),
	fsparam_flag  ("favordynmods",	Opt_favordynmods),
	fsparam_flag  ("nofavordynmods", Opt_nofavordynmods),
	{}
};

int cgroup1_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct cgroup_fs_context *ctx = cgroup_fc2context(fc);
	struct cgroup_subsys *ss;
	struct fs_parse_result result;
	int opt, i;

	opt = fs_parse(fc, cgroup1_fs_parameters, param, &result);
	if (opt == -ENOPARAM) {
		int ret;

		ret = vfs_parse_fs_param_source(fc, param);
		if (ret != -ENOPARAM)
			return ret;
		for_each_subsys(ss, i) {
			if (strcmp(param->key, ss->legacy_name))
				continue;
			if (!cgroup_ssid_enabled(i) || cgroup1_ssid_disabled(i))
				return invalfc(fc, "Disabled controller '%s'",
					       param->key);
			ctx->subsys_mask |= (1 << i);
			return 0;
		}
		return invalfc(fc, "Unknown subsys name '%s'", param->key);
	}
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_none:
		/* Explicitly have no subsystems */
		ctx->none = true;
		break;
	case Opt_all:
		ctx->all_ss = true;
		break;
	case Opt_noprefix:
		ctx->flags |= CGRP_ROOT_NOPREFIX;
		break;
	case Opt_clone_children:
		ctx->cpuset_clone_children = true;
		break;
	case Opt_cpuset_v2_mode:
		ctx->flags |= CGRP_ROOT_CPUSET_V2_MODE;
		break;
	case Opt_xattr:
		ctx->flags |= CGRP_ROOT_XATTR;
		break;
	case Opt_favordynmods:
		ctx->flags |= CGRP_ROOT_FAVOR_DYNMODS;
		break;
	case Opt_nofavordynmods:
		ctx->flags &= ~CGRP_ROOT_FAVOR_DYNMODS;
		break;
	case Opt_release_agent:
		/* Specifying two release agents is forbidden */
		if (ctx->release_agent)
			return invalfc(fc, "release_agent respecified");
		/*
		if ((fc->user_ns != &init_user_ns) || !capable(CAP_SYS_ADMIN))
			return invalfc(fc, "Setting release_agent not allowed");
		ctx->release_agent = param->string;
		param->string = NULL;
		break;
	case Opt_name:
		/* blocked by boot param? */
		if (cgroup_no_v1_named)
			return -ENOENT;
		/* Can't specify an empty name */
		if (!param->size)
			return invalfc(fc, "Empty name");
		if (param->size > MAX_CGROUP_ROOT_NAMELEN - 1)
			return invalfc(fc, "Name too long");
		/* Must match [\w.-]+ */
		for (i = 0; i < param->size; i++) {
			char c = param->string[i];
			if (isalnum(c))
				continue;
			if ((c == '.') || (c == '-') || (c == '_'))
				continue;
			return invalfc(fc, "Invalid name");
		}
		/* Specifying two names is forbidden */
		if (ctx->name)
			return invalfc(fc, "name respecified");
		ctx->name = param->string;
		param->string = NULL;
		break;
	}
	return 0;
}

static int check_cgroupfs_options(struct fs_context *fc)
{
	struct cgroup_fs_context *ctx = cgroup_fc2context(fc);
	u16 mask = U16_MAX;
	u16 enabled = 0;
	struct cgroup_subsys *ss;
	int i;

#ifdef CONFIG_CPUSETS
	mask = ~((u16)1 << cpuset_cgrp_id);
#endif
	for_each_subsys(ss, i)
		if (cgroup_ssid_enabled(i) && !cgroup1_ssid_disabled(i))
			enabled |= 1 << i;

	ctx->subsys_mask &= enabled;

	/*
	if (!ctx->subsys_mask && !ctx->none && !ctx->name)
		ctx->all_ss = true;

	if (ctx->all_ss) {
		/* Mutually exclusive option 'all' + subsystem name */
		if (ctx->subsys_mask)
			return invalfc(fc, "subsys name conflicts with all");
		/* 'all' => select all the subsystems */
		ctx->subsys_mask = enabled;
	}

	/*
	if (!ctx->subsys_mask && !ctx->name)
		return invalfc(fc, "Need name or subsystem set");

	/*
	if ((ctx->flags & CGRP_ROOT_NOPREFIX) && (ctx->subsys_mask & mask))
		return invalfc(fc, "noprefix used incorrectly");

	/* Can't specify "none" and some subsystems */
	if (ctx->subsys_mask && ctx->none)
		return invalfc(fc, "none used incorrectly");

	return 0;
}

int cgroup1_reconfigure(struct fs_context *fc)
{
	struct cgroup_fs_context *ctx = cgroup_fc2context(fc);
	struct kernfs_root *kf_root = kernfs_root_from_sb(fc->root->d_sb);
	struct cgroup_root *root = cgroup_root_from_kf(kf_root);
	int ret = 0;
	u16 added_mask, removed_mask;

	cgroup_lock_and_drain_offline(&cgrp_dfl_root.cgrp);

	/* See what subsystems are wanted */
	ret = check_cgroupfs_options(fc);
	if (ret)
		goto out_unlock;

	if (ctx->subsys_mask != root->subsys_mask || ctx->release_agent)
		pr_warn("option changes via remount are deprecated (pid=%d comm=%s)\n",
			task_tgid_nr(current), current->comm);

	added_mask = ctx->subsys_mask & ~root->subsys_mask;
	removed_mask = root->subsys_mask & ~ctx->subsys_mask;

	/* Don't allow flags or name to change at remount */
	if ((ctx->flags ^ root->flags) ||
	    (ctx->name && strcmp(ctx->name, root->name))) {
		errorfc(fc, "option or name mismatch, new: 0x%x \"%s\", old: 0x%x \"%s\"",
		       ctx->flags, ctx->name ?: "", root->flags, root->name);
		ret = -EINVAL;
		goto out_unlock;
	}

	/* remounting is not allowed for populated hierarchies */
	if (!list_empty(&root->cgrp.self.children)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = rebind_subsystems(root, added_mask);
	if (ret)
		goto out_unlock;

	WARN_ON(rebind_subsystems(&cgrp_dfl_root, removed_mask));

	if (ctx->release_agent) {
		spin_lock(&release_agent_path_lock);
		strcpy(root->release_agent_path, ctx->release_agent);
		spin_unlock(&release_agent_path_lock);
	}

	trace_cgroup_remount(root);

 out_unlock:
	mutex_unlock(&cgroup_mutex);
	return ret;
}

struct kernfs_syscall_ops cgroup1_kf_syscall_ops = {
	.rename			= cgroup1_rename,
	.show_options		= cgroup1_show_options,
	.mkdir			= cgroup_mkdir,
	.rmdir			= cgroup_rmdir,
	.show_path		= cgroup_show_path,
};

static int cgroup1_root_to_use(struct fs_context *fc)
{
	struct cgroup_fs_context *ctx = cgroup_fc2context(fc);
	struct cgroup_root *root;
	struct cgroup_subsys *ss;
	int i, ret;

	/* First find the desired set of subsystems */
	ret = check_cgroupfs_options(fc);
	if (ret)
		return ret;

	/*
	for_each_subsys(ss, i) {
		if (!(ctx->subsys_mask & (1 << i)) ||
		    ss->root == &cgrp_dfl_root)
			continue;

		if (!percpu_ref_tryget_live(&ss->root->cgrp.self.refcnt))
			return 1;	/* restart */
		cgroup_put(&ss->root->cgrp);
	}

	for_each_root(root) {
		bool name_match = false;

		if (root == &cgrp_dfl_root)
			continue;

		/*
		if (ctx->name) {
			if (strcmp(ctx->name, root->name))
				continue;
			name_match = true;
		}

		/*
		if ((ctx->subsys_mask || ctx->none) &&
		    (ctx->subsys_mask != root->subsys_mask)) {
			if (!name_match)
				continue;
			return -EBUSY;
		}

		if (root->flags ^ ctx->flags)
			pr_warn("new mount options do not match the existing superblock, will be ignored\n");

		ctx->root = root;
		return 0;
	}

	/*
	if (!ctx->subsys_mask && !ctx->none)
		return invalfc(fc, "No subsys list or none specified");

	/* Hierarchies may only be created in the initial cgroup namespace. */
	if (ctx->ns != &init_cgroup_ns)
		return -EPERM;

	root = kzalloc(sizeof(*root), GFP_KERNEL);
	if (!root)
		return -ENOMEM;

	ctx->root = root;
	init_cgroup_root(ctx);

	ret = cgroup_setup_root(root, ctx->subsys_mask);
	if (!ret)
		cgroup_favor_dynmods(root, ctx->flags & CGRP_ROOT_FAVOR_DYNMODS);
	else
		cgroup_free_root(root);

	return ret;
}

int cgroup1_get_tree(struct fs_context *fc)
{
	struct cgroup_fs_context *ctx = cgroup_fc2context(fc);
	int ret;

	/* Check if the caller has permission to mount. */
	if (!ns_capable(ctx->ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	cgroup_lock_and_drain_offline(&cgrp_dfl_root.cgrp);

	ret = cgroup1_root_to_use(fc);
	if (!ret && !percpu_ref_tryget_live(&ctx->root->cgrp.self.refcnt))
		ret = 1;	/* restart */

	mutex_unlock(&cgroup_mutex);

	if (!ret)
		ret = cgroup_do_get_tree(fc);

	if (!ret && percpu_ref_is_dying(&ctx->root->cgrp.self.refcnt)) {
		fc_drop_locked(fc);
		ret = 1;
	}

	if (unlikely(ret > 0)) {
		msleep(10);
		return restart_syscall();
	}
	return ret;
}

static int __init cgroup1_wq_init(void)
{
	/*
	cgroup_pidlist_destroy_wq = alloc_workqueue("cgroup_pidlist_destroy",
						    0, 1);
	BUG_ON(!cgroup_pidlist_destroy_wq);
	return 0;
}
core_initcall(cgroup1_wq_init);

static int __init cgroup_no_v1(char *str)
{
	struct cgroup_subsys *ss;
	char *token;
	int i;

	while ((token = strsep(&str, ",")) != NULL) {
		if (!*token)
			continue;

		if (!strcmp(token, "all")) {
			cgroup_no_v1_mask = U16_MAX;
			continue;
		}

		if (!strcmp(token, "named")) {
			cgroup_no_v1_named = true;
			continue;
		}

		for_each_subsys(ss, i) {
			if (strcmp(token, ss->name) &&
			    strcmp(token, ss->legacy_name))
				continue;

			cgroup_no_v1_mask |= 1 << i;
		}
	}
	return 1;
}
__setup("cgroup_no_v1=", cgroup_no_v1);
