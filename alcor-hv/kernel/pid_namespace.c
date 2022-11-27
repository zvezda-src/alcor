
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/acct.h>
#include <linux/slab.h>
#include <linux/proc_ns.h>
#include <linux/reboot.h>
#include <linux/export.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/idr.h>

static DEFINE_MUTEX(pid_caches_mutex);
static struct kmem_cache *pid_ns_cachep;
static struct kmem_cache *pid_cache[MAX_PID_NS_LEVEL];


static struct kmem_cache *create_pid_cachep(unsigned int level)
{
	/* Level 0 is init_pid_ns.pid_cachep */
	struct kmem_cache **pkc = &pid_cache[level - 1];
	struct kmem_cache *kc;
	char name[4 + 10 + 1];
	unsigned int len;

	kc = READ_ONCE(*pkc);
	if (kc)
		return kc;

	snprintf(name, sizeof(name), "pid_%u", level + 1);
	len = sizeof(struct pid) + level * sizeof(struct upid);
	mutex_lock(&pid_caches_mutex);
	/* Name collision forces to do allocation under mutex. */
	if (!*pkc)
		*pkc = kmem_cache_create(name, len, 0,
					 SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT, NULL);
	mutex_unlock(&pid_caches_mutex);
	/* current can fail, but someone else can succeed. */
	return READ_ONCE(*pkc);
}

static struct ucounts *inc_pid_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_PID_NAMESPACES);
}

static void dec_pid_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_PID_NAMESPACES);
}

static struct pid_namespace *create_pid_namespace(struct user_namespace *user_ns,
	struct pid_namespace *parent_pid_ns)
{
	struct pid_namespace *ns;
	unsigned int level = parent_pid_ns->level + 1;
	struct ucounts *ucounts;
	int err;

	err = -EINVAL;
	if (!in_userns(parent_pid_ns->user_ns, user_ns))
		goto out;

	err = -ENOSPC;
	if (level > MAX_PID_NS_LEVEL)
		goto out;
	ucounts = inc_pid_namespaces(user_ns);
	if (!ucounts)
		goto out;

	err = -ENOMEM;
	ns = kmem_cache_zalloc(pid_ns_cachep, GFP_KERNEL);
	if (ns == NULL)
		goto out_dec;

	idr_init(&ns->idr);

	ns->pid_cachep = create_pid_cachep(level);
	if (ns->pid_cachep == NULL)
		goto out_free_idr;

	err = ns_alloc_inum(&ns->ns);
	if (err)
		goto out_free_idr;
	ns->ns.ops = &pidns_operations;

	refcount_set(&ns->ns.count, 1);
	ns->level = level;
	ns->parent = get_pid_ns(parent_pid_ns);
	ns->user_ns = get_user_ns(user_ns);
	ns->ucounts = ucounts;
	ns->pid_allocated = PIDNS_ADDING;

	return ns;

out_free_idr:
	idr_destroy(&ns->idr);
	kmem_cache_free(pid_ns_cachep, ns);
out_dec:
	dec_pid_namespaces(ucounts);
out:
	return ERR_PTR(err);
}

static void delayed_free_pidns(struct rcu_head *p)
{
	struct pid_namespace *ns = container_of(p, struct pid_namespace, rcu);

	dec_pid_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);

	kmem_cache_free(pid_ns_cachep, ns);
}

static void destroy_pid_namespace(struct pid_namespace *ns)
{
	ns_free_inum(&ns->ns);

	idr_destroy(&ns->idr);
	call_rcu(&ns->rcu, delayed_free_pidns);
}

struct pid_namespace *copy_pid_ns(unsigned long flags,
	struct user_namespace *user_ns, struct pid_namespace *old_ns)
{
	if (!(flags & CLONE_NEWPID))
		return get_pid_ns(old_ns);
	if (task_active_pid_ns(current) != old_ns)
		return ERR_PTR(-EINVAL);
	return create_pid_namespace(user_ns, old_ns);
}

void put_pid_ns(struct pid_namespace *ns)
{
	struct pid_namespace *parent;

	while (ns != &init_pid_ns) {
		parent = ns->parent;
		if (!refcount_dec_and_test(&ns->ns.count))
			break;
		destroy_pid_namespace(ns);
		ns = parent;
	}
}
EXPORT_SYMBOL_GPL(put_pid_ns);

void zap_pid_ns_processes(struct pid_namespace *pid_ns)
{
	int nr;
	int rc;
	struct task_struct *task, *me = current;
	int init_pids = thread_group_leader(me) ? 1 : 2;
	struct pid *pid;

	/* Don't allow any more processes into the pid namespace */
	disable_pid_allocation(pid_ns);

	/*
	spin_lock_irq(&me->sighand->siglock);
	me->sighand->action[SIGCHLD - 1].sa.sa_handler = SIG_IGN;
	spin_unlock_irq(&me->sighand->siglock);

	/*
	rcu_read_lock();
	read_lock(&tasklist_lock);
	nr = 2;
	idr_for_each_entry_continue(&pid_ns->idr, pid, nr) {
		task = pid_task(pid, PIDTYPE_PID);
		if (task && !__fatal_signal_pending(task))
			group_send_sig_info(SIGKILL, SEND_SIG_PRIV, task, PIDTYPE_MAX);
	}
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	/*
	do {
		clear_thread_flag(TIF_SIGPENDING);
		rc = kernel_wait4(-1, NULL, __WALL, NULL);
	} while (rc != -ECHILD);

	/*
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (pid_ns->pid_allocated == init_pids)
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);

	if (pid_ns->reboot)
		current->signal->group_exit_code = pid_ns->reboot;

	acct_exit_ns(pid_ns);
	return;
}

#ifdef CONFIG_CHECKPOINT_RESTORE
static int pid_ns_ctl_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	struct ctl_table tmp = *table;
	int ret, next;

	if (write && !checkpoint_restore_ns_capable(pid_ns->user_ns))
		return -EPERM;

	/*

	next = idr_get_cursor(&pid_ns->idr) - 1;

	tmp.data = &next;
	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (!ret && write)
		idr_set_cursor(&pid_ns->idr, next + 1);

	return ret;
}

extern int pid_max;
static struct ctl_table pid_ns_ctl_table[] = {
	{
		.procname = "ns_last_pid",
		.maxlen = sizeof(int),
		.mode = 0666, /* permissions are checked in the handler */
		.proc_handler = pid_ns_ctl_handler,
		.extra1 = SYSCTL_ZERO,
		.extra2 = &pid_max,
	},
	{ }
};
static struct ctl_path kern_path[] = { { .procname = "kernel", }, { } };
#endif	/* CONFIG_CHECKPOINT_RESTORE */

int reboot_pid_ns(struct pid_namespace *pid_ns, int cmd)
{
	if (pid_ns == &init_pid_ns)
		return 0;

	switch (cmd) {
	case LINUX_REBOOT_CMD_RESTART2:
	case LINUX_REBOOT_CMD_RESTART:
		pid_ns->reboot = SIGHUP;
		break;

	case LINUX_REBOOT_CMD_POWER_OFF:
	case LINUX_REBOOT_CMD_HALT:
		pid_ns->reboot = SIGINT;
		break;
	default:
		return -EINVAL;
	}

	read_lock(&tasklist_lock);
	send_sig(SIGKILL, pid_ns->child_reaper, 1);
	read_unlock(&tasklist_lock);

	do_exit(0);

	/* Not reached */
	return 0;
}

static inline struct pid_namespace *to_pid_ns(struct ns_common *ns)
{
	return container_of(ns, struct pid_namespace, ns);
}

static struct ns_common *pidns_get(struct task_struct *task)
{
	struct pid_namespace *ns;

	rcu_read_lock();
	ns = task_active_pid_ns(task);
	if (ns)
		get_pid_ns(ns);
	rcu_read_unlock();

	return ns ? &ns->ns : NULL;
}

static struct ns_common *pidns_for_children_get(struct task_struct *task)
{
	struct pid_namespace *ns = NULL;

	task_lock(task);
	if (task->nsproxy) {
		ns = task->nsproxy->pid_ns_for_children;
		get_pid_ns(ns);
	}
	task_unlock(task);

	if (ns) {
		read_lock(&tasklist_lock);
		if (!ns->child_reaper) {
			put_pid_ns(ns);
			ns = NULL;
		}
		read_unlock(&tasklist_lock);
	}

	return ns ? &ns->ns : NULL;
}

static void pidns_put(struct ns_common *ns)
{
	put_pid_ns(to_pid_ns(ns));
}

static int pidns_install(struct nsset *nsset, struct ns_common *ns)
{
	struct nsproxy *nsproxy = nsset->nsproxy;
	struct pid_namespace *active = task_active_pid_ns(current);
	struct pid_namespace *ancestor, *new = to_pid_ns(ns);

	if (!ns_capable(new->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/*
	if (new->level < active->level)
		return -EINVAL;

	ancestor = new;
	while (ancestor->level > active->level)
		ancestor = ancestor->parent;
	if (ancestor != active)
		return -EINVAL;

	put_pid_ns(nsproxy->pid_ns_for_children);
	nsproxy->pid_ns_for_children = get_pid_ns(new);
	return 0;
}

static struct ns_common *pidns_get_parent(struct ns_common *ns)
{
	struct pid_namespace *active = task_active_pid_ns(current);
	struct pid_namespace *pid_ns, *p;

	/* See if the parent is in the current namespace */
	pid_ns = p = to_pid_ns(ns)->parent;
	for (;;) {
		if (!p)
			return ERR_PTR(-EPERM);
		if (p == active)
			break;
		p = p->parent;
	}

	return &get_pid_ns(pid_ns)->ns;
}

static struct user_namespace *pidns_owner(struct ns_common *ns)
{
	return to_pid_ns(ns)->user_ns;
}

const struct proc_ns_operations pidns_operations = {
	.name		= "pid",
	.type		= CLONE_NEWPID,
	.get		= pidns_get,
	.put		= pidns_put,
	.install	= pidns_install,
	.owner		= pidns_owner,
	.get_parent	= pidns_get_parent,
};

const struct proc_ns_operations pidns_for_children_operations = {
	.name		= "pid_for_children",
	.real_ns_name	= "pid",
	.type		= CLONE_NEWPID,
	.get		= pidns_for_children_get,
	.put		= pidns_put,
	.install	= pidns_install,
	.owner		= pidns_owner,
	.get_parent	= pidns_get_parent,
};

static __init int pid_namespaces_init(void)
{
	pid_ns_cachep = KMEM_CACHE(pid_namespace, SLAB_PANIC | SLAB_ACCOUNT);

#ifdef CONFIG_CHECKPOINT_RESTORE
	register_sysctl_paths(kern_path, pid_ns_ctl_table);
#endif
	return 0;
}

__initcall(pid_namespaces_init);
