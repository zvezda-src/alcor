
struct sched_core_cookie {
	refcount_t refcnt;
};

static unsigned long sched_core_alloc_cookie(void)
{
	struct sched_core_cookie *ck = kmalloc(sizeof(*ck), GFP_KERNEL);
	if (!ck)
		return 0;

	refcount_set(&ck->refcnt, 1);
	sched_core_get();

	return (unsigned long)ck;
}

static void sched_core_put_cookie(unsigned long cookie)
{
	struct sched_core_cookie *ptr = (void *)cookie;

	if (ptr && refcount_dec_and_test(&ptr->refcnt)) {
		kfree(ptr);
		sched_core_put();
	}
}

static unsigned long sched_core_get_cookie(unsigned long cookie)
{
	struct sched_core_cookie *ptr = (void *)cookie;

	if (ptr)
		refcount_inc(&ptr->refcnt);

	return cookie;
}

static unsigned long sched_core_update_cookie(struct task_struct *p,
					      unsigned long cookie)
{
	unsigned long old_cookie;
	struct rq_flags rf;
	struct rq *rq;

	rq = task_rq_lock(p, &rf);

	/*
	SCHED_WARN_ON((p->core_cookie || cookie) && !sched_core_enabled(rq));

	if (sched_core_enqueued(p))
		sched_core_dequeue(rq, p, DEQUEUE_SAVE);

	old_cookie = p->core_cookie;
	p->core_cookie = cookie;

	/*
	if (cookie && task_on_rq_queued(p))
		sched_core_enqueue(rq, p);

	/*
	if (task_running(rq, p))
		resched_curr(rq);

	task_rq_unlock(rq, p, &rf);

	return old_cookie;
}

static unsigned long sched_core_clone_cookie(struct task_struct *p)
{
	unsigned long cookie, flags;

	raw_spin_lock_irqsave(&p->pi_lock, flags);
	cookie = sched_core_get_cookie(p->core_cookie);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	return cookie;
}

void sched_core_fork(struct task_struct *p)
{
	RB_CLEAR_NODE(&p->core_node);
	p->core_cookie = sched_core_clone_cookie(current);
}

void sched_core_free(struct task_struct *p)
{
	sched_core_put_cookie(p->core_cookie);
}

static void __sched_core_set(struct task_struct *p, unsigned long cookie)
{
	cookie = sched_core_get_cookie(cookie);
	cookie = sched_core_update_cookie(p, cookie);
	sched_core_put_cookie(cookie);
}

int sched_core_share_pid(unsigned int cmd, pid_t pid, enum pid_type type,
			 unsigned long uaddr)
{
	unsigned long cookie = 0, id = 0;
	struct task_struct *task, *p;
	struct pid *grp;
	int err = 0;

	if (!static_branch_likely(&sched_smt_present))
		return -ENODEV;

	BUILD_BUG_ON(PR_SCHED_CORE_SCOPE_THREAD != PIDTYPE_PID);
	BUILD_BUG_ON(PR_SCHED_CORE_SCOPE_THREAD_GROUP != PIDTYPE_TGID);
	BUILD_BUG_ON(PR_SCHED_CORE_SCOPE_PROCESS_GROUP != PIDTYPE_PGID);

	if (type > PIDTYPE_PGID || cmd >= PR_SCHED_CORE_MAX || pid < 0 ||
	    (cmd != PR_SCHED_CORE_GET && uaddr))
		return -EINVAL;

	rcu_read_lock();
	if (pid == 0) {
		task = current;
	} else {
		task = find_task_by_vpid(pid);
		if (!task) {
			rcu_read_unlock();
			return -ESRCH;
		}
	}
	get_task_struct(task);
	rcu_read_unlock();

	/*
	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
		err = -EPERM;
		goto out;
	}

	switch (cmd) {
	case PR_SCHED_CORE_GET:
		if (type != PIDTYPE_PID || uaddr & 7) {
			err = -EINVAL;
			goto out;
		}
		cookie = sched_core_clone_cookie(task);
		if (cookie) {
			/* XXX improve ? */
			ptr_to_hashval((void *)cookie, &id);
		}
		err = put_user(id, (u64 __user *)uaddr);
		goto out;

	case PR_SCHED_CORE_CREATE:
		cookie = sched_core_alloc_cookie();
		if (!cookie) {
			err = -ENOMEM;
			goto out;
		}
		break;

	case PR_SCHED_CORE_SHARE_TO:
		cookie = sched_core_clone_cookie(current);
		break;

	case PR_SCHED_CORE_SHARE_FROM:
		if (type != PIDTYPE_PID) {
			err = -EINVAL;
			goto out;
		}
		cookie = sched_core_clone_cookie(task);
		__sched_core_set(current, cookie);
		goto out;

	default:
		err = -EINVAL;
		goto out;
	};

	if (type == PIDTYPE_PID) {
		__sched_core_set(task, cookie);
		goto out;
	}

	read_lock(&tasklist_lock);
	grp = task_pid_type(task, type);

	do_each_pid_thread(grp, type, p) {
		if (!ptrace_may_access(p, PTRACE_MODE_READ_REALCREDS)) {
			err = -EPERM;
			goto out_tasklist;
		}
	} while_each_pid_thread(grp, type, p);

	do_each_pid_thread(grp, type, p) {
		__sched_core_set(p, cookie);
	} while_each_pid_thread(grp, type, p);
out_tasklist:
	read_unlock(&tasklist_lock);

out:
	sched_core_put_cookie(cookie);
	put_task_struct(task);
	return err;
}

#ifdef CONFIG_SCHEDSTATS

void __sched_core_account_forceidle(struct rq *rq)
{
	const struct cpumask *smt_mask = cpu_smt_mask(cpu_of(rq));
	u64 delta, now = rq_clock(rq->core);
	struct rq *rq_i;
	struct task_struct *p;
	int i;

	lockdep_assert_rq_held(rq);

	WARN_ON_ONCE(!rq->core->core_forceidle_count);

	if (rq->core->core_forceidle_start == 0)
		return;

	delta = now - rq->core->core_forceidle_start;
	if (unlikely((s64)delta <= 0))
		return;

	rq->core->core_forceidle_start = now;

	if (WARN_ON_ONCE(!rq->core->core_forceidle_occupation)) {
		/* can't be forced idle without a running task */
	} else if (rq->core->core_forceidle_count > 1 ||
		   rq->core->core_forceidle_occupation > 1) {
		/*
		delta *= rq->core->core_forceidle_count;
		delta = div_u64(delta, rq->core->core_forceidle_occupation);
	}

	for_each_cpu(i, smt_mask) {
		rq_i = cpu_rq(i);
		p = rq_i->core_pick ?: rq_i->curr;

		if (p == rq_i->idle)
			continue;

		/*
		__account_forceidle_time(p, delta);
	}
}

void __sched_core_tick(struct rq *rq)
{
	if (!rq->core->core_forceidle_count)
		return;

	if (rq != rq->core)
		update_rq_clock(rq->core);

	__sched_core_account_forceidle(rq);
}

#endif /* CONFIG_SCHEDSTATS */
