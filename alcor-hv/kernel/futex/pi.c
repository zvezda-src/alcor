
#include <linux/slab.h>
#include <linux/sched/task.h>

#include "futex.h"
#include "../locking/rtmutex_common.h"

int refill_pi_state_cache(void)
{
	struct futex_pi_state *pi_state;

	if (likely(current->pi_state_cache))
		return 0;

	pi_state = kzalloc(sizeof(*pi_state), GFP_KERNEL);

	if (!pi_state)
		return -ENOMEM;

	INIT_LIST_HEAD(&pi_state->list);
	/* pi_mutex gets initialized later */
	pi_state->owner = NULL;
	refcount_set(&pi_state->refcount, 1);
	pi_state->key = FUTEX_KEY_INIT;

	current->pi_state_cache = pi_state;

	return 0;
}

static struct futex_pi_state *alloc_pi_state(void)
{
	struct futex_pi_state *pi_state = current->pi_state_cache;

	WARN_ON(!pi_state);
	current->pi_state_cache = NULL;

	return pi_state;
}

static void pi_state_update_owner(struct futex_pi_state *pi_state,
				  struct task_struct *new_owner)
{
	struct task_struct *old_owner = pi_state->owner;

	lockdep_assert_held(&pi_state->pi_mutex.wait_lock);

	if (old_owner) {
		raw_spin_lock(&old_owner->pi_lock);
		WARN_ON(list_empty(&pi_state->list));
		list_del_init(&pi_state->list);
		raw_spin_unlock(&old_owner->pi_lock);
	}

	if (new_owner) {
		raw_spin_lock(&new_owner->pi_lock);
		WARN_ON(!list_empty(&pi_state->list));
		list_add(&pi_state->list, &new_owner->pi_state_list);
		pi_state->owner = new_owner;
		raw_spin_unlock(&new_owner->pi_lock);
	}
}

void get_pi_state(struct futex_pi_state *pi_state)
{
	WARN_ON_ONCE(!refcount_inc_not_zero(&pi_state->refcount));
}

void put_pi_state(struct futex_pi_state *pi_state)
{
	if (!pi_state)
		return;

	if (!refcount_dec_and_test(&pi_state->refcount))
		return;

	/*
	if (pi_state->owner) {
		unsigned long flags;

		raw_spin_lock_irqsave(&pi_state->pi_mutex.wait_lock, flags);
		pi_state_update_owner(pi_state, NULL);
		rt_mutex_proxy_unlock(&pi_state->pi_mutex);
		raw_spin_unlock_irqrestore(&pi_state->pi_mutex.wait_lock, flags);
	}

	if (current->pi_state_cache) {
		kfree(pi_state);
	} else {
		/*
		pi_state->owner = NULL;
		refcount_set(&pi_state->refcount, 1);
		current->pi_state_cache = pi_state;
	}
}


static int attach_to_pi_state(u32 __user *uaddr, u32 uval,
			      struct futex_pi_state *pi_state,
			      struct futex_pi_state **ps)
{
	pid_t pid = uval & FUTEX_TID_MASK;
	u32 uval2;
	int ret;

	/*
	if (unlikely(!pi_state))
		return -EINVAL;

	/*
	WARN_ON(!refcount_read(&pi_state->refcount));

	/*
	raw_spin_lock_irq(&pi_state->pi_mutex.wait_lock);

	/*
	if (futex_get_value_locked(&uval2, uaddr))
		goto out_efault;

	if (uval != uval2)
		goto out_eagain;

	/*
	if (uval & FUTEX_OWNER_DIED) {
		/*
		if (!pi_state->owner) {
			/*
			if (pid)
				goto out_einval;
			/*
			goto out_attach;
		}

		/*
		if (!pid)
			goto out_attach;
	} else {
		/*
		if (!pi_state->owner)
			goto out_einval;
	}

	/*
	if (pid != task_pid_vnr(pi_state->owner))
		goto out_einval;

out_attach:
	get_pi_state(pi_state);
	raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);
	return 0;

out_einval:
	ret = -EINVAL;
	goto out_error;

out_eagain:
	ret = -EAGAIN;
	goto out_error;

out_efault:
	ret = -EFAULT;
	goto out_error;

out_error:
	raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);
	return ret;
}

static int handle_exit_race(u32 __user *uaddr, u32 uval,
			    struct task_struct *tsk)
{
	u32 uval2;

	/*
	if (tsk && tsk->futex_state != FUTEX_STATE_DEAD)
		return -EBUSY;

	/*
	if (futex_get_value_locked(&uval2, uaddr))
		return -EFAULT;

	/* If the user space value has changed, try again. */
	if (uval2 != uval)
		return -EAGAIN;

	/*
	return -ESRCH;
}

static void __attach_to_pi_owner(struct task_struct *p, union futex_key *key,
				 struct futex_pi_state **ps)
{
	/*
	struct futex_pi_state *pi_state = alloc_pi_state();

	/*
	rt_mutex_init_proxy_locked(&pi_state->pi_mutex, p);

	/* Store the key for possible exit cleanups: */
	pi_state->key = *key;

	WARN_ON(!list_empty(&pi_state->list));
	list_add(&pi_state->list, &p->pi_state_list);
	/*
	pi_state->owner = p;

}
static int attach_to_pi_owner(u32 __user *uaddr, u32 uval, union futex_key *key,
			      struct futex_pi_state **ps,
			      struct task_struct **exiting)
{
	pid_t pid = uval & FUTEX_TID_MASK;
	struct task_struct *p;

	/*
	if (!pid)
		return -EAGAIN;
	p = find_get_task_by_vpid(pid);
	if (!p)
		return handle_exit_race(uaddr, uval, NULL);

	if (unlikely(p->flags & PF_KTHREAD)) {
		put_task_struct(p);
		return -EPERM;
	}

	/*
	raw_spin_lock_irq(&p->pi_lock);
	if (unlikely(p->futex_state != FUTEX_STATE_OK)) {
		/*
		int ret = handle_exit_race(uaddr, uval, p);

		raw_spin_unlock_irq(&p->pi_lock);
		/*
		if (ret == -EBUSY)
			*exiting = p;
		else
			put_task_struct(p);
		return ret;
	}

	__attach_to_pi_owner(p, key, ps);
	raw_spin_unlock_irq(&p->pi_lock);

	put_task_struct(p);

	return 0;
}

static int lock_pi_update_atomic(u32 __user *uaddr, u32 uval, u32 newval)
{
	int err;
	u32 curval;

	if (unlikely(should_fail_futex(true)))
		return -EFAULT;

	err = futex_cmpxchg_value_locked(&curval, uaddr, uval, newval);
	if (unlikely(err))
		return err;

	/* If user space value changed, let the caller retry */
	return curval != uval ? -EAGAIN : 0;
}

int futex_lock_pi_atomic(u32 __user *uaddr, struct futex_hash_bucket *hb,
			 union futex_key *key,
			 struct futex_pi_state **ps,
			 struct task_struct *task,
			 struct task_struct **exiting,
			 int set_waiters)
{
	u32 uval, newval, vpid = task_pid_vnr(task);
	struct futex_q *top_waiter;
	int ret;

	/*
	if (futex_get_value_locked(&uval, uaddr))
		return -EFAULT;

	if (unlikely(should_fail_futex(true)))
		return -EFAULT;

	/*
	if ((unlikely((uval & FUTEX_TID_MASK) == vpid)))
		return -EDEADLK;

	if ((unlikely(should_fail_futex(true))))
		return -EDEADLK;

	/*
	top_waiter = futex_top_waiter(hb, key);
	if (top_waiter)
		return attach_to_pi_state(uaddr, uval, top_waiter->pi_state, ps);

	/*
	if (!(uval & FUTEX_TID_MASK)) {
		/*
		newval = uval & FUTEX_OWNER_DIED;
		newval |= vpid;

		/* The futex requeue_pi code can enforce the waiters bit */
		if (set_waiters)
			newval |= FUTEX_WAITERS;

		ret = lock_pi_update_atomic(uaddr, uval, newval);
		if (ret)
			return ret;

		/*
		if (set_waiters) {
			raw_spin_lock_irq(&task->pi_lock);
			__attach_to_pi_owner(task, key, ps);
			raw_spin_unlock_irq(&task->pi_lock);
		}
		return 1;
	}

	/*
	newval = uval | FUTEX_WAITERS;
	ret = lock_pi_update_atomic(uaddr, uval, newval);
	if (ret)
		return ret;
	/*
	return attach_to_pi_owner(uaddr, newval, key, ps, exiting);
}

static int wake_futex_pi(u32 __user *uaddr, u32 uval, struct futex_pi_state *pi_state)
{
	struct rt_mutex_waiter *top_waiter;
	struct task_struct *new_owner;
	bool postunlock = false;
	DEFINE_RT_WAKE_Q(wqh);
	u32 curval, newval;
	int ret = 0;

	top_waiter = rt_mutex_top_waiter(&pi_state->pi_mutex);
	if (WARN_ON_ONCE(!top_waiter)) {
		/*
		ret = -EAGAIN;
		goto out_unlock;
	}

	new_owner = top_waiter->task;

	/*
	newval = FUTEX_WAITERS | task_pid_vnr(new_owner);

	if (unlikely(should_fail_futex(true))) {
		ret = -EFAULT;
		goto out_unlock;
	}

	ret = futex_cmpxchg_value_locked(&curval, uaddr, uval, newval);
	if (!ret && (curval != uval)) {
		/*
		if ((FUTEX_TID_MASK & curval) == uval)
			ret = -EAGAIN;
		else
			ret = -EINVAL;
	}

	if (!ret) {
		/*
		pi_state_update_owner(pi_state, new_owner);
		postunlock = __rt_mutex_futex_unlock(&pi_state->pi_mutex, &wqh);
	}

out_unlock:
	raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);

	if (postunlock)
		rt_mutex_postunlock(&wqh);

	return ret;
}

static int __fixup_pi_state_owner(u32 __user *uaddr, struct futex_q *q,
				  struct task_struct *argowner)
{
	struct futex_pi_state *pi_state = q->pi_state;
	struct task_struct *oldowner, *newowner;
	u32 uval, curval, newval, newtid;
	int err = 0;

	oldowner = pi_state->owner;

	/*
retry:
	if (!argowner) {
		if (oldowner != current) {
			/*
			return 0;
		}

		if (__rt_mutex_futex_trylock(&pi_state->pi_mutex)) {
			/* We got the lock. pi_state is correct. Tell caller. */
			return 1;
		}

		/*
		newowner = rt_mutex_owner(&pi_state->pi_mutex);
		/*
		if (unlikely(!newowner)) {
			err = -EAGAIN;
			goto handle_err;
		}
	} else {
		WARN_ON_ONCE(argowner != current);
		if (oldowner == current) {
			/*
			return 1;
		}
		newowner = argowner;
	}

	newtid = task_pid_vnr(newowner) | FUTEX_WAITERS;
	/* Owner died? */
	if (!pi_state->owner)
		newtid |= FUTEX_OWNER_DIED;

	err = futex_get_value_locked(&uval, uaddr);
	if (err)
		goto handle_err;

	for (;;) {
		newval = (uval & FUTEX_OWNER_DIED) | newtid;

		err = futex_cmpxchg_value_locked(&curval, uaddr, uval, newval);
		if (err)
			goto handle_err;

		if (curval == uval)
			break;
		uval = curval;
	}

	/*
	pi_state_update_owner(pi_state, newowner);

	return argowner == current;

	/*
handle_err:
	raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);
	spin_unlock(q->lock_ptr);

	switch (err) {
	case -EFAULT:
		err = fault_in_user_writeable(uaddr);
		break;

	case -EAGAIN:
		cond_resched();
		err = 0;
		break;

	default:
		WARN_ON_ONCE(1);
		break;
	}

	spin_lock(q->lock_ptr);
	raw_spin_lock_irq(&pi_state->pi_mutex.wait_lock);

	/*
	if (pi_state->owner != oldowner)
		return argowner == current;

	/* Retry if err was -EAGAIN or the fault in succeeded */
	if (!err)
		goto retry;

	/*
	pi_state_update_owner(pi_state, rt_mutex_owner(&pi_state->pi_mutex));

	return err;
}

static int fixup_pi_state_owner(u32 __user *uaddr, struct futex_q *q,
				struct task_struct *argowner)
{
	struct futex_pi_state *pi_state = q->pi_state;
	int ret;

	lockdep_assert_held(q->lock_ptr);

	raw_spin_lock_irq(&pi_state->pi_mutex.wait_lock);
	ret = __fixup_pi_state_owner(uaddr, q, argowner);
	raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);
	return ret;
}

int fixup_pi_owner(u32 __user *uaddr, struct futex_q *q, int locked)
{
	if (locked) {
		/*
		if (q->pi_state->owner != current)
			return fixup_pi_state_owner(uaddr, q, current);
		return 1;
	}

	/*
	if (q->pi_state->owner == current)
		return fixup_pi_state_owner(uaddr, q, NULL);

	/*
	if (WARN_ON_ONCE(rt_mutex_owner(&q->pi_state->pi_mutex) == current))
		return fixup_pi_state_owner(uaddr, q, current);

	return 0;
}

int futex_lock_pi(u32 __user *uaddr, unsigned int flags, ktime_t *time, int trylock)
{
	struct hrtimer_sleeper timeout, *to;
	struct task_struct *exiting = NULL;
	struct rt_mutex_waiter rt_waiter;
	struct futex_hash_bucket *hb;
	struct futex_q q = futex_q_init;
	int res, ret;

	if (!IS_ENABLED(CONFIG_FUTEX_PI))
		return -ENOSYS;

	if (refill_pi_state_cache())
		return -ENOMEM;

	to = futex_setup_timer(time, &timeout, flags, 0);

retry:
	ret = get_futex_key(uaddr, flags & FLAGS_SHARED, &q.key, FUTEX_WRITE);
	if (unlikely(ret != 0))
		goto out;

retry_private:
	hb = futex_q_lock(&q);

	ret = futex_lock_pi_atomic(uaddr, hb, &q.key, &q.pi_state, current,
				   &exiting, 0);
	if (unlikely(ret)) {
		/*
		switch (ret) {
		case 1:
			/* We got the lock. */
			ret = 0;
			goto out_unlock_put_key;
		case -EFAULT:
			goto uaddr_faulted;
		case -EBUSY:
		case -EAGAIN:
			/*
			futex_q_unlock(hb);
			/*
			wait_for_owner_exiting(ret, exiting);
			cond_resched();
			goto retry;
		default:
			goto out_unlock_put_key;
		}
	}

	WARN_ON(!q.pi_state);

	/*
	__futex_queue(&q, hb);

	if (trylock) {
		ret = rt_mutex_futex_trylock(&q.pi_state->pi_mutex);
		/* Fixup the trylock return value: */
		ret = ret ? 0 : -EWOULDBLOCK;
		goto no_block;
	}

	rt_mutex_init_waiter(&rt_waiter);

	/*
	raw_spin_lock_irq(&q.pi_state->pi_mutex.wait_lock);
	spin_unlock(q.lock_ptr);
	/*
	ret = __rt_mutex_start_proxy_lock(&q.pi_state->pi_mutex, &rt_waiter, current);
	raw_spin_unlock_irq(&q.pi_state->pi_mutex.wait_lock);

	if (ret) {
		if (ret == 1)
			ret = 0;
		goto cleanup;
	}

	if (unlikely(to))
		hrtimer_sleeper_start_expires(to, HRTIMER_MODE_ABS);

	ret = rt_mutex_wait_proxy_lock(&q.pi_state->pi_mutex, to, &rt_waiter);

cleanup:
	spin_lock(q.lock_ptr);
	/*
	if (ret && !rt_mutex_cleanup_proxy_lock(&q.pi_state->pi_mutex, &rt_waiter))
		ret = 0;

no_block:
	/*
	res = fixup_pi_owner(uaddr, &q, !ret);
	/*
	if (res)
		ret = (res < 0) ? res : 0;

	futex_unqueue_pi(&q);
	spin_unlock(q.lock_ptr);
	goto out;

out_unlock_put_key:
	futex_q_unlock(hb);

out:
	if (to) {
		hrtimer_cancel(&to->timer);
		destroy_hrtimer_on_stack(&to->timer);
	}
	return ret != -EINTR ? ret : -ERESTARTNOINTR;

uaddr_faulted:
	futex_q_unlock(hb);

	ret = fault_in_user_writeable(uaddr);
	if (ret)
		goto out;

	if (!(flags & FLAGS_SHARED))
		goto retry_private;

	goto retry;
}

int futex_unlock_pi(u32 __user *uaddr, unsigned int flags)
{
	u32 curval, uval, vpid = task_pid_vnr(current);
	union futex_key key = FUTEX_KEY_INIT;
	struct futex_hash_bucket *hb;
	struct futex_q *top_waiter;
	int ret;

	if (!IS_ENABLED(CONFIG_FUTEX_PI))
		return -ENOSYS;

retry:
	if (get_user(uval, uaddr))
		return -EFAULT;
	/*
	if ((uval & FUTEX_TID_MASK) != vpid)
		return -EPERM;

	ret = get_futex_key(uaddr, flags & FLAGS_SHARED, &key, FUTEX_WRITE);
	if (ret)
		return ret;

	hb = futex_hash(&key);
	spin_lock(&hb->lock);

	/*
	top_waiter = futex_top_waiter(hb, &key);
	if (top_waiter) {
		struct futex_pi_state *pi_state = top_waiter->pi_state;

		ret = -EINVAL;
		if (!pi_state)
			goto out_unlock;

		/*
		if (pi_state->owner != current)
			goto out_unlock;

		get_pi_state(pi_state);
		/*
		raw_spin_lock_irq(&pi_state->pi_mutex.wait_lock);
		spin_unlock(&hb->lock);

		/* drops pi_state->pi_mutex.wait_lock */
		ret = wake_futex_pi(uaddr, uval, pi_state);

		put_pi_state(pi_state);

		/*
		if (!ret)
			return ret;
		/*
		if (ret == -EFAULT)
			goto pi_faulted;
		/*
		if (ret == -EAGAIN)
			goto pi_retry;
		/*
		return ret;
	}

	/*
	if ((ret = futex_cmpxchg_value_locked(&curval, uaddr, uval, 0))) {
		spin_unlock(&hb->lock);
		switch (ret) {
		case -EFAULT:
			goto pi_faulted;

		case -EAGAIN:
			goto pi_retry;

		default:
			WARN_ON_ONCE(1);
			return ret;
		}
	}

	/*
	ret = (curval == uval) ? 0 : -EAGAIN;

out_unlock:
	spin_unlock(&hb->lock);
	return ret;

pi_retry:
	cond_resched();
	goto retry;

pi_faulted:

	ret = fault_in_user_writeable(uaddr);
	if (!ret)
		goto retry;

	return ret;
}

