
#include <linux/sched/signal.h>

#include "futex.h"
#include "../locking/rtmutex_common.h"

enum {
	Q_REQUEUE_PI_NONE		=  0,
	Q_REQUEUE_PI_IGNORE,
	Q_REQUEUE_PI_IN_PROGRESS,
	Q_REQUEUE_PI_WAIT,
	Q_REQUEUE_PI_DONE,
	Q_REQUEUE_PI_LOCKED,
};

const struct futex_q futex_q_init = {
	/* list gets initialized in futex_queue()*/
	.key		= FUTEX_KEY_INIT,
	.bitset		= FUTEX_BITSET_MATCH_ANY,
	.requeue_state	= ATOMIC_INIT(Q_REQUEUE_PI_NONE),
};

static inline
void requeue_futex(struct futex_q *q, struct futex_hash_bucket *hb1,
		   struct futex_hash_bucket *hb2, union futex_key *key2)
{

	/*
	if (likely(&hb1->chain != &hb2->chain)) {
		plist_del(&q->list, &hb1->chain);
		futex_hb_waiters_dec(hb1);
		futex_hb_waiters_inc(hb2);
		plist_add(&q->list, &hb2->chain);
		q->lock_ptr = &hb2->lock;
	}
	q->key = *key2;
}

static inline bool futex_requeue_pi_prepare(struct futex_q *q,
					    struct futex_pi_state *pi_state)
{
	int old, new;

	/*
	old = atomic_read_acquire(&q->requeue_state);
	do {
		if (old == Q_REQUEUE_PI_IGNORE)
			return false;

		/*
		if (old != Q_REQUEUE_PI_NONE)
			break;

		new = Q_REQUEUE_PI_IN_PROGRESS;
	} while (!atomic_try_cmpxchg(&q->requeue_state, &old, new));

	q->pi_state = pi_state;
	return true;
}

static inline void futex_requeue_pi_complete(struct futex_q *q, int locked)
{
	int old, new;

	old = atomic_read_acquire(&q->requeue_state);
	do {
		if (old == Q_REQUEUE_PI_IGNORE)
			return;

		if (locked >= 0) {
			/* Requeue succeeded. Set DONE or LOCKED */
			WARN_ON_ONCE(old != Q_REQUEUE_PI_IN_PROGRESS &&
				     old != Q_REQUEUE_PI_WAIT);
			new = Q_REQUEUE_PI_DONE + locked;
		} else if (old == Q_REQUEUE_PI_IN_PROGRESS) {
			/* Deadlock, no early wakeup interleave */
			new = Q_REQUEUE_PI_NONE;
		} else {
			/* Deadlock, early wakeup interleave. */
			WARN_ON_ONCE(old != Q_REQUEUE_PI_WAIT);
			new = Q_REQUEUE_PI_IGNORE;
		}
	} while (!atomic_try_cmpxchg(&q->requeue_state, &old, new));

#ifdef CONFIG_PREEMPT_RT
	/* If the waiter interleaved with the requeue let it know */
	if (unlikely(old == Q_REQUEUE_PI_WAIT))
		rcuwait_wake_up(&q->requeue_wait);
#endif
}

static inline int futex_requeue_pi_wakeup_sync(struct futex_q *q)
{
	int old, new;

	old = atomic_read_acquire(&q->requeue_state);
	do {
		/* Is requeue done already? */
		if (old >= Q_REQUEUE_PI_DONE)
			return old;

		/*
		new = Q_REQUEUE_PI_WAIT;
		if (old == Q_REQUEUE_PI_NONE)
			new = Q_REQUEUE_PI_IGNORE;
	} while (!atomic_try_cmpxchg(&q->requeue_state, &old, new));

	/* If the requeue was in progress, wait for it to complete */
	if (old == Q_REQUEUE_PI_IN_PROGRESS) {
#ifdef CONFIG_PREEMPT_RT
		rcuwait_wait_event(&q->requeue_wait,
				   atomic_read(&q->requeue_state) != Q_REQUEUE_PI_WAIT,
				   TASK_UNINTERRUPTIBLE);
#else
		(void)atomic_cond_read_relaxed(&q->requeue_state, VAL != Q_REQUEUE_PI_WAIT);
#endif
	}

	/*
	return atomic_read(&q->requeue_state);
}

static inline
void requeue_pi_wake_futex(struct futex_q *q, union futex_key *key,
			   struct futex_hash_bucket *hb)
{
	q->key = *key;

	__futex_unqueue(q);

	WARN_ON(!q->rt_waiter);
	q->rt_waiter = NULL;

	q->lock_ptr = &hb->lock;

	/* Signal locked state to the waiter */
	futex_requeue_pi_complete(q, 1);
	wake_up_state(q->task, TASK_NORMAL);
}

static int
futex_proxy_trylock_atomic(u32 __user *pifutex, struct futex_hash_bucket *hb1,
			   struct futex_hash_bucket *hb2, union futex_key *key1,
			   union futex_key *key2, struct futex_pi_state **ps,
			   struct task_struct **exiting, int set_waiters)
{
	struct futex_q *top_waiter = NULL;
	u32 curval;
	int ret;

	if (futex_get_value_locked(&curval, pifutex))
		return -EFAULT;

	if (unlikely(should_fail_futex(true)))
		return -EFAULT;

	/*
	top_waiter = futex_top_waiter(hb1, key1);

	/* There are no waiters, nothing for us to do. */
	if (!top_waiter)
		return 0;

	/*
	if (!top_waiter->rt_waiter || top_waiter->pi_state)
		return -EINVAL;

	/* Ensure we requeue to the expected futex. */
	if (!futex_match(top_waiter->requeue_pi_key, key2))
		return -EINVAL;

	/* Ensure that this does not race against an early wakeup */
	if (!futex_requeue_pi_prepare(top_waiter, NULL))
		return -EAGAIN;

	/*
	ret = futex_lock_pi_atomic(pifutex, hb2, key2, ps, top_waiter->task,
				   exiting, set_waiters);
	if (ret == 1) {
		/*
		requeue_pi_wake_futex(top_waiter, key2, hb2);
	} else if (ret < 0) {
		/* Rewind top_waiter::requeue_state */
		futex_requeue_pi_complete(top_waiter, ret);
	} else {
		/*
	}
	return ret;
}

int futex_requeue(u32 __user *uaddr1, unsigned int flags, u32 __user *uaddr2,
		  int nr_wake, int nr_requeue, u32 *cmpval, int requeue_pi)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	int task_count = 0, ret;
	struct futex_pi_state *pi_state = NULL;
	struct futex_hash_bucket *hb1, *hb2;
	struct futex_q *this, *next;
	DEFINE_WAKE_Q(wake_q);

	if (nr_wake < 0 || nr_requeue < 0)
		return -EINVAL;

	/*
	if (!IS_ENABLED(CONFIG_FUTEX_PI) && requeue_pi)
		return -ENOSYS;

	if (requeue_pi) {
		/*
		if (uaddr1 == uaddr2)
			return -EINVAL;

		/*
		if (nr_wake != 1)
			return -EINVAL;

		/*
		if (refill_pi_state_cache())
			return -ENOMEM;
	}

retry:
	ret = get_futex_key(uaddr1, flags & FLAGS_SHARED, &key1, FUTEX_READ);
	if (unlikely(ret != 0))
		return ret;
	ret = get_futex_key(uaddr2, flags & FLAGS_SHARED, &key2,
			    requeue_pi ? FUTEX_WRITE : FUTEX_READ);
	if (unlikely(ret != 0))
		return ret;

	/*
	if (requeue_pi && futex_match(&key1, &key2))
		return -EINVAL;

	hb1 = futex_hash(&key1);
	hb2 = futex_hash(&key2);

retry_private:
	futex_hb_waiters_inc(hb2);
	double_lock_hb(hb1, hb2);

	if (likely(cmpval != NULL)) {
		u32 curval;

		ret = futex_get_value_locked(&curval, uaddr1);

		if (unlikely(ret)) {
			double_unlock_hb(hb1, hb2);
			futex_hb_waiters_dec(hb2);

			ret = get_user(curval, uaddr1);
			if (ret)
				return ret;

			if (!(flags & FLAGS_SHARED))
				goto retry_private;

			goto retry;
		}
		if (curval != *cmpval) {
			ret = -EAGAIN;
			goto out_unlock;
		}
	}

	if (requeue_pi) {
		struct task_struct *exiting = NULL;

		/*
		ret = futex_proxy_trylock_atomic(uaddr2, hb1, hb2, &key1,
						 &key2, &pi_state,
						 &exiting, nr_requeue);

		/*
		switch (ret) {
		case 0:
			/* We hold a reference on the pi state. */
			break;

		case 1:
			/*
			task_count++;
			ret = 0;
			break;

		/*
		case -EFAULT:
			double_unlock_hb(hb1, hb2);
			futex_hb_waiters_dec(hb2);
			ret = fault_in_user_writeable(uaddr2);
			if (!ret)
				goto retry;
			return ret;
		case -EBUSY:
		case -EAGAIN:
			/*
			double_unlock_hb(hb1, hb2);
			futex_hb_waiters_dec(hb2);
			/*
			wait_for_owner_exiting(ret, exiting);
			cond_resched();
			goto retry;
		default:
			goto out_unlock;
		}
	}

	plist_for_each_entry_safe(this, next, &hb1->chain, list) {
		if (task_count - nr_wake >= nr_requeue)
			break;

		if (!futex_match(&this->key, &key1))
			continue;

		/*
		if ((requeue_pi && !this->rt_waiter) ||
		    (!requeue_pi && this->rt_waiter) ||
		    this->pi_state) {
			ret = -EINVAL;
			break;
		}

		/* Plain futexes just wake or requeue and are done */
		if (!requeue_pi) {
			if (++task_count <= nr_wake)
				futex_wake_mark(&wake_q, this);
			else
				requeue_futex(this, hb1, hb2, &key2);
			continue;
		}

		/* Ensure we requeue to the expected futex for requeue_pi. */
		if (!futex_match(this->requeue_pi_key, &key2)) {
			ret = -EINVAL;
			break;
		}

		/*
		get_pi_state(pi_state);

		/* Don't requeue when the waiter is already on the way out. */
		if (!futex_requeue_pi_prepare(this, pi_state)) {
			/*
			put_pi_state(pi_state);
			continue;
		}

		ret = rt_mutex_start_proxy_lock(&pi_state->pi_mutex,
						this->rt_waiter,
						this->task);

		if (ret == 1) {
			/*
			requeue_pi_wake_futex(this, &key2, hb2);
			task_count++;
		} else if (!ret) {
			/* Waiter is queued, move it to hb2 */
			requeue_futex(this, hb1, hb2, &key2);
			futex_requeue_pi_complete(this, 0);
			task_count++;
		} else {
			/*
			this->pi_state = NULL;
			put_pi_state(pi_state);
			futex_requeue_pi_complete(this, ret);
			/*
			break;
		}
	}

	/*
	put_pi_state(pi_state);

out_unlock:
	double_unlock_hb(hb1, hb2);
	wake_up_q(&wake_q);
	futex_hb_waiters_dec(hb2);
	return ret ? ret : task_count;
}

static inline
int handle_early_requeue_pi_wakeup(struct futex_hash_bucket *hb,
				   struct futex_q *q,
				   struct hrtimer_sleeper *timeout)
{
	int ret;

	/*
	WARN_ON_ONCE(&hb->lock != q->lock_ptr);

	/*
	plist_del(&q->list, &hb->chain);
	futex_hb_waiters_dec(hb);

	/* Handle spurious wakeups gracefully */
	ret = -EWOULDBLOCK;
	if (timeout && !timeout->task)
		ret = -ETIMEDOUT;
	else if (signal_pending(current))
		ret = -ERESTARTNOINTR;
	return ret;
}

int futex_wait_requeue_pi(u32 __user *uaddr, unsigned int flags,
			  u32 val, ktime_t *abs_time, u32 bitset,
			  u32 __user *uaddr2)
{
	struct hrtimer_sleeper timeout, *to;
	struct rt_mutex_waiter rt_waiter;
	struct futex_hash_bucket *hb;
	union futex_key key2 = FUTEX_KEY_INIT;
	struct futex_q q = futex_q_init;
	struct rt_mutex_base *pi_mutex;
	int res, ret;

	if (!IS_ENABLED(CONFIG_FUTEX_PI))
		return -ENOSYS;

	if (uaddr == uaddr2)
		return -EINVAL;

	if (!bitset)
		return -EINVAL;

	to = futex_setup_timer(abs_time, &timeout, flags,
			       current->timer_slack_ns);

	/*
	rt_mutex_init_waiter(&rt_waiter);

	ret = get_futex_key(uaddr2, flags & FLAGS_SHARED, &key2, FUTEX_WRITE);
	if (unlikely(ret != 0))
		goto out;

	q.bitset = bitset;
	q.rt_waiter = &rt_waiter;
	q.requeue_pi_key = &key2;

	/*
	ret = futex_wait_setup(uaddr, val, flags, &q, &hb);
	if (ret)
		goto out;

	/*
	if (futex_match(&q.key, &key2)) {
		futex_q_unlock(hb);
		ret = -EINVAL;
		goto out;
	}

	/* Queue the futex_q, drop the hb lock, wait for wakeup. */
	futex_wait_queue(hb, &q, to);

	switch (futex_requeue_pi_wakeup_sync(&q)) {
	case Q_REQUEUE_PI_IGNORE:
		/* The waiter is still on uaddr1 */
		spin_lock(&hb->lock);
		ret = handle_early_requeue_pi_wakeup(hb, &q, to);
		spin_unlock(&hb->lock);
		break;

	case Q_REQUEUE_PI_LOCKED:
		/* The requeue acquired the lock */
		if (q.pi_state && (q.pi_state->owner != current)) {
			spin_lock(q.lock_ptr);
			ret = fixup_pi_owner(uaddr2, &q, true);
			/*
			put_pi_state(q.pi_state);
			spin_unlock(q.lock_ptr);
			/*
			ret = ret < 0 ? ret : 0;
		}
		break;

	case Q_REQUEUE_PI_DONE:
		/* Requeue completed. Current is 'pi_blocked_on' the rtmutex */
		pi_mutex = &q.pi_state->pi_mutex;
		ret = rt_mutex_wait_proxy_lock(pi_mutex, to, &rt_waiter);

		/* Current is not longer pi_blocked_on */
		spin_lock(q.lock_ptr);
		if (ret && !rt_mutex_cleanup_proxy_lock(pi_mutex, &rt_waiter))
			ret = 0;

		debug_rt_mutex_free_waiter(&rt_waiter);
		/*
		res = fixup_pi_owner(uaddr2, &q, !ret);
		/*
		if (res)
			ret = (res < 0) ? res : 0;

		futex_unqueue_pi(&q);
		spin_unlock(q.lock_ptr);

		if (ret == -EINTR) {
			/*
			ret = -EWOULDBLOCK;
		}
		break;
	default:
		BUG();
	}

out:
	if (to) {
		hrtimer_cancel(&to->timer);
		destroy_hrtimer_on_stack(&to->timer);
	}
	return ret;
}

