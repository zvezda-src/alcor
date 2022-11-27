
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/freezer.h>

#include "futex.h"


void futex_wake_mark(struct wake_q_head *wake_q, struct futex_q *q)
{
	struct task_struct *p = q->task;

	if (WARN(q->pi_state || q->rt_waiter, "refusing to wake PI futex\n"))
		return;

	get_task_struct(p);
	__futex_unqueue(q);
	/*
	smp_store_release(&q->lock_ptr, NULL);

	/*
	wake_q_add_safe(wake_q, p);
}

int futex_wake(u32 __user *uaddr, unsigned int flags, int nr_wake, u32 bitset)
{
	struct futex_hash_bucket *hb;
	struct futex_q *this, *next;
	union futex_key key = FUTEX_KEY_INIT;
	int ret;
	DEFINE_WAKE_Q(wake_q);

	if (!bitset)
		return -EINVAL;

	ret = get_futex_key(uaddr, flags & FLAGS_SHARED, &key, FUTEX_READ);
	if (unlikely(ret != 0))
		return ret;

	hb = futex_hash(&key);

	/* Make sure we really have tasks to wakeup */
	if (!futex_hb_waiters_pending(hb))
		return ret;

	spin_lock(&hb->lock);

	plist_for_each_entry_safe(this, next, &hb->chain, list) {
		if (futex_match (&this->key, &key)) {
			if (this->pi_state || this->rt_waiter) {
				ret = -EINVAL;
				break;
			}

			/* Check if one of the bits is set in both bitsets */
			if (!(this->bitset & bitset))
				continue;

			futex_wake_mark(&wake_q, this);
			if (++ret >= nr_wake)
				break;
		}
	}

	spin_unlock(&hb->lock);
	wake_up_q(&wake_q);
	return ret;
}

static int futex_atomic_op_inuser(unsigned int encoded_op, u32 __user *uaddr)
{
	unsigned int op =	  (encoded_op & 0x70000000) >> 28;
	unsigned int cmp =	  (encoded_op & 0x0f000000) >> 24;
	int oparg = sign_extend32((encoded_op & 0x00fff000) >> 12, 11);
	int cmparg = sign_extend32(encoded_op & 0x00000fff, 11);
	int oldval, ret;

	if (encoded_op & (FUTEX_OP_OPARG_SHIFT << 28)) {
		if (oparg < 0 || oparg > 31) {
			char comm[sizeof(current->comm)];
			/*
			pr_info_ratelimited("futex_wake_op: %s tries to shift op by %d; fix this program\n",
					get_task_comm(comm, current), oparg);
			oparg &= 31;
		}
		oparg = 1 << oparg;
	}

	pagefault_disable();
	ret = arch_futex_atomic_op_inuser(op, oparg, &oldval, uaddr);
	pagefault_enable();
	if (ret)
		return ret;

	switch (cmp) {
	case FUTEX_OP_CMP_EQ:
		return oldval == cmparg;
	case FUTEX_OP_CMP_NE:
		return oldval != cmparg;
	case FUTEX_OP_CMP_LT:
		return oldval < cmparg;
	case FUTEX_OP_CMP_GE:
		return oldval >= cmparg;
	case FUTEX_OP_CMP_LE:
		return oldval <= cmparg;
	case FUTEX_OP_CMP_GT:
		return oldval > cmparg;
	default:
		return -ENOSYS;
	}
}

int futex_wake_op(u32 __user *uaddr1, unsigned int flags, u32 __user *uaddr2,
		  int nr_wake, int nr_wake2, int op)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	struct futex_hash_bucket *hb1, *hb2;
	struct futex_q *this, *next;
	int ret, op_ret;
	DEFINE_WAKE_Q(wake_q);

retry:
	ret = get_futex_key(uaddr1, flags & FLAGS_SHARED, &key1, FUTEX_READ);
	if (unlikely(ret != 0))
		return ret;
	ret = get_futex_key(uaddr2, flags & FLAGS_SHARED, &key2, FUTEX_WRITE);
	if (unlikely(ret != 0))
		return ret;

	hb1 = futex_hash(&key1);
	hb2 = futex_hash(&key2);

retry_private:
	double_lock_hb(hb1, hb2);
	op_ret = futex_atomic_op_inuser(op, uaddr2);
	if (unlikely(op_ret < 0)) {
		double_unlock_hb(hb1, hb2);

		if (!IS_ENABLED(CONFIG_MMU) ||
		    unlikely(op_ret != -EFAULT && op_ret != -EAGAIN)) {
			/*
			ret = op_ret;
			return ret;
		}

		if (op_ret == -EFAULT) {
			ret = fault_in_user_writeable(uaddr2);
			if (ret)
				return ret;
		}

		cond_resched();
		if (!(flags & FLAGS_SHARED))
			goto retry_private;
		goto retry;
	}

	plist_for_each_entry_safe(this, next, &hb1->chain, list) {
		if (futex_match (&this->key, &key1)) {
			if (this->pi_state || this->rt_waiter) {
				ret = -EINVAL;
				goto out_unlock;
			}
			futex_wake_mark(&wake_q, this);
			if (++ret >= nr_wake)
				break;
		}
	}

	if (op_ret > 0) {
		op_ret = 0;
		plist_for_each_entry_safe(this, next, &hb2->chain, list) {
			if (futex_match (&this->key, &key2)) {
				if (this->pi_state || this->rt_waiter) {
					ret = -EINVAL;
					goto out_unlock;
				}
				futex_wake_mark(&wake_q, this);
				if (++op_ret >= nr_wake2)
					break;
			}
		}
		ret += op_ret;
	}

out_unlock:
	double_unlock_hb(hb1, hb2);
	wake_up_q(&wake_q);
	return ret;
}

static long futex_wait_restart(struct restart_block *restart);

void futex_wait_queue(struct futex_hash_bucket *hb, struct futex_q *q,
			    struct hrtimer_sleeper *timeout)
{
	/*
	set_current_state(TASK_INTERRUPTIBLE);
	futex_queue(q, hb);

	/* Arm the timer */
	if (timeout)
		hrtimer_sleeper_start_expires(timeout, HRTIMER_MODE_ABS);

	/*
	if (likely(!plist_node_empty(&q->list))) {
		/*
		if (!timeout || timeout->task)
			freezable_schedule();
	}
	__set_current_state(TASK_RUNNING);
}

static int unqueue_multiple(struct futex_vector *v, int count)
{
	int ret = -1, i;

	for (i = 0; i < count; i++) {
		if (!futex_unqueue(&v[i].q))
			ret = i;
	}

	return ret;
}

static int futex_wait_multiple_setup(struct futex_vector *vs, int count, int *woken)
{
	struct futex_hash_bucket *hb;
	bool retry = false;
	int ret, i;
	u32 uval;

	/*
retry:
	for (i = 0; i < count; i++) {
		if ((vs[i].w.flags & FUTEX_PRIVATE_FLAG) && retry)
			continue;

		ret = get_futex_key(u64_to_user_ptr(vs[i].w.uaddr),
				    !(vs[i].w.flags & FUTEX_PRIVATE_FLAG),
				    &vs[i].q.key, FUTEX_READ);

		if (unlikely(ret))
			return ret;
	}

	set_current_state(TASK_INTERRUPTIBLE);

	for (i = 0; i < count; i++) {
		u32 __user *uaddr = (u32 __user *)(unsigned long)vs[i].w.uaddr;
		struct futex_q *q = &vs[i].q;
		u32 val = (u32)vs[i].w.val;

		hb = futex_q_lock(q);
		ret = futex_get_value_locked(&uval, uaddr);

		if (!ret && uval == val) {
			/*
			futex_queue(q, hb);
			continue;
		}

		futex_q_unlock(hb);
		__set_current_state(TASK_RUNNING);

		/*
		*woken = unqueue_multiple(vs, i);
		if (*woken >= 0)
			return 1;

		if (ret) {
			/*
			if (get_user(uval, uaddr))
				return -EFAULT;

			retry = true;
			goto retry;
		}

		if (uval != val)
			return -EWOULDBLOCK;
	}

	return 0;
}

static void futex_sleep_multiple(struct futex_vector *vs, unsigned int count,
				 struct hrtimer_sleeper *to)
{
	if (to && !to->task)
		return;

	for (; count; count--, vs++) {
		if (!READ_ONCE(vs->q.lock_ptr))
			return;
	}

	freezable_schedule();
}

int futex_wait_multiple(struct futex_vector *vs, unsigned int count,
			struct hrtimer_sleeper *to)
{
	int ret, hint = 0;

	if (to)
		hrtimer_sleeper_start_expires(to, HRTIMER_MODE_ABS);

	while (1) {
		ret = futex_wait_multiple_setup(vs, count, &hint);
		if (ret) {
			if (ret > 0) {
				/* A futex was woken during setup */
				ret = hint;
			}
			return ret;
		}

		futex_sleep_multiple(vs, count, to);

		__set_current_state(TASK_RUNNING);

		ret = unqueue_multiple(vs, count);
		if (ret >= 0)
			return ret;

		if (to && !to->task)
			return -ETIMEDOUT;
		else if (signal_pending(current))
			return -ERESTARTSYS;
		/*
	}
}

int futex_wait_setup(u32 __user *uaddr, u32 val, unsigned int flags,
		     struct futex_q *q, struct futex_hash_bucket **hb)
{
	u32 uval;
	int ret;

	/*
retry:
	ret = get_futex_key(uaddr, flags & FLAGS_SHARED, &q->key, FUTEX_READ);
	if (unlikely(ret != 0))
		return ret;

retry_private:

	ret = futex_get_value_locked(&uval, uaddr);

	if (ret) {
		futex_q_unlock(*hb);

		ret = get_user(uval, uaddr);
		if (ret)
			return ret;

		if (!(flags & FLAGS_SHARED))
			goto retry_private;

		goto retry;
	}

	if (uval != val) {
		futex_q_unlock(*hb);
		ret = -EWOULDBLOCK;
	}

	return ret;
}

int futex_wait(u32 __user *uaddr, unsigned int flags, u32 val, ktime_t *abs_time, u32 bitset)
{
	struct hrtimer_sleeper timeout, *to;
	struct restart_block *restart;
	struct futex_hash_bucket *hb;
	struct futex_q q = futex_q_init;
	int ret;

	if (!bitset)
		return -EINVAL;
	q.bitset = bitset;

	to = futex_setup_timer(abs_time, &timeout, flags,
			       current->timer_slack_ns);
retry:
	/*
	ret = futex_wait_setup(uaddr, val, flags, &q, &hb);
	if (ret)
		goto out;

	/* futex_queue and wait for wakeup, timeout, or a signal. */
	futex_wait_queue(hb, &q, to);

	/* If we were woken (and unqueued), we succeeded, whatever. */
	ret = 0;
	if (!futex_unqueue(&q))
		goto out;
	ret = -ETIMEDOUT;
	if (to && !to->task)
		goto out;

	/*
	if (!signal_pending(current))
		goto retry;

	ret = -ERESTARTSYS;
	if (!abs_time)
		goto out;

	restart = &current->restart_block;
	restart->futex.uaddr = uaddr;
	restart->futex.val = val;
	restart->futex.time = *abs_time;
	restart->futex.bitset = bitset;
	restart->futex.flags = flags | FLAGS_HAS_TIMEOUT;

	ret = set_restart_fn(restart, futex_wait_restart);

out:
	if (to) {
		hrtimer_cancel(&to->timer);
		destroy_hrtimer_on_stack(&to->timer);
	}
	return ret;
}

static long futex_wait_restart(struct restart_block *restart)
{
	u32 __user *uaddr = restart->futex.uaddr;
	ktime_t t, *tp = NULL;

	if (restart->futex.flags & FLAGS_HAS_TIMEOUT) {
		t = restart->futex.time;
		tp = &t;
	}
	restart->fn = do_no_restart_syscall;

	return (long)futex_wait(uaddr, restart->futex.flags,
				restart->futex.val, tp, restart->futex.bitset);
}

