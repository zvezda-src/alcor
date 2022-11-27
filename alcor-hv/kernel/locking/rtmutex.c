#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/deadline.h>
#include <linux/sched/signal.h>
#include <linux/sched/rt.h>
#include <linux/sched/wake_q.h>
#include <linux/ww_mutex.h>

#include <trace/events/lock.h>

#include "rtmutex_common.h"

#ifndef WW_RT
# define build_ww_mutex()	(false)
# define ww_container_of(rtm)	NULL

static inline int __ww_mutex_add_waiter(struct rt_mutex_waiter *waiter,
					struct rt_mutex *lock,
					struct ww_acquire_ctx *ww_ctx)
{
	return 0;
}

static inline void __ww_mutex_check_waiters(struct rt_mutex *lock,
					    struct ww_acquire_ctx *ww_ctx)
{
}

static inline void ww_mutex_lock_acquired(struct ww_mutex *lock,
					  struct ww_acquire_ctx *ww_ctx)
{
}

static inline int __ww_mutex_check_kill(struct rt_mutex *lock,
					struct rt_mutex_waiter *waiter,
					struct ww_acquire_ctx *ww_ctx)
{
	return 0;
}

#else
# define build_ww_mutex()	(true)
# define ww_container_of(rtm)	container_of(rtm, struct ww_mutex, base)
# include "ww_mutex.h"
#endif


static __always_inline void
rt_mutex_set_owner(struct rt_mutex_base *lock, struct task_struct *owner)
{
	unsigned long val = (unsigned long)owner;

	if (rt_mutex_has_waiters(lock))
		val |= RT_MUTEX_HAS_WAITERS;

	WRITE_ONCE(lock->owner, (struct task_struct *)val);
}

static __always_inline void clear_rt_mutex_waiters(struct rt_mutex_base *lock)
{
	lock->owner = (struct task_struct *)
			((unsigned long)lock->owner & ~RT_MUTEX_HAS_WAITERS);
}

static __always_inline void fixup_rt_mutex_waiters(struct rt_mutex_base *lock)
{
	unsigned long owner, *p = (unsigned long *) &lock->owner;

	if (rt_mutex_has_waiters(lock))
		return;

	/*
	owner = READ_ONCE(*p);
	if (owner & RT_MUTEX_HAS_WAITERS)
		WRITE_ONCE(*p, owner & ~RT_MUTEX_HAS_WAITERS);
}

#ifndef CONFIG_DEBUG_RT_MUTEXES
static __always_inline bool rt_mutex_cmpxchg_acquire(struct rt_mutex_base *lock,
						     struct task_struct *old,
						     struct task_struct *new)
{
	return try_cmpxchg_acquire(&lock->owner, &old, new);
}

static __always_inline bool rt_mutex_cmpxchg_release(struct rt_mutex_base *lock,
						     struct task_struct *old,
						     struct task_struct *new)
{
	return try_cmpxchg_release(&lock->owner, &old, new);
}

static __always_inline void mark_rt_mutex_waiters(struct rt_mutex_base *lock)
{
	unsigned long owner, *p = (unsigned long *) &lock->owner;

	do {
		owner = *p;
	} while (cmpxchg_relaxed(p, owner,
				 owner | RT_MUTEX_HAS_WAITERS) != owner);
}

static __always_inline bool unlock_rt_mutex_safe(struct rt_mutex_base *lock,
						 unsigned long flags)
	__releases(lock->wait_lock)
{
	struct task_struct *owner = rt_mutex_owner(lock);

	clear_rt_mutex_waiters(lock);
	raw_spin_unlock_irqrestore(&lock->wait_lock, flags);
	/*
	return rt_mutex_cmpxchg_release(lock, owner, NULL);
}

#else
static __always_inline bool rt_mutex_cmpxchg_acquire(struct rt_mutex_base *lock,
						     struct task_struct *old,
						     struct task_struct *new)
{
	return false;

}

static __always_inline bool rt_mutex_cmpxchg_release(struct rt_mutex_base *lock,
						     struct task_struct *old,
						     struct task_struct *new)
{
	return false;
}

static __always_inline void mark_rt_mutex_waiters(struct rt_mutex_base *lock)
{
	lock->owner = (struct task_struct *)
			((unsigned long)lock->owner | RT_MUTEX_HAS_WAITERS);
}

static __always_inline bool unlock_rt_mutex_safe(struct rt_mutex_base *lock,
						 unsigned long flags)
	__releases(lock->wait_lock)
{
	lock->owner = NULL;
	raw_spin_unlock_irqrestore(&lock->wait_lock, flags);
	return true;
}
#endif

static __always_inline int __waiter_prio(struct task_struct *task)
{
	int prio = task->prio;

	if (!rt_prio(prio))
		return DEFAULT_PRIO;

	return prio;
}

static __always_inline void
waiter_update_prio(struct rt_mutex_waiter *waiter, struct task_struct *task)
{
	waiter->prio = __waiter_prio(task);
	waiter->deadline = task->dl.deadline;
}

#define task_to_waiter(p)	\
	&(struct rt_mutex_waiter){ .prio = __waiter_prio(p), .deadline = (p)->dl.deadline }

static __always_inline int rt_mutex_waiter_less(struct rt_mutex_waiter *left,
						struct rt_mutex_waiter *right)
{
	if (left->prio < right->prio)
		return 1;

	/*
	if (dl_prio(left->prio))
		return dl_time_before(left->deadline, right->deadline);

	return 0;
}

static __always_inline int rt_mutex_waiter_equal(struct rt_mutex_waiter *left,
						 struct rt_mutex_waiter *right)
{
	if (left->prio != right->prio)
		return 0;

	/*
	if (dl_prio(left->prio))
		return left->deadline == right->deadline;

	return 1;
}

static inline bool rt_mutex_steal(struct rt_mutex_waiter *waiter,
				  struct rt_mutex_waiter *top_waiter)
{
	if (rt_mutex_waiter_less(waiter, top_waiter))
		return true;

#ifdef RT_MUTEX_BUILD_SPINLOCKS
	/*
	if (rt_prio(waiter->prio) || dl_prio(waiter->prio))
		return false;

	return rt_mutex_waiter_equal(waiter, top_waiter);
#else
	return false;
#endif
}

#define __node_2_waiter(node) \
	rb_entry((node), struct rt_mutex_waiter, tree_entry)

static __always_inline bool __waiter_less(struct rb_node *a, const struct rb_node *b)
{
	struct rt_mutex_waiter *aw = __node_2_waiter(a);
	struct rt_mutex_waiter *bw = __node_2_waiter(b);

	if (rt_mutex_waiter_less(aw, bw))
		return 1;

	if (!build_ww_mutex())
		return 0;

	if (rt_mutex_waiter_less(bw, aw))
		return 0;

	/* NOTE: relies on waiter->ww_ctx being set before insertion */
	if (aw->ww_ctx) {
		if (!bw->ww_ctx)
			return 1;

		return (signed long)(aw->ww_ctx->stamp -
				     bw->ww_ctx->stamp) < 0;
	}

	return 0;
}

static __always_inline void
rt_mutex_enqueue(struct rt_mutex_base *lock, struct rt_mutex_waiter *waiter)
{
	rb_add_cached(&waiter->tree_entry, &lock->waiters, __waiter_less);
}

static __always_inline void
rt_mutex_dequeue(struct rt_mutex_base *lock, struct rt_mutex_waiter *waiter)
{
	if (RB_EMPTY_NODE(&waiter->tree_entry))
		return;

	rb_erase_cached(&waiter->tree_entry, &lock->waiters);
	RB_CLEAR_NODE(&waiter->tree_entry);
}

#define __node_2_pi_waiter(node) \
	rb_entry((node), struct rt_mutex_waiter, pi_tree_entry)

static __always_inline bool
__pi_waiter_less(struct rb_node *a, const struct rb_node *b)
{
	return rt_mutex_waiter_less(__node_2_pi_waiter(a), __node_2_pi_waiter(b));
}

static __always_inline void
rt_mutex_enqueue_pi(struct task_struct *task, struct rt_mutex_waiter *waiter)
{
	rb_add_cached(&waiter->pi_tree_entry, &task->pi_waiters, __pi_waiter_less);
}

static __always_inline void
rt_mutex_dequeue_pi(struct task_struct *task, struct rt_mutex_waiter *waiter)
{
	if (RB_EMPTY_NODE(&waiter->pi_tree_entry))
		return;

	rb_erase_cached(&waiter->pi_tree_entry, &task->pi_waiters);
	RB_CLEAR_NODE(&waiter->pi_tree_entry);
}

static __always_inline void rt_mutex_adjust_prio(struct task_struct *p)
{
	struct task_struct *pi_task = NULL;

	lockdep_assert_held(&p->pi_lock);

	if (task_has_pi_waiters(p))
		pi_task = task_top_pi_waiter(p)->task;

	rt_mutex_setprio(p, pi_task);
}

static __always_inline void rt_mutex_wake_q_add_task(struct rt_wake_q_head *wqh,
						     struct task_struct *task,
						     unsigned int wake_state)
{
	if (IS_ENABLED(CONFIG_PREEMPT_RT) && wake_state == TASK_RTLOCK_WAIT) {
		if (IS_ENABLED(CONFIG_PROVE_LOCKING))
			WARN_ON_ONCE(wqh->rtlock_task);
		get_task_struct(task);
		wqh->rtlock_task = task;
	} else {
		wake_q_add(&wqh->head, task);
	}
}

static __always_inline void rt_mutex_wake_q_add(struct rt_wake_q_head *wqh,
						struct rt_mutex_waiter *w)
{
	rt_mutex_wake_q_add_task(wqh, w->task, w->wake_state);
}

static __always_inline void rt_mutex_wake_up_q(struct rt_wake_q_head *wqh)
{
	if (IS_ENABLED(CONFIG_PREEMPT_RT) && wqh->rtlock_task) {
		wake_up_state(wqh->rtlock_task, TASK_RTLOCK_WAIT);
		put_task_struct(wqh->rtlock_task);
		wqh->rtlock_task = NULL;
	}

	if (!wake_q_empty(&wqh->head))
		wake_up_q(&wqh->head);

	/* Pairs with preempt_disable() in mark_wakeup_next_waiter() */
	preempt_enable();
}

static __always_inline bool
rt_mutex_cond_detect_deadlock(struct rt_mutex_waiter *waiter,
			      enum rtmutex_chainwalk chwalk)
{
	if (IS_ENABLED(CONFIG_DEBUG_RT_MUTEXES))
		return waiter != NULL;
	return chwalk == RT_MUTEX_FULL_CHAINWALK;
}

static __always_inline struct rt_mutex_base *task_blocked_on_lock(struct task_struct *p)
{
	return p->pi_blocked_on ? p->pi_blocked_on->lock : NULL;
}

static int __sched rt_mutex_adjust_prio_chain(struct task_struct *task,
					      enum rtmutex_chainwalk chwalk,
					      struct rt_mutex_base *orig_lock,
					      struct rt_mutex_base *next_lock,
					      struct rt_mutex_waiter *orig_waiter,
					      struct task_struct *top_task)
{
	struct rt_mutex_waiter *waiter, *top_waiter = orig_waiter;
	struct rt_mutex_waiter *prerequeue_top_waiter;
	int ret = 0, depth = 0;
	struct rt_mutex_base *lock;
	bool detect_deadlock;
	bool requeue = true;

	detect_deadlock = rt_mutex_cond_detect_deadlock(orig_waiter, chwalk);

	/*
 again:
	/*
	if (++depth > max_lock_depth) {
		static int prev_max;

		/*
		if (prev_max != max_lock_depth) {
			prev_max = max_lock_depth;
			printk(KERN_WARNING "Maximum lock depth %d reached "
			       "task: %s (%d)\n", max_lock_depth,
			       top_task->comm, task_pid_nr(top_task));
		}
		put_task_struct(task);

		return -EDEADLK;
	}

	/*
 retry:
	/*
	raw_spin_lock_irq(&task->pi_lock);

	/*
	waiter = task->pi_blocked_on;

	/*

	/*
	if (!waiter)
		goto out_unlock_pi;

	/*
	if (orig_waiter && !rt_mutex_owner(orig_lock))
		goto out_unlock_pi;

	/*
	if (next_lock != waiter->lock)
		goto out_unlock_pi;

	/*
	if (IS_ENABLED(CONFIG_PREEMPT_RT) && waiter->ww_ctx && detect_deadlock)
		detect_deadlock = false;

	/*
	if (top_waiter) {
		if (!task_has_pi_waiters(task))
			goto out_unlock_pi;
		/*
		if (top_waiter != task_top_pi_waiter(task)) {
			if (!detect_deadlock)
				goto out_unlock_pi;
			else
				requeue = false;
		}
	}

	/*
	if (rt_mutex_waiter_equal(waiter, task_to_waiter(task))) {
		if (!detect_deadlock)
			goto out_unlock_pi;
		else
			requeue = false;
	}

	/*
	lock = waiter->lock;
	/*
	if (!raw_spin_trylock(&lock->wait_lock)) {
		raw_spin_unlock_irq(&task->pi_lock);
		cpu_relax();
		goto retry;
	}

	/*
	if (lock == orig_lock || rt_mutex_owner(lock) == top_task) {
		ret = -EDEADLK;

		/*
		if (IS_ENABLED(CONFIG_PREEMPT_RT) && orig_waiter && orig_waiter->ww_ctx)
			ret = 0;

		raw_spin_unlock(&lock->wait_lock);
		goto out_unlock_pi;
	}

	/*
	if (!requeue) {
		/*
		raw_spin_unlock(&task->pi_lock);
		put_task_struct(task);

		/*
		if (!rt_mutex_owner(lock)) {
			raw_spin_unlock_irq(&lock->wait_lock);
			return 0;
		}

		/* [10] Grab the next task, i.e. owner of @lock */
		task = get_task_struct(rt_mutex_owner(lock));
		raw_spin_lock(&task->pi_lock);

		/*
		next_lock = task_blocked_on_lock(task);
		/*
		top_waiter = rt_mutex_top_waiter(lock);

		/* [13] Drop locks */
		raw_spin_unlock(&task->pi_lock);
		raw_spin_unlock_irq(&lock->wait_lock);

		/* If owner is not blocked, end of chain. */
		if (!next_lock)
			goto out_put_task;
		goto again;
	}

	/*
	prerequeue_top_waiter = rt_mutex_top_waiter(lock);

	/* [7] Requeue the waiter in the lock waiter tree. */
	rt_mutex_dequeue(lock, waiter);

	/*
	waiter_update_prio(waiter, task);

	rt_mutex_enqueue(lock, waiter);

	/* [8] Release the task */
	raw_spin_unlock(&task->pi_lock);
	put_task_struct(task);

	/*
	if (!rt_mutex_owner(lock)) {
		/*
		if (prerequeue_top_waiter != rt_mutex_top_waiter(lock))
			wake_up_state(waiter->task, waiter->wake_state);
		raw_spin_unlock_irq(&lock->wait_lock);
		return 0;
	}

	/* [10] Grab the next task, i.e. the owner of @lock */
	task = get_task_struct(rt_mutex_owner(lock));
	raw_spin_lock(&task->pi_lock);

	/* [11] requeue the pi waiters if necessary */
	if (waiter == rt_mutex_top_waiter(lock)) {
		/*
		rt_mutex_dequeue_pi(task, prerequeue_top_waiter);
		rt_mutex_enqueue_pi(task, waiter);
		rt_mutex_adjust_prio(task);

	} else if (prerequeue_top_waiter == waiter) {
		/*
		rt_mutex_dequeue_pi(task, waiter);
		waiter = rt_mutex_top_waiter(lock);
		rt_mutex_enqueue_pi(task, waiter);
		rt_mutex_adjust_prio(task);
	} else {
		/*
	}

	/*
	next_lock = task_blocked_on_lock(task);
	/*
	top_waiter = rt_mutex_top_waiter(lock);

	/* [13] Drop the locks */
	raw_spin_unlock(&task->pi_lock);
	raw_spin_unlock_irq(&lock->wait_lock);

	/*
	if (!next_lock)
		goto out_put_task;

	/*
	if (!detect_deadlock && waiter != top_waiter)
		goto out_put_task;

	goto again;

 out_unlock_pi:
	raw_spin_unlock_irq(&task->pi_lock);
 out_put_task:
	put_task_struct(task);

	return ret;
}

static int __sched
try_to_take_rt_mutex(struct rt_mutex_base *lock, struct task_struct *task,
		     struct rt_mutex_waiter *waiter)
{
	lockdep_assert_held(&lock->wait_lock);

	/*
	mark_rt_mutex_waiters(lock);

	/*
	if (rt_mutex_owner(lock))
		return 0;

	/*
	if (waiter) {
		struct rt_mutex_waiter *top_waiter = rt_mutex_top_waiter(lock);

		/*
		if (waiter == top_waiter || rt_mutex_steal(waiter, top_waiter)) {
			/*
			rt_mutex_dequeue(lock, waiter);
		} else {
			return 0;
		}
	} else {
		/*
		if (rt_mutex_has_waiters(lock)) {
			/* Check whether the trylock can steal it. */
			if (!rt_mutex_steal(task_to_waiter(task),
					    rt_mutex_top_waiter(lock)))
				return 0;

			/*
		} else {
			/*
			goto takeit;
		}
	}

	/*
	raw_spin_lock(&task->pi_lock);
	task->pi_blocked_on = NULL;
	/*
	if (rt_mutex_has_waiters(lock))
		rt_mutex_enqueue_pi(task, rt_mutex_top_waiter(lock));
	raw_spin_unlock(&task->pi_lock);

takeit:
	/*
	rt_mutex_set_owner(lock, task);

	return 1;
}

static int __sched task_blocks_on_rt_mutex(struct rt_mutex_base *lock,
					   struct rt_mutex_waiter *waiter,
					   struct task_struct *task,
					   struct ww_acquire_ctx *ww_ctx,
					   enum rtmutex_chainwalk chwalk)
{
	struct task_struct *owner = rt_mutex_owner(lock);
	struct rt_mutex_waiter *top_waiter = waiter;
	struct rt_mutex_base *next_lock;
	int chain_walk = 0, res;

	lockdep_assert_held(&lock->wait_lock);

	/*
	if (owner == task && !(build_ww_mutex() && ww_ctx))
		return -EDEADLK;

	raw_spin_lock(&task->pi_lock);
	waiter->task = task;
	waiter->lock = lock;
	waiter_update_prio(waiter, task);

	/* Get the top priority waiter on the lock */
	if (rt_mutex_has_waiters(lock))
		top_waiter = rt_mutex_top_waiter(lock);
	rt_mutex_enqueue(lock, waiter);

	task->pi_blocked_on = waiter;

	raw_spin_unlock(&task->pi_lock);

	if (build_ww_mutex() && ww_ctx) {
		struct rt_mutex *rtm;

		/* Check whether the waiter should back out immediately */
		rtm = container_of(lock, struct rt_mutex, rtmutex);
		res = __ww_mutex_add_waiter(waiter, rtm, ww_ctx);
		if (res) {
			raw_spin_lock(&task->pi_lock);
			rt_mutex_dequeue(lock, waiter);
			task->pi_blocked_on = NULL;
			raw_spin_unlock(&task->pi_lock);
			return res;
		}
	}

	if (!owner)
		return 0;

	raw_spin_lock(&owner->pi_lock);
	if (waiter == rt_mutex_top_waiter(lock)) {
		rt_mutex_dequeue_pi(owner, top_waiter);
		rt_mutex_enqueue_pi(owner, waiter);

		rt_mutex_adjust_prio(owner);
		if (owner->pi_blocked_on)
			chain_walk = 1;
	} else if (rt_mutex_cond_detect_deadlock(waiter, chwalk)) {
		chain_walk = 1;
	}

	/* Store the lock on which owner is blocked or NULL */
	next_lock = task_blocked_on_lock(owner);

	raw_spin_unlock(&owner->pi_lock);
	/*
	if (!chain_walk || !next_lock)
		return 0;

	/*
	get_task_struct(owner);

	raw_spin_unlock_irq(&lock->wait_lock);

	res = rt_mutex_adjust_prio_chain(owner, chwalk, lock,
					 next_lock, waiter, task);

	raw_spin_lock_irq(&lock->wait_lock);

	return res;
}

static void __sched mark_wakeup_next_waiter(struct rt_wake_q_head *wqh,
					    struct rt_mutex_base *lock)
{
	struct rt_mutex_waiter *waiter;

	raw_spin_lock(&current->pi_lock);

	waiter = rt_mutex_top_waiter(lock);

	/*
	rt_mutex_dequeue_pi(current, waiter);
	rt_mutex_adjust_prio(current);

	/*
	lock->owner = (void *) RT_MUTEX_HAS_WAITERS;

	/*
	preempt_disable();
	rt_mutex_wake_q_add(wqh, waiter);
	raw_spin_unlock(&current->pi_lock);
}

static int __sched __rt_mutex_slowtrylock(struct rt_mutex_base *lock)
{
	int ret = try_to_take_rt_mutex(lock, current, NULL);

	/*
	fixup_rt_mutex_waiters(lock);

	return ret;
}

static int __sched rt_mutex_slowtrylock(struct rt_mutex_base *lock)
{
	unsigned long flags;
	int ret;

	/*
	if (rt_mutex_owner(lock))
		return 0;

	/*
	raw_spin_lock_irqsave(&lock->wait_lock, flags);

	ret = __rt_mutex_slowtrylock(lock);

	raw_spin_unlock_irqrestore(&lock->wait_lock, flags);

	return ret;
}

static __always_inline int __rt_mutex_trylock(struct rt_mutex_base *lock)
{
	if (likely(rt_mutex_cmpxchg_acquire(lock, NULL, current)))
		return 1;

	return rt_mutex_slowtrylock(lock);
}

static void __sched rt_mutex_slowunlock(struct rt_mutex_base *lock)
{
	DEFINE_RT_WAKE_Q(wqh);
	unsigned long flags;

	/* irqsave required to support early boot calls */
	raw_spin_lock_irqsave(&lock->wait_lock, flags);

	debug_rt_mutex_unlock(lock);

	/*
	while (!rt_mutex_has_waiters(lock)) {
		/* Drops lock->wait_lock ! */
		if (unlock_rt_mutex_safe(lock, flags) == true)
			return;
		/* Relock the rtmutex and try again */
		raw_spin_lock_irqsave(&lock->wait_lock, flags);
	}

	/*
	mark_wakeup_next_waiter(&wqh, lock);
	raw_spin_unlock_irqrestore(&lock->wait_lock, flags);

	rt_mutex_wake_up_q(&wqh);
}

static __always_inline void __rt_mutex_unlock(struct rt_mutex_base *lock)
{
	if (likely(rt_mutex_cmpxchg_release(lock, current, NULL)))
		return;

	rt_mutex_slowunlock(lock);
}

#ifdef CONFIG_SMP
static bool rtmutex_spin_on_owner(struct rt_mutex_base *lock,
				  struct rt_mutex_waiter *waiter,
				  struct task_struct *owner)
{
	bool res = true;

	rcu_read_lock();
	for (;;) {
		/* If owner changed, trylock again. */
		if (owner != rt_mutex_owner(lock))
			break;
		/*
		barrier();
		/*
		if (!owner_on_cpu(owner) || need_resched() ||
		    !rt_mutex_waiter_is_top_waiter(lock, waiter)) {
			res = false;
			break;
		}
		cpu_relax();
	}
	rcu_read_unlock();
	return res;
}
#else
static bool rtmutex_spin_on_owner(struct rt_mutex_base *lock,
				  struct rt_mutex_waiter *waiter,
				  struct task_struct *owner)
{
	return false;
}
#endif

#ifdef RT_MUTEX_BUILD_MUTEX

static void __sched remove_waiter(struct rt_mutex_base *lock,
				  struct rt_mutex_waiter *waiter)
{
	bool is_top_waiter = (waiter == rt_mutex_top_waiter(lock));
	struct task_struct *owner = rt_mutex_owner(lock);
	struct rt_mutex_base *next_lock;

	lockdep_assert_held(&lock->wait_lock);

	raw_spin_lock(&current->pi_lock);
	rt_mutex_dequeue(lock, waiter);
	current->pi_blocked_on = NULL;
	raw_spin_unlock(&current->pi_lock);

	/*
	if (!owner || !is_top_waiter)
		return;

	raw_spin_lock(&owner->pi_lock);

	rt_mutex_dequeue_pi(owner, waiter);

	if (rt_mutex_has_waiters(lock))
		rt_mutex_enqueue_pi(owner, rt_mutex_top_waiter(lock));

	rt_mutex_adjust_prio(owner);

	/* Store the lock on which owner is blocked or NULL */
	next_lock = task_blocked_on_lock(owner);

	raw_spin_unlock(&owner->pi_lock);

	/*
	if (!next_lock)
		return;

	/* gets dropped in rt_mutex_adjust_prio_chain()! */
	get_task_struct(owner);

	raw_spin_unlock_irq(&lock->wait_lock);

	rt_mutex_adjust_prio_chain(owner, RT_MUTEX_MIN_CHAINWALK, lock,
				   next_lock, NULL, current);

	raw_spin_lock_irq(&lock->wait_lock);
}

static int __sched rt_mutex_slowlock_block(struct rt_mutex_base *lock,
					   struct ww_acquire_ctx *ww_ctx,
					   unsigned int state,
					   struct hrtimer_sleeper *timeout,
					   struct rt_mutex_waiter *waiter)
{
	struct rt_mutex *rtm = container_of(lock, struct rt_mutex, rtmutex);
	struct task_struct *owner;
	int ret = 0;

	for (;;) {
		/* Try to acquire the lock: */
		if (try_to_take_rt_mutex(lock, current, waiter))
			break;

		if (timeout && !timeout->task) {
			ret = -ETIMEDOUT;
			break;
		}
		if (signal_pending_state(state, current)) {
			ret = -EINTR;
			break;
		}

		if (build_ww_mutex() && ww_ctx) {
			ret = __ww_mutex_check_kill(rtm, waiter, ww_ctx);
			if (ret)
				break;
		}

		if (waiter == rt_mutex_top_waiter(lock))
			owner = rt_mutex_owner(lock);
		else
			owner = NULL;
		raw_spin_unlock_irq(&lock->wait_lock);

		if (!owner || !rtmutex_spin_on_owner(lock, waiter, owner))
			schedule();

		raw_spin_lock_irq(&lock->wait_lock);
		set_current_state(state);
	}

	__set_current_state(TASK_RUNNING);
	return ret;
}

static void __sched rt_mutex_handle_deadlock(int res, int detect_deadlock,
					     struct rt_mutex_waiter *w)
{
	/*
	if (res != -EDEADLOCK || detect_deadlock)
		return;

	if (build_ww_mutex() && w->ww_ctx)
		return;

	/*
	WARN(1, "rtmutex deadlock detected\n");
	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
}

static int __sched __rt_mutex_slowlock(struct rt_mutex_base *lock,
				       struct ww_acquire_ctx *ww_ctx,
				       unsigned int state,
				       enum rtmutex_chainwalk chwalk,
				       struct rt_mutex_waiter *waiter)
{
	struct rt_mutex *rtm = container_of(lock, struct rt_mutex, rtmutex);
	struct ww_mutex *ww = ww_container_of(rtm);
	int ret;

	lockdep_assert_held(&lock->wait_lock);

	/* Try to acquire the lock again: */
	if (try_to_take_rt_mutex(lock, current, NULL)) {
		if (build_ww_mutex() && ww_ctx) {
			__ww_mutex_check_waiters(rtm, ww_ctx);
			ww_mutex_lock_acquired(ww, ww_ctx);
		}
		return 0;
	}

	set_current_state(state);

	trace_contention_begin(lock, LCB_F_RT);

	ret = task_blocks_on_rt_mutex(lock, waiter, current, ww_ctx, chwalk);
	if (likely(!ret))
		ret = rt_mutex_slowlock_block(lock, ww_ctx, state, NULL, waiter);

	if (likely(!ret)) {
		/* acquired the lock */
		if (build_ww_mutex() && ww_ctx) {
			if (!ww_ctx->is_wait_die)
				__ww_mutex_check_waiters(rtm, ww_ctx);
			ww_mutex_lock_acquired(ww, ww_ctx);
		}
	} else {
		__set_current_state(TASK_RUNNING);
		remove_waiter(lock, waiter);
		rt_mutex_handle_deadlock(ret, chwalk, waiter);
	}

	/*
	fixup_rt_mutex_waiters(lock);

	trace_contention_end(lock, ret);

	return ret;
}

static inline int __rt_mutex_slowlock_locked(struct rt_mutex_base *lock,
					     struct ww_acquire_ctx *ww_ctx,
					     unsigned int state)
{
	struct rt_mutex_waiter waiter;
	int ret;

	rt_mutex_init_waiter(&waiter);
	waiter.ww_ctx = ww_ctx;

	ret = __rt_mutex_slowlock(lock, ww_ctx, state, RT_MUTEX_MIN_CHAINWALK,
				  &waiter);

	debug_rt_mutex_free_waiter(&waiter);
	return ret;
}

static int __sched rt_mutex_slowlock(struct rt_mutex_base *lock,
				     struct ww_acquire_ctx *ww_ctx,
				     unsigned int state)
{
	unsigned long flags;
	int ret;

	/*
	raw_spin_lock_irqsave(&lock->wait_lock, flags);
	ret = __rt_mutex_slowlock_locked(lock, ww_ctx, state);
	raw_spin_unlock_irqrestore(&lock->wait_lock, flags);

	return ret;
}

static __always_inline int __rt_mutex_lock(struct rt_mutex_base *lock,
					   unsigned int state)
{
	if (likely(rt_mutex_cmpxchg_acquire(lock, NULL, current)))
		return 0;

	return rt_mutex_slowlock(lock, NULL, state);
}
#endif /* RT_MUTEX_BUILD_MUTEX */

#ifdef RT_MUTEX_BUILD_SPINLOCKS

static void __sched rtlock_slowlock_locked(struct rt_mutex_base *lock)
{
	struct rt_mutex_waiter waiter;
	struct task_struct *owner;

	lockdep_assert_held(&lock->wait_lock);

	if (try_to_take_rt_mutex(lock, current, NULL))
		return;

	rt_mutex_init_rtlock_waiter(&waiter);

	/* Save current state and set state to TASK_RTLOCK_WAIT */
	current_save_and_set_rtlock_wait_state();

	trace_contention_begin(lock, LCB_F_RT);

	task_blocks_on_rt_mutex(lock, &waiter, current, NULL, RT_MUTEX_MIN_CHAINWALK);

	for (;;) {
		/* Try to acquire the lock again */
		if (try_to_take_rt_mutex(lock, current, &waiter))
			break;

		if (&waiter == rt_mutex_top_waiter(lock))
			owner = rt_mutex_owner(lock);
		else
			owner = NULL;
		raw_spin_unlock_irq(&lock->wait_lock);

		if (!owner || !rtmutex_spin_on_owner(lock, &waiter, owner))
			schedule_rtlock();

		raw_spin_lock_irq(&lock->wait_lock);
		set_current_state(TASK_RTLOCK_WAIT);
	}

	/* Restore the task state */
	current_restore_rtlock_saved_state();

	/*
	fixup_rt_mutex_waiters(lock);
	debug_rt_mutex_free_waiter(&waiter);

	trace_contention_end(lock, 0);
}

static __always_inline void __sched rtlock_slowlock(struct rt_mutex_base *lock)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&lock->wait_lock, flags);
	rtlock_slowlock_locked(lock);
	raw_spin_unlock_irqrestore(&lock->wait_lock, flags);
}

#endif /* RT_MUTEX_BUILD_SPINLOCKS */
