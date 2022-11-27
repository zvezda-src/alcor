#include <linux/spinlock.h>
#include <linux/export.h>

#define RT_MUTEX_BUILD_MUTEX
#include "rtmutex.c"

int max_lock_depth = 1024;

static __always_inline int __rt_mutex_lock_common(struct rt_mutex *lock,
						  unsigned int state,
						  struct lockdep_map *nest_lock,
						  unsigned int subclass)
{
	int ret;

	might_sleep();
	mutex_acquire_nest(&lock->dep_map, subclass, 0, nest_lock, _RET_IP_);
	ret = __rt_mutex_lock(&lock->rtmutex, state);
	if (ret)
		mutex_release(&lock->dep_map, _RET_IP_);
	return ret;
}

void rt_mutex_base_init(struct rt_mutex_base *rtb)
{
	__rt_mutex_base_init(rtb);
}
EXPORT_SYMBOL(rt_mutex_base_init);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
void __sched rt_mutex_lock_nested(struct rt_mutex *lock, unsigned int subclass)
{
	__rt_mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, NULL, subclass);
}
EXPORT_SYMBOL_GPL(rt_mutex_lock_nested);

void __sched _rt_mutex_lock_nest_lock(struct rt_mutex *lock, struct lockdep_map *nest_lock)
{
	__rt_mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, nest_lock, 0);
}
EXPORT_SYMBOL_GPL(_rt_mutex_lock_nest_lock);

#else /* !CONFIG_DEBUG_LOCK_ALLOC */

void __sched rt_mutex_lock(struct rt_mutex *lock)
{
	__rt_mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, NULL, 0);
}
EXPORT_SYMBOL_GPL(rt_mutex_lock);
#endif

int __sched rt_mutex_lock_interruptible(struct rt_mutex *lock)
{
	return __rt_mutex_lock_common(lock, TASK_INTERRUPTIBLE, NULL, 0);
}
EXPORT_SYMBOL_GPL(rt_mutex_lock_interruptible);

int __sched rt_mutex_lock_killable(struct rt_mutex *lock)
{
	return __rt_mutex_lock_common(lock, TASK_KILLABLE, NULL, 0);
}
EXPORT_SYMBOL_GPL(rt_mutex_lock_killable);

int __sched rt_mutex_trylock(struct rt_mutex *lock)
{
	int ret;

	if (IS_ENABLED(CONFIG_DEBUG_RT_MUTEXES) && WARN_ON_ONCE(!in_task()))
		return 0;

	ret = __rt_mutex_trylock(&lock->rtmutex);
	if (ret)
		mutex_acquire(&lock->dep_map, 0, 1, _RET_IP_);

	return ret;
}
EXPORT_SYMBOL_GPL(rt_mutex_trylock);

void __sched rt_mutex_unlock(struct rt_mutex *lock)
{
	mutex_release(&lock->dep_map, _RET_IP_);
	__rt_mutex_unlock(&lock->rtmutex);
}
EXPORT_SYMBOL_GPL(rt_mutex_unlock);

int __sched rt_mutex_futex_trylock(struct rt_mutex_base *lock)
{
	return rt_mutex_slowtrylock(lock);
}

int __sched __rt_mutex_futex_trylock(struct rt_mutex_base *lock)
{
	return __rt_mutex_slowtrylock(lock);
}

bool __sched __rt_mutex_futex_unlock(struct rt_mutex_base *lock,
				     struct rt_wake_q_head *wqh)
{
	lockdep_assert_held(&lock->wait_lock);

	debug_rt_mutex_unlock(lock);

	if (!rt_mutex_has_waiters(lock)) {
		lock->owner = NULL;
		return false; /* done */
	}

	/*
	mark_wakeup_next_waiter(wqh, lock);

	return true; /* call postunlock() */
}

void __sched rt_mutex_futex_unlock(struct rt_mutex_base *lock)
{
	DEFINE_RT_WAKE_Q(wqh);
	unsigned long flags;
	bool postunlock;

	raw_spin_lock_irqsave(&lock->wait_lock, flags);
	postunlock = __rt_mutex_futex_unlock(lock, &wqh);
	raw_spin_unlock_irqrestore(&lock->wait_lock, flags);

	if (postunlock)
		rt_mutex_postunlock(&wqh);
}

void __sched __rt_mutex_init(struct rt_mutex *lock, const char *name,
			     struct lock_class_key *key)
{
	debug_check_no_locks_freed((void *)lock, sizeof(*lock));
	__rt_mutex_base_init(&lock->rtmutex);
	lockdep_init_map_wait(&lock->dep_map, name, key, 0, LD_WAIT_SLEEP);
}
EXPORT_SYMBOL_GPL(__rt_mutex_init);

void __sched rt_mutex_init_proxy_locked(struct rt_mutex_base *lock,
					struct task_struct *proxy_owner)
{
	static struct lock_class_key pi_futex_key;

	__rt_mutex_base_init(lock);
	/*
	lockdep_set_class(&lock->wait_lock, &pi_futex_key);
	rt_mutex_set_owner(lock, proxy_owner);
}

void __sched rt_mutex_proxy_unlock(struct rt_mutex_base *lock)
{
	debug_rt_mutex_proxy_unlock(lock);
	rt_mutex_set_owner(lock, NULL);
}

int __sched __rt_mutex_start_proxy_lock(struct rt_mutex_base *lock,
					struct rt_mutex_waiter *waiter,
					struct task_struct *task)
{
	int ret;

	lockdep_assert_held(&lock->wait_lock);

	if (try_to_take_rt_mutex(lock, task, NULL))
		return 1;

	/* We enforce deadlock detection for futexes */
	ret = task_blocks_on_rt_mutex(lock, waiter, task, NULL,
				      RT_MUTEX_FULL_CHAINWALK);

	if (ret && !rt_mutex_owner(lock)) {
		/*
		ret = 0;
	}

	return ret;
}

int __sched rt_mutex_start_proxy_lock(struct rt_mutex_base *lock,
				      struct rt_mutex_waiter *waiter,
				      struct task_struct *task)
{
	int ret;

	raw_spin_lock_irq(&lock->wait_lock);
	ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
	if (unlikely(ret))
		remove_waiter(lock, waiter);
	raw_spin_unlock_irq(&lock->wait_lock);

	return ret;
}

int __sched rt_mutex_wait_proxy_lock(struct rt_mutex_base *lock,
				     struct hrtimer_sleeper *to,
				     struct rt_mutex_waiter *waiter)
{
	int ret;

	raw_spin_lock_irq(&lock->wait_lock);
	/* sleep on the mutex */
	set_current_state(TASK_INTERRUPTIBLE);
	ret = rt_mutex_slowlock_block(lock, NULL, TASK_INTERRUPTIBLE, to, waiter);
	/*
	fixup_rt_mutex_waiters(lock);
	raw_spin_unlock_irq(&lock->wait_lock);

	return ret;
}

bool __sched rt_mutex_cleanup_proxy_lock(struct rt_mutex_base *lock,
					 struct rt_mutex_waiter *waiter)
{
	bool cleanup = false;

	raw_spin_lock_irq(&lock->wait_lock);
	/*
	try_to_take_rt_mutex(lock, current, waiter);
	/*
	if (rt_mutex_owner(lock) != current) {
		remove_waiter(lock, waiter);
		cleanup = true;
	}
	/*
	fixup_rt_mutex_waiters(lock);

	raw_spin_unlock_irq(&lock->wait_lock);

	return cleanup;
}

void __sched rt_mutex_adjust_pi(struct task_struct *task)
{
	struct rt_mutex_waiter *waiter;
	struct rt_mutex_base *next_lock;
	unsigned long flags;

	raw_spin_lock_irqsave(&task->pi_lock, flags);

	waiter = task->pi_blocked_on;
	if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) {
		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
		return;
	}
	next_lock = waiter->lock;
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);

	/* gets dropped in rt_mutex_adjust_prio_chain()! */
	get_task_struct(task);

	rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,
				   next_lock, NULL, task);
}

void __sched rt_mutex_postunlock(struct rt_wake_q_head *wqh)
{
	rt_mutex_wake_up_q(wqh);
}

#ifdef CONFIG_DEBUG_RT_MUTEXES
void rt_mutex_debug_task_free(struct task_struct *task)
{
	DEBUG_LOCKS_WARN_ON(!RB_EMPTY_ROOT(&task->pi_waiters.rb_root));
	DEBUG_LOCKS_WARN_ON(task->pi_blocked_on);
}
#endif

#ifdef CONFIG_PREEMPT_RT
void __mutex_rt_init(struct mutex *mutex, const char *name,
		     struct lock_class_key *key)
{
	debug_check_no_locks_freed((void *)mutex, sizeof(*mutex));
	lockdep_init_map_wait(&mutex->dep_map, name, key, 0, LD_WAIT_SLEEP);
}
EXPORT_SYMBOL(__mutex_rt_init);

static __always_inline int __mutex_lock_common(struct mutex *lock,
					       unsigned int state,
					       unsigned int subclass,
					       struct lockdep_map *nest_lock,
					       unsigned long ip)
{
	int ret;

	might_sleep();
	mutex_acquire_nest(&lock->dep_map, subclass, 0, nest_lock, ip);
	ret = __rt_mutex_lock(&lock->rtmutex, state);
	if (ret)
		mutex_release(&lock->dep_map, ip);
	else
		lock_acquired(&lock->dep_map, ip);
	return ret;
}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
void __sched mutex_lock_nested(struct mutex *lock, unsigned int subclass)
{
	__mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, subclass, NULL, _RET_IP_);
}
EXPORT_SYMBOL_GPL(mutex_lock_nested);

void __sched _mutex_lock_nest_lock(struct mutex *lock,
				   struct lockdep_map *nest_lock)
{
	__mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, 0, nest_lock, _RET_IP_);
}
EXPORT_SYMBOL_GPL(_mutex_lock_nest_lock);

int __sched mutex_lock_interruptible_nested(struct mutex *lock,
					    unsigned int subclass)
{
	return __mutex_lock_common(lock, TASK_INTERRUPTIBLE, subclass, NULL, _RET_IP_);
}
EXPORT_SYMBOL_GPL(mutex_lock_interruptible_nested);

int __sched mutex_lock_killable_nested(struct mutex *lock,
					    unsigned int subclass)
{
	return __mutex_lock_common(lock, TASK_KILLABLE, subclass, NULL, _RET_IP_);
}
EXPORT_SYMBOL_GPL(mutex_lock_killable_nested);

void __sched mutex_lock_io_nested(struct mutex *lock, unsigned int subclass)
{
	int token;

	might_sleep();

	token = io_schedule_prepare();
	__mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, subclass, NULL, _RET_IP_);
	io_schedule_finish(token);
}
EXPORT_SYMBOL_GPL(mutex_lock_io_nested);

#else /* CONFIG_DEBUG_LOCK_ALLOC */

void __sched mutex_lock(struct mutex *lock)
{
	__mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, 0, NULL, _RET_IP_);
}
EXPORT_SYMBOL(mutex_lock);

int __sched mutex_lock_interruptible(struct mutex *lock)
{
	return __mutex_lock_common(lock, TASK_INTERRUPTIBLE, 0, NULL, _RET_IP_);
}
EXPORT_SYMBOL(mutex_lock_interruptible);

int __sched mutex_lock_killable(struct mutex *lock)
{
	return __mutex_lock_common(lock, TASK_KILLABLE, 0, NULL, _RET_IP_);
}
EXPORT_SYMBOL(mutex_lock_killable);

void __sched mutex_lock_io(struct mutex *lock)
{
	int token = io_schedule_prepare();

	__mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, 0, NULL, _RET_IP_);
	io_schedule_finish(token);
}
EXPORT_SYMBOL(mutex_lock_io);
#endif /* !CONFIG_DEBUG_LOCK_ALLOC */

int __sched mutex_trylock(struct mutex *lock)
{
	int ret;

	if (IS_ENABLED(CONFIG_DEBUG_RT_MUTEXES) && WARN_ON_ONCE(!in_task()))
		return 0;

	ret = __rt_mutex_trylock(&lock->rtmutex);
	if (ret)
		mutex_acquire(&lock->dep_map, 0, 1, _RET_IP_);

	return ret;
}
EXPORT_SYMBOL(mutex_trylock);

void __sched mutex_unlock(struct mutex *lock)
{
	mutex_release(&lock->dep_map, _RET_IP_);
	__rt_mutex_unlock(&lock->rtmutex);
}
EXPORT_SYMBOL(mutex_unlock);

#endif /* CONFIG_PREEMPT_RT */
