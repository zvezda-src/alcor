#include <linux/mutex.h>
#include <linux/ww_mutex.h>
#include <linux/sched/signal.h>
#include <linux/sched/rt.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/debug.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/debug_locks.h>
#include <linux/osq_lock.h>

#define CREATE_TRACE_POINTS
#include <trace/events/lock.h>

#ifndef CONFIG_PREEMPT_RT
#include "mutex.h"

#ifdef CONFIG_DEBUG_MUTEXES
# define MUTEX_WARN_ON(cond) DEBUG_LOCKS_WARN_ON(cond)
#else
# define MUTEX_WARN_ON(cond)
#endif

void
__mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
{
	atomic_long_set(&lock->owner, 0);
	raw_spin_lock_init(&lock->wait_lock);
	INIT_LIST_HEAD(&lock->wait_list);
#ifdef CONFIG_MUTEX_SPIN_ON_OWNER
	osq_lock_init(&lock->osq);
#endif

	debug_mutex_init(lock, name, key);
}
EXPORT_SYMBOL(__mutex_init);

#define MUTEX_FLAG_WAITERS	0x01
#define MUTEX_FLAG_HANDOFF	0x02
#define MUTEX_FLAG_PICKUP	0x04

#define MUTEX_FLAGS		0x07

static inline struct task_struct *__mutex_owner(struct mutex *lock)
{
	return (struct task_struct *)(atomic_long_read(&lock->owner) & ~MUTEX_FLAGS);
}

static inline struct task_struct *__owner_task(unsigned long owner)
{
	return (struct task_struct *)(owner & ~MUTEX_FLAGS);
}

bool mutex_is_locked(struct mutex *lock)
{
	return __mutex_owner(lock) != NULL;
}
EXPORT_SYMBOL(mutex_is_locked);

static inline unsigned long __owner_flags(unsigned long owner)
{
	return owner & MUTEX_FLAGS;
}

static inline struct task_struct *__mutex_trylock_common(struct mutex *lock, bool handoff)
{
	unsigned long owner, curr = (unsigned long)current;

	owner = atomic_long_read(&lock->owner);
	for (;;) { /* must loop, can race against a flag */
		unsigned long flags = __owner_flags(owner);
		unsigned long task = owner & ~MUTEX_FLAGS;

		if (task) {
			if (flags & MUTEX_FLAG_PICKUP) {
				if (task != curr)
					break;
				flags &= ~MUTEX_FLAG_PICKUP;
			} else if (handoff) {
				if (flags & MUTEX_FLAG_HANDOFF)
					break;
				flags |= MUTEX_FLAG_HANDOFF;
			} else {
				break;
			}
		} else {
			MUTEX_WARN_ON(flags & (MUTEX_FLAG_HANDOFF | MUTEX_FLAG_PICKUP));
			task = curr;
		}

		if (atomic_long_try_cmpxchg_acquire(&lock->owner, &owner, task | flags)) {
			if (task == curr)
				return NULL;
			break;
		}
	}

	return __owner_task(owner);
}

static inline bool __mutex_trylock_or_handoff(struct mutex *lock, bool handoff)
{
	return !__mutex_trylock_common(lock, handoff);
}

static inline bool __mutex_trylock(struct mutex *lock)
{
	return !__mutex_trylock_common(lock, false);
}

#ifndef CONFIG_DEBUG_LOCK_ALLOC

static __always_inline bool __mutex_trylock_fast(struct mutex *lock)
{
	unsigned long curr = (unsigned long)current;
	unsigned long zero = 0UL;

	if (atomic_long_try_cmpxchg_acquire(&lock->owner, &zero, curr))
		return true;

	return false;
}

static __always_inline bool __mutex_unlock_fast(struct mutex *lock)
{
	unsigned long curr = (unsigned long)current;

	return atomic_long_try_cmpxchg_release(&lock->owner, &curr, 0UL);
}
#endif

static inline void __mutex_set_flag(struct mutex *lock, unsigned long flag)
{
	atomic_long_or(flag, &lock->owner);
}

static inline void __mutex_clear_flag(struct mutex *lock, unsigned long flag)
{
	atomic_long_andnot(flag, &lock->owner);
}

static inline bool __mutex_waiter_is_first(struct mutex *lock, struct mutex_waiter *waiter)
{
	return list_first_entry(&lock->wait_list, struct mutex_waiter, list) == waiter;
}

static void
__mutex_add_waiter(struct mutex *lock, struct mutex_waiter *waiter,
		   struct list_head *list)
{
	debug_mutex_add_waiter(lock, waiter, current);

	list_add_tail(&waiter->list, list);
	if (__mutex_waiter_is_first(lock, waiter))
		__mutex_set_flag(lock, MUTEX_FLAG_WAITERS);
}

static void
__mutex_remove_waiter(struct mutex *lock, struct mutex_waiter *waiter)
{
	list_del(&waiter->list);
	if (likely(list_empty(&lock->wait_list)))
		__mutex_clear_flag(lock, MUTEX_FLAGS);

	debug_mutex_remove_waiter(lock, waiter, current);
}

static void __mutex_handoff(struct mutex *lock, struct task_struct *task)
{
	unsigned long owner = atomic_long_read(&lock->owner);

	for (;;) {
		unsigned long new;

		MUTEX_WARN_ON(__owner_task(owner) != current);
		MUTEX_WARN_ON(owner & MUTEX_FLAG_PICKUP);

		new = (owner & MUTEX_FLAG_WAITERS);
		new |= (unsigned long)task;
		if (task)
			new |= MUTEX_FLAG_PICKUP;

		if (atomic_long_try_cmpxchg_release(&lock->owner, &owner, new))
			break;
	}
}

#ifndef CONFIG_DEBUG_LOCK_ALLOC
static void __sched __mutex_lock_slowpath(struct mutex *lock);

void __sched mutex_lock(struct mutex *lock)
{
	might_sleep();

	if (!__mutex_trylock_fast(lock))
		__mutex_lock_slowpath(lock);
}
EXPORT_SYMBOL(mutex_lock);
#endif

#include "ww_mutex.h"

#ifdef CONFIG_MUTEX_SPIN_ON_OWNER

static inline struct task_struct *__mutex_trylock_or_owner(struct mutex *lock)
{
	return __mutex_trylock_common(lock, false);
}

static inline
bool ww_mutex_spin_on_owner(struct mutex *lock, struct ww_acquire_ctx *ww_ctx,
			    struct mutex_waiter *waiter)
{
	struct ww_mutex *ww;

	ww = container_of(lock, struct ww_mutex, base);

	/*
	if (ww_ctx->acquired > 0 && READ_ONCE(ww->ctx))
		return false;

	/*
	if (!waiter && (atomic_long_read(&lock->owner) & MUTEX_FLAG_WAITERS))
		return false;

	/*
	if (waiter && !__mutex_waiter_is_first(lock, waiter))
		return false;

	return true;
}

static noinline
bool mutex_spin_on_owner(struct mutex *lock, struct task_struct *owner,
			 struct ww_acquire_ctx *ww_ctx, struct mutex_waiter *waiter)
{
	bool ret = true;

	lockdep_assert_preemption_disabled();

	while (__mutex_owner(lock) == owner) {
		/*
		barrier();

		/*
		if (!owner_on_cpu(owner) || need_resched()) {
			ret = false;
			break;
		}

		if (ww_ctx && !ww_mutex_spin_on_owner(lock, ww_ctx, waiter)) {
			ret = false;
			break;
		}

		cpu_relax();
	}

	return ret;
}

static inline int mutex_can_spin_on_owner(struct mutex *lock)
{
	struct task_struct *owner;
	int retval = 1;

	lockdep_assert_preemption_disabled();

	if (need_resched())
		return 0;

	/*
	owner = __mutex_owner(lock);
	if (owner)
		retval = owner_on_cpu(owner);

	/*
	return retval;
}

static __always_inline bool
mutex_optimistic_spin(struct mutex *lock, struct ww_acquire_ctx *ww_ctx,
		      struct mutex_waiter *waiter)
{
	if (!waiter) {
		/*
		if (!mutex_can_spin_on_owner(lock))
			goto fail;

		/*
		if (!osq_lock(&lock->osq))
			goto fail;
	}

	for (;;) {
		struct task_struct *owner;

		/* Try to acquire the mutex... */
		owner = __mutex_trylock_or_owner(lock);
		if (!owner)
			break;

		/*
		if (!mutex_spin_on_owner(lock, owner, ww_ctx, waiter))
			goto fail_unlock;

		/*
		cpu_relax();
	}

	if (!waiter)
		osq_unlock(&lock->osq);

	return true;


fail_unlock:
	if (!waiter)
		osq_unlock(&lock->osq);

fail:
	/*
	if (need_resched()) {
		/*
		__set_current_state(TASK_RUNNING);
		schedule_preempt_disabled();
	}

	return false;
}
#else
static __always_inline bool
mutex_optimistic_spin(struct mutex *lock, struct ww_acquire_ctx *ww_ctx,
		      struct mutex_waiter *waiter)
{
	return false;
}
#endif

static noinline void __sched __mutex_unlock_slowpath(struct mutex *lock, unsigned long ip);

void __sched mutex_unlock(struct mutex *lock)
{
#ifndef CONFIG_DEBUG_LOCK_ALLOC
	if (__mutex_unlock_fast(lock))
		return;
#endif
	__mutex_unlock_slowpath(lock, _RET_IP_);
}
EXPORT_SYMBOL(mutex_unlock);

void __sched ww_mutex_unlock(struct ww_mutex *lock)
{
	__ww_mutex_unlock(lock);
	mutex_unlock(&lock->base);
}
EXPORT_SYMBOL(ww_mutex_unlock);

static __always_inline int __sched
__mutex_lock_common(struct mutex *lock, unsigned int state, unsigned int subclass,
		    struct lockdep_map *nest_lock, unsigned long ip,
		    struct ww_acquire_ctx *ww_ctx, const bool use_ww_ctx)
{
	struct mutex_waiter waiter;
	struct ww_mutex *ww;
	int ret;

	if (!use_ww_ctx)
		ww_ctx = NULL;

	might_sleep();

	MUTEX_WARN_ON(lock->magic != lock);

	ww = container_of(lock, struct ww_mutex, base);
	if (ww_ctx) {
		if (unlikely(ww_ctx == READ_ONCE(ww->ctx)))
			return -EALREADY;

		/*
		if (ww_ctx->acquired == 0)
			ww_ctx->wounded = 0;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
		nest_lock = &ww_ctx->dep_map;
#endif
	}

	preempt_disable();
	mutex_acquire_nest(&lock->dep_map, subclass, 0, nest_lock, ip);

	trace_contention_begin(lock, LCB_F_MUTEX | LCB_F_SPIN);
	if (__mutex_trylock(lock) ||
	    mutex_optimistic_spin(lock, ww_ctx, NULL)) {
		/* got the lock, yay! */
		lock_acquired(&lock->dep_map, ip);
		if (ww_ctx)
			ww_mutex_set_context_fastpath(ww, ww_ctx);
		trace_contention_end(lock, 0);
		preempt_enable();
		return 0;
	}

	raw_spin_lock(&lock->wait_lock);
	/*
	if (__mutex_trylock(lock)) {
		if (ww_ctx)
			__ww_mutex_check_waiters(lock, ww_ctx);

		goto skip_wait;
	}

	debug_mutex_lock_common(lock, &waiter);
	waiter.task = current;
	if (use_ww_ctx)
		waiter.ww_ctx = ww_ctx;

	lock_contended(&lock->dep_map, ip);

	if (!use_ww_ctx) {
		/* add waiting tasks to the end of the waitqueue (FIFO): */
		__mutex_add_waiter(lock, &waiter, &lock->wait_list);
	} else {
		/*
		ret = __ww_mutex_add_waiter(&waiter, lock, ww_ctx);
		if (ret)
			goto err_early_kill;
	}

	set_current_state(state);
	trace_contention_begin(lock, LCB_F_MUTEX);
	for (;;) {
		bool first;

		/*
		if (__mutex_trylock(lock))
			goto acquired;

		/*
		if (signal_pending_state(state, current)) {
			ret = -EINTR;
			goto err;
		}

		if (ww_ctx) {
			ret = __ww_mutex_check_kill(lock, &waiter, ww_ctx);
			if (ret)
				goto err;
		}

		raw_spin_unlock(&lock->wait_lock);
		schedule_preempt_disabled();

		first = __mutex_waiter_is_first(lock, &waiter);

		set_current_state(state);
		/*
		if (__mutex_trylock_or_handoff(lock, first))
			break;

		if (first) {
			trace_contention_begin(lock, LCB_F_MUTEX | LCB_F_SPIN);
			if (mutex_optimistic_spin(lock, ww_ctx, &waiter))
				break;
			trace_contention_begin(lock, LCB_F_MUTEX);
		}

		raw_spin_lock(&lock->wait_lock);
	}
	raw_spin_lock(&lock->wait_lock);
acquired:
	__set_current_state(TASK_RUNNING);

	if (ww_ctx) {
		/*
		if (!ww_ctx->is_wait_die &&
		    !__mutex_waiter_is_first(lock, &waiter))
			__ww_mutex_check_waiters(lock, ww_ctx);
	}

	__mutex_remove_waiter(lock, &waiter);

	debug_mutex_free_waiter(&waiter);

skip_wait:
	/* got the lock - cleanup and rejoice! */
	lock_acquired(&lock->dep_map, ip);
	trace_contention_end(lock, 0);

	if (ww_ctx)
		ww_mutex_lock_acquired(ww, ww_ctx);

	raw_spin_unlock(&lock->wait_lock);
	preempt_enable();
	return 0;

err:
	__set_current_state(TASK_RUNNING);
	__mutex_remove_waiter(lock, &waiter);
err_early_kill:
	trace_contention_end(lock, ret);
	raw_spin_unlock(&lock->wait_lock);
	debug_mutex_free_waiter(&waiter);
	mutex_release(&lock->dep_map, ip);
	preempt_enable();
	return ret;
}

static int __sched
__mutex_lock(struct mutex *lock, unsigned int state, unsigned int subclass,
	     struct lockdep_map *nest_lock, unsigned long ip)
{
	return __mutex_lock_common(lock, state, subclass, nest_lock, ip, NULL, false);
}

static int __sched
__ww_mutex_lock(struct mutex *lock, unsigned int state, unsigned int subclass,
		unsigned long ip, struct ww_acquire_ctx *ww_ctx)
{
	return __mutex_lock_common(lock, state, subclass, NULL, ip, ww_ctx, true);
}

int ww_mutex_trylock(struct ww_mutex *ww, struct ww_acquire_ctx *ww_ctx)
{
	if (!ww_ctx)
		return mutex_trylock(&ww->base);

	MUTEX_WARN_ON(ww->base.magic != &ww->base);

	/*
	if (ww_ctx->acquired == 0)
		ww_ctx->wounded = 0;

	if (__mutex_trylock(&ww->base)) {
		ww_mutex_set_context_fastpath(ww, ww_ctx);
		mutex_acquire_nest(&ww->base.dep_map, 0, 1, &ww_ctx->dep_map, _RET_IP_);
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL(ww_mutex_trylock);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
void __sched
mutex_lock_nested(struct mutex *lock, unsigned int subclass)
{
	__mutex_lock(lock, TASK_UNINTERRUPTIBLE, subclass, NULL, _RET_IP_);
}

EXPORT_SYMBOL_GPL(mutex_lock_nested);

void __sched
_mutex_lock_nest_lock(struct mutex *lock, struct lockdep_map *nest)
{
	__mutex_lock(lock, TASK_UNINTERRUPTIBLE, 0, nest, _RET_IP_);
}
EXPORT_SYMBOL_GPL(_mutex_lock_nest_lock);

int __sched
mutex_lock_killable_nested(struct mutex *lock, unsigned int subclass)
{
	return __mutex_lock(lock, TASK_KILLABLE, subclass, NULL, _RET_IP_);
}
EXPORT_SYMBOL_GPL(mutex_lock_killable_nested);

int __sched
mutex_lock_interruptible_nested(struct mutex *lock, unsigned int subclass)
{
	return __mutex_lock(lock, TASK_INTERRUPTIBLE, subclass, NULL, _RET_IP_);
}
EXPORT_SYMBOL_GPL(mutex_lock_interruptible_nested);

void __sched
mutex_lock_io_nested(struct mutex *lock, unsigned int subclass)
{
	int token;

	might_sleep();

	token = io_schedule_prepare();
	__mutex_lock_common(lock, TASK_UNINTERRUPTIBLE,
			    subclass, NULL, _RET_IP_, NULL, 0);
	io_schedule_finish(token);
}
EXPORT_SYMBOL_GPL(mutex_lock_io_nested);

static inline int
ww_mutex_deadlock_injection(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
#ifdef CONFIG_DEBUG_WW_MUTEX_SLOWPATH
	unsigned tmp;

	if (ctx->deadlock_inject_countdown-- == 0) {
		tmp = ctx->deadlock_inject_interval;
		if (tmp > UINT_MAX/4)
			tmp = UINT_MAX;
		else
			tmp = tmp*2 + tmp + tmp/2;

		ctx->deadlock_inject_interval = tmp;
		ctx->deadlock_inject_countdown = tmp;
		ctx->contending_lock = lock;

		ww_mutex_unlock(lock);

		return -EDEADLK;
	}
#endif

	return 0;
}

int __sched
ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	int ret;

	might_sleep();
	ret =  __ww_mutex_lock(&lock->base, TASK_UNINTERRUPTIBLE,
			       0, _RET_IP_, ctx);
	if (!ret && ctx && ctx->acquired > 1)
		return ww_mutex_deadlock_injection(lock, ctx);

	return ret;
}
EXPORT_SYMBOL_GPL(ww_mutex_lock);

int __sched
ww_mutex_lock_interruptible(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	int ret;

	might_sleep();
	ret = __ww_mutex_lock(&lock->base, TASK_INTERRUPTIBLE,
			      0, _RET_IP_, ctx);

	if (!ret && ctx && ctx->acquired > 1)
		return ww_mutex_deadlock_injection(lock, ctx);

	return ret;
}
EXPORT_SYMBOL_GPL(ww_mutex_lock_interruptible);

#endif

static noinline void __sched __mutex_unlock_slowpath(struct mutex *lock, unsigned long ip)
{
	struct task_struct *next = NULL;
	DEFINE_WAKE_Q(wake_q);
	unsigned long owner;

	mutex_release(&lock->dep_map, ip);

	/*
	owner = atomic_long_read(&lock->owner);
	for (;;) {
		MUTEX_WARN_ON(__owner_task(owner) != current);
		MUTEX_WARN_ON(owner & MUTEX_FLAG_PICKUP);

		if (owner & MUTEX_FLAG_HANDOFF)
			break;

		if (atomic_long_try_cmpxchg_release(&lock->owner, &owner, __owner_flags(owner))) {
			if (owner & MUTEX_FLAG_WAITERS)
				break;

			return;
		}
	}

	raw_spin_lock(&lock->wait_lock);
	debug_mutex_unlock(lock);
	if (!list_empty(&lock->wait_list)) {
		/* get the first entry from the wait-list: */
		struct mutex_waiter *waiter =
			list_first_entry(&lock->wait_list,
					 struct mutex_waiter, list);

		next = waiter->task;

		debug_mutex_wake_waiter(lock, waiter);
		wake_q_add(&wake_q, next);
	}

	if (owner & MUTEX_FLAG_HANDOFF)
		__mutex_handoff(lock, next);

	raw_spin_unlock(&lock->wait_lock);

	wake_up_q(&wake_q);
}

#ifndef CONFIG_DEBUG_LOCK_ALLOC
static noinline int __sched
__mutex_lock_killable_slowpath(struct mutex *lock);

static noinline int __sched
__mutex_lock_interruptible_slowpath(struct mutex *lock);

int __sched mutex_lock_interruptible(struct mutex *lock)
{
	might_sleep();

	if (__mutex_trylock_fast(lock))
		return 0;

	return __mutex_lock_interruptible_slowpath(lock);
}

EXPORT_SYMBOL(mutex_lock_interruptible);

int __sched mutex_lock_killable(struct mutex *lock)
{
	might_sleep();

	if (__mutex_trylock_fast(lock))
		return 0;

	return __mutex_lock_killable_slowpath(lock);
}
EXPORT_SYMBOL(mutex_lock_killable);

void __sched mutex_lock_io(struct mutex *lock)
{
	int token;

	token = io_schedule_prepare();
	mutex_lock(lock);
	io_schedule_finish(token);
}
EXPORT_SYMBOL_GPL(mutex_lock_io);

static noinline void __sched
__mutex_lock_slowpath(struct mutex *lock)
{
	__mutex_lock(lock, TASK_UNINTERRUPTIBLE, 0, NULL, _RET_IP_);
}

static noinline int __sched
__mutex_lock_killable_slowpath(struct mutex *lock)
{
	return __mutex_lock(lock, TASK_KILLABLE, 0, NULL, _RET_IP_);
}

static noinline int __sched
__mutex_lock_interruptible_slowpath(struct mutex *lock)
{
	return __mutex_lock(lock, TASK_INTERRUPTIBLE, 0, NULL, _RET_IP_);
}

static noinline int __sched
__ww_mutex_lock_slowpath(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	return __ww_mutex_lock(&lock->base, TASK_UNINTERRUPTIBLE, 0,
			       _RET_IP_, ctx);
}

static noinline int __sched
__ww_mutex_lock_interruptible_slowpath(struct ww_mutex *lock,
					    struct ww_acquire_ctx *ctx)
{
	return __ww_mutex_lock(&lock->base, TASK_INTERRUPTIBLE, 0,
			       _RET_IP_, ctx);
}

#endif

int __sched mutex_trylock(struct mutex *lock)
{
	bool locked;

	MUTEX_WARN_ON(lock->magic != lock);

	locked = __mutex_trylock(lock);
	if (locked)
		mutex_acquire(&lock->dep_map, 0, 1, _RET_IP_);

	return locked;
}
EXPORT_SYMBOL(mutex_trylock);

#ifndef CONFIG_DEBUG_LOCK_ALLOC
int __sched
ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	might_sleep();

	if (__mutex_trylock_fast(&lock->base)) {
		if (ctx)
			ww_mutex_set_context_fastpath(lock, ctx);
		return 0;
	}

	return __ww_mutex_lock_slowpath(lock, ctx);
}
EXPORT_SYMBOL(ww_mutex_lock);

int __sched
ww_mutex_lock_interruptible(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	might_sleep();

	if (__mutex_trylock_fast(&lock->base)) {
		if (ctx)
			ww_mutex_set_context_fastpath(lock, ctx);
		return 0;
	}

	return __ww_mutex_lock_interruptible_slowpath(lock, ctx);
}
EXPORT_SYMBOL(ww_mutex_lock_interruptible);

#endif /* !CONFIG_DEBUG_LOCK_ALLOC */
#endif /* !CONFIG_PREEMPT_RT */

int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock)
{
	/* dec if we can't possibly hit 0 */
	if (atomic_add_unless(cnt, -1, 1))
		return 0;
	/* we might hit 0, so take the lock */
	mutex_lock(lock);
	if (!atomic_dec_and_test(cnt)) {
		/* when we actually did the dec, we didn't hit 0 */
		mutex_unlock(lock);
		return 0;
	}
	/* we hit 0, and we hold the lock */
	return 1;
}
EXPORT_SYMBOL(atomic_dec_and_mutex_lock);
