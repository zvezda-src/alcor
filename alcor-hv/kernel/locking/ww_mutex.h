
#ifndef WW_RT

#define MUTEX		mutex
#define MUTEX_WAITER	mutex_waiter

static inline struct mutex_waiter *
__ww_waiter_first(struct mutex *lock)
{
	struct mutex_waiter *w;

	w = list_first_entry(&lock->wait_list, struct mutex_waiter, list);
	if (list_entry_is_head(w, &lock->wait_list, list))
		return NULL;

	return w;
}

static inline struct mutex_waiter *
__ww_waiter_next(struct mutex *lock, struct mutex_waiter *w)
{
	w = list_next_entry(w, list);
	if (list_entry_is_head(w, &lock->wait_list, list))
		return NULL;

	return w;
}

static inline struct mutex_waiter *
__ww_waiter_prev(struct mutex *lock, struct mutex_waiter *w)
{
	w = list_prev_entry(w, list);
	if (list_entry_is_head(w, &lock->wait_list, list))
		return NULL;

	return w;
}

static inline struct mutex_waiter *
__ww_waiter_last(struct mutex *lock)
{
	struct mutex_waiter *w;

	w = list_last_entry(&lock->wait_list, struct mutex_waiter, list);
	if (list_entry_is_head(w, &lock->wait_list, list))
		return NULL;

	return w;
}

static inline void
__ww_waiter_add(struct mutex *lock, struct mutex_waiter *waiter, struct mutex_waiter *pos)
{
	struct list_head *p = &lock->wait_list;
	if (pos)
		p = &pos->list;
	__mutex_add_waiter(lock, waiter, p);
}

static inline struct task_struct *
__ww_mutex_owner(struct mutex *lock)
{
	return __mutex_owner(lock);
}

static inline bool
__ww_mutex_has_waiters(struct mutex *lock)
{
	return atomic_long_read(&lock->owner) & MUTEX_FLAG_WAITERS;
}

static inline void lock_wait_lock(struct mutex *lock)
{
	raw_spin_lock(&lock->wait_lock);
}

static inline void unlock_wait_lock(struct mutex *lock)
{
	raw_spin_unlock(&lock->wait_lock);
}

static inline void lockdep_assert_wait_lock_held(struct mutex *lock)
{
	lockdep_assert_held(&lock->wait_lock);
}

#else /* WW_RT */

#define MUTEX		rt_mutex
#define MUTEX_WAITER	rt_mutex_waiter

static inline struct rt_mutex_waiter *
__ww_waiter_first(struct rt_mutex *lock)
{
	struct rb_node *n = rb_first(&lock->rtmutex.waiters.rb_root);
	if (!n)
		return NULL;
	return rb_entry(n, struct rt_mutex_waiter, tree_entry);
}

static inline struct rt_mutex_waiter *
__ww_waiter_next(struct rt_mutex *lock, struct rt_mutex_waiter *w)
{
	struct rb_node *n = rb_next(&w->tree_entry);
	if (!n)
		return NULL;
	return rb_entry(n, struct rt_mutex_waiter, tree_entry);
}

static inline struct rt_mutex_waiter *
__ww_waiter_prev(struct rt_mutex *lock, struct rt_mutex_waiter *w)
{
	struct rb_node *n = rb_prev(&w->tree_entry);
	if (!n)
		return NULL;
	return rb_entry(n, struct rt_mutex_waiter, tree_entry);
}

static inline struct rt_mutex_waiter *
__ww_waiter_last(struct rt_mutex *lock)
{
	struct rb_node *n = rb_last(&lock->rtmutex.waiters.rb_root);
	if (!n)
		return NULL;
	return rb_entry(n, struct rt_mutex_waiter, tree_entry);
}

static inline void
__ww_waiter_add(struct rt_mutex *lock, struct rt_mutex_waiter *waiter, struct rt_mutex_waiter *pos)
{
	/* RT unconditionally adds the waiter first and then removes it on error */
}

static inline struct task_struct *
__ww_mutex_owner(struct rt_mutex *lock)
{
	return rt_mutex_owner(&lock->rtmutex);
}

static inline bool
__ww_mutex_has_waiters(struct rt_mutex *lock)
{
	return rt_mutex_has_waiters(&lock->rtmutex);
}

static inline void lock_wait_lock(struct rt_mutex *lock)
{
	raw_spin_lock(&lock->rtmutex.wait_lock);
}

static inline void unlock_wait_lock(struct rt_mutex *lock)
{
	raw_spin_unlock(&lock->rtmutex.wait_lock);
}

static inline void lockdep_assert_wait_lock_held(struct rt_mutex *lock)
{
	lockdep_assert_held(&lock->rtmutex.wait_lock);
}

#endif /* WW_RT */


static __always_inline void
ww_mutex_lock_acquired(struct ww_mutex *ww, struct ww_acquire_ctx *ww_ctx)
{
#ifdef DEBUG_WW_MUTEXES
	/*
	DEBUG_LOCKS_WARN_ON(ww->ctx);

	/*
	DEBUG_LOCKS_WARN_ON(ww_ctx->done_acquire);

	if (ww_ctx->contending_lock) {
		/*
		DEBUG_LOCKS_WARN_ON(ww_ctx->contending_lock != ww);

		/*
		DEBUG_LOCKS_WARN_ON(ww_ctx->acquired > 0);
		ww_ctx->contending_lock = NULL;
	}

	/*
	DEBUG_LOCKS_WARN_ON(ww_ctx->ww_class != ww->ww_class);
#endif
	ww_ctx->acquired++;
	ww->ctx = ww_ctx;
}

static inline bool
__ww_ctx_less(struct ww_acquire_ctx *a, struct ww_acquire_ctx *b)
{
#ifdef WW_RT
	/* kernel prio; less is more */
	int a_prio = a->task->prio;
	int b_prio = b->task->prio;

	if (rt_prio(a_prio) || rt_prio(b_prio)) {

		if (a_prio > b_prio)
			return true;

		if (a_prio < b_prio)
			return false;

		/* equal static prio */

		if (dl_prio(a_prio)) {
			if (dl_time_before(b->task->dl.deadline,
					   a->task->dl.deadline))
				return true;

			if (dl_time_before(a->task->dl.deadline,
					   b->task->dl.deadline))
				return false;
		}

		/* equal prio */
	}
#endif

	/* FIFO order tie break -- bigger is younger */
	return (signed long)(a->stamp - b->stamp) > 0;
}

static bool
__ww_mutex_die(struct MUTEX *lock, struct MUTEX_WAITER *waiter,
	       struct ww_acquire_ctx *ww_ctx)
{
	if (!ww_ctx->is_wait_die)
		return false;

	if (waiter->ww_ctx->acquired > 0 && __ww_ctx_less(waiter->ww_ctx, ww_ctx)) {
#ifndef WW_RT
		debug_mutex_wake_waiter(lock, waiter);
#endif
		wake_up_process(waiter->task);
	}

	return true;
}

static bool __ww_mutex_wound(struct MUTEX *lock,
			     struct ww_acquire_ctx *ww_ctx,
			     struct ww_acquire_ctx *hold_ctx)
{
	struct task_struct *owner = __ww_mutex_owner(lock);

	lockdep_assert_wait_lock_held(lock);

	/*
	if (!hold_ctx)
		return false;

	/*
	if (!owner)
		return false;

	if (ww_ctx->acquired > 0 && __ww_ctx_less(hold_ctx, ww_ctx)) {
		hold_ctx->wounded = 1;

		/*
		if (owner != current)
			wake_up_process(owner);

		return true;
	}

	return false;
}

static void
__ww_mutex_check_waiters(struct MUTEX *lock, struct ww_acquire_ctx *ww_ctx)
{
	struct MUTEX_WAITER *cur;

	lockdep_assert_wait_lock_held(lock);

	for (cur = __ww_waiter_first(lock); cur;
	     cur = __ww_waiter_next(lock, cur)) {

		if (!cur->ww_ctx)
			continue;

		if (__ww_mutex_die(lock, cur, ww_ctx) ||
		    __ww_mutex_wound(lock, cur->ww_ctx, ww_ctx))
			break;
	}
}

static __always_inline void
ww_mutex_set_context_fastpath(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
	ww_mutex_lock_acquired(lock, ctx);

	/*
	smp_mb(); /* See comments above and below. */

	/*
	if (likely(!__ww_mutex_has_waiters(&lock->base)))
		return;

	/*
	lock_wait_lock(&lock->base);
	__ww_mutex_check_waiters(&lock->base, ctx);
	unlock_wait_lock(&lock->base);
}

static __always_inline int
__ww_mutex_kill(struct MUTEX *lock, struct ww_acquire_ctx *ww_ctx)
{
	if (ww_ctx->acquired > 0) {
#ifdef DEBUG_WW_MUTEXES
		struct ww_mutex *ww;

		ww = container_of(lock, struct ww_mutex, base);
		DEBUG_LOCKS_WARN_ON(ww_ctx->contending_lock);
		ww_ctx->contending_lock = ww;
#endif
		return -EDEADLK;
	}

	return 0;
}

static inline int
__ww_mutex_check_kill(struct MUTEX *lock, struct MUTEX_WAITER *waiter,
		      struct ww_acquire_ctx *ctx)
{
	struct ww_mutex *ww = container_of(lock, struct ww_mutex, base);
	struct ww_acquire_ctx *hold_ctx = READ_ONCE(ww->ctx);
	struct MUTEX_WAITER *cur;

	if (ctx->acquired == 0)
		return 0;

	if (!ctx->is_wait_die) {
		if (ctx->wounded)
			return __ww_mutex_kill(lock, ctx);

		return 0;
	}

	if (hold_ctx && __ww_ctx_less(ctx, hold_ctx))
		return __ww_mutex_kill(lock, ctx);

	/*
	for (cur = __ww_waiter_prev(lock, waiter); cur;
	     cur = __ww_waiter_prev(lock, cur)) {

		if (!cur->ww_ctx)
			continue;

		return __ww_mutex_kill(lock, ctx);
	}

	return 0;
}

static inline int
__ww_mutex_add_waiter(struct MUTEX_WAITER *waiter,
		      struct MUTEX *lock,
		      struct ww_acquire_ctx *ww_ctx)
{
	struct MUTEX_WAITER *cur, *pos = NULL;
	bool is_wait_die;

	if (!ww_ctx) {
		__ww_waiter_add(lock, waiter, NULL);
		return 0;
	}

	is_wait_die = ww_ctx->is_wait_die;

	/*
	for (cur = __ww_waiter_last(lock); cur;
	     cur = __ww_waiter_prev(lock, cur)) {

		if (!cur->ww_ctx)
			continue;

		if (__ww_ctx_less(ww_ctx, cur->ww_ctx)) {
			/*
			if (is_wait_die) {
				int ret = __ww_mutex_kill(lock, ww_ctx);

				if (ret)
					return ret;
			}

			break;
		}

		pos = cur;

		/* Wait-Die: ensure younger waiters die. */
		__ww_mutex_die(lock, cur, ww_ctx);
	}

	__ww_waiter_add(lock, waiter, pos);

	/*
	if (!is_wait_die) {
		struct ww_mutex *ww = container_of(lock, struct ww_mutex, base);

		/*
		smp_mb();
		__ww_mutex_wound(lock, ww_ctx, ww->ctx);
	}

	return 0;
}

static inline void __ww_mutex_unlock(struct ww_mutex *lock)
{
	if (lock->ctx) {
#ifdef DEBUG_WW_MUTEXES
		DEBUG_LOCKS_WARN_ON(!lock->ctx->acquired);
#endif
		if (lock->ctx->acquired > 0)
			lock->ctx->acquired--;
		lock->ctx = NULL;
	}
}
