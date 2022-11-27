

static __always_inline int rwbase_read_trylock(struct rwbase_rt *rwb)
{
	int r;

	/*
	for (r = atomic_read(&rwb->readers); r < 0;) {
		if (likely(atomic_try_cmpxchg_acquire(&rwb->readers, &r, r + 1)))
			return 1;
	}
	return 0;
}

static int __sched __rwbase_read_lock(struct rwbase_rt *rwb,
				      unsigned int state)
{
	struct rt_mutex_base *rtm = &rwb->rtmutex;
	int ret;

	raw_spin_lock_irq(&rtm->wait_lock);
	/*
	if (atomic_read(&rwb->readers) != WRITER_BIAS) {
		atomic_inc(&rwb->readers);
		raw_spin_unlock_irq(&rtm->wait_lock);
		return 0;
	}

	/*

	trace_contention_begin(rwb, LCB_F_RT | LCB_F_READ);

	/*
	ret = rwbase_rtmutex_slowlock_locked(rtm, state);

	/*
	if (!ret)
		atomic_inc(&rwb->readers);
	raw_spin_unlock_irq(&rtm->wait_lock);
	if (!ret)
		rwbase_rtmutex_unlock(rtm);

	trace_contention_end(rwb, ret);
	return ret;
}

static __always_inline int rwbase_read_lock(struct rwbase_rt *rwb,
					    unsigned int state)
{
	if (rwbase_read_trylock(rwb))
		return 0;

	return __rwbase_read_lock(rwb, state);
}

static void __sched __rwbase_read_unlock(struct rwbase_rt *rwb,
					 unsigned int state)
{
	struct rt_mutex_base *rtm = &rwb->rtmutex;
	struct task_struct *owner;
	DEFINE_RT_WAKE_Q(wqh);

	raw_spin_lock_irq(&rtm->wait_lock);
	/*
	owner = rt_mutex_owner(rtm);
	if (owner)
		rt_mutex_wake_q_add_task(&wqh, owner, state);

	/* Pairs with the preempt_enable in rt_mutex_wake_up_q() */
	preempt_disable();
	raw_spin_unlock_irq(&rtm->wait_lock);
	rt_mutex_wake_up_q(&wqh);
}

static __always_inline void rwbase_read_unlock(struct rwbase_rt *rwb,
					       unsigned int state)
{
	/*
	if (unlikely(atomic_dec_and_test(&rwb->readers)))
		__rwbase_read_unlock(rwb, state);
}

static inline void __rwbase_write_unlock(struct rwbase_rt *rwb, int bias,
					 unsigned long flags)
{
	struct rt_mutex_base *rtm = &rwb->rtmutex;

	/*
	(void)atomic_add_return_release(READER_BIAS - bias, &rwb->readers);
	raw_spin_unlock_irqrestore(&rtm->wait_lock, flags);
	rwbase_rtmutex_unlock(rtm);
}

static inline void rwbase_write_unlock(struct rwbase_rt *rwb)
{
	struct rt_mutex_base *rtm = &rwb->rtmutex;
	unsigned long flags;

	raw_spin_lock_irqsave(&rtm->wait_lock, flags);
	__rwbase_write_unlock(rwb, WRITER_BIAS, flags);
}

static inline void rwbase_write_downgrade(struct rwbase_rt *rwb)
{
	struct rt_mutex_base *rtm = &rwb->rtmutex;
	unsigned long flags;

	raw_spin_lock_irqsave(&rtm->wait_lock, flags);
	/* Release it and account current as reader */
	__rwbase_write_unlock(rwb, WRITER_BIAS - 1, flags);
}

static inline bool __rwbase_write_trylock(struct rwbase_rt *rwb)
{
	/* Can do without CAS because we're serialized by wait_lock. */
	lockdep_assert_held(&rwb->rtmutex.wait_lock);

	/*
	if (!atomic_read_acquire(&rwb->readers)) {
		atomic_set(&rwb->readers, WRITER_BIAS);
		return 1;
	}

	return 0;
}

static int __sched rwbase_write_lock(struct rwbase_rt *rwb,
				     unsigned int state)
{
	struct rt_mutex_base *rtm = &rwb->rtmutex;
	unsigned long flags;

	/* Take the rtmutex as a first step */
	if (rwbase_rtmutex_lock_state(rtm, state))
		return -EINTR;

	/* Force readers into slow path */
	atomic_sub(READER_BIAS, &rwb->readers);

	raw_spin_lock_irqsave(&rtm->wait_lock, flags);
	if (__rwbase_write_trylock(rwb))
		goto out_unlock;

	rwbase_set_and_save_current_state(state);
	trace_contention_begin(rwb, LCB_F_RT | LCB_F_WRITE);
	for (;;) {
		/* Optimized out for rwlocks */
		if (rwbase_signal_pending_state(state, current)) {
			rwbase_restore_current_state();
			__rwbase_write_unlock(rwb, 0, flags);
			trace_contention_end(rwb, -EINTR);
			return -EINTR;
		}

		if (__rwbase_write_trylock(rwb))
			break;

		raw_spin_unlock_irqrestore(&rtm->wait_lock, flags);
		rwbase_schedule();
		raw_spin_lock_irqsave(&rtm->wait_lock, flags);

		set_current_state(state);
	}
	rwbase_restore_current_state();
	trace_contention_end(rwb, 0);

out_unlock:
	raw_spin_unlock_irqrestore(&rtm->wait_lock, flags);
	return 0;
}

static inline int rwbase_write_trylock(struct rwbase_rt *rwb)
{
	struct rt_mutex_base *rtm = &rwb->rtmutex;
	unsigned long flags;

	if (!rwbase_rtmutex_trylock(rtm))
		return 0;

	atomic_sub(READER_BIAS, &rwb->readers);

	raw_spin_lock_irqsave(&rtm->wait_lock, flags);
	if (__rwbase_write_trylock(rwb)) {
		raw_spin_unlock_irqrestore(&rtm->wait_lock, flags);
		return 1;
	}
	__rwbase_write_unlock(rwb, 0, flags);
	return 0;
}
