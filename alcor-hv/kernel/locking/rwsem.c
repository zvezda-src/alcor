
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#include <linux/sched/debug.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/signal.h>
#include <linux/sched/clock.h>
#include <linux/export.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>
#include <trace/events/lock.h>

#ifndef CONFIG_PREEMPT_RT
#include "lock_events.h"

#define RWSEM_READER_OWNED	(1UL << 0)
#define RWSEM_NONSPINNABLE	(1UL << 1)
#define RWSEM_OWNER_FLAGS_MASK	(RWSEM_READER_OWNED | RWSEM_NONSPINNABLE)

#ifdef CONFIG_DEBUG_RWSEMS
# define DEBUG_RWSEMS_WARN_ON(c, sem)	do {			\
	if (!debug_locks_silent &&				\
	    WARN_ONCE(c, "DEBUG_RWSEMS_WARN_ON(%s): count = 0x%lx, magic = 0x%lx, owner = 0x%lx, curr 0x%lx, list %sempty\n",\
		#c, atomic_long_read(&(sem)->count),		\
		(unsigned long) sem->magic,			\
		atomic_long_read(&(sem)->owner), (long)current,	\
		list_empty(&(sem)->wait_list) ? "" : "not "))	\
			debug_locks_off();			\
	} while (0)
#else
# define DEBUG_RWSEMS_WARN_ON(c, sem)
#endif

#define RWSEM_WRITER_LOCKED	(1UL << 0)
#define RWSEM_FLAG_WAITERS	(1UL << 1)
#define RWSEM_FLAG_HANDOFF	(1UL << 2)
#define RWSEM_FLAG_READFAIL	(1UL << (BITS_PER_LONG - 1))

#define RWSEM_READER_SHIFT	8
#define RWSEM_READER_BIAS	(1UL << RWSEM_READER_SHIFT)
#define RWSEM_READER_MASK	(~(RWSEM_READER_BIAS - 1))
#define RWSEM_WRITER_MASK	RWSEM_WRITER_LOCKED
#define RWSEM_LOCK_MASK		(RWSEM_WRITER_MASK|RWSEM_READER_MASK)
#define RWSEM_READ_FAILED_MASK	(RWSEM_WRITER_MASK|RWSEM_FLAG_WAITERS|\
				 RWSEM_FLAG_HANDOFF|RWSEM_FLAG_READFAIL)

static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
	atomic_long_set(&sem->owner, (long)current);
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
	atomic_long_set(&sem->owner, 0);
}

static inline bool rwsem_test_oflags(struct rw_semaphore *sem, long flags)
{
	return atomic_long_read(&sem->owner) & flags;
}

static inline void __rwsem_set_reader_owned(struct rw_semaphore *sem,
					    struct task_struct *owner)
{
	unsigned long val = (unsigned long)owner | RWSEM_READER_OWNED |
		(atomic_long_read(&sem->owner) & RWSEM_NONSPINNABLE);

	atomic_long_set(&sem->owner, val);
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
	__rwsem_set_reader_owned(sem, current);
}

static inline bool is_rwsem_reader_owned(struct rw_semaphore *sem)
{
#ifdef CONFIG_DEBUG_RWSEMS
	/*
	long count = atomic_long_read(&sem->count);

	if (count & RWSEM_WRITER_MASK)
		return false;
#endif
	return rwsem_test_oflags(sem, RWSEM_READER_OWNED);
}

#ifdef CONFIG_DEBUG_RWSEMS
static inline void rwsem_clear_reader_owned(struct rw_semaphore *sem)
{
	unsigned long val = atomic_long_read(&sem->owner);

	while ((val & ~RWSEM_OWNER_FLAGS_MASK) == (unsigned long)current) {
		if (atomic_long_try_cmpxchg(&sem->owner, &val,
					    val & RWSEM_OWNER_FLAGS_MASK))
			return;
	}
}
#else
static inline void rwsem_clear_reader_owned(struct rw_semaphore *sem)
{
}
#endif

static inline void rwsem_set_nonspinnable(struct rw_semaphore *sem)
{
	unsigned long owner = atomic_long_read(&sem->owner);

	do {
		if (!(owner & RWSEM_READER_OWNED))
			break;
		if (owner & RWSEM_NONSPINNABLE)
			break;
	} while (!atomic_long_try_cmpxchg(&sem->owner, &owner,
					  owner | RWSEM_NONSPINNABLE));
}

static inline bool rwsem_read_trylock(struct rw_semaphore *sem, long *cntp)
{

	if (WARN_ON_ONCE(*cntp < 0))
		rwsem_set_nonspinnable(sem);

	if (!(*cntp & RWSEM_READ_FAILED_MASK)) {
		rwsem_set_reader_owned(sem);
		return true;
	}

	return false;
}

static inline bool rwsem_write_trylock(struct rw_semaphore *sem)
{
	long tmp = RWSEM_UNLOCKED_VALUE;

	if (atomic_long_try_cmpxchg_acquire(&sem->count, &tmp, RWSEM_WRITER_LOCKED)) {
		rwsem_set_owner(sem);
		return true;
	}

	return false;
}

static inline struct task_struct *rwsem_owner(struct rw_semaphore *sem)
{
	return (struct task_struct *)
		(atomic_long_read(&sem->owner) & ~RWSEM_OWNER_FLAGS_MASK);
}

static inline struct task_struct *
rwsem_owner_flags(struct rw_semaphore *sem, unsigned long *pflags)
{
	unsigned long owner = atomic_long_read(&sem->owner);

	return (struct task_struct *)(owner & ~RWSEM_OWNER_FLAGS_MASK);
}


void __init_rwsem(struct rw_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map_wait(&sem->dep_map, name, key, 0, LD_WAIT_SLEEP);
#endif
#ifdef CONFIG_DEBUG_RWSEMS
	sem->magic = sem;
#endif
	atomic_long_set(&sem->count, RWSEM_UNLOCKED_VALUE);
	raw_spin_lock_init(&sem->wait_lock);
	INIT_LIST_HEAD(&sem->wait_list);
	atomic_long_set(&sem->owner, 0L);
#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
	osq_lock_init(&sem->osq);
#endif
}
EXPORT_SYMBOL(__init_rwsem);

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE,
	RWSEM_WAITING_FOR_READ
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
	unsigned long timeout;
	bool handoff_set;
};
#define rwsem_first_waiter(sem) \
	list_first_entry(&sem->wait_list, struct rwsem_waiter, list)

enum rwsem_wake_type {
	RWSEM_WAKE_ANY,		/* Wake whatever's at head of wait list */
	RWSEM_WAKE_READERS,	/* Wake readers only */
	RWSEM_WAKE_READ_OWNED	/* Waker thread holds the read lock */
};

#define RWSEM_WAIT_TIMEOUT	DIV_ROUND_UP(HZ, 250)

#define MAX_READERS_WAKEUP	0x100

static inline void
rwsem_add_waiter(struct rw_semaphore *sem, struct rwsem_waiter *waiter)
{
	lockdep_assert_held(&sem->wait_lock);
	list_add_tail(&waiter->list, &sem->wait_list);
	/* caller will set RWSEM_FLAG_WAITERS */
}

static inline bool
rwsem_del_waiter(struct rw_semaphore *sem, struct rwsem_waiter *waiter)
{
	lockdep_assert_held(&sem->wait_lock);
	list_del(&waiter->list);
	if (likely(!list_empty(&sem->wait_list)))
		return true;

	atomic_long_andnot(RWSEM_FLAG_HANDOFF | RWSEM_FLAG_WAITERS, &sem->count);
	return false;
}

static void rwsem_mark_wake(struct rw_semaphore *sem,
			    enum rwsem_wake_type wake_type,
			    struct wake_q_head *wake_q)
{
	struct rwsem_waiter *waiter, *tmp;
	long oldcount, woken = 0, adjustment = 0;
	struct list_head wlist;

	lockdep_assert_held(&sem->wait_lock);

	/*
	waiter = rwsem_first_waiter(sem);

	if (waiter->type == RWSEM_WAITING_FOR_WRITE) {
		if (wake_type == RWSEM_WAKE_ANY) {
			/*
			wake_q_add(wake_q, waiter->task);
			lockevent_inc(rwsem_wake_writer);
		}

		return;
	}

	/*
	if (unlikely(atomic_long_read(&sem->count) < 0))
		return;

	/*
	if (wake_type != RWSEM_WAKE_READ_OWNED) {
		struct task_struct *owner;

		adjustment = RWSEM_READER_BIAS;
		oldcount = atomic_long_fetch_add(adjustment, &sem->count);
		if (unlikely(oldcount & RWSEM_WRITER_MASK)) {
			/*
			if (time_after(jiffies, waiter->timeout)) {
				if (!(oldcount & RWSEM_FLAG_HANDOFF)) {
					adjustment -= RWSEM_FLAG_HANDOFF;
					lockevent_inc(rwsem_rlock_handoff);
				}
				waiter->handoff_set = true;
			}

			atomic_long_add(-adjustment, &sem->count);
			return;
		}
		/*
		owner = waiter->task;
		__rwsem_set_reader_owned(sem, owner);
	}

	/*
	INIT_LIST_HEAD(&wlist);
	list_for_each_entry_safe(waiter, tmp, &sem->wait_list, list) {
		if (waiter->type == RWSEM_WAITING_FOR_WRITE)
			continue;

		woken++;
		list_move_tail(&waiter->list, &wlist);

		/*
		if (unlikely(woken >= MAX_READERS_WAKEUP))
			break;
	}

	adjustment = woken * RWSEM_READER_BIAS - adjustment;
	lockevent_cond_inc(rwsem_wake_reader, woken);

	oldcount = atomic_long_read(&sem->count);
	if (list_empty(&sem->wait_list)) {
		/*
		adjustment -= RWSEM_FLAG_WAITERS;
		if (oldcount & RWSEM_FLAG_HANDOFF)
			adjustment -= RWSEM_FLAG_HANDOFF;
	} else if (woken) {
		/*
		if (oldcount & RWSEM_FLAG_HANDOFF)
			adjustment -= RWSEM_FLAG_HANDOFF;
	}

	if (adjustment)
		atomic_long_add(adjustment, &sem->count);

	/* 2nd pass */
	list_for_each_entry_safe(waiter, tmp, &wlist, list) {
		struct task_struct *tsk;

		tsk = waiter->task;
		get_task_struct(tsk);

		/*
		smp_store_release(&waiter->task, NULL);
		/*
		wake_q_add_safe(wake_q, tsk);
	}
}

static inline void
rwsem_del_wake_waiter(struct rw_semaphore *sem, struct rwsem_waiter *waiter,
		      struct wake_q_head *wake_q)
		      __releases(&sem->wait_lock)
{
	bool first = rwsem_first_waiter(sem) == waiter;

	wake_q_init(wake_q);

	/*
	if (rwsem_del_waiter(sem, waiter) && first)
		rwsem_mark_wake(sem, RWSEM_WAKE_ANY, wake_q);
	raw_spin_unlock_irq(&sem->wait_lock);
	if (!wake_q_empty(wake_q))
		wake_up_q(wake_q);
}

static inline bool rwsem_try_write_lock(struct rw_semaphore *sem,
					struct rwsem_waiter *waiter)
{
	struct rwsem_waiter *first = rwsem_first_waiter(sem);
	long count, new;

	lockdep_assert_held(&sem->wait_lock);

	count = atomic_long_read(&sem->count);
	do {
		bool has_handoff = !!(count & RWSEM_FLAG_HANDOFF);

		if (has_handoff) {
			/*
			if (first->handoff_set && (waiter != first))
				return false;

			/*
			if (waiter == first)
				waiter->handoff_set = true;
		}

		new = count;

		if (count & RWSEM_LOCK_MASK) {
			if (has_handoff || (!rt_task(waiter->task) &&
					    !time_after(jiffies, waiter->timeout)))
				return false;

			new |= RWSEM_FLAG_HANDOFF;
		} else {
			new |= RWSEM_WRITER_LOCKED;
			new &= ~RWSEM_FLAG_HANDOFF;

			if (list_is_singular(&sem->wait_list))
				new &= ~RWSEM_FLAG_WAITERS;
		}
	} while (!atomic_long_try_cmpxchg_acquire(&sem->count, &count, new));

	/*
	if (new & RWSEM_FLAG_HANDOFF) {
		waiter->handoff_set = true;
		lockevent_inc(rwsem_wlock_handoff);
		return false;
	}

	/*
	list_del(&waiter->list);
	rwsem_set_owner(sem);
	return true;
}

enum owner_state {
	OWNER_NULL		= 1 << 0,
	OWNER_WRITER		= 1 << 1,
	OWNER_READER		= 1 << 2,
	OWNER_NONSPINNABLE	= 1 << 3,
};

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
static inline bool rwsem_try_write_lock_unqueued(struct rw_semaphore *sem)
{
	long count = atomic_long_read(&sem->count);

	while (!(count & (RWSEM_LOCK_MASK|RWSEM_FLAG_HANDOFF))) {
		if (atomic_long_try_cmpxchg_acquire(&sem->count, &count,
					count | RWSEM_WRITER_LOCKED)) {
			rwsem_set_owner(sem);
			lockevent_inc(rwsem_opt_lock);
			return true;
		}
	}
	return false;
}

static inline bool rwsem_can_spin_on_owner(struct rw_semaphore *sem)
{
	struct task_struct *owner;
	unsigned long flags;
	bool ret = true;

	if (need_resched()) {
		lockevent_inc(rwsem_opt_fail);
		return false;
	}

	preempt_disable();
	/*
	owner = rwsem_owner_flags(sem, &flags);
	/*
	if ((flags & RWSEM_NONSPINNABLE) ||
	    (owner && !(flags & RWSEM_READER_OWNED) && !owner_on_cpu(owner)))
		ret = false;
	preempt_enable();

	lockevent_cond_inc(rwsem_opt_fail, !ret);
	return ret;
}

#define OWNER_SPINNABLE		(OWNER_NULL | OWNER_WRITER | OWNER_READER)

static inline enum owner_state
rwsem_owner_state(struct task_struct *owner, unsigned long flags)
{
	if (flags & RWSEM_NONSPINNABLE)
		return OWNER_NONSPINNABLE;

	if (flags & RWSEM_READER_OWNED)
		return OWNER_READER;

	return owner ? OWNER_WRITER : OWNER_NULL;
}

static noinline enum owner_state
rwsem_spin_on_owner(struct rw_semaphore *sem)
{
	struct task_struct *new, *owner;
	unsigned long flags, new_flags;
	enum owner_state state;

	lockdep_assert_preemption_disabled();

	owner = rwsem_owner_flags(sem, &flags);
	state = rwsem_owner_state(owner, flags);
	if (state != OWNER_WRITER)
		return state;

	for (;;) {
		/*
		new = rwsem_owner_flags(sem, &new_flags);
		if ((new != owner) || (new_flags != flags)) {
			state = rwsem_owner_state(new, new_flags);
			break;
		}

		/*
		barrier();

		if (need_resched() || !owner_on_cpu(owner)) {
			state = OWNER_NONSPINNABLE;
			break;
		}

		cpu_relax();
	}

	return state;
}

static inline u64 rwsem_rspin_threshold(struct rw_semaphore *sem)
{
	long count = atomic_long_read(&sem->count);
	int readers = count >> RWSEM_READER_SHIFT;
	u64 delta;

	if (readers > 30)
		readers = 30;
	delta = (20 + readers) * NSEC_PER_USEC / 2;

	return sched_clock() + delta;
}

static bool rwsem_optimistic_spin(struct rw_semaphore *sem)
{
	bool taken = false;
	int prev_owner_state = OWNER_NULL;
	int loop = 0;
	u64 rspin_threshold = 0;

	preempt_disable();

	/* sem->wait_lock should not be held when doing optimistic spinning */
	if (!osq_lock(&sem->osq))
		goto done;

	/*
	for (;;) {
		enum owner_state owner_state;

		owner_state = rwsem_spin_on_owner(sem);
		if (!(owner_state & OWNER_SPINNABLE))
			break;

		/*
		taken = rwsem_try_write_lock_unqueued(sem);

		if (taken)
			break;

		/*
		if (owner_state == OWNER_READER) {
			/*
			if (prev_owner_state != OWNER_READER) {
				if (rwsem_test_oflags(sem, RWSEM_NONSPINNABLE))
					break;
				rspin_threshold = rwsem_rspin_threshold(sem);
				loop = 0;
			}

			/*
			else if (!(++loop & 0xf) && (sched_clock() > rspin_threshold)) {
				rwsem_set_nonspinnable(sem);
				lockevent_inc(rwsem_opt_nospin);
				break;
			}
		}

		/*
		if (owner_state != OWNER_WRITER) {
			if (need_resched())
				break;
			if (rt_task(current) &&
			   (prev_owner_state != OWNER_WRITER))
				break;
		}
		prev_owner_state = owner_state;

		/*
		cpu_relax();
	}
	osq_unlock(&sem->osq);
done:
	preempt_enable();
	lockevent_cond_inc(rwsem_opt_fail, !taken);
	return taken;
}

static inline void clear_nonspinnable(struct rw_semaphore *sem)
{
	if (unlikely(rwsem_test_oflags(sem, RWSEM_NONSPINNABLE)))
		atomic_long_andnot(RWSEM_NONSPINNABLE, &sem->owner);
}

#else
static inline bool rwsem_can_spin_on_owner(struct rw_semaphore *sem)
{
	return false;
}

static inline bool rwsem_optimistic_spin(struct rw_semaphore *sem)
{
	return false;
}

static inline void clear_nonspinnable(struct rw_semaphore *sem) { }

static inline enum owner_state
rwsem_spin_on_owner(struct rw_semaphore *sem)
{
	return OWNER_NONSPINNABLE;
}
#endif

static inline void rwsem_cond_wake_waiter(struct rw_semaphore *sem, long count,
					  struct wake_q_head *wake_q)
{
	enum rwsem_wake_type wake_type;

	if (count & RWSEM_WRITER_MASK)
		return;

	if (count & RWSEM_READER_MASK) {
		wake_type = RWSEM_WAKE_READERS;
	} else {
		wake_type = RWSEM_WAKE_ANY;
		clear_nonspinnable(sem);
	}
	rwsem_mark_wake(sem, wake_type, wake_q);
}

static struct rw_semaphore __sched *
rwsem_down_read_slowpath(struct rw_semaphore *sem, long count, unsigned int state)
{
	long adjustment = -RWSEM_READER_BIAS;
	long rcnt = (count >> RWSEM_READER_SHIFT);
	struct rwsem_waiter waiter;
	DEFINE_WAKE_Q(wake_q);

	/*
	if ((atomic_long_read(&sem->owner) & RWSEM_READER_OWNED) &&
	    (rcnt > 1) && !(count & RWSEM_WRITER_LOCKED))
		goto queue;

	/*
	if (!(count & (RWSEM_WRITER_LOCKED | RWSEM_FLAG_HANDOFF))) {
		rwsem_set_reader_owned(sem);
		lockevent_inc(rwsem_rlock_steal);

		/*
		if ((rcnt == 1) && (count & RWSEM_FLAG_WAITERS)) {
			raw_spin_lock_irq(&sem->wait_lock);
			if (!list_empty(&sem->wait_list))
				rwsem_mark_wake(sem, RWSEM_WAKE_READ_OWNED,
						&wake_q);
			raw_spin_unlock_irq(&sem->wait_lock);
			wake_up_q(&wake_q);
		}
		return sem;
	}

queue:
	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_READ;
	waiter.timeout = jiffies + RWSEM_WAIT_TIMEOUT;
	waiter.handoff_set = false;

	raw_spin_lock_irq(&sem->wait_lock);
	if (list_empty(&sem->wait_list)) {
		/*
		if (!(atomic_long_read(&sem->count) & RWSEM_WRITER_MASK)) {
			/* Provide lock ACQUIRE */
			smp_acquire__after_ctrl_dep();
			raw_spin_unlock_irq(&sem->wait_lock);
			rwsem_set_reader_owned(sem);
			lockevent_inc(rwsem_rlock_fast);
			return sem;
		}
		adjustment += RWSEM_FLAG_WAITERS;
	}
	rwsem_add_waiter(sem, &waiter);

	/* we're now waiting on the lock, but no longer actively locking */
	count = atomic_long_add_return(adjustment, &sem->count);

	rwsem_cond_wake_waiter(sem, count, &wake_q);
	raw_spin_unlock_irq(&sem->wait_lock);

	if (!wake_q_empty(&wake_q))
		wake_up_q(&wake_q);

	trace_contention_begin(sem, LCB_F_READ);

	/* wait to be given the lock */
	for (;;) {
		set_current_state(state);
		if (!smp_load_acquire(&waiter.task)) {
			/* Matches rwsem_mark_wake()'s smp_store_release(). */
			break;
		}
		if (signal_pending_state(state, current)) {
			raw_spin_lock_irq(&sem->wait_lock);
			if (waiter.task)
				goto out_nolock;
			raw_spin_unlock_irq(&sem->wait_lock);
			/* Ordered by sem->wait_lock against rwsem_mark_wake(). */
			break;
		}
		schedule();
		lockevent_inc(rwsem_sleep_reader);
	}

	__set_current_state(TASK_RUNNING);
	lockevent_inc(rwsem_rlock);
	trace_contention_end(sem, 0);
	return sem;

out_nolock:
	rwsem_del_wake_waiter(sem, &waiter, &wake_q);
	__set_current_state(TASK_RUNNING);
	lockevent_inc(rwsem_rlock_fail);
	trace_contention_end(sem, -EINTR);
	return ERR_PTR(-EINTR);
}

static struct rw_semaphore __sched *
rwsem_down_write_slowpath(struct rw_semaphore *sem, int state)
{
	struct rwsem_waiter waiter;
	DEFINE_WAKE_Q(wake_q);

	/* do optimistic spinning and steal lock if possible */
	if (rwsem_can_spin_on_owner(sem) && rwsem_optimistic_spin(sem)) {
		/* rwsem_optimistic_spin() implies ACQUIRE on success */
		return sem;
	}

	/*
	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_WRITE;
	waiter.timeout = jiffies + RWSEM_WAIT_TIMEOUT;
	waiter.handoff_set = false;

	raw_spin_lock_irq(&sem->wait_lock);
	rwsem_add_waiter(sem, &waiter);

	/* we're now waiting on the lock */
	if (rwsem_first_waiter(sem) != &waiter) {
		rwsem_cond_wake_waiter(sem, atomic_long_read(&sem->count),
				       &wake_q);
		if (!wake_q_empty(&wake_q)) {
			/*
			raw_spin_unlock_irq(&sem->wait_lock);
			wake_up_q(&wake_q);
			raw_spin_lock_irq(&sem->wait_lock);
		}
	} else {
		atomic_long_or(RWSEM_FLAG_WAITERS, &sem->count);
	}

	/* wait until we successfully acquire the lock */
	set_current_state(state);
	trace_contention_begin(sem, LCB_F_WRITE);

	for (;;) {
		if (rwsem_try_write_lock(sem, &waiter)) {
			/* rwsem_try_write_lock() implies ACQUIRE on success */
			break;
		}

		raw_spin_unlock_irq(&sem->wait_lock);

		if (signal_pending_state(state, current))
			goto out_nolock;

		/*
		if (waiter.handoff_set) {
			enum owner_state owner_state;

			preempt_disable();
			owner_state = rwsem_spin_on_owner(sem);
			preempt_enable();

			if (owner_state == OWNER_NULL)
				goto trylock_again;
		}

		schedule();
		lockevent_inc(rwsem_sleep_writer);
		set_current_state(state);
trylock_again:
		raw_spin_lock_irq(&sem->wait_lock);
	}
	__set_current_state(TASK_RUNNING);
	raw_spin_unlock_irq(&sem->wait_lock);
	lockevent_inc(rwsem_wlock);
	trace_contention_end(sem, 0);
	return sem;

out_nolock:
	__set_current_state(TASK_RUNNING);
	raw_spin_lock_irq(&sem->wait_lock);
	rwsem_del_wake_waiter(sem, &waiter, &wake_q);
	lockevent_inc(rwsem_wlock_fail);
	trace_contention_end(sem, -EINTR);
	return ERR_PTR(-EINTR);
}

static struct rw_semaphore *rwsem_wake(struct rw_semaphore *sem)
{
	unsigned long flags;
	DEFINE_WAKE_Q(wake_q);

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (!list_empty(&sem->wait_list))
		rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}

static struct rw_semaphore *rwsem_downgrade_wake(struct rw_semaphore *sem)
{
	unsigned long flags;
	DEFINE_WAKE_Q(wake_q);

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (!list_empty(&sem->wait_list))
		rwsem_mark_wake(sem, RWSEM_WAKE_READ_OWNED, &wake_q);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	wake_up_q(&wake_q);

	return sem;
}

static inline int __down_read_common(struct rw_semaphore *sem, int state)
{
	long count;

	if (!rwsem_read_trylock(sem, &count)) {
		if (IS_ERR(rwsem_down_read_slowpath(sem, count, state)))
			return -EINTR;
		DEBUG_RWSEMS_WARN_ON(!is_rwsem_reader_owned(sem), sem);
	}
	return 0;
}

static inline void __down_read(struct rw_semaphore *sem)
{
	__down_read_common(sem, TASK_UNINTERRUPTIBLE);
}

static inline int __down_read_interruptible(struct rw_semaphore *sem)
{
	return __down_read_common(sem, TASK_INTERRUPTIBLE);
}

static inline int __down_read_killable(struct rw_semaphore *sem)
{
	return __down_read_common(sem, TASK_KILLABLE);
}

static inline int __down_read_trylock(struct rw_semaphore *sem)
{
	long tmp;

	DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);

	tmp = atomic_long_read(&sem->count);
	while (!(tmp & RWSEM_READ_FAILED_MASK)) {
		if (atomic_long_try_cmpxchg_acquire(&sem->count, &tmp,
						    tmp + RWSEM_READER_BIAS)) {
			rwsem_set_reader_owned(sem);
			return 1;
		}
	}
	return 0;
}

static inline int __down_write_common(struct rw_semaphore *sem, int state)
{
	if (unlikely(!rwsem_write_trylock(sem))) {
		if (IS_ERR(rwsem_down_write_slowpath(sem, state)))
			return -EINTR;
	}

	return 0;
}

static inline void __down_write(struct rw_semaphore *sem)
{
	__down_write_common(sem, TASK_UNINTERRUPTIBLE);
}

static inline int __down_write_killable(struct rw_semaphore *sem)
{
	return __down_write_common(sem, TASK_KILLABLE);
}

static inline int __down_write_trylock(struct rw_semaphore *sem)
{
	DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);
	return rwsem_write_trylock(sem);
}

static inline void __up_read(struct rw_semaphore *sem)
{
	long tmp;

	DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);
	DEBUG_RWSEMS_WARN_ON(!is_rwsem_reader_owned(sem), sem);

	rwsem_clear_reader_owned(sem);
	tmp = atomic_long_add_return_release(-RWSEM_READER_BIAS, &sem->count);
	DEBUG_RWSEMS_WARN_ON(tmp < 0, sem);
	if (unlikely((tmp & (RWSEM_LOCK_MASK|RWSEM_FLAG_WAITERS)) ==
		      RWSEM_FLAG_WAITERS)) {
		clear_nonspinnable(sem);
		rwsem_wake(sem);
	}
}

static inline void __up_write(struct rw_semaphore *sem)
{
	long tmp;

	DEBUG_RWSEMS_WARN_ON(sem->magic != sem, sem);
	/*
	DEBUG_RWSEMS_WARN_ON((rwsem_owner(sem) != current) &&
			    !rwsem_test_oflags(sem, RWSEM_NONSPINNABLE), sem);

	rwsem_clear_owner(sem);
	tmp = atomic_long_fetch_add_release(-RWSEM_WRITER_LOCKED, &sem->count);
	if (unlikely(tmp & RWSEM_FLAG_WAITERS))
		rwsem_wake(sem);
}

static inline void __downgrade_write(struct rw_semaphore *sem)
{
	long tmp;

	/*
	DEBUG_RWSEMS_WARN_ON(rwsem_owner(sem) != current, sem);
	tmp = atomic_long_fetch_add_release(
		-RWSEM_WRITER_LOCKED+RWSEM_READER_BIAS, &sem->count);
	rwsem_set_reader_owned(sem);
	if (tmp & RWSEM_FLAG_WAITERS)
		rwsem_downgrade_wake(sem);
}

#else /* !CONFIG_PREEMPT_RT */

#define RT_MUTEX_BUILD_MUTEX
#include "rtmutex.c"

#define rwbase_set_and_save_current_state(state)	\
	set_current_state(state)

#define rwbase_restore_current_state()			\
	__set_current_state(TASK_RUNNING)

#define rwbase_rtmutex_lock_state(rtm, state)		\
	__rt_mutex_lock(rtm, state)

#define rwbase_rtmutex_slowlock_locked(rtm, state)	\
	__rt_mutex_slowlock_locked(rtm, NULL, state)

#define rwbase_rtmutex_unlock(rtm)			\
	__rt_mutex_unlock(rtm)

#define rwbase_rtmutex_trylock(rtm)			\
	__rt_mutex_trylock(rtm)

#define rwbase_signal_pending_state(state, current)	\
	signal_pending_state(state, current)

#define rwbase_schedule()				\
	schedule()

#include "rwbase_rt.c"

void __init_rwsem(struct rw_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
	init_rwbase_rt(&(sem)->rwbase);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map_wait(&sem->dep_map, name, key, 0, LD_WAIT_SLEEP);
#endif
}
EXPORT_SYMBOL(__init_rwsem);

static inline void __down_read(struct rw_semaphore *sem)
{
	rwbase_read_lock(&sem->rwbase, TASK_UNINTERRUPTIBLE);
}

static inline int __down_read_interruptible(struct rw_semaphore *sem)
{
	return rwbase_read_lock(&sem->rwbase, TASK_INTERRUPTIBLE);
}

static inline int __down_read_killable(struct rw_semaphore *sem)
{
	return rwbase_read_lock(&sem->rwbase, TASK_KILLABLE);
}

static inline int __down_read_trylock(struct rw_semaphore *sem)
{
	return rwbase_read_trylock(&sem->rwbase);
}

static inline void __up_read(struct rw_semaphore *sem)
{
	rwbase_read_unlock(&sem->rwbase, TASK_NORMAL);
}

static inline void __sched __down_write(struct rw_semaphore *sem)
{
	rwbase_write_lock(&sem->rwbase, TASK_UNINTERRUPTIBLE);
}

static inline int __sched __down_write_killable(struct rw_semaphore *sem)
{
	return rwbase_write_lock(&sem->rwbase, TASK_KILLABLE);
}

static inline int __down_write_trylock(struct rw_semaphore *sem)
{
	return rwbase_write_trylock(&sem->rwbase);
}

static inline void __up_write(struct rw_semaphore *sem)
{
	rwbase_write_unlock(&sem->rwbase);
}

static inline void __downgrade_write(struct rw_semaphore *sem)
{
	rwbase_write_downgrade(&sem->rwbase);
}

#define DEBUG_RWSEMS_WARN_ON(c, sem)

static inline void __rwsem_set_reader_owned(struct rw_semaphore *sem,
					    struct task_struct *owner)
{
}

static inline bool is_rwsem_reader_owned(struct rw_semaphore *sem)
{
	int count = atomic_read(&sem->rwbase.readers);

	return count < 0 && count != READER_BIAS;
}

#endif /* CONFIG_PREEMPT_RT */

void __sched down_read(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_read_trylock, __down_read);
}
EXPORT_SYMBOL(down_read);

int __sched down_read_interruptible(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_read_trylock, __down_read_interruptible)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_read_interruptible);

int __sched down_read_killable(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_read_trylock, __down_read_killable)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_read_killable);

int down_read_trylock(struct rw_semaphore *sem)
{
	int ret = __down_read_trylock(sem);

	if (ret == 1)
		rwsem_acquire_read(&sem->dep_map, 0, 1, _RET_IP_);
	return ret;
}
EXPORT_SYMBOL(down_read_trylock);

void __sched down_write(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
}
EXPORT_SYMBOL(down_write);

int __sched down_write_killable(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_write_trylock,
				  __down_write_killable)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_write_killable);

int down_write_trylock(struct rw_semaphore *sem)
{
	int ret = __down_write_trylock(sem);

	if (ret == 1)
		rwsem_acquire(&sem->dep_map, 0, 1, _RET_IP_);

	return ret;
}
EXPORT_SYMBOL(down_write_trylock);

void up_read(struct rw_semaphore *sem)
{
	rwsem_release(&sem->dep_map, _RET_IP_);
	__up_read(sem);
}
EXPORT_SYMBOL(up_read);

void up_write(struct rw_semaphore *sem)
{
	rwsem_release(&sem->dep_map, _RET_IP_);
	__up_write(sem);
}
EXPORT_SYMBOL(up_write);

void downgrade_write(struct rw_semaphore *sem)
{
	lock_downgrade(&sem->dep_map, _RET_IP_);
	__downgrade_write(sem);
}
EXPORT_SYMBOL(downgrade_write);

#ifdef CONFIG_DEBUG_LOCK_ALLOC

void down_read_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, subclass, 0, _RET_IP_);
	LOCK_CONTENDED(sem, __down_read_trylock, __down_read);
}
EXPORT_SYMBOL(down_read_nested);

int down_read_killable_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, subclass, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_read_trylock, __down_read_killable)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_read_killable_nested);

void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest)
{
	might_sleep();
	rwsem_acquire_nest(&sem->dep_map, 0, 0, nest, _RET_IP_);
	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
}
EXPORT_SYMBOL(_down_write_nest_lock);

void down_read_non_owner(struct rw_semaphore *sem)
{
	might_sleep();
	__down_read(sem);
	__rwsem_set_reader_owned(sem, NULL);
}
EXPORT_SYMBOL(down_read_non_owner);

void down_write_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, subclass, 0, _RET_IP_);
	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
}
EXPORT_SYMBOL(down_write_nested);

int __sched down_write_killable_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, subclass, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_write_trylock,
				  __down_write_killable)) {
		rwsem_release(&sem->dep_map, _RET_IP_);
		return -EINTR;
	}

	return 0;
}
EXPORT_SYMBOL(down_write_killable_nested);

void up_read_non_owner(struct rw_semaphore *sem)
{
	DEBUG_RWSEMS_WARN_ON(!is_rwsem_reader_owned(sem), sem);
	__up_read(sem);
}
EXPORT_SYMBOL(up_read_non_owner);

#endif
