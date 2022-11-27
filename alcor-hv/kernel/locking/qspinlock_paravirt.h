#ifndef _GEN_PV_LOCK_SLOWPATH
#error "do not include this file"
#endif

#include <linux/hash.h>
#include <linux/memblock.h>
#include <linux/debug_locks.h>


#define _Q_SLOW_VAL	(3U << _Q_LOCKED_OFFSET)

#define PV_PREV_CHECK_MASK	0xff

enum vcpu_state {
	vcpu_running = 0,
	vcpu_halted,		/* Used only in pv_wait_node */
	vcpu_hashed,		/* = pv_hash'ed + vcpu_halted */
};

struct pv_node {
	struct mcs_spinlock	mcs;
	int			cpu;
	u8			state;
};

#define queued_spin_trylock(l)	pv_hybrid_queued_unfair_trylock(l)
static inline bool pv_hybrid_queued_unfair_trylock(struct qspinlock *lock)
{
	/*
	for (;;) {
		int val = atomic_read(&lock->val);

		if (!(val & _Q_LOCKED_PENDING_MASK) &&
		   (cmpxchg_acquire(&lock->locked, 0, _Q_LOCKED_VAL) == 0)) {
			lockevent_inc(pv_lock_stealing);
			return true;
		}
		if (!(val & _Q_TAIL_MASK) || (val & _Q_PENDING_MASK))
			break;

		cpu_relax();
	}

	return false;
}

#if _Q_PENDING_BITS == 8
static __always_inline void set_pending(struct qspinlock *lock)
{
	WRITE_ONCE(lock->pending, 1);
}

static __always_inline int trylock_clear_pending(struct qspinlock *lock)
{
	return !READ_ONCE(lock->locked) &&
	       (cmpxchg_acquire(&lock->locked_pending, _Q_PENDING_VAL,
				_Q_LOCKED_VAL) == _Q_PENDING_VAL);
}
#else /* _Q_PENDING_BITS == 8 */
static __always_inline void set_pending(struct qspinlock *lock)
{
	atomic_or(_Q_PENDING_VAL, &lock->val);
}

static __always_inline int trylock_clear_pending(struct qspinlock *lock)
{
	int val = atomic_read(&lock->val);

	for (;;) {
		int old, new;

		if (val  & _Q_LOCKED_MASK)
			break;

		/*
		old = val;
		new = (val & ~_Q_PENDING_MASK) | _Q_LOCKED_VAL;
		val = atomic_cmpxchg_acquire(&lock->val, old, new);

		if (val == old)
			return 1;
	}
	return 0;
}
#endif /* _Q_PENDING_BITS == 8 */

struct pv_hash_entry {
	struct qspinlock *lock;
	struct pv_node   *node;
};

#define PV_HE_PER_LINE	(SMP_CACHE_BYTES / sizeof(struct pv_hash_entry))
#define PV_HE_MIN	(PAGE_SIZE / sizeof(struct pv_hash_entry))

static struct pv_hash_entry *pv_lock_hash;
static unsigned int pv_lock_hash_bits __read_mostly;

void __init __pv_init_lock_hash(void)
{
	int pv_hash_size = ALIGN(4 * num_possible_cpus(), PV_HE_PER_LINE);

	if (pv_hash_size < PV_HE_MIN)
		pv_hash_size = PV_HE_MIN;

	/*
	pv_lock_hash = alloc_large_system_hash("PV qspinlock",
					       sizeof(struct pv_hash_entry),
					       pv_hash_size, 0,
					       HASH_EARLY | HASH_ZERO,
					       &pv_lock_hash_bits, NULL,
					       pv_hash_size, pv_hash_size);
}

#define for_each_hash_entry(he, offset, hash)						\
	for (hash &= ~(PV_HE_PER_LINE - 1), he = &pv_lock_hash[hash], offset = 0;	\
	     offset < (1 << pv_lock_hash_bits);						\
	     offset++, he = &pv_lock_hash[(hash + offset) & ((1 << pv_lock_hash_bits) - 1)])

static struct qspinlock **pv_hash(struct qspinlock *lock, struct pv_node *node)
{
	unsigned long offset, hash = hash_ptr(lock, pv_lock_hash_bits);
	struct pv_hash_entry *he;
	int hopcnt = 0;

	for_each_hash_entry(he, offset, hash) {
		hopcnt++;
		if (!cmpxchg(&he->lock, NULL, lock)) {
			WRITE_ONCE(he->node, node);
			lockevent_pv_hop(hopcnt);
			return &he->lock;
		}
	}
	/*
	BUG();
}

static struct pv_node *pv_unhash(struct qspinlock *lock)
{
	unsigned long offset, hash = hash_ptr(lock, pv_lock_hash_bits);
	struct pv_hash_entry *he;
	struct pv_node *node;

	for_each_hash_entry(he, offset, hash) {
		if (READ_ONCE(he->lock) == lock) {
			node = READ_ONCE(he->node);
			WRITE_ONCE(he->lock, NULL);
			return node;
		}
	}
	/*
	BUG();
}

static inline bool
pv_wait_early(struct pv_node *prev, int loop)
{
	if ((loop & PV_PREV_CHECK_MASK) != 0)
		return false;

	return READ_ONCE(prev->state) != vcpu_running;
}

static void pv_init_node(struct mcs_spinlock *node)
{
	struct pv_node *pn = (struct pv_node *)node;

	BUILD_BUG_ON(sizeof(struct pv_node) > sizeof(struct qnode));

	pn->cpu = smp_processor_id();
	pn->state = vcpu_running;
}

static void pv_wait_node(struct mcs_spinlock *node, struct mcs_spinlock *prev)
{
	struct pv_node *pn = (struct pv_node *)node;
	struct pv_node *pp = (struct pv_node *)prev;
	int loop;
	bool wait_early;

	for (;;) {
		for (wait_early = false, loop = SPIN_THRESHOLD; loop; loop--) {
			if (READ_ONCE(node->locked))
				return;
			if (pv_wait_early(pp, loop)) {
				wait_early = true;
				break;
			}
			cpu_relax();
		}

		/*
		smp_store_mb(pn->state, vcpu_halted);

		if (!READ_ONCE(node->locked)) {
			lockevent_inc(pv_wait_node);
			lockevent_cond_inc(pv_wait_early, wait_early);
			pv_wait(&pn->state, vcpu_halted);
		}

		/*
		cmpxchg(&pn->state, vcpu_halted, vcpu_running);

		/*
		lockevent_cond_inc(pv_spurious_wakeup,
				  !READ_ONCE(node->locked));
	}

	/*
}

static void pv_kick_node(struct qspinlock *lock, struct mcs_spinlock *node)
{
	struct pv_node *pn = (struct pv_node *)node;

	/*
	smp_mb__before_atomic();
	if (cmpxchg_relaxed(&pn->state, vcpu_halted, vcpu_hashed)
	    != vcpu_halted)
		return;

	/*
	WRITE_ONCE(lock->locked, _Q_SLOW_VAL);
	(void)pv_hash(lock, pn);
}

static u32
pv_wait_head_or_lock(struct qspinlock *lock, struct mcs_spinlock *node)
{
	struct pv_node *pn = (struct pv_node *)node;
	struct qspinlock **lp = NULL;
	int waitcnt = 0;
	int loop;

	/*
	if (READ_ONCE(pn->state) == vcpu_hashed)
		lp = (struct qspinlock **)1;

	/*
	lockevent_inc(lock_slowpath);

	for (;; waitcnt++) {
		/*
		WRITE_ONCE(pn->state, vcpu_running);

		/*
		set_pending(lock);
		for (loop = SPIN_THRESHOLD; loop; loop--) {
			if (trylock_clear_pending(lock))
				goto gotlock;
			cpu_relax();
		}
		clear_pending(lock);


		if (!lp) { /* ONCE */
			lp = pv_hash(lock, pn);

			/*
			if (xchg(&lock->locked, _Q_SLOW_VAL) == 0) {
				/*
				WRITE_ONCE(lock->locked, _Q_LOCKED_VAL);
				WRITE_ONCE(*lp, NULL);
				goto gotlock;
			}
		}
		WRITE_ONCE(pn->state, vcpu_hashed);
		lockevent_inc(pv_wait_head);
		lockevent_cond_inc(pv_wait_again, waitcnt);
		pv_wait(&lock->locked, _Q_SLOW_VAL);

		/*
	}

	/*
gotlock:
	return (u32)(atomic_read(&lock->val) | _Q_LOCKED_VAL);
}

__visible void
__pv_queued_spin_unlock_slowpath(struct qspinlock *lock, u8 locked)
{
	struct pv_node *node;

	if (unlikely(locked != _Q_SLOW_VAL)) {
		WARN(!debug_locks_silent,
		     "pvqspinlock: lock 0x%lx has corrupted value 0x%x!\n",
		     (unsigned long)lock, atomic_read(&lock->val));
		return;
	}

	/*
	smp_rmb();

	/*
	node = pv_unhash(lock);

	/*
	smp_store_release(&lock->locked, 0);

	/*
	lockevent_inc(pv_kick_unlock);
	pv_kick(node->cpu);
}

#include <asm/qspinlock_paravirt.h>

#ifndef __pv_queued_spin_unlock
__visible void __pv_queued_spin_unlock(struct qspinlock *lock)
{
	u8 locked;

	/*
	locked = cmpxchg_release(&lock->locked, _Q_LOCKED_VAL, 0);
	if (likely(locked == _Q_LOCKED_VAL))
		return;

	__pv_queued_spin_unlock_slowpath(lock, locked);
}
#endif /* __pv_queued_spin_unlock */
