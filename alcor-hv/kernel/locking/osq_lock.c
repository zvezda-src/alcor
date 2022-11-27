#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/osq_lock.h>

static DEFINE_PER_CPU_SHARED_ALIGNED(struct optimistic_spin_node, osq_node);

static inline int encode_cpu(int cpu_nr)
{
	return cpu_nr + 1;
}

static inline int node_cpu(struct optimistic_spin_node *node)
{
	return node->cpu - 1;
}

static inline struct optimistic_spin_node *decode_cpu(int encoded_cpu_val)
{
	int cpu_nr = encoded_cpu_val - 1;

	return per_cpu_ptr(&osq_node, cpu_nr);
}

static inline struct optimistic_spin_node *
osq_wait_next(struct optimistic_spin_queue *lock,
	      struct optimistic_spin_node *node,
	      struct optimistic_spin_node *prev)
{
	struct optimistic_spin_node *next = NULL;
	int curr = encode_cpu(smp_processor_id());
	int old;

	/*
	old = prev ? prev->cpu : OSQ_UNLOCKED_VAL;

	for (;;) {
		if (atomic_read(&lock->tail) == curr &&
		    atomic_cmpxchg_acquire(&lock->tail, curr, old) == curr) {
			/*
			break;
		}

		/*
		if (node->next) {
			next = xchg(&node->next, NULL);
			if (next)
				break;
		}

		cpu_relax();
	}

	return next;
}

bool osq_lock(struct optimistic_spin_queue *lock)
{
	struct optimistic_spin_node *node = this_cpu_ptr(&osq_node);
	struct optimistic_spin_node *prev, *next;
	int curr = encode_cpu(smp_processor_id());
	int old;

	node->locked = 0;
	node->next = NULL;
	node->cpu = curr;

	/*
	old = atomic_xchg(&lock->tail, curr);
	if (old == OSQ_UNLOCKED_VAL)
		return true;

	prev = decode_cpu(old);
	node->prev = prev;

	/*
	smp_wmb();

	WRITE_ONCE(prev->next, node);

	/*

	/*
	if (smp_cond_load_relaxed(&node->locked, VAL || need_resched() ||
				  vcpu_is_preempted(node_cpu(node->prev))))
		return true;

	/* unqueue */
	/*

	for (;;) {
		/*
		if (data_race(prev->next) == node &&
		    cmpxchg(&prev->next, node, NULL) == node)
			break;

		/*
		if (smp_load_acquire(&node->locked))
			return true;

		cpu_relax();

		/*
		prev = READ_ONCE(node->prev);
	}

	/*

	next = osq_wait_next(lock, node, prev);
	if (!next)
		return false;

	/*

	WRITE_ONCE(next->prev, prev);
	WRITE_ONCE(prev->next, next);

	return false;
}

void osq_unlock(struct optimistic_spin_queue *lock)
{
	struct optimistic_spin_node *node, *next;
	int curr = encode_cpu(smp_processor_id());

	/*
	if (likely(atomic_cmpxchg_release(&lock->tail, curr,
					  OSQ_UNLOCKED_VAL) == curr))
		return;

	/*
	node = this_cpu_ptr(&osq_node);
	next = xchg(&node->next, NULL);
	if (next) {
		WRITE_ONCE(next->locked, 1);
		return;
	}

	next = osq_wait_next(lock, node, NULL);
	if (next)
		WRITE_ONCE(next->locked, 1);
}
