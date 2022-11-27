#include <linux/compat.h>
#include <linux/jhash.h>
#include <linux/pagemap.h>
#include <linux/memblock.h>
#include <linux/fault-inject.h>
#include <linux/slab.h>

#include "futex.h"
#include "../locking/rtmutex_common.h"

static struct {
	struct futex_hash_bucket *queues;
	unsigned long            hashsize;
} __futex_data __read_mostly __aligned(2*sizeof(long));
#define futex_queues   (__futex_data.queues)
#define futex_hashsize (__futex_data.hashsize)


#ifdef CONFIG_FAIL_FUTEX

static struct {
	struct fault_attr attr;

	bool ignore_private;
} fail_futex = {
	.attr = FAULT_ATTR_INITIALIZER,
	.ignore_private = false,
};

static int __init setup_fail_futex(char *str)
{
	return setup_fault_attr(&fail_futex.attr, str);
}
__setup("fail_futex=", setup_fail_futex);

bool should_fail_futex(bool fshared)
{
	if (fail_futex.ignore_private && !fshared)
		return false;

	return should_fail(&fail_futex.attr, 1);
}

#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS

static int __init fail_futex_debugfs(void)
{
	umode_t mode = S_IFREG | S_IRUSR | S_IWUSR;
	struct dentry *dir;

	dir = fault_create_debugfs_attr("fail_futex", NULL,
					&fail_futex.attr);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	debugfs_create_bool("ignore-private", mode, dir,
			    &fail_futex.ignore_private);
	return 0;
}

late_initcall(fail_futex_debugfs);

#endif /* CONFIG_FAULT_INJECTION_DEBUG_FS */

#endif /* CONFIG_FAIL_FUTEX */

struct futex_hash_bucket *futex_hash(union futex_key *key)
{
	u32 hash = jhash2((u32 *)key, offsetof(typeof(*key), both.offset) / 4,
			  key->both.offset);

	return &futex_queues[hash & (futex_hashsize - 1)];
}


struct hrtimer_sleeper *
futex_setup_timer(ktime_t *time, struct hrtimer_sleeper *timeout,
		  int flags, u64 range_ns)
{
	if (!time)
		return NULL;

	hrtimer_init_sleeper_on_stack(timeout, (flags & FLAGS_CLOCKRT) ?
				      CLOCK_REALTIME : CLOCK_MONOTONIC,
				      HRTIMER_MODE_ABS);
	/*
	hrtimer_set_expires_range_ns(&timeout->timer, *time, range_ns);

	return timeout;
}

static u64 get_inode_sequence_number(struct inode *inode)
{
	static atomic64_t i_seq;
	u64 old;

	/* Does the inode already have a sequence number? */
	old = atomic64_read(&inode->i_sequence);
	if (likely(old))
		return old;

	for (;;) {
		u64 new = atomic64_add_return(1, &i_seq);
		if (WARN_ON_ONCE(!new))
			continue;

		old = atomic64_cmpxchg_relaxed(&inode->i_sequence, 0, new);
		if (old)
			return old;
		return new;
	}
}

int get_futex_key(u32 __user *uaddr, bool fshared, union futex_key *key,
		  enum futex_access rw)
{
	unsigned long address = (unsigned long)uaddr;
	struct mm_struct *mm = current->mm;
	struct page *page, *tail;
	struct address_space *mapping;
	int err, ro = 0;

	/*
	key->both.offset = address % PAGE_SIZE;
	if (unlikely((address % sizeof(u32)) != 0))
		return -EINVAL;
	address -= key->both.offset;

	if (unlikely(!access_ok(uaddr, sizeof(u32))))
		return -EFAULT;

	if (unlikely(should_fail_futex(fshared)))
		return -EFAULT;

	/*
	if (!fshared) {
		key->private.mm = mm;
		key->private.address = address;
		return 0;
	}

again:
	/* Ignore any VERIFY_READ mapping (futex common case) */
	if (unlikely(should_fail_futex(true)))
		return -EFAULT;

	err = get_user_pages_fast(address, 1, FOLL_WRITE, &page);
	/*
	if (err == -EFAULT && rw == FUTEX_READ) {
		err = get_user_pages_fast(address, 1, 0, &page);
		ro = 1;
	}
	if (err < 0)
		return err;
	else
		err = 0;

	/*
	tail = page;
	page = compound_head(page);
	mapping = READ_ONCE(page->mapping);

	/*
	if (unlikely(!mapping)) {
		int shmem_swizzled;

		/*
		lock_page(page);
		shmem_swizzled = PageSwapCache(page) || page->mapping;
		unlock_page(page);
		put_page(page);

		if (shmem_swizzled)
			goto again;

		return -EFAULT;
	}

	/*
	if (PageAnon(page)) {
		/*
		if (unlikely(should_fail_futex(true)) || ro) {
			err = -EFAULT;
			goto out;
		}

		key->both.offset |= FUT_OFF_MMSHARED; /* ref taken on mm */
		key->private.mm = mm;
		key->private.address = address;

	} else {
		struct inode *inode;

		/*
		rcu_read_lock();

		if (READ_ONCE(page->mapping) != mapping) {
			rcu_read_unlock();
			put_page(page);

			goto again;
		}

		inode = READ_ONCE(mapping->host);
		if (!inode) {
			rcu_read_unlock();
			put_page(page);

			goto again;
		}

		key->both.offset |= FUT_OFF_INODE; /* inode-based key */
		key->shared.i_seq = get_inode_sequence_number(inode);
		key->shared.pgoff = page_to_pgoff(tail);
		rcu_read_unlock();
	}

out:
	put_page(page);
	return err;
}

int fault_in_user_writeable(u32 __user *uaddr)
{
	struct mm_struct *mm = current->mm;
	int ret;

	mmap_read_lock(mm);
	ret = fixup_user_fault(mm, (unsigned long)uaddr,
			       FAULT_FLAG_WRITE, NULL);
	mmap_read_unlock(mm);

	return ret < 0 ? ret : 0;
}

struct futex_q *futex_top_waiter(struct futex_hash_bucket *hb, union futex_key *key)
{
	struct futex_q *this;

	plist_for_each_entry(this, &hb->chain, list) {
		if (futex_match(&this->key, key))
			return this;
	}
	return NULL;
}

int futex_cmpxchg_value_locked(u32 *curval, u32 __user *uaddr, u32 uval, u32 newval)
{
	int ret;

	pagefault_disable();
	ret = futex_atomic_cmpxchg_inatomic(curval, uaddr, uval, newval);
	pagefault_enable();

	return ret;
}

int futex_get_value_locked(u32 *dest, u32 __user *from)
{
	int ret;

	pagefault_disable();
	ret = __get_user(*dest, from);
	pagefault_enable();

	return ret ? -EFAULT : 0;
}

void wait_for_owner_exiting(int ret, struct task_struct *exiting)
{
	if (ret != -EBUSY) {
		WARN_ON_ONCE(exiting);
		return;
	}

	if (WARN_ON_ONCE(ret == -EBUSY && !exiting))
		return;

	mutex_lock(&exiting->futex_exit_mutex);
	/*
	mutex_unlock(&exiting->futex_exit_mutex);

	put_task_struct(exiting);
}

void __futex_unqueue(struct futex_q *q)
{
	struct futex_hash_bucket *hb;

	if (WARN_ON_SMP(!q->lock_ptr) || WARN_ON(plist_node_empty(&q->list)))
		return;
	lockdep_assert_held(q->lock_ptr);

	hb = container_of(q->lock_ptr, struct futex_hash_bucket, lock);
	plist_del(&q->list, &hb->chain);
	futex_hb_waiters_dec(hb);
}

struct futex_hash_bucket *futex_q_lock(struct futex_q *q)
	__acquires(&hb->lock)
{
	struct futex_hash_bucket *hb;

	hb = futex_hash(&q->key);

	/*
	futex_hb_waiters_inc(hb); /* implies smp_mb(); (A) */

	q->lock_ptr = &hb->lock;

	spin_lock(&hb->lock);
	return hb;
}

void futex_q_unlock(struct futex_hash_bucket *hb)
	__releases(&hb->lock)
{
	spin_unlock(&hb->lock);
	futex_hb_waiters_dec(hb);
}

void __futex_queue(struct futex_q *q, struct futex_hash_bucket *hb)
{
	int prio;

	/*
	prio = min(current->normal_prio, MAX_RT_PRIO);

	plist_node_init(&q->list, prio);
	plist_add(&q->list, &hb->chain);
	q->task = current;
}

int futex_unqueue(struct futex_q *q)
{
	spinlock_t *lock_ptr;
	int ret = 0;

	/* In the common case we don't take the spinlock, which is nice. */
retry:
	/*
	lock_ptr = READ_ONCE(q->lock_ptr);
	if (lock_ptr != NULL) {
		spin_lock(lock_ptr);
		/*
		if (unlikely(lock_ptr != q->lock_ptr)) {
			spin_unlock(lock_ptr);
			goto retry;
		}
		__futex_unqueue(q);

		BUG_ON(q->pi_state);

		spin_unlock(lock_ptr);
		ret = 1;
	}

	return ret;
}

void futex_unqueue_pi(struct futex_q *q)
{
	__futex_unqueue(q);

	BUG_ON(!q->pi_state);
	put_pi_state(q->pi_state);
	q->pi_state = NULL;
}

#define HANDLE_DEATH_PENDING	true
#define HANDLE_DEATH_LIST	false

static int handle_futex_death(u32 __user *uaddr, struct task_struct *curr,
			      bool pi, bool pending_op)
{
	u32 uval, nval, mval;
	int err;

	/* Futex address must be 32bit aligned */
	if ((((unsigned long)uaddr) % sizeof(*uaddr)) != 0)
		return -1;

retry:
	if (get_user(uval, uaddr))
		return -1;

	/*
	if (pending_op && !pi && !uval) {
		futex_wake(uaddr, 1, 1, FUTEX_BITSET_MATCH_ANY);
		return 0;
	}

	if ((uval & FUTEX_TID_MASK) != task_pid_vnr(curr))
		return 0;

	/*
	mval = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED;

	/*
	if ((err = futex_cmpxchg_value_locked(&nval, uaddr, uval, mval))) {
		switch (err) {
		case -EFAULT:
			if (fault_in_user_writeable(uaddr))
				return -1;
			goto retry;

		case -EAGAIN:
			cond_resched();
			goto retry;

		default:
			WARN_ON_ONCE(1);
			return err;
		}
	}

	if (nval != uval)
		goto retry;

	/*
	if (!pi && (uval & FUTEX_WAITERS))
		futex_wake(uaddr, 1, 1, FUTEX_BITSET_MATCH_ANY);

	return 0;
}

static inline int fetch_robust_entry(struct robust_list __user **entry,
				     struct robust_list __user * __user *head,
				     unsigned int *pi)
{
	unsigned long uentry;

	if (get_user(uentry, (unsigned long __user *)head))
		return -EFAULT;


	return 0;
}

static void exit_robust_list(struct task_struct *curr)
{
	struct robust_list_head __user *head = curr->robust_list;
	struct robust_list __user *entry, *next_entry, *pending;
	unsigned int limit = ROBUST_LIST_LIMIT, pi, pip;
	unsigned int next_pi;
	unsigned long futex_offset;
	int rc;

	/*
	if (fetch_robust_entry(&entry, &head->list.next, &pi))
		return;
	/*
	if (get_user(futex_offset, &head->futex_offset))
		return;
	/*
	if (fetch_robust_entry(&pending, &head->list_op_pending, &pip))
		return;

	next_entry = NULL;	/* avoid warning with gcc */
	while (entry != &head->list) {
		/*
		rc = fetch_robust_entry(&next_entry, &entry->next, &next_pi);
		/*
		if (entry != pending) {
			if (handle_futex_death((void __user *)entry + futex_offset,
						curr, pi, HANDLE_DEATH_LIST))
				return;
		}
		if (rc)
			return;
		entry = next_entry;
		pi = next_pi;
		/*
		if (!--limit)
			break;

		cond_resched();
	}

	if (pending) {
		handle_futex_death((void __user *)pending + futex_offset,
				   curr, pip, HANDLE_DEATH_PENDING);
	}
}

#ifdef CONFIG_COMPAT
static void __user *futex_uaddr(struct robust_list __user *entry,
				compat_long_t futex_offset)
{
	compat_uptr_t base = ptr_to_compat(entry);
	void __user *uaddr = compat_ptr(base + futex_offset);

	return uaddr;
}

static inline int
compat_fetch_robust_entry(compat_uptr_t *uentry, struct robust_list __user **entry,
		   compat_uptr_t __user *head, unsigned int *pi)
{
	if (get_user(*uentry, head))
		return -EFAULT;


	return 0;
}

static void compat_exit_robust_list(struct task_struct *curr)
{
	struct compat_robust_list_head __user *head = curr->compat_robust_list;
	struct robust_list __user *entry, *next_entry, *pending;
	unsigned int limit = ROBUST_LIST_LIMIT, pi, pip;
	unsigned int next_pi;
	compat_uptr_t uentry, next_uentry, upending;
	compat_long_t futex_offset;
	int rc;

	/*
	if (compat_fetch_robust_entry(&uentry, &entry, &head->list.next, &pi))
		return;
	/*
	if (get_user(futex_offset, &head->futex_offset))
		return;
	/*
	if (compat_fetch_robust_entry(&upending, &pending,
			       &head->list_op_pending, &pip))
		return;

	next_entry = NULL;	/* avoid warning with gcc */
	while (entry != (struct robust_list __user *) &head->list) {
		/*
		rc = compat_fetch_robust_entry(&next_uentry, &next_entry,
			(compat_uptr_t __user *)&entry->next, &next_pi);
		/*
		if (entry != pending) {
			void __user *uaddr = futex_uaddr(entry, futex_offset);

			if (handle_futex_death(uaddr, curr, pi,
					       HANDLE_DEATH_LIST))
				return;
		}
		if (rc)
			return;
		uentry = next_uentry;
		entry = next_entry;
		pi = next_pi;
		/*
		if (!--limit)
			break;

		cond_resched();
	}
	if (pending) {
		void __user *uaddr = futex_uaddr(pending, futex_offset);

		handle_futex_death(uaddr, curr, pip, HANDLE_DEATH_PENDING);
	}
}
#endif

#ifdef CONFIG_FUTEX_PI

static void exit_pi_state_list(struct task_struct *curr)
{
	struct list_head *next, *head = &curr->pi_state_list;
	struct futex_pi_state *pi_state;
	struct futex_hash_bucket *hb;
	union futex_key key = FUTEX_KEY_INIT;

	/*
	raw_spin_lock_irq(&curr->pi_lock);
	while (!list_empty(head)) {
		next = head->next;
		pi_state = list_entry(next, struct futex_pi_state, list);
		key = pi_state->key;
		hb = futex_hash(&key);

		/*
		if (!refcount_inc_not_zero(&pi_state->refcount)) {
			raw_spin_unlock_irq(&curr->pi_lock);
			cpu_relax();
			raw_spin_lock_irq(&curr->pi_lock);
			continue;
		}
		raw_spin_unlock_irq(&curr->pi_lock);

		spin_lock(&hb->lock);
		raw_spin_lock_irq(&pi_state->pi_mutex.wait_lock);
		raw_spin_lock(&curr->pi_lock);
		/*
		if (head->next != next) {
			/* retain curr->pi_lock for the loop invariant */
			raw_spin_unlock(&pi_state->pi_mutex.wait_lock);
			spin_unlock(&hb->lock);
			put_pi_state(pi_state);
			continue;
		}

		WARN_ON(pi_state->owner != curr);
		WARN_ON(list_empty(&pi_state->list));
		list_del_init(&pi_state->list);
		pi_state->owner = NULL;

		raw_spin_unlock(&curr->pi_lock);
		raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);
		spin_unlock(&hb->lock);

		rt_mutex_futex_unlock(&pi_state->pi_mutex);
		put_pi_state(pi_state);

		raw_spin_lock_irq(&curr->pi_lock);
	}
	raw_spin_unlock_irq(&curr->pi_lock);
}
#else
static inline void exit_pi_state_list(struct task_struct *curr) { }
#endif

static void futex_cleanup(struct task_struct *tsk)
{
	if (unlikely(tsk->robust_list)) {
		exit_robust_list(tsk);
		tsk->robust_list = NULL;
	}

#ifdef CONFIG_COMPAT
	if (unlikely(tsk->compat_robust_list)) {
		compat_exit_robust_list(tsk);
		tsk->compat_robust_list = NULL;
	}
#endif

	if (unlikely(!list_empty(&tsk->pi_state_list)))
		exit_pi_state_list(tsk);
}

void futex_exit_recursive(struct task_struct *tsk)
{
	/* If the state is FUTEX_STATE_EXITING then futex_exit_mutex is held */
	if (tsk->futex_state == FUTEX_STATE_EXITING)
		mutex_unlock(&tsk->futex_exit_mutex);
	tsk->futex_state = FUTEX_STATE_DEAD;
}

static void futex_cleanup_begin(struct task_struct *tsk)
{
	/*
	mutex_lock(&tsk->futex_exit_mutex);

	/*
	raw_spin_lock_irq(&tsk->pi_lock);
	tsk->futex_state = FUTEX_STATE_EXITING;
	raw_spin_unlock_irq(&tsk->pi_lock);
}

static void futex_cleanup_end(struct task_struct *tsk, int state)
{
	/*
	tsk->futex_state = state;
	/*
	mutex_unlock(&tsk->futex_exit_mutex);
}

void futex_exec_release(struct task_struct *tsk)
{
	/*
	futex_cleanup_begin(tsk);
	futex_cleanup(tsk);
	/*
	futex_cleanup_end(tsk, FUTEX_STATE_OK);
}

void futex_exit_release(struct task_struct *tsk)
{
	futex_cleanup_begin(tsk);
	futex_cleanup(tsk);
	futex_cleanup_end(tsk, FUTEX_STATE_DEAD);
}

static int __init futex_init(void)
{
	unsigned int futex_shift;
	unsigned long i;

#if CONFIG_BASE_SMALL
	futex_hashsize = 16;
#else
	futex_hashsize = roundup_pow_of_two(256 * num_possible_cpus());
#endif

	futex_queues = alloc_large_system_hash("futex", sizeof(*futex_queues),
					       futex_hashsize, 0,
					       futex_hashsize < 256 ? HASH_SMALL : 0,
					       &futex_shift, NULL,
					       futex_hashsize, futex_hashsize);
	futex_hashsize = 1UL << futex_shift;

	for (i = 0; i < futex_hashsize; i++) {
		atomic_set(&futex_queues[i].waiters, 0);
		plist_head_init(&futex_queues[i].chain);
		spin_lock_init(&futex_queues[i].lock);
	}

	return 0;
}
core_initcall(futex_init);
