#include <uapi/linux/sched/types.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/cgroup.h>
#include <linux/cpuset.h>
#include <linux/unistd.h>
#include <linux/file.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/freezer.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/numa.h>
#include <linux/sched/isolation.h>
#include <trace/events/sched.h>


static DEFINE_SPINLOCK(kthread_create_lock);
static LIST_HEAD(kthread_create_list);
struct task_struct *kthreadd_task;

struct kthread_create_info
{
	/* Information passed to kthread() from kthreadd. */
	int (*threadfn)(void *data);
	void *data;
	int node;

	/* Result passed back to kthread_create() from kthreadd. */
	struct task_struct *result;
	struct completion *done;

	struct list_head list;
};

struct kthread {
	unsigned long flags;
	unsigned int cpu;
	int result;
	int (*threadfn)(void *);
	void *data;
	struct completion parked;
	struct completion exited;
#ifdef CONFIG_BLK_CGROUP
	struct cgroup_subsys_state *blkcg_css;
#endif
	/* To store the full name if task comm is truncated. */
	char *full_name;
};

enum KTHREAD_BITS {
	KTHREAD_IS_PER_CPU = 0,
	KTHREAD_SHOULD_STOP,
	KTHREAD_SHOULD_PARK,
};

static inline struct kthread *to_kthread(struct task_struct *k)
{
	WARN_ON(!(k->flags & PF_KTHREAD));
	return k->worker_private;
}

static inline struct kthread *__to_kthread(struct task_struct *p)
{
	void *kthread = p->worker_private;
	if (kthread && !(p->flags & PF_KTHREAD))
		kthread = NULL;
	return kthread;
}

void get_kthread_comm(char *buf, size_t buf_size, struct task_struct *tsk)
{
	struct kthread *kthread = to_kthread(tsk);

	if (!kthread || !kthread->full_name) {
		__get_task_comm(buf, buf_size, tsk);
		return;
	}

	strscpy_pad(buf, kthread->full_name, buf_size);
}

bool set_kthread_struct(struct task_struct *p)
{
	struct kthread *kthread;

	if (WARN_ON_ONCE(to_kthread(p)))
		return false;

	kthread = kzalloc(sizeof(*kthread), GFP_KERNEL);
	if (!kthread)
		return false;

	init_completion(&kthread->exited);
	init_completion(&kthread->parked);
	p->vfork_done = &kthread->exited;

	p->worker_private = kthread;
	return true;
}

void free_kthread_struct(struct task_struct *k)
{
	struct kthread *kthread;

	/*
	kthread = to_kthread(k);
	if (!kthread)
		return;

#ifdef CONFIG_BLK_CGROUP
	WARN_ON_ONCE(kthread->blkcg_css);
#endif
	k->worker_private = NULL;
	kfree(kthread->full_name);
	kfree(kthread);
}

bool kthread_should_stop(void)
{
	return test_bit(KTHREAD_SHOULD_STOP, &to_kthread(current)->flags);
}
EXPORT_SYMBOL(kthread_should_stop);

bool __kthread_should_park(struct task_struct *k)
{
	return test_bit(KTHREAD_SHOULD_PARK, &to_kthread(k)->flags);
}
EXPORT_SYMBOL_GPL(__kthread_should_park);

bool kthread_should_park(void)
{
	return __kthread_should_park(current);
}
EXPORT_SYMBOL_GPL(kthread_should_park);

bool kthread_freezable_should_stop(bool *was_frozen)
{
	bool frozen = false;

	might_sleep();

	if (unlikely(freezing(current)))
		frozen = __refrigerator(true);

	if (was_frozen)
		*was_frozen = frozen;

	return kthread_should_stop();
}
EXPORT_SYMBOL_GPL(kthread_freezable_should_stop);

void *kthread_func(struct task_struct *task)
{
	struct kthread *kthread = __to_kthread(task);
	if (kthread)
		return kthread->threadfn;
	return NULL;
}
EXPORT_SYMBOL_GPL(kthread_func);

void *kthread_data(struct task_struct *task)
{
	return to_kthread(task)->data;
}
EXPORT_SYMBOL_GPL(kthread_data);

void *kthread_probe_data(struct task_struct *task)
{
	struct kthread *kthread = __to_kthread(task);
	void *data = NULL;

	if (kthread)
		copy_from_kernel_nofault(&data, &kthread->data, sizeof(data));
	return data;
}

static void __kthread_parkme(struct kthread *self)
{
	for (;;) {
		/*
		set_special_state(TASK_PARKED);
		if (!test_bit(KTHREAD_SHOULD_PARK, &self->flags))
			break;

		/*
		preempt_disable();
		complete(&self->parked);
		schedule_preempt_disabled();
		preempt_enable();
	}
	__set_current_state(TASK_RUNNING);
}

void kthread_parkme(void)
{
	__kthread_parkme(to_kthread(current));
}
EXPORT_SYMBOL_GPL(kthread_parkme);

void __noreturn kthread_exit(long result)
{
	struct kthread *kthread = to_kthread(current);
	kthread->result = result;
	do_exit(0);
}

void __noreturn kthread_complete_and_exit(struct completion *comp, long code)
{
	if (comp)
		complete(comp);

	kthread_exit(code);
}
EXPORT_SYMBOL(kthread_complete_and_exit);

static int kthread(void *_create)
{
	static const struct sched_param param = { .sched_priority = 0 };
	/* Copy data: it's on kthread's stack */
	struct kthread_create_info *create = _create;
	int (*threadfn)(void *data) = create->threadfn;
	void *data = create->data;
	struct completion *done;
	struct kthread *self;
	int ret;

	self = to_kthread(current);

	/* Release the structure when caller killed by a fatal signal. */
	done = xchg(&create->done, NULL);
	if (!done) {
		kfree(create);
		kthread_exit(-EINTR);
	}

	self->threadfn = threadfn;
	self->data = data;

	/*
	sched_setscheduler_nocheck(current, SCHED_NORMAL, &param);
	set_cpus_allowed_ptr(current, housekeeping_cpumask(HK_TYPE_KTHREAD));

	/* OK, tell user we're spawned, wait for stop or wakeup */
	__set_current_state(TASK_UNINTERRUPTIBLE);
	create->result = current;
	/*
	preempt_disable();
	complete(done);
	schedule_preempt_disabled();
	preempt_enable();

	ret = -EINTR;
	if (!test_bit(KTHREAD_SHOULD_STOP, &self->flags)) {
		cgroup_kthread_ready();
		__kthread_parkme(self);
		ret = threadfn(data);
	}
	kthread_exit(ret);
}

int tsk_fork_get_node(struct task_struct *tsk)
{
#ifdef CONFIG_NUMA
	if (tsk == kthreadd_task)
		return tsk->pref_node_fork;
#endif
	return NUMA_NO_NODE;
}

static void create_kthread(struct kthread_create_info *create)
{
	int pid;

#ifdef CONFIG_NUMA
	current->pref_node_fork = create->node;
#endif
	/* We want our own signal handler (we take no signals by default). */
	pid = kernel_thread(kthread, create, CLONE_FS | CLONE_FILES | SIGCHLD);
	if (pid < 0) {
		/* Release the structure when caller killed by a fatal signal. */
		struct completion *done = xchg(&create->done, NULL);

		if (!done) {
			kfree(create);
			return;
		}
		create->result = ERR_PTR(pid);
		complete(done);
	}
}

static __printf(4, 0)
struct task_struct *__kthread_create_on_node(int (*threadfn)(void *data),
						    void *data, int node,
						    const char namefmt[],
						    va_list args)
{
	DECLARE_COMPLETION_ONSTACK(done);
	struct task_struct *task;
	struct kthread_create_info *create = kmalloc(sizeof(*create),
						     GFP_KERNEL);

	if (!create)
		return ERR_PTR(-ENOMEM);
	create->threadfn = threadfn;
	create->data = data;
	create->node = node;
	create->done = &done;

	spin_lock(&kthread_create_lock);
	list_add_tail(&create->list, &kthread_create_list);
	spin_unlock(&kthread_create_lock);

	wake_up_process(kthreadd_task);
	/*
	if (unlikely(wait_for_completion_killable(&done))) {
		/*
		if (xchg(&create->done, NULL))
			return ERR_PTR(-EINTR);
		/*
		wait_for_completion(&done);
	}
	task = create->result;
	if (!IS_ERR(task)) {
		char name[TASK_COMM_LEN];
		va_list aq;
		int len;

		/*
		va_copy(aq, args);
		len = vsnprintf(name, sizeof(name), namefmt, aq);
		va_end(aq);
		if (len >= TASK_COMM_LEN) {
			struct kthread *kthread = to_kthread(task);

			/* leave it truncated when out of memory. */
			kthread->full_name = kvasprintf(GFP_KERNEL, namefmt, args);
		}
		set_task_comm(task, name);
	}
	kfree(create);
	return task;
}

struct task_struct *kthread_create_on_node(int (*threadfn)(void *data),
					   void *data, int node,
					   const char namefmt[],
					   ...)
{
	struct task_struct *task;
	va_list args;

	va_start(args, namefmt);
	task = __kthread_create_on_node(threadfn, data, node, namefmt, args);
	va_end(args);

	return task;
}
EXPORT_SYMBOL(kthread_create_on_node);

static void __kthread_bind_mask(struct task_struct *p, const struct cpumask *mask, unsigned int state)
{
	unsigned long flags;

	if (!wait_task_inactive(p, state)) {
		WARN_ON(1);
		return;
	}

	/* It's safe because the task is inactive. */
	raw_spin_lock_irqsave(&p->pi_lock, flags);
	do_set_cpus_allowed(p, mask);
	p->flags |= PF_NO_SETAFFINITY;
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);
}

static void __kthread_bind(struct task_struct *p, unsigned int cpu, unsigned int state)
{
	__kthread_bind_mask(p, cpumask_of(cpu), state);
}

void kthread_bind_mask(struct task_struct *p, const struct cpumask *mask)
{
	__kthread_bind_mask(p, mask, TASK_UNINTERRUPTIBLE);
}

void kthread_bind(struct task_struct *p, unsigned int cpu)
{
	__kthread_bind(p, cpu, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(kthread_bind);

struct task_struct *kthread_create_on_cpu(int (*threadfn)(void *data),
					  void *data, unsigned int cpu,
					  const char *namefmt)
{
	struct task_struct *p;

	p = kthread_create_on_node(threadfn, data, cpu_to_node(cpu), namefmt,
				   cpu);
	if (IS_ERR(p))
		return p;
	kthread_bind(p, cpu);
	/* CPU hotplug need to bind once again when unparking the thread. */
	to_kthread(p)->cpu = cpu;
	return p;
}
EXPORT_SYMBOL(kthread_create_on_cpu);

void kthread_set_per_cpu(struct task_struct *k, int cpu)
{
	struct kthread *kthread = to_kthread(k);
	if (!kthread)
		return;

	WARN_ON_ONCE(!(k->flags & PF_NO_SETAFFINITY));

	if (cpu < 0) {
		clear_bit(KTHREAD_IS_PER_CPU, &kthread->flags);
		return;
	}

	kthread->cpu = cpu;
	set_bit(KTHREAD_IS_PER_CPU, &kthread->flags);
}

bool kthread_is_per_cpu(struct task_struct *p)
{
	struct kthread *kthread = __to_kthread(p);
	if (!kthread)
		return false;

	return test_bit(KTHREAD_IS_PER_CPU, &kthread->flags);
}

void kthread_unpark(struct task_struct *k)
{
	struct kthread *kthread = to_kthread(k);

	/*
	if (test_bit(KTHREAD_IS_PER_CPU, &kthread->flags))
		__kthread_bind(k, kthread->cpu, TASK_PARKED);

	clear_bit(KTHREAD_SHOULD_PARK, &kthread->flags);
	/*
	wake_up_state(k, TASK_PARKED);
}
EXPORT_SYMBOL_GPL(kthread_unpark);

int kthread_park(struct task_struct *k)
{
	struct kthread *kthread = to_kthread(k);

	if (WARN_ON(k->flags & PF_EXITING))
		return -ENOSYS;

	if (WARN_ON_ONCE(test_bit(KTHREAD_SHOULD_PARK, &kthread->flags)))
		return -EBUSY;

	set_bit(KTHREAD_SHOULD_PARK, &kthread->flags);
	if (k != current) {
		wake_up_process(k);
		/*
		wait_for_completion(&kthread->parked);
		/*
		WARN_ON_ONCE(!wait_task_inactive(k, TASK_PARKED));
	}

	return 0;
}
EXPORT_SYMBOL_GPL(kthread_park);

int kthread_stop(struct task_struct *k)
{
	struct kthread *kthread;
	int ret;

	trace_sched_kthread_stop(k);

	get_task_struct(k);
	kthread = to_kthread(k);
	set_bit(KTHREAD_SHOULD_STOP, &kthread->flags);
	kthread_unpark(k);
	wake_up_process(k);
	wait_for_completion(&kthread->exited);
	ret = kthread->result;
	put_task_struct(k);

	trace_sched_kthread_stop_ret(ret);
	return ret;
}
EXPORT_SYMBOL(kthread_stop);

int kthreadd(void *unused)
{
	struct task_struct *tsk = current;

	/* Setup a clean context for our children to inherit. */
	set_task_comm(tsk, "kthreadd");
	ignore_signals(tsk);
	set_cpus_allowed_ptr(tsk, housekeeping_cpumask(HK_TYPE_KTHREAD));
	set_mems_allowed(node_states[N_MEMORY]);

	current->flags |= PF_NOFREEZE;
	cgroup_init_kthreadd();

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (list_empty(&kthread_create_list))
			schedule();
		__set_current_state(TASK_RUNNING);

		spin_lock(&kthread_create_lock);
		while (!list_empty(&kthread_create_list)) {
			struct kthread_create_info *create;

			create = list_entry(kthread_create_list.next,
					    struct kthread_create_info, list);
			list_del_init(&create->list);
			spin_unlock(&kthread_create_lock);

			create_kthread(create);

			spin_lock(&kthread_create_lock);
		}
		spin_unlock(&kthread_create_lock);
	}

	return 0;
}

void __kthread_init_worker(struct kthread_worker *worker,
				const char *name,
				struct lock_class_key *key)
{
	memset(worker, 0, sizeof(struct kthread_worker));
	raw_spin_lock_init(&worker->lock);
	lockdep_set_class_and_name(&worker->lock, key, name);
	INIT_LIST_HEAD(&worker->work_list);
	INIT_LIST_HEAD(&worker->delayed_work_list);
}
EXPORT_SYMBOL_GPL(__kthread_init_worker);

int kthread_worker_fn(void *worker_ptr)
{
	struct kthread_worker *worker = worker_ptr;
	struct kthread_work *work;

	/*
	WARN_ON(worker->task && worker->task != current);
	worker->task = current;

	if (worker->flags & KTW_FREEZABLE)
		set_freezable();

repeat:
	set_current_state(TASK_INTERRUPTIBLE);	/* mb paired w/ kthread_stop */

	if (kthread_should_stop()) {
		__set_current_state(TASK_RUNNING);
		raw_spin_lock_irq(&worker->lock);
		worker->task = NULL;
		raw_spin_unlock_irq(&worker->lock);
		return 0;
	}

	work = NULL;
	raw_spin_lock_irq(&worker->lock);
	if (!list_empty(&worker->work_list)) {
		work = list_first_entry(&worker->work_list,
					struct kthread_work, node);
		list_del_init(&work->node);
	}
	worker->current_work = work;
	raw_spin_unlock_irq(&worker->lock);

	if (work) {
		kthread_work_func_t func = work->func;
		__set_current_state(TASK_RUNNING);
		trace_sched_kthread_work_execute_start(work);
		work->func(work);
		/*
		trace_sched_kthread_work_execute_end(work, func);
	} else if (!freezing(current))
		schedule();

	try_to_freeze();
	cond_resched();
	goto repeat;
}
EXPORT_SYMBOL_GPL(kthread_worker_fn);

static __printf(3, 0) struct kthread_worker *
__kthread_create_worker(int cpu, unsigned int flags,
			const char namefmt[], va_list args)
{
	struct kthread_worker *worker;
	struct task_struct *task;
	int node = NUMA_NO_NODE;

	worker = kzalloc(sizeof(*worker), GFP_KERNEL);
	if (!worker)
		return ERR_PTR(-ENOMEM);

	kthread_init_worker(worker);

	if (cpu >= 0)
		node = cpu_to_node(cpu);

	task = __kthread_create_on_node(kthread_worker_fn, worker,
						node, namefmt, args);
	if (IS_ERR(task))
		goto fail_task;

	if (cpu >= 0)
		kthread_bind(task, cpu);

	worker->flags = flags;
	worker->task = task;
	wake_up_process(task);
	return worker;

fail_task:
	kfree(worker);
	return ERR_CAST(task);
}

struct kthread_worker *
kthread_create_worker(unsigned int flags, const char namefmt[], ...)
{
	struct kthread_worker *worker;
	va_list args;

	va_start(args, namefmt);
	worker = __kthread_create_worker(-1, flags, namefmt, args);
	va_end(args);

	return worker;
}
EXPORT_SYMBOL(kthread_create_worker);

struct kthread_worker *
kthread_create_worker_on_cpu(int cpu, unsigned int flags,
			     const char namefmt[], ...)
{
	struct kthread_worker *worker;
	va_list args;

	va_start(args, namefmt);
	worker = __kthread_create_worker(cpu, flags, namefmt, args);
	va_end(args);

	return worker;
}
EXPORT_SYMBOL(kthread_create_worker_on_cpu);

static inline bool queuing_blocked(struct kthread_worker *worker,
				   struct kthread_work *work)
{
	lockdep_assert_held(&worker->lock);

	return !list_empty(&work->node) || work->canceling;
}

static void kthread_insert_work_sanity_check(struct kthread_worker *worker,
					     struct kthread_work *work)
{
	lockdep_assert_held(&worker->lock);
	WARN_ON_ONCE(!list_empty(&work->node));
	/* Do not use a work with >1 worker, see kthread_queue_work() */
	WARN_ON_ONCE(work->worker && work->worker != worker);
}

static void kthread_insert_work(struct kthread_worker *worker,
				struct kthread_work *work,
				struct list_head *pos)
{
	kthread_insert_work_sanity_check(worker, work);

	trace_sched_kthread_work_queue_work(worker, work);

	list_add_tail(&work->node, pos);
	work->worker = worker;
	if (!worker->current_work && likely(worker->task))
		wake_up_process(worker->task);
}

bool kthread_queue_work(struct kthread_worker *worker,
			struct kthread_work *work)
{
	bool ret = false;
	unsigned long flags;

	raw_spin_lock_irqsave(&worker->lock, flags);
	if (!queuing_blocked(worker, work)) {
		kthread_insert_work(worker, work, &worker->work_list);
		ret = true;
	}
	raw_spin_unlock_irqrestore(&worker->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(kthread_queue_work);

void kthread_delayed_work_timer_fn(struct timer_list *t)
{
	struct kthread_delayed_work *dwork = from_timer(dwork, t, timer);
	struct kthread_work *work = &dwork->work;
	struct kthread_worker *worker = work->worker;
	unsigned long flags;

	/*
	if (WARN_ON_ONCE(!worker))
		return;

	raw_spin_lock_irqsave(&worker->lock, flags);
	/* Work must not be used with >1 worker, see kthread_queue_work(). */
	WARN_ON_ONCE(work->worker != worker);

	/* Move the work from worker->delayed_work_list. */
	WARN_ON_ONCE(list_empty(&work->node));
	list_del_init(&work->node);
	if (!work->canceling)
		kthread_insert_work(worker, work, &worker->work_list);

	raw_spin_unlock_irqrestore(&worker->lock, flags);
}
EXPORT_SYMBOL(kthread_delayed_work_timer_fn);

static void __kthread_queue_delayed_work(struct kthread_worker *worker,
					 struct kthread_delayed_work *dwork,
					 unsigned long delay)
{
	struct timer_list *timer = &dwork->timer;
	struct kthread_work *work = &dwork->work;

	WARN_ON_FUNCTION_MISMATCH(timer->function,
				  kthread_delayed_work_timer_fn);

	/*
	if (!delay) {
		kthread_insert_work(worker, work, &worker->work_list);
		return;
	}

	/* Be paranoid and try to detect possible races already now. */
	kthread_insert_work_sanity_check(worker, work);

	list_add(&work->node, &worker->delayed_work_list);
	work->worker = worker;
	timer->expires = jiffies + delay;
	add_timer(timer);
}

bool kthread_queue_delayed_work(struct kthread_worker *worker,
				struct kthread_delayed_work *dwork,
				unsigned long delay)
{
	struct kthread_work *work = &dwork->work;
	unsigned long flags;
	bool ret = false;

	raw_spin_lock_irqsave(&worker->lock, flags);

	if (!queuing_blocked(worker, work)) {
		__kthread_queue_delayed_work(worker, dwork, delay);
		ret = true;
	}

	raw_spin_unlock_irqrestore(&worker->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(kthread_queue_delayed_work);

struct kthread_flush_work {
	struct kthread_work	work;
	struct completion	done;
};

static void kthread_flush_work_fn(struct kthread_work *work)
{
	struct kthread_flush_work *fwork =
		container_of(work, struct kthread_flush_work, work);
	complete(&fwork->done);
}

void kthread_flush_work(struct kthread_work *work)
{
	struct kthread_flush_work fwork = {
		KTHREAD_WORK_INIT(fwork.work, kthread_flush_work_fn),
		COMPLETION_INITIALIZER_ONSTACK(fwork.done),
	};
	struct kthread_worker *worker;
	bool noop = false;

	worker = work->worker;
	if (!worker)
		return;

	raw_spin_lock_irq(&worker->lock);
	/* Work must not be used with >1 worker, see kthread_queue_work(). */
	WARN_ON_ONCE(work->worker != worker);

	if (!list_empty(&work->node))
		kthread_insert_work(worker, &fwork.work, work->node.next);
	else if (worker->current_work == work)
		kthread_insert_work(worker, &fwork.work,
				    worker->work_list.next);
	else
		noop = true;

	raw_spin_unlock_irq(&worker->lock);

	if (!noop)
		wait_for_completion(&fwork.done);
}
EXPORT_SYMBOL_GPL(kthread_flush_work);

static void kthread_cancel_delayed_work_timer(struct kthread_work *work,
					      unsigned long *flags)
{
	struct kthread_delayed_work *dwork =
		container_of(work, struct kthread_delayed_work, work);
	struct kthread_worker *worker = work->worker;

	/*
	work->canceling++;
	raw_spin_unlock_irqrestore(&worker->lock, *flags);
	del_timer_sync(&dwork->timer);
	raw_spin_lock_irqsave(&worker->lock, *flags);
	work->canceling--;
}

static bool __kthread_cancel_work(struct kthread_work *work)
{
	/*
	if (!list_empty(&work->node)) {
		list_del_init(&work->node);
		return true;
	}

	return false;
}

bool kthread_mod_delayed_work(struct kthread_worker *worker,
			      struct kthread_delayed_work *dwork,
			      unsigned long delay)
{
	struct kthread_work *work = &dwork->work;
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&worker->lock, flags);

	/* Do not bother with canceling when never queued. */
	if (!work->worker) {
		ret = false;
		goto fast_queue;
	}

	/* Work must not be used with >1 worker, see kthread_queue_work() */
	WARN_ON_ONCE(work->worker != worker);

	/*
	kthread_cancel_delayed_work_timer(work, &flags);
	if (work->canceling) {
		/* The number of works in the queue does not change. */
		ret = true;
		goto out;
	}
	ret = __kthread_cancel_work(work);

fast_queue:
	__kthread_queue_delayed_work(worker, dwork, delay);
out:
	raw_spin_unlock_irqrestore(&worker->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(kthread_mod_delayed_work);

static bool __kthread_cancel_work_sync(struct kthread_work *work, bool is_dwork)
{
	struct kthread_worker *worker = work->worker;
	unsigned long flags;
	int ret = false;

	if (!worker)
		goto out;

	raw_spin_lock_irqsave(&worker->lock, flags);
	/* Work must not be used with >1 worker, see kthread_queue_work(). */
	WARN_ON_ONCE(work->worker != worker);

	if (is_dwork)
		kthread_cancel_delayed_work_timer(work, &flags);

	ret = __kthread_cancel_work(work);

	if (worker->current_work != work)
		goto out_fast;

	/*
	work->canceling++;
	raw_spin_unlock_irqrestore(&worker->lock, flags);
	kthread_flush_work(work);
	raw_spin_lock_irqsave(&worker->lock, flags);
	work->canceling--;

out_fast:
	raw_spin_unlock_irqrestore(&worker->lock, flags);
out:
	return ret;
}

bool kthread_cancel_work_sync(struct kthread_work *work)
{
	return __kthread_cancel_work_sync(work, false);
}
EXPORT_SYMBOL_GPL(kthread_cancel_work_sync);

bool kthread_cancel_delayed_work_sync(struct kthread_delayed_work *dwork)
{
	return __kthread_cancel_work_sync(&dwork->work, true);
}
EXPORT_SYMBOL_GPL(kthread_cancel_delayed_work_sync);

void kthread_flush_worker(struct kthread_worker *worker)
{
	struct kthread_flush_work fwork = {
		KTHREAD_WORK_INIT(fwork.work, kthread_flush_work_fn),
		COMPLETION_INITIALIZER_ONSTACK(fwork.done),
	};

	kthread_queue_work(worker, &fwork.work);
	wait_for_completion(&fwork.done);
}
EXPORT_SYMBOL_GPL(kthread_flush_worker);

void kthread_destroy_worker(struct kthread_worker *worker)
{
	struct task_struct *task;

	task = worker->task;
	if (WARN_ON(!task))
		return;

	kthread_flush_worker(worker);
	kthread_stop(task);
	WARN_ON(!list_empty(&worker->work_list));
	kfree(worker);
}
EXPORT_SYMBOL(kthread_destroy_worker);

void kthread_use_mm(struct mm_struct *mm)
{
	struct mm_struct *active_mm;
	struct task_struct *tsk = current;

	WARN_ON_ONCE(!(tsk->flags & PF_KTHREAD));
	WARN_ON_ONCE(tsk->mm);

	task_lock(tsk);
	/* Hold off tlb flush IPIs while switching mm's */
	local_irq_disable();
	active_mm = tsk->active_mm;
	if (active_mm != mm) {
		mmgrab(mm);
		tsk->active_mm = mm;
	}
	tsk->mm = mm;
	membarrier_update_current_mm(mm);
	switch_mm_irqs_off(active_mm, mm, tsk);
	local_irq_enable();
	task_unlock(tsk);
#ifdef finish_arch_post_lock_switch
	finish_arch_post_lock_switch();
#endif

	/*
	if (active_mm != mm)
		mmdrop(active_mm);
	else
		smp_mb();
}
EXPORT_SYMBOL_GPL(kthread_use_mm);

void kthread_unuse_mm(struct mm_struct *mm)
{
	struct task_struct *tsk = current;

	WARN_ON_ONCE(!(tsk->flags & PF_KTHREAD));
	WARN_ON_ONCE(!tsk->mm);

	task_lock(tsk);
	/*
	smp_mb__after_spinlock();
	sync_mm_rss(mm);
	local_irq_disable();
	tsk->mm = NULL;
	membarrier_update_current_mm(NULL);
	/* active_mm is still 'mm' */
	enter_lazy_tlb(mm, tsk);
	local_irq_enable();
	task_unlock(tsk);
}
EXPORT_SYMBOL_GPL(kthread_unuse_mm);

#ifdef CONFIG_BLK_CGROUP
void kthread_associate_blkcg(struct cgroup_subsys_state *css)
{
	struct kthread *kthread;

	if (!(current->flags & PF_KTHREAD))
		return;
	kthread = to_kthread(current);
	if (!kthread)
		return;

	if (kthread->blkcg_css) {
		css_put(kthread->blkcg_css);
		kthread->blkcg_css = NULL;
	}
	if (css) {
		css_get(css);
		kthread->blkcg_css = css;
	}
}
EXPORT_SYMBOL(kthread_associate_blkcg);

struct cgroup_subsys_state *kthread_blkcg(void)
{
	struct kthread *kthread;

	if (current->flags & PF_KTHREAD) {
		kthread = to_kthread(current);
		if (kthread)
			return kthread->blkcg_css;
	}
	return NULL;
}
#endif
