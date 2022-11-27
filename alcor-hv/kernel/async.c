


#include <linux/async.h>
#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/export.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "workqueue_internal.h"

static async_cookie_t next_cookie = 1;

#define MAX_WORK		32768
#define ASYNC_COOKIE_MAX	ULLONG_MAX	/* infinity cookie */

static LIST_HEAD(async_global_pending);	/* pending from all registered doms */
static ASYNC_DOMAIN(async_dfl_domain);
static DEFINE_SPINLOCK(async_lock);

struct async_entry {
	struct list_head	domain_list;
	struct list_head	global_list;
	struct work_struct	work;
	async_cookie_t		cookie;
	async_func_t		func;
	void			*data;
	struct async_domain	*domain;
};

static DECLARE_WAIT_QUEUE_HEAD(async_done);

static atomic_t entry_count;

static long long microseconds_since(ktime_t start)
{
	ktime_t now = ktime_get();
	return ktime_to_ns(ktime_sub(now, start)) >> 10;
}

static async_cookie_t lowest_in_progress(struct async_domain *domain)
{
	struct async_entry *first = NULL;
	async_cookie_t ret = ASYNC_COOKIE_MAX;
	unsigned long flags;

	spin_lock_irqsave(&async_lock, flags);

	if (domain) {
		if (!list_empty(&domain->pending))
			first = list_first_entry(&domain->pending,
					struct async_entry, domain_list);
	} else {
		if (!list_empty(&async_global_pending))
			first = list_first_entry(&async_global_pending,
					struct async_entry, global_list);
	}

	if (first)
		ret = first->cookie;

	spin_unlock_irqrestore(&async_lock, flags);
	return ret;
}

static void async_run_entry_fn(struct work_struct *work)
{
	struct async_entry *entry =
		container_of(work, struct async_entry, work);
	unsigned long flags;
	ktime_t calltime;

	/* 1) run (and print duration) */
	pr_debug("calling  %lli_%pS @ %i\n", (long long)entry->cookie,
		 entry->func, task_pid_nr(current));
	calltime = ktime_get();

	entry->func(entry->data, entry->cookie);

	pr_debug("initcall %lli_%pS returned after %lld usecs\n",
		 (long long)entry->cookie, entry->func,
		 microseconds_since(calltime));

	/* 2) remove self from the pending queues */
	spin_lock_irqsave(&async_lock, flags);
	list_del_init(&entry->domain_list);
	list_del_init(&entry->global_list);

	/* 3) free the entry */
	kfree(entry);
	atomic_dec(&entry_count);

	spin_unlock_irqrestore(&async_lock, flags);

	/* 4) wake up any waiters */
	wake_up(&async_done);
}

async_cookie_t async_schedule_node_domain(async_func_t func, void *data,
					  int node, struct async_domain *domain)
{
	struct async_entry *entry;
	unsigned long flags;
	async_cookie_t newcookie;

	/* allow irq-off callers */
	entry = kzalloc(sizeof(struct async_entry), GFP_ATOMIC);

	/*
	if (!entry || atomic_read(&entry_count) > MAX_WORK) {
		kfree(entry);
		spin_lock_irqsave(&async_lock, flags);
		newcookie = next_cookie++;
		spin_unlock_irqrestore(&async_lock, flags);

		/* low on memory.. run synchronously */
		func(data, newcookie);
		return newcookie;
	}
	INIT_LIST_HEAD(&entry->domain_list);
	INIT_LIST_HEAD(&entry->global_list);
	INIT_WORK(&entry->work, async_run_entry_fn);
	entry->func = func;
	entry->data = data;
	entry->domain = domain;

	spin_lock_irqsave(&async_lock, flags);

	/* allocate cookie and queue */
	newcookie = entry->cookie = next_cookie++;

	list_add_tail(&entry->domain_list, &domain->pending);
	if (domain->registered)
		list_add_tail(&entry->global_list, &async_global_pending);

	atomic_inc(&entry_count);
	spin_unlock_irqrestore(&async_lock, flags);

	/* schedule for execution */
	queue_work_node(node, system_unbound_wq, &entry->work);

	return newcookie;
}
EXPORT_SYMBOL_GPL(async_schedule_node_domain);

async_cookie_t async_schedule_node(async_func_t func, void *data, int node)
{
	return async_schedule_node_domain(func, data, node, &async_dfl_domain);
}
EXPORT_SYMBOL_GPL(async_schedule_node);

void async_synchronize_full(void)
{
	async_synchronize_full_domain(NULL);
}
EXPORT_SYMBOL_GPL(async_synchronize_full);

void async_synchronize_full_domain(struct async_domain *domain)
{
	async_synchronize_cookie_domain(ASYNC_COOKIE_MAX, domain);
}
EXPORT_SYMBOL_GPL(async_synchronize_full_domain);

void async_synchronize_cookie_domain(async_cookie_t cookie, struct async_domain *domain)
{
	ktime_t starttime;

	pr_debug("async_waiting @ %i\n", task_pid_nr(current));
	starttime = ktime_get();

	wait_event(async_done, lowest_in_progress(domain) >= cookie);

	pr_debug("async_continuing @ %i after %lli usec\n", task_pid_nr(current),
		 microseconds_since(starttime));
}
EXPORT_SYMBOL_GPL(async_synchronize_cookie_domain);

void async_synchronize_cookie(async_cookie_t cookie)
{
	async_synchronize_cookie_domain(cookie, &async_dfl_domain);
}
EXPORT_SYMBOL_GPL(async_synchronize_cookie);

bool current_is_async(void)
{
	struct worker *worker = current_wq_worker();

	return worker && worker->current_func == async_run_entry_fn;
}
EXPORT_SYMBOL_GPL(current_is_async);
