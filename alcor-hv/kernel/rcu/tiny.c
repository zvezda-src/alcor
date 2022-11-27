#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/rcupdate_wait.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/cpu.h>
#include <linux/prefetch.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include "rcu.h"

struct rcu_ctrlblk {
	struct rcu_head *rcucblist;	/* List of pending callbacks (CBs). */
	struct rcu_head **donetail;	/* ->next pointer of last "done" CB. */
	struct rcu_head **curtail;	/* ->next pointer of last CB. */
	unsigned long gp_seq;		/* Grace-period counter. */
};

static struct rcu_ctrlblk rcu_ctrlblk = {
	.donetail	= &rcu_ctrlblk.rcucblist,
	.curtail	= &rcu_ctrlblk.rcucblist,
	.gp_seq		= 0 - 300UL,
};

void rcu_barrier(void)
{
	wait_rcu_gp(call_rcu);
}
EXPORT_SYMBOL(rcu_barrier);

void rcu_qs(void)
{
	unsigned long flags;

	local_irq_save(flags);
	if (rcu_ctrlblk.donetail != rcu_ctrlblk.curtail) {
		rcu_ctrlblk.donetail = rcu_ctrlblk.curtail;
		raise_softirq_irqoff(RCU_SOFTIRQ);
	}
	WRITE_ONCE(rcu_ctrlblk.gp_seq, rcu_ctrlblk.gp_seq + 2);
	local_irq_restore(flags);
}

void rcu_sched_clock_irq(int user)
{
	if (user) {
		rcu_qs();
	} else if (rcu_ctrlblk.donetail != rcu_ctrlblk.curtail) {
		set_tsk_need_resched(current);
		set_preempt_need_resched();
	}
}

static inline bool rcu_reclaim_tiny(struct rcu_head *head)
{
	rcu_callback_t f;
	unsigned long offset = (unsigned long)head->func;

	rcu_lock_acquire(&rcu_callback_map);
	if (__is_kvfree_rcu_offset(offset)) {
		trace_rcu_invoke_kvfree_callback("", head, offset);
		kvfree((void *)head - offset);
		rcu_lock_release(&rcu_callback_map);
		return true;
	}

	trace_rcu_invoke_callback("", head);
	f = head->func;
	WRITE_ONCE(head->func, (rcu_callback_t)0L);
	f(head);
	rcu_lock_release(&rcu_callback_map);
	return false;
}

static __latent_entropy void rcu_process_callbacks(struct softirq_action *unused)
{
	struct rcu_head *next, *list;
	unsigned long flags;

	/* Move the ready-to-invoke callbacks to a local list. */
	local_irq_save(flags);
	if (rcu_ctrlblk.donetail == &rcu_ctrlblk.rcucblist) {
		/* No callbacks ready, so just leave. */
		local_irq_restore(flags);
		return;
	}
	list = rcu_ctrlblk.rcucblist;
	rcu_ctrlblk.rcucblist = *rcu_ctrlblk.donetail;
	if (rcu_ctrlblk.curtail == rcu_ctrlblk.donetail)
		rcu_ctrlblk.curtail = &rcu_ctrlblk.rcucblist;
	rcu_ctrlblk.donetail = &rcu_ctrlblk.rcucblist;
	local_irq_restore(flags);

	/* Invoke the callbacks on the local list. */
	while (list) {
		next = list->next;
		prefetch(next);
		debug_rcu_head_unqueue(list);
		local_bh_disable();
		rcu_reclaim_tiny(list);
		local_bh_enable();
		list = next;
	}
}

void synchronize_rcu(void)
{
	RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map) ||
			 lock_is_held(&rcu_lock_map) ||
			 lock_is_held(&rcu_sched_lock_map),
			 "Illegal synchronize_rcu() in RCU read-side critical section");
	WRITE_ONCE(rcu_ctrlblk.gp_seq, rcu_ctrlblk.gp_seq + 2);
}
EXPORT_SYMBOL_GPL(synchronize_rcu);

void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	unsigned long flags;

	debug_rcu_head_queue(head);
	head->func = func;
	head->next = NULL;

	local_irq_save(flags);
	rcu_ctrlblk.curtail = &head->next;
	local_irq_restore(flags);

	if (unlikely(is_idle_task(current))) {
		/* force scheduling for rcu_qs() */
		resched_cpu(0);
	}
}
EXPORT_SYMBOL_GPL(call_rcu);

unsigned long get_state_synchronize_rcu(void)
{
	return READ_ONCE(rcu_ctrlblk.gp_seq);
}
EXPORT_SYMBOL_GPL(get_state_synchronize_rcu);

unsigned long start_poll_synchronize_rcu(void)
{
	unsigned long gp_seq = get_state_synchronize_rcu();

	if (unlikely(is_idle_task(current))) {
		/* force scheduling for rcu_qs() */
		resched_cpu(0);
	}
	return gp_seq;
}
EXPORT_SYMBOL_GPL(start_poll_synchronize_rcu);

bool poll_state_synchronize_rcu(unsigned long oldstate)
{
	return oldstate == RCU_GET_STATE_COMPLETED || READ_ONCE(rcu_ctrlblk.gp_seq) != oldstate;
}
EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);

#ifdef CONFIG_KASAN_GENERIC
void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	if (head) {
		void *ptr = (void *) head - (unsigned long) func;

		kasan_record_aux_stack_noalloc(ptr);
	}

	__kvfree_call_rcu(head, func);
}
EXPORT_SYMBOL_GPL(kvfree_call_rcu);
#endif

void __init rcu_init(void)
{
	open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);
	rcu_early_boot_tests();
}
