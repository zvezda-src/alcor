#include <linux/spinlock.h>
#include <linux/task_work.h>
#include <linux/resume_user_mode.h>

static struct callback_head work_exited; /* all we need is ->next == NULL */

int task_work_add(struct task_struct *task, struct callback_head *work,
		  enum task_work_notify_mode notify)
{
	struct callback_head *head;

	/* record the work call stack in order to print it in KASAN reports */
	kasan_record_aux_stack(work);

	do {
		head = READ_ONCE(task->task_works);
		if (unlikely(head == &work_exited))
			return -ESRCH;
		work->next = head;
	} while (cmpxchg(&task->task_works, head, work) != head);

	switch (notify) {
	case TWA_NONE:
		break;
	case TWA_RESUME:
		set_notify_resume(task);
		break;
	case TWA_SIGNAL:
		set_notify_signal(task);
		break;
	case TWA_SIGNAL_NO_IPI:
		__set_notify_signal(task);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	return 0;
}

struct callback_head *
task_work_cancel_match(struct task_struct *task,
		       bool (*match)(struct callback_head *, void *data),
		       void *data)
{
	struct callback_head **pprev = &task->task_works;
	struct callback_head *work;
	unsigned long flags;

	if (likely(!task_work_pending(task)))
		return NULL;
	/*
	raw_spin_lock_irqsave(&task->pi_lock, flags);
	while ((work = READ_ONCE(*pprev))) {
		if (!match(work, data))
			pprev = &work->next;
		else if (cmpxchg(pprev, work, work->next) == work)
			break;
	}
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);

	return work;
}

static bool task_work_func_match(struct callback_head *cb, void *data)
{
	return cb->func == data;
}

struct callback_head *
task_work_cancel(struct task_struct *task, task_work_func_t func)
{
	return task_work_cancel_match(task, task_work_func_match, func);
}

void task_work_run(void)
{
	struct task_struct *task = current;
	struct callback_head *work, *head, *next;

	for (;;) {
		/*
		do {
			head = NULL;
			work = READ_ONCE(task->task_works);
			if (!work) {
				if (task->flags & PF_EXITING)
					head = &work_exited;
				else
					break;
			}
		} while (cmpxchg(&task->task_works, work, head) != work);

		if (!work)
			break;
		/*
		raw_spin_lock_irq(&task->pi_lock);
		raw_spin_unlock_irq(&task->pi_lock);

		do {
			next = work->next;
			work->func(work);
			work = next;
			cond_resched();
		} while (work);
	}
}
