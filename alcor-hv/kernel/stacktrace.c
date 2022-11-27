#include <linux/sched/task_stack.h>
#include <linux/sched/debug.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/kallsyms.h>
#include <linux/stacktrace.h>
#include <linux/interrupt.h>

void stack_trace_print(const unsigned long *entries, unsigned int nr_entries,
		       int spaces)
{
	unsigned int i;

	if (WARN_ON(!entries))
		return;

	for (i = 0; i < nr_entries; i++)
		printk("%*c%pS\n", 1 + spaces, ' ', (void *)entries[i]);
}
EXPORT_SYMBOL_GPL(stack_trace_print);

int stack_trace_snprint(char *buf, size_t size, const unsigned long *entries,
			unsigned int nr_entries, int spaces)
{
	unsigned int generated, i, total = 0;

	if (WARN_ON(!entries))
		return 0;

	for (i = 0; i < nr_entries && size; i++) {
		generated = snprintf(buf, size, "%*c%pS\n", 1 + spaces, ' ',
				     (void *)entries[i]);

		total += generated;
		if (generated >= size) {
			buf += size;
			size = 0;
		} else {
			buf += generated;
			size -= generated;
		}
	}

	return total;
}
EXPORT_SYMBOL_GPL(stack_trace_snprint);

#ifdef CONFIG_ARCH_STACKWALK

struct stacktrace_cookie {
	unsigned long	*store;
	unsigned int	size;
	unsigned int	skip;
	unsigned int	len;
};

static bool stack_trace_consume_entry(void *cookie, unsigned long addr)
{
	struct stacktrace_cookie *c = cookie;

	if (c->len >= c->size)
		return false;

	if (c->skip > 0) {
		c->skip--;
		return true;
	}
	c->store[c->len++] = addr;
	return c->len < c->size;
}

static bool stack_trace_consume_entry_nosched(void *cookie, unsigned long addr)
{
	if (in_sched_functions(addr))
		return true;
	return stack_trace_consume_entry(cookie, addr);
}

unsigned int stack_trace_save(unsigned long *store, unsigned int size,
			      unsigned int skipnr)
{
	stack_trace_consume_fn consume_entry = stack_trace_consume_entry;
	struct stacktrace_cookie c = {
		.store	= store,
		.size	= size,
		.skip	= skipnr + 1,
	};

	arch_stack_walk(consume_entry, &c, current, NULL);
	return c.len;
}
EXPORT_SYMBOL_GPL(stack_trace_save);

unsigned int stack_trace_save_tsk(struct task_struct *tsk, unsigned long *store,
				  unsigned int size, unsigned int skipnr)
{
	stack_trace_consume_fn consume_entry = stack_trace_consume_entry_nosched;
	struct stacktrace_cookie c = {
		.store	= store,
		.size	= size,
		/* skip this function if they are tracing us */
		.skip	= skipnr + (current == tsk),
	};

	if (!try_get_task_stack(tsk))
		return 0;

	arch_stack_walk(consume_entry, &c, tsk, NULL);
	put_task_stack(tsk);
	return c.len;
}

unsigned int stack_trace_save_regs(struct pt_regs *regs, unsigned long *store,
				   unsigned int size, unsigned int skipnr)
{
	stack_trace_consume_fn consume_entry = stack_trace_consume_entry;
	struct stacktrace_cookie c = {
		.store	= store,
		.size	= size,
		.skip	= skipnr,
	};

	arch_stack_walk(consume_entry, &c, current, regs);
	return c.len;
}

#ifdef CONFIG_HAVE_RELIABLE_STACKTRACE
int stack_trace_save_tsk_reliable(struct task_struct *tsk, unsigned long *store,
				  unsigned int size)
{
	stack_trace_consume_fn consume_entry = stack_trace_consume_entry;
	struct stacktrace_cookie c = {
		.store	= store,
		.size	= size,
	};
	int ret;

	/*
	if (!try_get_task_stack(tsk))
		return 0;

	ret = arch_stack_walk_reliable(consume_entry, &c, tsk);
	put_task_stack(tsk);
	return ret ? ret : c.len;
}
#endif

#ifdef CONFIG_USER_STACKTRACE_SUPPORT
unsigned int stack_trace_save_user(unsigned long *store, unsigned int size)
{
	stack_trace_consume_fn consume_entry = stack_trace_consume_entry;
	struct stacktrace_cookie c = {
		.store	= store,
		.size	= size,
	};

	/* Trace user stack if not a kernel thread */
	if (current->flags & PF_KTHREAD)
		return 0;

	arch_stack_walk_user(consume_entry, &c, task_pt_regs(current));

	return c.len;
}
#endif

#else /* CONFIG_ARCH_STACKWALK */

__weak void
save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
{
	WARN_ONCE(1, KERN_INFO "save_stack_trace_tsk() not implemented yet.\n");
}

__weak void
save_stack_trace_regs(struct pt_regs *regs, struct stack_trace *trace)
{
	WARN_ONCE(1, KERN_INFO "save_stack_trace_regs() not implemented yet.\n");
}

unsigned int stack_trace_save(unsigned long *store, unsigned int size,
			      unsigned int skipnr)
{
	struct stack_trace trace = {
		.entries	= store,
		.max_entries	= size,
		.skip		= skipnr + 1,
	};

	save_stack_trace(&trace);
	return trace.nr_entries;
}
EXPORT_SYMBOL_GPL(stack_trace_save);

unsigned int stack_trace_save_tsk(struct task_struct *task,
				  unsigned long *store, unsigned int size,
				  unsigned int skipnr)
{
	struct stack_trace trace = {
		.entries	= store,
		.max_entries	= size,
		/* skip this function if they are tracing us */
		.skip	= skipnr + (current == task),
	};

	save_stack_trace_tsk(task, &trace);
	return trace.nr_entries;
}

unsigned int stack_trace_save_regs(struct pt_regs *regs, unsigned long *store,
				   unsigned int size, unsigned int skipnr)
{
	struct stack_trace trace = {
		.entries	= store,
		.max_entries	= size,
		.skip		= skipnr,
	};

	save_stack_trace_regs(regs, &trace);
	return trace.nr_entries;
}

#ifdef CONFIG_HAVE_RELIABLE_STACKTRACE
int stack_trace_save_tsk_reliable(struct task_struct *tsk, unsigned long *store,
				  unsigned int size)
{
	struct stack_trace trace = {
		.entries	= store,
		.max_entries	= size,
	};
	int ret = save_stack_trace_tsk_reliable(tsk, &trace);

	return ret ? ret : trace.nr_entries;
}
#endif

#ifdef CONFIG_USER_STACKTRACE_SUPPORT
unsigned int stack_trace_save_user(unsigned long *store, unsigned int size)
{
	struct stack_trace trace = {
		.entries	= store,
		.max_entries	= size,
	};

	save_stack_trace_user(&trace);
	return trace.nr_entries;
}
#endif /* CONFIG_USER_STACKTRACE_SUPPORT */

#endif /* !CONFIG_ARCH_STACKWALK */

static inline bool in_irqentry_text(unsigned long ptr)
{
	return (ptr >= (unsigned long)&__irqentry_text_start &&
		ptr < (unsigned long)&__irqentry_text_end) ||
		(ptr >= (unsigned long)&__softirqentry_text_start &&
		 ptr < (unsigned long)&__softirqentry_text_end);
}

unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries)
{
	unsigned int i;

	for (i = 0; i < nr_entries; i++) {
		if (in_irqentry_text(entries[i])) {
			/* Include the irqentry function into the stack. */
			return i + 1;
		}
	}
	return nr_entries;
}
EXPORT_SYMBOL_GPL(filter_irq_stacks);
