#include <linux/jump_label.h>
#include <linux/suspend.h>
#include <linux/ftrace.h>
#include <linux/slab.h>

#include <trace/events/sched.h>

#include "ftrace_internal.h"

#ifdef CONFIG_DYNAMIC_FTRACE
#define ASSIGN_OPS_HASH(opsname, val) \
	.func_hash		= val, \
	.local_hash.regex_lock	= __MUTEX_INITIALIZER(opsname.local_hash.regex_lock),
#else
#define ASSIGN_OPS_HASH(opsname, val)
#endif

DEFINE_STATIC_KEY_FALSE(kill_ftrace_graph);
int ftrace_graph_active;

static bool fgraph_sleep_time = true;

#ifdef CONFIG_DYNAMIC_FTRACE
int __weak ftrace_enable_ftrace_graph_caller(void)
{
	return 0;
}

int __weak ftrace_disable_ftrace_graph_caller(void)
{
	return 0;
}
#endif

void ftrace_graph_stop(void)
{
	static_branch_enable(&kill_ftrace_graph);
}

static int
ftrace_push_return_trace(unsigned long ret, unsigned long func,
			 unsigned long frame_pointer, unsigned long *retp)
{
	unsigned long long calltime;
	int index;

	if (unlikely(ftrace_graph_is_dead()))
		return -EBUSY;

	if (!current->ret_stack)
		return -EBUSY;

	/*
	smp_rmb();

	/* The return trace stack is full */
	if (current->curr_ret_stack == FTRACE_RETFUNC_DEPTH - 1) {
		atomic_inc(&current->trace_overrun);
		return -EBUSY;
	}

	calltime = trace_clock_local();

	index = ++current->curr_ret_stack;
	barrier();
	current->ret_stack[index].ret = ret;
	current->ret_stack[index].func = func;
	current->ret_stack[index].calltime = calltime;
#ifdef HAVE_FUNCTION_GRAPH_FP_TEST
	current->ret_stack[index].fp = frame_pointer;
#endif
#ifdef HAVE_FUNCTION_GRAPH_RET_ADDR_PTR
	current->ret_stack[index].retp = retp;
#endif
	return 0;
}

#ifndef MCOUNT_INSN_SIZE
# ifdef CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
#  error MCOUNT_INSN_SIZE not defined with direct calls enabled
# endif
# define MCOUNT_INSN_SIZE 0
#endif

int function_graph_enter(unsigned long ret, unsigned long func,
			 unsigned long frame_pointer, unsigned long *retp)
{
	struct ftrace_graph_ent trace;

#ifndef CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS
	/*
	if (ftrace_direct_func_count &&
	    ftrace_find_rec_direct(ret - MCOUNT_INSN_SIZE))
		return -EBUSY;
#endif
	trace.func = func;
	trace.depth = ++current->curr_ret_depth;

	if (ftrace_push_return_trace(ret, func, frame_pointer, retp))
		goto out;

	/* Only trace if the calling function expects to */
	if (!ftrace_graph_entry(&trace))
		goto out_ret;

	return 0;
 out_ret:
	current->curr_ret_stack--;
 out:
	current->curr_ret_depth--;
	return -EBUSY;
}

static void
ftrace_pop_return_trace(struct ftrace_graph_ret *trace, unsigned long *ret,
			unsigned long frame_pointer)
{
	int index;

	index = current->curr_ret_stack;

	if (unlikely(index < 0 || index >= FTRACE_RETFUNC_DEPTH)) {
		ftrace_graph_stop();
		WARN_ON(1);
		/* Might as well panic, otherwise we have no where to go */
		*ret = (unsigned long)panic;
		return;
	}

#ifdef HAVE_FUNCTION_GRAPH_FP_TEST
	/*
	if (unlikely(current->ret_stack[index].fp != frame_pointer)) {
		ftrace_graph_stop();
		WARN(1, "Bad frame pointer: expected %lx, received %lx\n"
		     "  from func %ps return to %lx\n",
		     current->ret_stack[index].fp,
		     frame_pointer,
		     (void *)current->ret_stack[index].func,
		     current->ret_stack[index].ret);
		*ret = (unsigned long)panic;
		return;
	}
#endif

	trace->func = current->ret_stack[index].func;
	trace->calltime = current->ret_stack[index].calltime;
	trace->overrun = atomic_read(&current->trace_overrun);
	trace->depth = current->curr_ret_depth--;
	/*
	barrier();
}

static int
ftrace_suspend_notifier_call(struct notifier_block *bl, unsigned long state,
							void *unused)
{
	switch (state) {
	case PM_HIBERNATION_PREPARE:
		pause_graph_tracing();
		break;

	case PM_POST_HIBERNATION:
		unpause_graph_tracing();
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block ftrace_suspend_notifier = {
	.notifier_call = ftrace_suspend_notifier_call,
};

unsigned long ftrace_return_to_handler(unsigned long frame_pointer)
{
	struct ftrace_graph_ret trace;
	unsigned long ret;

	ftrace_pop_return_trace(&trace, &ret, frame_pointer);
	trace.rettime = trace_clock_local();
	ftrace_graph_return(&trace);
	/*
	barrier();
	current->curr_ret_stack--;

	if (unlikely(!ret)) {
		ftrace_graph_stop();
		WARN_ON(1);
		/* Might as well panic. What else to do? */
		ret = (unsigned long)panic;
	}

	return ret;
}

struct ftrace_ret_stack *
ftrace_graph_get_ret_stack(struct task_struct *task, int idx)
{
	idx = task->curr_ret_stack - idx;

	if (idx >= 0 && idx <= task->curr_ret_stack)
		return &task->ret_stack[idx];

	return NULL;
}

#ifdef HAVE_FUNCTION_GRAPH_RET_ADDR_PTR
unsigned long ftrace_graph_ret_addr(struct task_struct *task, int *idx,
				    unsigned long ret, unsigned long *retp)
{
	int index = task->curr_ret_stack;
	int i;

	if (ret != (unsigned long)dereference_kernel_function_descriptor(return_to_handler))
		return ret;

	if (index < 0)
		return ret;

	for (i = 0; i <= index; i++)
		if (task->ret_stack[i].retp == retp)
			return task->ret_stack[i].ret;

	return ret;
}
#else /* !HAVE_FUNCTION_GRAPH_RET_ADDR_PTR */
unsigned long ftrace_graph_ret_addr(struct task_struct *task, int *idx,
				    unsigned long ret, unsigned long *retp)
{
	int task_idx;

	if (ret != (unsigned long)dereference_kernel_function_descriptor(return_to_handler))
		return ret;

	task_idx = task->curr_ret_stack;

	if (!task->ret_stack || task_idx < *idx)
		return ret;

	task_idx -= *idx;
	(*idx)++;

	return task->ret_stack[task_idx].ret;
}
#endif /* HAVE_FUNCTION_GRAPH_RET_ADDR_PTR */

static struct ftrace_ops graph_ops = {
	.func			= ftrace_graph_func,
	.flags			= FTRACE_OPS_FL_INITIALIZED |
				   FTRACE_OPS_FL_PID |
				   FTRACE_OPS_GRAPH_STUB,
#ifdef FTRACE_GRAPH_TRAMP_ADDR
	.trampoline		= FTRACE_GRAPH_TRAMP_ADDR,
	/* trampoline_size is only needed for dynamically allocated tramps */
#endif
	ASSIGN_OPS_HASH(graph_ops, &global_ops.local_hash)
};

void ftrace_graph_sleep_time_control(bool enable)
{
	fgraph_sleep_time = enable;
}

int ftrace_graph_entry_stub(struct ftrace_graph_ent *trace)
{
	return 0;
}

extern void ftrace_stub_graph(struct ftrace_graph_ret *);

trace_func_graph_ret_t ftrace_graph_return = ftrace_stub_graph;
trace_func_graph_ent_t ftrace_graph_entry = ftrace_graph_entry_stub;
static trace_func_graph_ent_t __ftrace_graph_entry = ftrace_graph_entry_stub;

static int alloc_retstack_tasklist(struct ftrace_ret_stack **ret_stack_list)
{
	int i;
	int ret = 0;
	int start = 0, end = FTRACE_RETSTACK_ALLOC_SIZE;
	struct task_struct *g, *t;

	for (i = 0; i < FTRACE_RETSTACK_ALLOC_SIZE; i++) {
		ret_stack_list[i] =
			kmalloc_array(FTRACE_RETFUNC_DEPTH,
				      sizeof(struct ftrace_ret_stack),
				      GFP_KERNEL);
		if (!ret_stack_list[i]) {
			start = 0;
			end = i;
			ret = -ENOMEM;
			goto free;
		}
	}

	rcu_read_lock();
	for_each_process_thread(g, t) {
		if (start == end) {
			ret = -EAGAIN;
			goto unlock;
		}

		if (t->ret_stack == NULL) {
			atomic_set(&t->trace_overrun, 0);
			t->curr_ret_stack = -1;
			t->curr_ret_depth = -1;
			/* Make sure the tasks see the -1 first: */
			smp_wmb();
			t->ret_stack = ret_stack_list[start++];
		}
	}

unlock:
	rcu_read_unlock();
free:
	for (i = start; i < end; i++)
		kfree(ret_stack_list[i]);
	return ret;
}

static void
ftrace_graph_probe_sched_switch(void *ignore, bool preempt,
				struct task_struct *prev,
				struct task_struct *next,
				unsigned int prev_state)
{
	unsigned long long timestamp;
	int index;

	/*
	if (fgraph_sleep_time)
		return;

	timestamp = trace_clock_local();

	prev->ftrace_timestamp = timestamp;

	/* only process tasks that we timestamped */
	if (!next->ftrace_timestamp)
		return;

	/*
	timestamp -= next->ftrace_timestamp;

	for (index = next->curr_ret_stack; index >= 0; index--)
		next->ret_stack[index].calltime += timestamp;
}

static int ftrace_graph_entry_test(struct ftrace_graph_ent *trace)
{
	if (!ftrace_ops_test(&global_ops, trace->func, NULL))
		return 0;
	return __ftrace_graph_entry(trace);
}

void update_function_graph_func(void)
{
	struct ftrace_ops *op;
	bool do_test = false;

	/*
	do_for_each_ftrace_op(op, ftrace_ops_list) {
		if (op != &global_ops && op != &graph_ops &&
		    op != &ftrace_list_end) {
			do_test = true;
			/* in double loop, break out with goto */
			goto out;
		}
	} while_for_each_ftrace_op(op);
 out:
	if (do_test)
		ftrace_graph_entry = ftrace_graph_entry_test;
	else
		ftrace_graph_entry = __ftrace_graph_entry;
}

static DEFINE_PER_CPU(struct ftrace_ret_stack *, idle_ret_stack);

static void
graph_init_task(struct task_struct *t, struct ftrace_ret_stack *ret_stack)
{
	atomic_set(&t->trace_overrun, 0);
	t->ftrace_timestamp = 0;
	/* make curr_ret_stack visible before we add the ret_stack */
	smp_wmb();
	t->ret_stack = ret_stack;
}

void ftrace_graph_init_idle_task(struct task_struct *t, int cpu)
{
	t->curr_ret_stack = -1;
	t->curr_ret_depth = -1;
	/*
	if (t->ret_stack)
		WARN_ON(t->ret_stack != per_cpu(idle_ret_stack, cpu));

	if (ftrace_graph_active) {
		struct ftrace_ret_stack *ret_stack;

		ret_stack = per_cpu(idle_ret_stack, cpu);
		if (!ret_stack) {
			ret_stack =
				kmalloc_array(FTRACE_RETFUNC_DEPTH,
					      sizeof(struct ftrace_ret_stack),
					      GFP_KERNEL);
			if (!ret_stack)
				return;
			per_cpu(idle_ret_stack, cpu) = ret_stack;
		}
		graph_init_task(t, ret_stack);
	}
}

void ftrace_graph_init_task(struct task_struct *t)
{
	/* Make sure we do not use the parent ret_stack */
	t->ret_stack = NULL;
	t->curr_ret_stack = -1;
	t->curr_ret_depth = -1;

	if (ftrace_graph_active) {
		struct ftrace_ret_stack *ret_stack;

		ret_stack = kmalloc_array(FTRACE_RETFUNC_DEPTH,
					  sizeof(struct ftrace_ret_stack),
					  GFP_KERNEL);
		if (!ret_stack)
			return;
		graph_init_task(t, ret_stack);
	}
}

void ftrace_graph_exit_task(struct task_struct *t)
{
	struct ftrace_ret_stack	*ret_stack = t->ret_stack;

	t->ret_stack = NULL;
	/* NULL must become visible to IRQs before we free it: */
	barrier();

	kfree(ret_stack);
}

static int start_graph_tracing(void)
{
	struct ftrace_ret_stack **ret_stack_list;
	int ret, cpu;

	ret_stack_list = kmalloc_array(FTRACE_RETSTACK_ALLOC_SIZE,
				       sizeof(struct ftrace_ret_stack *),
				       GFP_KERNEL);

	if (!ret_stack_list)
		return -ENOMEM;

	/* The cpu_boot init_task->ret_stack will never be freed */
	for_each_online_cpu(cpu) {
		if (!idle_task(cpu)->ret_stack)
			ftrace_graph_init_idle_task(idle_task(cpu), cpu);
	}

	do {
		ret = alloc_retstack_tasklist(ret_stack_list);
	} while (ret == -EAGAIN);

	if (!ret) {
		ret = register_trace_sched_switch(ftrace_graph_probe_sched_switch, NULL);
		if (ret)
			pr_info("ftrace_graph: Couldn't activate tracepoint"
				" probe to kernel_sched_switch\n");
	}

	kfree(ret_stack_list);
	return ret;
}

int register_ftrace_graph(struct fgraph_ops *gops)
{
	int ret = 0;

	mutex_lock(&ftrace_lock);

	/* we currently allow only one tracer registered at a time */
	if (ftrace_graph_active) {
		ret = -EBUSY;
		goto out;
	}

	register_pm_notifier(&ftrace_suspend_notifier);

	ftrace_graph_active++;
	ret = start_graph_tracing();
	if (ret) {
		ftrace_graph_active--;
		goto out;
	}

	ftrace_graph_return = gops->retfunc;

	/*
	__ftrace_graph_entry = gops->entryfunc;
	ftrace_graph_entry = ftrace_graph_entry_test;
	update_function_graph_func();

	ret = ftrace_startup(&graph_ops, FTRACE_START_FUNC_RET);
out:
	mutex_unlock(&ftrace_lock);
	return ret;
}

void unregister_ftrace_graph(struct fgraph_ops *gops)
{
	mutex_lock(&ftrace_lock);

	if (unlikely(!ftrace_graph_active))
		goto out;

	ftrace_graph_active--;
	ftrace_graph_return = ftrace_stub_graph;
	ftrace_graph_entry = ftrace_graph_entry_stub;
	__ftrace_graph_entry = ftrace_graph_entry_stub;
	ftrace_shutdown(&graph_ops, FTRACE_STOP_FUNC_RET);
	unregister_pm_notifier(&ftrace_suspend_notifier);
	unregister_trace_sched_switch(ftrace_graph_probe_sched_switch, NULL);

 out:
	mutex_unlock(&ftrace_lock);
}
