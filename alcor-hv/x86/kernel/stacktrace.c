#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
		     struct task_struct *task, struct pt_regs *regs)
{
	struct unwind_state state;
	unsigned long addr;

	if (regs && !consume_entry(cookie, regs->ip))
		return;

	for (unwind_start(&state, task, regs, NULL); !unwind_done(&state);
	     unwind_next_frame(&state)) {
		addr = unwind_get_return_address(&state);
		if (!addr || !consume_entry(cookie, addr))
			break;
	}
}

int arch_stack_walk_reliable(stack_trace_consume_fn consume_entry,
			     void *cookie, struct task_struct *task)
{
	struct unwind_state state;
	struct pt_regs *regs;
	unsigned long addr;

	for (unwind_start(&state, task, NULL, NULL);
	     !unwind_done(&state) && !unwind_error(&state);
	     unwind_next_frame(&state)) {

		regs = unwind_get_entry_regs(&state, NULL);
		if (regs) {
			/* Success path for user tasks */
			if (user_mode(regs))
				return 0;

			/*
			if (IS_ENABLED(CONFIG_FRAME_POINTER))
				return -EINVAL;
		}

		addr = unwind_get_return_address(&state);

		/*
		if (!addr)
			return -EINVAL;

		if (!consume_entry(cookie, addr))
			return -EINVAL;
	}

	/* Check for stack corruption */
	if (unwind_error(&state))
		return -EINVAL;

	return 0;
}


struct stack_frame_user {
	const void __user	*next_fp;
	unsigned long		ret_addr;
};

static int
copy_stack_frame(const struct stack_frame_user __user *fp,
		 struct stack_frame_user *frame)
{
	int ret;

	if (!__access_ok(fp, sizeof(*frame)))
		return 0;

	ret = 1;
	pagefault_disable();
	if (__get_user(frame->next_fp, &fp->next_fp) ||
	    __get_user(frame->ret_addr, &fp->ret_addr))
		ret = 0;
	pagefault_enable();

	return ret;
}

void arch_stack_walk_user(stack_trace_consume_fn consume_entry, void *cookie,
			  const struct pt_regs *regs)
{
	const void __user *fp = (const void __user *)regs->bp;

	if (!consume_entry(cookie, regs->ip))
		return;

	while (1) {
		struct stack_frame_user frame;

		frame.next_fp = NULL;
		frame.ret_addr = 0;
		if (!copy_stack_frame(fp, &frame))
			break;
		if ((unsigned long)fp < regs->sp)
			break;
		if (!frame.ret_addr)
			break;
		if (!consume_entry(cookie, frame.ret_addr))
			break;
		fp = frame.next_fp;
	}
}

