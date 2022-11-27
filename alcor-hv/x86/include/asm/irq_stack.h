#ifndef _ASM_X86_IRQ_STACK_H
#define _ASM_X86_IRQ_STACK_H

#include <linux/ptrace.h>
#include <linux/objtool.h>

#include <asm/processor.h>

#ifdef CONFIG_X86_64

#define call_on_stack(stack, func, asm_call, argconstr...)		\
{									\
	register void *tos asm("r11");					\
									\
	tos = ((void *)(stack));					\
									\
	asm_inline volatile(						\
	"movq	%%rsp, (%[tos])				\n"		\
	"movq	%[tos], %%rsp				\n"		\
									\
	asm_call							\
									\
	"popq	%%rsp					\n"		\
									\
	: "+r" (tos), ASM_CALL_CONSTRAINT				\
	: [__func] "i" (func), [tos] "r" (tos) argconstr		\
	: "cc", "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",	\
	  "memory"							\
	);								\
}

#define ASM_CALL_ARG0							\
	"call %P[__func]				\n"		\
	ASM_REACHABLE

#define ASM_CALL_ARG1							\
	"movq	%[arg1], %%rdi				\n"		\
	ASM_CALL_ARG0

#define ASM_CALL_ARG2							\
	"movq	%[arg2], %%rsi				\n"		\
	ASM_CALL_ARG1

#define ASM_CALL_ARG3							\
	"movq	%[arg3], %%rdx				\n"		\
	ASM_CALL_ARG2

#define call_on_irqstack(func, asm_call, argconstr...)			\
	call_on_stack(__this_cpu_read(hardirq_stack_ptr),		\
		      func, asm_call, argconstr)

#define assert_function_type(func, proto)				\
	static_assert(__builtin_types_compatible_p(typeof(&func), proto))

#define assert_arg_type(arg, proto)					\
	static_assert(__builtin_types_compatible_p(typeof(arg), proto))

#define call_on_irqstack_cond(func, regs, asm_call, constr, c_args...)	\
{									\
	/*								\
	 * User mode entry and interrupt on the irq stack do not	\
	 * switch stacks. If from user mode the task stack is empty.	\
	 */								\
	if (user_mode(regs) || __this_cpu_read(hardirq_stack_inuse)) {	\
		irq_enter_rcu();					\
		func(c_args);						\
		irq_exit_rcu();						\
	} else {							\
		/*							\
		 * Mark the irq stack inuse _before_ and unmark _after_	\
		 * switching stacks. Interrupts are disabled in both	\
		 * places. Invoke the stack switch macro with the call	\
		 * sequence which matches the above direct invocation.	\
		 */							\
		__this_cpu_write(hardirq_stack_inuse, true);		\
		call_on_irqstack(func, asm_call, constr);		\
		__this_cpu_write(hardirq_stack_inuse, false);		\
	}								\
}

#define ASM_CALL_SYSVEC							\
	"call irq_enter_rcu				\n"		\
	ASM_CALL_ARG1							\
	"call irq_exit_rcu				\n"

#define SYSVEC_CONSTRAINTS	, [arg1] "r" (regs)

#define run_sysvec_on_irqstack_cond(func, regs)				\
{									\
	assert_function_type(func, void (*)(struct pt_regs *));		\
	assert_arg_type(regs, struct pt_regs *);			\
									\
	call_on_irqstack_cond(func, regs, ASM_CALL_SYSVEC,		\
			      SYSVEC_CONSTRAINTS, regs);		\
}

#define ASM_CALL_IRQ							\
	"call irq_enter_rcu				\n"		\
	ASM_CALL_ARG2							\
	"call irq_exit_rcu				\n"

#define IRQ_CONSTRAINTS	, [arg1] "r" (regs), [arg2] "r" ((unsigned long)vector)

#define run_irq_on_irqstack_cond(func, regs, vector)			\
{									\
	assert_function_type(func, void (*)(struct pt_regs *, u32));	\
	assert_arg_type(regs, struct pt_regs *);			\
	assert_arg_type(vector, u32);					\
									\
	call_on_irqstack_cond(func, regs, ASM_CALL_IRQ,			\
			      IRQ_CONSTRAINTS, regs, vector);		\
}

#ifndef CONFIG_PREEMPT_RT
#define do_softirq_own_stack()						\
{									\
	__this_cpu_write(hardirq_stack_inuse, true);			\
	call_on_irqstack(__do_softirq, ASM_CALL_ARG0);			\
	__this_cpu_write(hardirq_stack_inuse, false);			\
}

#endif

#else /* CONFIG_X86_64 */
#define run_sysvec_on_irqstack_cond(func, regs)				\
{									\
	irq_enter_rcu();						\
	func(regs);							\
	irq_exit_rcu();							\
}

#define run_irq_on_irqstack_cond(func, regs, vector)			\
{									\
	irq_enter_rcu();						\
	func(regs, vector);						\
	irq_exit_rcu();							\
}

#endif /* !CONFIG_X86_64 */

#endif
