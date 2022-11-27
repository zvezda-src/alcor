#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <asm/desc.h>
#include <asm/mmu_context.h>

unsigned long convert_ip_to_linear(struct task_struct *child, struct pt_regs *regs)
{
	unsigned long addr, seg;

	addr = regs->ip;
	seg = regs->cs;
	if (v8086_mode(regs)) {
		addr = (addr & 0xffff) + (seg << 4);
		return addr;
	}

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	/*
	if ((seg & SEGMENT_TI_MASK) == SEGMENT_LDT) {
		struct desc_struct *desc;
		unsigned long base;

		seg >>= 3;

		mutex_lock(&child->mm->context.lock);
		if (unlikely(!child->mm->context.ldt ||
			     seg >= child->mm->context.ldt->nr_entries))
			addr = -1L; /* bogus selector, access would fault */
		else {
			desc = &child->mm->context.ldt->entries[seg];
			base = get_desc_base(desc);

			/* 16-bit code segment? */
			if (!desc->d)
				addr &= 0xffff;
			addr += base;
		}
		mutex_unlock(&child->mm->context.lock);
	}
#endif

	return addr;
}

static int is_setting_trap_flag(struct task_struct *child, struct pt_regs *regs)
{
	int i, copied;
	unsigned char opcode[15];
	unsigned long addr = convert_ip_to_linear(child, regs);

	copied = access_process_vm(child, addr, opcode, sizeof(opcode),
			FOLL_FORCE);
	for (i = 0; i < copied; i++) {
		switch (opcode[i]) {
		/* popf and iret */
		case 0x9d: case 0xcf:
			return 1;

			/* CHECKME: 64 65 */

		/* opcode and address size prefixes */
		case 0x66: case 0x67:
			continue;
		/* irrelevant prefixes (segment overrides and repeats) */
		case 0x26: case 0x2e:
		case 0x36: case 0x3e:
		case 0x64: case 0x65:
		case 0xf0: case 0xf2: case 0xf3:
			continue;

#ifdef CONFIG_X86_64
		case 0x40 ... 0x4f:
			if (!user_64bit_mode(regs))
				/* 32-bit mode: register increment */
				return 0;
			/* 64-bit mode: REX prefix */
			continue;
#endif

			/* CHECKME: f2, f3 */

		/*
		case 0x9c:
		default:
			return 0;
		}
	}
	return 0;
}

static int enable_single_step(struct task_struct *child)
{
	struct pt_regs *regs = task_pt_regs(child);
	unsigned long oflags;

	/*
	if (unlikely(test_tsk_thread_flag(child, TIF_SINGLESTEP)))
		regs->flags |= X86_EFLAGS_TF;

	/*
	set_tsk_thread_flag(child, TIF_SINGLESTEP);

	/*
	set_task_syscall_work(child, SYSCALL_EXIT_TRAP);

	oflags = regs->flags;

	/* Set TF on the kernel stack.. */
	regs->flags |= X86_EFLAGS_TF;

	/*
	if (is_setting_trap_flag(child, regs)) {
		clear_tsk_thread_flag(child, TIF_FORCED_TF);
		return 0;
	}

	/*
	if (oflags & X86_EFLAGS_TF)
		return test_tsk_thread_flag(child, TIF_FORCED_TF);

	set_tsk_thread_flag(child, TIF_FORCED_TF);

	return 1;
}

void set_task_blockstep(struct task_struct *task, bool on)
{
	unsigned long debugctl;

	/*
	local_irq_disable();
	debugctl = get_debugctlmsr();
	if (on) {
		debugctl |= DEBUGCTLMSR_BTF;
		set_tsk_thread_flag(task, TIF_BLOCKSTEP);
	} else {
		debugctl &= ~DEBUGCTLMSR_BTF;
		clear_tsk_thread_flag(task, TIF_BLOCKSTEP);
	}
	if (task == current)
		update_debugctlmsr(debugctl);
	local_irq_enable();
}

static void enable_step(struct task_struct *child, bool block)
{
	/*
	if (enable_single_step(child) && block)
		set_task_blockstep(child, true);
	else if (test_tsk_thread_flag(child, TIF_BLOCKSTEP))
		set_task_blockstep(child, false);
}

void user_enable_single_step(struct task_struct *child)
{
	enable_step(child, 0);
}

void user_enable_block_step(struct task_struct *child)
{
	enable_step(child, 1);
}

void user_disable_single_step(struct task_struct *child)
{
	/*
	if (test_tsk_thread_flag(child, TIF_BLOCKSTEP))
		set_task_blockstep(child, false);

	/* Always clear TIF_SINGLESTEP... */
	clear_tsk_thread_flag(child, TIF_SINGLESTEP);
	clear_task_syscall_work(child, SYSCALL_EXIT_TRAP);

	/* But touch TF only if it was set by us.. */
	if (test_and_clear_tsk_thread_flag(child, TIF_FORCED_TF))
		task_pt_regs(child)->flags &= ~X86_EFLAGS_TF;
}
