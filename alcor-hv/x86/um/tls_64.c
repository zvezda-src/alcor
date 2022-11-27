#include <linux/sched.h>
#include <asm/ptrace-abi.h>

void clear_flushed_tls(struct task_struct *task)
{
}

int arch_set_tls(struct task_struct *t, unsigned long tls)
{
	/*
	t->thread.arch.fs = tls;

	return 0;
}
