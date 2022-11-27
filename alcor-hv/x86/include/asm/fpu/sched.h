#ifndef _ASM_X86_FPU_SCHED_H
#define _ASM_X86_FPU_SCHED_H

#include <linux/sched.h>

#include <asm/cpufeature.h>
#include <asm/fpu/types.h>

#include <asm/trace/fpu.h>

extern void save_fpregs_to_fpstate(struct fpu *fpu);
extern void fpu__drop(struct fpu *fpu);
extern int  fpu_clone(struct task_struct *dst, unsigned long clone_flags, bool minimal);
extern void fpu_flush_thread(void);

static inline void switch_fpu_prepare(struct fpu *old_fpu, int cpu)
{
	if (cpu_feature_enabled(X86_FEATURE_FPU) &&
	    !(current->flags & PF_KTHREAD)) {
		save_fpregs_to_fpstate(old_fpu);
		/*
		old_fpu->last_cpu = cpu;

		trace_x86_fpu_regs_deactivated(old_fpu);
	}
}

static inline void switch_fpu_finish(void)
{
	if (cpu_feature_enabled(X86_FEATURE_FPU))
		set_thread_flag(TIF_NEED_FPU_LOAD);
}

#endif /* _ASM_X86_FPU_SCHED_H */
