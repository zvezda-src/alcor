#ifndef __X86_KERNEL_FPU_CONTEXT_H
#define __X86_KERNEL_FPU_CONTEXT_H

#include <asm/fpu/xstate.h>
#include <asm/trace/fpu.h>


static inline void __cpu_invalidate_fpregs_state(void)
{
	__this_cpu_write(fpu_fpregs_owner_ctx, NULL);
}

static inline void __fpu_invalidate_fpregs_state(struct fpu *fpu)
{
	fpu->last_cpu = -1;
}

static inline int fpregs_state_valid(struct fpu *fpu, unsigned int cpu)
{
	return fpu == this_cpu_read(fpu_fpregs_owner_ctx) && cpu == fpu->last_cpu;
}

static inline void fpregs_deactivate(struct fpu *fpu)
{
	__this_cpu_write(fpu_fpregs_owner_ctx, NULL);
	trace_x86_fpu_regs_deactivated(fpu);
}

static inline void fpregs_activate(struct fpu *fpu)
{
	__this_cpu_write(fpu_fpregs_owner_ctx, fpu);
	trace_x86_fpu_regs_activated(fpu);
}

static inline void fpregs_restore_userregs(void)
{
	struct fpu *fpu = &current->thread.fpu;
	int cpu = smp_processor_id();

	if (WARN_ON_ONCE(current->flags & PF_KTHREAD))
		return;

	if (!fpregs_state_valid(fpu, cpu)) {
		/*
		restore_fpregs_from_fpstate(fpu->fpstate, XFEATURE_MASK_FPSTATE);

		fpregs_activate(fpu);
		fpu->last_cpu = cpu;
	}
	clear_thread_flag(TIF_NEED_FPU_LOAD);
}

#endif
