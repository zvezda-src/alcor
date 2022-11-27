//
// Code shared between 32 and 64 bit

#include <asm/spec-ctrl.h>

void __switch_to_xtra(struct task_struct *prev_p, struct task_struct *next_p);

static inline void switch_to_extra(struct task_struct *prev,
				   struct task_struct *next)
{
	unsigned long next_tif = read_task_thread_flags(next);
	unsigned long prev_tif = read_task_thread_flags(prev);

	if (IS_ENABLED(CONFIG_SMP)) {
		/*
		if (!static_branch_likely(&switch_to_cond_stibp)) {
			prev_tif &= ~_TIF_SPEC_IB;
			next_tif &= ~_TIF_SPEC_IB;
		}
	}

	/*
	if (unlikely(next_tif & _TIF_WORK_CTXSW_NEXT ||
		     prev_tif & _TIF_WORK_CTXSW_PREV))
		__switch_to_xtra(prev, next);
}
