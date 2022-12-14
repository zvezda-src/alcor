#ifndef _ASM_X86_FPU_REGSET_H
#define _ASM_X86_FPU_REGSET_H

#include <linux/regset.h>

extern user_regset_active_fn regset_fpregs_active, regset_xregset_fpregs_active;
extern user_regset_get2_fn fpregs_get, xfpregs_get, fpregs_soft_get,
				 xstateregs_get;
extern user_regset_set_fn fpregs_set, xfpregs_set, fpregs_soft_set,
				 xstateregs_set;

#define xstateregs_active	regset_fpregs_active

#endif /* _ASM_X86_FPU_REGSET_H */
