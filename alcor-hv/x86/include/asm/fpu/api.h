
#ifndef _ASM_X86_FPU_API_H
#define _ASM_X86_FPU_API_H
#include <linux/bottom_half.h>

#include <asm/fpu/types.h>


#define KFPU_387	_BITUL(0)	/* 387 state will be initialized */
#define KFPU_MXCSR	_BITUL(1)	/* MXCSR will be initialized */

extern void kernel_fpu_begin_mask(unsigned int kfpu_mask);
extern void kernel_fpu_end(void);
extern bool irq_fpu_usable(void);
extern void fpregs_mark_activate(void);

static inline void kernel_fpu_begin(void)
{
#ifdef CONFIG_X86_64
	/*
	kernel_fpu_begin_mask(KFPU_MXCSR);
#else
	/*
	kernel_fpu_begin_mask(KFPU_387 | KFPU_MXCSR);
#endif
}

static inline void fpregs_lock(void)
{
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
		local_bh_disable();
	else
		preempt_disable();
}

static inline void fpregs_unlock(void)
{
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
		local_bh_enable();
	else
		preempt_enable();
}

#ifdef CONFIG_X86_DEBUG_FPU
extern void fpregs_assert_state_consistent(void);
#else
static inline void fpregs_assert_state_consistent(void) { }
#endif

extern void switch_fpu_return(void);

extern int cpu_has_xfeatures(u64 xfeatures_mask, const char **feature_name);

extern int  fpu__exception_code(struct fpu *fpu, int trap_nr);
extern void fpu_sync_fpstate(struct fpu *fpu);
extern void fpu_reset_from_exception_fixup(void);

extern void fpu__init_cpu(void);
extern void fpu__init_system(struct cpuinfo_x86 *c);
extern void fpu__init_check_bugs(void);
extern void fpu__resume_cpu(void);

#ifdef CONFIG_MATH_EMULATION
extern void fpstate_init_soft(struct swregs_state *soft);
#else
static inline void fpstate_init_soft(struct swregs_state *soft) {}
#endif

DECLARE_PER_CPU(struct fpu *, fpu_fpregs_owner_ctx);

#ifdef CONFIG_X86_64
extern void fpstate_free(struct fpu *fpu);
#else
static inline void fpstate_free(struct fpu *fpu) { }
#endif

extern void fpstate_clear_xstate_component(struct fpstate *fps, unsigned int xfeature);

extern u64 xstate_get_guest_group_perm(void);

extern bool fpu_alloc_guest_fpstate(struct fpu_guest *gfpu);
extern void fpu_free_guest_fpstate(struct fpu_guest *gfpu);
extern int fpu_swap_kvm_fpstate(struct fpu_guest *gfpu, bool enter_guest);
extern int fpu_enable_guest_xfd_features(struct fpu_guest *guest_fpu, u64 xfeatures);

#ifdef CONFIG_X86_64
extern void fpu_update_guest_xfd(struct fpu_guest *guest_fpu, u64 xfd);
extern void fpu_sync_guest_vmexit_xfd_state(void);
#else
static inline void fpu_update_guest_xfd(struct fpu_guest *guest_fpu, u64 xfd) { }
static inline void fpu_sync_guest_vmexit_xfd_state(void) { }
#endif

extern void fpu_copy_guest_fpstate_to_uabi(struct fpu_guest *gfpu, void *buf, unsigned int size, u32 pkru);
extern int fpu_copy_uabi_to_guest_fpstate(struct fpu_guest *gfpu, const void *buf, u64 xcr0, u32 *vpkru);

static inline void fpstate_set_confidential(struct fpu_guest *gfpu)
{
	gfpu->fpstate->is_confidential = true;
}

static inline bool fpstate_is_confidential(struct fpu_guest *gfpu)
{
	return gfpu->fpstate->is_confidential;
}

extern long fpu_xstate_prctl(int option, unsigned long arg2);

extern void fpu_idle_fpregs(void);

#endif /* _ASM_X86_FPU_API_H */
