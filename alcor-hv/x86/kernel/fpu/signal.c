
#include <linux/compat.h>
#include <linux/cpu.h>
#include <linux/pagemap.h>

#include <asm/fpu/signal.h>
#include <asm/fpu/regset.h>
#include <asm/fpu/xstate.h>

#include <asm/sigframe.h>
#include <asm/trapnr.h>
#include <asm/trace/fpu.h>

#include "context.h"
#include "internal.h"
#include "legacy.h"
#include "xstate.h"

static inline bool check_xstate_in_sigframe(struct fxregs_state __user *fxbuf,
					    struct _fpx_sw_bytes *fx_sw)
{
	int min_xstate_size = sizeof(struct fxregs_state) +
			      sizeof(struct xstate_header);
	void __user *fpstate = fxbuf;
	unsigned int magic2;

	if (__copy_from_user(fx_sw, &fxbuf->sw_reserved[0], sizeof(*fx_sw)))
		return false;

	/* Check for the first magic field and other error scenarios. */
	if (fx_sw->magic1 != FP_XSTATE_MAGIC1 ||
	    fx_sw->xstate_size < min_xstate_size ||
	    fx_sw->xstate_size > current->thread.fpu.fpstate->user_size ||
	    fx_sw->xstate_size > fx_sw->extended_size)
		goto setfx;

	/*
	if (__get_user(magic2, (__u32 __user *)(fpstate + fx_sw->xstate_size)))
		return false;

	if (likely(magic2 == FP_XSTATE_MAGIC2))
		return true;
setfx:
	trace_x86_fpu_xstate_check_failed(&current->thread.fpu);

	/* Set the parameters for fx only state */
	fx_sw->magic1 = 0;
	fx_sw->xstate_size = sizeof(struct fxregs_state);
	fx_sw->xfeatures = XFEATURE_MASK_FPSSE;
	return true;
}

static inline bool save_fsave_header(struct task_struct *tsk, void __user *buf)
{
	if (use_fxsr()) {
		struct xregs_state *xsave = &tsk->thread.fpu.fpstate->regs.xsave;
		struct user_i387_ia32_struct env;
		struct _fpstate_32 __user *fp = buf;

		fpregs_lock();
		if (!test_thread_flag(TIF_NEED_FPU_LOAD))
			fxsave(&tsk->thread.fpu.fpstate->regs.fxsave);
		fpregs_unlock();

		convert_from_fxsr(&env, tsk);

		if (__copy_to_user(buf, &env, sizeof(env)) ||
		    __put_user(xsave->i387.swd, &fp->status) ||
		    __put_user(X86_FXSR_MAGIC, &fp->magic))
			return false;
	} else {
		struct fregs_state __user *fp = buf;
		u32 swd;

		if (__get_user(swd, &fp->swd) || __put_user(swd, &fp->status))
			return false;
	}

	return true;
}

static inline void save_sw_bytes(struct _fpx_sw_bytes *sw_bytes, bool ia32_frame,
				 struct fpstate *fpstate)
{
	sw_bytes->magic1 = FP_XSTATE_MAGIC1;
	sw_bytes->extended_size = fpstate->user_size + FP_XSTATE_MAGIC2_SIZE;
	sw_bytes->xfeatures = fpstate->user_xfeatures;
	sw_bytes->xstate_size = fpstate->user_size;

	if (ia32_frame)
		sw_bytes->extended_size += sizeof(struct fregs_state);
}

static inline bool save_xstate_epilog(void __user *buf, int ia32_frame,
				      struct fpstate *fpstate)
{
	struct xregs_state __user *x = buf;
	struct _fpx_sw_bytes sw_bytes = {};
	u32 xfeatures;
	int err;

	/* Setup the bytes not touched by the [f]xsave and reserved for SW. */
	save_sw_bytes(&sw_bytes, ia32_frame, fpstate);
	err = __copy_to_user(&x->i387.sw_reserved, &sw_bytes, sizeof(sw_bytes));

	if (!use_xsave())
		return !err;

	err |= __put_user(FP_XSTATE_MAGIC2,
			  (__u32 __user *)(buf + fpstate->user_size));

	/*
	err |= __get_user(xfeatures, (__u32 __user *)&x->header.xfeatures);

	/*
	xfeatures |= XFEATURE_MASK_FPSSE;

	err |= __put_user(xfeatures, (__u32 __user *)&x->header.xfeatures);

	return !err;
}

static inline int copy_fpregs_to_sigframe(struct xregs_state __user *buf)
{
	if (use_xsave())
		return xsave_to_user_sigframe(buf);
	if (use_fxsr())
		return fxsave_to_user_sigframe((struct fxregs_state __user *) buf);
	else
		return fnsave_to_user_sigframe((struct fregs_state __user *) buf);
}

bool copy_fpstate_to_sigframe(void __user *buf, void __user *buf_fx, int size)
{
	struct task_struct *tsk = current;
	struct fpstate *fpstate = tsk->thread.fpu.fpstate;
	bool ia32_fxstate = (buf != buf_fx);
	int ret;

	ia32_fxstate &= (IS_ENABLED(CONFIG_X86_32) ||
			 IS_ENABLED(CONFIG_IA32_EMULATION));

	if (!static_cpu_has(X86_FEATURE_FPU)) {
		struct user_i387_ia32_struct fp;

		fpregs_soft_get(current, NULL, (struct membuf){.p = &fp,
						.left = sizeof(fp)});
		return !copy_to_user(buf, &fp, sizeof(fp));
	}

	if (!access_ok(buf, size))
		return false;

	if (use_xsave()) {
		struct xregs_state __user *xbuf = buf_fx;

		/*
		if (__clear_user(&xbuf->header, sizeof(xbuf->header)))
			return false;
	}
retry:
	/*
	fpregs_lock();
	if (test_thread_flag(TIF_NEED_FPU_LOAD))
		fpregs_restore_userregs();

	pagefault_disable();
	ret = copy_fpregs_to_sigframe(buf_fx);
	pagefault_enable();
	fpregs_unlock();

	if (ret) {
		if (!__clear_user(buf_fx, fpstate->user_size))
			goto retry;
		return false;
	}

	/* Save the fsave header for the 32-bit frames. */
	if ((ia32_fxstate || !use_fxsr()) && !save_fsave_header(tsk, buf))
		return false;

	if (use_fxsr() && !save_xstate_epilog(buf_fx, ia32_fxstate, fpstate))
		return false;

	return true;
}

static int __restore_fpregs_from_user(void __user *buf, u64 ufeatures,
				      u64 xrestore, bool fx_only)
{
	if (use_xsave()) {
		u64 init_bv = ufeatures & ~xrestore;
		int ret;

		if (likely(!fx_only))
			ret = xrstor_from_user_sigframe(buf, xrestore);
		else
			ret = fxrstor_from_user_sigframe(buf);

		if (!ret && unlikely(init_bv))
			os_xrstor(&init_fpstate, init_bv);
		return ret;
	} else if (use_fxsr()) {
		return fxrstor_from_user_sigframe(buf);
	} else {
		return frstor_from_user_sigframe(buf);
	}
}

static bool restore_fpregs_from_user(void __user *buf, u64 xrestore,
				     bool fx_only, unsigned int size)
{
	struct fpu *fpu = &current->thread.fpu;
	int ret;

retry:
	fpregs_lock();
	/* Ensure that XFD is up to date */
	xfd_update_state(fpu->fpstate);
	pagefault_disable();
	ret = __restore_fpregs_from_user(buf, fpu->fpstate->user_xfeatures,
					 xrestore, fx_only);
	pagefault_enable();

	if (unlikely(ret)) {
		/*
		if (test_thread_flag(TIF_NEED_FPU_LOAD))
			__cpu_invalidate_fpregs_state();
		fpregs_unlock();

		/* Try to handle #PF, but anything else is fatal. */
		if (ret != X86_TRAP_PF)
			return false;

		if (!fault_in_readable(buf, size))
			goto retry;
		return false;
	}

	/*
	if (test_thread_flag(TIF_NEED_FPU_LOAD) && xfeatures_mask_supervisor())
		os_xrstor_supervisor(fpu->fpstate);

	fpregs_mark_activate();
	fpregs_unlock();
	return true;
}

static bool __fpu_restore_sig(void __user *buf, void __user *buf_fx,
			      bool ia32_fxstate)
{
	struct task_struct *tsk = current;
	struct fpu *fpu = &tsk->thread.fpu;
	struct user_i387_ia32_struct env;
	bool success, fx_only = false;
	union fpregs_state *fpregs;
	unsigned int state_size;
	u64 user_xfeatures = 0;

	if (use_xsave()) {
		struct _fpx_sw_bytes fx_sw_user;

		if (!check_xstate_in_sigframe(buf_fx, &fx_sw_user))
			return false;

		fx_only = !fx_sw_user.magic1;
		state_size = fx_sw_user.xstate_size;
		user_xfeatures = fx_sw_user.xfeatures;
	} else {
		user_xfeatures = XFEATURE_MASK_FPSSE;
		state_size = fpu->fpstate->user_size;
	}

	if (likely(!ia32_fxstate)) {
		/* Restore the FPU registers directly from user memory. */
		return restore_fpregs_from_user(buf_fx, user_xfeatures, fx_only,
						state_size);
	}

	/*
	if (__copy_from_user(&env, buf, sizeof(env)))
		return false;

	/*
	fpregs_lock();
	if (!test_thread_flag(TIF_NEED_FPU_LOAD)) {
		/*
		if (xfeatures_mask_supervisor())
			os_xsave(fpu->fpstate);
		set_thread_flag(TIF_NEED_FPU_LOAD);
	}
	__fpu_invalidate_fpregs_state(fpu);
	__cpu_invalidate_fpregs_state();
	fpregs_unlock();

	fpregs = &fpu->fpstate->regs;
	if (use_xsave() && !fx_only) {
		if (copy_sigframe_from_user_to_xstate(fpu->fpstate, buf_fx))
			return false;
	} else {
		if (__copy_from_user(&fpregs->fxsave, buf_fx,
				     sizeof(fpregs->fxsave)))
			return false;

		if (IS_ENABLED(CONFIG_X86_64)) {
			/* Reject invalid MXCSR values. */
			if (fpregs->fxsave.mxcsr & ~mxcsr_feature_mask)
				return false;
		} else {
			/* Mask invalid bits out for historical reasons (broken hardware). */
			fpregs->fxsave.mxcsr &= mxcsr_feature_mask;
		}

		/* Enforce XFEATURE_MASK_FPSSE when XSAVE is enabled */
		if (use_xsave())
			fpregs->xsave.header.xfeatures |= XFEATURE_MASK_FPSSE;
	}

	/* Fold the legacy FP storage */
	convert_to_fxsr(&fpregs->fxsave, &env);

	fpregs_lock();
	if (use_xsave()) {
		/*
		u64 mask = user_xfeatures | xfeatures_mask_supervisor();

		fpregs->xsave.header.xfeatures &= mask;
		success = !os_xrstor_safe(fpu->fpstate,
					  fpu_kernel_cfg.max_features);
	} else {
		success = !fxrstor_safe(&fpregs->fxsave);
	}

	if (likely(success))
		fpregs_mark_activate();

	fpregs_unlock();
	return success;
}

static inline unsigned int xstate_sigframe_size(struct fpstate *fpstate)
{
	unsigned int size = fpstate->user_size;

	return use_xsave() ? size + FP_XSTATE_MAGIC2_SIZE : size;
}

bool fpu__restore_sig(void __user *buf, int ia32_frame)
{
	struct fpu *fpu = &current->thread.fpu;
	void __user *buf_fx = buf;
	bool ia32_fxstate = false;
	bool success = false;
	unsigned int size;

	if (unlikely(!buf)) {
		fpu__clear_user_states(fpu);
		return true;
	}

	size = xstate_sigframe_size(fpu->fpstate);

	ia32_frame &= (IS_ENABLED(CONFIG_X86_32) ||
		       IS_ENABLED(CONFIG_IA32_EMULATION));

	/*
	if (ia32_frame && use_fxsr()) {
		buf_fx = buf + sizeof(struct fregs_state);
		size += sizeof(struct fregs_state);
		ia32_fxstate = true;
	}

	if (!access_ok(buf, size))
		goto out;

	if (!IS_ENABLED(CONFIG_X86_64) && !cpu_feature_enabled(X86_FEATURE_FPU)) {
		success = !fpregs_soft_set(current, NULL, 0,
					   sizeof(struct user_i387_ia32_struct),
					   NULL, buf);
	} else {
		success = __fpu_restore_sig(buf, buf_fx, ia32_fxstate);
	}

out:
	if (unlikely(!success))
		fpu__clear_user_states(fpu);
	return success;
}

unsigned long
fpu__alloc_mathframe(unsigned long sp, int ia32_frame,
		     unsigned long *buf_fx, unsigned long *size)
{
	unsigned long frame_size = xstate_sigframe_size(current->thread.fpu.fpstate);

	if (ia32_frame && use_fxsr()) {
		frame_size += sizeof(struct fregs_state);
		sp -= sizeof(struct fregs_state);
	}


	return sp;
}

unsigned long __init fpu__get_fpstate_size(void)
{
	unsigned long ret = fpu_user_cfg.max_size;

	if (use_xsave())
		ret += FP_XSTATE_MAGIC2_SIZE;

	/*
	if ((IS_ENABLED(CONFIG_IA32_EMULATION) ||
	     IS_ENABLED(CONFIG_X86_32)) && use_fxsr())
		ret += sizeof(struct fregs_state);

	return ret;
}

