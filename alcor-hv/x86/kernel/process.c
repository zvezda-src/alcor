#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/prctl.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/idle.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/pm.h>
#include <linux/tick.h>
#include <linux/random.h>
#include <linux/user-return-notifier.h>
#include <linux/dmi.h>
#include <linux/utsname.h>
#include <linux/stackprotector.h>
#include <linux/cpuidle.h>
#include <linux/acpi.h>
#include <linux/elf-randomize.h>
#include <trace/events/power.h>
#include <linux/hw_breakpoint.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <linux/uaccess.h>
#include <asm/mwait.h>
#include <asm/fpu/api.h>
#include <asm/fpu/sched.h>
#include <asm/fpu/xstate.h>
#include <asm/debugreg.h>
#include <asm/nmi.h>
#include <asm/tlbflush.h>
#include <asm/mce.h>
#include <asm/vm86.h>
#include <asm/switch_to.h>
#include <asm/desc.h>
#include <asm/prctl.h>
#include <asm/spec-ctrl.h>
#include <asm/io_bitmap.h>
#include <asm/proto.h>
#include <asm/frame.h>
#include <asm/unwind.h>
#include <asm/tdx.h>

#include "process.h"

__visible DEFINE_PER_CPU_PAGE_ALIGNED(struct tss_struct, cpu_tss_rw) = {
	.x86_tss = {
		/*
		.sp0 = (1UL << (BITS_PER_LONG-1)) + 1,

#ifdef CONFIG_X86_32
		.sp1 = TOP_OF_INIT_STACK,

		.ss0 = __KERNEL_DS,
		.ss1 = __KERNEL_CS,
#endif
		.io_bitmap_base	= IO_BITMAP_OFFSET_INVALID,
	 },
};
EXPORT_PER_CPU_SYMBOL(cpu_tss_rw);

DEFINE_PER_CPU(bool, __tss_limit_invalid);
EXPORT_PER_CPU_SYMBOL_GPL(__tss_limit_invalid);

int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	memcpy(dst, src, arch_task_struct_size);
#ifdef CONFIG_VM86
	dst->thread.vm86 = NULL;
#endif
	/* Drop the copied pointer to current's fpstate */
	dst->thread.fpu.fpstate = NULL;

	return 0;
}

#ifdef CONFIG_X86_64
void arch_release_task_struct(struct task_struct *tsk)
{
	if (fpu_state_size_dynamic())
		fpstate_free(&tsk->thread.fpu);
}
#endif

void exit_thread(struct task_struct *tsk)
{
	struct thread_struct *t = &tsk->thread;
	struct fpu *fpu = &t->fpu;

	if (test_thread_flag(TIF_IO_BITMAP))
		io_bitmap_exit(tsk);

	free_vm86(t);

	fpu__drop(fpu);
}

static int set_new_tls(struct task_struct *p, unsigned long tls)
{
	struct user_desc __user *utls = (struct user_desc __user *)tls;

	if (in_ia32_syscall())
		return do_set_thread_area(p, -1, utls, 0);
	else
		return do_set_thread_area_64(p, ARCH_SET_FS, tls);
}

int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
{
	unsigned long clone_flags = args->flags;
	unsigned long sp = args->stack;
	unsigned long tls = args->tls;
	struct inactive_task_frame *frame;
	struct fork_frame *fork_frame;
	struct pt_regs *childregs;
	int ret = 0;

	childregs = task_pt_regs(p);
	fork_frame = container_of(childregs, struct fork_frame, regs);
	frame = &fork_frame->frame;

	frame->bp = encode_frame_pointer(childregs);
	frame->ret_addr = (unsigned long) ret_from_fork;
	p->thread.sp = (unsigned long) fork_frame;
	p->thread.io_bitmap = NULL;
	p->thread.iopl_warn = 0;
	memset(p->thread.ptrace_bps, 0, sizeof(p->thread.ptrace_bps));

#ifdef CONFIG_X86_64
	current_save_fsgs();
	p->thread.fsindex = current->thread.fsindex;
	p->thread.fsbase = current->thread.fsbase;
	p->thread.gsindex = current->thread.gsindex;
	p->thread.gsbase = current->thread.gsbase;

	savesegment(es, p->thread.es);
	savesegment(ds, p->thread.ds);
#else
	p->thread.sp0 = (unsigned long) (childregs + 1);
	savesegment(gs, p->thread.gs);
	/*
	frame->flags = X86_EFLAGS_FIXED;
#endif

	fpu_clone(p, clone_flags, args->fn);

	/* Kernel thread ? */
	if (unlikely(p->flags & PF_KTHREAD)) {
		p->thread.pkru = pkru_get_init_value();
		memset(childregs, 0, sizeof(struct pt_regs));
		kthread_frame_init(frame, args->fn, args->fn_arg);
		return 0;
	}

	/*
	p->thread.pkru = read_pkru();

	frame->bx = 0;
	childregs->ax = 0;
	if (sp)
		childregs->sp = sp;

	if (unlikely(args->fn)) {
		/*
		childregs->sp = 0;
		childregs->ip = 0;
		kthread_frame_init(frame, args->fn, args->fn_arg);
		return 0;
	}

	/* Set a new TLS for the child thread? */
	if (clone_flags & CLONE_SETTLS)
		ret = set_new_tls(p, tls);

	if (!ret && unlikely(test_tsk_thread_flag(current, TIF_IO_BITMAP)))
		io_bitmap_share(p);

	return ret;
}

static void pkru_flush_thread(void)
{
	/*
	pkru_write_default();
}

void flush_thread(void)
{
	struct task_struct *tsk = current;

	flush_ptrace_hw_breakpoint(tsk);
	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));

	fpu_flush_thread();
	pkru_flush_thread();
}

void disable_TSC(void)
{
	preempt_disable();
	if (!test_and_set_thread_flag(TIF_NOTSC))
		/*
		cr4_set_bits(X86_CR4_TSD);
	preempt_enable();
}

static void enable_TSC(void)
{
	preempt_disable();
	if (test_and_clear_thread_flag(TIF_NOTSC))
		/*
		cr4_clear_bits(X86_CR4_TSD);
	preempt_enable();
}

int get_tsc_mode(unsigned long adr)
{
	unsigned int val;

	if (test_thread_flag(TIF_NOTSC))
		val = PR_TSC_SIGSEGV;
	else
		val = PR_TSC_ENABLE;

	return put_user(val, (unsigned int __user *)adr);
}

int set_tsc_mode(unsigned int val)
{
	if (val == PR_TSC_SIGSEGV)
		disable_TSC();
	else if (val == PR_TSC_ENABLE)
		enable_TSC();
	else
		return -EINVAL;

	return 0;
}

DEFINE_PER_CPU(u64, msr_misc_features_shadow);

static void set_cpuid_faulting(bool on)
{
	u64 msrval;

	msrval = this_cpu_read(msr_misc_features_shadow);
	msrval &= ~MSR_MISC_FEATURES_ENABLES_CPUID_FAULT;
	msrval |= (on << MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT);
	this_cpu_write(msr_misc_features_shadow, msrval);
	wrmsrl(MSR_MISC_FEATURES_ENABLES, msrval);
}

static void disable_cpuid(void)
{
	preempt_disable();
	if (!test_and_set_thread_flag(TIF_NOCPUID)) {
		/*
		set_cpuid_faulting(true);
	}
	preempt_enable();
}

static void enable_cpuid(void)
{
	preempt_disable();
	if (test_and_clear_thread_flag(TIF_NOCPUID)) {
		/*
		set_cpuid_faulting(false);
	}
	preempt_enable();
}

static int get_cpuid_mode(void)
{
	return !test_thread_flag(TIF_NOCPUID);
}

static int set_cpuid_mode(unsigned long cpuid_enabled)
{
	if (!boot_cpu_has(X86_FEATURE_CPUID_FAULT))
		return -ENODEV;

	if (cpuid_enabled)
		enable_cpuid();
	else
		disable_cpuid();

	return 0;
}

void arch_setup_new_exec(void)
{
	/* If cpuid was previously disabled for this task, re-enable it. */
	if (test_thread_flag(TIF_NOCPUID))
		enable_cpuid();

	/*
	if (test_thread_flag(TIF_SSBD) &&
	    task_spec_ssb_noexec(current)) {
		clear_thread_flag(TIF_SSBD);
		task_clear_spec_ssb_disable(current);
		task_clear_spec_ssb_noexec(current);
		speculation_ctrl_update(read_thread_flags());
	}
}

#ifdef CONFIG_X86_IOPL_IOPERM
static inline void switch_to_bitmap(unsigned long tifp)
{
	/*
	if (tifp & _TIF_IO_BITMAP)
		tss_invalidate_io_bitmap();
}

static void tss_copy_io_bitmap(struct tss_struct *tss, struct io_bitmap *iobm)
{
	/*
	memcpy(tss->io_bitmap.bitmap, iobm->bitmap,
	       max(tss->io_bitmap.prev_max, iobm->max));

	/*
	tss->io_bitmap.prev_max = iobm->max;
	tss->io_bitmap.prev_sequence = iobm->sequence;
}

void native_tss_update_io_bitmap(void)
{
	struct tss_struct *tss = this_cpu_ptr(&cpu_tss_rw);
	struct thread_struct *t = &current->thread;
	u16 *base = &tss->x86_tss.io_bitmap_base;

	if (!test_thread_flag(TIF_IO_BITMAP)) {
		native_tss_invalidate_io_bitmap();
		return;
	}

	if (IS_ENABLED(CONFIG_X86_IOPL_IOPERM) && t->iopl_emul == 3) {
		*base = IO_BITMAP_OFFSET_VALID_ALL;
	} else {
		struct io_bitmap *iobm = t->io_bitmap;

		/*
		if (tss->io_bitmap.prev_sequence != iobm->sequence)
			tss_copy_io_bitmap(tss, iobm);

		/* Enable the bitmap */
		*base = IO_BITMAP_OFFSET_VALID_MAP;
	}

	/*
	refresh_tss_limit();
}
#else /* CONFIG_X86_IOPL_IOPERM */
static inline void switch_to_bitmap(unsigned long tifp) { }
#endif

#ifdef CONFIG_SMP

struct ssb_state {
	struct ssb_state	*shared_state;
	raw_spinlock_t		lock;
	unsigned int		disable_state;
	unsigned long		local_state;
};

#define LSTATE_SSB	0

static DEFINE_PER_CPU(struct ssb_state, ssb_state);

void speculative_store_bypass_ht_init(void)
{
	struct ssb_state *st = this_cpu_ptr(&ssb_state);
	unsigned int this_cpu = smp_processor_id();
	unsigned int cpu;

	st->local_state = 0;

	/*
	if (st->shared_state)
		return;

	raw_spin_lock_init(&st->lock);

	/*
	for_each_cpu(cpu, topology_sibling_cpumask(this_cpu)) {
		if (cpu == this_cpu)
			continue;

		if (!per_cpu(ssb_state, cpu).shared_state)
			continue;

		/* Link it to the state of the sibling: */
		st->shared_state = per_cpu(ssb_state, cpu).shared_state;
		return;
	}

	/*
	st->shared_state = st;
}

static __always_inline void amd_set_core_ssb_state(unsigned long tifn)
{
	struct ssb_state *st = this_cpu_ptr(&ssb_state);
	u64 msr = x86_amd_ls_cfg_base;

	if (!static_cpu_has(X86_FEATURE_ZEN)) {
		msr |= ssbd_tif_to_amd_ls_cfg(tifn);
		wrmsrl(MSR_AMD64_LS_CFG, msr);
		return;
	}

	if (tifn & _TIF_SSBD) {
		/*
		if (__test_and_set_bit(LSTATE_SSB, &st->local_state))
			return;

		msr |= x86_amd_ls_cfg_ssbd_mask;

		raw_spin_lock(&st->shared_state->lock);
		/* First sibling enables SSBD: */
		if (!st->shared_state->disable_state)
			wrmsrl(MSR_AMD64_LS_CFG, msr);
		st->shared_state->disable_state++;
		raw_spin_unlock(&st->shared_state->lock);
	} else {
		if (!__test_and_clear_bit(LSTATE_SSB, &st->local_state))
			return;

		raw_spin_lock(&st->shared_state->lock);
		st->shared_state->disable_state--;
		if (!st->shared_state->disable_state)
			wrmsrl(MSR_AMD64_LS_CFG, msr);
		raw_spin_unlock(&st->shared_state->lock);
	}
}
#else
static __always_inline void amd_set_core_ssb_state(unsigned long tifn)
{
	u64 msr = x86_amd_ls_cfg_base | ssbd_tif_to_amd_ls_cfg(tifn);

	wrmsrl(MSR_AMD64_LS_CFG, msr);
}
#endif

static __always_inline void amd_set_ssb_virt_state(unsigned long tifn)
{
	/*
	wrmsrl(MSR_AMD64_VIRT_SPEC_CTRL, ssbd_tif_to_spec_ctrl(tifn));
}

static __always_inline void __speculation_ctrl_update(unsigned long tifp,
						      unsigned long tifn)
{
	unsigned long tif_diff = tifp ^ tifn;
	u64 msr = x86_spec_ctrl_base;
	bool updmsr = false;

	lockdep_assert_irqs_disabled();

	/* Handle change of TIF_SSBD depending on the mitigation method. */
	if (static_cpu_has(X86_FEATURE_VIRT_SSBD)) {
		if (tif_diff & _TIF_SSBD)
			amd_set_ssb_virt_state(tifn);
	} else if (static_cpu_has(X86_FEATURE_LS_CFG_SSBD)) {
		if (tif_diff & _TIF_SSBD)
			amd_set_core_ssb_state(tifn);
	} else if (static_cpu_has(X86_FEATURE_SPEC_CTRL_SSBD) ||
		   static_cpu_has(X86_FEATURE_AMD_SSBD)) {
		updmsr |= !!(tif_diff & _TIF_SSBD);
		msr |= ssbd_tif_to_spec_ctrl(tifn);
	}

	/* Only evaluate TIF_SPEC_IB if conditional STIBP is enabled. */
	if (IS_ENABLED(CONFIG_SMP) &&
	    static_branch_unlikely(&switch_to_cond_stibp)) {
		updmsr |= !!(tif_diff & _TIF_SPEC_IB);
		msr |= stibp_tif_to_spec_ctrl(tifn);
	}

	if (updmsr)
		write_spec_ctrl_current(msr, false);
}

static unsigned long speculation_ctrl_update_tif(struct task_struct *tsk)
{
	if (test_and_clear_tsk_thread_flag(tsk, TIF_SPEC_FORCE_UPDATE)) {
		if (task_spec_ssb_disable(tsk))
			set_tsk_thread_flag(tsk, TIF_SSBD);
		else
			clear_tsk_thread_flag(tsk, TIF_SSBD);

		if (task_spec_ib_disable(tsk))
			set_tsk_thread_flag(tsk, TIF_SPEC_IB);
		else
			clear_tsk_thread_flag(tsk, TIF_SPEC_IB);
	}
	/* Return the updated threadinfo flags*/
	return read_task_thread_flags(tsk);
}

void speculation_ctrl_update(unsigned long tif)
{
	unsigned long flags;

	/* Forced update. Make sure all relevant TIF flags are different */
	local_irq_save(flags);
	__speculation_ctrl_update(~tif, tif);
	local_irq_restore(flags);
}

void speculation_ctrl_update_current(void)
{
	preempt_disable();
	speculation_ctrl_update(speculation_ctrl_update_tif(current));
	preempt_enable();
}

static inline void cr4_toggle_bits_irqsoff(unsigned long mask)
{
	unsigned long newval, cr4 = this_cpu_read(cpu_tlbstate.cr4);

	newval = cr4 ^ mask;
	if (newval != cr4) {
		this_cpu_write(cpu_tlbstate.cr4, newval);
		__write_cr4(newval);
	}
}

void __switch_to_xtra(struct task_struct *prev_p, struct task_struct *next_p)
{
	unsigned long tifp, tifn;

	tifn = read_task_thread_flags(next_p);
	tifp = read_task_thread_flags(prev_p);

	switch_to_bitmap(tifp);

	propagate_user_return_notify(prev_p, next_p);

	if ((tifp & _TIF_BLOCKSTEP || tifn & _TIF_BLOCKSTEP) &&
	    arch_has_block_step()) {
		unsigned long debugctl, msk;

		rdmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
		debugctl &= ~DEBUGCTLMSR_BTF;
		msk = tifn & _TIF_BLOCKSTEP;
		debugctl |= (msk >> TIF_BLOCKSTEP) << DEBUGCTLMSR_BTF_SHIFT;
		wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
	}

	if ((tifp ^ tifn) & _TIF_NOTSC)
		cr4_toggle_bits_irqsoff(X86_CR4_TSD);

	if ((tifp ^ tifn) & _TIF_NOCPUID)
		set_cpuid_faulting(!!(tifn & _TIF_NOCPUID));

	if (likely(!((tifp | tifn) & _TIF_SPEC_FORCE_UPDATE))) {
		__speculation_ctrl_update(tifp, tifn);
	} else {
		speculation_ctrl_update_tif(prev_p);
		tifn = speculation_ctrl_update_tif(next_p);

		/* Enforce MSR update to ensure consistent state */
		__speculation_ctrl_update(~tifn, tifn);
	}
}

unsigned long boot_option_idle_override = IDLE_NO_OVERRIDE;
EXPORT_SYMBOL(boot_option_idle_override);

static void (*x86_idle)(void);

#ifndef CONFIG_SMP
static inline void play_dead(void)
{
	BUG();
}
#endif

void arch_cpu_idle_enter(void)
{
	tsc_verify_tsc_adjust(false);
	local_touch_nmi();
}

void arch_cpu_idle_dead(void)
{
	play_dead();
}

void arch_cpu_idle(void)
{
	x86_idle();
}

void __cpuidle default_idle(void)
{
	raw_safe_halt();
}
#if defined(CONFIG_APM_MODULE) || defined(CONFIG_HALTPOLL_CPUIDLE_MODULE)
EXPORT_SYMBOL(default_idle);
#endif

#ifdef CONFIG_XEN
bool xen_set_default_idle(void)
{
	bool ret = !!x86_idle;

	x86_idle = default_idle;

	return ret;
}
#endif

void __noreturn stop_this_cpu(void *dummy)
{
	local_irq_disable();
	/*
	set_cpu_online(smp_processor_id(), false);
	disable_local_APIC();
	mcheck_cpu_clear(this_cpu_ptr(&cpu_info));

	/*
	if (cpuid_eax(0x8000001f) & BIT(0))
		native_wbinvd();
	for (;;) {
		/*
		native_halt();
	}
}

static void amd_e400_idle(void)
{
	/*
	if (!boot_cpu_has_bug(X86_BUG_AMD_APIC_C1E)) {
		default_idle();
		return;
	}

	tick_broadcast_enter();

	default_idle();

	/*
	raw_local_irq_disable();
	tick_broadcast_exit();
	raw_local_irq_enable();
}

static int prefer_mwait_c1_over_halt(const struct cpuinfo_x86 *c)
{
	u32 eax, ebx, ecx, edx;

	/* User has disallowed the use of MWAIT. Fallback to HALT */
	if (boot_option_idle_override == IDLE_NOMWAIT)
		return 0;

	/* MWAIT is not supported on this platform. Fallback to HALT */
	if (!cpu_has(c, X86_FEATURE_MWAIT))
		return 0;

	/* Monitor has a bug. Fallback to HALT */
	if (boot_cpu_has_bug(X86_BUG_MONITOR))
		return 0;

	cpuid(CPUID_MWAIT_LEAF, &eax, &ebx, &ecx, &edx);

	/*
	if (!(ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED))
		return 1;

	/*
	return (edx & MWAIT_C1_SUBSTATE_MASK);
}

static __cpuidle void mwait_idle(void)
{
	if (!current_set_polling_and_test()) {
		if (this_cpu_has(X86_BUG_CLFLUSH_MONITOR)) {
			mb(); /* quirk */
			clflush((void *)&current_thread_info()->flags);
			mb(); /* quirk */
		}

		__monitor((void *)&current_thread_info()->flags, 0, 0);
		if (!need_resched())
			__sti_mwait(0, 0);
		else
			raw_local_irq_enable();
	} else {
		raw_local_irq_enable();
	}
	__current_clr_polling();
}

void select_idle_routine(const struct cpuinfo_x86 *c)
{
#ifdef CONFIG_SMP
	if (boot_option_idle_override == IDLE_POLL && smp_num_siblings > 1)
		pr_warn_once("WARNING: polling idle and HT enabled, performance may degrade\n");
#endif
	if (x86_idle || boot_option_idle_override == IDLE_POLL)
		return;

	if (boot_cpu_has_bug(X86_BUG_AMD_E400)) {
		pr_info("using AMD E400 aware idle routine\n");
		x86_idle = amd_e400_idle;
	} else if (prefer_mwait_c1_over_halt(c)) {
		pr_info("using mwait in idle threads\n");
		x86_idle = mwait_idle;
	} else if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST)) {
		pr_info("using TDX aware idle routine\n");
		x86_idle = tdx_safe_halt;
	} else
		x86_idle = default_idle;
}

void amd_e400_c1e_apic_setup(void)
{
	if (boot_cpu_has_bug(X86_BUG_AMD_APIC_C1E)) {
		pr_info("Switch to broadcast mode on CPU%d\n", smp_processor_id());
		local_irq_disable();
		tick_broadcast_force();
		local_irq_enable();
	}
}

void __init arch_post_acpi_subsys_init(void)
{
	u32 lo, hi;

	if (!boot_cpu_has_bug(X86_BUG_AMD_E400))
		return;

	/*
	rdmsr(MSR_K8_INT_PENDING_MSG, lo, hi);
	if (!(lo & K8_INTP_C1E_ACTIVE_MASK))
		return;

	boot_cpu_set_bug(X86_BUG_AMD_APIC_C1E);

	if (!boot_cpu_has(X86_FEATURE_NONSTOP_TSC))
		mark_tsc_unstable("TSC halt in AMD C1E");
	pr_info("System has AMD C1E enabled\n");
}

static int __init idle_setup(char *str)
{
	if (!str)
		return -EINVAL;

	if (!strcmp(str, "poll")) {
		pr_info("using polling idle threads\n");
		boot_option_idle_override = IDLE_POLL;
		cpu_idle_poll_ctrl(true);
	} else if (!strcmp(str, "halt")) {
		/*
		x86_idle = default_idle;
		boot_option_idle_override = IDLE_HALT;
	} else if (!strcmp(str, "nomwait")) {
		/*
		boot_option_idle_override = IDLE_NOMWAIT;
	} else
		return -1;

	return 0;
}
early_param("idle", idle_setup);

unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_int() % 8192;
	return sp & ~0xf;
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_page(mm->brk, 0x02000000);
}

unsigned long __get_wchan(struct task_struct *p)
{
	struct unwind_state state;
	unsigned long addr = 0;

	if (!try_get_task_stack(p))
		return 0;

	for (unwind_start(&state, p, NULL, NULL); !unwind_done(&state);
	     unwind_next_frame(&state)) {
		addr = unwind_get_return_address(&state);
		if (!addr)
			break;
		if (in_sched_functions(addr))
			continue;
		break;
	}

	put_task_stack(p);

	return addr;
}

long do_arch_prctl_common(int option, unsigned long arg2)
{
	switch (option) {
	case ARCH_GET_CPUID:
		return get_cpuid_mode();
	case ARCH_SET_CPUID:
		return set_cpuid_mode(arg2);
	case ARCH_GET_XCOMP_SUPP:
	case ARCH_GET_XCOMP_PERM:
	case ARCH_REQ_XCOMP_PERM:
	case ARCH_GET_XCOMP_GUEST_PERM:
	case ARCH_REQ_XCOMP_GUEST_PERM:
		return fpu_xstate_prctl(option, arg2);
	}

	return -EINVAL;
}
