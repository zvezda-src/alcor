#include <linux/init.h>

#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/export.h>
#include <linux/cpu.h>
#include <linux/debugfs.h>
#include <linux/sched/smt.h>
#include <linux/task_work.h>

#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/nospec-branch.h>
#include <asm/cache.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/perf_event.h>

#include "mm_internal.h"

#ifdef CONFIG_PARAVIRT
# define STATIC_NOPV
#else
# define STATIC_NOPV			static
# define __flush_tlb_local		native_flush_tlb_local
# define __flush_tlb_global		native_flush_tlb_global
# define __flush_tlb_one_user(addr)	native_flush_tlb_one_user(addr)
# define __flush_tlb_multi(msk, info)	native_flush_tlb_multi(msk, info)
#endif


#define LAST_USER_MM_IBPB	0x1UL
#define LAST_USER_MM_L1D_FLUSH	0x2UL
#define LAST_USER_MM_SPEC_MASK	(LAST_USER_MM_IBPB | LAST_USER_MM_L1D_FLUSH)

#define LAST_USER_MM_INIT	LAST_USER_MM_IBPB


#define CR3_HW_ASID_BITS		12

#ifdef CONFIG_PAGE_TABLE_ISOLATION
# define PTI_CONSUMED_PCID_BITS	1
#else
# define PTI_CONSUMED_PCID_BITS	0
#endif

#define CR3_AVAIL_PCID_BITS (X86_CR3_PCID_BITS - PTI_CONSUMED_PCID_BITS)

#define MAX_ASID_AVAILABLE ((1 << CR3_AVAIL_PCID_BITS) - 2)

static inline u16 kern_pcid(u16 asid)
{
	VM_WARN_ON_ONCE(asid > MAX_ASID_AVAILABLE);

#ifdef CONFIG_PAGE_TABLE_ISOLATION
	/*
	BUILD_BUG_ON(TLB_NR_DYN_ASIDS >= (1 << X86_CR3_PTI_PCID_USER_BIT));

	/*
	VM_WARN_ON_ONCE(asid & (1 << X86_CR3_PTI_PCID_USER_BIT));
#endif
	/*
	return asid + 1;
}

static inline u16 user_pcid(u16 asid)
{
	u16 ret = kern_pcid(asid);
#ifdef CONFIG_PAGE_TABLE_ISOLATION
	ret |= 1 << X86_CR3_PTI_PCID_USER_BIT;
#endif
	return ret;
}

static inline unsigned long build_cr3(pgd_t *pgd, u16 asid)
{
	if (static_cpu_has(X86_FEATURE_PCID)) {
		return __sme_pa(pgd) | kern_pcid(asid);
	} else {
		VM_WARN_ON_ONCE(asid != 0);
		return __sme_pa(pgd);
	}
}

static inline unsigned long build_cr3_noflush(pgd_t *pgd, u16 asid)
{
	VM_WARN_ON_ONCE(asid > MAX_ASID_AVAILABLE);
	/*
	VM_WARN_ON_ONCE(!boot_cpu_has(X86_FEATURE_PCID));
	return __sme_pa(pgd) | kern_pcid(asid) | CR3_NOFLUSH;
}

static void clear_asid_other(void)
{
	u16 asid;

	/*
	if (!static_cpu_has(X86_FEATURE_PTI)) {
		WARN_ON_ONCE(1);
		return;
	}

	for (asid = 0; asid < TLB_NR_DYN_ASIDS; asid++) {
		/* Do not need to flush the current asid */
		if (asid == this_cpu_read(cpu_tlbstate.loaded_mm_asid))
			continue;
		/*
		this_cpu_write(cpu_tlbstate.ctxs[asid].ctx_id, 0);
	}
	this_cpu_write(cpu_tlbstate.invalidate_other, false);
}

atomic64_t last_mm_ctx_id = ATOMIC64_INIT(1);


static void choose_new_asid(struct mm_struct *next, u64 next_tlb_gen,
			    u16 *new_asid, bool *need_flush)
{
	u16 asid;

	if (!static_cpu_has(X86_FEATURE_PCID)) {
		*new_asid = 0;
		*need_flush = true;
		return;
	}

	if (this_cpu_read(cpu_tlbstate.invalidate_other))
		clear_asid_other();

	for (asid = 0; asid < TLB_NR_DYN_ASIDS; asid++) {
		if (this_cpu_read(cpu_tlbstate.ctxs[asid].ctx_id) !=
		    next->context.ctx_id)
			continue;

		*new_asid = asid;
		*need_flush = (this_cpu_read(cpu_tlbstate.ctxs[asid].tlb_gen) <
			       next_tlb_gen);
		return;
	}

	/*
	if (*new_asid >= TLB_NR_DYN_ASIDS) {
		*new_asid = 0;
		this_cpu_write(cpu_tlbstate.next_asid, 1);
	}
}

static inline void invalidate_user_asid(u16 asid)
{
	/* There is no user ASID if address space separation is off */
	if (!IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION))
		return;

	/*
	if (!cpu_feature_enabled(X86_FEATURE_PCID))
		return;

	if (!static_cpu_has(X86_FEATURE_PTI))
		return;

	__set_bit(kern_pcid(asid),
		  (unsigned long *)this_cpu_ptr(&cpu_tlbstate.user_pcid_flush_mask));
}

static void load_new_mm_cr3(pgd_t *pgdir, u16 new_asid, bool need_flush)
{
	unsigned long new_mm_cr3;

	if (need_flush) {
		invalidate_user_asid(new_asid);
		new_mm_cr3 = build_cr3(pgdir, new_asid);
	} else {
		new_mm_cr3 = build_cr3_noflush(pgdir, new_asid);
	}

	/*
	write_cr3(new_mm_cr3);
}

void leave_mm(int cpu)
{
	struct mm_struct *loaded_mm = this_cpu_read(cpu_tlbstate.loaded_mm);

	/*
	if (loaded_mm == &init_mm)
		return;

	/* Warn if we're not lazy. */
	WARN_ON(!this_cpu_read(cpu_tlbstate_shared.is_lazy));

	switch_mm(NULL, &init_mm, NULL);
}
EXPORT_SYMBOL_GPL(leave_mm);

void switch_mm(struct mm_struct *prev, struct mm_struct *next,
	       struct task_struct *tsk)
{
	unsigned long flags;

	local_irq_save(flags);
	switch_mm_irqs_off(prev, next, tsk);
	local_irq_restore(flags);
}

static void l1d_flush_force_sigbus(struct callback_head *ch)
{
	force_sig(SIGBUS);
}

static void l1d_flush_evaluate(unsigned long prev_mm, unsigned long next_mm,
				struct task_struct *next)
{
	/* Flush L1D if the outgoing task requests it */
	if (prev_mm & LAST_USER_MM_L1D_FLUSH)
		wrmsrl(MSR_IA32_FLUSH_CMD, L1D_FLUSH);

	/* Check whether the incoming task opted in for L1D flush */
	if (likely(!(next_mm & LAST_USER_MM_L1D_FLUSH)))
		return;

	/*
	if (this_cpu_read(cpu_info.smt_active)) {
		clear_ti_thread_flag(&next->thread_info, TIF_SPEC_L1D_FLUSH);
		next->l1d_flush_kill.func = l1d_flush_force_sigbus;
		task_work_add(next, &next->l1d_flush_kill, TWA_RESUME);
	}
}

static unsigned long mm_mangle_tif_spec_bits(struct task_struct *next)
{
	unsigned long next_tif = read_task_thread_flags(next);
	unsigned long spec_bits = (next_tif >> TIF_SPEC_IB) & LAST_USER_MM_SPEC_MASK;

	/*
	BUILD_BUG_ON(TIF_SPEC_L1D_FLUSH != TIF_SPEC_IB + 1);

	return (unsigned long)next->mm | spec_bits;
}

static void cond_mitigation(struct task_struct *next)
{
	unsigned long prev_mm, next_mm;

	if (!next || !next->mm)
		return;

	next_mm = mm_mangle_tif_spec_bits(next);
	prev_mm = this_cpu_read(cpu_tlbstate.last_user_mm_spec);

	/*
	if (static_branch_likely(&switch_mm_cond_ibpb)) {
		/*
		if (next_mm != prev_mm &&
		    (next_mm | prev_mm) & LAST_USER_MM_IBPB)
			indirect_branch_prediction_barrier();
	}

	if (static_branch_unlikely(&switch_mm_always_ibpb)) {
		/*
		if ((prev_mm & ~LAST_USER_MM_SPEC_MASK) !=
					(unsigned long)next->mm)
			indirect_branch_prediction_barrier();
	}

	if (static_branch_unlikely(&switch_mm_cond_l1d_flush)) {
		/*
		if (unlikely((prev_mm | next_mm) & LAST_USER_MM_L1D_FLUSH))
			l1d_flush_evaluate(prev_mm, next_mm, next);
	}

	this_cpu_write(cpu_tlbstate.last_user_mm_spec, next_mm);
}

#ifdef CONFIG_PERF_EVENTS
static inline void cr4_update_pce_mm(struct mm_struct *mm)
{
	if (static_branch_unlikely(&rdpmc_always_available_key) ||
	    (!static_branch_unlikely(&rdpmc_never_available_key) &&
	     atomic_read(&mm->context.perf_rdpmc_allowed))) {
		/*
		perf_clear_dirty_counters();
		cr4_set_bits_irqsoff(X86_CR4_PCE);
	} else
		cr4_clear_bits_irqsoff(X86_CR4_PCE);
}

void cr4_update_pce(void *ignored)
{
	cr4_update_pce_mm(this_cpu_read(cpu_tlbstate.loaded_mm));
}

#else
static inline void cr4_update_pce_mm(struct mm_struct *mm) { }
#endif

void switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
			struct task_struct *tsk)
{
	struct mm_struct *real_prev = this_cpu_read(cpu_tlbstate.loaded_mm);
	u16 prev_asid = this_cpu_read(cpu_tlbstate.loaded_mm_asid);
	bool was_lazy = this_cpu_read(cpu_tlbstate_shared.is_lazy);
	unsigned cpu = smp_processor_id();
	u64 next_tlb_gen;
	bool need_flush;
	u16 new_asid;

	/*

	/* We don't want flush_tlb_func() to run concurrently with us. */
	if (IS_ENABLED(CONFIG_PROVE_LOCKING))
		WARN_ON_ONCE(!irqs_disabled());

	/*
#ifdef CONFIG_DEBUG_VM
	if (WARN_ON_ONCE(__read_cr3() != build_cr3(real_prev->pgd, prev_asid))) {
		/*
		__flush_tlb_all();
	}
#endif
	if (was_lazy)
		this_cpu_write(cpu_tlbstate_shared.is_lazy, false);

	/*
	if (real_prev == next) {
		VM_WARN_ON(this_cpu_read(cpu_tlbstate.ctxs[prev_asid].ctx_id) !=
			   next->context.ctx_id);

		/*
		if (WARN_ON_ONCE(real_prev != &init_mm &&
				 !cpumask_test_cpu(cpu, mm_cpumask(next))))
			cpumask_set_cpu(cpu, mm_cpumask(next));

		/*
		if (!was_lazy)
			return;

		/*
		smp_mb();
		next_tlb_gen = atomic64_read(&next->context.tlb_gen);
		if (this_cpu_read(cpu_tlbstate.ctxs[prev_asid].tlb_gen) ==
				next_tlb_gen)
			return;

		/*
		new_asid = prev_asid;
		need_flush = true;
	} else {
		/*
		cond_mitigation(tsk);

		/*
		if (real_prev != &init_mm) {
			VM_WARN_ON_ONCE(!cpumask_test_cpu(cpu,
						mm_cpumask(real_prev)));
			cpumask_clear_cpu(cpu, mm_cpumask(real_prev));
		}

		/*
		if (next != &init_mm)
			cpumask_set_cpu(cpu, mm_cpumask(next));
		next_tlb_gen = atomic64_read(&next->context.tlb_gen);

		choose_new_asid(next, next_tlb_gen, &new_asid, &need_flush);

		/* Let nmi_uaccess_okay() know that we're changing CR3. */
		this_cpu_write(cpu_tlbstate.loaded_mm, LOADED_MM_SWITCHING);
		barrier();
	}

	if (need_flush) {
		this_cpu_write(cpu_tlbstate.ctxs[new_asid].ctx_id, next->context.ctx_id);
		this_cpu_write(cpu_tlbstate.ctxs[new_asid].tlb_gen, next_tlb_gen);
		load_new_mm_cr3(next->pgd, new_asid, true);

		trace_tlb_flush(TLB_FLUSH_ON_TASK_SWITCH, TLB_FLUSH_ALL);
	} else {
		/* The new ASID is already up to date. */
		load_new_mm_cr3(next->pgd, new_asid, false);

		trace_tlb_flush(TLB_FLUSH_ON_TASK_SWITCH, 0);
	}

	/* Make sure we write CR3 before loaded_mm. */
	barrier();

	this_cpu_write(cpu_tlbstate.loaded_mm, next);
	this_cpu_write(cpu_tlbstate.loaded_mm_asid, new_asid);

	if (next != real_prev) {
		cr4_update_pce_mm(next);
		switch_ldt(real_prev, next);
	}
}

void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk)
{
	if (this_cpu_read(cpu_tlbstate.loaded_mm) == &init_mm)
		return;

	this_cpu_write(cpu_tlbstate_shared.is_lazy, true);
}

void initialize_tlbstate_and_flush(void)
{
	int i;
	struct mm_struct *mm = this_cpu_read(cpu_tlbstate.loaded_mm);
	u64 tlb_gen = atomic64_read(&init_mm.context.tlb_gen);
	unsigned long cr3 = __read_cr3();

	/* Assert that CR3 already references the right mm. */
	WARN_ON((cr3 & CR3_ADDR_MASK) != __pa(mm->pgd));

	/*
	WARN_ON(boot_cpu_has(X86_FEATURE_PCID) &&
		!(cr4_read_shadow() & X86_CR4_PCIDE));

	/* Force ASID 0 and force a TLB flush. */
	write_cr3(build_cr3(mm->pgd, 0));

	/* Reinitialize tlbstate. */
	this_cpu_write(cpu_tlbstate.last_user_mm_spec, LAST_USER_MM_INIT);
	this_cpu_write(cpu_tlbstate.loaded_mm_asid, 0);
	this_cpu_write(cpu_tlbstate.next_asid, 1);
	this_cpu_write(cpu_tlbstate.ctxs[0].ctx_id, mm->context.ctx_id);
	this_cpu_write(cpu_tlbstate.ctxs[0].tlb_gen, tlb_gen);

	for (i = 1; i < TLB_NR_DYN_ASIDS; i++)
		this_cpu_write(cpu_tlbstate.ctxs[i].ctx_id, 0);
}

static void flush_tlb_func(void *info)
{
	/*
	const struct flush_tlb_info *f = info;
	struct mm_struct *loaded_mm = this_cpu_read(cpu_tlbstate.loaded_mm);
	u32 loaded_mm_asid = this_cpu_read(cpu_tlbstate.loaded_mm_asid);
	u64 local_tlb_gen = this_cpu_read(cpu_tlbstate.ctxs[loaded_mm_asid].tlb_gen);
	bool local = smp_processor_id() == f->initiating_cpu;
	unsigned long nr_invalidate = 0;
	u64 mm_tlb_gen;

	/* This code cannot presently handle being reentered. */
	VM_WARN_ON(!irqs_disabled());

	if (!local) {
		inc_irq_stat(irq_tlb_count);
		count_vm_tlb_event(NR_TLB_REMOTE_FLUSH_RECEIVED);

		/* Can only happen on remote CPUs */
		if (f->mm && f->mm != loaded_mm)
			return;
	}

	if (unlikely(loaded_mm == &init_mm))
		return;

	VM_WARN_ON(this_cpu_read(cpu_tlbstate.ctxs[loaded_mm_asid].ctx_id) !=
		   loaded_mm->context.ctx_id);

	if (this_cpu_read(cpu_tlbstate_shared.is_lazy)) {
		/*
		switch_mm_irqs_off(NULL, &init_mm, NULL);
		return;
	}

	if (unlikely(f->new_tlb_gen != TLB_GENERATION_INVALID &&
		     f->new_tlb_gen <= local_tlb_gen)) {
		/*
		return;
	}

	/*
	mm_tlb_gen = atomic64_read(&loaded_mm->context.tlb_gen);

	if (unlikely(local_tlb_gen == mm_tlb_gen)) {
		/*
		goto done;
	}

	WARN_ON_ONCE(local_tlb_gen > mm_tlb_gen);
	WARN_ON_ONCE(f->new_tlb_gen > mm_tlb_gen);

	/*
	if (f->end != TLB_FLUSH_ALL &&
	    f->new_tlb_gen == local_tlb_gen + 1 &&
	    f->new_tlb_gen == mm_tlb_gen) {
		/* Partial flush */
		unsigned long addr = f->start;

		/* Partial flush cannot have invalid generations */
		VM_WARN_ON(f->new_tlb_gen == TLB_GENERATION_INVALID);

		/* Partial flush must have valid mm */
		VM_WARN_ON(f->mm == NULL);

		nr_invalidate = (f->end - f->start) >> f->stride_shift;

		while (addr < f->end) {
			flush_tlb_one_user(addr);
			addr += 1UL << f->stride_shift;
		}
		if (local)
			count_vm_tlb_events(NR_TLB_LOCAL_FLUSH_ONE, nr_invalidate);
	} else {
		/* Full flush. */
		nr_invalidate = TLB_FLUSH_ALL;

		flush_tlb_local();
		if (local)
			count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
	}

	/* Both paths above update our state to mm_tlb_gen. */
	this_cpu_write(cpu_tlbstate.ctxs[loaded_mm_asid].tlb_gen, mm_tlb_gen);

	/* Tracing is done in a unified manner to reduce the code size */
done:
	trace_tlb_flush(!local ? TLB_REMOTE_SHOOTDOWN :
				(f->mm == NULL) ? TLB_LOCAL_SHOOTDOWN :
						  TLB_LOCAL_MM_SHOOTDOWN,
			nr_invalidate);
}

static bool tlb_is_not_lazy(int cpu, void *data)
{
	return !per_cpu(cpu_tlbstate_shared.is_lazy, cpu);
}

DEFINE_PER_CPU_SHARED_ALIGNED(struct tlb_state_shared, cpu_tlbstate_shared);
EXPORT_PER_CPU_SYMBOL(cpu_tlbstate_shared);

STATIC_NOPV void native_flush_tlb_multi(const struct cpumask *cpumask,
					 const struct flush_tlb_info *info)
{
	/*
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
	if (info->end == TLB_FLUSH_ALL)
		trace_tlb_flush(TLB_REMOTE_SEND_IPI, TLB_FLUSH_ALL);
	else
		trace_tlb_flush(TLB_REMOTE_SEND_IPI,
				(info->end - info->start) >> PAGE_SHIFT);

	/*
	if (info->freed_tables)
		on_each_cpu_mask(cpumask, flush_tlb_func, (void *)info, true);
	else
		on_each_cpu_cond_mask(tlb_is_not_lazy, flush_tlb_func,
				(void *)info, 1, cpumask);
}

void flush_tlb_multi(const struct cpumask *cpumask,
		      const struct flush_tlb_info *info)
{
	__flush_tlb_multi(cpumask, info);
}

unsigned long tlb_single_page_flush_ceiling __read_mostly = 33;

static DEFINE_PER_CPU_SHARED_ALIGNED(struct flush_tlb_info, flush_tlb_info);

#ifdef CONFIG_DEBUG_VM
static DEFINE_PER_CPU(unsigned int, flush_tlb_info_idx);
#endif

static struct flush_tlb_info *get_flush_tlb_info(struct mm_struct *mm,
			unsigned long start, unsigned long end,
			unsigned int stride_shift, bool freed_tables,
			u64 new_tlb_gen)
{
	struct flush_tlb_info *info = this_cpu_ptr(&flush_tlb_info);

#ifdef CONFIG_DEBUG_VM
	/*
	BUG_ON(this_cpu_inc_return(flush_tlb_info_idx) != 1);
#endif

	info->start		= start;
	info->end		= end;
	info->mm		= mm;
	info->stride_shift	= stride_shift;
	info->freed_tables	= freed_tables;
	info->new_tlb_gen	= new_tlb_gen;
	info->initiating_cpu	= smp_processor_id();

	return info;
}

static void put_flush_tlb_info(void)
{
#ifdef CONFIG_DEBUG_VM
	/* Complete reentrancy prevention checks */
	barrier();
	this_cpu_dec(flush_tlb_info_idx);
#endif
}

void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned int stride_shift,
				bool freed_tables)
{
	struct flush_tlb_info *info;
	u64 new_tlb_gen;
	int cpu;

	cpu = get_cpu();

	/* Should we flush just the requested range? */
	if ((end == TLB_FLUSH_ALL) ||
	    ((end - start) >> stride_shift) > tlb_single_page_flush_ceiling) {
		start = 0;
		end = TLB_FLUSH_ALL;
	}

	/* This is also a barrier that synchronizes with switch_mm(). */
	new_tlb_gen = inc_mm_tlb_gen(mm);

	info = get_flush_tlb_info(mm, start, end, stride_shift, freed_tables,
				  new_tlb_gen);

	/*
	if (cpumask_any_but(mm_cpumask(mm), cpu) < nr_cpu_ids) {
		flush_tlb_multi(mm_cpumask(mm), info);
	} else if (mm == this_cpu_read(cpu_tlbstate.loaded_mm)) {
		lockdep_assert_irqs_enabled();
		local_irq_disable();
		flush_tlb_func(info);
		local_irq_enable();
	}

	put_flush_tlb_info();
	put_cpu();
}


static void do_flush_tlb_all(void *info)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH_RECEIVED);
	__flush_tlb_all();
}

void flush_tlb_all(void)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
	on_each_cpu(do_flush_tlb_all, NULL, 1);
}

static void do_kernel_range_flush(void *info)
{
	struct flush_tlb_info *f = info;
	unsigned long addr;

	/* flush range by one by one 'invlpg' */
	for (addr = f->start; addr < f->end; addr += PAGE_SIZE)
		flush_tlb_one_kernel(addr);
}

void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	/* Balance as user space task's flush, a bit conservative */
	if (end == TLB_FLUSH_ALL ||
	    (end - start) > tlb_single_page_flush_ceiling << PAGE_SHIFT) {
		on_each_cpu(do_flush_tlb_all, NULL, 1);
	} else {
		struct flush_tlb_info *info;

		preempt_disable();
		info = get_flush_tlb_info(NULL, start, end, 0, false,
					  TLB_GENERATION_INVALID);

		on_each_cpu(do_kernel_range_flush, info, 1);

		put_flush_tlb_info();
		preempt_enable();
	}
}

unsigned long __get_current_cr3_fast(void)
{
	unsigned long cr3 = build_cr3(this_cpu_read(cpu_tlbstate.loaded_mm)->pgd,
		this_cpu_read(cpu_tlbstate.loaded_mm_asid));

	/* For now, be very restrictive about when this can be called. */
	VM_WARN_ON(in_nmi() || preemptible());

	VM_BUG_ON(cr3 != __read_cr3());
	return cr3;
}
EXPORT_SYMBOL_GPL(__get_current_cr3_fast);

void flush_tlb_one_kernel(unsigned long addr)
{
	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ONE);

	/*
	flush_tlb_one_user(addr);

	if (!static_cpu_has(X86_FEATURE_PTI))
		return;

	/*
	this_cpu_write(cpu_tlbstate.invalidate_other, true);
}

STATIC_NOPV void native_flush_tlb_one_user(unsigned long addr)
{
	u32 loaded_mm_asid = this_cpu_read(cpu_tlbstate.loaded_mm_asid);

	asm volatile("invlpg (%0)" ::"r" (addr) : "memory");

	if (!static_cpu_has(X86_FEATURE_PTI))
		return;

	/*
	if (!this_cpu_has(X86_FEATURE_INVPCID_SINGLE))
		invalidate_user_asid(loaded_mm_asid);
	else
		invpcid_flush_one(user_pcid(loaded_mm_asid), addr);
}

void flush_tlb_one_user(unsigned long addr)
{
	__flush_tlb_one_user(addr);
}

STATIC_NOPV void native_flush_tlb_global(void)
{
	unsigned long flags;

	if (static_cpu_has(X86_FEATURE_INVPCID)) {
		/*
		invpcid_flush_all();
		return;
	}

	/*
	raw_local_irq_save(flags);

	__native_tlb_flush_global(this_cpu_read(cpu_tlbstate.cr4));

	raw_local_irq_restore(flags);
}

STATIC_NOPV void native_flush_tlb_local(void)
{
	/*
	WARN_ON_ONCE(preemptible());

	invalidate_user_asid(this_cpu_read(cpu_tlbstate.loaded_mm_asid));

	/* If current->mm == NULL then the read_cr3() "borrows" an mm */
	native_write_cr3(__native_read_cr3());
}

void flush_tlb_local(void)
{
	__flush_tlb_local();
}

void __flush_tlb_all(void)
{
	/*
	VM_WARN_ON_ONCE(preemptible());

	if (boot_cpu_has(X86_FEATURE_PGE)) {
		__flush_tlb_global();
	} else {
		/*
		flush_tlb_local();
	}
}
EXPORT_SYMBOL_GPL(__flush_tlb_all);

void arch_tlbbatch_flush(struct arch_tlbflush_unmap_batch *batch)
{
	struct flush_tlb_info *info;

	int cpu = get_cpu();

	info = get_flush_tlb_info(NULL, 0, TLB_FLUSH_ALL, 0, false,
				  TLB_GENERATION_INVALID);
	/*
	if (cpumask_any_but(&batch->cpumask, cpu) < nr_cpu_ids) {
		flush_tlb_multi(&batch->cpumask, info);
	} else if (cpumask_test_cpu(cpu, &batch->cpumask)) {
		lockdep_assert_irqs_enabled();
		local_irq_disable();
		flush_tlb_func(info);
		local_irq_enable();
	}

	cpumask_clear(&batch->cpumask);

	put_flush_tlb_info();
	put_cpu();
}

bool nmi_uaccess_okay(void)
{
	struct mm_struct *loaded_mm = this_cpu_read(cpu_tlbstate.loaded_mm);
	struct mm_struct *current_mm = current->mm;

	VM_WARN_ON_ONCE(!loaded_mm);

	/*
	if (loaded_mm != current_mm)
		return false;

	VM_WARN_ON_ONCE(current_mm->pgd != __va(read_cr3_pa()));

	return true;
}

static ssize_t tlbflush_read_file(struct file *file, char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "%ld\n", tlb_single_page_flush_ceiling);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t tlbflush_write_file(struct file *file,
		 const char __user *user_buf, size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	int ceiling;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtoint(buf, 0, &ceiling))
		return -EINVAL;

	if (ceiling < 0)
		return -EINVAL;

	tlb_single_page_flush_ceiling = ceiling;
	return count;
}

static const struct file_operations fops_tlbflush = {
	.read = tlbflush_read_file,
	.write = tlbflush_write_file,
	.llseek = default_llseek,
};

static int __init create_tlb_single_page_flush_ceiling(void)
{
	debugfs_create_file("tlb_single_page_flush_ceiling", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_tlbflush);
	return 0;
}
late_initcall(create_tlb_single_page_flush_ceiling);
