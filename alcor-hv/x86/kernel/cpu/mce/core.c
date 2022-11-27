
#include <linux/thread_info.h>
#include <linux/capability.h>
#include <linux/miscdevice.h>
#include <linux/ratelimit.h>
#include <linux/rcupdate.h>
#include <linux/kobject.h>
#include <linux/uaccess.h>
#include <linux/kdebug.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/syscore_ops.h>
#include <linux/delay.h>
#include <linux/ctype.h>
#include <linux/sched.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/poll.h>
#include <linux/nmi.h>
#include <linux/cpu.h>
#include <linux/ras.h>
#include <linux/smp.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/irq_work.h>
#include <linux/export.h>
#include <linux/set_memory.h>
#include <linux/sync_core.h>
#include <linux/task_work.h>
#include <linux/hardirq.h>

#include <asm/intel-family.h>
#include <asm/processor.h>
#include <asm/traps.h>
#include <asm/tlbflush.h>
#include <asm/mce.h>
#include <asm/msr.h>
#include <asm/reboot.h>

#include "internal.h"

static DEFINE_MUTEX(mce_sysfs_mutex);

#define CREATE_TRACE_POINTS
#include <trace/events/mce.h>

#define SPINUNIT		100	/* 100ns */

DEFINE_PER_CPU(unsigned, mce_exception_count);

DEFINE_PER_CPU_READ_MOSTLY(unsigned int, mce_num_banks);

struct mce_bank {
	u64			ctl;			/* subevents to enable */

	__u64 init			: 1,		/* initialise bank? */
	      __reserved_1		: 63;
};
static DEFINE_PER_CPU_READ_MOSTLY(struct mce_bank[MAX_NR_BANKS], mce_banks_array);

#define ATTR_LEN               16
struct mce_bank_dev {
	struct device_attribute	attr;			/* device attribute */
	char			attrname[ATTR_LEN];	/* attribute name */
	u8			bank;			/* bank number */
};
static struct mce_bank_dev mce_bank_devs[MAX_NR_BANKS];

struct mce_vendor_flags mce_flags __read_mostly;

struct mca_config mca_cfg __read_mostly = {
	.bootlog  = -1,
	.monarch_timeout = -1
};

static DEFINE_PER_CPU(struct mce, mces_seen);
static unsigned long mce_need_notify;

DEFINE_PER_CPU(mce_banks_t, mce_poll_banks) = {
	[0 ... BITS_TO_LONGS(MAX_NR_BANKS)-1] = ~0UL
};

mce_banks_t mce_banks_ce_disabled;

static struct work_struct mce_work;
static struct irq_work mce_irq_work;

BLOCKING_NOTIFIER_HEAD(x86_mce_decoder_chain);

void mce_setup(struct mce *m)
{
	memset(m, 0, sizeof(struct mce));
	m->cpu = m->extcpu = smp_processor_id();
	/* need the internal __ version to avoid deadlocks */
	m->time = __ktime_get_real_seconds();
	m->cpuvendor = boot_cpu_data.x86_vendor;
	m->cpuid = cpuid_eax(1);
	m->socketid = cpu_data(m->extcpu).phys_proc_id;
	m->apicid = cpu_data(m->extcpu).initial_apicid;
	m->mcgcap = __rdmsr(MSR_IA32_MCG_CAP);
	m->ppin = cpu_data(m->extcpu).ppin;
	m->microcode = boot_cpu_data.microcode;
}

DEFINE_PER_CPU(struct mce, injectm);
EXPORT_PER_CPU_SYMBOL_GPL(injectm);

void mce_log(struct mce *m)
{
	if (!mce_gen_pool_add(m))
		irq_work_queue(&mce_irq_work);
}
EXPORT_SYMBOL_GPL(mce_log);

void mce_register_decode_chain(struct notifier_block *nb)
{
	if (WARN_ON(nb->priority < MCE_PRIO_LOWEST ||
		    nb->priority > MCE_PRIO_HIGHEST))
		return;

	blocking_notifier_chain_register(&x86_mce_decoder_chain, nb);
}
EXPORT_SYMBOL_GPL(mce_register_decode_chain);

void mce_unregister_decode_chain(struct notifier_block *nb)
{
	blocking_notifier_chain_unregister(&x86_mce_decoder_chain, nb);
}
EXPORT_SYMBOL_GPL(mce_unregister_decode_chain);

static void __print_mce(struct mce *m)
{
	pr_emerg(HW_ERR "CPU %d: Machine Check%s: %Lx Bank %d: %016Lx\n",
		 m->extcpu,
		 (m->mcgstatus & MCG_STATUS_MCIP ? " Exception" : ""),
		 m->mcgstatus, m->bank, m->status);

	if (m->ip) {
		pr_emerg(HW_ERR "RIP%s %02x:<%016Lx> ",
			!(m->mcgstatus & MCG_STATUS_EIPV) ? " !INEXACT!" : "",
			m->cs, m->ip);

		if (m->cs == __KERNEL_CS)
			pr_cont("{%pS}", (void *)(unsigned long)m->ip);
		pr_cont("\n");
	}

	pr_emerg(HW_ERR "TSC %llx ", m->tsc);
	if (m->addr)
		pr_cont("ADDR %llx ", m->addr);
	if (m->misc)
		pr_cont("MISC %llx ", m->misc);
	if (m->ppin)
		pr_cont("PPIN %llx ", m->ppin);

	if (mce_flags.smca) {
		if (m->synd)
			pr_cont("SYND %llx ", m->synd);
		if (m->ipid)
			pr_cont("IPID %llx ", m->ipid);
	}

	pr_cont("\n");

	/*
	pr_emerg(HW_ERR "PROCESSOR %u:%x TIME %llu SOCKET %u APIC %x microcode %x\n",
		m->cpuvendor, m->cpuid, m->time, m->socketid, m->apicid,
		m->microcode);
}

static void print_mce(struct mce *m)
{
	__print_mce(m);

	if (m->cpuvendor != X86_VENDOR_AMD && m->cpuvendor != X86_VENDOR_HYGON)
		pr_emerg_ratelimited(HW_ERR "Run the above through 'mcelog --ascii'\n");
}

#define PANIC_TIMEOUT 5 /* 5 seconds */

static atomic_t mce_panicked;

static int fake_panic;
static atomic_t mce_fake_panicked;

static void wait_for_panic(void)
{
	long timeout = PANIC_TIMEOUT*USEC_PER_SEC;

	preempt_disable();
	local_irq_enable();
	while (timeout-- > 0)
		udelay(1);
	if (panic_timeout == 0)
		panic_timeout = mca_cfg.panic_timeout;
	panic("Panicing machine check CPU died");
}

static noinstr void mce_panic(const char *msg, struct mce *final, char *exp)
{
	struct llist_node *pending;
	struct mce_evt_llist *l;
	int apei_err = 0;

	/*
	instrumentation_begin();

	if (!fake_panic) {
		/*
		if (atomic_inc_return(&mce_panicked) > 1)
			wait_for_panic();
		barrier();

		bust_spinlocks(1);
		console_verbose();
	} else {
		/* Don't log too much for fake panic */
		if (atomic_inc_return(&mce_fake_panicked) > 1)
			goto out;
	}
	pending = mce_gen_pool_prepare_records();
	/* First print corrected ones that are still unlogged */
	llist_for_each_entry(l, pending, llnode) {
		struct mce *m = &l->mce;
		if (!(m->status & MCI_STATUS_UC)) {
			print_mce(m);
			if (!apei_err)
				apei_err = apei_write_mce(m);
		}
	}
	/* Now print uncorrected but with the final one last */
	llist_for_each_entry(l, pending, llnode) {
		struct mce *m = &l->mce;
		if (!(m->status & MCI_STATUS_UC))
			continue;
		if (!final || mce_cmp(m, final)) {
			print_mce(m);
			if (!apei_err)
				apei_err = apei_write_mce(m);
		}
	}
	if (final) {
		print_mce(final);
		if (!apei_err)
			apei_err = apei_write_mce(final);
	}
	if (exp)
		pr_emerg(HW_ERR "Machine check: %s\n", exp);
	if (!fake_panic) {
		if (panic_timeout == 0)
			panic_timeout = mca_cfg.panic_timeout;
		panic(msg);
	} else
		pr_emerg(HW_ERR "Fake kernel panic: %s\n", msg);

out:
	instrumentation_end();
}


static int msr_to_offset(u32 msr)
{
	unsigned bank = __this_cpu_read(injectm.bank);

	if (msr == mca_cfg.rip_msr)
		return offsetof(struct mce, ip);
	if (msr == mca_msr_reg(bank, MCA_STATUS))
		return offsetof(struct mce, status);
	if (msr == mca_msr_reg(bank, MCA_ADDR))
		return offsetof(struct mce, addr);
	if (msr == mca_msr_reg(bank, MCA_MISC))
		return offsetof(struct mce, misc);
	if (msr == MSR_IA32_MCG_STATUS)
		return offsetof(struct mce, mcgstatus);
	return -1;
}

void ex_handler_msr_mce(struct pt_regs *regs, bool wrmsr)
{
	if (wrmsr) {
		pr_emerg("MSR access error: WRMSR to 0x%x (tried to write 0x%08x%08x) at rIP: 0x%lx (%pS)\n",
			 (unsigned int)regs->cx, (unsigned int)regs->dx, (unsigned int)regs->ax,
			 regs->ip, (void *)regs->ip);
	} else {
		pr_emerg("MSR access error: RDMSR from 0x%x at rIP: 0x%lx (%pS)\n",
			 (unsigned int)regs->cx, regs->ip, (void *)regs->ip);
	}

	show_stack_regs(regs);

	panic("MCA architectural violation!\n");

	while (true)
		cpu_relax();
}

noinstr u64 mce_rdmsrl(u32 msr)
{
	DECLARE_ARGS(val, low, high);

	if (__this_cpu_read(injectm.finished)) {
		int offset;
		u64 ret;

		instrumentation_begin();

		offset = msr_to_offset(msr);
		if (offset < 0)
			ret = 0;
		else
			ret = *(u64 *)((char *)this_cpu_ptr(&injectm) + offset);

		instrumentation_end();

		return ret;
	}

	/*
	asm volatile("1: rdmsr\n"
		     "2:\n"
		     _ASM_EXTABLE_TYPE(1b, 2b, EX_TYPE_RDMSR_IN_MCE)
		     : EAX_EDX_RET(val, low, high) : "c" (msr));


	return EAX_EDX_VAL(val, low, high);
}

static noinstr void mce_wrmsrl(u32 msr, u64 v)
{
	u32 low, high;

	if (__this_cpu_read(injectm.finished)) {
		int offset;

		instrumentation_begin();

		offset = msr_to_offset(msr);
		if (offset >= 0)
			*(u64 *)((char *)this_cpu_ptr(&injectm) + offset) = v;

		instrumentation_end();

		return;
	}

	low  = (u32)v;
	high = (u32)(v >> 32);

	/* See comment in mce_rdmsrl() */
	asm volatile("1: wrmsr\n"
		     "2:\n"
		     _ASM_EXTABLE_TYPE(1b, 2b, EX_TYPE_WRMSR_IN_MCE)
		     : : "c" (msr), "a"(low), "d" (high) : "memory");
}

static noinstr void mce_gather_info(struct mce *m, struct pt_regs *regs)
{
	/*
	instrumentation_begin();
	mce_setup(m);
	instrumentation_end();

	m->mcgstatus = mce_rdmsrl(MSR_IA32_MCG_STATUS);
	if (regs) {
		/*
		if (m->mcgstatus & (MCG_STATUS_RIPV|MCG_STATUS_EIPV)) {
			m->ip = regs->ip;
			m->cs = regs->cs;

			/*
			if (v8086_mode(regs))
				m->cs |= 3;
		}
		/* Use accurate RIP reporting if available. */
		if (mca_cfg.rip_msr)
			m->ip = mce_rdmsrl(mca_cfg.rip_msr);
	}
}

int mce_available(struct cpuinfo_x86 *c)
{
	if (mca_cfg.disabled)
		return 0;
	return cpu_has(c, X86_FEATURE_MCE) && cpu_has(c, X86_FEATURE_MCA);
}

static void mce_schedule_work(void)
{
	if (!mce_gen_pool_empty())
		schedule_work(&mce_work);
}

static void mce_irq_work_cb(struct irq_work *entry)
{
	mce_schedule_work();
}

int mce_usable_address(struct mce *m)
{
	if (!(m->status & MCI_STATUS_ADDRV))
		return 0;

	/* Checks after this one are Intel/Zhaoxin-specific: */
	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL &&
	    boot_cpu_data.x86_vendor != X86_VENDOR_ZHAOXIN)
		return 1;

	if (!(m->status & MCI_STATUS_MISCV))
		return 0;

	if (MCI_MISC_ADDR_LSB(m->misc) > PAGE_SHIFT)
		return 0;

	if (MCI_MISC_ADDR_MODE(m->misc) != MCI_MISC_ADDR_PHYS)
		return 0;

	return 1;
}
EXPORT_SYMBOL_GPL(mce_usable_address);

bool mce_is_memory_error(struct mce *m)
{
	switch (m->cpuvendor) {
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		return amd_mce_is_memory_error(m);

	case X86_VENDOR_INTEL:
	case X86_VENDOR_ZHAOXIN:
		/*
		return (m->status & 0xef80) == BIT(7) ||
		       (m->status & 0xef00) == BIT(8) ||
		       (m->status & 0xeffc) == 0xc;

	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(mce_is_memory_error);

static bool whole_page(struct mce *m)
{
	if (!mca_cfg.ser || !(m->status & MCI_STATUS_MISCV))
		return true;

	return MCI_MISC_ADDR_LSB(m->misc) >= PAGE_SHIFT;
}

bool mce_is_correctable(struct mce *m)
{
	if (m->cpuvendor == X86_VENDOR_AMD && m->status & MCI_STATUS_DEFERRED)
		return false;

	if (m->cpuvendor == X86_VENDOR_HYGON && m->status & MCI_STATUS_DEFERRED)
		return false;

	if (m->status & MCI_STATUS_UC)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(mce_is_correctable);

static int mce_early_notifier(struct notifier_block *nb, unsigned long val,
			      void *data)
{
	struct mce *m = (struct mce *)data;

	if (!m)
		return NOTIFY_DONE;

	/* Emit the trace record: */
	trace_mce_record(m);

	set_bit(0, &mce_need_notify);

	mce_notify_irq();

	return NOTIFY_DONE;
}

static struct notifier_block early_nb = {
	.notifier_call	= mce_early_notifier,
	.priority	= MCE_PRIO_EARLY,
};

static int uc_decode_notifier(struct notifier_block *nb, unsigned long val,
			      void *data)
{
	struct mce *mce = (struct mce *)data;
	unsigned long pfn;

	if (!mce || !mce_usable_address(mce))
		return NOTIFY_DONE;

	if (mce->severity != MCE_AO_SEVERITY &&
	    mce->severity != MCE_DEFERRED_SEVERITY)
		return NOTIFY_DONE;

	pfn = mce->addr >> PAGE_SHIFT;
	if (!memory_failure(pfn, 0)) {
		set_mce_nospec(pfn);
		mce->kflags |= MCE_HANDLED_UC;
	}

	return NOTIFY_OK;
}

static struct notifier_block mce_uc_nb = {
	.notifier_call	= uc_decode_notifier,
	.priority	= MCE_PRIO_UC,
};

static int mce_default_notifier(struct notifier_block *nb, unsigned long val,
				void *data)
{
	struct mce *m = (struct mce *)data;

	if (!m)
		return NOTIFY_DONE;

	if (mca_cfg.print_all || !m->kflags)
		__print_mce(m);

	return NOTIFY_DONE;
}

static struct notifier_block mce_default_nb = {
	.notifier_call	= mce_default_notifier,
	/* lowest prio, we want it to run last. */
	.priority	= MCE_PRIO_LOWEST,
};

static noinstr void mce_read_aux(struct mce *m, int i)
{
	if (m->status & MCI_STATUS_MISCV)
		m->misc = mce_rdmsrl(mca_msr_reg(i, MCA_MISC));

	if (m->status & MCI_STATUS_ADDRV) {
		m->addr = mce_rdmsrl(mca_msr_reg(i, MCA_ADDR));

		/*
		if (mca_cfg.ser && (m->status & MCI_STATUS_MISCV)) {
			u8 shift = MCI_MISC_ADDR_LSB(m->misc);
			m->addr >>= shift;
			m->addr <<= shift;
		}

		/*
		if (mce_flags.smca) {
			u8 lsb = (m->addr >> 56) & 0x3f;

			m->addr &= GENMASK_ULL(55, lsb);
		}
	}

	if (mce_flags.smca) {
		m->ipid = mce_rdmsrl(MSR_AMD64_SMCA_MCx_IPID(i));

		if (m->status & MCI_STATUS_SYNDV)
			m->synd = mce_rdmsrl(MSR_AMD64_SMCA_MCx_SYND(i));
	}
}

DEFINE_PER_CPU(unsigned, mce_poll_count);

bool machine_check_poll(enum mcp_flags flags, mce_banks_t *b)
{
	struct mce_bank *mce_banks = this_cpu_ptr(mce_banks_array);
	bool error_seen = false;
	struct mce m;
	int i;

	this_cpu_inc(mce_poll_count);

	mce_gather_info(&m, NULL);

	if (flags & MCP_TIMESTAMP)
		m.tsc = rdtsc();

	for (i = 0; i < this_cpu_read(mce_num_banks); i++) {
		if (!mce_banks[i].ctl || !test_bit(i, *b))
			continue;

		m.misc = 0;
		m.addr = 0;
		m.bank = i;

		barrier();
		m.status = mce_rdmsrl(mca_msr_reg(i, MCA_STATUS));

		/* If this entry is not valid, ignore it */
		if (!(m.status & MCI_STATUS_VAL))
			continue;

		/*
		if ((flags & MCP_UC) || !(m.status & MCI_STATUS_UC))
			goto log_it;

		/*
		if (!mca_cfg.ser) {
			if (m.status & MCI_STATUS_UC)
				continue;
			goto log_it;
		}

		/* Log "not enabled" (speculative) errors */
		if (!(m.status & MCI_STATUS_EN))
			goto log_it;

		/*
		if (!(m.status & MCI_STATUS_PCC) && !(m.status & MCI_STATUS_S))
			goto log_it;

		/*
		continue;

log_it:
		error_seen = true;

		if (flags & MCP_DONTLOG)
			goto clear_it;

		mce_read_aux(&m, i);
		m.severity = mce_severity(&m, NULL, NULL, false);
		/*

		if (mca_cfg.dont_log_ce && !mce_usable_address(&m))
			goto clear_it;

		if (flags & MCP_QUEUE_LOG)
			mce_gen_pool_add(&m);
		else
			mce_log(&m);

clear_it:
		/*
		mce_wrmsrl(mca_msr_reg(i, MCA_STATUS), 0);
	}

	/*

	sync_core();

	return error_seen;
}
EXPORT_SYMBOL_GPL(machine_check_poll);

static __always_inline void
quirk_sandybridge_ifu(int bank, struct mce *m, struct pt_regs *regs)
{
	if (bank != 0)
		return;
	if ((m->mcgstatus & (MCG_STATUS_EIPV|MCG_STATUS_RIPV)) != 0)
		return;
	if ((m->status & (MCI_STATUS_OVER|MCI_STATUS_UC|
		          MCI_STATUS_EN|MCI_STATUS_MISCV|MCI_STATUS_ADDRV|
			  MCI_STATUS_PCC|MCI_STATUS_S|MCI_STATUS_AR|
			  MCACOD)) !=
			 (MCI_STATUS_UC|MCI_STATUS_EN|
			  MCI_STATUS_MISCV|MCI_STATUS_ADDRV|MCI_STATUS_S|
			  MCI_STATUS_AR|MCACOD_INSTR))
		return;

	m->mcgstatus |= MCG_STATUS_EIPV;
	m->ip = regs->ip;
	m->cs = regs->cs;
}

static noinstr bool quirk_skylake_repmov(void)
{
	u64 mcgstatus   = mce_rdmsrl(MSR_IA32_MCG_STATUS);
	u64 misc_enable = mce_rdmsrl(MSR_IA32_MISC_ENABLE);
	u64 mc1_status;

	/*
	if (!(mcgstatus & MCG_STATUS_LMCES) ||
	    !(misc_enable & MSR_IA32_MISC_ENABLE_FAST_STRING))
		return false;

	mc1_status = mce_rdmsrl(MSR_IA32_MCx_STATUS(1));

	/* Check for a software-recoverable data fetch error. */
	if ((mc1_status &
	     (MCI_STATUS_VAL | MCI_STATUS_OVER | MCI_STATUS_UC | MCI_STATUS_EN |
	      MCI_STATUS_ADDRV | MCI_STATUS_MISCV | MCI_STATUS_PCC |
	      MCI_STATUS_AR | MCI_STATUS_S)) ==
	     (MCI_STATUS_VAL |                   MCI_STATUS_UC | MCI_STATUS_EN |
	      MCI_STATUS_ADDRV | MCI_STATUS_MISCV |
	      MCI_STATUS_AR | MCI_STATUS_S)) {
		misc_enable &= ~MSR_IA32_MISC_ENABLE_FAST_STRING;
		mce_wrmsrl(MSR_IA32_MISC_ENABLE, misc_enable);
		mce_wrmsrl(MSR_IA32_MCx_STATUS(1), 0);

		instrumentation_begin();
		pr_err_once("Erratum detected, disable fast string copy instructions.\n");
		instrumentation_end();

		return true;
	}

	return false;
}

static __always_inline int mce_no_way_out(struct mce *m, char **msg, unsigned long *validp,
					  struct pt_regs *regs)
{
	char *tmp = *msg;
	int i;

	for (i = 0; i < this_cpu_read(mce_num_banks); i++) {
		m->status = mce_rdmsrl(mca_msr_reg(i, MCA_STATUS));
		if (!(m->status & MCI_STATUS_VAL))
			continue;

		arch___set_bit(i, validp);
		if (mce_flags.snb_ifu_quirk)
			quirk_sandybridge_ifu(i, m, regs);

		m->bank = i;
		if (mce_severity(m, regs, &tmp, true) >= MCE_PANIC_SEVERITY) {
			mce_read_aux(m, i);
			*msg = tmp;
			return 1;
		}
	}
	return 0;
}

static atomic_t mce_executing;

static atomic_t mce_callin;

static cpumask_t mce_missing_cpus = CPU_MASK_ALL;

static noinstr int mce_timed_out(u64 *t, const char *msg)
{
	int ret = 0;

	/* Enable instrumentation around calls to external facilities */
	instrumentation_begin();

	/*
	rmb();
	if (atomic_read(&mce_panicked))
		wait_for_panic();
	if (!mca_cfg.monarch_timeout)
		goto out;
	if ((s64)*t < SPINUNIT) {
		if (cpumask_and(&mce_missing_cpus, cpu_online_mask, &mce_missing_cpus))
			pr_emerg("CPUs not responding to MCE broadcast (may include false positives): %*pbl\n",
				 cpumask_pr_args(&mce_missing_cpus));
		mce_panic(msg, NULL, NULL);

		ret = 1;
		goto out;
	}

out:
	touch_nmi_watchdog();

	instrumentation_end();

	return ret;
}

static void mce_reign(void)
{
	int cpu;
	struct mce *m = NULL;
	int global_worst = 0;
	char *msg = NULL;

	/*
	for_each_possible_cpu(cpu) {
		struct mce *mtmp = &per_cpu(mces_seen, cpu);

		if (mtmp->severity > global_worst) {
			global_worst = mtmp->severity;
			m = &per_cpu(mces_seen, cpu);
		}
	}

	/*
	if (m && global_worst >= MCE_PANIC_SEVERITY) {
		/* call mce_severity() to get "msg" for panic */
		mce_severity(m, NULL, &msg, true);
		mce_panic("Fatal machine check", m, msg);
	}

	/*

	/*
	if (global_worst <= MCE_KEEP_SEVERITY)
		mce_panic("Fatal machine check from unknown source", NULL, NULL);

	/*
	for_each_possible_cpu(cpu)
		memset(&per_cpu(mces_seen, cpu), 0, sizeof(struct mce));
}

static atomic_t global_nwo;

static noinstr int mce_start(int *no_way_out)
{
	u64 timeout = (u64)mca_cfg.monarch_timeout * NSEC_PER_USEC;
	int order, ret = -1;

	if (!timeout)
		return ret;

	arch_atomic_add(*no_way_out, &global_nwo);
	/*
	order = arch_atomic_inc_return(&mce_callin);
	arch_cpumask_clear_cpu(smp_processor_id(), &mce_missing_cpus);

	/* Enable instrumentation around calls to external facilities */
	instrumentation_begin();

	/*
	while (arch_atomic_read(&mce_callin) != num_online_cpus()) {
		if (mce_timed_out(&timeout,
				  "Timeout: Not all CPUs entered broadcast exception handler")) {
			arch_atomic_set(&global_nwo, 0);
			goto out;
		}
		ndelay(SPINUNIT);
	}

	/*
	smp_rmb();

	if (order == 1) {
		/*
		arch_atomic_set(&mce_executing, 1);
	} else {
		/*
		while (arch_atomic_read(&mce_executing) < order) {
			if (mce_timed_out(&timeout,
					  "Timeout: Subject CPUs unable to finish machine check processing")) {
				arch_atomic_set(&global_nwo, 0);
				goto out;
			}
			ndelay(SPINUNIT);
		}
	}

	/*

	ret = order;

out:
	instrumentation_end();

	return ret;
}

static noinstr int mce_end(int order)
{
	u64 timeout = (u64)mca_cfg.monarch_timeout * NSEC_PER_USEC;
	int ret = -1;

	/* Allow instrumentation around external facilities. */
	instrumentation_begin();

	if (!timeout)
		goto reset;
	if (order < 0)
		goto reset;

	/*
	atomic_inc(&mce_executing);

	if (order == 1) {
		/*
		while (atomic_read(&mce_executing) <= num_online_cpus()) {
			if (mce_timed_out(&timeout,
					  "Timeout: Monarch CPU unable to finish machine check processing"))
				goto reset;
			ndelay(SPINUNIT);
		}

		mce_reign();
		barrier();
		ret = 0;
	} else {
		/*
		while (atomic_read(&mce_executing) != 0) {
			if (mce_timed_out(&timeout,
					  "Timeout: Monarch CPU did not finish machine check processing"))
				goto reset;
			ndelay(SPINUNIT);
		}

		/*
		ret = 0;
		goto out;
	}

	/*
reset:
	atomic_set(&global_nwo, 0);
	atomic_set(&mce_callin, 0);
	cpumask_setall(&mce_missing_cpus);
	barrier();

	/*
	atomic_set(&mce_executing, 0);

out:
	instrumentation_end();

	return ret;
}

static __always_inline void mce_clear_state(unsigned long *toclear)
{
	int i;

	for (i = 0; i < this_cpu_read(mce_num_banks); i++) {
		if (arch_test_bit(i, toclear))
			mce_wrmsrl(mca_msr_reg(i, MCA_STATUS), 0);
	}
}

static noinstr bool mce_check_crashing_cpu(void)
{
	unsigned int cpu = smp_processor_id();

	if (arch_cpu_is_offline(cpu) ||
	    (crashing_cpu != -1 && crashing_cpu != cpu)) {
		u64 mcgstatus;

		mcgstatus = __rdmsr(MSR_IA32_MCG_STATUS);

		if (boot_cpu_data.x86_vendor == X86_VENDOR_ZHAOXIN) {
			if (mcgstatus & MCG_STATUS_LMCES)
				return false;
		}

		if (mcgstatus & MCG_STATUS_RIPV) {
			__wrmsr(MSR_IA32_MCG_STATUS, 0, 0);
			return true;
		}
	}
	return false;
}

static __always_inline int
__mc_scan_banks(struct mce *m, struct pt_regs *regs, struct mce *final,
		unsigned long *toclear, unsigned long *valid_banks, int no_way_out,
		int *worst)
{
	struct mce_bank *mce_banks = this_cpu_ptr(mce_banks_array);
	struct mca_config *cfg = &mca_cfg;
	int severity, i, taint = 0;

	for (i = 0; i < this_cpu_read(mce_num_banks); i++) {
		arch___clear_bit(i, toclear);
		if (!arch_test_bit(i, valid_banks))
			continue;

		if (!mce_banks[i].ctl)
			continue;

		m->misc = 0;
		m->addr = 0;
		m->bank = i;

		m->status = mce_rdmsrl(mca_msr_reg(i, MCA_STATUS));
		if (!(m->status & MCI_STATUS_VAL))
			continue;

		/*
		if (!(m->status & (cfg->ser ? MCI_STATUS_S : MCI_STATUS_UC)) &&
			!no_way_out)
			continue;

		/* Set taint even when machine check was not enabled. */
		taint++;

		severity = mce_severity(m, regs, NULL, true);

		/*
		if ((severity == MCE_KEEP_SEVERITY ||
		     severity == MCE_UCNA_SEVERITY) && !no_way_out)
			continue;

		arch___set_bit(i, toclear);

		/* Machine check event was not enabled. Clear, but ignore. */
		if (severity == MCE_NO_SEVERITY)
			continue;

		mce_read_aux(m, i);

		/* assuming valid severity level != 0 */
		m->severity = severity;

		/*
		instrumentation_begin();
		mce_log(m);
		instrumentation_end();

		if (severity > *worst) {
			*final = *m;
			*worst = severity;
		}
	}

	/* mce_clear_state will clear *final, save locally for use later */

	return taint;
}

static void kill_me_now(struct callback_head *ch)
{
	struct task_struct *p = container_of(ch, struct task_struct, mce_kill_me);

	p->mce_count = 0;
	force_sig(SIGBUS);
}

static void kill_me_maybe(struct callback_head *cb)
{
	struct task_struct *p = container_of(cb, struct task_struct, mce_kill_me);
	int flags = MF_ACTION_REQUIRED;
	int ret;

	p->mce_count = 0;
	pr_err("Uncorrected hardware memory error in user-access at %llx", p->mce_addr);

	if (!p->mce_ripv)
		flags |= MF_MUST_KILL;

	ret = memory_failure(p->mce_addr >> PAGE_SHIFT, flags);
	if (!ret) {
		set_mce_nospec(p->mce_addr >> PAGE_SHIFT);
		sync_core();
		return;
	}

	/*
	if (ret == -EHWPOISON || ret == -EOPNOTSUPP)
		return;

	pr_err("Memory error not recovered");
	kill_me_now(cb);
}

static void kill_me_never(struct callback_head *cb)
{
	struct task_struct *p = container_of(cb, struct task_struct, mce_kill_me);

	p->mce_count = 0;
	pr_err("Kernel accessed poison in user space at %llx\n", p->mce_addr);
	if (!memory_failure(p->mce_addr >> PAGE_SHIFT, 0))
		set_mce_nospec(p->mce_addr >> PAGE_SHIFT);
}

static void queue_task_work(struct mce *m, char *msg, void (*func)(struct callback_head *))
{
	int count = ++current->mce_count;

	/* First call, save all the details */
	if (count == 1) {
		current->mce_addr = m->addr;
		current->mce_kflags = m->kflags;
		current->mce_ripv = !!(m->mcgstatus & MCG_STATUS_RIPV);
		current->mce_whole_page = whole_page(m);
		current->mce_kill_me.func = func;
	}

	/* Ten is likely overkill. Don't expect more than two faults before task_work() */
	if (count > 10)
		mce_panic("Too many consecutive machine checks while accessing user data", m, msg);

	/* Second or later call, make sure page address matches the one from first call */
	if (count > 1 && (current->mce_addr >> PAGE_SHIFT) != (m->addr >> PAGE_SHIFT))
		mce_panic("Consecutive machine checks to different user pages", m, msg);

	/* Do not call task_work_add() more than once */
	if (count > 1)
		return;

	task_work_add(current, &current->mce_kill_me, TWA_RESUME);
}

static noinstr void unexpected_machine_check(struct pt_regs *regs)
{
	instrumentation_begin();
	pr_err("CPU#%d: Unexpected int18 (Machine Check)\n",
	       smp_processor_id());
	instrumentation_end();
}

noinstr void do_machine_check(struct pt_regs *regs)
{
	int worst = 0, order, no_way_out, kill_current_task, lmce, taint = 0;
	DECLARE_BITMAP(valid_banks, MAX_NR_BANKS) = { 0 };
	DECLARE_BITMAP(toclear, MAX_NR_BANKS) = { 0 };
	struct mce m, *final;
	char *msg = NULL;

	if (unlikely(mce_flags.p5))
		return pentium_machine_check(regs);
	else if (unlikely(mce_flags.winchip))
		return winchip_machine_check(regs);
	else if (unlikely(!mca_cfg.initialized))
		return unexpected_machine_check(regs);

	if (mce_flags.skx_repmov_quirk && quirk_skylake_repmov())
		goto clear;

	/*
	order = -1;

	/*
	no_way_out = 0;

	/*
	kill_current_task = 0;

	/*
	lmce = 1;

	this_cpu_inc(mce_exception_count);

	mce_gather_info(&m, regs);
	m.tsc = rdtsc();

	final = this_cpu_ptr(&mces_seen);

	no_way_out = mce_no_way_out(&m, &msg, valid_banks, regs);

	barrier();

	/*
	if (!(m.mcgstatus & MCG_STATUS_RIPV))
		kill_current_task = 1;
	/*
	if (m.cpuvendor == X86_VENDOR_INTEL ||
	    m.cpuvendor == X86_VENDOR_ZHAOXIN)
		lmce = m.mcgstatus & MCG_STATUS_LMCES;

	/*
	if (lmce) {
		if (no_way_out)
			mce_panic("Fatal local machine check", &m, msg);
	} else {
		order = mce_start(&no_way_out);
	}

	taint = __mc_scan_banks(&m, regs, final, toclear, valid_banks, no_way_out, &worst);

	if (!no_way_out)
		mce_clear_state(toclear);

	/*
	if (!lmce) {
		if (mce_end(order) < 0) {
			if (!no_way_out)
				no_way_out = worst >= MCE_PANIC_SEVERITY;

			if (no_way_out)
				mce_panic("Fatal machine check on current CPU", &m, msg);
		}
	} else {
		/*
		if (worst >= MCE_PANIC_SEVERITY) {
			mce_severity(&m, regs, &msg, true);
			mce_panic("Local fatal machine check!", &m, msg);
		}
	}

	/*
	instrumentation_begin();

	if (taint)
		add_taint(TAINT_MACHINE_CHECK, LOCKDEP_NOW_UNRELIABLE);

	if (worst != MCE_AR_SEVERITY && !kill_current_task)
		goto out;

	/* Fault was in user mode and we need to take some action */
	if ((m.cs & 3) == 3) {
		/* If this triggers there is no way to recover. Die hard. */
		BUG_ON(!on_thread_stack() || !user_mode(regs));

		if (kill_current_task)
			queue_task_work(&m, msg, kill_me_now);
		else
			queue_task_work(&m, msg, kill_me_maybe);

	} else {
		/*
		if (m.kflags & MCE_IN_KERNEL_RECOV) {
			if (!fixup_exception(regs, X86_TRAP_MC, 0, 0))
				mce_panic("Failed kernel mode recovery", &m, msg);
		}

		if (m.kflags & MCE_IN_KERNEL_COPYIN)
			queue_task_work(&m, msg, kill_me_never);
	}

out:
	instrumentation_end();

clear:
	mce_wrmsrl(MSR_IA32_MCG_STATUS, 0);
}
EXPORT_SYMBOL_GPL(do_machine_check);

#ifndef CONFIG_MEMORY_FAILURE
int memory_failure(unsigned long pfn, int flags)
{
	/* mce_severity() should not hand us an ACTION_REQUIRED error */
	BUG_ON(flags & MF_ACTION_REQUIRED);
	pr_err("Uncorrected memory error in page 0x%lx ignored\n"
	       "Rebuild kernel with CONFIG_MEMORY_FAILURE=y for smarter handling\n",
	       pfn);

	return 0;
}
#endif

static unsigned long check_interval = INITIAL_CHECK_INTERVAL;

static DEFINE_PER_CPU(unsigned long, mce_next_interval); /* in jiffies */
static DEFINE_PER_CPU(struct timer_list, mce_timer);

static unsigned long mce_adjust_timer_default(unsigned long interval)
{
	return interval;
}

static unsigned long (*mce_adjust_timer)(unsigned long interval) = mce_adjust_timer_default;

static void __start_timer(struct timer_list *t, unsigned long interval)
{
	unsigned long when = jiffies + interval;
	unsigned long flags;

	local_irq_save(flags);

	if (!timer_pending(t) || time_before(when, t->expires))
		mod_timer(t, round_jiffies(when));

	local_irq_restore(flags);
}

static void mce_timer_fn(struct timer_list *t)
{
	struct timer_list *cpu_t = this_cpu_ptr(&mce_timer);
	unsigned long iv;

	WARN_ON(cpu_t != t);

	iv = __this_cpu_read(mce_next_interval);

	if (mce_available(this_cpu_ptr(&cpu_info))) {
		machine_check_poll(0, this_cpu_ptr(&mce_poll_banks));

		if (mce_intel_cmci_poll()) {
			iv = mce_adjust_timer(iv);
			goto done;
		}
	}

	/*
	if (mce_notify_irq())
		iv = max(iv / 2, (unsigned long) HZ/100);
	else
		iv = min(iv * 2, round_jiffies_relative(check_interval * HZ));

done:
	__this_cpu_write(mce_next_interval, iv);
	__start_timer(t, iv);
}

void mce_timer_kick(unsigned long interval)
{
	struct timer_list *t = this_cpu_ptr(&mce_timer);
	unsigned long iv = __this_cpu_read(mce_next_interval);

	__start_timer(t, interval);

	if (interval < iv)
		__this_cpu_write(mce_next_interval, interval);
}

static void mce_timer_delete_all(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		del_timer_sync(&per_cpu(mce_timer, cpu));
}

int mce_notify_irq(void)
{
	/* Not more than two messages every minute */
	static DEFINE_RATELIMIT_STATE(ratelimit, 60*HZ, 2);

	if (test_and_clear_bit(0, &mce_need_notify)) {
		mce_work_trigger();

		if (__ratelimit(&ratelimit))
			pr_info(HW_ERR "Machine check events logged\n");

		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(mce_notify_irq);

static void __mcheck_cpu_mce_banks_init(void)
{
	struct mce_bank *mce_banks = this_cpu_ptr(mce_banks_array);
	u8 n_banks = this_cpu_read(mce_num_banks);
	int i;

	for (i = 0; i < n_banks; i++) {
		struct mce_bank *b = &mce_banks[i];

		/*
		b->ctl = -1ULL;
		b->init = true;
	}
}

static void __mcheck_cpu_cap_init(void)
{
	u64 cap;
	u8 b;

	rdmsrl(MSR_IA32_MCG_CAP, cap);

	b = cap & MCG_BANKCNT_MASK;

	if (b > MAX_NR_BANKS) {
		pr_warn("CPU%d: Using only %u machine check banks out of %u\n",
			smp_processor_id(), MAX_NR_BANKS, b);
		b = MAX_NR_BANKS;
	}

	this_cpu_write(mce_num_banks, b);

	__mcheck_cpu_mce_banks_init();

	/* Use accurate RIP reporting if available. */
	if ((cap & MCG_EXT_P) && MCG_EXT_CNT(cap) >= 9)
		mca_cfg.rip_msr = MSR_IA32_MCG_EIP;

	if (cap & MCG_SER_P)
		mca_cfg.ser = 1;
}

static void __mcheck_cpu_init_generic(void)
{
	enum mcp_flags m_fl = 0;
	mce_banks_t all_banks;
	u64 cap;

	if (!mca_cfg.bootlog)
		m_fl = MCP_DONTLOG;

	/*
	bitmap_fill(all_banks, MAX_NR_BANKS);
	machine_check_poll(MCP_UC | MCP_QUEUE_LOG | m_fl, &all_banks);

	cr4_set_bits(X86_CR4_MCE);

	rdmsrl(MSR_IA32_MCG_CAP, cap);
	if (cap & MCG_CTL_P)
		wrmsr(MSR_IA32_MCG_CTL, 0xffffffff, 0xffffffff);
}

static void __mcheck_cpu_init_clear_banks(void)
{
	struct mce_bank *mce_banks = this_cpu_ptr(mce_banks_array);
	int i;

	for (i = 0; i < this_cpu_read(mce_num_banks); i++) {
		struct mce_bank *b = &mce_banks[i];

		if (!b->init)
			continue;
		wrmsrl(mca_msr_reg(i, MCA_CTL), b->ctl);
		wrmsrl(mca_msr_reg(i, MCA_STATUS), 0);
	}
}

static void __mcheck_cpu_check_banks(void)
{
	struct mce_bank *mce_banks = this_cpu_ptr(mce_banks_array);
	u64 msrval;
	int i;

	for (i = 0; i < this_cpu_read(mce_num_banks); i++) {
		struct mce_bank *b = &mce_banks[i];

		if (!b->init)
			continue;

		rdmsrl(mca_msr_reg(i, MCA_CTL), msrval);
		b->init = !!msrval;
	}
}

static int __mcheck_cpu_apply_quirks(struct cpuinfo_x86 *c)
{
	struct mce_bank *mce_banks = this_cpu_ptr(mce_banks_array);
	struct mca_config *cfg = &mca_cfg;

	if (c->x86_vendor == X86_VENDOR_UNKNOWN) {
		pr_info("unknown CPU type - not enabling MCE support\n");
		return -EOPNOTSUPP;
	}

	/* This should be disabled by the BIOS, but isn't always */
	if (c->x86_vendor == X86_VENDOR_AMD) {
		if (c->x86 == 15 && this_cpu_read(mce_num_banks) > 4) {
			/*
			clear_bit(10, (unsigned long *)&mce_banks[4].ctl);
		}
		if (c->x86 < 0x11 && cfg->bootlog < 0) {
			/*
			cfg->bootlog = 0;
		}
		/*
		if (c->x86 == 6 && this_cpu_read(mce_num_banks) > 0)
			mce_banks[0].ctl = 0;

		/*
		if (c->x86 == 0x15 && c->x86_model <= 0xf)
			mce_flags.overflow_recov = 1;

	}

	if (c->x86_vendor == X86_VENDOR_INTEL) {
		/*

		if (c->x86 == 6 && c->x86_model < 0x1A && this_cpu_read(mce_num_banks) > 0)
			mce_banks[0].init = false;

		/*
		if ((c->x86 > 6 || (c->x86 == 6 && c->x86_model >= 0xe)) &&
			cfg->monarch_timeout < 0)
			cfg->monarch_timeout = USEC_PER_SEC;

		/*
		if (c->x86 == 6 && c->x86_model <= 13 && cfg->bootlog < 0)
			cfg->bootlog = 0;

		if (c->x86 == 6 && c->x86_model == 45)
			mce_flags.snb_ifu_quirk = 1;

		/*
		if (c->x86 == 6 && c->x86_model == INTEL_FAM6_SKYLAKE_X)
			mce_flags.skx_repmov_quirk = 1;
	}

	if (c->x86_vendor == X86_VENDOR_ZHAOXIN) {
		/*
		if (c->x86 > 6 || (c->x86_model == 0x19 || c->x86_model == 0x1f)) {
			if (cfg->monarch_timeout < 0)
				cfg->monarch_timeout = USEC_PER_SEC;
		}
	}

	if (cfg->monarch_timeout < 0)
		cfg->monarch_timeout = 0;
	if (cfg->bootlog != 0)
		cfg->panic_timeout = 30;

	return 0;
}

static int __mcheck_cpu_ancient_init(struct cpuinfo_x86 *c)
{
	if (c->x86 != 5)
		return 0;

	switch (c->x86_vendor) {
	case X86_VENDOR_INTEL:
		intel_p5_mcheck_init(c);
		mce_flags.p5 = 1;
		return 1;
	case X86_VENDOR_CENTAUR:
		winchip_mcheck_init(c);
		mce_flags.winchip = 1;
		return 1;
	default:
		return 0;
	}

	return 0;
}

static void __mcheck_cpu_init_early(struct cpuinfo_x86 *c)
{
	if (c->x86_vendor == X86_VENDOR_AMD || c->x86_vendor == X86_VENDOR_HYGON) {
		mce_flags.overflow_recov = !!cpu_has(c, X86_FEATURE_OVERFLOW_RECOV);
		mce_flags.succor	 = !!cpu_has(c, X86_FEATURE_SUCCOR);
		mce_flags.smca		 = !!cpu_has(c, X86_FEATURE_SMCA);
		mce_flags.amd_threshold	 = 1;
	}
}

static void mce_centaur_feature_init(struct cpuinfo_x86 *c)
{
	struct mca_config *cfg = &mca_cfg;

	 /*
	if ((c->x86 == 6 && c->x86_model == 0xf && c->x86_stepping >= 0xe) ||
	     c->x86 > 6) {
		if (cfg->monarch_timeout < 0)
			cfg->monarch_timeout = USEC_PER_SEC;
	}
}

static void mce_zhaoxin_feature_init(struct cpuinfo_x86 *c)
{
	struct mce_bank *mce_banks = this_cpu_ptr(mce_banks_array);

	/*
	if ((c->x86 == 7 && c->x86_model == 0x1b) ||
	    (c->x86_model == 0x19 || c->x86_model == 0x1f)) {
		if (this_cpu_read(mce_num_banks) > 8)
			mce_banks[8].ctl = 0;
	}

	intel_init_cmci();
	intel_init_lmce();
	mce_adjust_timer = cmci_intel_adjust_timer;
}

static void mce_zhaoxin_feature_clear(struct cpuinfo_x86 *c)
{
	intel_clear_lmce();
}

static void __mcheck_cpu_init_vendor(struct cpuinfo_x86 *c)
{
	switch (c->x86_vendor) {
	case X86_VENDOR_INTEL:
		mce_intel_feature_init(c);
		mce_adjust_timer = cmci_intel_adjust_timer;
		break;

	case X86_VENDOR_AMD: {
		mce_amd_feature_init(c);
		break;
		}

	case X86_VENDOR_HYGON:
		mce_hygon_feature_init(c);
		break;

	case X86_VENDOR_CENTAUR:
		mce_centaur_feature_init(c);
		break;

	case X86_VENDOR_ZHAOXIN:
		mce_zhaoxin_feature_init(c);
		break;

	default:
		break;
	}
}

static void __mcheck_cpu_clear_vendor(struct cpuinfo_x86 *c)
{
	switch (c->x86_vendor) {
	case X86_VENDOR_INTEL:
		mce_intel_feature_clear(c);
		break;

	case X86_VENDOR_ZHAOXIN:
		mce_zhaoxin_feature_clear(c);
		break;

	default:
		break;
	}
}

static void mce_start_timer(struct timer_list *t)
{
	unsigned long iv = check_interval * HZ;

	if (mca_cfg.ignore_ce || !iv)
		return;

	this_cpu_write(mce_next_interval, iv);
	__start_timer(t, iv);
}

static void __mcheck_cpu_setup_timer(void)
{
	struct timer_list *t = this_cpu_ptr(&mce_timer);

	timer_setup(t, mce_timer_fn, TIMER_PINNED);
}

static void __mcheck_cpu_init_timer(void)
{
	struct timer_list *t = this_cpu_ptr(&mce_timer);

	timer_setup(t, mce_timer_fn, TIMER_PINNED);
	mce_start_timer(t);
}

bool filter_mce(struct mce *m)
{
	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD)
		return amd_filter_mce(m);
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		return intel_filter_mce(m);

	return false;
}

static __always_inline void exc_machine_check_kernel(struct pt_regs *regs)
{
	irqentry_state_t irq_state;

	WARN_ON_ONCE(user_mode(regs));

	/*
	if (mca_cfg.initialized && mce_check_crashing_cpu())
		return;

	irq_state = irqentry_nmi_enter(regs);

	do_machine_check(regs);

	irqentry_nmi_exit(regs, irq_state);
}

static __always_inline void exc_machine_check_user(struct pt_regs *regs)
{
	irqentry_enter_from_user_mode(regs);

	do_machine_check(regs);

	irqentry_exit_to_user_mode(regs);
}

#ifdef CONFIG_X86_64
DEFINE_IDTENTRY_MCE(exc_machine_check)
{
	unsigned long dr7;

	dr7 = local_db_save();
	exc_machine_check_kernel(regs);
	local_db_restore(dr7);
}

DEFINE_IDTENTRY_MCE_USER(exc_machine_check)
{
	unsigned long dr7;

	dr7 = local_db_save();
	exc_machine_check_user(regs);
	local_db_restore(dr7);
}
#else
DEFINE_IDTENTRY_RAW(exc_machine_check)
{
	unsigned long dr7;

	dr7 = local_db_save();
	if (user_mode(regs))
		exc_machine_check_user(regs);
	else
		exc_machine_check_kernel(regs);
	local_db_restore(dr7);
}
#endif

void mcheck_cpu_init(struct cpuinfo_x86 *c)
{
	if (mca_cfg.disabled)
		return;

	if (__mcheck_cpu_ancient_init(c))
		return;

	if (!mce_available(c))
		return;

	__mcheck_cpu_cap_init();

	if (__mcheck_cpu_apply_quirks(c) < 0) {
		mca_cfg.disabled = 1;
		return;
	}

	if (mce_gen_pool_init()) {
		mca_cfg.disabled = 1;
		pr_emerg("Couldn't allocate MCE records pool!\n");
		return;
	}

	mca_cfg.initialized = 1;

	__mcheck_cpu_init_early(c);
	__mcheck_cpu_init_generic();
	__mcheck_cpu_init_vendor(c);
	__mcheck_cpu_init_clear_banks();
	__mcheck_cpu_check_banks();
	__mcheck_cpu_setup_timer();
}

void mcheck_cpu_clear(struct cpuinfo_x86 *c)
{
	if (mca_cfg.disabled)
		return;

	if (!mce_available(c))
		return;

	/*
	__mcheck_cpu_clear_vendor(c);

}

static void __mce_disable_bank(void *arg)
{
	int bank = *((int *)arg);
	__clear_bit(bank, this_cpu_ptr(mce_poll_banks));
	cmci_disable_bank(bank);
}

void mce_disable_bank(int bank)
{
	if (bank >= this_cpu_read(mce_num_banks)) {
		pr_warn(FW_BUG
			"Ignoring request to disable invalid MCA bank %d.\n",
			bank);
		return;
	}
	set_bit(bank, mce_banks_ce_disabled);
	on_each_cpu(__mce_disable_bank, &bank, 1);
}

static int __init mcheck_enable(char *str)
{
	struct mca_config *cfg = &mca_cfg;

	if (*str == 0) {
		enable_p5_mce();
		return 1;
	}
	if (*str == '=')
		str++;
	if (!strcmp(str, "off"))
		cfg->disabled = 1;
	else if (!strcmp(str, "no_cmci"))
		cfg->cmci_disabled = true;
	else if (!strcmp(str, "no_lmce"))
		cfg->lmce_disabled = 1;
	else if (!strcmp(str, "dont_log_ce"))
		cfg->dont_log_ce = true;
	else if (!strcmp(str, "print_all"))
		cfg->print_all = true;
	else if (!strcmp(str, "ignore_ce"))
		cfg->ignore_ce = true;
	else if (!strcmp(str, "bootlog") || !strcmp(str, "nobootlog"))
		cfg->bootlog = (str[0] == 'b');
	else if (!strcmp(str, "bios_cmci_threshold"))
		cfg->bios_cmci_threshold = 1;
	else if (!strcmp(str, "recovery"))
		cfg->recovery = 1;
	else if (isdigit(str[0]))
		get_option(&str, &(cfg->monarch_timeout));
	else {
		pr_info("mce argument %s ignored. Please use /sys\n", str);
		return 0;
	}
	return 1;
}
__setup("mce", mcheck_enable);

int __init mcheck_init(void)
{
	mce_register_decode_chain(&early_nb);
	mce_register_decode_chain(&mce_uc_nb);
	mce_register_decode_chain(&mce_default_nb);

	INIT_WORK(&mce_work, mce_gen_pool_process);
	init_irq_work(&mce_irq_work, mce_irq_work_cb);

	return 0;
}


static void mce_disable_error_reporting(void)
{
	struct mce_bank *mce_banks = this_cpu_ptr(mce_banks_array);
	int i;

	for (i = 0; i < this_cpu_read(mce_num_banks); i++) {
		struct mce_bank *b = &mce_banks[i];

		if (b->init)
			wrmsrl(mca_msr_reg(i, MCA_CTL), 0);
	}
	return;
}

static void vendor_disable_error_reporting(void)
{
	/*
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL ||
	    boot_cpu_data.x86_vendor == X86_VENDOR_HYGON ||
	    boot_cpu_data.x86_vendor == X86_VENDOR_AMD ||
	    boot_cpu_data.x86_vendor == X86_VENDOR_ZHAOXIN)
		return;

	mce_disable_error_reporting();
}

static int mce_syscore_suspend(void)
{
	vendor_disable_error_reporting();
	return 0;
}

static void mce_syscore_shutdown(void)
{
	vendor_disable_error_reporting();
}

static void mce_syscore_resume(void)
{
	__mcheck_cpu_init_generic();
	__mcheck_cpu_init_vendor(raw_cpu_ptr(&cpu_info));
	__mcheck_cpu_init_clear_banks();
}

static struct syscore_ops mce_syscore_ops = {
	.suspend	= mce_syscore_suspend,
	.shutdown	= mce_syscore_shutdown,
	.resume		= mce_syscore_resume,
};


static void mce_cpu_restart(void *data)
{
	if (!mce_available(raw_cpu_ptr(&cpu_info)))
		return;
	__mcheck_cpu_init_generic();
	__mcheck_cpu_init_clear_banks();
	__mcheck_cpu_init_timer();
}

static void mce_restart(void)
{
	mce_timer_delete_all();
	on_each_cpu(mce_cpu_restart, NULL, 1);
}

static void mce_disable_cmci(void *data)
{
	if (!mce_available(raw_cpu_ptr(&cpu_info)))
		return;
	cmci_clear();
}

static void mce_enable_ce(void *all)
{
	if (!mce_available(raw_cpu_ptr(&cpu_info)))
		return;
	cmci_reenable();
	cmci_recheck();
	if (all)
		__mcheck_cpu_init_timer();
}

static struct bus_type mce_subsys = {
	.name		= "machinecheck",
	.dev_name	= "machinecheck",
};

DEFINE_PER_CPU(struct device *, mce_device);

static inline struct mce_bank_dev *attr_to_bank(struct device_attribute *attr)
{
	return container_of(attr, struct mce_bank_dev, attr);
}

static ssize_t show_bank(struct device *s, struct device_attribute *attr,
			 char *buf)
{
	u8 bank = attr_to_bank(attr)->bank;
	struct mce_bank *b;

	if (bank >= per_cpu(mce_num_banks, s->id))
		return -EINVAL;

	b = &per_cpu(mce_banks_array, s->id)[bank];

	if (!b->init)
		return -ENODEV;

	return sprintf(buf, "%llx\n", b->ctl);
}

static ssize_t set_bank(struct device *s, struct device_attribute *attr,
			const char *buf, size_t size)
{
	u8 bank = attr_to_bank(attr)->bank;
	struct mce_bank *b;
	u64 new;

	if (kstrtou64(buf, 0, &new) < 0)
		return -EINVAL;

	if (bank >= per_cpu(mce_num_banks, s->id))
		return -EINVAL;

	b = &per_cpu(mce_banks_array, s->id)[bank];

	if (!b->init)
		return -ENODEV;

	b->ctl = new;
	mce_restart();

	return size;
}

static ssize_t set_ignore_ce(struct device *s,
			     struct device_attribute *attr,
			     const char *buf, size_t size)
{
	u64 new;

	if (kstrtou64(buf, 0, &new) < 0)
		return -EINVAL;

	mutex_lock(&mce_sysfs_mutex);
	if (mca_cfg.ignore_ce ^ !!new) {
		if (new) {
			/* disable ce features */
			mce_timer_delete_all();
			on_each_cpu(mce_disable_cmci, NULL, 1);
			mca_cfg.ignore_ce = true;
		} else {
			/* enable ce features */
			mca_cfg.ignore_ce = false;
			on_each_cpu(mce_enable_ce, (void *)1, 1);
		}
	}
	mutex_unlock(&mce_sysfs_mutex);

	return size;
}

static ssize_t set_cmci_disabled(struct device *s,
				 struct device_attribute *attr,
				 const char *buf, size_t size)
{
	u64 new;

	if (kstrtou64(buf, 0, &new) < 0)
		return -EINVAL;

	mutex_lock(&mce_sysfs_mutex);
	if (mca_cfg.cmci_disabled ^ !!new) {
		if (new) {
			/* disable cmci */
			on_each_cpu(mce_disable_cmci, NULL, 1);
			mca_cfg.cmci_disabled = true;
		} else {
			/* enable cmci */
			mca_cfg.cmci_disabled = false;
			on_each_cpu(mce_enable_ce, NULL, 1);
		}
	}
	mutex_unlock(&mce_sysfs_mutex);

	return size;
}

static ssize_t store_int_with_restart(struct device *s,
				      struct device_attribute *attr,
				      const char *buf, size_t size)
{
	unsigned long old_check_interval = check_interval;
	ssize_t ret = device_store_ulong(s, attr, buf, size);

	if (check_interval == old_check_interval)
		return ret;

	mutex_lock(&mce_sysfs_mutex);
	mce_restart();
	mutex_unlock(&mce_sysfs_mutex);

	return ret;
}

static DEVICE_INT_ATTR(monarch_timeout, 0644, mca_cfg.monarch_timeout);
static DEVICE_BOOL_ATTR(dont_log_ce, 0644, mca_cfg.dont_log_ce);
static DEVICE_BOOL_ATTR(print_all, 0644, mca_cfg.print_all);

static struct dev_ext_attribute dev_attr_check_interval = {
	__ATTR(check_interval, 0644, device_show_int, store_int_with_restart),
	&check_interval
};

static struct dev_ext_attribute dev_attr_ignore_ce = {
	__ATTR(ignore_ce, 0644, device_show_bool, set_ignore_ce),
	&mca_cfg.ignore_ce
};

static struct dev_ext_attribute dev_attr_cmci_disabled = {
	__ATTR(cmci_disabled, 0644, device_show_bool, set_cmci_disabled),
	&mca_cfg.cmci_disabled
};

static struct device_attribute *mce_device_attrs[] = {
	&dev_attr_check_interval.attr,
#ifdef CONFIG_X86_MCELOG_LEGACY
	&dev_attr_trigger,
#endif
	&dev_attr_monarch_timeout.attr,
	&dev_attr_dont_log_ce.attr,
	&dev_attr_print_all.attr,
	&dev_attr_ignore_ce.attr,
	&dev_attr_cmci_disabled.attr,
	NULL
};

static cpumask_var_t mce_device_initialized;

static void mce_device_release(struct device *dev)
{
	kfree(dev);
}

static int mce_device_create(unsigned int cpu)
{
	struct device *dev;
	int err;
	int i, j;

	if (!mce_available(&boot_cpu_data))
		return -EIO;

	dev = per_cpu(mce_device, cpu);
	if (dev)
		return 0;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;
	dev->id  = cpu;
	dev->bus = &mce_subsys;
	dev->release = &mce_device_release;

	err = device_register(dev);
	if (err) {
		put_device(dev);
		return err;
	}

	for (i = 0; mce_device_attrs[i]; i++) {
		err = device_create_file(dev, mce_device_attrs[i]);
		if (err)
			goto error;
	}
	for (j = 0; j < per_cpu(mce_num_banks, cpu); j++) {
		err = device_create_file(dev, &mce_bank_devs[j].attr);
		if (err)
			goto error2;
	}
	cpumask_set_cpu(cpu, mce_device_initialized);
	per_cpu(mce_device, cpu) = dev;

	return 0;
error2:
	while (--j >= 0)
		device_remove_file(dev, &mce_bank_devs[j].attr);
error:
	while (--i >= 0)
		device_remove_file(dev, mce_device_attrs[i]);

	device_unregister(dev);

	return err;
}

static void mce_device_remove(unsigned int cpu)
{
	struct device *dev = per_cpu(mce_device, cpu);
	int i;

	if (!cpumask_test_cpu(cpu, mce_device_initialized))
		return;

	for (i = 0; mce_device_attrs[i]; i++)
		device_remove_file(dev, mce_device_attrs[i]);

	for (i = 0; i < per_cpu(mce_num_banks, cpu); i++)
		device_remove_file(dev, &mce_bank_devs[i].attr);

	device_unregister(dev);
	cpumask_clear_cpu(cpu, mce_device_initialized);
	per_cpu(mce_device, cpu) = NULL;
}

static void mce_disable_cpu(void)
{
	if (!mce_available(raw_cpu_ptr(&cpu_info)))
		return;

	if (!cpuhp_tasks_frozen)
		cmci_clear();

	vendor_disable_error_reporting();
}

static void mce_reenable_cpu(void)
{
	struct mce_bank *mce_banks = this_cpu_ptr(mce_banks_array);
	int i;

	if (!mce_available(raw_cpu_ptr(&cpu_info)))
		return;

	if (!cpuhp_tasks_frozen)
		cmci_reenable();
	for (i = 0; i < this_cpu_read(mce_num_banks); i++) {
		struct mce_bank *b = &mce_banks[i];

		if (b->init)
			wrmsrl(mca_msr_reg(i, MCA_CTL), b->ctl);
	}
}

static int mce_cpu_dead(unsigned int cpu)
{
	mce_intel_hcpu_update(cpu);

	/* intentionally ignoring frozen here */
	if (!cpuhp_tasks_frozen)
		cmci_rediscover();
	return 0;
}

static int mce_cpu_online(unsigned int cpu)
{
	struct timer_list *t = this_cpu_ptr(&mce_timer);
	int ret;

	mce_device_create(cpu);

	ret = mce_threshold_create_device(cpu);
	if (ret) {
		mce_device_remove(cpu);
		return ret;
	}
	mce_reenable_cpu();
	mce_start_timer(t);
	return 0;
}

static int mce_cpu_pre_down(unsigned int cpu)
{
	struct timer_list *t = this_cpu_ptr(&mce_timer);

	mce_disable_cpu();
	del_timer_sync(t);
	mce_threshold_remove_device(cpu);
	mce_device_remove(cpu);
	return 0;
}

static __init void mce_init_banks(void)
{
	int i;

	for (i = 0; i < MAX_NR_BANKS; i++) {
		struct mce_bank_dev *b = &mce_bank_devs[i];
		struct device_attribute *a = &b->attr;

		b->bank = i;

		sysfs_attr_init(&a->attr);
		a->attr.name	= b->attrname;
		snprintf(b->attrname, ATTR_LEN, "bank%d", i);

		a->attr.mode	= 0644;
		a->show		= show_bank;
		a->store	= set_bank;
	}
}

static __init int mcheck_init_device(void)
{
	int err;

	/*
	MAYBE_BUILD_BUG_ON(__VIRTUAL_MASK_SHIFT >= 63);

	if (!mce_available(&boot_cpu_data)) {
		err = -EIO;
		goto err_out;
	}

	if (!zalloc_cpumask_var(&mce_device_initialized, GFP_KERNEL)) {
		err = -ENOMEM;
		goto err_out;
	}

	mce_init_banks();

	err = subsys_system_register(&mce_subsys, NULL);
	if (err)
		goto err_out_mem;

	err = cpuhp_setup_state(CPUHP_X86_MCE_DEAD, "x86/mce:dead", NULL,
				mce_cpu_dead);
	if (err)
		goto err_out_mem;

	/*
	err = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/mce:online",
				mce_cpu_online, mce_cpu_pre_down);
	if (err < 0)
		goto err_out_online;

	register_syscore_ops(&mce_syscore_ops);

	return 0;

err_out_online:
	cpuhp_remove_state(CPUHP_X86_MCE_DEAD);

err_out_mem:
	free_cpumask_var(mce_device_initialized);

err_out:
	pr_err("Unable to init MCE device (rc: %d)\n", err);

	return err;
}
device_initcall_sync(mcheck_init_device);

static int __init mcheck_disable(char *str)
{
	mca_cfg.disabled = 1;
	return 1;
}
__setup("nomce", mcheck_disable);

#ifdef CONFIG_DEBUG_FS
struct dentry *mce_get_debugfs_dir(void)
{
	static struct dentry *dmce;

	if (!dmce)
		dmce = debugfs_create_dir("mce", NULL);

	return dmce;
}

static void mce_reset(void)
{
	atomic_set(&mce_fake_panicked, 0);
	atomic_set(&mce_executing, 0);
	atomic_set(&mce_callin, 0);
	atomic_set(&global_nwo, 0);
	cpumask_setall(&mce_missing_cpus);
}

static int fake_panic_get(void *data, u64 *val)
{
	return 0;
}

static int fake_panic_set(void *data, u64 val)
{
	mce_reset();
	fake_panic = val;
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(fake_panic_fops, fake_panic_get, fake_panic_set,
			 "%llu\n");

static void __init mcheck_debugfs_init(void)
{
	struct dentry *dmce;

	dmce = mce_get_debugfs_dir();
	debugfs_create_file_unsafe("fake_panic", 0444, dmce, NULL,
				   &fake_panic_fops);
}
#else
static void __init mcheck_debugfs_init(void) { }
#endif

static int __init mcheck_late_init(void)
{
	if (mca_cfg.recovery)
		enable_copy_mc_fragile();

	mcheck_debugfs_init();

	/*
	mce_schedule_work();

	return 0;
}
late_initcall(mcheck_late_init);
