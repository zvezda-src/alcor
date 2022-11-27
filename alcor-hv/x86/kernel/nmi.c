
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/sched/debug.h>
#include <linux/nmi.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/hardirq.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/atomic.h>
#include <linux/sched/clock.h>

#include <asm/cpu_entry_area.h>
#include <asm/traps.h>
#include <asm/mach_traps.h>
#include <asm/nmi.h>
#include <asm/x86_init.h>
#include <asm/reboot.h>
#include <asm/cache.h>
#include <asm/nospec-branch.h>
#include <asm/sev.h>

#define CREATE_TRACE_POINTS
#include <trace/events/nmi.h>

struct nmi_desc {
	raw_spinlock_t lock;
	struct list_head head;
};

static struct nmi_desc nmi_desc[NMI_MAX] = 
{
	{
		.lock = __RAW_SPIN_LOCK_UNLOCKED(&nmi_desc[0].lock),
		.head = LIST_HEAD_INIT(nmi_desc[0].head),
	},
	{
		.lock = __RAW_SPIN_LOCK_UNLOCKED(&nmi_desc[1].lock),
		.head = LIST_HEAD_INIT(nmi_desc[1].head),
	},
	{
		.lock = __RAW_SPIN_LOCK_UNLOCKED(&nmi_desc[2].lock),
		.head = LIST_HEAD_INIT(nmi_desc[2].head),
	},
	{
		.lock = __RAW_SPIN_LOCK_UNLOCKED(&nmi_desc[3].lock),
		.head = LIST_HEAD_INIT(nmi_desc[3].head),
	},

};

struct nmi_stats {
	unsigned int normal;
	unsigned int unknown;
	unsigned int external;
	unsigned int swallow;
};

static DEFINE_PER_CPU(struct nmi_stats, nmi_stats);

static int ignore_nmis __read_mostly;

int unknown_nmi_panic;
static DEFINE_RAW_SPINLOCK(nmi_reason_lock);

static int __init setup_unknown_nmi_panic(char *str)
{
	unknown_nmi_panic = 1;
	return 1;
}
__setup("unknown_nmi_panic", setup_unknown_nmi_panic);

#define nmi_to_desc(type) (&nmi_desc[type])

static u64 nmi_longest_ns = 1 * NSEC_PER_MSEC;

static int __init nmi_warning_debugfs(void)
{
	debugfs_create_u64("nmi_longest_ns", 0644,
			arch_debugfs_dir, &nmi_longest_ns);
	return 0;
}
fs_initcall(nmi_warning_debugfs);

static void nmi_check_duration(struct nmiaction *action, u64 duration)
{
	int remainder_ns, decimal_msecs;

	if (duration < nmi_longest_ns || duration < action->max_duration)
		return;

	action->max_duration = duration;

	remainder_ns = do_div(duration, (1000 * 1000));
	decimal_msecs = remainder_ns / 1000;

	printk_ratelimited(KERN_INFO
		"INFO: NMI handler (%ps) took too long to run: %lld.%03d msecs\n",
		action->handler, duration, decimal_msecs);
}

static int nmi_handle(unsigned int type, struct pt_regs *regs)
{
	struct nmi_desc *desc = nmi_to_desc(type);
	struct nmiaction *a;
	int handled=0;

	rcu_read_lock();

	/*
	list_for_each_entry_rcu(a, &desc->head, list) {
		int thishandled;
		u64 delta;

		delta = sched_clock();
		thishandled = a->handler(type, regs);
		handled += thishandled;
		delta = sched_clock() - delta;
		trace_nmi_handler(a->handler, (int)delta, thishandled);

		nmi_check_duration(a, delta);
	}

	rcu_read_unlock();

	/* return total number of NMI events handled */
	return handled;
}
NOKPROBE_SYMBOL(nmi_handle);

int __register_nmi_handler(unsigned int type, struct nmiaction *action)
{
	struct nmi_desc *desc = nmi_to_desc(type);
	unsigned long flags;

	if (WARN_ON_ONCE(!action->handler || !list_empty(&action->list)))
		return -EINVAL;

	raw_spin_lock_irqsave(&desc->lock, flags);

	/*
	WARN_ON_ONCE(type == NMI_SERR && !list_empty(&desc->head));
	WARN_ON_ONCE(type == NMI_IO_CHECK && !list_empty(&desc->head));

	/*
	if (action->flags & NMI_FLAG_FIRST)
		list_add_rcu(&action->list, &desc->head);
	else
		list_add_tail_rcu(&action->list, &desc->head);

	raw_spin_unlock_irqrestore(&desc->lock, flags);
	return 0;
}
EXPORT_SYMBOL(__register_nmi_handler);

void unregister_nmi_handler(unsigned int type, const char *name)
{
	struct nmi_desc *desc = nmi_to_desc(type);
	struct nmiaction *n, *found = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&desc->lock, flags);

	list_for_each_entry_rcu(n, &desc->head, list) {
		/*
		if (!strcmp(n->name, name)) {
			WARN(in_nmi(),
				"Trying to free NMI (%s) from NMI context!\n", n->name);
			list_del_rcu(&n->list);
			found = n;
			break;
		}
	}

	raw_spin_unlock_irqrestore(&desc->lock, flags);
	if (found) {
		synchronize_rcu();
		INIT_LIST_HEAD(&found->list);
	}
}
EXPORT_SYMBOL_GPL(unregister_nmi_handler);

static void
pci_serr_error(unsigned char reason, struct pt_regs *regs)
{
	/* check to see if anyone registered against these types of errors */
	if (nmi_handle(NMI_SERR, regs))
		return;

	pr_emerg("NMI: PCI system error (SERR) for reason %02x on CPU %d.\n",
		 reason, smp_processor_id());

	if (panic_on_unrecovered_nmi)
		nmi_panic(regs, "NMI: Not continuing");

	pr_emerg("Dazed and confused, but trying to continue\n");

	/* Clear and disable the PCI SERR error line. */
	reason = (reason & NMI_REASON_CLEAR_MASK) | NMI_REASON_CLEAR_SERR;
	outb(reason, NMI_REASON_PORT);
}
NOKPROBE_SYMBOL(pci_serr_error);

static void
io_check_error(unsigned char reason, struct pt_regs *regs)
{
	unsigned long i;

	/* check to see if anyone registered against these types of errors */
	if (nmi_handle(NMI_IO_CHECK, regs))
		return;

	pr_emerg(
	"NMI: IOCK error (debug interrupt?) for reason %02x on CPU %d.\n",
		 reason, smp_processor_id());
	show_regs(regs);

	if (panic_on_io_nmi) {
		nmi_panic(regs, "NMI IOCK error: Not continuing");

		/*
		return;
	}

	/* Re-enable the IOCK line, wait for a few seconds */
	reason = (reason & NMI_REASON_CLEAR_MASK) | NMI_REASON_CLEAR_IOCHK;
	outb(reason, NMI_REASON_PORT);

	i = 20000;
	while (--i) {
		touch_nmi_watchdog();
		udelay(100);
	}

	reason &= ~NMI_REASON_CLEAR_IOCHK;
	outb(reason, NMI_REASON_PORT);
}
NOKPROBE_SYMBOL(io_check_error);

static void
unknown_nmi_error(unsigned char reason, struct pt_regs *regs)
{
	int handled;

	/*
	handled = nmi_handle(NMI_UNKNOWN, regs);
	if (handled) {
		__this_cpu_add(nmi_stats.unknown, handled);
		return;
	}

	__this_cpu_add(nmi_stats.unknown, 1);

	pr_emerg("Uhhuh. NMI received for unknown reason %02x on CPU %d.\n",
		 reason, smp_processor_id());

	if (unknown_nmi_panic || panic_on_unrecovered_nmi)
		nmi_panic(regs, "NMI: Not continuing");

	pr_emerg("Dazed and confused, but trying to continue\n");
}
NOKPROBE_SYMBOL(unknown_nmi_error);

static DEFINE_PER_CPU(bool, swallow_nmi);
static DEFINE_PER_CPU(unsigned long, last_nmi_rip);

static noinstr void default_do_nmi(struct pt_regs *regs)
{
	unsigned char reason = 0;
	int handled;
	bool b2b = false;

	/*

	/*
	if (regs->ip == __this_cpu_read(last_nmi_rip))
		b2b = true;
	else
		__this_cpu_write(swallow_nmi, false);

	__this_cpu_write(last_nmi_rip, regs->ip);

	instrumentation_begin();

	handled = nmi_handle(NMI_LOCAL, regs);
	__this_cpu_add(nmi_stats.normal, handled);
	if (handled) {
		/*
		if (handled > 1)
			__this_cpu_write(swallow_nmi, true);
		goto out;
	}

	/*
	while (!raw_spin_trylock(&nmi_reason_lock)) {
		run_crash_ipi_callback(regs);
		cpu_relax();
	}

	reason = x86_platform.get_nmi_reason();

	if (reason & NMI_REASON_MASK) {
		if (reason & NMI_REASON_SERR)
			pci_serr_error(reason, regs);
		else if (reason & NMI_REASON_IOCHK)
			io_check_error(reason, regs);
#ifdef CONFIG_X86_32
		/*
		reassert_nmi();
#endif
		__this_cpu_add(nmi_stats.external, 1);
		raw_spin_unlock(&nmi_reason_lock);
		goto out;
	}
	raw_spin_unlock(&nmi_reason_lock);

	/*
	if (b2b && __this_cpu_read(swallow_nmi))
		__this_cpu_add(nmi_stats.swallow, 1);
	else
		unknown_nmi_error(reason, regs);

out:
	instrumentation_end();
}

enum nmi_states {
	NMI_NOT_RUNNING = 0,
	NMI_EXECUTING,
	NMI_LATCHED,
};
static DEFINE_PER_CPU(enum nmi_states, nmi_state);
static DEFINE_PER_CPU(unsigned long, nmi_cr2);
static DEFINE_PER_CPU(unsigned long, nmi_dr7);

DEFINE_IDTENTRY_RAW(exc_nmi)
{
	irqentry_state_t irq_state;

	/*
	sev_es_nmi_complete();

	if (IS_ENABLED(CONFIG_SMP) && arch_cpu_is_offline(smp_processor_id()))
		return;

	if (this_cpu_read(nmi_state) != NMI_NOT_RUNNING) {
		this_cpu_write(nmi_state, NMI_LATCHED);
		return;
	}
	this_cpu_write(nmi_state, NMI_EXECUTING);
	this_cpu_write(nmi_cr2, read_cr2());
nmi_restart:

	/*
	sev_es_ist_enter(regs);

	this_cpu_write(nmi_dr7, local_db_save());

	irq_state = irqentry_nmi_enter(regs);

	inc_irq_stat(__nmi_count);

	if (!ignore_nmis)
		default_do_nmi(regs);

	irqentry_nmi_exit(regs, irq_state);

	local_db_restore(this_cpu_read(nmi_dr7));

	sev_es_ist_exit();

	if (unlikely(this_cpu_read(nmi_cr2) != read_cr2()))
		write_cr2(this_cpu_read(nmi_cr2));
	if (this_cpu_dec_return(nmi_state))
		goto nmi_restart;

	if (user_mode(regs))
		mds_user_clear_cpu_buffers();
}

#if defined(CONFIG_X86_64) && IS_ENABLED(CONFIG_KVM_INTEL)
DEFINE_IDTENTRY_RAW(exc_nmi_noist)
{
	exc_nmi(regs);
}
#endif
#if IS_MODULE(CONFIG_KVM_INTEL)
EXPORT_SYMBOL_GPL(asm_exc_nmi_noist);
#endif

void stop_nmi(void)
{
	ignore_nmis++;
}

void restart_nmi(void)
{
	ignore_nmis--;
}

void local_touch_nmi(void)
{
	__this_cpu_write(last_nmi_rip, 0);
}
EXPORT_SYMBOL_GPL(local_touch_nmi);
