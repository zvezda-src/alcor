
#include <linux/debug_locks.h>
#include <linux/sched/debug.h>
#include <linux/interrupt.h>
#include <linux/kgdb.h>
#include <linux/kmsg_dump.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/vt_kern.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/ftrace.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/kexec.h>
#include <linux/panic_notifier.h>
#include <linux/sched.h>
#include <linux/sysrq.h>
#include <linux/init.h>
#include <linux/nmi.h>
#include <linux/console.h>
#include <linux/bug.h>
#include <linux/ratelimit.h>
#include <linux/debugfs.h>
#include <trace/events/error_report.h>
#include <asm/sections.h>

#define PANIC_TIMER_STEP 100
#define PANIC_BLINK_SPD 18

#ifdef CONFIG_SMP
static unsigned int __read_mostly sysctl_oops_all_cpu_backtrace;
#else
#define sysctl_oops_all_cpu_backtrace 0
#endif /* CONFIG_SMP */

int panic_on_oops = CONFIG_PANIC_ON_OOPS_VALUE;
static unsigned long tainted_mask =
	IS_ENABLED(CONFIG_RANDSTRUCT) ? (1 << TAINT_RANDSTRUCT) : 0;
static int pause_on_oops;
static int pause_on_oops_flag;
static DEFINE_SPINLOCK(pause_on_oops_lock);
bool crash_kexec_post_notifiers;
int panic_on_warn __read_mostly;
unsigned long panic_on_taint;
bool panic_on_taint_nousertaint = false;

int panic_timeout = CONFIG_PANIC_TIMEOUT;
EXPORT_SYMBOL_GPL(panic_timeout);

#define PANIC_PRINT_TASK_INFO		0x00000001
#define PANIC_PRINT_MEM_INFO		0x00000002
#define PANIC_PRINT_TIMER_INFO		0x00000004
#define PANIC_PRINT_LOCK_INFO		0x00000008
#define PANIC_PRINT_FTRACE_INFO		0x00000010
#define PANIC_PRINT_ALL_PRINTK_MSG	0x00000020
#define PANIC_PRINT_ALL_CPU_BT		0x00000040
unsigned long panic_print;

ATOMIC_NOTIFIER_HEAD(panic_notifier_list);

EXPORT_SYMBOL(panic_notifier_list);

#if defined(CONFIG_SMP) && defined(CONFIG_SYSCTL)
static struct ctl_table kern_panic_table[] = {
	{
		.procname       = "oops_all_cpu_backtrace",
		.data           = &sysctl_oops_all_cpu_backtrace,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{ }
};

static __init int kernel_panic_sysctls_init(void)
{
	register_sysctl_init("kernel", kern_panic_table);
	return 0;
}
late_initcall(kernel_panic_sysctls_init);
#endif

static long no_blink(int state)
{
	return 0;
}

long (*panic_blink)(int state);
EXPORT_SYMBOL(panic_blink);

void __weak panic_smp_self_stop(void)
{
	while (1)
		cpu_relax();
}

void __weak nmi_panic_self_stop(struct pt_regs *regs)
{
	panic_smp_self_stop();
}

void __weak crash_smp_send_stop(void)
{
	static int cpus_stopped;

	/*
	if (cpus_stopped)
		return;

	/*
	smp_send_stop();
	cpus_stopped = 1;
}

atomic_t panic_cpu = ATOMIC_INIT(PANIC_CPU_INVALID);

void nmi_panic(struct pt_regs *regs, const char *msg)
{
	int old_cpu, cpu;

	cpu = raw_smp_processor_id();
	old_cpu = atomic_cmpxchg(&panic_cpu, PANIC_CPU_INVALID, cpu);

	if (old_cpu == PANIC_CPU_INVALID)
		panic("%s", msg);
	else if (old_cpu != cpu)
		nmi_panic_self_stop(regs);
}
EXPORT_SYMBOL(nmi_panic);

static void panic_print_sys_info(bool console_flush)
{
	if (console_flush) {
		if (panic_print & PANIC_PRINT_ALL_PRINTK_MSG)
			console_flush_on_panic(CONSOLE_REPLAY_ALL);
		return;
	}

	if (panic_print & PANIC_PRINT_ALL_CPU_BT)
		trigger_all_cpu_backtrace();

	if (panic_print & PANIC_PRINT_TASK_INFO)
		show_state();

	if (panic_print & PANIC_PRINT_MEM_INFO)
		show_mem(0, NULL);

	if (panic_print & PANIC_PRINT_TIMER_INFO)
		sysrq_timer_list_show();

	if (panic_print & PANIC_PRINT_LOCK_INFO)
		debug_show_all_locks();

	if (panic_print & PANIC_PRINT_FTRACE_INFO)
		ftrace_dump(DUMP_ALL);
}

void panic(const char *fmt, ...)
{
	static char buf[1024];
	va_list args;
	long i, i_next = 0, len;
	int state = 0;
	int old_cpu, this_cpu;
	bool _crash_kexec_post_notifiers = crash_kexec_post_notifiers;

	if (panic_on_warn) {
		/*
		panic_on_warn = 0;
	}

	/*
	local_irq_disable();
	preempt_disable_notrace();

	/*
	this_cpu = raw_smp_processor_id();
	old_cpu  = atomic_cmpxchg(&panic_cpu, PANIC_CPU_INVALID, this_cpu);

	if (old_cpu != PANIC_CPU_INVALID && old_cpu != this_cpu)
		panic_smp_self_stop();

	console_verbose();
	bust_spinlocks(1);
	va_start(args, fmt);
	len = vscnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (len && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	pr_emerg("Kernel panic - not syncing: %s\n", buf);
#ifdef CONFIG_DEBUG_BUGVERBOSE
	/*
	if (!test_taint(TAINT_DIE) && oops_in_progress <= 1)
		dump_stack();
#endif

	/*
	kgdb_panic(buf);

	/*
	if (!_crash_kexec_post_notifiers) {
		__crash_kexec(NULL);

		/*
		smp_send_stop();
	} else {
		/*
		crash_smp_send_stop();
	}

	/*
	atomic_notifier_call_chain(&panic_notifier_list, 0, buf);

	panic_print_sys_info(false);

	kmsg_dump(KMSG_DUMP_PANIC);

	/*
	if (_crash_kexec_post_notifiers)
		__crash_kexec(NULL);

#ifdef CONFIG_VT
	unblank_screen();
#endif
	console_unblank();

	/*
	debug_locks_off();
	console_flush_on_panic(CONSOLE_FLUSH_PENDING);

	panic_print_sys_info(true);

	if (!panic_blink)
		panic_blink = no_blink;

	if (panic_timeout > 0) {
		/*
		pr_emerg("Rebooting in %d seconds..\n", panic_timeout);

		for (i = 0; i < panic_timeout * 1000; i += PANIC_TIMER_STEP) {
			touch_nmi_watchdog();
			if (i >= i_next) {
				i += panic_blink(state ^= 1);
				i_next = i + 3600 / PANIC_BLINK_SPD;
			}
			mdelay(PANIC_TIMER_STEP);
		}
	}
	if (panic_timeout != 0) {
		/*
		if (panic_reboot_mode != REBOOT_UNDEFINED)
			reboot_mode = panic_reboot_mode;
		emergency_restart();
	}
#ifdef __sparc__
	{
		extern int stop_a_enabled;
		/* Make sure the user can actually press Stop-A (L1-A) */
		stop_a_enabled = 1;
		pr_emerg("Press Stop-A (L1-A) from sun keyboard or send break\n"
			 "twice on console to return to the boot prom\n");
	}
#endif
#if defined(CONFIG_S390)
	disabled_wait();
#endif
	pr_emerg("---[ end Kernel panic - not syncing: %s ]---\n", buf);

	/* Do not scroll important messages printed above */
	suppress_printk = 1;
	local_irq_enable();
	for (i = 0; ; i += PANIC_TIMER_STEP) {
		touch_softlockup_watchdog();
		if (i >= i_next) {
			i += panic_blink(state ^= 1);
			i_next = i + 3600 / PANIC_BLINK_SPD;
		}
		mdelay(PANIC_TIMER_STEP);
	}
}

EXPORT_SYMBOL(panic);

const struct taint_flag taint_flags[TAINT_FLAGS_COUNT] = {
	[ TAINT_PROPRIETARY_MODULE ]	= { 'P', 'G', true },
	[ TAINT_FORCED_MODULE ]		= { 'F', ' ', true },
	[ TAINT_CPU_OUT_OF_SPEC ]	= { 'S', ' ', false },
	[ TAINT_FORCED_RMMOD ]		= { 'R', ' ', false },
	[ TAINT_MACHINE_CHECK ]		= { 'M', ' ', false },
	[ TAINT_BAD_PAGE ]		= { 'B', ' ', false },
	[ TAINT_USER ]			= { 'U', ' ', false },
	[ TAINT_DIE ]			= { 'D', ' ', false },
	[ TAINT_OVERRIDDEN_ACPI_TABLE ]	= { 'A', ' ', false },
	[ TAINT_WARN ]			= { 'W', ' ', false },
	[ TAINT_CRAP ]			= { 'C', ' ', true },
	[ TAINT_FIRMWARE_WORKAROUND ]	= { 'I', ' ', false },
	[ TAINT_OOT_MODULE ]		= { 'O', ' ', true },
	[ TAINT_UNSIGNED_MODULE ]	= { 'E', ' ', true },
	[ TAINT_SOFTLOCKUP ]		= { 'L', ' ', false },
	[ TAINT_LIVEPATCH ]		= { 'K', ' ', true },
	[ TAINT_AUX ]			= { 'X', ' ', true },
	[ TAINT_RANDSTRUCT ]		= { 'T', ' ', true },
	[ TAINT_TEST ]			= { 'N', ' ', true },
};

const char *print_tainted(void)
{
	static char buf[TAINT_FLAGS_COUNT + sizeof("Tainted: ")];

	BUILD_BUG_ON(ARRAY_SIZE(taint_flags) != TAINT_FLAGS_COUNT);

	if (tainted_mask) {
		char *s;
		int i;

		s = buf + sprintf(buf, "Tainted: ");
		for (i = 0; i < TAINT_FLAGS_COUNT; i++) {
			const struct taint_flag *t = &taint_flags[i];
			*s++ = test_bit(i, &tainted_mask) ?
					t->c_true : t->c_false;
		}
		*s = 0;
	} else
		snprintf(buf, sizeof(buf), "Not tainted");

	return buf;
}

int test_taint(unsigned flag)
{
	return test_bit(flag, &tainted_mask);
}
EXPORT_SYMBOL(test_taint);

unsigned long get_taint(void)
{
	return tainted_mask;
}

void add_taint(unsigned flag, enum lockdep_ok lockdep_ok)
{
	if (lockdep_ok == LOCKDEP_NOW_UNRELIABLE && __debug_locks_off())
		pr_warn("Disabling lock debugging due to kernel taint\n");

	set_bit(flag, &tainted_mask);

	if (tainted_mask & panic_on_taint) {
		panic_on_taint = 0;
		panic("panic_on_taint set ...");
	}
}
EXPORT_SYMBOL(add_taint);

static void spin_msec(int msecs)
{
	int i;

	for (i = 0; i < msecs; i++) {
		touch_nmi_watchdog();
		mdelay(1);
	}
}

static void do_oops_enter_exit(void)
{
	unsigned long flags;
	static int spin_counter;

	if (!pause_on_oops)
		return;

	spin_lock_irqsave(&pause_on_oops_lock, flags);
	if (pause_on_oops_flag == 0) {
		/* This CPU may now print the oops message */
		pause_on_oops_flag = 1;
	} else {
		/* We need to stall this CPU */
		if (!spin_counter) {
			/* This CPU gets to do the counting */
			spin_counter = pause_on_oops;
			do {
				spin_unlock(&pause_on_oops_lock);
				spin_msec(MSEC_PER_SEC);
				spin_lock(&pause_on_oops_lock);
			} while (--spin_counter);
			pause_on_oops_flag = 0;
		} else {
			/* This CPU waits for a different one */
			while (spin_counter) {
				spin_unlock(&pause_on_oops_lock);
				spin_msec(1);
				spin_lock(&pause_on_oops_lock);
			}
		}
	}
	spin_unlock_irqrestore(&pause_on_oops_lock, flags);
}

bool oops_may_print(void)
{
	return pause_on_oops_flag == 0;
}

void oops_enter(void)
{
	tracing_off();
	/* can't trust the integrity of the kernel anymore: */
	debug_locks_off();
	do_oops_enter_exit();

	if (sysctl_oops_all_cpu_backtrace)
		trigger_all_cpu_backtrace();
}

static void print_oops_end_marker(void)
{
	pr_warn("---[ end trace %016llx ]---\n", 0ULL);
}

void oops_exit(void)
{
	do_oops_enter_exit();
	print_oops_end_marker();
	kmsg_dump(KMSG_DUMP_OOPS);
}

struct warn_args {
	const char *fmt;
	va_list args;
};

void __warn(const char *file, int line, void *caller, unsigned taint,
	    struct pt_regs *regs, struct warn_args *args)
{
	disable_trace_on_warning();

	if (file)
		pr_warn("WARNING: CPU: %d PID: %d at %s:%d %pS\n",
			raw_smp_processor_id(), current->pid, file, line,
			caller);
	else
		pr_warn("WARNING: CPU: %d PID: %d at %pS\n",
			raw_smp_processor_id(), current->pid, caller);

	if (args)
		vprintk(args->fmt, args->args);

	print_modules();

	if (regs)
		show_regs(regs);

	if (panic_on_warn)
		panic("panic_on_warn set ...\n");

	if (!regs)
		dump_stack();

	print_irqtrace_events(current);

	print_oops_end_marker();
	trace_error_report_end(ERROR_DETECTOR_WARN, (unsigned long)caller);

	/* Just a warning, don't kill lockdep. */
	add_taint(taint, LOCKDEP_STILL_OK);
}

#ifndef __WARN_FLAGS
void warn_slowpath_fmt(const char *file, int line, unsigned taint,
		       const char *fmt, ...)
{
	struct warn_args args;

	pr_warn(CUT_HERE);

	if (!fmt) {
		__warn(file, line, __builtin_return_address(0), taint,
		       NULL, NULL);
		return;
	}

	args.fmt = fmt;
	va_start(args.args, fmt);
	__warn(file, line, __builtin_return_address(0), taint, NULL, &args);
	va_end(args.args);
}
EXPORT_SYMBOL(warn_slowpath_fmt);
#else
void __warn_printk(const char *fmt, ...)
{
	va_list args;

	pr_warn(CUT_HERE);

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}
EXPORT_SYMBOL(__warn_printk);
#endif

#ifdef CONFIG_BUG


static int clear_warn_once_set(void *data, u64 val)
{
	generic_bug_clear_once();
	memset(__start_once, 0, __end_once - __start_once);
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(clear_warn_once_fops, NULL, clear_warn_once_set,
			 "%lld\n");

static __init int register_warn_debugfs(void)
{
	/* Don't care about failure */
	debugfs_create_file_unsafe("clear_warn_once", 0200, NULL, NULL,
				   &clear_warn_once_fops);
	return 0;
}

device_initcall(register_warn_debugfs);
#endif

#ifdef CONFIG_STACKPROTECTOR

__visible noinstr void __stack_chk_fail(void)
{
	instrumentation_begin();
	panic("stack-protector: Kernel stack is corrupted in: %pB",
		__builtin_return_address(0));
	instrumentation_end();
}
EXPORT_SYMBOL(__stack_chk_fail);

#endif

core_param(panic, panic_timeout, int, 0644);
core_param(panic_print, panic_print, ulong, 0644);
core_param(pause_on_oops, pause_on_oops, int, 0644);
core_param(panic_on_warn, panic_on_warn, int, 0644);
core_param(crash_kexec_post_notifiers, crash_kexec_post_notifiers, bool, 0644);

static int __init oops_setup(char *s)
{
	if (!s)
		return -EINVAL;
	if (!strcmp(s, "panic"))
		panic_on_oops = 1;
	return 0;
}
early_param("oops", oops_setup);

static int __init panic_on_taint_setup(char *s)
{
	char *taint_str;

	if (!s)
		return -EINVAL;

	taint_str = strsep(&s, ",");
	if (kstrtoul(taint_str, 16, &panic_on_taint))
		return -EINVAL;

	/* make sure panic_on_taint doesn't hold out-of-range TAINT flags */
	panic_on_taint &= TAINT_FLAGS_MAX;

	if (!panic_on_taint)
		return -EINVAL;

	if (s && !strcmp(s, "nousertaint"))
		panic_on_taint_nousertaint = true;

	pr_info("panic_on_taint: bitmask=0x%lx nousertaint_mode=%sabled\n",
		panic_on_taint, panic_on_taint_nousertaint ? "en" : "dis");

	return 0;
}
early_param("panic_on_taint", panic_on_taint_setup);
