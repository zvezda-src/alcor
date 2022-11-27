
#include <linux/debug_locks.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>

#include "kcsan.h"
#include "encoding.h"

#define NUM_STACK_ENTRIES 64

struct access_info {
	const volatile void	*ptr;
	size_t			size;
	int			access_type;
	int			task_pid;
	int			cpu_id;
	unsigned long		ip;
};

struct other_info {
	struct access_info	ai;
	unsigned long		stack_entries[NUM_STACK_ENTRIES];
	int			num_stack_entries;

	/*
	struct task_struct	*task;
};

static struct other_info other_infos[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];

struct report_time {
	/*
	unsigned long time;

	/*
	unsigned long frame1;
	unsigned long frame2;
};

#define REPORT_TIMES_MAX (PAGE_SIZE / sizeof(struct report_time))
#define REPORT_TIMES_SIZE                                                      \
	(CONFIG_KCSAN_REPORT_ONCE_IN_MS > REPORT_TIMES_MAX ?                   \
		 REPORT_TIMES_MAX :                                            \
		 CONFIG_KCSAN_REPORT_ONCE_IN_MS)
static struct report_time report_times[REPORT_TIMES_SIZE];

static DEFINE_RAW_SPINLOCK(report_lock);

static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
{
	struct report_time *use_entry = &report_times[0];
	unsigned long invalid_before;
	int i;

	BUILD_BUG_ON(CONFIG_KCSAN_REPORT_ONCE_IN_MS != 0 && REPORT_TIMES_SIZE == 0);

	if (CONFIG_KCSAN_REPORT_ONCE_IN_MS == 0)
		return false;

	invalid_before = jiffies - msecs_to_jiffies(CONFIG_KCSAN_REPORT_ONCE_IN_MS);

	/* Check if a matching race report exists. */
	for (i = 0; i < REPORT_TIMES_SIZE; ++i) {
		struct report_time *rt = &report_times[i];

		/*
		if (time_before(rt->time, use_entry->time))
			use_entry = rt;

		/*
		if (rt->time == 0)
			break;

		/* Check if entry expired. */
		if (time_before(rt->time, invalid_before))
			continue; /* before KCSAN_REPORT_ONCE_IN_MS ago */

		/* Reported recently, check if race matches. */
		if ((rt->frame1 == frame1 && rt->frame2 == frame2) ||
		    (rt->frame1 == frame2 && rt->frame2 == frame1))
			return true;
	}

	use_entry->time = jiffies;
	use_entry->frame1 = frame1;
	use_entry->frame2 = frame2;
	return false;
}

static bool
skip_report(enum kcsan_value_change value_change, unsigned long top_frame)
{
	/* Should never get here if value_change==FALSE. */
	WARN_ON_ONCE(value_change == KCSAN_VALUE_CHANGE_FALSE);

	/*
	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) &&
	    value_change == KCSAN_VALUE_CHANGE_MAYBE) {
		/*
		char buf[64];
		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)top_frame);

		if (!strnstr(buf, "rcu_", len) &&
		    !strnstr(buf, "_rcu", len) &&
		    !strnstr(buf, "_srcu", len))
			return true;
	}

	return kcsan_skip_report_debugfs(top_frame);
}

static const char *get_access_type(int type)
{
	if (type & KCSAN_ACCESS_ASSERT) {
		if (type & KCSAN_ACCESS_SCOPED) {
			if (type & KCSAN_ACCESS_WRITE)
				return "assert no accesses (reordered)";
			else
				return "assert no writes (reordered)";
		} else {
			if (type & KCSAN_ACCESS_WRITE)
				return "assert no accesses";
			else
				return "assert no writes";
		}
	}

	switch (type) {
	case 0:
		return "read";
	case KCSAN_ACCESS_ATOMIC:
		return "read (marked)";
	case KCSAN_ACCESS_WRITE:
		return "write";
	case KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
		return "write (marked)";
	case KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE:
		return "read-write";
	case KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
		return "read-write (marked)";
	case KCSAN_ACCESS_SCOPED:
		return "read (reordered)";
	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_ATOMIC:
		return "read (marked, reordered)";
	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE:
		return "write (reordered)";
	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
		return "write (marked, reordered)";
	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE:
		return "read-write (reordered)";
	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
		return "read-write (marked, reordered)";
	default:
		BUG();
	}
}

static const char *get_bug_type(int type)
{
	return (type & KCSAN_ACCESS_ASSERT) != 0 ? "assert: race" : "data-race";
}

static const char *get_thread_desc(int task_id)
{
	if (task_id != -1) {
		static char buf[32]; /* safe: protected by report_lock */

		snprintf(buf, sizeof(buf), "task %i", task_id);
		return buf;
	}
	return "interrupt";
}

static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
{
	char buf[64];
	char *cur;
	int len, skip;

	for (skip = 0; skip < num_entries; ++skip) {
		len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);

		/* Never show tsan_* or {read,write}_once_size. */
		if (strnstr(buf, "tsan_", len) ||
		    strnstr(buf, "_once_size", len))
			continue;

		cur = strnstr(buf, "kcsan_", len);
		if (cur) {
			cur += strlen("kcsan_");
			if (!str_has_prefix(cur, "test"))
				continue; /* KCSAN runtime function. */
			/* KCSAN related test. */
		}

		/*
		break;
	}

	return skip;
}

static int
replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned long ip,
		    unsigned long *replaced)
{
	unsigned long symbolsize, offset;
	unsigned long target_func;
	int skip;

	if (kallsyms_lookup_size_offset(ip, &symbolsize, &offset))
		target_func = ip - offset;
	else
		goto fallback;

	for (skip = 0; skip < num_entries; ++skip) {
		unsigned long func = stack_entries[skip];

		if (!kallsyms_lookup_size_offset(func, &symbolsize, &offset))
			goto fallback;
		func -= offset;

		if (func == target_func) {
			*replaced = stack_entries[skip];
			stack_entries[skip] = ip;
			return skip;
		}
	}

fallback:
	/* Should not happen; the resulting stack trace is likely misleading. */
	WARN_ONCE(1, "Cannot find frame for %pS in stack trace", (void *)ip);
	return get_stack_skipnr(stack_entries, num_entries);
}

static int
sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip,
		       unsigned long *replaced)
{
	return ip ? replace_stack_entry(stack_entries, num_entries, ip, replaced) :
			  get_stack_skipnr(stack_entries, num_entries);
}

static int sym_strcmp(void *addr1, void *addr2)
{
	char buf1[64];
	char buf2[64];

	snprintf(buf1, sizeof(buf1), "%pS", addr1);
	snprintf(buf2, sizeof(buf2), "%pS", addr2);

	return strncmp(buf1, buf2, sizeof(buf1));
}

static void
print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long reordered_to)
{
	stack_trace_print(stack_entries, num_entries, 0);
	if (reordered_to)
		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to);
}

static void print_verbose_info(struct task_struct *task)
{
	if (!task)
		return;

	/* Restore IRQ state trace for printing. */
	kcsan_restore_irqtrace(task);

	pr_err("\n");
	debug_show_held_locks(task);
	print_irqtrace_events(task);
}

static void print_report(enum kcsan_value_change value_change,
			 const struct access_info *ai,
			 struct other_info *other_info,
			 u64 old, u64 new, u64 mask)
{
	unsigned long reordered_to = 0;
	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip, &reordered_to);
	unsigned long this_frame = stack_entries[skipnr];
	unsigned long other_reordered_to = 0;
	unsigned long other_frame = 0;
	int other_skipnr = 0; /* silence uninit warnings */

	/*
	if (skip_report(KCSAN_VALUE_CHANGE_TRUE, stack_entries[skipnr]))
		return;

	if (other_info) {
		other_skipnr = sanitize_stack_entries(other_info->stack_entries,
						      other_info->num_stack_entries,
						      other_info->ai.ip, &other_reordered_to);
		other_frame = other_info->stack_entries[other_skipnr];

		/* @value_change is only known for the other thread */
		if (skip_report(value_change, other_frame))
			return;
	}

	if (rate_limit_report(this_frame, other_frame))
		return;

	/* Print report header. */
	pr_err("==================================================================\n");
	if (other_info) {
		int cmp;

		/*
		cmp = sym_strcmp((void *)other_frame, (void *)this_frame);
		pr_err("BUG: KCSAN: %s in %ps / %ps\n",
		       get_bug_type(ai->access_type | other_info->ai.access_type),
		       (void *)(cmp < 0 ? other_frame : this_frame),
		       (void *)(cmp < 0 ? this_frame : other_frame));
	} else {
		pr_err("BUG: KCSAN: %s in %pS\n", get_bug_type(ai->access_type),
		       (void *)this_frame);
	}

	pr_err("\n");

	/* Print information about the racing accesses. */
	if (other_info) {
		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
		       get_access_type(other_info->ai.access_type), other_info->ai.ptr,
		       other_info->ai.size, get_thread_desc(other_info->ai.task_pid),
		       other_info->ai.cpu_id);

		/* Print the other thread's stack trace. */
		print_stack_trace(other_info->stack_entries + other_skipnr,
				  other_info->num_stack_entries - other_skipnr,
				  other_reordered_to);
		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
			print_verbose_info(other_info->task);

		pr_err("\n");
		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
		       get_access_type(ai->access_type), ai->ptr, ai->size,
		       get_thread_desc(ai->task_pid), ai->cpu_id);
	} else {
		pr_err("race at unknown origin, with %s to 0x%px of %zu bytes by %s on cpu %i:\n",
		       get_access_type(ai->access_type), ai->ptr, ai->size,
		       get_thread_desc(ai->task_pid), ai->cpu_id);
	}
	/* Print stack trace of this thread. */
	print_stack_trace(stack_entries + skipnr, num_stack_entries - skipnr, reordered_to);
	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
		print_verbose_info(current);

	/* Print observed value change. */
	if (ai->size <= 8) {
		int hex_len = ai->size * 2;
		u64 diff = old ^ new;

		if (mask)
			diff &= mask;
		if (diff) {
			pr_err("\n");
			pr_err("value changed: 0x%0*llx -> 0x%0*llx\n",
			       hex_len, old, hex_len, new);
			if (mask) {
				pr_err(" bits changed: 0x%0*llx with mask 0x%0*llx\n",
				       hex_len, diff, hex_len, mask);
			}
		}
	}

	/* Print report footer. */
	pr_err("\n");
	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
	dump_stack_print_info(KERN_DEFAULT);
	pr_err("==================================================================\n");

	if (panic_on_warn)
		panic("panic_on_warn set ...\n");
}

static void release_report(unsigned long *flags, struct other_info *other_info)
{
	/*
	other_info->ai.size = 0;
	raw_spin_unlock_irqrestore(&report_lock, *flags);
}

static void set_other_info_task_blocking(unsigned long *flags,
					 const struct access_info *ai,
					 struct other_info *other_info)
{
	/*
	const bool is_running = task_is_running(current);
	/*
	int timeout = max(kcsan_udelay_task, kcsan_udelay_interrupt);

	other_info->task = current;
	do {
		if (is_running) {
			/*
			set_current_state(TASK_UNINTERRUPTIBLE);
		}
		raw_spin_unlock_irqrestore(&report_lock, *flags);
		/*

		udelay(1);
		raw_spin_lock_irqsave(&report_lock, *flags);
		if (timeout-- < 0) {
			/*
			other_info->task = NULL;
			break;
		}
		/*
	} while (other_info->ai.size && other_info->ai.ptr == ai->ptr &&
		 other_info->task == current);
	if (is_running)
		set_current_state(TASK_RUNNING);
}

static void prepare_report_producer(unsigned long *flags,
				    const struct access_info *ai,
				    struct other_info *other_info)
{
	raw_spin_lock_irqsave(&report_lock, *flags);

	/*
	WARN_ON(other_info->ai.size);

	other_info->ai = *ai;
	other_info->num_stack_entries = stack_trace_save(other_info->stack_entries, NUM_STACK_ENTRIES, 2);

	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
		set_other_info_task_blocking(flags, ai, other_info);

	raw_spin_unlock_irqrestore(&report_lock, *flags);
}

static bool prepare_report_consumer(unsigned long *flags,
				    const struct access_info *ai,
				    struct other_info *other_info)
{

	raw_spin_lock_irqsave(&report_lock, *flags);
	while (!other_info->ai.size) { /* Await valid @other_info. */
		raw_spin_unlock_irqrestore(&report_lock, *flags);
		cpu_relax();
		raw_spin_lock_irqsave(&report_lock, *flags);
	}

	/* Should always have a matching access based on watchpoint encoding. */
	if (WARN_ON(!matching_access((unsigned long)other_info->ai.ptr & WATCHPOINT_ADDR_MASK, other_info->ai.size,
				     (unsigned long)ai->ptr & WATCHPOINT_ADDR_MASK, ai->size)))
		goto discard;

	if (!matching_access((unsigned long)other_info->ai.ptr, other_info->ai.size,
			     (unsigned long)ai->ptr, ai->size)) {
		/*
		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ENCODING_FALSE_POSITIVES]);
		goto discard;
	}

	return true;

discard:
	release_report(flags, other_info);
	return false;
}

static struct access_info prepare_access_info(const volatile void *ptr, size_t size,
					      int access_type, unsigned long ip)
{
	return (struct access_info) {
		.ptr		= ptr,
		.size		= size,
		.access_type	= access_type,
		.task_pid	= in_task() ? task_pid_nr(current) : -1,
		.cpu_id		= raw_smp_processor_id(),
		/* Only replace stack entry with @ip if scoped access. */
		.ip		= (access_type & KCSAN_ACCESS_SCOPED) ? ip : 0,
	};
}

void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_type,
			   unsigned long ip, int watchpoint_idx)
{
	const struct access_info ai = prepare_access_info(ptr, size, access_type, ip);
	unsigned long flags;

	kcsan_disable_current();
	lockdep_off(); /* See kcsan_report_known_origin(). */

	prepare_report_producer(&flags, &ai, &other_infos[watchpoint_idx]);

	lockdep_on();
	kcsan_enable_current();
}

void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
			       unsigned long ip, enum kcsan_value_change value_change,
			       int watchpoint_idx, u64 old, u64 new, u64 mask)
{
	const struct access_info ai = prepare_access_info(ptr, size, access_type, ip);
	struct other_info *other_info = &other_infos[watchpoint_idx];
	unsigned long flags = 0;

	kcsan_disable_current();
	/*
	lockdep_off();

	if (!prepare_report_consumer(&flags, &ai, other_info))
		goto out;
	/*
	if (value_change != KCSAN_VALUE_CHANGE_FALSE)
		print_report(value_change, &ai, other_info, old, new, mask);

	release_report(&flags, other_info);
out:
	lockdep_on();
	kcsan_enable_current();
}

void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type,
				 unsigned long ip, u64 old, u64 new, u64 mask)
{
	const struct access_info ai = prepare_access_info(ptr, size, access_type, ip);
	unsigned long flags;

	kcsan_disable_current();
	lockdep_off(); /* See kcsan_report_known_origin(). */

	raw_spin_lock_irqsave(&report_lock, flags);
	print_report(KCSAN_VALUE_CHANGE_TRUE, &ai, NULL, old, new, mask);
	raw_spin_unlock_irqrestore(&report_lock, flags);

	lockdep_on();
	kcsan_enable_current();
}
