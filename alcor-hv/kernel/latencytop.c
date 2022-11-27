

#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/notifier.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/latencytop.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/stat.h>
#include <linux/list.h>
#include <linux/stacktrace.h>
#include <linux/sysctl.h>

static DEFINE_RAW_SPINLOCK(latency_lock);

#define MAXLR 128
static struct latency_record latency_record[MAXLR];

int latencytop_enabled;

#ifdef CONFIG_SYSCTL
static int sysctl_latencytop(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	int err;

	err = proc_dointvec(table, write, buffer, lenp, ppos);
	if (latencytop_enabled)
		force_schedstat_enabled();

	return err;
}

static struct ctl_table latencytop_sysctl[] = {
	{
		.procname   = "latencytop",
		.data       = &latencytop_enabled,
		.maxlen     = sizeof(int),
		.mode       = 0644,
		.proc_handler   = sysctl_latencytop,
	},
	{}
};
#endif

void clear_tsk_latency_tracing(struct task_struct *p)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&latency_lock, flags);
	memset(&p->latency_record, 0, sizeof(p->latency_record));
	p->latency_record_count = 0;
	raw_spin_unlock_irqrestore(&latency_lock, flags);
}

static void clear_global_latency_tracing(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&latency_lock, flags);
	memset(&latency_record, 0, sizeof(latency_record));
	raw_spin_unlock_irqrestore(&latency_lock, flags);
}

static void __sched
account_global_scheduler_latency(struct task_struct *tsk,
				 struct latency_record *lat)
{
	int firstnonnull = MAXLR + 1;
	int i;

	/* skip kernel threads for now */
	if (!tsk->mm)
		return;

	for (i = 0; i < MAXLR; i++) {
		int q, same = 1;

		/* Nothing stored: */
		if (!latency_record[i].backtrace[0]) {
			if (firstnonnull > i)
				firstnonnull = i;
			continue;
		}
		for (q = 0; q < LT_BACKTRACEDEPTH; q++) {
			unsigned long record = lat->backtrace[q];

			if (latency_record[i].backtrace[q] != record) {
				same = 0;
				break;
			}

			/* 0 entry marks end of backtrace: */
			if (!record)
				break;
		}
		if (same) {
			latency_record[i].count++;
			latency_record[i].time += lat->time;
			if (lat->time > latency_record[i].max)
				latency_record[i].max = lat->time;
			return;
		}
	}

	i = firstnonnull;
	if (i >= MAXLR - 1)
		return;

	/* Allocted a new one: */
	memcpy(&latency_record[i], lat, sizeof(struct latency_record));
}

void __sched
__account_scheduler_latency(struct task_struct *tsk, int usecs, int inter)
{
	unsigned long flags;
	int i, q;
	struct latency_record lat;

	/* Long interruptible waits are generally user requested... */
	if (inter && usecs > 5000)
		return;

	/* Negative sleeps are time going backwards */
	/* Zero-time sleeps are non-interesting */
	if (usecs <= 0)
		return;

	memset(&lat, 0, sizeof(lat));
	lat.count = 1;
	lat.time = usecs;
	lat.max = usecs;

	stack_trace_save_tsk(tsk, lat.backtrace, LT_BACKTRACEDEPTH, 0);

	raw_spin_lock_irqsave(&latency_lock, flags);

	account_global_scheduler_latency(tsk, &lat);

	for (i = 0; i < tsk->latency_record_count; i++) {
		struct latency_record *mylat;
		int same = 1;

		mylat = &tsk->latency_record[i];
		for (q = 0; q < LT_BACKTRACEDEPTH; q++) {
			unsigned long record = lat.backtrace[q];

			if (mylat->backtrace[q] != record) {
				same = 0;
				break;
			}

			/* 0 entry is end of backtrace */
			if (!record)
				break;
		}
		if (same) {
			mylat->count++;
			mylat->time += lat.time;
			if (lat.time > mylat->max)
				mylat->max = lat.time;
			goto out_unlock;
		}
	}

	/*
	if (tsk->latency_record_count >= LT_SAVECOUNT)
		goto out_unlock;

	/* Allocated a new one: */
	i = tsk->latency_record_count++;
	memcpy(&tsk->latency_record[i], &lat, sizeof(struct latency_record));

out_unlock:
	raw_spin_unlock_irqrestore(&latency_lock, flags);
}

static int lstats_show(struct seq_file *m, void *v)
{
	int i;

	seq_puts(m, "Latency Top version : v0.1\n");

	for (i = 0; i < MAXLR; i++) {
		struct latency_record *lr = &latency_record[i];

		if (lr->backtrace[0]) {
			int q;
			seq_printf(m, "%i %lu %lu",
				   lr->count, lr->time, lr->max);
			for (q = 0; q < LT_BACKTRACEDEPTH; q++) {
				unsigned long bt = lr->backtrace[q];

				if (!bt)
					break;

				seq_printf(m, " %ps", (void *)bt);
			}
			seq_puts(m, "\n");
		}
	}
	return 0;
}

static ssize_t
lstats_write(struct file *file, const char __user *buf, size_t count,
	     loff_t *offs)
{
	clear_global_latency_tracing();

	return count;
}

static int lstats_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, lstats_show, NULL);
}

static const struct proc_ops lstats_proc_ops = {
	.proc_open	= lstats_open,
	.proc_read	= seq_read,
	.proc_write	= lstats_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init init_lstats_procfs(void)
{
	proc_create("latency_stats", 0644, NULL, &lstats_proc_ops);
#ifdef CONFIG_SYSCTL
	register_sysctl_init("kernel", latencytop_sysctl);
#endif
	return 0;
}
device_initcall(init_lstats_procfs);
