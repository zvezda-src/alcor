
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/fs.h>

#include "trace_output.h"

struct recursed_functions {
	unsigned long		ip;
	unsigned long		parent_ip;
};

static struct recursed_functions recursed_functions[CONFIG_FTRACE_RECORD_RECURSION_SIZE];
static atomic_t nr_records;

static unsigned long cached_function;

void ftrace_record_recursion(unsigned long ip, unsigned long parent_ip)
{
	int index = 0;
	int i;
	unsigned long old;

 again:
	/* First check the last one recorded */
	if (ip == cached_function)
		return;

	i = atomic_read(&nr_records);
	/* nr_records is -1 when clearing records */
	smp_mb__after_atomic();
	if (i < 0)
		return;

	/*
	if (index < i)
		index = i;
	if (index >= CONFIG_FTRACE_RECORD_RECURSION_SIZE)
		return;

	for (i = index - 1; i >= 0; i--) {
		if (recursed_functions[i].ip == ip) {
			cached_function = ip;
			return;
		}
	}

	cached_function = ip;

	/*
	old = cmpxchg(&recursed_functions[index].ip, 0, ip);
	if (old != 0) {
		/* Did something else already added this for us? */
		if (old == ip)
			return;
		/* Try the next location (use i for the next index) */
		index++;
		goto again;
	}

	recursed_functions[index].parent_ip = parent_ip;

	/*
	i = atomic_read(&nr_records);
	smp_mb__after_atomic();
	if (i < 0)
		cmpxchg(&recursed_functions[index].ip, ip, 0);
	else if (i <= index)
		atomic_cmpxchg(&nr_records, i, index + 1);
}
EXPORT_SYMBOL_GPL(ftrace_record_recursion);

static DEFINE_MUTEX(recursed_function_lock);
static struct trace_seq *tseq;

static void *recursed_function_seq_start(struct seq_file *m, loff_t *pos)
{
	void *ret = NULL;
	int index;

	mutex_lock(&recursed_function_lock);
	index = atomic_read(&nr_records);
	if (*pos < index) {
		ret = &recursed_functions[*pos];
	}

	tseq = kzalloc(sizeof(*tseq), GFP_KERNEL);
	if (!tseq)
		return ERR_PTR(-ENOMEM);

	trace_seq_init(tseq);

	return ret;
}

static void *recursed_function_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	int index;
	int p;

	index = atomic_read(&nr_records);
	p = ++(*pos);

	return p < index ? &recursed_functions[p] : NULL;
}

static void recursed_function_seq_stop(struct seq_file *m, void *v)
{
	kfree(tseq);
	mutex_unlock(&recursed_function_lock);
}

static int recursed_function_seq_show(struct seq_file *m, void *v)
{
	struct recursed_functions *record = v;
	int ret = 0;

	if (record) {
		trace_seq_print_sym(tseq, record->parent_ip, true);
		trace_seq_puts(tseq, ":\t");
		trace_seq_print_sym(tseq, record->ip, true);
		trace_seq_putc(tseq, '\n');
		ret = trace_print_seq(m, tseq);
	}

	return ret;
}

static const struct seq_operations recursed_function_seq_ops = {
	.start  = recursed_function_seq_start,
	.next   = recursed_function_seq_next,
	.stop   = recursed_function_seq_stop,
	.show   = recursed_function_seq_show
};

static int recursed_function_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	mutex_lock(&recursed_function_lock);
	/* If this file was opened for write, then erase contents */
	if ((file->f_mode & FMODE_WRITE) && (file->f_flags & O_TRUNC)) {
		/* disable updating records */
		atomic_set(&nr_records, -1);
		smp_mb__after_atomic();
		memset(recursed_functions, 0, sizeof(recursed_functions));
		smp_wmb();
		/* enable them again */
		atomic_set(&nr_records, 0);
	}
	if (file->f_mode & FMODE_READ)
		ret = seq_open(file, &recursed_function_seq_ops);
	mutex_unlock(&recursed_function_lock);

	return ret;
}

static ssize_t recursed_function_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	return count;
}

static int recursed_function_release(struct inode *inode, struct file *file)
{
	if (file->f_mode & FMODE_READ)
		seq_release(inode, file);
	return 0;
}

static const struct file_operations recursed_functions_fops = {
	.open           = recursed_function_open,
	.write		= recursed_function_write,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = recursed_function_release,
};

__init static int create_recursed_functions(void)
{

	trace_create_file("recursed_functions", TRACE_MODE_WRITE,
			  NULL, NULL, &recursed_functions_fops);
	return 0;
}

fs_initcall(create_recursed_functions);
