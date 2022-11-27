
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/tracefs.h>

#include "trace.h"
#include "trace_output.h"	/* for trace_event_sem */
#include "trace_dynevent.h"

static DEFINE_MUTEX(dyn_event_ops_mutex);
static LIST_HEAD(dyn_event_ops_list);

bool trace_event_dyn_try_get_ref(struct trace_event_call *dyn_call)
{
	struct trace_event_call *call;
	bool ret = false;

	if (WARN_ON_ONCE(!(dyn_call->flags & TRACE_EVENT_FL_DYNAMIC)))
		return false;

	down_read(&trace_event_sem);
	list_for_each_entry(call, &ftrace_events, list) {
		if (call == dyn_call) {
			atomic_inc(&dyn_call->refcnt);
			ret = true;
		}
	}
	up_read(&trace_event_sem);
	return ret;
}

void trace_event_dyn_put_ref(struct trace_event_call *call)
{
	if (WARN_ON_ONCE(!(call->flags & TRACE_EVENT_FL_DYNAMIC)))
		return;

	if (WARN_ON_ONCE(atomic_read(&call->refcnt) <= 0)) {
		atomic_set(&call->refcnt, 0);
		return;
	}

	atomic_dec(&call->refcnt);
}

bool trace_event_dyn_busy(struct trace_event_call *call)
{
	return atomic_read(&call->refcnt) != 0;
}

int dyn_event_register(struct dyn_event_operations *ops)
{
	if (!ops || !ops->create || !ops->show || !ops->is_busy ||
	    !ops->free || !ops->match)
		return -EINVAL;

	INIT_LIST_HEAD(&ops->list);
	mutex_lock(&dyn_event_ops_mutex);
	list_add_tail(&ops->list, &dyn_event_ops_list);
	mutex_unlock(&dyn_event_ops_mutex);
	return 0;
}

int dyn_event_release(const char *raw_command, struct dyn_event_operations *type)
{
	struct dyn_event *pos, *n;
	char *system = NULL, *event, *p;
	int argc, ret = -ENOENT;
	char **argv;

	argv = argv_split(GFP_KERNEL, raw_command, &argc);
	if (!argv)
		return -ENOMEM;

	if (argv[0][0] == '-') {
		if (argv[0][1] != ':') {
			ret = -EINVAL;
			goto out;
		}
		event = &argv[0][2];
	} else {
		event = strchr(argv[0], ':');
		if (!event) {
			ret = -EINVAL;
			goto out;
		}
		event++;
	}

	p = strchr(event, '/');
	if (p) {
		system = event;
		event = p + 1;
		*p = '\0';
	}
	if (!system && event[0] == '\0') {
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&event_mutex);
	for_each_dyn_event_safe(pos, n) {
		if (type && type != pos->ops)
			continue;
		if (!pos->ops->match(system, event,
				argc - 1, (const char **)argv + 1, pos))
			continue;

		ret = pos->ops->free(pos);
		if (ret)
			break;
	}
	mutex_unlock(&event_mutex);
out:
	argv_free(argv);
	return ret;
}

static int create_dyn_event(const char *raw_command)
{
	struct dyn_event_operations *ops;
	int ret = -ENODEV;

	if (raw_command[0] == '-' || raw_command[0] == '!')
		return dyn_event_release(raw_command, NULL);

	mutex_lock(&dyn_event_ops_mutex);
	list_for_each_entry(ops, &dyn_event_ops_list, list) {
		ret = ops->create(raw_command);
		if (!ret || ret != -ECANCELED)
			break;
	}
	mutex_unlock(&dyn_event_ops_mutex);
	if (ret == -ECANCELED)
		ret = -EINVAL;

	return ret;
}

LIST_HEAD(dyn_event_list);

void *dyn_event_seq_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&event_mutex);
	return seq_list_start(&dyn_event_list, *pos);
}

void *dyn_event_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &dyn_event_list, pos);
}

void dyn_event_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&event_mutex);
}

static int dyn_event_seq_show(struct seq_file *m, void *v)
{
	struct dyn_event *ev = v;

	if (ev && ev->ops)
		return ev->ops->show(m, ev);

	return 0;
}

static const struct seq_operations dyn_event_seq_op = {
	.start	= dyn_event_seq_start,
	.next	= dyn_event_seq_next,
	.stop	= dyn_event_seq_stop,
	.show	= dyn_event_seq_show
};

int dyn_events_release_all(struct dyn_event_operations *type)
{
	struct dyn_event *ev, *tmp;
	int ret = 0;

	mutex_lock(&event_mutex);
	for_each_dyn_event(ev) {
		if (type && ev->ops != type)
			continue;
		if (ev->ops->is_busy(ev)) {
			ret = -EBUSY;
			goto out;
		}
	}
	for_each_dyn_event_safe(ev, tmp) {
		if (type && ev->ops != type)
			continue;
		ret = ev->ops->free(ev);
		if (ret)
			break;
	}
out:
	mutex_unlock(&event_mutex);

	return ret;
}

static int dyn_event_open(struct inode *inode, struct file *file)
{
	int ret;

	ret = tracing_check_open_get_tr(NULL);
	if (ret)
		return ret;

	if ((file->f_mode & FMODE_WRITE) && (file->f_flags & O_TRUNC)) {
		ret = dyn_events_release_all(NULL);
		if (ret < 0)
			return ret;
	}

	return seq_open(file, &dyn_event_seq_op);
}

static ssize_t dyn_event_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *ppos)
{
	return trace_parse_run_command(file, buffer, count, ppos,
				       create_dyn_event);
}

static const struct file_operations dynamic_events_ops = {
	.owner          = THIS_MODULE,
	.open           = dyn_event_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
	.write		= dyn_event_write,
};

static __init int init_dynamic_event(void)
{
	int ret;

	ret = tracing_init_dentry();
	if (ret)
		return 0;

	trace_create_file("dynamic_events", TRACE_MODE_WRITE, NULL,
			  NULL, &dynamic_events_ops);

	return 0;
}
fs_initcall(init_dynamic_event);

int dynevent_arg_add(struct dynevent_cmd *cmd,
		     struct dynevent_arg *arg,
		     dynevent_check_arg_fn_t check_arg)
{
	int ret = 0;

	if (check_arg) {
		ret = check_arg(arg);
		if (ret)
			return ret;
	}

	ret = seq_buf_printf(&cmd->seq, " %s%c", arg->str, arg->separator);
	if (ret) {
		pr_err("String is too long: %s%c\n", arg->str, arg->separator);
		return -E2BIG;
	}

	return ret;
}

int dynevent_arg_pair_add(struct dynevent_cmd *cmd,
			  struct dynevent_arg_pair *arg_pair,
			  dynevent_check_arg_fn_t check_arg)
{
	int ret = 0;

	if (check_arg) {
		ret = check_arg(arg_pair);
		if (ret)
			return ret;
	}

	ret = seq_buf_printf(&cmd->seq, " %s%c%s%c", arg_pair->lhs,
			     arg_pair->operator, arg_pair->rhs,
			     arg_pair->separator);
	if (ret) {
		pr_err("field string is too long: %s%c%s%c\n", arg_pair->lhs,
		       arg_pair->operator, arg_pair->rhs,
		       arg_pair->separator);
		return -E2BIG;
	}

	return ret;
}

int dynevent_str_add(struct dynevent_cmd *cmd, const char *str)
{
	int ret = 0;

	ret = seq_buf_puts(&cmd->seq, str);
	if (ret) {
		pr_err("String is too long: %s\n", str);
		return -E2BIG;
	}

	return ret;
}

void dynevent_cmd_init(struct dynevent_cmd *cmd, char *buf, int maxlen,
		       enum dynevent_type type,
		       dynevent_create_fn_t run_command)
{
	memset(cmd, '\0', sizeof(*cmd));

	seq_buf_init(&cmd->seq, buf, maxlen);
	cmd->type = type;
	cmd->run_command = run_command;
}

void dynevent_arg_init(struct dynevent_arg *arg,
		       char separator)
{
	memset(arg, '\0', sizeof(*arg));

	if (!separator)
		separator = ' ';
	arg->separator = separator;
}

void dynevent_arg_pair_init(struct dynevent_arg_pair *arg_pair,
			    char operator, char separator)
{
	memset(arg_pair, '\0', sizeof(*arg_pair));

	if (!operator)
		operator = ' ';
	arg_pair->operator = operator;

	if (!separator)
		separator = ' ';
	arg_pair->separator = separator;
}

int dynevent_create(struct dynevent_cmd *cmd)
{
	return cmd->run_command(cmd);
}
EXPORT_SYMBOL_GPL(dynevent_create);
