
#include <linux/security.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/rculist.h>

#include "trace.h"

static LIST_HEAD(trigger_commands);
static DEFINE_MUTEX(trigger_cmd_mutex);

void trigger_data_free(struct event_trigger_data *data)
{
	if (data->cmd_ops->set_filter)
		data->cmd_ops->set_filter(NULL, data, NULL);

	/* make sure current triggers exit before free */
	tracepoint_synchronize_unregister();

	kfree(data);
}

enum event_trigger_type
event_triggers_call(struct trace_event_file *file,
		    struct trace_buffer *buffer, void *rec,
		    struct ring_buffer_event *event)
{
	struct event_trigger_data *data;
	enum event_trigger_type tt = ETT_NONE;
	struct event_filter *filter;

	if (list_empty(&file->triggers))
		return tt;

	list_for_each_entry_rcu(data, &file->triggers, list) {
		if (data->paused)
			continue;
		if (!rec) {
			data->ops->trigger(data, buffer, rec, event);
			continue;
		}
		filter = rcu_dereference_sched(data->filter);
		if (filter && !filter_match_preds(filter, rec))
			continue;
		if (event_command_post_trigger(data->cmd_ops)) {
			tt |= data->cmd_ops->trigger_type;
			continue;
		}
		data->ops->trigger(data, buffer, rec, event);
	}
	return tt;
}
EXPORT_SYMBOL_GPL(event_triggers_call);

bool __trace_trigger_soft_disabled(struct trace_event_file *file)
{
	unsigned long eflags = file->flags;

	if (eflags & EVENT_FILE_FL_TRIGGER_MODE)
		event_triggers_call(file, NULL, NULL, NULL);
	if (eflags & EVENT_FILE_FL_SOFT_DISABLED)
		return true;
	if (eflags & EVENT_FILE_FL_PID_FILTER)
		return trace_event_ignore_this_pid(file);
	return false;
}
EXPORT_SYMBOL_GPL(__trace_trigger_soft_disabled);

void
event_triggers_post_call(struct trace_event_file *file,
			 enum event_trigger_type tt)
{
	struct event_trigger_data *data;

	list_for_each_entry_rcu(data, &file->triggers, list) {
		if (data->paused)
			continue;
		if (data->cmd_ops->trigger_type & tt)
			data->ops->trigger(data, NULL, NULL, NULL);
	}
}
EXPORT_SYMBOL_GPL(event_triggers_post_call);

#define SHOW_AVAILABLE_TRIGGERS	(void *)(1UL)

static void *trigger_next(struct seq_file *m, void *t, loff_t *pos)
{
	struct trace_event_file *event_file = event_file_data(m->private);

	if (t == SHOW_AVAILABLE_TRIGGERS) {
		(*pos)++;
		return NULL;
	}
	return seq_list_next(t, &event_file->triggers, pos);
}

static bool check_user_trigger(struct trace_event_file *file)
{
	struct event_trigger_data *data;

	list_for_each_entry_rcu(data, &file->triggers, list) {
		if (data->flags & EVENT_TRIGGER_FL_PROBE)
			continue;
		return true;
	}
	return false;
}

static void *trigger_start(struct seq_file *m, loff_t *pos)
{
	struct trace_event_file *event_file;

	/* ->stop() is called even if ->start() fails */
	mutex_lock(&event_mutex);
	event_file = event_file_data(m->private);
	if (unlikely(!event_file))
		return ERR_PTR(-ENODEV);

	if (list_empty(&event_file->triggers) || !check_user_trigger(event_file))
		return *pos == 0 ? SHOW_AVAILABLE_TRIGGERS : NULL;

	return seq_list_start(&event_file->triggers, *pos);
}

static void trigger_stop(struct seq_file *m, void *t)
{
	mutex_unlock(&event_mutex);
}

static int trigger_show(struct seq_file *m, void *v)
{
	struct event_trigger_data *data;
	struct event_command *p;

	if (v == SHOW_AVAILABLE_TRIGGERS) {
		seq_puts(m, "# Available triggers:\n");
		seq_putc(m, '#');
		mutex_lock(&trigger_cmd_mutex);
		list_for_each_entry_reverse(p, &trigger_commands, list)
			seq_printf(m, " %s", p->name);
		seq_putc(m, '\n');
		mutex_unlock(&trigger_cmd_mutex);
		return 0;
	}

	data = list_entry(v, struct event_trigger_data, list);
	data->ops->print(m, data);

	return 0;
}

static const struct seq_operations event_triggers_seq_ops = {
	.start = trigger_start,
	.next = trigger_next,
	.stop = trigger_stop,
	.show = trigger_show,
};

static int event_trigger_regex_open(struct inode *inode, struct file *file)
{
	int ret;

	ret = security_locked_down(LOCKDOWN_TRACEFS);
	if (ret)
		return ret;

	mutex_lock(&event_mutex);

	if (unlikely(!event_file_data(file))) {
		mutex_unlock(&event_mutex);
		return -ENODEV;
	}

	if ((file->f_mode & FMODE_WRITE) &&
	    (file->f_flags & O_TRUNC)) {
		struct trace_event_file *event_file;
		struct event_command *p;

		event_file = event_file_data(file);

		list_for_each_entry(p, &trigger_commands, list) {
			if (p->unreg_all)
				p->unreg_all(event_file);
		}
	}

	if (file->f_mode & FMODE_READ) {
		ret = seq_open(file, &event_triggers_seq_ops);
		if (!ret) {
			struct seq_file *m = file->private_data;
			m->private = file;
		}
	}

	mutex_unlock(&event_mutex);

	return ret;
}

int trigger_process_regex(struct trace_event_file *file, char *buff)
{
	char *command, *next;
	struct event_command *p;
	int ret = -EINVAL;

	next = buff = skip_spaces(buff);
	command = strsep(&next, ": \t");
	if (next) {
		next = skip_spaces(next);
		if (!*next)
			next = NULL;
	}
	command = (command[0] != '!') ? command : command + 1;

	mutex_lock(&trigger_cmd_mutex);
	list_for_each_entry(p, &trigger_commands, list) {
		if (strcmp(p->name, command) == 0) {
			ret = p->parse(p, file, buff, command, next);
			goto out_unlock;
		}
	}
 out_unlock:
	mutex_unlock(&trigger_cmd_mutex);

	return ret;
}

static ssize_t event_trigger_regex_write(struct file *file,
					 const char __user *ubuf,
					 size_t cnt, loff_t *ppos)
{
	struct trace_event_file *event_file;
	ssize_t ret;
	char *buf;

	if (!cnt)
		return 0;

	if (cnt >= PAGE_SIZE)
		return -EINVAL;

	buf = memdup_user_nul(ubuf, cnt);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	strim(buf);

	mutex_lock(&event_mutex);
	event_file = event_file_data(file);
	if (unlikely(!event_file)) {
		mutex_unlock(&event_mutex);
		kfree(buf);
		return -ENODEV;
	}
	ret = trigger_process_regex(event_file, buf);
	mutex_unlock(&event_mutex);

	kfree(buf);
	if (ret < 0)
		goto out;

	ret = cnt;
 out:
	return ret;
}

static int event_trigger_regex_release(struct inode *inode, struct file *file)
{
	mutex_lock(&event_mutex);

	if (file->f_mode & FMODE_READ)
		seq_release(inode, file);

	mutex_unlock(&event_mutex);

	return 0;
}

static ssize_t
event_trigger_write(struct file *filp, const char __user *ubuf,
		    size_t cnt, loff_t *ppos)
{
	return event_trigger_regex_write(filp, ubuf, cnt, ppos);
}

static int
event_trigger_open(struct inode *inode, struct file *filp)
{
	/* Checks for tracefs lockdown */
	return event_trigger_regex_open(inode, filp);
}

static int
event_trigger_release(struct inode *inode, struct file *file)
{
	return event_trigger_regex_release(inode, file);
}

const struct file_operations event_trigger_fops = {
	.open = event_trigger_open,
	.read = seq_read,
	.write = event_trigger_write,
	.llseek = tracing_lseek,
	.release = event_trigger_release,
};

__init int register_event_command(struct event_command *cmd)
{
	struct event_command *p;
	int ret = 0;

	mutex_lock(&trigger_cmd_mutex);
	list_for_each_entry(p, &trigger_commands, list) {
		if (strcmp(cmd->name, p->name) == 0) {
			ret = -EBUSY;
			goto out_unlock;
		}
	}
	list_add(&cmd->list, &trigger_commands);
 out_unlock:
	mutex_unlock(&trigger_cmd_mutex);

	return ret;
}

__init int unregister_event_command(struct event_command *cmd)
{
	struct event_command *p, *n;
	int ret = -ENODEV;

	mutex_lock(&trigger_cmd_mutex);
	list_for_each_entry_safe(p, n, &trigger_commands, list) {
		if (strcmp(cmd->name, p->name) == 0) {
			ret = 0;
			list_del_init(&p->list);
			goto out_unlock;
		}
	}
 out_unlock:
	mutex_unlock(&trigger_cmd_mutex);

	return ret;
}

static int
event_trigger_print(const char *name, struct seq_file *m,
		    void *data, char *filter_str)
{
	long count = (long)data;

	seq_puts(m, name);

	if (count == -1)
		seq_puts(m, ":unlimited");
	else
		seq_printf(m, ":count=%ld", count);

	if (filter_str)
		seq_printf(m, " if %s\n", filter_str);
	else
		seq_putc(m, '\n');

	return 0;
}

int event_trigger_init(struct event_trigger_data *data)
{
	data->ref++;
	return 0;
}

static void
event_trigger_free(struct event_trigger_data *data)
{
	if (WARN_ON_ONCE(data->ref <= 0))
		return;

	data->ref--;
	if (!data->ref)
		trigger_data_free(data);
}

int trace_event_trigger_enable_disable(struct trace_event_file *file,
				       int trigger_enable)
{
	int ret = 0;

	if (trigger_enable) {
		if (atomic_inc_return(&file->tm_ref) > 1)
			return ret;
		set_bit(EVENT_FILE_FL_TRIGGER_MODE_BIT, &file->flags);
		ret = trace_event_enable_disable(file, 1, 1);
	} else {
		if (atomic_dec_return(&file->tm_ref) > 0)
			return ret;
		clear_bit(EVENT_FILE_FL_TRIGGER_MODE_BIT, &file->flags);
		ret = trace_event_enable_disable(file, 0, 1);
	}

	return ret;
}

void
clear_event_triggers(struct trace_array *tr)
{
	struct trace_event_file *file;

	list_for_each_entry(file, &tr->events, list) {
		struct event_trigger_data *data, *n;
		list_for_each_entry_safe(data, n, &file->triggers, list) {
			trace_event_trigger_enable_disable(file, 0);
			list_del_rcu(&data->list);
			if (data->ops->free)
				data->ops->free(data);
		}
	}
}

void update_cond_flag(struct trace_event_file *file)
{
	struct event_trigger_data *data;
	bool set_cond = false;

	lockdep_assert_held(&event_mutex);

	list_for_each_entry(data, &file->triggers, list) {
		if (data->filter || event_command_post_trigger(data->cmd_ops) ||
		    event_command_needs_rec(data->cmd_ops)) {
			set_cond = true;
			break;
		}
	}

	if (set_cond)
		set_bit(EVENT_FILE_FL_TRIGGER_COND_BIT, &file->flags);
	else
		clear_bit(EVENT_FILE_FL_TRIGGER_COND_BIT, &file->flags);
}

static int register_trigger(char *glob,
			    struct event_trigger_data *data,
			    struct trace_event_file *file)
{
	struct event_trigger_data *test;
	int ret = 0;

	lockdep_assert_held(&event_mutex);

	list_for_each_entry(test, &file->triggers, list) {
		if (test->cmd_ops->trigger_type == data->cmd_ops->trigger_type) {
			ret = -EEXIST;
			goto out;
		}
	}

	if (data->ops->init) {
		ret = data->ops->init(data);
		if (ret < 0)
			goto out;
	}

	list_add_rcu(&data->list, &file->triggers);

	update_cond_flag(file);
	ret = trace_event_trigger_enable_disable(file, 1);
	if (ret < 0) {
		list_del_rcu(&data->list);
		update_cond_flag(file);
	}
out:
	return ret;
}

static void unregister_trigger(char *glob,
			       struct event_trigger_data *test,
			       struct trace_event_file *file)
{
	struct event_trigger_data *data = NULL, *iter;

	lockdep_assert_held(&event_mutex);

	list_for_each_entry(iter, &file->triggers, list) {
		if (iter->cmd_ops->trigger_type == test->cmd_ops->trigger_type) {
			data = iter;
			list_del_rcu(&data->list);
			trace_event_trigger_enable_disable(file, 0);
			update_cond_flag(file);
			break;
		}
	}

	if (data && data->ops->free)
		data->ops->free(data);
}


bool event_trigger_check_remove(const char *glob)
{
	return (glob && glob[0] == '!') ? true : false;
}

bool event_trigger_empty_param(const char *param)
{
	return !param;
}

int event_trigger_separate_filter(char *param_and_filter, char **param,
				  char **filter, bool param_required)
{
	int ret = 0;


	if (!param_and_filter) {
		if (param_required)
			ret = -EINVAL;
		goto out;
	}

	/*
	if (!param_required && param_and_filter && !isdigit(param_and_filter[0])) {
		*filter = param_and_filter;
		goto out;
	}

	/*

	/*
	if (param_and_filter) {
		*filter = skip_spaces(param_and_filter);
		if (!**filter)
			*filter = NULL;
	}
out:
	return ret;
}

struct event_trigger_data *event_trigger_alloc(struct event_command *cmd_ops,
					       char *cmd,
					       char *param,
					       void *private_data)
{
	struct event_trigger_data *trigger_data;
	struct event_trigger_ops *trigger_ops;

	trigger_ops = cmd_ops->get_trigger_ops(cmd, param);

	trigger_data = kzalloc(sizeof(*trigger_data), GFP_KERNEL);
	if (!trigger_data)
		return NULL;

	trigger_data->count = -1;
	trigger_data->ops = trigger_ops;
	trigger_data->cmd_ops = cmd_ops;
	trigger_data->private_data = private_data;

	INIT_LIST_HEAD(&trigger_data->list);
	INIT_LIST_HEAD(&trigger_data->named_list);
	RCU_INIT_POINTER(trigger_data->filter, NULL);

	return trigger_data;
}

int event_trigger_parse_num(char *param,
			    struct event_trigger_data *trigger_data)
{
	char *number;
	int ret = 0;

	if (param) {
		number = strsep(&param, ":");

		if (!strlen(number))
			return -EINVAL;

		/*
		ret = kstrtoul(number, 0, &trigger_data->count);
	}

	return ret;
}

int event_trigger_set_filter(struct event_command *cmd_ops,
			     struct trace_event_file *file,
			     char *param,
			     struct event_trigger_data *trigger_data)
{
	if (param && cmd_ops->set_filter)
		return cmd_ops->set_filter(param, trigger_data, file);

	return 0;
}

void event_trigger_reset_filter(struct event_command *cmd_ops,
				struct event_trigger_data *trigger_data)
{
	if (cmd_ops->set_filter)
		cmd_ops->set_filter(NULL, trigger_data, NULL);
}

int event_trigger_register(struct event_command *cmd_ops,
			   struct trace_event_file *file,
			   char *glob,
			   struct event_trigger_data *trigger_data)
{
	return cmd_ops->reg(glob, trigger_data, file);
}

void event_trigger_unregister(struct event_command *cmd_ops,
			      struct trace_event_file *file,
			      char *glob,
			      struct event_trigger_data *trigger_data)
{
	cmd_ops->unreg(glob, trigger_data, file);
}


static int
event_trigger_parse(struct event_command *cmd_ops,
		    struct trace_event_file *file,
		    char *glob, char *cmd, char *param_and_filter)
{
	struct event_trigger_data *trigger_data;
	char *param, *filter;
	bool remove;
	int ret;

	remove = event_trigger_check_remove(glob);

	ret = event_trigger_separate_filter(param_and_filter, &param, &filter, false);
	if (ret)
		return ret;

	ret = -ENOMEM;
	trigger_data = event_trigger_alloc(cmd_ops, cmd, param, file);
	if (!trigger_data)
		goto out;

	if (remove) {
		event_trigger_unregister(cmd_ops, file, glob+1, trigger_data);
		kfree(trigger_data);
		ret = 0;
		goto out;
	}

	ret = event_trigger_parse_num(param, trigger_data);
	if (ret)
		goto out_free;

	ret = event_trigger_set_filter(cmd_ops, file, filter, trigger_data);
	if (ret < 0)
		goto out_free;

	/* Up the trigger_data count to make sure reg doesn't free it on failure */
	event_trigger_init(trigger_data);

	ret = event_trigger_register(cmd_ops, file, glob, trigger_data);
	if (ret)
		goto out_free;

	/* Down the counter of trigger_data or free it if not used anymore */
	event_trigger_free(trigger_data);
 out:
	return ret;

 out_free:
	event_trigger_reset_filter(cmd_ops, trigger_data);
	kfree(trigger_data);
	goto out;
}

int set_trigger_filter(char *filter_str,
		       struct event_trigger_data *trigger_data,
		       struct trace_event_file *file)
{
	struct event_trigger_data *data = trigger_data;
	struct event_filter *filter = NULL, *tmp;
	int ret = -EINVAL;
	char *s;

	if (!filter_str) /* clear the current filter */
		goto assign;

	s = strsep(&filter_str, " \t");

	if (!strlen(s) || strcmp(s, "if") != 0)
		goto out;

	if (!filter_str)
		goto out;

	/* The filter is for the 'trigger' event, not the triggered event */
	ret = create_event_filter(file->tr, file->event_call,
				  filter_str, false, &filter);
	/*
 assign:
	tmp = rcu_access_pointer(data->filter);

	rcu_assign_pointer(data->filter, filter);

	if (tmp) {
		/* Make sure the call is done with the filter */
		tracepoint_synchronize_unregister();
		free_event_filter(tmp);
	}

	kfree(data->filter_str);
	data->filter_str = NULL;

	if (filter_str) {
		data->filter_str = kstrdup(filter_str, GFP_KERNEL);
		if (!data->filter_str) {
			free_event_filter(rcu_access_pointer(data->filter));
			data->filter = NULL;
			ret = -ENOMEM;
		}
	}
 out:
	return ret;
}

static LIST_HEAD(named_triggers);

struct event_trigger_data *find_named_trigger(const char *name)
{
	struct event_trigger_data *data;

	if (!name)
		return NULL;

	list_for_each_entry(data, &named_triggers, named_list) {
		if (data->named_data)
			continue;
		if (strcmp(data->name, name) == 0)
			return data;
	}

	return NULL;
}

bool is_named_trigger(struct event_trigger_data *test)
{
	struct event_trigger_data *data;

	list_for_each_entry(data, &named_triggers, named_list) {
		if (test == data)
			return true;
	}

	return false;
}

int save_named_trigger(const char *name, struct event_trigger_data *data)
{
	data->name = kstrdup(name, GFP_KERNEL);
	if (!data->name)
		return -ENOMEM;

	list_add(&data->named_list, &named_triggers);

	return 0;
}

void del_named_trigger(struct event_trigger_data *data)
{
	kfree(data->name);
	data->name = NULL;

	list_del(&data->named_list);
}

static void __pause_named_trigger(struct event_trigger_data *data, bool pause)
{
	struct event_trigger_data *test;

	list_for_each_entry(test, &named_triggers, named_list) {
		if (strcmp(test->name, data->name) == 0) {
			if (pause) {
				test->paused_tmp = test->paused;
				test->paused = true;
			} else {
				test->paused = test->paused_tmp;
			}
		}
	}
}

void pause_named_trigger(struct event_trigger_data *data)
{
	__pause_named_trigger(data, true);
}

void unpause_named_trigger(struct event_trigger_data *data)
{
	__pause_named_trigger(data, false);
}

void set_named_trigger_data(struct event_trigger_data *data,
			    struct event_trigger_data *named_data)
{
	data->named_data = named_data;
}

struct event_trigger_data *
get_named_trigger_data(struct event_trigger_data *data)
{
	return data->named_data;
}

static void
traceon_trigger(struct event_trigger_data *data,
		struct trace_buffer *buffer, void *rec,
		struct ring_buffer_event *event)
{
	struct trace_event_file *file = data->private_data;

	if (file) {
		if (tracer_tracing_is_on(file->tr))
			return;

		tracer_tracing_on(file->tr);
		return;
	}

	if (tracing_is_on())
		return;

	tracing_on();
}

static void
traceon_count_trigger(struct event_trigger_data *data,
		      struct trace_buffer *buffer, void *rec,
		      struct ring_buffer_event *event)
{
	struct trace_event_file *file = data->private_data;

	if (file) {
		if (tracer_tracing_is_on(file->tr))
			return;
	} else {
		if (tracing_is_on())
			return;
	}

	if (!data->count)
		return;

	if (data->count != -1)
		(data->count)--;

	if (file)
		tracer_tracing_on(file->tr);
	else
		tracing_on();
}

static void
traceoff_trigger(struct event_trigger_data *data,
		 struct trace_buffer *buffer, void *rec,
		 struct ring_buffer_event *event)
{
	struct trace_event_file *file = data->private_data;

	if (file) {
		if (!tracer_tracing_is_on(file->tr))
			return;

		tracer_tracing_off(file->tr);
		return;
	}

	if (!tracing_is_on())
		return;

	tracing_off();
}

static void
traceoff_count_trigger(struct event_trigger_data *data,
		       struct trace_buffer *buffer, void *rec,
		       struct ring_buffer_event *event)
{
	struct trace_event_file *file = data->private_data;

	if (file) {
		if (!tracer_tracing_is_on(file->tr))
			return;
	} else {
		if (!tracing_is_on())
			return;
	}

	if (!data->count)
		return;

	if (data->count != -1)
		(data->count)--;

	if (file)
		tracer_tracing_off(file->tr);
	else
		tracing_off();
}

static int
traceon_trigger_print(struct seq_file *m, struct event_trigger_data *data)
{
	return event_trigger_print("traceon", m, (void *)data->count,
				   data->filter_str);
}

static int
traceoff_trigger_print(struct seq_file *m, struct event_trigger_data *data)
{
	return event_trigger_print("traceoff", m, (void *)data->count,
				   data->filter_str);
}

static struct event_trigger_ops traceon_trigger_ops = {
	.trigger		= traceon_trigger,
	.print			= traceon_trigger_print,
	.init			= event_trigger_init,
	.free			= event_trigger_free,
};

static struct event_trigger_ops traceon_count_trigger_ops = {
	.trigger		= traceon_count_trigger,
	.print			= traceon_trigger_print,
	.init			= event_trigger_init,
	.free			= event_trigger_free,
};

static struct event_trigger_ops traceoff_trigger_ops = {
	.trigger		= traceoff_trigger,
	.print			= traceoff_trigger_print,
	.init			= event_trigger_init,
	.free			= event_trigger_free,
};

static struct event_trigger_ops traceoff_count_trigger_ops = {
	.trigger		= traceoff_count_trigger,
	.print			= traceoff_trigger_print,
	.init			= event_trigger_init,
	.free			= event_trigger_free,
};

static struct event_trigger_ops *
onoff_get_trigger_ops(char *cmd, char *param)
{
	struct event_trigger_ops *ops;

	/* we register both traceon and traceoff to this callback */
	if (strcmp(cmd, "traceon") == 0)
		ops = param ? &traceon_count_trigger_ops :
			&traceon_trigger_ops;
	else
		ops = param ? &traceoff_count_trigger_ops :
			&traceoff_trigger_ops;

	return ops;
}

static struct event_command trigger_traceon_cmd = {
	.name			= "traceon",
	.trigger_type		= ETT_TRACE_ONOFF,
	.parse			= event_trigger_parse,
	.reg			= register_trigger,
	.unreg			= unregister_trigger,
	.get_trigger_ops	= onoff_get_trigger_ops,
	.set_filter		= set_trigger_filter,
};

static struct event_command trigger_traceoff_cmd = {
	.name			= "traceoff",
	.trigger_type		= ETT_TRACE_ONOFF,
	.flags			= EVENT_CMD_FL_POST_TRIGGER,
	.parse			= event_trigger_parse,
	.reg			= register_trigger,
	.unreg			= unregister_trigger,
	.get_trigger_ops	= onoff_get_trigger_ops,
	.set_filter		= set_trigger_filter,
};

#ifdef CONFIG_TRACER_SNAPSHOT
static void
snapshot_trigger(struct event_trigger_data *data,
		 struct trace_buffer *buffer, void *rec,
		 struct ring_buffer_event *event)
{
	struct trace_event_file *file = data->private_data;

	if (file)
		tracing_snapshot_instance(file->tr);
	else
		tracing_snapshot();
}

static void
snapshot_count_trigger(struct event_trigger_data *data,
		       struct trace_buffer *buffer, void *rec,
		       struct ring_buffer_event *event)
{
	if (!data->count)
		return;

	if (data->count != -1)
		(data->count)--;

	snapshot_trigger(data, buffer, rec, event);
}

static int
register_snapshot_trigger(char *glob,
			  struct event_trigger_data *data,
			  struct trace_event_file *file)
{
	if (tracing_alloc_snapshot_instance(file->tr) != 0)
		return 0;

	return register_trigger(glob, data, file);
}

static int
snapshot_trigger_print(struct seq_file *m, struct event_trigger_data *data)
{
	return event_trigger_print("snapshot", m, (void *)data->count,
				   data->filter_str);
}

static struct event_trigger_ops snapshot_trigger_ops = {
	.trigger		= snapshot_trigger,
	.print			= snapshot_trigger_print,
	.init			= event_trigger_init,
	.free			= event_trigger_free,
};

static struct event_trigger_ops snapshot_count_trigger_ops = {
	.trigger		= snapshot_count_trigger,
	.print			= snapshot_trigger_print,
	.init			= event_trigger_init,
	.free			= event_trigger_free,
};

static struct event_trigger_ops *
snapshot_get_trigger_ops(char *cmd, char *param)
{
	return param ? &snapshot_count_trigger_ops : &snapshot_trigger_ops;
}

static struct event_command trigger_snapshot_cmd = {
	.name			= "snapshot",
	.trigger_type		= ETT_SNAPSHOT,
	.parse			= event_trigger_parse,
	.reg			= register_snapshot_trigger,
	.unreg			= unregister_trigger,
	.get_trigger_ops	= snapshot_get_trigger_ops,
	.set_filter		= set_trigger_filter,
};

static __init int register_trigger_snapshot_cmd(void)
{
	int ret;

	ret = register_event_command(&trigger_snapshot_cmd);
	WARN_ON(ret < 0);

	return ret;
}
#else
static __init int register_trigger_snapshot_cmd(void) { return 0; }
#endif /* CONFIG_TRACER_SNAPSHOT */

#ifdef CONFIG_STACKTRACE
#ifdef CONFIG_UNWINDER_ORC
# define STACK_SKIP 2
#else
#define STACK_SKIP 4
#endif

static void
stacktrace_trigger(struct event_trigger_data *data,
		   struct trace_buffer *buffer,  void *rec,
		   struct ring_buffer_event *event)
{
	struct trace_event_file *file = data->private_data;

	if (file)
		__trace_stack(file->tr, tracing_gen_ctx(), STACK_SKIP);
	else
		trace_dump_stack(STACK_SKIP);
}

static void
stacktrace_count_trigger(struct event_trigger_data *data,
			 struct trace_buffer *buffer, void *rec,
			 struct ring_buffer_event *event)
{
	if (!data->count)
		return;

	if (data->count != -1)
		(data->count)--;

	stacktrace_trigger(data, buffer, rec, event);
}

static int
stacktrace_trigger_print(struct seq_file *m, struct event_trigger_data *data)
{
	return event_trigger_print("stacktrace", m, (void *)data->count,
				   data->filter_str);
}

static struct event_trigger_ops stacktrace_trigger_ops = {
	.trigger		= stacktrace_trigger,
	.print			= stacktrace_trigger_print,
	.init			= event_trigger_init,
	.free			= event_trigger_free,
};

static struct event_trigger_ops stacktrace_count_trigger_ops = {
	.trigger		= stacktrace_count_trigger,
	.print			= stacktrace_trigger_print,
	.init			= event_trigger_init,
	.free			= event_trigger_free,
};

static struct event_trigger_ops *
stacktrace_get_trigger_ops(char *cmd, char *param)
{
	return param ? &stacktrace_count_trigger_ops : &stacktrace_trigger_ops;
}

static struct event_command trigger_stacktrace_cmd = {
	.name			= "stacktrace",
	.trigger_type		= ETT_STACKTRACE,
	.flags			= EVENT_CMD_FL_POST_TRIGGER,
	.parse			= event_trigger_parse,
	.reg			= register_trigger,
	.unreg			= unregister_trigger,
	.get_trigger_ops	= stacktrace_get_trigger_ops,
	.set_filter		= set_trigger_filter,
};

static __init int register_trigger_stacktrace_cmd(void)
{
	int ret;

	ret = register_event_command(&trigger_stacktrace_cmd);
	WARN_ON(ret < 0);

	return ret;
}
#else
static __init int register_trigger_stacktrace_cmd(void) { return 0; }
#endif /* CONFIG_STACKTRACE */

static __init void unregister_trigger_traceon_traceoff_cmds(void)
{
	unregister_event_command(&trigger_traceon_cmd);
	unregister_event_command(&trigger_traceoff_cmd);
}

static void
event_enable_trigger(struct event_trigger_data *data,
		     struct trace_buffer *buffer,  void *rec,
		     struct ring_buffer_event *event)
{
	struct enable_trigger_data *enable_data = data->private_data;

	if (enable_data->enable)
		clear_bit(EVENT_FILE_FL_SOFT_DISABLED_BIT, &enable_data->file->flags);
	else
		set_bit(EVENT_FILE_FL_SOFT_DISABLED_BIT, &enable_data->file->flags);
}

static void
event_enable_count_trigger(struct event_trigger_data *data,
			   struct trace_buffer *buffer,  void *rec,
			   struct ring_buffer_event *event)
{
	struct enable_trigger_data *enable_data = data->private_data;

	if (!data->count)
		return;

	/* Skip if the event is in a state we want to switch to */
	if (enable_data->enable == !(enable_data->file->flags & EVENT_FILE_FL_SOFT_DISABLED))
		return;

	if (data->count != -1)
		(data->count)--;

	event_enable_trigger(data, buffer, rec, event);
}

int event_enable_trigger_print(struct seq_file *m,
			       struct event_trigger_data *data)
{
	struct enable_trigger_data *enable_data = data->private_data;

	seq_printf(m, "%s:%s:%s",
		   enable_data->hist ?
		   (enable_data->enable ? ENABLE_HIST_STR : DISABLE_HIST_STR) :
		   (enable_data->enable ? ENABLE_EVENT_STR : DISABLE_EVENT_STR),
		   enable_data->file->event_call->class->system,
		   trace_event_name(enable_data->file->event_call));

	if (data->count == -1)
		seq_puts(m, ":unlimited");
	else
		seq_printf(m, ":count=%ld", data->count);

	if (data->filter_str)
		seq_printf(m, " if %s\n", data->filter_str);
	else
		seq_putc(m, '\n');

	return 0;
}

void event_enable_trigger_free(struct event_trigger_data *data)
{
	struct enable_trigger_data *enable_data = data->private_data;

	if (WARN_ON_ONCE(data->ref <= 0))
		return;

	data->ref--;
	if (!data->ref) {
		/* Remove the SOFT_MODE flag */
		trace_event_enable_disable(enable_data->file, 0, 1);
		trace_event_put_ref(enable_data->file->event_call);
		trigger_data_free(data);
		kfree(enable_data);
	}
}

static struct event_trigger_ops event_enable_trigger_ops = {
	.trigger		= event_enable_trigger,
	.print			= event_enable_trigger_print,
	.init			= event_trigger_init,
	.free			= event_enable_trigger_free,
};

static struct event_trigger_ops event_enable_count_trigger_ops = {
	.trigger		= event_enable_count_trigger,
	.print			= event_enable_trigger_print,
	.init			= event_trigger_init,
	.free			= event_enable_trigger_free,
};

static struct event_trigger_ops event_disable_trigger_ops = {
	.trigger		= event_enable_trigger,
	.print			= event_enable_trigger_print,
	.init			= event_trigger_init,
	.free			= event_enable_trigger_free,
};

static struct event_trigger_ops event_disable_count_trigger_ops = {
	.trigger		= event_enable_count_trigger,
	.print			= event_enable_trigger_print,
	.init			= event_trigger_init,
	.free			= event_enable_trigger_free,
};

int event_enable_trigger_parse(struct event_command *cmd_ops,
			       struct trace_event_file *file,
			       char *glob, char *cmd, char *param_and_filter)
{
	struct trace_event_file *event_enable_file;
	struct enable_trigger_data *enable_data;
	struct event_trigger_data *trigger_data;
	struct trace_array *tr = file->tr;
	char *param, *filter;
	bool enable, remove;
	const char *system;
	const char *event;
	bool hist = false;
	int ret;

	remove = event_trigger_check_remove(glob);

	if (event_trigger_empty_param(param_and_filter))
		return -EINVAL;

	ret = event_trigger_separate_filter(param_and_filter, &param, &filter, true);
	if (ret)
		return ret;

	system = strsep(&param, ":");
	if (!param)
		return -EINVAL;

	event = strsep(&param, ":");

	ret = -EINVAL;
	event_enable_file = find_event_file(tr, system, event);
	if (!event_enable_file)
		goto out;

#ifdef CONFIG_HIST_TRIGGERS
	hist = ((strcmp(cmd, ENABLE_HIST_STR) == 0) ||
		(strcmp(cmd, DISABLE_HIST_STR) == 0));

	enable = ((strcmp(cmd, ENABLE_EVENT_STR) == 0) ||
		  (strcmp(cmd, ENABLE_HIST_STR) == 0));
#else
	enable = strcmp(cmd, ENABLE_EVENT_STR) == 0;
#endif
	ret = -ENOMEM;

	enable_data = kzalloc(sizeof(*enable_data), GFP_KERNEL);
	if (!enable_data)
		goto out;

	enable_data->hist = hist;
	enable_data->enable = enable;
	enable_data->file = event_enable_file;

	trigger_data = event_trigger_alloc(cmd_ops, cmd, param, enable_data);
	if (!trigger_data) {
		kfree(enable_data);
		goto out;
	}

	if (remove) {
		event_trigger_unregister(cmd_ops, file, glob+1, trigger_data);
		kfree(trigger_data);
		kfree(enable_data);
		ret = 0;
		goto out;
	}

	/* Up the trigger_data count to make sure nothing frees it on failure */
	event_trigger_init(trigger_data);

	ret = event_trigger_parse_num(param, trigger_data);
	if (ret)
		goto out_free;

	ret = event_trigger_set_filter(cmd_ops, file, filter, trigger_data);
	if (ret < 0)
		goto out_free;

	/* Don't let event modules unload while probe registered */
	ret = trace_event_try_get_ref(event_enable_file->event_call);
	if (!ret) {
		ret = -EBUSY;
		goto out_free;
	}

	ret = trace_event_enable_disable(event_enable_file, 1, 1);
	if (ret < 0)
		goto out_put;

	ret = event_trigger_register(cmd_ops, file, glob, trigger_data);
	if (ret)
		goto out_disable;

	event_trigger_free(trigger_data);
 out:
	return ret;
 out_disable:
	trace_event_enable_disable(event_enable_file, 0, 1);
 out_put:
	trace_event_put_ref(event_enable_file->event_call);
 out_free:
	event_trigger_reset_filter(cmd_ops, trigger_data);
	event_trigger_free(trigger_data);
	kfree(enable_data);

	goto out;
}

int event_enable_register_trigger(char *glob,
				  struct event_trigger_data *data,
				  struct trace_event_file *file)
{
	struct enable_trigger_data *enable_data = data->private_data;
	struct enable_trigger_data *test_enable_data;
	struct event_trigger_data *test;
	int ret = 0;

	lockdep_assert_held(&event_mutex);

	list_for_each_entry(test, &file->triggers, list) {
		test_enable_data = test->private_data;
		if (test_enable_data &&
		    (test->cmd_ops->trigger_type ==
		     data->cmd_ops->trigger_type) &&
		    (test_enable_data->file == enable_data->file)) {
			ret = -EEXIST;
			goto out;
		}
	}

	if (data->ops->init) {
		ret = data->ops->init(data);
		if (ret < 0)
			goto out;
	}

	list_add_rcu(&data->list, &file->triggers);

	update_cond_flag(file);
	ret = trace_event_trigger_enable_disable(file, 1);
	if (ret < 0) {
		list_del_rcu(&data->list);
		update_cond_flag(file);
	}
out:
	return ret;
}

void event_enable_unregister_trigger(char *glob,
				     struct event_trigger_data *test,
				     struct trace_event_file *file)
{
	struct enable_trigger_data *test_enable_data = test->private_data;
	struct event_trigger_data *data = NULL, *iter;
	struct enable_trigger_data *enable_data;

	lockdep_assert_held(&event_mutex);

	list_for_each_entry(iter, &file->triggers, list) {
		enable_data = iter->private_data;
		if (enable_data &&
		    (iter->cmd_ops->trigger_type ==
		     test->cmd_ops->trigger_type) &&
		    (enable_data->file == test_enable_data->file)) {
			data = iter;
			list_del_rcu(&data->list);
			trace_event_trigger_enable_disable(file, 0);
			update_cond_flag(file);
			break;
		}
	}

	if (data && data->ops->free)
		data->ops->free(data);
}

static struct event_trigger_ops *
event_enable_get_trigger_ops(char *cmd, char *param)
{
	struct event_trigger_ops *ops;
	bool enable;

#ifdef CONFIG_HIST_TRIGGERS
	enable = ((strcmp(cmd, ENABLE_EVENT_STR) == 0) ||
		  (strcmp(cmd, ENABLE_HIST_STR) == 0));
#else
	enable = strcmp(cmd, ENABLE_EVENT_STR) == 0;
#endif
	if (enable)
		ops = param ? &event_enable_count_trigger_ops :
			&event_enable_trigger_ops;
	else
		ops = param ? &event_disable_count_trigger_ops :
			&event_disable_trigger_ops;

	return ops;
}

static struct event_command trigger_enable_cmd = {
	.name			= ENABLE_EVENT_STR,
	.trigger_type		= ETT_EVENT_ENABLE,
	.parse			= event_enable_trigger_parse,
	.reg			= event_enable_register_trigger,
	.unreg			= event_enable_unregister_trigger,
	.get_trigger_ops	= event_enable_get_trigger_ops,
	.set_filter		= set_trigger_filter,
};

static struct event_command trigger_disable_cmd = {
	.name			= DISABLE_EVENT_STR,
	.trigger_type		= ETT_EVENT_ENABLE,
	.parse			= event_enable_trigger_parse,
	.reg			= event_enable_register_trigger,
	.unreg			= event_enable_unregister_trigger,
	.get_trigger_ops	= event_enable_get_trigger_ops,
	.set_filter		= set_trigger_filter,
};

static __init void unregister_trigger_enable_disable_cmds(void)
{
	unregister_event_command(&trigger_enable_cmd);
	unregister_event_command(&trigger_disable_cmd);
}

static __init int register_trigger_enable_disable_cmds(void)
{
	int ret;

	ret = register_event_command(&trigger_enable_cmd);
	if (WARN_ON(ret < 0))
		return ret;
	ret = register_event_command(&trigger_disable_cmd);
	if (WARN_ON(ret < 0))
		unregister_trigger_enable_disable_cmds();

	return ret;
}

static __init int register_trigger_traceon_traceoff_cmds(void)
{
	int ret;

	ret = register_event_command(&trigger_traceon_cmd);
	if (WARN_ON(ret < 0))
		return ret;
	ret = register_event_command(&trigger_traceoff_cmd);
	if (WARN_ON(ret < 0))
		unregister_trigger_traceon_traceoff_cmds();

	return ret;
}

__init int register_trigger_cmds(void)
{
	register_trigger_traceon_traceoff_cmds();
	register_trigger_snapshot_cmd();
	register_trigger_stacktrace_cmd();
	register_trigger_enable_disable_cmds();
	register_trigger_hist_enable_disable_cmds();
	register_trigger_hist_cmd();

	return 0;
}
