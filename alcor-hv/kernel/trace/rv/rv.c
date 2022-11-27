
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>

#ifdef CONFIG_DA_MON_EVENTS
#define CREATE_TRACE_POINTS
#include <trace/events/rv.h>
#endif

#include "rv.h"

DEFINE_MUTEX(rv_interface_lock);

static struct rv_interface rv_root;

struct dentry *get_monitors_root(void)
{
	return rv_root.monitors_dir;
}

static LIST_HEAD(rv_monitors_list);

static int task_monitor_count;
static bool task_monitor_slots[RV_PER_TASK_MONITORS];

int rv_get_task_monitor_slot(void)
{
	int i;

	lockdep_assert_held(&rv_interface_lock);

	if (task_monitor_count == RV_PER_TASK_MONITORS)
		return -EBUSY;

	task_monitor_count++;

	for (i = 0; i < RV_PER_TASK_MONITORS; i++) {
		if (task_monitor_slots[i] == false) {
			task_monitor_slots[i] = true;
			return i;
		}
	}

	WARN_ONCE(1, "RV task_monitor_count and slots are out of sync\n");

	return -EINVAL;
}

void rv_put_task_monitor_slot(int slot)
{
	lockdep_assert_held(&rv_interface_lock);

	if (slot < 0 || slot >= RV_PER_TASK_MONITORS) {
		WARN_ONCE(1, "RV releasing an invalid slot!: %d\n", slot);
		return;
	}

	WARN_ONCE(!task_monitor_slots[slot], "RV releasing unused task_monitor_slots: %d\n",
		  slot);

	task_monitor_count--;
	task_monitor_slots[slot] = false;
}

static ssize_t monitor_enable_read_data(struct file *filp, char __user *user_buf, size_t count,
					loff_t *ppos)
{
	struct rv_monitor_def *mdef = filp->private_data;
	const char *buff;

	buff = mdef->monitor->enabled ? "1\n" : "0\n";

	return simple_read_from_buffer(user_buf, count, ppos, buff, strlen(buff)+1);
}

static int __rv_disable_monitor(struct rv_monitor_def *mdef, bool sync)
{
	lockdep_assert_held(&rv_interface_lock);

	if (mdef->monitor->enabled) {
		mdef->monitor->enabled = 0;
		mdef->monitor->disable();

		/*
		if (sync)
			tracepoint_synchronize_unregister();
		return 1;
	}
	return 0;
}

int rv_disable_monitor(struct rv_monitor_def *mdef)
{
	__rv_disable_monitor(mdef, true);
	return 0;
}

int rv_enable_monitor(struct rv_monitor_def *mdef)
{
	int retval;

	lockdep_assert_held(&rv_interface_lock);

	if (mdef->monitor->enabled)
		return 0;

	retval = mdef->monitor->enable();

	if (!retval)
		mdef->monitor->enabled = 1;

	return retval;
}

static ssize_t monitor_enable_write_data(struct file *filp, const char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	struct rv_monitor_def *mdef = filp->private_data;
	int retval;
	bool val;

	retval = kstrtobool_from_user(user_buf, count, &val);
	if (retval)
		return retval;

	retval = count;

	mutex_lock(&rv_interface_lock);

	if (val)
		retval = rv_enable_monitor(mdef);
	else
		retval = rv_disable_monitor(mdef);

	mutex_unlock(&rv_interface_lock);

	return retval ? : count;
}

static const struct file_operations interface_enable_fops = {
	.open   = simple_open,
	.llseek = no_llseek,
	.write  = monitor_enable_write_data,
	.read   = monitor_enable_read_data,
};

static ssize_t monitor_desc_read_data(struct file *filp, char __user *user_buf, size_t count,
				      loff_t *ppos)
{
	struct rv_monitor_def *mdef = filp->private_data;
	char buff[256];

	memset(buff, 0, sizeof(buff));

	snprintf(buff, sizeof(buff), "%s\n", mdef->monitor->description);

	return simple_read_from_buffer(user_buf, count, ppos, buff, strlen(buff) + 1);
}

static const struct file_operations interface_desc_fops = {
	.open   = simple_open,
	.llseek	= no_llseek,
	.read	= monitor_desc_read_data,
};

static int create_monitor_dir(struct rv_monitor_def *mdef)
{
	struct dentry *root = get_monitors_root();
	const char *name = mdef->monitor->name;
	struct dentry *tmp;
	int retval;

	mdef->root_d = rv_create_dir(name, root);
	if (!mdef->root_d)
		return -ENOMEM;

	tmp = rv_create_file("enable", RV_MODE_WRITE, mdef->root_d, mdef, &interface_enable_fops);
	if (!tmp) {
		retval = -ENOMEM;
		goto out_remove_root;
	}

	tmp = rv_create_file("desc", RV_MODE_READ, mdef->root_d, mdef, &interface_desc_fops);
	if (!tmp) {
		retval = -ENOMEM;
		goto out_remove_root;
	}

	retval = reactor_populate_monitor(mdef);
	if (retval)
		goto out_remove_root;

	return 0;

out_remove_root:
	rv_remove(mdef->root_d);
	return retval;
}

static int monitors_show(struct seq_file *m, void *p)
{
	struct rv_monitor_def *mon_def = p;

	seq_printf(m, "%s\n", mon_def->monitor->name);
	return 0;
}

static void monitors_stop(struct seq_file *m, void *p)
{
	mutex_unlock(&rv_interface_lock);
}

static void *available_monitors_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&rv_interface_lock);
	return seq_list_start(&rv_monitors_list, *pos);
}

static void *available_monitors_next(struct seq_file *m, void *p, loff_t *pos)
{
	return seq_list_next(p, &rv_monitors_list, pos);
}

static void *enabled_monitors_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct rv_monitor_def *m_def = p;

	(*pos)++;

	list_for_each_entry_continue(m_def, &rv_monitors_list, list) {
		if (m_def->monitor->enabled)
			return m_def;
	}

	return NULL;
}

static void *enabled_monitors_start(struct seq_file *m, loff_t *pos)
{
	struct rv_monitor_def *m_def;
	loff_t l;

	mutex_lock(&rv_interface_lock);

	if (list_empty(&rv_monitors_list))
		return NULL;

	m_def = list_entry(&rv_monitors_list, struct rv_monitor_def, list);

	for (l = 0; l <= *pos; ) {
		m_def = enabled_monitors_next(m, m_def, &l);
		if (!m_def)
			break;
	}

	return m_def;
}

static const struct seq_operations available_monitors_seq_ops = {
	.start	= available_monitors_start,
	.next	= available_monitors_next,
	.stop	= monitors_stop,
	.show	= monitors_show
};

static const struct seq_operations enabled_monitors_seq_ops = {
	.start  = enabled_monitors_start,
	.next   = enabled_monitors_next,
	.stop   = monitors_stop,
	.show   = monitors_show
};

static int available_monitors_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &available_monitors_seq_ops);
};

static const struct file_operations available_monitors_ops = {
	.open    = available_monitors_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

static void disable_all_monitors(void)
{
	struct rv_monitor_def *mdef;
	int enabled = 0;

	mutex_lock(&rv_interface_lock);

	list_for_each_entry(mdef, &rv_monitors_list, list)
		enabled += __rv_disable_monitor(mdef, false);

	if (enabled) {
		/*
		tracepoint_synchronize_unregister();
	}

	mutex_unlock(&rv_interface_lock);
}

static int enabled_monitors_open(struct inode *inode, struct file *file)
{
	if ((file->f_mode & FMODE_WRITE) && (file->f_flags & O_TRUNC))
		disable_all_monitors();

	return seq_open(file, &enabled_monitors_seq_ops);
};

static ssize_t enabled_monitors_write(struct file *filp, const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	char buff[MAX_RV_MONITOR_NAME_SIZE + 2];
	struct rv_monitor_def *mdef;
	int retval = -EINVAL;
	bool enable = true;
	char *ptr = buff;
	int len;

	if (count < 1 || count > MAX_RV_MONITOR_NAME_SIZE + 1)
		return -EINVAL;

	memset(buff, 0, sizeof(buff));

	retval = simple_write_to_buffer(buff, sizeof(buff) - 1, ppos, user_buf, count);
	if (retval < 0)
		return -EFAULT;

	ptr = strim(buff);

	if (ptr[0] == '!') {
		enable = false;
		ptr++;
	}

	len = strlen(ptr);
	if (!len)
		return count;

	mutex_lock(&rv_interface_lock);

	retval = -EINVAL;

	list_for_each_entry(mdef, &rv_monitors_list, list) {
		if (strcmp(ptr, mdef->monitor->name) != 0)
			continue;

		/*
		if (enable)
			retval = rv_enable_monitor(mdef);
		else
			retval = rv_disable_monitor(mdef);

		if (!retval)
			retval = count;

		break;
	}

	mutex_unlock(&rv_interface_lock);
	return retval;
}

static const struct file_operations enabled_monitors_ops = {
	.open		= enabled_monitors_open,
	.read		= seq_read,
	.write		= enabled_monitors_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static bool __read_mostly monitoring_on;

bool rv_monitoring_on(void)
{
	/* Ensures that concurrent monitors read consistent monitoring_on */
	smp_rmb();
	return READ_ONCE(monitoring_on);
}

static ssize_t monitoring_on_read_data(struct file *filp, char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	const char *buff;

	buff = rv_monitoring_on() ? "1\n" : "0\n";

	return simple_read_from_buffer(user_buf, count, ppos, buff, strlen(buff) + 1);
}

static void turn_monitoring_off(void)
{
	WRITE_ONCE(monitoring_on, false);
	/* Ensures that concurrent monitors read consistent monitoring_on */
	smp_wmb();
}

static void reset_all_monitors(void)
{
	struct rv_monitor_def *mdef;

	list_for_each_entry(mdef, &rv_monitors_list, list) {
		if (mdef->monitor->enabled)
			mdef->monitor->reset();
	}
}

static void turn_monitoring_on(void)
{
	WRITE_ONCE(monitoring_on, true);
	/* Ensures that concurrent monitors read consistent monitoring_on */
	smp_wmb();
}

static void turn_monitoring_on_with_reset(void)
{
	lockdep_assert_held(&rv_interface_lock);

	if (rv_monitoring_on())
		return;

	/*
	reset_all_monitors();
	turn_monitoring_on();
}

static ssize_t monitoring_on_write_data(struct file *filp, const char __user *user_buf,
					size_t count, loff_t *ppos)
{
	int retval;
	bool val;

	retval = kstrtobool_from_user(user_buf, count, &val);
	if (retval)
		return retval;

	mutex_lock(&rv_interface_lock);

	if (val)
		turn_monitoring_on_with_reset();
	else
		turn_monitoring_off();

	/*
	tracepoint_synchronize_unregister();

	mutex_unlock(&rv_interface_lock);

	return count;
}

static const struct file_operations monitoring_on_fops = {
	.open   = simple_open,
	.llseek = no_llseek,
	.write  = monitoring_on_write_data,
	.read   = monitoring_on_read_data,
};

static void destroy_monitor_dir(struct rv_monitor_def *mdef)
{
	reactor_cleanup_monitor(mdef);
	rv_remove(mdef->root_d);
}

int rv_register_monitor(struct rv_monitor *monitor)
{
	struct rv_monitor_def *r;
	int retval = 0;

	if (strlen(monitor->name) >= MAX_RV_MONITOR_NAME_SIZE) {
		pr_info("Monitor %s has a name longer than %d\n", monitor->name,
			MAX_RV_MONITOR_NAME_SIZE);
		return -1;
	}

	mutex_lock(&rv_interface_lock);

	list_for_each_entry(r, &rv_monitors_list, list) {
		if (strcmp(monitor->name, r->monitor->name) == 0) {
			pr_info("Monitor %s is already registered\n", monitor->name);
			retval = -1;
			goto out_unlock;
		}
	}

	r = kzalloc(sizeof(struct rv_monitor_def), GFP_KERNEL);
	if (!r) {
		retval = -ENOMEM;
		goto out_unlock;
	}

	r->monitor = monitor;

	retval = create_monitor_dir(r);
	if (retval) {
		kfree(r);
		goto out_unlock;
	}

	list_add_tail(&r->list, &rv_monitors_list);

out_unlock:
	mutex_unlock(&rv_interface_lock);
	return retval;
}

int rv_unregister_monitor(struct rv_monitor *monitor)
{
	struct rv_monitor_def *ptr, *next;

	mutex_lock(&rv_interface_lock);

	list_for_each_entry_safe(ptr, next, &rv_monitors_list, list) {
		if (strcmp(monitor->name, ptr->monitor->name) == 0) {
			rv_disable_monitor(ptr);
			list_del(&ptr->list);
			destroy_monitor_dir(ptr);
		}
	}

	mutex_unlock(&rv_interface_lock);
	return 0;
}

int __init rv_init_interface(void)
{
	struct dentry *tmp;
	int retval;

	rv_root.root_dir = rv_create_dir("rv", NULL);
	if (!rv_root.root_dir)
		goto out_err;

	rv_root.monitors_dir = rv_create_dir("monitors", rv_root.root_dir);
	if (!rv_root.monitors_dir)
		goto out_err;

	tmp = rv_create_file("available_monitors", RV_MODE_READ, rv_root.root_dir, NULL,
			     &available_monitors_ops);
	if (!tmp)
		goto out_err;

	tmp = rv_create_file("enabled_monitors", RV_MODE_WRITE, rv_root.root_dir, NULL,
			     &enabled_monitors_ops);
	if (!tmp)
		goto out_err;

	tmp = rv_create_file("monitoring_on", RV_MODE_WRITE, rv_root.root_dir, NULL,
			     &monitoring_on_fops);
	if (!tmp)
		goto out_err;
	retval = init_rv_reactors(rv_root.root_dir);
	if (retval)
		goto out_err;

	turn_monitoring_on();

	return 0;

out_err:
	rv_remove(rv_root.root_dir);
	printk(KERN_ERR "RV: Error while creating the RV interface\n");
	return 1;
}
