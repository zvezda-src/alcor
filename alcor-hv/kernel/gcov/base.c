
#define pr_fmt(fmt)	"gcov: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include "gcov.h"

int gcov_events_enabled;
DEFINE_MUTEX(gcov_lock);

void gcov_enable_events(void)
{
	struct gcov_info *info = NULL;

	mutex_lock(&gcov_lock);
	gcov_events_enabled = 1;

	/* Perform event callback for previously registered entries. */
	while ((info = gcov_info_next(info))) {
		gcov_event(GCOV_ADD, info);
		cond_resched();
	}

	mutex_unlock(&gcov_lock);
}

size_t store_gcov_u32(void *buffer, size_t off, u32 v)
{
	u32 *data;

	if (buffer) {
		data = buffer + off;
		*data = v;
	}

	return sizeof(*data);
}

size_t store_gcov_u64(void *buffer, size_t off, u64 v)
{
	u32 *data;

	if (buffer) {
		data = buffer + off;

		data[0] = (v & 0xffffffffUL);
		data[1] = (v >> 32);
	}

	return sizeof(*data) * 2;
}

#ifdef CONFIG_MODULES
static int gcov_module_notifier(struct notifier_block *nb, unsigned long event,
				void *data)
{
	struct module *mod = data;
	struct gcov_info *info = NULL;
	struct gcov_info *prev = NULL;

	if (event != MODULE_STATE_GOING)
		return NOTIFY_OK;
	mutex_lock(&gcov_lock);

	/* Remove entries located in module from linked list. */
	while ((info = gcov_info_next(info))) {
		if (gcov_info_within_module(info, mod)) {
			gcov_info_unlink(prev, info);
			if (gcov_events_enabled)
				gcov_event(GCOV_REMOVE, info);
		} else
			prev = info;
	}

	mutex_unlock(&gcov_lock);

	return NOTIFY_OK;
}

static struct notifier_block gcov_nb = {
	.notifier_call	= gcov_module_notifier,
};

static int __init gcov_init(void)
{
	return register_module_notifier(&gcov_nb);
}
device_initcall(gcov_init);
#endif /* CONFIG_MODULES */
