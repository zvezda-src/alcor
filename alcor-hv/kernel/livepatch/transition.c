
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpu.h>
#include <linux/stacktrace.h>
#include "core.h"
#include "patch.h"
#include "transition.h"

#define MAX_STACK_ENTRIES  100
#define STACK_ERR_BUF_SIZE 128

#define SIGNALS_TIMEOUT 15

struct klp_patch *klp_transition_patch;

static int klp_target_state = KLP_UNDEFINED;

static unsigned int klp_signals_cnt;

static void klp_transition_work_fn(struct work_struct *work)
{
	mutex_lock(&klp_mutex);

	if (klp_transition_patch)
		klp_try_complete_transition();

	mutex_unlock(&klp_mutex);
}
static DECLARE_DELAYED_WORK(klp_transition_work, klp_transition_work_fn);

static void klp_sync(struct work_struct *work)
{
}

static void klp_synchronize_transition(void)
{
	schedule_on_each_cpu(klp_sync);
}

static void klp_complete_transition(void)
{
	struct klp_object *obj;
	struct klp_func *func;
	struct task_struct *g, *task;
	unsigned int cpu;

	pr_debug("'%s': completing %s transition\n",
		 klp_transition_patch->mod->name,
		 klp_target_state == KLP_PATCHED ? "patching" : "unpatching");

	if (klp_transition_patch->replace && klp_target_state == KLP_PATCHED) {
		klp_unpatch_replaced_patches(klp_transition_patch);
		klp_discard_nops(klp_transition_patch);
	}

	if (klp_target_state == KLP_UNPATCHED) {
		/*
		klp_unpatch_objects(klp_transition_patch);

		/*
		klp_synchronize_transition();
	}

	klp_for_each_object(klp_transition_patch, obj)
		klp_for_each_func(obj, func)
			func->transition = false;

	/* Prevent klp_ftrace_handler() from seeing KLP_UNDEFINED state */
	if (klp_target_state == KLP_PATCHED)
		klp_synchronize_transition();

	read_lock(&tasklist_lock);
	for_each_process_thread(g, task) {
		WARN_ON_ONCE(test_tsk_thread_flag(task, TIF_PATCH_PENDING));
		task->patch_state = KLP_UNDEFINED;
	}
	read_unlock(&tasklist_lock);

	for_each_possible_cpu(cpu) {
		task = idle_task(cpu);
		WARN_ON_ONCE(test_tsk_thread_flag(task, TIF_PATCH_PENDING));
		task->patch_state = KLP_UNDEFINED;
	}

	klp_for_each_object(klp_transition_patch, obj) {
		if (!klp_is_object_loaded(obj))
			continue;
		if (klp_target_state == KLP_PATCHED)
			klp_post_patch_callback(obj);
		else if (klp_target_state == KLP_UNPATCHED)
			klp_post_unpatch_callback(obj);
	}

	pr_notice("'%s': %s complete\n", klp_transition_patch->mod->name,
		  klp_target_state == KLP_PATCHED ? "patching" : "unpatching");

	klp_target_state = KLP_UNDEFINED;
	klp_transition_patch = NULL;
}

void klp_cancel_transition(void)
{
	if (WARN_ON_ONCE(klp_target_state != KLP_PATCHED))
		return;

	pr_debug("'%s': canceling patching transition, going to unpatch\n",
		 klp_transition_patch->mod->name);

	klp_target_state = KLP_UNPATCHED;
	klp_complete_transition();
}

void klp_update_patch_state(struct task_struct *task)
{
	/*
	preempt_disable_notrace();

	/*
	if (test_and_clear_tsk_thread_flag(task, TIF_PATCH_PENDING))
		task->patch_state = READ_ONCE(klp_target_state);

	preempt_enable_notrace();
}

static int klp_check_stack_func(struct klp_func *func, unsigned long *entries,
				unsigned int nr_entries)
{
	unsigned long func_addr, func_size, address;
	struct klp_ops *ops;
	int i;

	for (i = 0; i < nr_entries; i++) {
		address = entries[i];

		if (klp_target_state == KLP_UNPATCHED) {
			 /*
			func_addr = (unsigned long)func->new_func;
			func_size = func->new_size;
		} else {
			/*
			ops = klp_find_ops(func->old_func);

			if (list_is_singular(&ops->func_stack)) {
				/* original function */
				func_addr = (unsigned long)func->old_func;
				func_size = func->old_size;
			} else {
				/* previously patched function */
				struct klp_func *prev;

				prev = list_next_entry(func, stack_node);
				func_addr = (unsigned long)prev->new_func;
				func_size = prev->new_size;
			}
		}

		if (address >= func_addr && address < func_addr + func_size)
			return -EAGAIN;
	}

	return 0;
}

static int klp_check_stack(struct task_struct *task, const char **oldname)
{
	static unsigned long entries[MAX_STACK_ENTRIES];
	struct klp_object *obj;
	struct klp_func *func;
	int ret, nr_entries;

	ret = stack_trace_save_tsk_reliable(task, entries, ARRAY_SIZE(entries));
	if (ret < 0)
		return -EINVAL;
	nr_entries = ret;

	klp_for_each_object(klp_transition_patch, obj) {
		if (!obj->patched)
			continue;
		klp_for_each_func(obj, func) {
			ret = klp_check_stack_func(func, entries, nr_entries);
			if (ret) {
				*oldname = func->old_name;
				return -EADDRINUSE;
			}
		}
	}

	return 0;
}

static int klp_check_and_switch_task(struct task_struct *task, void *arg)
{
	int ret;

	if (task_curr(task) && task != current)
		return -EBUSY;

	ret = klp_check_stack(task, arg);
	if (ret)
		return ret;

	clear_tsk_thread_flag(task, TIF_PATCH_PENDING);
	task->patch_state = klp_target_state;
	return 0;
}

static bool klp_try_switch_task(struct task_struct *task)
{
	const char *old_name;
	int ret;

	/* check if this task has already switched over */
	if (task->patch_state == klp_target_state)
		return true;

	/*
	if (!klp_have_reliable_stack())
		return false;

	/*
	ret = task_call_func(task, klp_check_and_switch_task, &old_name);
	switch (ret) {
	case 0:		/* success */
		break;

	case -EBUSY:	/* klp_check_and_switch_task() */
		pr_debug("%s: %s:%d is running\n",
			 __func__, task->comm, task->pid);
		break;
	case -EINVAL:	/* klp_check_and_switch_task() */
		pr_debug("%s: %s:%d has an unreliable stack\n",
			 __func__, task->comm, task->pid);
		break;
	case -EADDRINUSE: /* klp_check_and_switch_task() */
		pr_debug("%s: %s:%d is sleeping on function %s\n",
			 __func__, task->comm, task->pid, old_name);
		break;

	default:
		pr_debug("%s: Unknown error code (%d) when trying to switch %s:%d\n",
			 __func__, ret, task->comm, task->pid);
		break;
	}

	return !ret;
}

static void klp_send_signals(void)
{
	struct task_struct *g, *task;

	if (klp_signals_cnt == SIGNALS_TIMEOUT)
		pr_notice("signaling remaining tasks\n");

	read_lock(&tasklist_lock);
	for_each_process_thread(g, task) {
		if (!klp_patch_pending(task))
			continue;

		/*
		if (task->flags & PF_KTHREAD) {
			/*
			wake_up_state(task, TASK_INTERRUPTIBLE);
		} else {
			/*
			set_notify_signal(task);
		}
	}
	read_unlock(&tasklist_lock);
}

void klp_try_complete_transition(void)
{
	unsigned int cpu;
	struct task_struct *g, *task;
	struct klp_patch *patch;
	bool complete = true;

	WARN_ON_ONCE(klp_target_state == KLP_UNDEFINED);

	/*
	read_lock(&tasklist_lock);
	for_each_process_thread(g, task)
		if (!klp_try_switch_task(task))
			complete = false;
	read_unlock(&tasklist_lock);

	/*
	cpus_read_lock();
	for_each_possible_cpu(cpu) {
		task = idle_task(cpu);
		if (cpu_online(cpu)) {
			if (!klp_try_switch_task(task)) {
				complete = false;
				/* Make idle task go through the main loop. */
				wake_up_if_idle(cpu);
			}
		} else if (task->patch_state != klp_target_state) {
			/* offline idle tasks can be switched immediately */
			clear_tsk_thread_flag(task, TIF_PATCH_PENDING);
			task->patch_state = klp_target_state;
		}
	}
	cpus_read_unlock();

	if (!complete) {
		if (klp_signals_cnt && !(klp_signals_cnt % SIGNALS_TIMEOUT))
			klp_send_signals();
		klp_signals_cnt++;

		/*
		schedule_delayed_work(&klp_transition_work,
				      round_jiffies_relative(HZ));
		return;
	}

	/* we're done, now cleanup the data structures */
	patch = klp_transition_patch;
	klp_complete_transition();

	/*
	if (!patch->enabled)
		klp_free_patch_async(patch);
	else if (patch->replace)
		klp_free_replaced_patches_async(patch);
}

void klp_start_transition(void)
{
	struct task_struct *g, *task;
	unsigned int cpu;

	WARN_ON_ONCE(klp_target_state == KLP_UNDEFINED);

	pr_notice("'%s': starting %s transition\n",
		  klp_transition_patch->mod->name,
		  klp_target_state == KLP_PATCHED ? "patching" : "unpatching");

	/*
	read_lock(&tasklist_lock);
	for_each_process_thread(g, task)
		if (task->patch_state != klp_target_state)
			set_tsk_thread_flag(task, TIF_PATCH_PENDING);
	read_unlock(&tasklist_lock);

	/*
	for_each_possible_cpu(cpu) {
		task = idle_task(cpu);
		if (task->patch_state != klp_target_state)
			set_tsk_thread_flag(task, TIF_PATCH_PENDING);
	}

	klp_signals_cnt = 0;
}

void klp_init_transition(struct klp_patch *patch, int state)
{
	struct task_struct *g, *task;
	unsigned int cpu;
	struct klp_object *obj;
	struct klp_func *func;
	int initial_state = !state;

	WARN_ON_ONCE(klp_target_state != KLP_UNDEFINED);

	klp_transition_patch = patch;

	/*
	klp_target_state = state;

	pr_debug("'%s': initializing %s transition\n", patch->mod->name,
		 klp_target_state == KLP_PATCHED ? "patching" : "unpatching");

	/*
	read_lock(&tasklist_lock);
	for_each_process_thread(g, task) {
		WARN_ON_ONCE(task->patch_state != KLP_UNDEFINED);
		task->patch_state = initial_state;
	}
	read_unlock(&tasklist_lock);

	/*
	for_each_possible_cpu(cpu) {
		task = idle_task(cpu);
		WARN_ON_ONCE(task->patch_state != KLP_UNDEFINED);
		task->patch_state = initial_state;
	}

	/*
	smp_wmb();

	/*
	klp_for_each_object(patch, obj)
		klp_for_each_func(obj, func)
			func->transition = true;
}

void klp_reverse_transition(void)
{
	unsigned int cpu;
	struct task_struct *g, *task;

	pr_debug("'%s': reversing transition from %s\n",
		 klp_transition_patch->mod->name,
		 klp_target_state == KLP_PATCHED ? "patching to unpatching" :
						   "unpatching to patching");

	klp_transition_patch->enabled = !klp_transition_patch->enabled;

	klp_target_state = !klp_target_state;

	/*
	read_lock(&tasklist_lock);
	for_each_process_thread(g, task)
		clear_tsk_thread_flag(task, TIF_PATCH_PENDING);
	read_unlock(&tasklist_lock);

	for_each_possible_cpu(cpu)
		clear_tsk_thread_flag(idle_task(cpu), TIF_PATCH_PENDING);

	/* Let any remaining calls to klp_update_patch_state() complete */
	klp_synchronize_transition();

	klp_start_transition();
}

void klp_copy_process(struct task_struct *child)
{
	child->patch_state = current->patch_state;

	/* TIF_PATCH_PENDING gets copied in setup_thread_stack() */
}

void klp_force_transition(void)
{
	struct klp_patch *patch;
	struct task_struct *g, *task;
	unsigned int cpu;

	pr_warn("forcing remaining tasks to the patched state\n");

	read_lock(&tasklist_lock);
	for_each_process_thread(g, task)
		klp_update_patch_state(task);
	read_unlock(&tasklist_lock);

	for_each_possible_cpu(cpu)
		klp_update_patch_state(idle_task(cpu));

	/* Set forced flag for patches being removed. */
	if (klp_target_state == KLP_UNPATCHED)
		klp_transition_patch->forced = true;
	else if (klp_transition_patch->replace) {
		klp_for_each_patch(patch) {
			if (patch != klp_transition_patch)
				patch->forced = true;
		}
	}
}
