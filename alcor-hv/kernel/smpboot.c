#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/kthread.h>
#include <linux/smpboot.h>

#include "smpboot.h"

#ifdef CONFIG_SMP

#ifdef CONFIG_GENERIC_SMP_IDLE_THREAD
static DEFINE_PER_CPU(struct task_struct *, idle_threads);

struct task_struct *idle_thread_get(unsigned int cpu)
{
	struct task_struct *tsk = per_cpu(idle_threads, cpu);

	if (!tsk)
		return ERR_PTR(-ENOMEM);
	return tsk;
}

void __init idle_thread_set_boot_cpu(void)
{
	per_cpu(idle_threads, smp_processor_id()) = current;
}

static __always_inline void idle_init(unsigned int cpu)
{
	struct task_struct *tsk = per_cpu(idle_threads, cpu);

	if (!tsk) {
		tsk = fork_idle(cpu);
		if (IS_ERR(tsk))
			pr_err("SMP: fork_idle() failed for CPU %u\n", cpu);
		else
			per_cpu(idle_threads, cpu) = tsk;
	}
}

void __init idle_threads_init(void)
{
	unsigned int cpu, boot_cpu;

	boot_cpu = smp_processor_id();

	for_each_possible_cpu(cpu) {
		if (cpu != boot_cpu)
			idle_init(cpu);
	}
}
#endif

#endif /* #ifdef CONFIG_SMP */

static LIST_HEAD(hotplug_threads);
static DEFINE_MUTEX(smpboot_threads_lock);

struct smpboot_thread_data {
	unsigned int			cpu;
	unsigned int			status;
	struct smp_hotplug_thread	*ht;
};

enum {
	HP_THREAD_NONE = 0,
	HP_THREAD_ACTIVE,
	HP_THREAD_PARKED,
};

static int smpboot_thread_fn(void *data)
{
	struct smpboot_thread_data *td = data;
	struct smp_hotplug_thread *ht = td->ht;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		preempt_disable();
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			/* cleanup must mirror setup */
			if (ht->cleanup && td->status != HP_THREAD_NONE)
				ht->cleanup(td->cpu, cpu_online(td->cpu));
			kfree(td);
			return 0;
		}

		if (kthread_should_park()) {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			if (ht->park && td->status == HP_THREAD_ACTIVE) {
				BUG_ON(td->cpu != smp_processor_id());
				ht->park(td->cpu);
				td->status = HP_THREAD_PARKED;
			}
			kthread_parkme();
			/* We might have been woken for stop */
			continue;
		}

		BUG_ON(td->cpu != smp_processor_id());

		/* Check for state change setup */
		switch (td->status) {
		case HP_THREAD_NONE:
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			if (ht->setup)
				ht->setup(td->cpu);
			td->status = HP_THREAD_ACTIVE;
			continue;

		case HP_THREAD_PARKED:
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			if (ht->unpark)
				ht->unpark(td->cpu);
			td->status = HP_THREAD_ACTIVE;
			continue;
		}

		if (!ht->thread_should_run(td->cpu)) {
			preempt_enable_no_resched();
			schedule();
		} else {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			ht->thread_fn(td->cpu);
		}
	}
}

static int
__smpboot_create_thread(struct smp_hotplug_thread *ht, unsigned int cpu)
{
	struct task_struct *tsk = *per_cpu_ptr(ht->store, cpu);
	struct smpboot_thread_data *td;

	if (tsk)
		return 0;

	td = kzalloc_node(sizeof(*td), GFP_KERNEL, cpu_to_node(cpu));
	if (!td)
		return -ENOMEM;
	td->cpu = cpu;
	td->ht = ht;

	tsk = kthread_create_on_cpu(smpboot_thread_fn, td, cpu,
				    ht->thread_comm);
	if (IS_ERR(tsk)) {
		kfree(td);
		return PTR_ERR(tsk);
	}
	kthread_set_per_cpu(tsk, cpu);
	/*
	kthread_park(tsk);
	get_task_struct(tsk);
	if (ht->create) {
		/*
		if (!wait_task_inactive(tsk, TASK_PARKED))
			WARN_ON(1);
		else
			ht->create(cpu);
	}
	return 0;
}

int smpboot_create_threads(unsigned int cpu)
{
	struct smp_hotplug_thread *cur;
	int ret = 0;

	mutex_lock(&smpboot_threads_lock);
	list_for_each_entry(cur, &hotplug_threads, list) {
		ret = __smpboot_create_thread(cur, cpu);
		if (ret)
			break;
	}
	mutex_unlock(&smpboot_threads_lock);
	return ret;
}

static void smpboot_unpark_thread(struct smp_hotplug_thread *ht, unsigned int cpu)
{
	struct task_struct *tsk = *per_cpu_ptr(ht->store, cpu);

	if (!ht->selfparking)
		kthread_unpark(tsk);
}

int smpboot_unpark_threads(unsigned int cpu)
{
	struct smp_hotplug_thread *cur;

	mutex_lock(&smpboot_threads_lock);
	list_for_each_entry(cur, &hotplug_threads, list)
		smpboot_unpark_thread(cur, cpu);
	mutex_unlock(&smpboot_threads_lock);
	return 0;
}

static void smpboot_park_thread(struct smp_hotplug_thread *ht, unsigned int cpu)
{
	struct task_struct *tsk = *per_cpu_ptr(ht->store, cpu);

	if (tsk && !ht->selfparking)
		kthread_park(tsk);
}

int smpboot_park_threads(unsigned int cpu)
{
	struct smp_hotplug_thread *cur;

	mutex_lock(&smpboot_threads_lock);
	list_for_each_entry_reverse(cur, &hotplug_threads, list)
		smpboot_park_thread(cur, cpu);
	mutex_unlock(&smpboot_threads_lock);
	return 0;
}

static void smpboot_destroy_threads(struct smp_hotplug_thread *ht)
{
	unsigned int cpu;

	/* We need to destroy also the parked threads of offline cpus */
	for_each_possible_cpu(cpu) {
		struct task_struct *tsk = *per_cpu_ptr(ht->store, cpu);

		if (tsk) {
			kthread_stop(tsk);
			put_task_struct(tsk);
			*per_cpu_ptr(ht->store, cpu) = NULL;
		}
	}
}

int smpboot_register_percpu_thread(struct smp_hotplug_thread *plug_thread)
{
	unsigned int cpu;
	int ret = 0;

	cpus_read_lock();
	mutex_lock(&smpboot_threads_lock);
	for_each_online_cpu(cpu) {
		ret = __smpboot_create_thread(plug_thread, cpu);
		if (ret) {
			smpboot_destroy_threads(plug_thread);
			goto out;
		}
		smpboot_unpark_thread(plug_thread, cpu);
	}
	list_add(&plug_thread->list, &hotplug_threads);
out:
	mutex_unlock(&smpboot_threads_lock);
	cpus_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(smpboot_register_percpu_thread);

void smpboot_unregister_percpu_thread(struct smp_hotplug_thread *plug_thread)
{
	cpus_read_lock();
	mutex_lock(&smpboot_threads_lock);
	list_del(&plug_thread->list);
	smpboot_destroy_threads(plug_thread);
	mutex_unlock(&smpboot_threads_lock);
	cpus_read_unlock();
}
EXPORT_SYMBOL_GPL(smpboot_unregister_percpu_thread);

static DEFINE_PER_CPU(atomic_t, cpu_hotplug_state) = ATOMIC_INIT(CPU_POST_DEAD);

int cpu_report_state(int cpu)
{
	return atomic_read(&per_cpu(cpu_hotplug_state, cpu));
}

int cpu_check_up_prepare(int cpu)
{
	if (!IS_ENABLED(CONFIG_HOTPLUG_CPU)) {
		atomic_set(&per_cpu(cpu_hotplug_state, cpu), CPU_UP_PREPARE);
		return 0;
	}

	switch (atomic_read(&per_cpu(cpu_hotplug_state, cpu))) {

	case CPU_POST_DEAD:

		/* The CPU died properly, so just start it up again. */
		atomic_set(&per_cpu(cpu_hotplug_state, cpu), CPU_UP_PREPARE);
		return 0;

	case CPU_DEAD_FROZEN:

		/*
		return -EBUSY;

	case CPU_BROKEN:

		/*
		return -EAGAIN;

	case CPU_UP_PREPARE:
		/*
		return 0;

	default:

		/* Should not happen.  Famous last words. */
		return -EIO;
	}
}

void cpu_set_state_online(int cpu)
{
	(void)atomic_xchg(&per_cpu(cpu_hotplug_state, cpu), CPU_ONLINE);
}

#ifdef CONFIG_HOTPLUG_CPU

bool cpu_wait_death(unsigned int cpu, int seconds)
{
	int jf_left = seconds * HZ;
	int oldstate;
	bool ret = true;
	int sleep_jf = 1;

	might_sleep();

	/* The outgoing CPU will normally get done quite quickly. */
	if (atomic_read(&per_cpu(cpu_hotplug_state, cpu)) == CPU_DEAD)
		goto update_state;
	udelay(5);

	/* But if the outgoing CPU dawdles, wait increasingly long times. */
	while (atomic_read(&per_cpu(cpu_hotplug_state, cpu)) != CPU_DEAD) {
		schedule_timeout_uninterruptible(sleep_jf);
		jf_left -= sleep_jf;
		if (jf_left <= 0)
			break;
		sleep_jf = DIV_ROUND_UP(sleep_jf * 11, 10);
	}
update_state:
	oldstate = atomic_read(&per_cpu(cpu_hotplug_state, cpu));
	if (oldstate == CPU_DEAD) {
		/* Outgoing CPU died normally, update state. */
		smp_mb(); /* atomic_read() before update. */
		atomic_set(&per_cpu(cpu_hotplug_state, cpu), CPU_POST_DEAD);
	} else {
		/* Outgoing CPU still hasn't died, set state accordingly. */
		if (atomic_cmpxchg(&per_cpu(cpu_hotplug_state, cpu),
				   oldstate, CPU_BROKEN) != oldstate)
			goto update_state;
		ret = false;
	}
	return ret;
}

bool cpu_report_death(void)
{
	int oldstate;
	int newstate;
	int cpu = smp_processor_id();

	do {
		oldstate = atomic_read(&per_cpu(cpu_hotplug_state, cpu));
		if (oldstate != CPU_BROKEN)
			newstate = CPU_DEAD;
		else
			newstate = CPU_DEAD_FROZEN;
	} while (atomic_cmpxchg(&per_cpu(cpu_hotplug_state, cpu),
				oldstate, newstate) != oldstate);
	return newstate == CPU_DEAD;
}

#endif /* #ifdef CONFIG_HOTPLUG_CPU */
