#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/stop_machine.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/smpboot.h>
#include <linux/atomic.h>
#include <linux/nmi.h>
#include <linux/sched/wake_q.h>

struct cpu_stop_done {
	atomic_t		nr_todo;	/* nr left to execute */
	int			ret;		/* collected return value */
	struct completion	completion;	/* fired if nr_todo reaches 0 */
};

struct cpu_stopper {
	struct task_struct	*thread;

	raw_spinlock_t		lock;
	bool			enabled;	/* is this stopper enabled? */
	struct list_head	works;		/* list of pending works */

	struct cpu_stop_work	stop_work;	/* for stop_cpus */
	unsigned long		caller;
	cpu_stop_fn_t		fn;
};

static DEFINE_PER_CPU(struct cpu_stopper, cpu_stopper);
static bool stop_machine_initialized = false;

void print_stop_info(const char *log_lvl, struct task_struct *task)
{
	/*
	struct cpu_stopper *stopper = per_cpu_ptr(&cpu_stopper, task_cpu(task));

	if (task != stopper->thread)
		return;

	printk("%sStopper: %pS <- %pS\n", log_lvl, stopper->fn, (void *)stopper->caller);
}

static DEFINE_MUTEX(stop_cpus_mutex);
static bool stop_cpus_in_progress;

static void cpu_stop_init_done(struct cpu_stop_done *done, unsigned int nr_todo)
{
	memset(done, 0, sizeof(*done));
	atomic_set(&done->nr_todo, nr_todo);
	init_completion(&done->completion);
}

static void cpu_stop_signal_done(struct cpu_stop_done *done)
{
	if (atomic_dec_and_test(&done->nr_todo))
		complete(&done->completion);
}

static void __cpu_stop_queue_work(struct cpu_stopper *stopper,
					struct cpu_stop_work *work,
					struct wake_q_head *wakeq)
{
	list_add_tail(&work->list, &stopper->works);
	wake_q_add(wakeq, stopper->thread);
}

static bool cpu_stop_queue_work(unsigned int cpu, struct cpu_stop_work *work)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
	DEFINE_WAKE_Q(wakeq);
	unsigned long flags;
	bool enabled;

	preempt_disable();
	raw_spin_lock_irqsave(&stopper->lock, flags);
	enabled = stopper->enabled;
	if (enabled)
		__cpu_stop_queue_work(stopper, work, &wakeq);
	else if (work->done)
		cpu_stop_signal_done(work->done);
	raw_spin_unlock_irqrestore(&stopper->lock, flags);

	wake_up_q(&wakeq);
	preempt_enable();

	return enabled;
}

int stop_one_cpu(unsigned int cpu, cpu_stop_fn_t fn, void *arg)
{
	struct cpu_stop_done done;
	struct cpu_stop_work work = { .fn = fn, .arg = arg, .done = &done, .caller = _RET_IP_ };

	cpu_stop_init_done(&done, 1);
	if (!cpu_stop_queue_work(cpu, &work))
		return -ENOENT;
	/*
	cond_resched();
	wait_for_completion(&done.completion);
	return done.ret;
}

enum multi_stop_state {
	/* Dummy starting state for thread. */
	MULTI_STOP_NONE,
	/* Awaiting everyone to be scheduled. */
	MULTI_STOP_PREPARE,
	/* Disable interrupts. */
	MULTI_STOP_DISABLE_IRQ,
	/* Run the function */
	MULTI_STOP_RUN,
	/* Exit */
	MULTI_STOP_EXIT,
};

struct multi_stop_data {
	cpu_stop_fn_t		fn;
	void			*data;
	/* Like num_online_cpus(), but hotplug cpu uses us, so we need this. */
	unsigned int		num_threads;
	const struct cpumask	*active_cpus;

	enum multi_stop_state	state;
	atomic_t		thread_ack;
};

static void set_state(struct multi_stop_data *msdata,
		      enum multi_stop_state newstate)
{
	/* Reset ack counter. */
	atomic_set(&msdata->thread_ack, msdata->num_threads);
	smp_wmb();
	WRITE_ONCE(msdata->state, newstate);
}

static void ack_state(struct multi_stop_data *msdata)
{
	if (atomic_dec_and_test(&msdata->thread_ack))
		set_state(msdata, msdata->state + 1);
}

notrace void __weak stop_machine_yield(const struct cpumask *cpumask)
{
	cpu_relax();
}

static int multi_cpu_stop(void *data)
{
	struct multi_stop_data *msdata = data;
	enum multi_stop_state newstate, curstate = MULTI_STOP_NONE;
	int cpu = smp_processor_id(), err = 0;
	const struct cpumask *cpumask;
	unsigned long flags;
	bool is_active;

	/*
	local_save_flags(flags);

	if (!msdata->active_cpus) {
		cpumask = cpu_online_mask;
		is_active = cpu == cpumask_first(cpumask);
	} else {
		cpumask = msdata->active_cpus;
		is_active = cpumask_test_cpu(cpu, cpumask);
	}

	/* Simple state machine */
	do {
		/* Chill out and ensure we re-read multi_stop_state. */
		stop_machine_yield(cpumask);
		newstate = READ_ONCE(msdata->state);
		if (newstate != curstate) {
			curstate = newstate;
			switch (curstate) {
			case MULTI_STOP_DISABLE_IRQ:
				local_irq_disable();
				hard_irq_disable();
				break;
			case MULTI_STOP_RUN:
				if (is_active)
					err = msdata->fn(msdata->data);
				break;
			default:
				break;
			}
			ack_state(msdata);
		} else if (curstate > MULTI_STOP_PREPARE) {
			/*
			touch_nmi_watchdog();
		}
		rcu_momentary_dyntick_idle();
	} while (curstate != MULTI_STOP_EXIT);

	local_irq_restore(flags);
	return err;
}

static int cpu_stop_queue_two_works(int cpu1, struct cpu_stop_work *work1,
				    int cpu2, struct cpu_stop_work *work2)
{
	struct cpu_stopper *stopper1 = per_cpu_ptr(&cpu_stopper, cpu1);
	struct cpu_stopper *stopper2 = per_cpu_ptr(&cpu_stopper, cpu2);
	DEFINE_WAKE_Q(wakeq);
	int err;

retry:
	/*
	preempt_disable();
	raw_spin_lock_irq(&stopper1->lock);
	raw_spin_lock_nested(&stopper2->lock, SINGLE_DEPTH_NESTING);

	if (!stopper1->enabled || !stopper2->enabled) {
		err = -ENOENT;
		goto unlock;
	}

	/*
	if (unlikely(stop_cpus_in_progress)) {
		err = -EDEADLK;
		goto unlock;
	}

	err = 0;
	__cpu_stop_queue_work(stopper1, work1, &wakeq);
	__cpu_stop_queue_work(stopper2, work2, &wakeq);

unlock:
	raw_spin_unlock(&stopper2->lock);
	raw_spin_unlock_irq(&stopper1->lock);

	if (unlikely(err == -EDEADLK)) {
		preempt_enable();

		while (stop_cpus_in_progress)
			cpu_relax();

		goto retry;
	}

	wake_up_q(&wakeq);
	preempt_enable();

	return err;
}
int stop_two_cpus(unsigned int cpu1, unsigned int cpu2, cpu_stop_fn_t fn, void *arg)
{
	struct cpu_stop_done done;
	struct cpu_stop_work work1, work2;
	struct multi_stop_data msdata;

	msdata = (struct multi_stop_data){
		.fn = fn,
		.data = arg,
		.num_threads = 2,
		.active_cpus = cpumask_of(cpu1),
	};

	work1 = work2 = (struct cpu_stop_work){
		.fn = multi_cpu_stop,
		.arg = &msdata,
		.done = &done,
		.caller = _RET_IP_,
	};

	cpu_stop_init_done(&done, 2);
	set_state(&msdata, MULTI_STOP_PREPARE);

	if (cpu1 > cpu2)
		swap(cpu1, cpu2);
	if (cpu_stop_queue_two_works(cpu1, &work1, cpu2, &work2))
		return -ENOENT;

	wait_for_completion(&done.completion);
	return done.ret;
}

bool stop_one_cpu_nowait(unsigned int cpu, cpu_stop_fn_t fn, void *arg,
			struct cpu_stop_work *work_buf)
{
	return cpu_stop_queue_work(cpu, work_buf);
}

static bool queue_stop_cpus_work(const struct cpumask *cpumask,
				 cpu_stop_fn_t fn, void *arg,
				 struct cpu_stop_done *done)
{
	struct cpu_stop_work *work;
	unsigned int cpu;
	bool queued = false;

	/*
	preempt_disable();
	stop_cpus_in_progress = true;
	barrier();
	for_each_cpu(cpu, cpumask) {
		work = &per_cpu(cpu_stopper.stop_work, cpu);
		work->fn = fn;
		work->arg = arg;
		work->done = done;
		work->caller = _RET_IP_;
		if (cpu_stop_queue_work(cpu, work))
			queued = true;
	}
	barrier();
	stop_cpus_in_progress = false;
	preempt_enable();

	return queued;
}

static int __stop_cpus(const struct cpumask *cpumask,
		       cpu_stop_fn_t fn, void *arg)
{
	struct cpu_stop_done done;

	cpu_stop_init_done(&done, cpumask_weight(cpumask));
	if (!queue_stop_cpus_work(cpumask, fn, arg, &done))
		return -ENOENT;
	wait_for_completion(&done.completion);
	return done.ret;
}

static int stop_cpus(const struct cpumask *cpumask, cpu_stop_fn_t fn, void *arg)
{
	int ret;

	/* static works are used, process one request at a time */
	mutex_lock(&stop_cpus_mutex);
	ret = __stop_cpus(cpumask, fn, arg);
	mutex_unlock(&stop_cpus_mutex);
	return ret;
}

static int cpu_stop_should_run(unsigned int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
	unsigned long flags;
	int run;

	raw_spin_lock_irqsave(&stopper->lock, flags);
	run = !list_empty(&stopper->works);
	raw_spin_unlock_irqrestore(&stopper->lock, flags);
	return run;
}

static void cpu_stopper_thread(unsigned int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
	struct cpu_stop_work *work;

repeat:
	work = NULL;
	raw_spin_lock_irq(&stopper->lock);
	if (!list_empty(&stopper->works)) {
		work = list_first_entry(&stopper->works,
					struct cpu_stop_work, list);
		list_del_init(&work->list);
	}
	raw_spin_unlock_irq(&stopper->lock);

	if (work) {
		cpu_stop_fn_t fn = work->fn;
		void *arg = work->arg;
		struct cpu_stop_done *done = work->done;
		int ret;

		/* cpu stop callbacks must not sleep, make in_atomic() == T */
		stopper->caller = work->caller;
		stopper->fn = fn;
		preempt_count_inc();
		ret = fn(arg);
		if (done) {
			if (ret)
				done->ret = ret;
			cpu_stop_signal_done(done);
		}
		preempt_count_dec();
		stopper->fn = NULL;
		stopper->caller = 0;
		WARN_ONCE(preempt_count(),
			  "cpu_stop: %ps(%p) leaked preempt count\n", fn, arg);
		goto repeat;
	}
}

void stop_machine_park(int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
	/*
	stopper->enabled = false;
	kthread_park(stopper->thread);
}

static void cpu_stop_create(unsigned int cpu)
{
	sched_set_stop_task(cpu, per_cpu(cpu_stopper.thread, cpu));
}

static void cpu_stop_park(unsigned int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

	WARN_ON(!list_empty(&stopper->works));
}

void stop_machine_unpark(int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

	stopper->enabled = true;
	kthread_unpark(stopper->thread);
}

static struct smp_hotplug_thread cpu_stop_threads = {
	.store			= &cpu_stopper.thread,
	.thread_should_run	= cpu_stop_should_run,
	.thread_fn		= cpu_stopper_thread,
	.thread_comm		= "migration/%u",
	.create			= cpu_stop_create,
	.park			= cpu_stop_park,
	.selfparking		= true,
};

static int __init cpu_stop_init(void)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

		raw_spin_lock_init(&stopper->lock);
		INIT_LIST_HEAD(&stopper->works);
	}

	BUG_ON(smpboot_register_percpu_thread(&cpu_stop_threads));
	stop_machine_unpark(raw_smp_processor_id());
	stop_machine_initialized = true;
	return 0;
}
early_initcall(cpu_stop_init);

int stop_machine_cpuslocked(cpu_stop_fn_t fn, void *data,
			    const struct cpumask *cpus)
{
	struct multi_stop_data msdata = {
		.fn = fn,
		.data = data,
		.num_threads = num_online_cpus(),
		.active_cpus = cpus,
	};

	lockdep_assert_cpus_held();

	if (!stop_machine_initialized) {
		/*
		unsigned long flags;
		int ret;

		WARN_ON_ONCE(msdata.num_threads != 1);

		local_irq_save(flags);
		hard_irq_disable();
		ret = (*fn)(data);
		local_irq_restore(flags);

		return ret;
	}

	/* Set the initial state and stop all online cpus. */
	set_state(&msdata, MULTI_STOP_PREPARE);
	return stop_cpus(cpu_online_mask, multi_cpu_stop, &msdata);
}

int stop_machine(cpu_stop_fn_t fn, void *data, const struct cpumask *cpus)
{
	int ret;

	/* No CPUs can come up or down during this. */
	cpus_read_lock();
	ret = stop_machine_cpuslocked(fn, data, cpus);
	cpus_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(stop_machine);

#ifdef CONFIG_SCHED_SMT
int stop_core_cpuslocked(unsigned int cpu, cpu_stop_fn_t fn, void *data)
{
	const struct cpumask *smt_mask = cpu_smt_mask(cpu);

	struct multi_stop_data msdata = {
		.fn = fn,
		.data = data,
		.num_threads = cpumask_weight(smt_mask),
		.active_cpus = smt_mask,
	};

	lockdep_assert_cpus_held();

	/* Set the initial state and stop all online cpus. */
	set_state(&msdata, MULTI_STOP_PREPARE);
	return stop_cpus(smt_mask, multi_cpu_stop, &msdata);
}
EXPORT_SYMBOL_GPL(stop_core_cpuslocked);
#endif

int stop_machine_from_inactive_cpu(cpu_stop_fn_t fn, void *data,
				  const struct cpumask *cpus)
{
	struct multi_stop_data msdata = { .fn = fn, .data = data,
					    .active_cpus = cpus };
	struct cpu_stop_done done;
	int ret;

	/* Local CPU must be inactive and CPU hotplug in progress. */
	BUG_ON(cpu_active(raw_smp_processor_id()));
	msdata.num_threads = num_active_cpus() + 1;	/* +1 for local */

	/* No proper task established and can't sleep - busy wait for lock. */
	while (!mutex_trylock(&stop_cpus_mutex))
		cpu_relax();

	/* Schedule work on other CPUs and execute directly for local CPU */
	set_state(&msdata, MULTI_STOP_PREPARE);
	cpu_stop_init_done(&done, num_active_cpus());
	queue_stop_cpus_work(cpu_active_mask, multi_cpu_stop, &msdata,
			     &done);
	ret = multi_cpu_stop(&msdata);

	/* Busy wait for completion. */
	while (!completion_done(&done.completion))
		cpu_relax();

	mutex_unlock(&stop_cpus_mutex);
	return ret ?: done.ret;
}
