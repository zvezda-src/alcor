
#define pr_fmt(fmt) fmt

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/completion.h>
#include <linux/moduleparam.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/freezer.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/trace_clock.h>
#include <linux/ktime.h>
#include <asm/byteorder.h>
#include <linux/torture.h>
#include "rcu/rcu.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Paul E. McKenney <paulmck@linux.ibm.com>");

static bool disable_onoff_at_boot;
module_param(disable_onoff_at_boot, bool, 0444);

static bool ftrace_dump_at_shutdown;
module_param(ftrace_dump_at_shutdown, bool, 0444);

static int verbose_sleep_frequency;
module_param(verbose_sleep_frequency, int, 0444);

static int verbose_sleep_duration = 1;
module_param(verbose_sleep_duration, int, 0444);

static char *torture_type;
static int verbose;

#define FULLSTOP_DONTSTOP 0	/* Normal operation. */
#define FULLSTOP_SHUTDOWN 1	/* System shutdown with torture running. */
#define FULLSTOP_RMMOD    2	/* Normal rmmod of torture. */
static int fullstop = FULLSTOP_RMMOD;
static DEFINE_MUTEX(fullstop_mutex);

static atomic_t verbose_sleep_counter;

void verbose_torout_sleep(void)
{
	if (verbose_sleep_frequency > 0 &&
	    verbose_sleep_duration > 0 &&
	    !(atomic_inc_return(&verbose_sleep_counter) % verbose_sleep_frequency))
		schedule_timeout_uninterruptible(verbose_sleep_duration);
}
EXPORT_SYMBOL_GPL(verbose_torout_sleep);

int torture_hrtimeout_ns(ktime_t baset_ns, u32 fuzzt_ns, struct torture_random_state *trsp)
{
	ktime_t hto = baset_ns;

	if (trsp)
		hto += (torture_random(trsp) >> 3) % fuzzt_ns;
	set_current_state(TASK_UNINTERRUPTIBLE);
	return schedule_hrtimeout(&hto, HRTIMER_MODE_REL);
}
EXPORT_SYMBOL_GPL(torture_hrtimeout_ns);

int torture_hrtimeout_us(u32 baset_us, u32 fuzzt_ns, struct torture_random_state *trsp)
{
	ktime_t baset_ns = baset_us * NSEC_PER_USEC;

	return torture_hrtimeout_ns(baset_ns, fuzzt_ns, trsp);
}
EXPORT_SYMBOL_GPL(torture_hrtimeout_us);

int torture_hrtimeout_ms(u32 baset_ms, u32 fuzzt_us, struct torture_random_state *trsp)
{
	ktime_t baset_ns = baset_ms * NSEC_PER_MSEC;
	u32 fuzzt_ns;

	if ((u32)~0U / NSEC_PER_USEC < fuzzt_us)
		fuzzt_ns = (u32)~0U;
	else
		fuzzt_ns = fuzzt_us * NSEC_PER_USEC;
	return torture_hrtimeout_ns(baset_ns, fuzzt_ns, trsp);
}
EXPORT_SYMBOL_GPL(torture_hrtimeout_ms);

int torture_hrtimeout_jiffies(u32 baset_j, struct torture_random_state *trsp)
{
	ktime_t baset_ns = jiffies_to_nsecs(baset_j);

	return torture_hrtimeout_ns(baset_ns, jiffies_to_nsecs(1), trsp);
}
EXPORT_SYMBOL_GPL(torture_hrtimeout_jiffies);

int torture_hrtimeout_s(u32 baset_s, u32 fuzzt_ms, struct torture_random_state *trsp)
{
	ktime_t baset_ns = baset_s * NSEC_PER_SEC;
	u32 fuzzt_ns;

	if ((u32)~0U / NSEC_PER_MSEC < fuzzt_ms)
		fuzzt_ns = (u32)~0U;
	else
		fuzzt_ns = fuzzt_ms * NSEC_PER_MSEC;
	return torture_hrtimeout_ns(baset_ns, fuzzt_ns, trsp);
}
EXPORT_SYMBOL_GPL(torture_hrtimeout_s);

#ifdef CONFIG_HOTPLUG_CPU


static struct task_struct *onoff_task;
static long onoff_holdoff;
static long onoff_interval;
static torture_ofl_func *onoff_f;
static long n_offline_attempts;
static long n_offline_successes;
static unsigned long sum_offline;
static int min_offline = -1;
static int max_offline;
static long n_online_attempts;
static long n_online_successes;
static unsigned long sum_online;
static int min_online = -1;
static int max_online;

static int torture_online_cpus = NR_CPUS;

int torture_num_online_cpus(void)
{
	return READ_ONCE(torture_online_cpus);
}
EXPORT_SYMBOL_GPL(torture_num_online_cpus);

bool torture_offline(int cpu, long *n_offl_attempts, long *n_offl_successes,
		     unsigned long *sum_offl, int *min_offl, int *max_offl)
{
	unsigned long delta;
	int ret;
	char *s;
	unsigned long starttime;

	if (!cpu_online(cpu) || !cpu_is_hotpluggable(cpu))
		return false;
	if (num_online_cpus() <= 1)
		return false;  /* Can't offline the last CPU. */

	if (verbose > 1)
		pr_alert("%s" TORTURE_FLAG
			 "torture_onoff task: offlining %d\n",
			 torture_type, cpu);
	starttime = jiffies;
	(*n_offl_attempts)++;
	ret = remove_cpu(cpu);
	if (ret) {
		s = "";
		if (!rcu_inkernel_boot_has_ended() && ret == -EBUSY) {
			// PCI probe frequently disables hotplug during boot.
			(*n_offl_attempts)--;
			s = " (-EBUSY forgiven during boot)";
		}
		if (verbose)
			pr_alert("%s" TORTURE_FLAG
				 "torture_onoff task: offline %d failed%s: errno %d\n",
				 torture_type, cpu, s, ret);
	} else {
		if (verbose > 1)
			pr_alert("%s" TORTURE_FLAG
				 "torture_onoff task: offlined %d\n",
				 torture_type, cpu);
		if (onoff_f)
			onoff_f();
		(*n_offl_successes)++;
		delta = jiffies - starttime;
		*sum_offl += delta;
		if (*min_offl < 0) {
			*min_offl = delta;
			*max_offl = delta;
		}
		if (*min_offl > delta)
			*min_offl = delta;
		if (*max_offl < delta)
			*max_offl = delta;
		WRITE_ONCE(torture_online_cpus, torture_online_cpus - 1);
		WARN_ON_ONCE(torture_online_cpus <= 0);
	}

	return true;
}
EXPORT_SYMBOL_GPL(torture_offline);

bool torture_online(int cpu, long *n_onl_attempts, long *n_onl_successes,
		    unsigned long *sum_onl, int *min_onl, int *max_onl)
{
	unsigned long delta;
	int ret;
	char *s;
	unsigned long starttime;

	if (cpu_online(cpu) || !cpu_is_hotpluggable(cpu))
		return false;

	if (verbose > 1)
		pr_alert("%s" TORTURE_FLAG
			 "torture_onoff task: onlining %d\n",
			 torture_type, cpu);
	starttime = jiffies;
	(*n_onl_attempts)++;
	ret = add_cpu(cpu);
	if (ret) {
		s = "";
		if (!rcu_inkernel_boot_has_ended() && ret == -EBUSY) {
			// PCI probe frequently disables hotplug during boot.
			(*n_onl_attempts)--;
			s = " (-EBUSY forgiven during boot)";
		}
		if (verbose)
			pr_alert("%s" TORTURE_FLAG
				 "torture_onoff task: online %d failed%s: errno %d\n",
				 torture_type, cpu, s, ret);
	} else {
		if (verbose > 1)
			pr_alert("%s" TORTURE_FLAG
				 "torture_onoff task: onlined %d\n",
				 torture_type, cpu);
		(*n_onl_successes)++;
		delta = jiffies - starttime;
		*sum_onl += delta;
		if (*min_onl < 0) {
			*min_onl = delta;
			*max_onl = delta;
		}
		if (*min_onl > delta)
			*min_onl = delta;
		if (*max_onl < delta)
			*max_onl = delta;
		WRITE_ONCE(torture_online_cpus, torture_online_cpus + 1);
	}

	return true;
}
EXPORT_SYMBOL_GPL(torture_online);

static void torture_online_all(char *phase)
{
	int cpu;
	int ret;

	for_each_possible_cpu(cpu) {
		if (cpu_online(cpu))
			continue;
		ret = add_cpu(cpu);
		if (ret && verbose) {
			pr_alert("%s" TORTURE_FLAG
				 "%s: %s online %d: errno %d\n",
				 __func__, phase, torture_type, cpu, ret);
		}
	}
}

static int
torture_onoff(void *arg)
{
	int cpu;
	int maxcpu = -1;
	DEFINE_TORTURE_RANDOM(rand);

	VERBOSE_TOROUT_STRING("torture_onoff task started");
	for_each_online_cpu(cpu)
		maxcpu = cpu;
	WARN_ON(maxcpu < 0);
	torture_online_all("Initial");
	if (maxcpu == 0) {
		VERBOSE_TOROUT_STRING("Only one CPU, so CPU-hotplug testing is disabled");
		goto stop;
	}

	if (onoff_holdoff > 0) {
		VERBOSE_TOROUT_STRING("torture_onoff begin holdoff");
		schedule_timeout_interruptible(onoff_holdoff);
		VERBOSE_TOROUT_STRING("torture_onoff end holdoff");
	}
	while (!torture_must_stop()) {
		if (disable_onoff_at_boot && !rcu_inkernel_boot_has_ended()) {
			schedule_timeout_interruptible(HZ / 10);
			continue;
		}
		cpu = (torture_random(&rand) >> 4) % (maxcpu + 1);
		if (!torture_offline(cpu,
				     &n_offline_attempts, &n_offline_successes,
				     &sum_offline, &min_offline, &max_offline))
			torture_online(cpu,
				       &n_online_attempts, &n_online_successes,
				       &sum_online, &min_online, &max_online);
		schedule_timeout_interruptible(onoff_interval);
	}

stop:
	torture_kthread_stopping("torture_onoff");
	torture_online_all("Final");
	return 0;
}

#endif /* #ifdef CONFIG_HOTPLUG_CPU */

int torture_onoff_init(long ooholdoff, long oointerval, torture_ofl_func *f)
{
#ifdef CONFIG_HOTPLUG_CPU
	onoff_holdoff = ooholdoff;
	onoff_interval = oointerval;
	onoff_f = f;
	if (onoff_interval <= 0)
		return 0;
	return torture_create_kthread(torture_onoff, NULL, onoff_task);
#else /* #ifdef CONFIG_HOTPLUG_CPU */
	return 0;
#endif /* #else #ifdef CONFIG_HOTPLUG_CPU */
}
EXPORT_SYMBOL_GPL(torture_onoff_init);

static void torture_onoff_cleanup(void)
{
#ifdef CONFIG_HOTPLUG_CPU
	if (onoff_task == NULL)
		return;
	VERBOSE_TOROUT_STRING("Stopping torture_onoff task");
	kthread_stop(onoff_task);
	onoff_task = NULL;
#endif /* #ifdef CONFIG_HOTPLUG_CPU */
}

void torture_onoff_stats(void)
{
#ifdef CONFIG_HOTPLUG_CPU
	pr_cont("onoff: %ld/%ld:%ld/%ld %d,%d:%d,%d %lu:%lu (HZ=%d) ",
		n_online_successes, n_online_attempts,
		n_offline_successes, n_offline_attempts,
		min_online, max_online,
		min_offline, max_offline,
		sum_online, sum_offline, HZ);
#endif /* #ifdef CONFIG_HOTPLUG_CPU */
}
EXPORT_SYMBOL_GPL(torture_onoff_stats);

bool torture_onoff_failures(void)
{
#ifdef CONFIG_HOTPLUG_CPU
	return n_online_successes != n_online_attempts ||
	       n_offline_successes != n_offline_attempts;
#else /* #ifdef CONFIG_HOTPLUG_CPU */
	return false;
#endif /* #else #ifdef CONFIG_HOTPLUG_CPU */
}
EXPORT_SYMBOL_GPL(torture_onoff_failures);

#define TORTURE_RANDOM_MULT	39916801  /* prime */
#define TORTURE_RANDOM_ADD	479001701 /* prime */
#define TORTURE_RANDOM_REFRESH	10000

unsigned long
torture_random(struct torture_random_state *trsp)
{
	if (--trsp->trs_count < 0) {
		trsp->trs_state += (unsigned long)local_clock();
		trsp->trs_count = TORTURE_RANDOM_REFRESH;
	}
	trsp->trs_state = trsp->trs_state * TORTURE_RANDOM_MULT +
		TORTURE_RANDOM_ADD;
	return swahw32(trsp->trs_state);
}
EXPORT_SYMBOL_GPL(torture_random);

struct shuffle_task {
	struct list_head st_l;
	struct task_struct *st_t;
};

static long shuffle_interval;	/* In jiffies. */
static struct task_struct *shuffler_task;
static cpumask_var_t shuffle_tmp_mask;
static int shuffle_idle_cpu;	/* Force all torture tasks off this CPU */
static struct list_head shuffle_task_list = LIST_HEAD_INIT(shuffle_task_list);
static DEFINE_MUTEX(shuffle_task_mutex);

void torture_shuffle_task_register(struct task_struct *tp)
{
	struct shuffle_task *stp;

	if (WARN_ON_ONCE(tp == NULL))
		return;
	stp = kmalloc(sizeof(*stp), GFP_KERNEL);
	if (WARN_ON_ONCE(stp == NULL))
		return;
	stp->st_t = tp;
	mutex_lock(&shuffle_task_mutex);
	list_add(&stp->st_l, &shuffle_task_list);
	mutex_unlock(&shuffle_task_mutex);
}
EXPORT_SYMBOL_GPL(torture_shuffle_task_register);

static void torture_shuffle_task_unregister_all(void)
{
	struct shuffle_task *stp;
	struct shuffle_task *p;

	mutex_lock(&shuffle_task_mutex);
	list_for_each_entry_safe(stp, p, &shuffle_task_list, st_l) {
		list_del(&stp->st_l);
		kfree(stp);
	}
	mutex_unlock(&shuffle_task_mutex);
}

static void torture_shuffle_tasks(void)
{
	struct shuffle_task *stp;

	cpumask_setall(shuffle_tmp_mask);
	cpus_read_lock();

	/* No point in shuffling if there is only one online CPU (ex: UP) */
	if (num_online_cpus() == 1) {
		cpus_read_unlock();
		return;
	}

	/* Advance to the next CPU.  Upon overflow, don't idle any CPUs. */
	shuffle_idle_cpu = cpumask_next(shuffle_idle_cpu, shuffle_tmp_mask);
	if (shuffle_idle_cpu >= nr_cpu_ids)
		shuffle_idle_cpu = -1;
	else
		cpumask_clear_cpu(shuffle_idle_cpu, shuffle_tmp_mask);

	mutex_lock(&shuffle_task_mutex);
	list_for_each_entry(stp, &shuffle_task_list, st_l)
		set_cpus_allowed_ptr(stp->st_t, shuffle_tmp_mask);
	mutex_unlock(&shuffle_task_mutex);

	cpus_read_unlock();
}

static int torture_shuffle(void *arg)
{
	VERBOSE_TOROUT_STRING("torture_shuffle task started");
	do {
		schedule_timeout_interruptible(shuffle_interval);
		torture_shuffle_tasks();
		torture_shutdown_absorb("torture_shuffle");
	} while (!torture_must_stop());
	torture_kthread_stopping("torture_shuffle");
	return 0;
}

int torture_shuffle_init(long shuffint)
{
	shuffle_interval = shuffint;

	shuffle_idle_cpu = -1;

	if (!alloc_cpumask_var(&shuffle_tmp_mask, GFP_KERNEL)) {
		TOROUT_ERRSTRING("Failed to alloc mask");
		return -ENOMEM;
	}

	/* Create the shuffler thread */
	return torture_create_kthread(torture_shuffle, NULL, shuffler_task);
}
EXPORT_SYMBOL_GPL(torture_shuffle_init);

static void torture_shuffle_cleanup(void)
{
	torture_shuffle_task_unregister_all();
	if (shuffler_task) {
		VERBOSE_TOROUT_STRING("Stopping torture_shuffle task");
		kthread_stop(shuffler_task);
		free_cpumask_var(shuffle_tmp_mask);
	}
	shuffler_task = NULL;
}

static struct task_struct *shutdown_task;
static ktime_t shutdown_time;		/* time to system shutdown. */
static void (*torture_shutdown_hook)(void);

void torture_shutdown_absorb(const char *title)
{
	while (READ_ONCE(fullstop) == FULLSTOP_SHUTDOWN) {
		pr_notice("torture thread %s parking due to system shutdown\n",
			  title);
		schedule_timeout_uninterruptible(MAX_SCHEDULE_TIMEOUT);
	}
}
EXPORT_SYMBOL_GPL(torture_shutdown_absorb);

static int torture_shutdown(void *arg)
{
	ktime_t ktime_snap;

	VERBOSE_TOROUT_STRING("torture_shutdown task started");
	ktime_snap = ktime_get();
	while (ktime_before(ktime_snap, shutdown_time) &&
	       !torture_must_stop()) {
		if (verbose)
			pr_alert("%s" TORTURE_FLAG
				 "torture_shutdown task: %llu ms remaining\n",
				 torture_type,
				 ktime_ms_delta(shutdown_time, ktime_snap));
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_hrtimeout(&shutdown_time, HRTIMER_MODE_ABS);
		ktime_snap = ktime_get();
	}
	if (torture_must_stop()) {
		torture_kthread_stopping("torture_shutdown");
		return 0;
	}

	/* OK, shut down the system. */

	VERBOSE_TOROUT_STRING("torture_shutdown task shutting down system");
	shutdown_task = NULL;	/* Avoid self-kill deadlock. */
	if (torture_shutdown_hook)
		torture_shutdown_hook();
	else
		VERBOSE_TOROUT_STRING("No torture_shutdown_hook(), skipping.");
	if (ftrace_dump_at_shutdown)
		rcu_ftrace_dump(DUMP_ALL);
	kernel_power_off();	/* Shut down the system. */
	return 0;
}

int torture_shutdown_init(int ssecs, void (*cleanup)(void))
{
	torture_shutdown_hook = cleanup;
	if (ssecs > 0) {
		shutdown_time = ktime_add(ktime_get(), ktime_set(ssecs, 0));
		return torture_create_kthread(torture_shutdown, NULL,
					     shutdown_task);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(torture_shutdown_init);

static int torture_shutdown_notify(struct notifier_block *unused1,
				   unsigned long unused2, void *unused3)
{
	mutex_lock(&fullstop_mutex);
	if (READ_ONCE(fullstop) == FULLSTOP_DONTSTOP) {
		VERBOSE_TOROUT_STRING("Unscheduled system shutdown detected");
		WRITE_ONCE(fullstop, FULLSTOP_SHUTDOWN);
	} else {
		pr_warn("Concurrent rmmod and shutdown illegal!\n");
	}
	mutex_unlock(&fullstop_mutex);
	return NOTIFY_DONE;
}

static struct notifier_block torture_shutdown_nb = {
	.notifier_call = torture_shutdown_notify,
};

static void torture_shutdown_cleanup(void)
{
	unregister_reboot_notifier(&torture_shutdown_nb);
	if (shutdown_task != NULL) {
		VERBOSE_TOROUT_STRING("Stopping torture_shutdown task");
		kthread_stop(shutdown_task);
	}
	shutdown_task = NULL;
}

static struct task_struct *stutter_task;
static int stutter_pause_test;
static int stutter;
static int stutter_gap;

bool stutter_wait(const char *title)
{
	unsigned int i = 0;
	bool ret = false;
	int spt;

	cond_resched_tasks_rcu_qs();
	spt = READ_ONCE(stutter_pause_test);
	for (; spt; spt = READ_ONCE(stutter_pause_test)) {
		if (!ret) {
			sched_set_normal(current, MAX_NICE);
			ret = true;
		}
		if (spt == 1) {
			schedule_timeout_interruptible(1);
		} else if (spt == 2) {
			while (READ_ONCE(stutter_pause_test)) {
				if (!(i++ & 0xffff))
					torture_hrtimeout_us(10, 0, NULL);
				cond_resched();
			}
		} else {
			schedule_timeout_interruptible(round_jiffies_relative(HZ));
		}
		torture_shutdown_absorb(title);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(stutter_wait);

static int torture_stutter(void *arg)
{
	DEFINE_TORTURE_RANDOM(rand);
	int wtime;

	VERBOSE_TOROUT_STRING("torture_stutter task started");
	do {
		if (!torture_must_stop() && stutter > 1) {
			wtime = stutter;
			if (stutter > 2) {
				WRITE_ONCE(stutter_pause_test, 1);
				wtime = stutter - 3;
				torture_hrtimeout_jiffies(wtime, &rand);
				wtime = 2;
			}
			WRITE_ONCE(stutter_pause_test, 2);
			torture_hrtimeout_jiffies(wtime, NULL);
		}
		WRITE_ONCE(stutter_pause_test, 0);
		if (!torture_must_stop())
			torture_hrtimeout_jiffies(stutter_gap, NULL);
		torture_shutdown_absorb("torture_stutter");
	} while (!torture_must_stop());
	torture_kthread_stopping("torture_stutter");
	return 0;
}

int torture_stutter_init(const int s, const int sgap)
{
	stutter = s;
	stutter_gap = sgap;
	return torture_create_kthread(torture_stutter, NULL, stutter_task);
}
EXPORT_SYMBOL_GPL(torture_stutter_init);

static void torture_stutter_cleanup(void)
{
	if (!stutter_task)
		return;
	VERBOSE_TOROUT_STRING("Stopping torture_stutter task");
	kthread_stop(stutter_task);
	stutter_task = NULL;
}

bool torture_init_begin(char *ttype, int v)
{
	mutex_lock(&fullstop_mutex);
	if (torture_type != NULL) {
		pr_alert("%s: Refusing %s init: %s running.\n",
			  __func__, ttype, torture_type);
		pr_alert("%s: One torture test at a time!\n", __func__);
		mutex_unlock(&fullstop_mutex);
		return false;
	}
	torture_type = ttype;
	verbose = v;
	fullstop = FULLSTOP_DONTSTOP;
	return true;
}
EXPORT_SYMBOL_GPL(torture_init_begin);

void torture_init_end(void)
{
	mutex_unlock(&fullstop_mutex);
	register_reboot_notifier(&torture_shutdown_nb);
}
EXPORT_SYMBOL_GPL(torture_init_end);

bool torture_cleanup_begin(void)
{
	mutex_lock(&fullstop_mutex);
	if (READ_ONCE(fullstop) == FULLSTOP_SHUTDOWN) {
		pr_warn("Concurrent rmmod and shutdown illegal!\n");
		mutex_unlock(&fullstop_mutex);
		schedule_timeout_uninterruptible(10);
		return true;
	}
	WRITE_ONCE(fullstop, FULLSTOP_RMMOD);
	mutex_unlock(&fullstop_mutex);
	torture_shutdown_cleanup();
	torture_shuffle_cleanup();
	torture_stutter_cleanup();
	torture_onoff_cleanup();
	return false;
}
EXPORT_SYMBOL_GPL(torture_cleanup_begin);

void torture_cleanup_end(void)
{
	mutex_lock(&fullstop_mutex);
	torture_type = NULL;
	mutex_unlock(&fullstop_mutex);
}
EXPORT_SYMBOL_GPL(torture_cleanup_end);

bool torture_must_stop(void)
{
	return torture_must_stop_irq() || kthread_should_stop();
}
EXPORT_SYMBOL_GPL(torture_must_stop);

bool torture_must_stop_irq(void)
{
	return READ_ONCE(fullstop) != FULLSTOP_DONTSTOP;
}
EXPORT_SYMBOL_GPL(torture_must_stop_irq);

void torture_kthread_stopping(char *title)
{
	char buf[128];

	snprintf(buf, sizeof(buf), "%s is stopping", title);
	VERBOSE_TOROUT_STRING(buf);
	while (!kthread_should_stop()) {
		torture_shutdown_absorb(title);
		schedule_timeout_uninterruptible(1);
	}
}
EXPORT_SYMBOL_GPL(torture_kthread_stopping);

int _torture_create_kthread(int (*fn)(void *arg), void *arg, char *s, char *m,
			    char *f, struct task_struct **tp)
{
	int ret = 0;

	VERBOSE_TOROUT_STRING(m);
	if (IS_ERR(*tp)) {
		ret = PTR_ERR(*tp);
		TOROUT_ERRSTRING(f);
		*tp = NULL;
		return ret;
	}
	wake_up_process(*tp);  // Process is sleeping, so ordering provided.
	torture_shuffle_task_register(*tp);
	return ret;
}
EXPORT_SYMBOL_GPL(_torture_create_kthread);

void _torture_stop_kthread(char *m, struct task_struct **tp)
{
	if (*tp == NULL)
		return;
	VERBOSE_TOROUT_STRING(m);
	kthread_stop(*tp);
}
EXPORT_SYMBOL_GPL(_torture_stop_kthread);
