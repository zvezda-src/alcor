
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/cpuset.h>
#include <linux/mutex.h>
#include <linux/sysctl.h>
#include <linux/nodemask.h>

static DEFINE_MUTEX(itmt_update_mutex);
DEFINE_PER_CPU_READ_MOSTLY(int, sched_core_priority);

static bool __read_mostly sched_itmt_capable;

unsigned int __read_mostly sysctl_sched_itmt_enabled;

static int sched_itmt_update_handler(struct ctl_table *table, int write,
				     void *buffer, size_t *lenp, loff_t *ppos)
{
	unsigned int old_sysctl;
	int ret;

	mutex_lock(&itmt_update_mutex);

	if (!sched_itmt_capable) {
		mutex_unlock(&itmt_update_mutex);
		return -EINVAL;
	}

	old_sysctl = sysctl_sched_itmt_enabled;
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (!ret && write && old_sysctl != sysctl_sched_itmt_enabled) {
		x86_topology_update = true;
		rebuild_sched_domains();
	}

	mutex_unlock(&itmt_update_mutex);

	return ret;
}

static struct ctl_table itmt_kern_table[] = {
	{
		.procname	= "sched_itmt_enabled",
		.data		= &sysctl_sched_itmt_enabled,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_itmt_update_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{}
};

static struct ctl_table itmt_root_table[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= itmt_kern_table,
	},
	{}
};

static struct ctl_table_header *itmt_sysctl_header;

int sched_set_itmt_support(void)
{
	mutex_lock(&itmt_update_mutex);

	if (sched_itmt_capable) {
		mutex_unlock(&itmt_update_mutex);
		return 0;
	}

	itmt_sysctl_header = register_sysctl_table(itmt_root_table);
	if (!itmt_sysctl_header) {
		mutex_unlock(&itmt_update_mutex);
		return -ENOMEM;
	}

	sched_itmt_capable = true;

	sysctl_sched_itmt_enabled = 1;

	x86_topology_update = true;
	rebuild_sched_domains();

	mutex_unlock(&itmt_update_mutex);

	return 0;
}

void sched_clear_itmt_support(void)
{
	mutex_lock(&itmt_update_mutex);

	if (!sched_itmt_capable) {
		mutex_unlock(&itmt_update_mutex);
		return;
	}
	sched_itmt_capable = false;

	if (itmt_sysctl_header) {
		unregister_sysctl_table(itmt_sysctl_header);
		itmt_sysctl_header = NULL;
	}

	if (sysctl_sched_itmt_enabled) {
		/* disable sched_itmt if we are no longer ITMT capable */
		sysctl_sched_itmt_enabled = 0;
		x86_topology_update = true;
		rebuild_sched_domains();
	}

	mutex_unlock(&itmt_update_mutex);
}

int arch_asym_cpu_priority(int cpu)
{
	return per_cpu(sched_core_priority, cpu);
}

void sched_set_itmt_core_prio(int prio, int core_cpu)
{
	int cpu, i = 1;

	for_each_cpu(cpu, topology_sibling_cpumask(core_cpu)) {
		int smt_prio;

		/*
		smt_prio = prio * smp_num_siblings / (i * i);
		per_cpu(sched_core_priority, cpu) = smt_prio;
		i++;
	}
}
