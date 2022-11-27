 /*

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/smp.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/topology.h>
#include <linux/sched/hotplug.h>
#include <linux/sched/task_stack.h>
#include <linux/percpu.h>
#include <linux/memblock.h>
#include <linux/err.h>
#include <linux/nmi.h>
#include <linux/tboot.h>
#include <linux/gfp.h>
#include <linux/cpuidle.h>
#include <linux/numa.h>
#include <linux/pgtable.h>
#include <linux/overflow.h>

#include <asm/acpi.h>
#include <asm/desc.h>
#include <asm/nmi.h>
#include <asm/irq.h>
#include <asm/realmode.h>
#include <asm/cpu.h>
#include <asm/numa.h>
#include <asm/tlbflush.h>
#include <asm/mtrr.h>
#include <asm/mwait.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/fpu/api.h>
#include <asm/setup.h>
#include <asm/uv/uv.h>
#include <linux/mc146818rtc.h>
#include <asm/i8259.h>
#include <asm/misc.h>
#include <asm/qspinlock.h>
#include <asm/intel-family.h>
#include <asm/cpu_device_id.h>
#include <asm/spec-ctrl.h>
#include <asm/hw_irq.h>
#include <asm/stackprotector.h>
#include <asm/sev.h>

DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_sibling_map);
EXPORT_PER_CPU_SYMBOL(cpu_sibling_map);

DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_core_map);
EXPORT_PER_CPU_SYMBOL(cpu_core_map);

DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_die_map);
EXPORT_PER_CPU_SYMBOL(cpu_die_map);

DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_llc_shared_map);

DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_l2c_shared_map);

DEFINE_PER_CPU_READ_MOSTLY(struct cpuinfo_x86, cpu_info);
EXPORT_PER_CPU_SYMBOL(cpu_info);

unsigned int __max_logical_packages __read_mostly;
EXPORT_SYMBOL(__max_logical_packages);
static unsigned int logical_packages __read_mostly;
static unsigned int logical_die __read_mostly;

int __read_mostly __max_smt_threads = 1;

bool x86_topology_update;

int arch_update_cpu_topology(void)
{
	int retval = x86_topology_update;

	x86_topology_update = false;
	return retval;
}

static inline void smpboot_setup_warm_reset_vector(unsigned long start_eip)
{
	unsigned long flags;

	spin_lock_irqsave(&rtc_lock, flags);
	CMOS_WRITE(0xa, 0xf);
	spin_unlock_irqrestore(&rtc_lock, flags);
							start_eip >> 4;
							start_eip & 0xf;
}

static inline void smpboot_restore_warm_reset_vector(void)
{
	unsigned long flags;

	/*
	spin_lock_irqsave(&rtc_lock, flags);
	CMOS_WRITE(0, 0xf);
	spin_unlock_irqrestore(&rtc_lock, flags);

}

static void smp_callin(void)
{
	int cpuid;

	/*
	cpuid = smp_processor_id();

	/*
	apic_ap_setup();

	/*
	smp_store_cpu_info(cpuid);

	/*
	set_cpu_sibling_map(raw_smp_processor_id());

	ap_init_aperfmperf();

	/*
	calibrate_delay();
	cpu_data(cpuid).loops_per_jiffy = loops_per_jiffy;
	pr_debug("Stack at about %p\n", &cpuid);

	wmb();

	notify_cpu_starting(cpuid);

	/*
	cpumask_set_cpu(cpuid, cpu_callin_mask);
}

static int cpu0_logical_apicid;
static int enable_start_cpu0;
static void notrace start_secondary(void *unused)
{
	/*
	cr4_init();

#ifdef CONFIG_X86_32
	/* switch away from the initial page table */
	load_cr3(swapper_pg_dir);
	__flush_tlb_all();
#endif
	cpu_init_secondary();
	rcu_cpu_starting(raw_smp_processor_id());
	x86_cpuinit.early_percpu_clock_init();
	smp_callin();

	enable_start_cpu0 = 0;

	/* otherwise gcc will move up smp_processor_id before the cpu_init */
	barrier();
	/*
	check_tsc_sync_target();

	speculative_store_bypass_ht_init();

	/*
	lock_vector_lock();
	set_cpu_online(smp_processor_id(), true);
	lapic_online();
	unlock_vector_lock();
	cpu_set_state_online(smp_processor_id());
	x86_platform.nmi_init();

	/* enable local interrupts */
	local_irq_enable();

	x86_cpuinit.setup_percpu_clockev();

	wmb();
	cpu_startup_entry(CPUHP_AP_ONLINE_IDLE);
}

bool topology_is_primary_thread(unsigned int cpu)
{
	return apic_id_is_primary_thread(per_cpu(x86_cpu_to_apicid, cpu));
}

bool topology_smt_supported(void)
{
	return smp_num_siblings > 1;
}

int topology_phys_to_logical_pkg(unsigned int phys_pkg)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct cpuinfo_x86 *c = &cpu_data(cpu);

		if (c->initialized && c->phys_proc_id == phys_pkg)
			return c->logical_proc_id;
	}
	return -1;
}
EXPORT_SYMBOL(topology_phys_to_logical_pkg);
int topology_phys_to_logical_die(unsigned int die_id, unsigned int cur_cpu)
{
	int cpu;
	int proc_id = cpu_data(cur_cpu).phys_proc_id;

	for_each_possible_cpu(cpu) {
		struct cpuinfo_x86 *c = &cpu_data(cpu);

		if (c->initialized && c->cpu_die_id == die_id &&
		    c->phys_proc_id == proc_id)
			return c->logical_die_id;
	}
	return -1;
}
EXPORT_SYMBOL(topology_phys_to_logical_die);

int topology_update_package_map(unsigned int pkg, unsigned int cpu)
{
	int new;

	/* Already available somewhere? */
	new = topology_phys_to_logical_pkg(pkg);
	if (new >= 0)
		goto found;

	new = logical_packages++;
	if (new != pkg) {
		pr_info("CPU %u Converting physical %u to logical package %u\n",
			cpu, pkg, new);
	}
found:
	cpu_data(cpu).logical_proc_id = new;
	return 0;
}
int topology_update_die_map(unsigned int die, unsigned int cpu)
{
	int new;

	/* Already available somewhere? */
	new = topology_phys_to_logical_die(die, cpu);
	if (new >= 0)
		goto found;

	new = logical_die++;
	if (new != die) {
		pr_info("CPU %u Converting physical %u to logical die %u\n",
			cpu, die, new);
	}
found:
	cpu_data(cpu).logical_die_id = new;
	return 0;
}

void __init smp_store_boot_cpu_info(void)
{
	int id = 0; /* CPU 0 */
	struct cpuinfo_x86 *c = &cpu_data(id);

	c->cpu_index = id;
	topology_update_package_map(c->phys_proc_id, id);
	topology_update_die_map(c->cpu_die_id, id);
	c->initialized = true;
}

void smp_store_cpu_info(int id)
{
	struct cpuinfo_x86 *c = &cpu_data(id);

	/* Copy boot_cpu_data only on the first bringup */
	if (!c->initialized)
		*c = boot_cpu_data;
	c->cpu_index = id;
	/*
	identify_secondary_cpu(c);
	c->initialized = true;
}

static bool
topology_same_node(struct cpuinfo_x86 *c, struct cpuinfo_x86 *o)
{
	int cpu1 = c->cpu_index, cpu2 = o->cpu_index;

	return (cpu_to_node(cpu1) == cpu_to_node(cpu2));
}

static bool
topology_sane(struct cpuinfo_x86 *c, struct cpuinfo_x86 *o, const char *name)
{
	int cpu1 = c->cpu_index, cpu2 = o->cpu_index;

	return !WARN_ONCE(!topology_same_node(c, o),
		"sched: CPU #%d's %s-sibling CPU #%d is not on the same node! "
		"[node: %d != %d]. Ignoring dependency.\n",
		cpu1, name, cpu2, cpu_to_node(cpu1), cpu_to_node(cpu2));
}

#define link_mask(mfunc, c1, c2)					\
do {									\
	cpumask_set_cpu((c1), mfunc(c2));				\
	cpumask_set_cpu((c2), mfunc(c1));				\
} while (0)

static bool match_smt(struct cpuinfo_x86 *c, struct cpuinfo_x86 *o)
{
	if (boot_cpu_has(X86_FEATURE_TOPOEXT)) {
		int cpu1 = c->cpu_index, cpu2 = o->cpu_index;

		if (c->phys_proc_id == o->phys_proc_id &&
		    c->cpu_die_id == o->cpu_die_id &&
		    per_cpu(cpu_llc_id, cpu1) == per_cpu(cpu_llc_id, cpu2)) {
			if (c->cpu_core_id == o->cpu_core_id)
				return topology_sane(c, o, "smt");

			if ((c->cu_id != 0xff) &&
			    (o->cu_id != 0xff) &&
			    (c->cu_id == o->cu_id))
				return topology_sane(c, o, "smt");
		}

	} else if (c->phys_proc_id == o->phys_proc_id &&
		   c->cpu_die_id == o->cpu_die_id &&
		   c->cpu_core_id == o->cpu_core_id) {
		return topology_sane(c, o, "smt");
	}

	return false;
}

static bool match_die(struct cpuinfo_x86 *c, struct cpuinfo_x86 *o)
{
	if (c->phys_proc_id == o->phys_proc_id &&
	    c->cpu_die_id == o->cpu_die_id)
		return true;
	return false;
}

static bool match_l2c(struct cpuinfo_x86 *c, struct cpuinfo_x86 *o)
{
	int cpu1 = c->cpu_index, cpu2 = o->cpu_index;

	/* If the arch didn't set up l2c_id, fall back to SMT */
	if (per_cpu(cpu_l2c_id, cpu1) == BAD_APICID)
		return match_smt(c, o);

	/* Do not match if L2 cache id does not match: */
	if (per_cpu(cpu_l2c_id, cpu1) != per_cpu(cpu_l2c_id, cpu2))
		return false;

	return topology_sane(c, o, "l2c");
}

static bool match_pkg(struct cpuinfo_x86 *c, struct cpuinfo_x86 *o)
{
	if (c->phys_proc_id == o->phys_proc_id)
		return true;
	return false;
}


static const struct x86_cpu_id intel_cod_cpu[] = {
	X86_MATCH_INTEL_FAM6_MODEL(HASWELL_X, 0),	/* COD */
	X86_MATCH_INTEL_FAM6_MODEL(BROADWELL_X, 0),	/* COD */
	X86_MATCH_INTEL_FAM6_MODEL(ANY, 1),		/* SNC */
	{}
};

static bool match_llc(struct cpuinfo_x86 *c, struct cpuinfo_x86 *o)
{
	const struct x86_cpu_id *id = x86_match_cpu(intel_cod_cpu);
	int cpu1 = c->cpu_index, cpu2 = o->cpu_index;
	bool intel_snc = id && id->driver_data;

	/* Do not match if we do not have a valid APICID for cpu: */
	if (per_cpu(cpu_llc_id, cpu1) == BAD_APICID)
		return false;

	/* Do not match if LLC id does not match: */
	if (per_cpu(cpu_llc_id, cpu1) != per_cpu(cpu_llc_id, cpu2))
		return false;

	/*
	if (match_pkg(c, o) && !topology_same_node(c, o) && intel_snc)
		return false;

	return topology_sane(c, o, "llc");
}


#if defined(CONFIG_SCHED_SMT) || defined(CONFIG_SCHED_CLUSTER) || defined(CONFIG_SCHED_MC)
static inline int x86_sched_itmt_flags(void)
{
	return sysctl_sched_itmt_enabled ? SD_ASYM_PACKING : 0;
}

#ifdef CONFIG_SCHED_MC
static int x86_core_flags(void)
{
	return cpu_core_flags() | x86_sched_itmt_flags();
}
#endif
#ifdef CONFIG_SCHED_SMT
static int x86_smt_flags(void)
{
	return cpu_smt_flags() | x86_sched_itmt_flags();
}
#endif
#ifdef CONFIG_SCHED_CLUSTER
static int x86_cluster_flags(void)
{
	return cpu_cluster_flags() | x86_sched_itmt_flags();
}
#endif
#endif

static struct sched_domain_topology_level x86_numa_in_package_topology[] = {
#ifdef CONFIG_SCHED_SMT
	{ cpu_smt_mask, x86_smt_flags, SD_INIT_NAME(SMT) },
#endif
#ifdef CONFIG_SCHED_CLUSTER
	{ cpu_clustergroup_mask, x86_cluster_flags, SD_INIT_NAME(CLS) },
#endif
#ifdef CONFIG_SCHED_MC
	{ cpu_coregroup_mask, x86_core_flags, SD_INIT_NAME(MC) },
#endif
	{ NULL, },
};

static struct sched_domain_topology_level x86_hybrid_topology[] = {
#ifdef CONFIG_SCHED_SMT
	{ cpu_smt_mask, x86_smt_flags, SD_INIT_NAME(SMT) },
#endif
#ifdef CONFIG_SCHED_MC
	{ cpu_coregroup_mask, x86_core_flags, SD_INIT_NAME(MC) },
#endif
	{ cpu_cpu_mask, SD_INIT_NAME(DIE) },
	{ NULL, },
};

static struct sched_domain_topology_level x86_topology[] = {
#ifdef CONFIG_SCHED_SMT
	{ cpu_smt_mask, x86_smt_flags, SD_INIT_NAME(SMT) },
#endif
#ifdef CONFIG_SCHED_CLUSTER
	{ cpu_clustergroup_mask, x86_cluster_flags, SD_INIT_NAME(CLS) },
#endif
#ifdef CONFIG_SCHED_MC
	{ cpu_coregroup_mask, x86_core_flags, SD_INIT_NAME(MC) },
#endif
	{ cpu_cpu_mask, SD_INIT_NAME(DIE) },
	{ NULL, },
};

static bool x86_has_numa_in_package;

void set_cpu_sibling_map(int cpu)
{
	bool has_smt = smp_num_siblings > 1;
	bool has_mp = has_smt || boot_cpu_data.x86_max_cores > 1;
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	struct cpuinfo_x86 *o;
	int i, threads;

	cpumask_set_cpu(cpu, cpu_sibling_setup_mask);

	if (!has_mp) {
		cpumask_set_cpu(cpu, topology_sibling_cpumask(cpu));
		cpumask_set_cpu(cpu, cpu_llc_shared_mask(cpu));
		cpumask_set_cpu(cpu, cpu_l2c_shared_mask(cpu));
		cpumask_set_cpu(cpu, topology_core_cpumask(cpu));
		cpumask_set_cpu(cpu, topology_die_cpumask(cpu));
		c->booted_cores = 1;
		return;
	}

	for_each_cpu(i, cpu_sibling_setup_mask) {
		o = &cpu_data(i);

		if (match_pkg(c, o) && !topology_same_node(c, o))
			x86_has_numa_in_package = true;

		if ((i == cpu) || (has_smt && match_smt(c, o)))
			link_mask(topology_sibling_cpumask, cpu, i);

		if ((i == cpu) || (has_mp && match_llc(c, o)))
			link_mask(cpu_llc_shared_mask, cpu, i);

		if ((i == cpu) || (has_mp && match_l2c(c, o)))
			link_mask(cpu_l2c_shared_mask, cpu, i);

		if ((i == cpu) || (has_mp && match_die(c, o)))
			link_mask(topology_die_cpumask, cpu, i);
	}

	threads = cpumask_weight(topology_sibling_cpumask(cpu));
	if (threads > __max_smt_threads)
		__max_smt_threads = threads;

	for_each_cpu(i, topology_sibling_cpumask(cpu))
		cpu_data(i).smt_active = threads > 1;

	/*
	for_each_cpu(i, cpu_sibling_setup_mask) {
		o = &cpu_data(i);

		if ((i == cpu) || (has_mp && match_pkg(c, o))) {
			link_mask(topology_core_cpumask, cpu, i);

			/*
			if (threads == 1) {
				/*
				if (cpumask_first(
				    topology_sibling_cpumask(i)) == i)
					c->booted_cores++;
				/*
				if (i != cpu)
					cpu_data(i).booted_cores++;
			} else if (i != cpu && !c->booted_cores)
				c->booted_cores = cpu_data(i).booted_cores;
		}
	}
}

const struct cpumask *cpu_coregroup_mask(int cpu)
{
	return cpu_llc_shared_mask(cpu);
}

const struct cpumask *cpu_clustergroup_mask(int cpu)
{
	return cpu_l2c_shared_mask(cpu);
}

static void impress_friends(void)
{
	int cpu;
	unsigned long bogosum = 0;
	/*
	pr_debug("Before bogomips\n");
	for_each_possible_cpu(cpu)
		if (cpumask_test_cpu(cpu, cpu_callout_mask))
			bogosum += cpu_data(cpu).loops_per_jiffy;
	pr_info("Total of %d processors activated (%lu.%02lu BogoMIPS)\n",
		num_online_cpus(),
		bogosum/(500000/HZ),
		(bogosum/(5000/HZ))%100);

	pr_debug("Before bogocount - setting activated=1\n");
}

void __inquire_remote_apic(int apicid)
{
	unsigned i, regs[] = { APIC_ID >> 4, APIC_LVR >> 4, APIC_SPIV >> 4 };
	const char * const names[] = { "ID", "VERSION", "SPIV" };
	int timeout;
	u32 status;

	pr_info("Inquiring remote APIC 0x%x...\n", apicid);

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		pr_info("... APIC 0x%x %s: ", apicid, names[i]);

		/*
		status = safe_apic_wait_icr_idle();
		if (status)
			pr_cont("a previous APIC delivery may have failed\n");

		apic_icr_write(APIC_DM_REMRD | regs[i], apicid);

		timeout = 0;
		do {
			udelay(100);
			status = apic_read(APIC_ICR) & APIC_ICR_RR_MASK;
		} while (status == APIC_ICR_RR_INPROG && timeout++ < 1000);

		switch (status) {
		case APIC_ICR_RR_VALID:
			status = apic_read(APIC_RRR);
			pr_cont("%08x\n", status);
			break;
		default:
			pr_cont("failed\n");
		}
	}
}

#define UDELAY_10MS_DEFAULT 10000

static unsigned int init_udelay = UINT_MAX;

static int __init cpu_init_udelay(char *str)
{
	get_option(&str, &init_udelay);

	return 0;
}
early_param("cpu_init_udelay", cpu_init_udelay);

static void __init smp_quirk_init_udelay(void)
{
	/* if cmdline changed it from default, leave it alone */
	if (init_udelay != UINT_MAX)
		return;

	/* if modern processor, use no delay */
	if (((boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) && (boot_cpu_data.x86 == 6)) ||
	    ((boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) && (boot_cpu_data.x86 >= 0x18)) ||
	    ((boot_cpu_data.x86_vendor == X86_VENDOR_AMD) && (boot_cpu_data.x86 >= 0xF))) {
		init_udelay = 0;
		return;
	}
	/* else, use legacy delay */
	init_udelay = UDELAY_10MS_DEFAULT;
}

int
wakeup_secondary_cpu_via_nmi(int apicid, unsigned long start_eip)
{
	u32 dm = apic->dest_mode_logical ? APIC_DEST_LOGICAL : APIC_DEST_PHYSICAL;
	unsigned long send_status, accept_status = 0;
	int maxlvt;

	/* Target chip */
	/* Boot on the stack */
	/* Kick the second */
	apic_icr_write(APIC_DM_NMI | dm, apicid);

	pr_debug("Waiting for send to finish...\n");
	send_status = safe_apic_wait_icr_idle();

	/*
	udelay(200);
	if (APIC_INTEGRATED(boot_cpu_apic_version)) {
		maxlvt = lapic_get_maxlvt();
		if (maxlvt > 3)			/* Due to the Pentium erratum 3AP.  */
			apic_write(APIC_ESR, 0);
		accept_status = (apic_read(APIC_ESR) & 0xEF);
	}
	pr_debug("NMI sent\n");

	if (send_status)
		pr_err("APIC never delivered???\n");
	if (accept_status)
		pr_err("APIC delivery error (%lx)\n", accept_status);

	return (send_status | accept_status);
}

static int
wakeup_secondary_cpu_via_init(int phys_apicid, unsigned long start_eip)
{
	unsigned long send_status = 0, accept_status = 0;
	int maxlvt, num_starts, j;

	maxlvt = lapic_get_maxlvt();

	/*
	if (APIC_INTEGRATED(boot_cpu_apic_version)) {
		if (maxlvt > 3)		/* Due to the Pentium erratum 3AP.  */
			apic_write(APIC_ESR, 0);
		apic_read(APIC_ESR);
	}

	pr_debug("Asserting INIT\n");

	/*
	/*
	apic_icr_write(APIC_INT_LEVELTRIG | APIC_INT_ASSERT | APIC_DM_INIT,
		       phys_apicid);

	pr_debug("Waiting for send to finish...\n");
	send_status = safe_apic_wait_icr_idle();

	udelay(init_udelay);

	pr_debug("Deasserting INIT\n");

	/* Target chip */
	/* Send IPI */
	apic_icr_write(APIC_INT_LEVELTRIG | APIC_DM_INIT, phys_apicid);

	pr_debug("Waiting for send to finish...\n");
	send_status = safe_apic_wait_icr_idle();

	mb();

	/*
	if (APIC_INTEGRATED(boot_cpu_apic_version))
		num_starts = 2;
	else
		num_starts = 0;

	/*
	pr_debug("#startup loops: %d\n", num_starts);

	for (j = 1; j <= num_starts; j++) {
		pr_debug("Sending STARTUP #%d\n", j);
		if (maxlvt > 3)		/* Due to the Pentium erratum 3AP.  */
			apic_write(APIC_ESR, 0);
		apic_read(APIC_ESR);
		pr_debug("After apic_write\n");

		/*

		/* Target chip */
		/* Boot on the stack */
		/* Kick the second */
		apic_icr_write(APIC_DM_STARTUP | (start_eip >> 12),
			       phys_apicid);

		/*
		if (init_udelay == 0)
			udelay(10);
		else
			udelay(300);

		pr_debug("Startup point 1\n");

		pr_debug("Waiting for send to finish...\n");
		send_status = safe_apic_wait_icr_idle();

		/*
		if (init_udelay == 0)
			udelay(10);
		else
			udelay(200);

		if (maxlvt > 3)		/* Due to the Pentium erratum 3AP.  */
			apic_write(APIC_ESR, 0);
		accept_status = (apic_read(APIC_ESR) & 0xEF);
		if (send_status || accept_status)
			break;
	}
	pr_debug("After Startup\n");

	if (send_status)
		pr_err("APIC never delivered???\n");
	if (accept_status)
		pr_err("APIC delivery error (%lx)\n", accept_status);

	return (send_status | accept_status);
}

static void announce_cpu(int cpu, int apicid)
{
	static int current_node = NUMA_NO_NODE;
	int node = early_cpu_to_node(cpu);
	static int width, node_width;

	if (!width)
		width = num_digits(num_possible_cpus()) + 1; /* + '#' sign */

	if (!node_width)
		node_width = num_digits(num_possible_nodes()) + 1; /* + '#' */

	if (cpu == 1)
		printk(KERN_INFO "x86: Booting SMP configuration:\n");

	if (system_state < SYSTEM_RUNNING) {
		if (node != current_node) {
			if (current_node > (-1))
				pr_cont("\n");
			current_node = node;

			printk(KERN_INFO ".... node %*s#%d, CPUs:  ",
			       node_width - num_digits(node), " ", node);
		}

		/* Add padding for the BSP */
		if (cpu == 1)
			pr_cont("%*s", width + 1, " ");

		pr_cont("%*s#%d", width - num_digits(cpu), " ", cpu);

	} else
		pr_info("Booting Node %d Processor %d APIC 0x%x\n",
			node, cpu, apicid);
}

static int wakeup_cpu0_nmi(unsigned int cmd, struct pt_regs *regs)
{
	int cpu;

	cpu = smp_processor_id();
	if (cpu == 0 && !cpu_online(cpu) && enable_start_cpu0)
		return NMI_HANDLED;

	return NMI_DONE;
}

static int
wakeup_cpu_via_init_nmi(int cpu, unsigned long start_ip, int apicid,
	       int *cpu0_nmi_registered)
{
	int id;
	int boot_error;

	preempt_disable();

	/*
	if (cpu) {
		boot_error = wakeup_secondary_cpu_via_init(apicid, start_ip);
		goto out;
	}

	/*
	boot_error = register_nmi_handler(NMI_LOCAL,
					  wakeup_cpu0_nmi, 0, "wake_cpu0");

	if (!boot_error) {
		enable_start_cpu0 = 1;
		*cpu0_nmi_registered = 1;
		id = apic->dest_mode_logical ? cpu0_logical_apicid : apicid;
		boot_error = wakeup_secondary_cpu_via_nmi(id, start_ip);
	}

out:
	preempt_enable();

	return boot_error;
}

int common_cpu_up(unsigned int cpu, struct task_struct *idle)
{
	int ret;

	/* Just in case we booted with a single CPU. */
	alternatives_enable_smp();

	per_cpu(current_task, cpu) = idle;
	cpu_init_stack_canary(cpu, idle);

	/* Initialize the interrupt stack(s) */
	ret = irq_init_percpu_irqstack(cpu);
	if (ret)
		return ret;

#ifdef CONFIG_X86_32
	/* Stack for startup_32 can be just as for start_secondary onwards */
	per_cpu(cpu_current_top_of_stack, cpu) = task_top_of_stack(idle);
#else
	initial_gs = per_cpu_offset(cpu);
#endif
	return 0;
}

static int do_boot_cpu(int apicid, int cpu, struct task_struct *idle,
		       int *cpu0_nmi_registered)
{
	/* start_ip had better be page-aligned! */
	unsigned long start_ip = real_mode_header->trampoline_start;

	unsigned long boot_error = 0;
	unsigned long timeout;

#ifdef CONFIG_X86_64
	/* If 64-bit wakeup method exists, use the 64-bit mode trampoline IP */
	if (apic->wakeup_secondary_cpu_64)
		start_ip = real_mode_header->trampoline_start64;
#endif
	idle->thread.sp = (unsigned long)task_pt_regs(idle);
	early_gdt_descr.address = (unsigned long)get_cpu_gdt_rw(cpu);
	initial_code = (unsigned long)start_secondary;
	initial_stack  = idle->thread.sp;

	/* Enable the espfix hack for this CPU */
	init_espfix_ap(cpu);

	/* So we see what's up */
	announce_cpu(cpu, apicid);

	/*

	if (x86_platform.legacy.warm_reset) {

		pr_debug("Setting warm reset code and vector.\n");

		smpboot_setup_warm_reset_vector(start_ip);
		/*
		if (APIC_INTEGRATED(boot_cpu_apic_version)) {
			apic_write(APIC_ESR, 0);
			apic_read(APIC_ESR);
		}
	}

	/*
	cpumask_clear_cpu(cpu, cpu_initialized_mask);
	smp_mb();

	/*
	if (apic->wakeup_secondary_cpu_64)
		boot_error = apic->wakeup_secondary_cpu_64(apicid, start_ip);
	else if (apic->wakeup_secondary_cpu)
		boot_error = apic->wakeup_secondary_cpu(apicid, start_ip);
	else
		boot_error = wakeup_cpu_via_init_nmi(cpu, start_ip, apicid,
						     cpu0_nmi_registered);

	if (!boot_error) {
		/*
		boot_error = -1;
		timeout = jiffies + 10*HZ;
		while (time_before(jiffies, timeout)) {
			if (cpumask_test_cpu(cpu, cpu_initialized_mask)) {
				/*
				cpumask_set_cpu(cpu, cpu_callout_mask);
				boot_error = 0;
				break;
			}
			schedule();
		}
	}

	if (!boot_error) {
		/*
		while (!cpumask_test_cpu(cpu, cpu_callin_mask)) {
			/*
			schedule();
		}
	}

	if (x86_platform.legacy.warm_reset) {
		/*
		smpboot_restore_warm_reset_vector();
	}

	return boot_error;
}

int native_cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	int apicid = apic->cpu_present_to_apicid(cpu);
	int cpu0_nmi_registered = 0;
	unsigned long flags;
	int err, ret = 0;

	lockdep_assert_irqs_enabled();

	pr_debug("++++++++++++++++++++=_---CPU UP  %u\n", cpu);

	if (apicid == BAD_APICID ||
	    !physid_isset(apicid, phys_cpu_present_map) ||
	    !apic->apic_id_valid(apicid)) {
		pr_err("%s: bad cpu %d\n", __func__, cpu);
		return -EINVAL;
	}

	/*
	if (cpumask_test_cpu(cpu, cpu_callin_mask)) {
		pr_debug("do_boot_cpu %d Already started\n", cpu);
		return -ENOSYS;
	}

	/*
	mtrr_save_state();

	/* x86 CPUs take themselves offline, so delayed offline is OK. */
	err = cpu_check_up_prepare(cpu);
	if (err && err != -EBUSY)
		return err;

	/* the FPU context is blank, nobody can own it */
	per_cpu(fpu_fpregs_owner_ctx, cpu) = NULL;

	err = common_cpu_up(cpu, tidle);
	if (err)
		return err;

	err = do_boot_cpu(apicid, cpu, tidle, &cpu0_nmi_registered);
	if (err) {
		pr_err("do_boot_cpu failed(%d) to wakeup CPU#%u\n", err, cpu);
		ret = -EIO;
		goto unreg_nmi;
	}

	/*
	local_irq_save(flags);
	check_tsc_sync_source(cpu);
	local_irq_restore(flags);

	while (!cpu_online(cpu)) {
		cpu_relax();
		touch_nmi_watchdog();
	}

unreg_nmi:
	/*
	if (cpu0_nmi_registered)
		unregister_nmi_handler(NMI_LOCAL, "wake_cpu0");

	return ret;
}

void arch_disable_smp_support(void)
{
	disable_ioapic_support();
}

static __init void disable_smp(void)
{
	pr_info("SMP disabled\n");

	disable_ioapic_support();

	init_cpu_present(cpumask_of(0));
	init_cpu_possible(cpumask_of(0));

	if (smp_found_config)
		physid_set_mask_of_physid(boot_cpu_physical_apicid, &phys_cpu_present_map);
	else
		physid_set_mask_of_physid(0, &phys_cpu_present_map);
	cpumask_set_cpu(0, topology_sibling_cpumask(0));
	cpumask_set_cpu(0, topology_core_cpumask(0));
	cpumask_set_cpu(0, topology_die_cpumask(0));
}

static void __init smp_sanity_check(void)
{
	preempt_disable();

#if !defined(CONFIG_X86_BIGSMP) && defined(CONFIG_X86_32)
	if (def_to_bigsmp && nr_cpu_ids > 8) {
		unsigned int cpu;
		unsigned nr;

		pr_warn("More than 8 CPUs detected - skipping them\n"
			"Use CONFIG_X86_BIGSMP\n");

		nr = 0;
		for_each_present_cpu(cpu) {
			if (nr >= 8)
				set_cpu_present(cpu, false);
			nr++;
		}

		nr = 0;
		for_each_possible_cpu(cpu) {
			if (nr >= 8)
				set_cpu_possible(cpu, false);
			nr++;
		}

		nr_cpu_ids = 8;
	}
#endif

	if (!physid_isset(hard_smp_processor_id(), phys_cpu_present_map)) {
		pr_warn("weird, boot CPU (#%d) not listed by the BIOS\n",
			hard_smp_processor_id());

		physid_set(hard_smp_processor_id(), phys_cpu_present_map);
	}

	/*
	if (!apic->check_phys_apicid_present(boot_cpu_physical_apicid)) {
		pr_notice("weird, boot CPU (#%d) not listed by the BIOS\n",
			  boot_cpu_physical_apicid);
		physid_set(hard_smp_processor_id(), phys_cpu_present_map);
	}
	preempt_enable();
}

static void __init smp_cpu_index_default(void)
{
	int i;
	struct cpuinfo_x86 *c;

	for_each_possible_cpu(i) {
		c = &cpu_data(i);
		/* mark all to hotplug */
		c->cpu_index = nr_cpu_ids;
	}
}

static void __init smp_get_logical_apicid(void)
{
	if (x2apic_mode)
		cpu0_logical_apicid = apic_read(APIC_LDR);
	else
		cpu0_logical_apicid = GET_APIC_LOGICAL_ID(apic_read(APIC_LDR));
}

void __init smp_prepare_cpus_common(void)
{
	unsigned int i;

	smp_cpu_index_default();

	/*
	smp_store_boot_cpu_info(); /* Final full version of the data */
	cpumask_copy(cpu_callin_mask, cpumask_of(0));
	mb();

	for_each_possible_cpu(i) {
		zalloc_cpumask_var(&per_cpu(cpu_sibling_map, i), GFP_KERNEL);
		zalloc_cpumask_var(&per_cpu(cpu_core_map, i), GFP_KERNEL);
		zalloc_cpumask_var(&per_cpu(cpu_die_map, i), GFP_KERNEL);
		zalloc_cpumask_var(&per_cpu(cpu_llc_shared_map, i), GFP_KERNEL);
		zalloc_cpumask_var(&per_cpu(cpu_l2c_shared_map, i), GFP_KERNEL);
	}

	/*
	set_sched_topology(x86_topology);

	set_cpu_sibling_map(0);
}

void __init native_smp_prepare_cpus(unsigned int max_cpus)
{
	smp_prepare_cpus_common();

	smp_sanity_check();

	switch (apic_intr_mode) {
	case APIC_PIC:
	case APIC_VIRTUAL_WIRE_NO_CONFIG:
		disable_smp();
		return;
	case APIC_SYMMETRIC_IO_NO_ROUTING:
		disable_smp();
		/* Setup local timer */
		x86_init.timers.setup_percpu_clockev();
		return;
	case APIC_VIRTUAL_WIRE:
	case APIC_SYMMETRIC_IO:
		break;
	}

	/* Setup local timer */
	x86_init.timers.setup_percpu_clockev();

	smp_get_logical_apicid();

	pr_info("CPU0: ");
	print_cpu_info(&cpu_data(0));

	uv_system_init();

	set_mtrr_aps_delayed_init();

	smp_quirk_init_udelay();

	speculative_store_bypass_ht_init();

	snp_set_wakeup_secondary_cpu();
}

void arch_thaw_secondary_cpus_begin(void)
{
	set_mtrr_aps_delayed_init();
}

void arch_thaw_secondary_cpus_end(void)
{
	mtrr_aps_init();
}

void __init native_smp_prepare_boot_cpu(void)
{
	int me = smp_processor_id();
	switch_to_new_gdt(me);
	/* already set me in cpu_online_mask in boot_cpu_init() */
	cpumask_set_cpu(me, cpu_callout_mask);
	cpu_set_state_online(me);
	native_pv_lock_init();
}

void __init calculate_max_logical_packages(void)
{
	int ncpus;

	/*
	ncpus = cpu_data(0).booted_cores * topology_max_smt_threads();
	__max_logical_packages = DIV_ROUND_UP(total_cpus, ncpus);
	pr_info("Max logical packages: %u\n", __max_logical_packages);
}

void __init native_smp_cpus_done(unsigned int max_cpus)
{
	pr_debug("Boot done\n");

	calculate_max_logical_packages();

	/* XXX for now assume numa-in-package and hybrid don't overlap */
	if (x86_has_numa_in_package)
		set_sched_topology(x86_numa_in_package_topology);
	if (cpu_feature_enabled(X86_FEATURE_HYBRID_CPU))
		set_sched_topology(x86_hybrid_topology);

	nmi_selftest();
	impress_friends();
	mtrr_aps_init();
}

static int __initdata setup_possible_cpus = -1;
static int __init _setup_possible_cpus(char *str)
{
	get_option(&str, &setup_possible_cpus);
	return 0;
}
early_param("possible_cpus", _setup_possible_cpus);


__init void prefill_possible_map(void)
{
	int i, possible;

	/* No boot processor was found in mptable or ACPI MADT */
	if (!num_processors) {
		if (boot_cpu_has(X86_FEATURE_APIC)) {
			int apicid = boot_cpu_physical_apicid;
			int cpu = hard_smp_processor_id();

			pr_warn("Boot CPU (id %d) not listed by BIOS\n", cpu);

			/* Make sure boot cpu is enumerated */
			if (apic->cpu_present_to_apicid(0) == BAD_APICID &&
			    apic->apic_id_valid(apicid))
				generic_processor_info(apicid, boot_cpu_apic_version);
		}

		if (!num_processors)
			num_processors = 1;
	}

	i = setup_max_cpus ?: 1;
	if (setup_possible_cpus == -1) {
		possible = num_processors;
#ifdef CONFIG_HOTPLUG_CPU
		if (setup_max_cpus)
			possible += disabled_cpus;
#else
		if (possible > i)
			possible = i;
#endif
	} else
		possible = setup_possible_cpus;

	total_cpus = max_t(int, possible, num_processors + disabled_cpus);

	/* nr_cpu_ids could be reduced via nr_cpus= */
	if (possible > nr_cpu_ids) {
		pr_warn("%d Processors exceeds NR_CPUS limit of %u\n",
			possible, nr_cpu_ids);
		possible = nr_cpu_ids;
	}

#ifdef CONFIG_HOTPLUG_CPU
	if (!setup_max_cpus)
#endif
	if (possible > i) {
		pr_warn("%d Processors exceeds max_cpus limit of %u\n",
			possible, setup_max_cpus);
		possible = i;
	}

	nr_cpu_ids = possible;

	pr_info("Allowing %d CPUs, %d hotplug CPUs\n",
		possible, max_t(int, possible - num_processors, 0));

	reset_cpu_possible_mask();

	for (i = 0; i < possible; i++)
		set_cpu_possible(i, true);
}

#ifdef CONFIG_HOTPLUG_CPU

static void recompute_smt_state(void)
{
	int max_threads, cpu;

	max_threads = 0;
	for_each_online_cpu (cpu) {
		int threads = cpumask_weight(topology_sibling_cpumask(cpu));

		if (threads > max_threads)
			max_threads = threads;
	}
	__max_smt_threads = max_threads;
}

static void remove_siblinginfo(int cpu)
{
	int sibling;
	struct cpuinfo_x86 *c = &cpu_data(cpu);

	for_each_cpu(sibling, topology_core_cpumask(cpu)) {
		cpumask_clear_cpu(cpu, topology_core_cpumask(sibling));
		/*/
		 * last thread sibling in this cpu core going down
		 */
		if (cpumask_weight(topology_sibling_cpumask(cpu)) == 1)
			cpu_data(sibling).booted_cores--;
	}

	for_each_cpu(sibling, topology_die_cpumask(cpu))
		cpumask_clear_cpu(cpu, topology_die_cpumask(sibling));

	for_each_cpu(sibling, topology_sibling_cpumask(cpu)) {
		cpumask_clear_cpu(cpu, topology_sibling_cpumask(sibling));
		if (cpumask_weight(topology_sibling_cpumask(sibling)) == 1)
			cpu_data(sibling).smt_active = false;
	}

	for_each_cpu(sibling, cpu_llc_shared_mask(cpu))
		cpumask_clear_cpu(cpu, cpu_llc_shared_mask(sibling));
	for_each_cpu(sibling, cpu_l2c_shared_mask(cpu))
		cpumask_clear_cpu(cpu, cpu_l2c_shared_mask(sibling));
	cpumask_clear(cpu_llc_shared_mask(cpu));
	cpumask_clear(cpu_l2c_shared_mask(cpu));
	cpumask_clear(topology_sibling_cpumask(cpu));
	cpumask_clear(topology_core_cpumask(cpu));
	cpumask_clear(topology_die_cpumask(cpu));
	c->cpu_core_id = 0;
	c->booted_cores = 0;
	cpumask_clear_cpu(cpu, cpu_sibling_setup_mask);
	recompute_smt_state();
}

static void remove_cpu_from_maps(int cpu)
{
	set_cpu_online(cpu, false);
	cpumask_clear_cpu(cpu, cpu_callout_mask);
	cpumask_clear_cpu(cpu, cpu_callin_mask);
	/* was set by cpu_init() */
	cpumask_clear_cpu(cpu, cpu_initialized_mask);
	numa_remove_cpu(cpu);
}

void cpu_disable_common(void)
{
	int cpu = smp_processor_id();

	remove_siblinginfo(cpu);

	/* It's now safe to remove this processor from the online map */
	lock_vector_lock();
	remove_cpu_from_maps(cpu);
	unlock_vector_lock();
	fixup_irqs();
	lapic_offline();
}

int native_cpu_disable(void)
{
	int ret;

	ret = lapic_can_unplug_cpu();
	if (ret)
		return ret;

	cpu_disable_common();

        /*
	apic_soft_disable();

	return 0;
}

int common_cpu_die(unsigned int cpu)
{
	int ret = 0;

	/* We don't do anything here: idle task is faking death itself. */

	/* They ack this in play_dead() by setting CPU_DEAD */
	if (cpu_wait_death(cpu, 5)) {
		if (system_state == SYSTEM_RUNNING)
			pr_info("CPU %u is now offline\n", cpu);
	} else {
		pr_err("CPU %u didn't die...\n", cpu);
		ret = -1;
	}

	return ret;
}

void native_cpu_die(unsigned int cpu)
{
	common_cpu_die(cpu);
}

void play_dead_common(void)
{
	idle_task_exit();

	/* Ack it */
	(void)cpu_report_death();

	/*
	local_irq_disable();
}

void cond_wakeup_cpu0(void)
{
	if (smp_processor_id() == 0 && enable_start_cpu0)
		start_cpu0();
}
EXPORT_SYMBOL_GPL(cond_wakeup_cpu0);

static inline void mwait_play_dead(void)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned int highest_cstate = 0;
	unsigned int highest_subcstate = 0;
	void *mwait_ptr;
	int i;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD ||
	    boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
		return;
	if (!this_cpu_has(X86_FEATURE_MWAIT))
		return;
	if (!this_cpu_has(X86_FEATURE_CLFLUSH))
		return;
	if (__this_cpu_read(cpu_info.cpuid_level) < CPUID_MWAIT_LEAF)
		return;

	eax = CPUID_MWAIT_LEAF;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);

	/*
	if (!(ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED)) {
		eax = 0;
	} else {
		edx >>= MWAIT_SUBSTATE_SIZE;
		for (i = 0; i < 7 && edx; i++, edx >>= MWAIT_SUBSTATE_SIZE) {
			if (edx & MWAIT_SUBSTATE_MASK) {
				highest_cstate = i;
				highest_subcstate = edx & MWAIT_SUBSTATE_MASK;
			}
		}
		eax = (highest_cstate << MWAIT_SUBSTATE_SIZE) |
			(highest_subcstate - 1);
	}

	/*
	mwait_ptr = &current_thread_info()->flags;

	wbinvd();

	while (1) {
		/*
		mb();
		clflush(mwait_ptr);
		mb();
		__monitor(mwait_ptr, 0, 0);
		mb();
		__mwait(eax, 0);

		cond_wakeup_cpu0();
	}
}

void hlt_play_dead(void)
{
	if (__this_cpu_read(cpu_info.x86) >= 4)
		wbinvd();

	while (1) {
		native_halt();

		cond_wakeup_cpu0();
	}
}

void native_play_dead(void)
{
	play_dead_common();
	tboot_shutdown(TB_SHUTDOWN_WFS);

	mwait_play_dead();	/* Only returns on failure */
	if (cpuidle_play_dead())
		hlt_play_dead();
}

#else /* ... !CONFIG_HOTPLUG_CPU */
int native_cpu_disable(void)
{
	return -ENOSYS;
}

void native_cpu_die(unsigned int cpu)
{
	/* We said "no" in __cpu_disable */
	BUG();
}

void native_play_dead(void)
{
	BUG();
}

#endif
