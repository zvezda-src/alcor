#include <linux/thread_info.h>
#include <asm/smp.h>

#include <xen/events.h>

#include "xen-ops.h"
#include "smp.h"


static void __init xen_hvm_smp_prepare_boot_cpu(void)
{
	BUG_ON(smp_processor_id() != 0);
	native_smp_prepare_boot_cpu();

	/*
	xen_vcpu_setup(0);

	/*
	xen_hvm_init_time_ops();

	/*
	xen_init_spinlocks();
}

static void __init xen_hvm_smp_prepare_cpus(unsigned int max_cpus)
{
	int cpu;

	native_smp_prepare_cpus(max_cpus);

	if (xen_have_vector_callback) {
		WARN_ON(xen_smp_intr_init(0));
		xen_init_lock_cpu(0);
	}

	for_each_possible_cpu(cpu) {
		if (cpu == 0)
			continue;

		/* Set default vcpu_id to make sure that we don't use cpu-0's */
		per_cpu(xen_vcpu_id, cpu) = XEN_VCPU_ID_INVALID;
	}
}

#ifdef CONFIG_HOTPLUG_CPU
static void xen_hvm_cpu_die(unsigned int cpu)
{
	if (common_cpu_die(cpu) == 0) {
		if (xen_have_vector_callback) {
			xen_smp_intr_free(cpu);
			xen_uninit_lock_cpu(cpu);
			xen_teardown_timer(cpu);
		}
	}
}
#else
static void xen_hvm_cpu_die(unsigned int cpu)
{
	BUG();
}
#endif

void __init xen_hvm_smp_init(void)
{
	smp_ops.smp_prepare_boot_cpu = xen_hvm_smp_prepare_boot_cpu;
	smp_ops.smp_prepare_cpus = xen_hvm_smp_prepare_cpus;
	smp_ops.smp_cpus_done = xen_smp_cpus_done;
	smp_ops.cpu_die = xen_hvm_cpu_die;

	if (!xen_have_vector_callback) {
#ifdef CONFIG_PARAVIRT_SPINLOCKS
		nopvspin = true;
#endif
		return;
	}

	smp_ops.smp_send_reschedule = xen_smp_send_reschedule;
	smp_ops.send_call_func_ipi = xen_smp_send_call_function_ipi;
	smp_ops.send_call_func_single_ipi = xen_smp_send_call_function_single_ipi;
}
