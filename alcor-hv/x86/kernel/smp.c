
#include <linux/init.h>

#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/export.h>
#include <linux/kernel_stat.h>
#include <linux/mc146818rtc.h>
#include <linux/cache.h>
#include <linux/interrupt.h>
#include <linux/cpu.h>
#include <linux/gfp.h>

#include <asm/mtrr.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/proto.h>
#include <asm/apic.h>
#include <asm/idtentry.h>
#include <asm/nmi.h>
#include <asm/mce.h>
#include <asm/trace/irq_vectors.h>
#include <asm/kexec.h>
#include <asm/virtext.h>


static atomic_t stopping_cpu = ATOMIC_INIT(-1);
static bool smp_no_nmi_ipi = false;

static int smp_stop_nmi_callback(unsigned int val, struct pt_regs *regs)
{
	/* We are registered on stopping cpu too, avoid spurious NMI */
	if (raw_smp_processor_id() == atomic_read(&stopping_cpu))
		return NMI_HANDLED;

	cpu_emergency_vmxoff();
	stop_this_cpu(NULL);

	return NMI_HANDLED;
}

DEFINE_IDTENTRY_SYSVEC(sysvec_reboot)
{
	ack_APIC_irq();
	cpu_emergency_vmxoff();
	stop_this_cpu(NULL);
}

static int register_stop_handler(void)
{
	return register_nmi_handler(NMI_LOCAL, smp_stop_nmi_callback,
				    NMI_FLAG_FIRST, "smp_stop");
}

static void native_stop_other_cpus(int wait)
{
	unsigned long flags;
	unsigned long timeout;

	if (reboot_force)
		return;

	/*

	/*
	if (num_online_cpus() > 1) {
		/* did someone beat us here? */
		if (atomic_cmpxchg(&stopping_cpu, -1, safe_smp_processor_id()) != -1)
			return;

		/* sync above data before sending IRQ */
		wmb();

		apic_send_IPI_allbutself(REBOOT_VECTOR);

		/*
		timeout = USEC_PER_SEC;
		while (num_online_cpus() > 1 && timeout--)
			udelay(1);
	}

	/* if the REBOOT_VECTOR didn't work, try with the NMI */
	if (num_online_cpus() > 1) {
		/*
		if (!smp_no_nmi_ipi && !register_stop_handler()) {
			/* Sync above data before sending IRQ */
			wmb();

			pr_emerg("Shutting down cpus with NMI\n");

			apic_send_IPI_allbutself(NMI_VECTOR);
		}
		/*
		timeout = USEC_PER_MSEC * 10;
		while (num_online_cpus() > 1 && (wait || timeout--))
			udelay(1);
	}

	local_irq_save(flags);
	disable_local_APIC();
	mcheck_cpu_clear(this_cpu_ptr(&cpu_info));
	local_irq_restore(flags);
}

DEFINE_IDTENTRY_SYSVEC_SIMPLE(sysvec_reschedule_ipi)
{
	ack_APIC_irq();
	trace_reschedule_entry(RESCHEDULE_VECTOR);
	inc_irq_stat(irq_resched_count);
	scheduler_ipi();
	trace_reschedule_exit(RESCHEDULE_VECTOR);
}

DEFINE_IDTENTRY_SYSVEC(sysvec_call_function)
{
	ack_APIC_irq();
	trace_call_function_entry(CALL_FUNCTION_VECTOR);
	inc_irq_stat(irq_call_count);
	generic_smp_call_function_interrupt();
	trace_call_function_exit(CALL_FUNCTION_VECTOR);
}

DEFINE_IDTENTRY_SYSVEC(sysvec_call_function_single)
{
	ack_APIC_irq();
	trace_call_function_single_entry(CALL_FUNCTION_SINGLE_VECTOR);
	inc_irq_stat(irq_call_count);
	generic_smp_call_function_single_interrupt();
	trace_call_function_single_exit(CALL_FUNCTION_SINGLE_VECTOR);
}

static int __init nonmi_ipi_setup(char *str)
{
	smp_no_nmi_ipi = true;
	return 1;
}

__setup("nonmi_ipi", nonmi_ipi_setup);

struct smp_ops smp_ops = {
	.smp_prepare_boot_cpu	= native_smp_prepare_boot_cpu,
	.smp_prepare_cpus	= native_smp_prepare_cpus,
	.smp_cpus_done		= native_smp_cpus_done,

	.stop_other_cpus	= native_stop_other_cpus,
#if defined(CONFIG_KEXEC_CORE)
	.crash_stop_other_cpus	= kdump_nmi_shootdown_cpus,
#endif
	.smp_send_reschedule	= native_smp_send_reschedule,

	.cpu_up			= native_cpu_up,
	.cpu_die		= native_cpu_die,
	.cpu_disable		= native_cpu_disable,
	.play_dead		= native_play_dead,

	.send_call_func_ipi	= native_send_call_func_ipi,
	.send_call_func_single_ipi = native_send_call_func_single_ipi,
};
EXPORT_SYMBOL_GPL(smp_ops);
