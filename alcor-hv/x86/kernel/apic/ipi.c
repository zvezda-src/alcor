
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <asm/io_apic.h>

#include "local.h"

DEFINE_STATIC_KEY_FALSE(apic_use_ipi_shorthand);

#ifdef CONFIG_SMP
static int apic_ipi_shorthand_off __ro_after_init;

static __init int apic_ipi_shorthand(char *str)
{
	get_option(&str, &apic_ipi_shorthand_off);
	return 1;
}
__setup("no_ipi_broadcast=", apic_ipi_shorthand);

static int __init print_ipi_mode(void)
{
	pr_info("IPI shorthand broadcast: %s\n",
		apic_ipi_shorthand_off ? "disabled" : "enabled");
	return 0;
}
late_initcall(print_ipi_mode);

void apic_smt_update(void)
{
	/*
	if (apic_ipi_shorthand_off || num_online_cpus() == 1 ||
	    !cpumask_equal(cpu_present_mask, &cpus_booted_once_mask)) {
		static_branch_disable(&apic_use_ipi_shorthand);
	} else {
		static_branch_enable(&apic_use_ipi_shorthand);
	}
}

void apic_send_IPI_allbutself(unsigned int vector)
{
	if (num_online_cpus() < 2)
		return;

	if (static_branch_likely(&apic_use_ipi_shorthand))
		apic->send_IPI_allbutself(vector);
	else
		apic->send_IPI_mask_allbutself(cpu_online_mask, vector);
}

void native_smp_send_reschedule(int cpu)
{
	if (unlikely(cpu_is_offline(cpu))) {
		WARN(1, "sched: Unexpected reschedule of offline CPU#%d!\n", cpu);
		return;
	}
	apic->send_IPI(cpu, RESCHEDULE_VECTOR);
}

void native_send_call_func_single_ipi(int cpu)
{
	apic->send_IPI(cpu, CALL_FUNCTION_SINGLE_VECTOR);
}

void native_send_call_func_ipi(const struct cpumask *mask)
{
	if (static_branch_likely(&apic_use_ipi_shorthand)) {
		unsigned int cpu = smp_processor_id();

		if (!cpumask_or_equal(mask, cpumask_of(cpu), cpu_online_mask))
			goto sendmask;

		if (cpumask_test_cpu(cpu, mask))
			apic->send_IPI_all(CALL_FUNCTION_VECTOR);
		else if (num_online_cpus() > 1)
			apic->send_IPI_allbutself(CALL_FUNCTION_VECTOR);
		return;
	}

sendmask:
	apic->send_IPI_mask(mask, CALL_FUNCTION_VECTOR);
}

#endif /* CONFIG_SMP */

static inline int __prepare_ICR2(unsigned int mask)
{
	return SET_XAPIC_DEST_FIELD(mask);
}

static inline void __xapic_wait_icr_idle(void)
{
	while (native_apic_mem_read(APIC_ICR) & APIC_ICR_BUSY)
		cpu_relax();
}

void __default_send_IPI_shortcut(unsigned int shortcut, int vector)
{
	/*
	unsigned int cfg;

	/*
	if (unlikely(vector == NMI_VECTOR))
		safe_apic_wait_icr_idle();
	else
		__xapic_wait_icr_idle();

	/*
	cfg = __prepare_ICR(shortcut, vector, 0);

	/*
	native_apic_mem_write(APIC_ICR, cfg);
}

void __default_send_IPI_dest_field(unsigned int mask, int vector, unsigned int dest)
{
	unsigned long cfg;

	/*
	if (unlikely(vector == NMI_VECTOR))
		safe_apic_wait_icr_idle();
	else
		__xapic_wait_icr_idle();

	/*
	cfg = __prepare_ICR2(mask);
	native_apic_mem_write(APIC_ICR2, cfg);

	/*
	cfg = __prepare_ICR(0, vector, dest);

	/*
	native_apic_mem_write(APIC_ICR, cfg);
}

void default_send_IPI_single_phys(int cpu, int vector)
{
	unsigned long flags;

	local_irq_save(flags);
	__default_send_IPI_dest_field(per_cpu(x86_cpu_to_apicid, cpu),
				      vector, APIC_DEST_PHYSICAL);
	local_irq_restore(flags);
}

void default_send_IPI_mask_sequence_phys(const struct cpumask *mask, int vector)
{
	unsigned long query_cpu;
	unsigned long flags;

	/*
	local_irq_save(flags);
	for_each_cpu(query_cpu, mask) {
		__default_send_IPI_dest_field(per_cpu(x86_cpu_to_apicid,
				query_cpu), vector, APIC_DEST_PHYSICAL);
	}
	local_irq_restore(flags);
}

void default_send_IPI_mask_allbutself_phys(const struct cpumask *mask,
						 int vector)
{
	unsigned int this_cpu = smp_processor_id();
	unsigned int query_cpu;
	unsigned long flags;

	/* See Hack comment above */

	local_irq_save(flags);
	for_each_cpu(query_cpu, mask) {
		if (query_cpu == this_cpu)
			continue;
		__default_send_IPI_dest_field(per_cpu(x86_cpu_to_apicid,
				 query_cpu), vector, APIC_DEST_PHYSICAL);
	}
	local_irq_restore(flags);
}

void default_send_IPI_single(int cpu, int vector)
{
	apic->send_IPI_mask(cpumask_of(cpu), vector);
}

void default_send_IPI_allbutself(int vector)
{
	__default_send_IPI_shortcut(APIC_DEST_ALLBUT, vector);
}

void default_send_IPI_all(int vector)
{
	__default_send_IPI_shortcut(APIC_DEST_ALLINC, vector);
}

void default_send_IPI_self(int vector)
{
	__default_send_IPI_shortcut(APIC_DEST_SELF, vector);
}

#ifdef CONFIG_X86_32

void default_send_IPI_mask_sequence_logical(const struct cpumask *mask,
						 int vector)
{
	unsigned long flags;
	unsigned int query_cpu;

	/*

	local_irq_save(flags);
	for_each_cpu(query_cpu, mask)
		__default_send_IPI_dest_field(
			early_per_cpu(x86_cpu_to_logical_apicid, query_cpu),
			vector, APIC_DEST_LOGICAL);
	local_irq_restore(flags);
}

void default_send_IPI_mask_allbutself_logical(const struct cpumask *mask,
						 int vector)
{
	unsigned long flags;
	unsigned int query_cpu;
	unsigned int this_cpu = smp_processor_id();

	/* See Hack comment above */

	local_irq_save(flags);
	for_each_cpu(query_cpu, mask) {
		if (query_cpu == this_cpu)
			continue;
		__default_send_IPI_dest_field(
			early_per_cpu(x86_cpu_to_logical_apicid, query_cpu),
			vector, APIC_DEST_LOGICAL);
		}
	local_irq_restore(flags);
}

void default_send_IPI_mask_logical(const struct cpumask *cpumask, int vector)
{
	unsigned long mask = cpumask_bits(cpumask)[0];
	unsigned long flags;

	if (!mask)
		return;

	local_irq_save(flags);
	WARN_ON(mask & ~cpumask_bits(cpu_online_mask)[0]);
	__default_send_IPI_dest_field(mask, vector, APIC_DEST_LOGICAL);
	local_irq_restore(flags);
}

static int convert_apicid_to_cpu(int apic_id)
{
	int i;

	for_each_possible_cpu(i) {
		if (per_cpu(x86_cpu_to_apicid, i) == apic_id)
			return i;
	}
	return -1;
}

int safe_smp_processor_id(void)
{
	int apicid, cpuid;

	if (!boot_cpu_has(X86_FEATURE_APIC))
		return 0;

	apicid = hard_smp_processor_id();
	if (apicid == BAD_APICID)
		return 0;

	cpuid = convert_apicid_to_cpu(apicid);

	return cpuid >= 0 ? cpuid : 0;
}
#endif
