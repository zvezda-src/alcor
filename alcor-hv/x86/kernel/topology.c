#include <linux/interrupt.h>
#include <linux/nodemask.h>
#include <linux/export.h>
#include <linux/mmzone.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/irq.h>
#include <asm/io_apic.h>
#include <asm/cpu.h>

static DEFINE_PER_CPU(struct x86_cpu, cpu_devices);

#ifdef CONFIG_HOTPLUG_CPU

#ifdef CONFIG_BOOTPARAM_HOTPLUG_CPU0
static int cpu0_hotpluggable = 1;
#else
static int cpu0_hotpluggable;
static int __init enable_cpu0_hotplug(char *str)
{
	cpu0_hotpluggable = 1;
	return 1;
}

__setup("cpu0_hotplug", enable_cpu0_hotplug);
#endif

#ifdef CONFIG_DEBUG_HOTPLUG_CPU0
int _debug_hotplug_cpu(int cpu, int action)
{
	int ret;

	if (!cpu_is_hotpluggable(cpu))
		return -EINVAL;

	switch (action) {
	case 0:
		ret = remove_cpu(cpu);
		if (!ret)
			pr_info("DEBUG_HOTPLUG_CPU0: CPU %u is now offline\n", cpu);
		else
			pr_debug("Can't offline CPU%d.\n", cpu);
		break;
	case 1:
		ret = add_cpu(cpu);
		if (ret)
			pr_debug("Can't online CPU%d.\n", cpu);

		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int __init debug_hotplug_cpu(void)
{
	_debug_hotplug_cpu(0, 0);
	return 0;
}

late_initcall_sync(debug_hotplug_cpu);
#endif /* CONFIG_DEBUG_HOTPLUG_CPU0 */

int arch_register_cpu(int num)
{
	struct cpuinfo_x86 *c = &cpu_data(num);

	/*
	if (c->x86_vendor != X86_VENDOR_INTEL ||
	    boot_cpu_has(X86_FEATURE_XENPV))
		cpu0_hotpluggable = 0;

	/*
	if (num == 0 && cpu0_hotpluggable) {
		unsigned int irq;
		/*
		for_each_active_irq(irq) {
			if (!IO_APIC_IRQ(irq) && irq_has_action(irq)) {
				cpu0_hotpluggable = 0;
				break;
			}
		}
	}
	if (num || cpu0_hotpluggable)
		per_cpu(cpu_devices, num).cpu.hotpluggable = 1;

	return register_cpu(&per_cpu(cpu_devices, num).cpu, num);
}
EXPORT_SYMBOL(arch_register_cpu);

void arch_unregister_cpu(int num)
{
	unregister_cpu(&per_cpu(cpu_devices, num).cpu);
}
EXPORT_SYMBOL(arch_unregister_cpu);
#else /* CONFIG_HOTPLUG_CPU */

static int __init arch_register_cpu(int num)
{
	return register_cpu(&per_cpu(cpu_devices, num).cpu, num);
}
#endif /* CONFIG_HOTPLUG_CPU */

static int __init topology_init(void)
{
	int i;

	for_each_present_cpu(i)
		arch_register_cpu(i);

	return 0;
}
subsys_initcall(topology_init);
