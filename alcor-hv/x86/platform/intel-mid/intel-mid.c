
#define pr_fmt(fmt) "intel_mid: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/regulator/machine.h>
#include <linux/scatterlist.h>
#include <linux/irq.h>
#include <linux/export.h>
#include <linux/notifier.h>

#include <asm/setup.h>
#include <asm/mpspec_def.h>
#include <asm/hw_irq.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/intel-mid.h>
#include <asm/io.h>
#include <asm/i8259.h>
#include <asm/intel_scu_ipc.h>
#include <asm/reboot.h>

#define IPCMSG_COLD_OFF		0x80	/* Only for Tangier */
#define IPCMSG_COLD_RESET	0xF1

static void intel_mid_power_off(void)
{
	/* Shut down South Complex via PWRMU */
	intel_mid_pwr_power_off();

	/* Only for Tangier, the rest will ignore this command */
	intel_scu_ipc_dev_simple_command(NULL, IPCMSG_COLD_OFF, 1);
};

static void intel_mid_reboot(void)
{
	intel_scu_ipc_dev_simple_command(NULL, IPCMSG_COLD_RESET, 0);
}

static void __init intel_mid_time_init(void)
{
	/* Lapic only, no apbt */
	x86_init.timers.setup_percpu_clockev = setup_boot_APIC_clock;
	x86_cpuinit.setup_percpu_clockev = setup_secondary_APIC_clock;
}

static void intel_mid_arch_setup(void)
{
	switch (boot_cpu_data.x86_model) {
	case 0x3C:
	case 0x4A:
		x86_platform.legacy.rtc = 1;
		break;
	default:
		break;
	}

	/*
	regulator_has_full_constraints();
}

static unsigned char intel_mid_get_nmi_reason(void)
{
	return 0;
}

void __init x86_intel_mid_early_setup(void)
{
	x86_init.resources.probe_roms = x86_init_noop;
	x86_init.resources.reserve_resources = x86_init_noop;

	x86_init.timers.timer_init = intel_mid_time_init;
	x86_init.timers.setup_percpu_clockev = x86_init_noop;

	x86_init.irqs.pre_vector_init = x86_init_noop;

	x86_init.oem.arch_setup = intel_mid_arch_setup;

	x86_platform.get_nmi_reason = intel_mid_get_nmi_reason;

	x86_init.pci.arch_init = intel_mid_pci_init;
	x86_init.pci.fixup_irqs = x86_init_noop;

	legacy_pic = &null_legacy_pic;

	/*
	x86_init.acpi.reduced_hw_early_init = x86_init_noop;

	pm_power_off = intel_mid_power_off;
	machine_ops.emergency_restart  = intel_mid_reboot;

	/* Avoid searching for BIOS MP tables */
	x86_init.mpparse.find_smp_config = x86_init_noop;
	x86_init.mpparse.get_smp_config = x86_init_uint_noop;
	set_bit(MP_BUS_ISA, mp_bus_not_pci);
}
