
#include <linux/types.h>
#include <linux/time.h>
#include <linux/clocksource.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/hardirq.h>
#include <linux/efi.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kexec.h>
#include <linux/i8253.h>
#include <linux/random.h>
#include <linux/swiotlb.h>
#include <asm/processor.h>
#include <asm/hypervisor.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>
#include <asm/desc.h>
#include <asm/idtentry.h>
#include <asm/irq_regs.h>
#include <asm/i8259.h>
#include <asm/apic.h>
#include <asm/timer.h>
#include <asm/reboot.h>
#include <asm/nmi.h>
#include <clocksource/hyperv_timer.h>
#include <asm/numa.h>
#include <asm/coco.h>

bool hv_root_partition;
struct ms_hyperv_info ms_hyperv;

#if IS_ENABLED(CONFIG_HYPERV)
static void (*vmbus_handler)(void);
static void (*hv_stimer0_handler)(void);
static void (*hv_kexec_handler)(void);
static void (*hv_crash_handler)(struct pt_regs *regs);

DEFINE_IDTENTRY_SYSVEC(sysvec_hyperv_callback)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(irq_hv_callback_count);
	if (vmbus_handler)
		vmbus_handler();

	if (ms_hyperv.hints & HV_DEPRECATING_AEOI_RECOMMENDED)
		ack_APIC_irq();

	set_irq_regs(old_regs);
}

void hv_setup_vmbus_handler(void (*handler)(void))
{
	vmbus_handler = handler;
}

void hv_remove_vmbus_handler(void)
{
	/* We have no way to deallocate the interrupt gate */
	vmbus_handler = NULL;
}

DEFINE_IDTENTRY_SYSVEC(sysvec_hyperv_stimer0)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(hyperv_stimer0_count);
	if (hv_stimer0_handler)
		hv_stimer0_handler();
	add_interrupt_randomness(HYPERV_STIMER0_VECTOR);
	ack_APIC_irq();

	set_irq_regs(old_regs);
}

void hv_setup_stimer0_handler(void (*handler)(void))
{
	hv_stimer0_handler = handler;
}

void hv_remove_stimer0_handler(void)
{
	/* We have no way to deallocate the interrupt gate */
	hv_stimer0_handler = NULL;
}

void hv_setup_kexec_handler(void (*handler)(void))
{
	hv_kexec_handler = handler;
}

void hv_remove_kexec_handler(void)
{
	hv_kexec_handler = NULL;
}

void hv_setup_crash_handler(void (*handler)(struct pt_regs *regs))
{
	hv_crash_handler = handler;
}

void hv_remove_crash_handler(void)
{
	hv_crash_handler = NULL;
}

#ifdef CONFIG_KEXEC_CORE
static void hv_machine_shutdown(void)
{
	if (kexec_in_progress && hv_kexec_handler)
		hv_kexec_handler();

	/*
	if (kexec_in_progress && hyperv_init_cpuhp > 0)
		cpuhp_remove_state(hyperv_init_cpuhp);

	/* The function calls stop_other_cpus(). */
	native_machine_shutdown();

	/* Disable the hypercall page when there is only 1 active CPU. */
	if (kexec_in_progress)
		hyperv_cleanup();
}

static void hv_machine_crash_shutdown(struct pt_regs *regs)
{
	if (hv_crash_handler)
		hv_crash_handler(regs);

	/* The function calls crash_smp_send_stop(). */
	native_machine_crash_shutdown(regs);

	/* Disable the hypercall page when there is only 1 active CPU. */
	hyperv_cleanup();
}
#endif /* CONFIG_KEXEC_CORE */
#endif /* CONFIG_HYPERV */

static uint32_t  __init ms_hyperv_platform(void)
{
	u32 eax;
	u32 hyp_signature[3];

	if (!boot_cpu_has(X86_FEATURE_HYPERVISOR))
		return 0;

	cpuid(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS,
	      &eax, &hyp_signature[0], &hyp_signature[1], &hyp_signature[2]);

	if (eax < HYPERV_CPUID_MIN || eax > HYPERV_CPUID_MAX ||
	    memcmp("Microsoft Hv", hyp_signature, 12))
		return 0;

	/* HYPERCALL and VP_INDEX MSRs are mandatory for all features. */
	eax = cpuid_eax(HYPERV_CPUID_FEATURES);
	if (!(eax & HV_MSR_HYPERCALL_AVAILABLE)) {
		pr_warn("x86/hyperv: HYPERCALL MSR not available.\n");
		return 0;
	}
	if (!(eax & HV_MSR_VP_INDEX_AVAILABLE)) {
		pr_warn("x86/hyperv: VP_INDEX MSR not available.\n");
		return 0;
	}

	return HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS;
}

static unsigned char hv_get_nmi_reason(void)
{
	return 0;
}

#ifdef CONFIG_X86_LOCAL_APIC
static int hv_nmi_unknown(unsigned int val, struct pt_regs *regs)
{
	static atomic_t nmi_cpu = ATOMIC_INIT(-1);

	if (!unknown_nmi_panic)
		return NMI_DONE;

	if (atomic_cmpxchg(&nmi_cpu, -1, raw_smp_processor_id()) != -1)
		return NMI_HANDLED;

	return NMI_DONE;
}
#endif

static unsigned long hv_get_tsc_khz(void)
{
	unsigned long freq;

	rdmsrl(HV_X64_MSR_TSC_FREQUENCY, freq);

	return freq / 1000;
}

#if defined(CONFIG_SMP) && IS_ENABLED(CONFIG_HYPERV)
static void __init hv_smp_prepare_boot_cpu(void)
{
	native_smp_prepare_boot_cpu();
#if defined(CONFIG_X86_64) && defined(CONFIG_PARAVIRT_SPINLOCKS)
	hv_init_spinlocks();
#endif
}

static void __init hv_smp_prepare_cpus(unsigned int max_cpus)
{
#ifdef CONFIG_X86_64
	int i;
	int ret;
#endif

	native_smp_prepare_cpus(max_cpus);

#ifdef CONFIG_X86_64
	for_each_present_cpu(i) {
		if (i == 0)
			continue;
		ret = hv_call_add_logical_proc(numa_cpu_node(i), i, cpu_physical_id(i));
		BUG_ON(ret);
	}

	for_each_present_cpu(i) {
		if (i == 0)
			continue;
		ret = hv_call_create_vp(numa_cpu_node(i), hv_current_partition_id, i, i);
		BUG_ON(ret);
	}
#endif
}
#endif

static void __init ms_hyperv_init_platform(void)
{
	int hv_max_functions_eax;
	int hv_host_info_eax;
	int hv_host_info_ebx;
	int hv_host_info_ecx;
	int hv_host_info_edx;

#ifdef CONFIG_PARAVIRT
	pv_info.name = "Hyper-V";
#endif

	/*
	ms_hyperv.features = cpuid_eax(HYPERV_CPUID_FEATURES);
	ms_hyperv.priv_high = cpuid_ebx(HYPERV_CPUID_FEATURES);
	ms_hyperv.misc_features = cpuid_edx(HYPERV_CPUID_FEATURES);
	ms_hyperv.hints    = cpuid_eax(HYPERV_CPUID_ENLIGHTMENT_INFO);

	hv_max_functions_eax = cpuid_eax(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS);

	pr_info("Hyper-V: privilege flags low 0x%x, high 0x%x, hints 0x%x, misc 0x%x\n",
		ms_hyperv.features, ms_hyperv.priv_high, ms_hyperv.hints,
		ms_hyperv.misc_features);

	ms_hyperv.max_vp_index = cpuid_eax(HYPERV_CPUID_IMPLEMENT_LIMITS);
	ms_hyperv.max_lp_index = cpuid_ebx(HYPERV_CPUID_IMPLEMENT_LIMITS);

	pr_debug("Hyper-V: max %u virtual processors, %u logical processors\n",
		 ms_hyperv.max_vp_index, ms_hyperv.max_lp_index);

	/*
	if (cpuid_ebx(HYPERV_CPUID_FEATURES) & HV_CPU_MANAGEMENT) {
		hv_root_partition = true;
		pr_info("Hyper-V: running as root partition\n");
	}

	/*
	if (hv_max_functions_eax >= HYPERV_CPUID_VERSION) {
		hv_host_info_eax = cpuid_eax(HYPERV_CPUID_VERSION);
		hv_host_info_ebx = cpuid_ebx(HYPERV_CPUID_VERSION);
		hv_host_info_ecx = cpuid_ecx(HYPERV_CPUID_VERSION);
		hv_host_info_edx = cpuid_edx(HYPERV_CPUID_VERSION);

		pr_info("Hyper-V: Host Build %d.%d.%d.%d-%d-%d\n",
			hv_host_info_ebx >> 16, hv_host_info_ebx & 0xFFFF,
			hv_host_info_eax, hv_host_info_edx & 0xFFFFFF,
			hv_host_info_ecx, hv_host_info_edx >> 24);
	}

	if (ms_hyperv.features & HV_ACCESS_FREQUENCY_MSRS &&
	    ms_hyperv.misc_features & HV_FEATURE_FREQUENCY_MSRS_AVAILABLE) {
		x86_platform.calibrate_tsc = hv_get_tsc_khz;
		x86_platform.calibrate_cpu = hv_get_tsc_khz;
	}

	if (ms_hyperv.priv_high & HV_ISOLATION) {
		ms_hyperv.isolation_config_a = cpuid_eax(HYPERV_CPUID_ISOLATION_CONFIG);
		ms_hyperv.isolation_config_b = cpuid_ebx(HYPERV_CPUID_ISOLATION_CONFIG);
		ms_hyperv.shared_gpa_boundary =
			BIT_ULL(ms_hyperv.shared_gpa_boundary_bits);

		pr_info("Hyper-V: Isolation Config: Group A 0x%x, Group B 0x%x\n",
			ms_hyperv.isolation_config_a, ms_hyperv.isolation_config_b);

		if (hv_get_isolation_type() == HV_ISOLATION_TYPE_SNP) {
			static_branch_enable(&isolation_type_snp);
#ifdef CONFIG_SWIOTLB
			swiotlb_unencrypted_base = ms_hyperv.shared_gpa_boundary;
#endif
		}
		/* Isolation VMs are unenlightened SEV-based VMs, thus this check: */
		if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
			if (hv_get_isolation_type() != HV_ISOLATION_TYPE_NONE)
				cc_set_vendor(CC_VENDOR_HYPERV);
		}
	}

	if (hv_max_functions_eax >= HYPERV_CPUID_NESTED_FEATURES) {
		ms_hyperv.nested_features =
			cpuid_eax(HYPERV_CPUID_NESTED_FEATURES);
		pr_info("Hyper-V: Nested features: 0x%x\n",
			ms_hyperv.nested_features);
	}

#ifdef CONFIG_X86_LOCAL_APIC
	if (ms_hyperv.features & HV_ACCESS_FREQUENCY_MSRS &&
	    ms_hyperv.misc_features & HV_FEATURE_FREQUENCY_MSRS_AVAILABLE) {
		/*
		u64	hv_lapic_frequency;

		rdmsrl(HV_X64_MSR_APIC_FREQUENCY, hv_lapic_frequency);
		hv_lapic_frequency = div_u64(hv_lapic_frequency, HZ);
		lapic_timer_period = hv_lapic_frequency;
		pr_info("Hyper-V: LAPIC Timer Frequency: %#x\n",
			lapic_timer_period);
	}

	register_nmi_handler(NMI_UNKNOWN, hv_nmi_unknown, NMI_FLAG_FIRST,
			     "hv_nmi_unknown");
#endif

#ifdef CONFIG_X86_IO_APIC
	no_timer_check = 1;
#endif

#if IS_ENABLED(CONFIG_HYPERV) && defined(CONFIG_KEXEC_CORE)
	machine_ops.shutdown = hv_machine_shutdown;
	machine_ops.crash_shutdown = hv_machine_crash_shutdown;
#endif
	if (ms_hyperv.features & HV_ACCESS_TSC_INVARIANT) {
		/*
		wrmsrl(HV_X64_MSR_TSC_INVARIANT_CONTROL, 0x1);
		setup_force_cpu_cap(X86_FEATURE_TSC_RELIABLE);
	}

	/*
	if (efi_enabled(EFI_BOOT))
		x86_platform.get_nmi_reason = hv_get_nmi_reason;

	/*
	i8253_clear_counter_on_shutdown = false;

#if IS_ENABLED(CONFIG_HYPERV)
	/*
	x86_platform.apic_post_init = hyperv_init;
	hyperv_setup_mmu_ops();
	/* Setup the IDT for hypervisor callback */
	alloc_intr_gate(HYPERVISOR_CALLBACK_VECTOR, asm_sysvec_hyperv_callback);

	/* Setup the IDT for reenlightenment notifications */
	if (ms_hyperv.features & HV_ACCESS_REENLIGHTENMENT) {
		alloc_intr_gate(HYPERV_REENLIGHTENMENT_VECTOR,
				asm_sysvec_hyperv_reenlightenment);
	}

	/* Setup the IDT for stimer0 */
	if (ms_hyperv.misc_features & HV_STIMER_DIRECT_MODE_AVAILABLE) {
		alloc_intr_gate(HYPERV_STIMER0_VECTOR,
				asm_sysvec_hyperv_stimer0);
	}

# ifdef CONFIG_SMP
	smp_ops.smp_prepare_boot_cpu = hv_smp_prepare_boot_cpu;
	if (hv_root_partition)
		smp_ops.smp_prepare_cpus = hv_smp_prepare_cpus;
# endif

	/*
# ifdef CONFIG_X86_X2APIC
	if (x2apic_supported())
		x2apic_phys = 1;
# endif

	/* Register Hyper-V specific clocksource */
	hv_init_clocksource();
#endif
	/*
	if (!(ms_hyperv.features & HV_ACCESS_TSC_INVARIANT))
		mark_tsc_unstable("running on Hyper-V");

	hardlockup_detector_disable();
}

static bool __init ms_hyperv_x2apic_available(void)
{
	return x2apic_supported();
}

static bool __init ms_hyperv_msi_ext_dest_id(void)
{
	u32 eax;

	eax = cpuid_eax(HYPERV_CPUID_VIRT_STACK_INTERFACE);
	if (eax != HYPERV_VS_INTERFACE_EAX_SIGNATURE)
		return false;

	eax = cpuid_eax(HYPERV_CPUID_VIRT_STACK_PROPERTIES);
	return eax & HYPERV_VS_PROPERTIES_EAX_EXTENDED_IOAPIC_RTE;
}

const __initconst struct hypervisor_x86 x86_hyper_ms_hyperv = {
	.name			= "Microsoft Hyper-V",
	.detect			= ms_hyperv_platform,
	.type			= X86_HYPER_MS_HYPERV,
	.init.x2apic_available	= ms_hyperv_x2apic_available,
	.init.msi_ext_dest_id	= ms_hyperv_msi_ext_dest_id,
	.init.init_platform	= ms_hyperv_init_platform,
};
