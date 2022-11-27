
#include <linux/dmi.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/clocksource.h>
#include <linux/cpu.h>
#include <linux/reboot.h>
#include <linux/static_call.h>
#include <asm/div64.h>
#include <asm/x86_init.h>
#include <asm/hypervisor.h>
#include <asm/timer.h>
#include <asm/apic.h>
#include <asm/vmware.h>
#include <asm/svm.h>

#undef pr_fmt
#define pr_fmt(fmt)	"vmware: " fmt

#define CPUID_VMWARE_INFO_LEAF               0x40000000
#define CPUID_VMWARE_FEATURES_LEAF           0x40000010
#define CPUID_VMWARE_FEATURES_ECX_VMMCALL    BIT(0)
#define CPUID_VMWARE_FEATURES_ECX_VMCALL     BIT(1)

#define VMWARE_HYPERVISOR_MAGIC	0x564D5868

#define VMWARE_CMD_GETVERSION    10
#define VMWARE_CMD_GETHZ         45
#define VMWARE_CMD_GETVCPU_INFO  68
#define VMWARE_CMD_LEGACY_X2APIC  3
#define VMWARE_CMD_VCPU_RESERVED 31
#define VMWARE_CMD_STEALCLOCK    91

#define STEALCLOCK_NOT_AVAILABLE (-1)
#define STEALCLOCK_DISABLED        0
#define STEALCLOCK_ENABLED         1

#define VMWARE_PORT(cmd, eax, ebx, ecx, edx)				\
	__asm__("inl (%%dx), %%eax" :					\
		"=a"(eax), "=c"(ecx), "=d"(edx), "=b"(ebx) :		\
		"a"(VMWARE_HYPERVISOR_MAGIC),				\
		"c"(VMWARE_CMD_##cmd),					\
		"d"(VMWARE_HYPERVISOR_PORT), "b"(UINT_MAX) :		\
		"memory")

#define VMWARE_VMCALL(cmd, eax, ebx, ecx, edx)				\
	__asm__("vmcall" :						\
		"=a"(eax), "=c"(ecx), "=d"(edx), "=b"(ebx) :		\
		"a"(VMWARE_HYPERVISOR_MAGIC),				\
		"c"(VMWARE_CMD_##cmd),					\
		"d"(0), "b"(UINT_MAX) :					\
		"memory")

#define VMWARE_VMMCALL(cmd, eax, ebx, ecx, edx)                         \
	__asm__("vmmcall" :						\
		"=a"(eax), "=c"(ecx), "=d"(edx), "=b"(ebx) :		\
		"a"(VMWARE_HYPERVISOR_MAGIC),				\
		"c"(VMWARE_CMD_##cmd),					\
		"d"(0), "b"(UINT_MAX) :					\
		"memory")

#define VMWARE_CMD(cmd, eax, ebx, ecx, edx) do {		\
	switch (vmware_hypercall_mode) {			\
	case CPUID_VMWARE_FEATURES_ECX_VMCALL:			\
		VMWARE_VMCALL(cmd, eax, ebx, ecx, edx);		\
		break;						\
	case CPUID_VMWARE_FEATURES_ECX_VMMCALL:			\
		VMWARE_VMMCALL(cmd, eax, ebx, ecx, edx);	\
		break;						\
	default:						\
		VMWARE_PORT(cmd, eax, ebx, ecx, edx);		\
		break;						\
	}							\
	} while (0)

struct vmware_steal_time {
	union {
		uint64_t clock;	/* stolen time counter in units of vtsc */
		struct {
			/* only for little-endian */
			uint32_t clock_low;
			uint32_t clock_high;
		};
	};
	uint64_t reserved[7];
};

static unsigned long vmware_tsc_khz __ro_after_init;
static u8 vmware_hypercall_mode     __ro_after_init;

static inline int __vmware_platform(void)
{
	uint32_t eax, ebx, ecx, edx;
	VMWARE_CMD(GETVERSION, eax, ebx, ecx, edx);
	return eax != (uint32_t)-1 && ebx == VMWARE_HYPERVISOR_MAGIC;
}

static unsigned long vmware_get_tsc_khz(void)
{
	return vmware_tsc_khz;
}

#ifdef CONFIG_PARAVIRT
static struct cyc2ns_data vmware_cyc2ns __ro_after_init;
static bool vmw_sched_clock __initdata = true;
static DEFINE_PER_CPU_DECRYPTED(struct vmware_steal_time, vmw_steal_time) __aligned(64);
static bool has_steal_clock;
static bool steal_acc __initdata = true; /* steal time accounting */

static __init int setup_vmw_sched_clock(char *s)
{
	vmw_sched_clock = false;
	return 0;
}
early_param("no-vmw-sched-clock", setup_vmw_sched_clock);

static __init int parse_no_stealacc(char *arg)
{
	steal_acc = false;
	return 0;
}
early_param("no-steal-acc", parse_no_stealacc);

static unsigned long long notrace vmware_sched_clock(void)
{
	unsigned long long ns;

	ns = mul_u64_u32_shr(rdtsc(), vmware_cyc2ns.cyc2ns_mul,
			     vmware_cyc2ns.cyc2ns_shift);
	ns -= vmware_cyc2ns.cyc2ns_offset;
	return ns;
}

static void __init vmware_cyc2ns_setup(void)
{
	struct cyc2ns_data *d = &vmware_cyc2ns;
	unsigned long long tsc_now = rdtsc();

	clocks_calc_mult_shift(&d->cyc2ns_mul, &d->cyc2ns_shift,
			       vmware_tsc_khz, NSEC_PER_MSEC, 0);
	d->cyc2ns_offset = mul_u64_u32_shr(tsc_now, d->cyc2ns_mul,
					   d->cyc2ns_shift);

	pr_info("using clock offset of %llu ns\n", d->cyc2ns_offset);
}

static int vmware_cmd_stealclock(uint32_t arg1, uint32_t arg2)
{
	uint32_t result, info;

	asm volatile (VMWARE_HYPERCALL :
		"=a"(result),
		"=c"(info) :
		"a"(VMWARE_HYPERVISOR_MAGIC),
		"b"(0),
		"c"(VMWARE_CMD_STEALCLOCK),
		"d"(0),
		"S"(arg1),
		"D"(arg2) :
		"memory");
	return result;
}

static bool stealclock_enable(phys_addr_t pa)
{
	return vmware_cmd_stealclock(upper_32_bits(pa),
				     lower_32_bits(pa)) == STEALCLOCK_ENABLED;
}

static int __stealclock_disable(void)
{
	return vmware_cmd_stealclock(0, 1);
}

static void stealclock_disable(void)
{
	__stealclock_disable();
}

static bool vmware_is_stealclock_available(void)
{
	return __stealclock_disable() != STEALCLOCK_NOT_AVAILABLE;
}

static uint64_t vmware_steal_clock(int cpu)
{
	struct vmware_steal_time *steal = &per_cpu(vmw_steal_time, cpu);
	uint64_t clock;

	if (IS_ENABLED(CONFIG_64BIT))
		clock = READ_ONCE(steal->clock);
	else {
		uint32_t initial_high, low, high;

		do {
			initial_high = READ_ONCE(steal->clock_high);
			/* Do not reorder initial_high and high readings */
			virt_rmb();
			low = READ_ONCE(steal->clock_low);
			/* Keep low reading in between */
			virt_rmb();
			high = READ_ONCE(steal->clock_high);
		} while (initial_high != high);

		clock = ((uint64_t)high << 32) | low;
	}

	return mul_u64_u32_shr(clock, vmware_cyc2ns.cyc2ns_mul,
			     vmware_cyc2ns.cyc2ns_shift);
}

static void vmware_register_steal_time(void)
{
	int cpu = smp_processor_id();
	struct vmware_steal_time *st = &per_cpu(vmw_steal_time, cpu);

	if (!has_steal_clock)
		return;

	if (!stealclock_enable(slow_virt_to_phys(st))) {
		has_steal_clock = false;
		return;
	}

	pr_info("vmware-stealtime: cpu %d, pa %llx\n",
		cpu, (unsigned long long) slow_virt_to_phys(st));
}

static void vmware_disable_steal_time(void)
{
	if (!has_steal_clock)
		return;

	stealclock_disable();
}

static void vmware_guest_cpu_init(void)
{
	if (has_steal_clock)
		vmware_register_steal_time();
}

static void vmware_pv_guest_cpu_reboot(void *unused)
{
	vmware_disable_steal_time();
}

static int vmware_pv_reboot_notify(struct notifier_block *nb,
				unsigned long code, void *unused)
{
	if (code == SYS_RESTART)
		on_each_cpu(vmware_pv_guest_cpu_reboot, NULL, 1);
	return NOTIFY_DONE;
}

static struct notifier_block vmware_pv_reboot_nb = {
	.notifier_call = vmware_pv_reboot_notify,
};

#ifdef CONFIG_SMP
static void __init vmware_smp_prepare_boot_cpu(void)
{
	vmware_guest_cpu_init();
	native_smp_prepare_boot_cpu();
}

static int vmware_cpu_online(unsigned int cpu)
{
	local_irq_disable();
	vmware_guest_cpu_init();
	local_irq_enable();
	return 0;
}

static int vmware_cpu_down_prepare(unsigned int cpu)
{
	local_irq_disable();
	vmware_disable_steal_time();
	local_irq_enable();
	return 0;
}
#endif

static __init int activate_jump_labels(void)
{
	if (has_steal_clock) {
		static_key_slow_inc(&paravirt_steal_enabled);
		if (steal_acc)
			static_key_slow_inc(&paravirt_steal_rq_enabled);
	}

	return 0;
}
arch_initcall(activate_jump_labels);

static void __init vmware_paravirt_ops_setup(void)
{
	pv_info.name = "VMware hypervisor";
	pv_ops.cpu.io_delay = paravirt_nop;

	if (vmware_tsc_khz == 0)
		return;

	vmware_cyc2ns_setup();

	if (vmw_sched_clock)
		paravirt_set_sched_clock(vmware_sched_clock);

	if (vmware_is_stealclock_available()) {
		has_steal_clock = true;
		static_call_update(pv_steal_clock, vmware_steal_clock);

		/* We use reboot notifier only to disable steal clock */
		register_reboot_notifier(&vmware_pv_reboot_nb);

#ifdef CONFIG_SMP
		smp_ops.smp_prepare_boot_cpu =
			vmware_smp_prepare_boot_cpu;
		if (cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					      "x86/vmware:online",
					      vmware_cpu_online,
					      vmware_cpu_down_prepare) < 0)
			pr_err("vmware_guest: Failed to install cpu hotplug callbacks\n");
#else
		vmware_guest_cpu_init();
#endif
	}
}
#else
#define vmware_paravirt_ops_setup() do {} while (0)
#endif

static void __init vmware_set_capabilities(void)
{
	setup_force_cpu_cap(X86_FEATURE_CONSTANT_TSC);
	setup_force_cpu_cap(X86_FEATURE_TSC_RELIABLE);
	if (vmware_tsc_khz)
		setup_force_cpu_cap(X86_FEATURE_TSC_KNOWN_FREQ);
	if (vmware_hypercall_mode == CPUID_VMWARE_FEATURES_ECX_VMCALL)
		setup_force_cpu_cap(X86_FEATURE_VMCALL);
	else if (vmware_hypercall_mode == CPUID_VMWARE_FEATURES_ECX_VMMCALL)
		setup_force_cpu_cap(X86_FEATURE_VMW_VMMCALL);
}

static void __init vmware_platform_setup(void)
{
	uint32_t eax, ebx, ecx, edx;
	uint64_t lpj, tsc_khz;

	VMWARE_CMD(GETHZ, eax, ebx, ecx, edx);

	if (ebx != UINT_MAX) {
		lpj = tsc_khz = eax | (((uint64_t)ebx) << 32);
		do_div(tsc_khz, 1000);
		WARN_ON(tsc_khz >> 32);
		pr_info("TSC freq read from hypervisor : %lu.%03lu MHz\n",
			(unsigned long) tsc_khz / 1000,
			(unsigned long) tsc_khz % 1000);

		if (!preset_lpj) {
			do_div(lpj, HZ);
			preset_lpj = lpj;
		}

		vmware_tsc_khz = tsc_khz;
		x86_platform.calibrate_tsc = vmware_get_tsc_khz;
		x86_platform.calibrate_cpu = vmware_get_tsc_khz;

#ifdef CONFIG_X86_LOCAL_APIC
		/* Skip lapic calibration since we know the bus frequency. */
		lapic_timer_period = ecx / HZ;
		pr_info("Host bus clock speed read from hypervisor : %u Hz\n",
			ecx);
#endif
	} else {
		pr_warn("Failed to get TSC freq from the hypervisor\n");
	}

	vmware_paravirt_ops_setup();

#ifdef CONFIG_X86_IO_APIC
	no_timer_check = 1;
#endif

	vmware_set_capabilities();
}

static u8 __init vmware_select_hypercall(void)
{
	int eax, ebx, ecx, edx;

	cpuid(CPUID_VMWARE_FEATURES_LEAF, &eax, &ebx, &ecx, &edx);
	return (ecx & (CPUID_VMWARE_FEATURES_ECX_VMMCALL |
		       CPUID_VMWARE_FEATURES_ECX_VMCALL));
}

static uint32_t __init vmware_platform(void)
{
	if (boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
		unsigned int eax;
		unsigned int hyper_vendor_id[3];

		cpuid(CPUID_VMWARE_INFO_LEAF, &eax, &hyper_vendor_id[0],
		      &hyper_vendor_id[1], &hyper_vendor_id[2]);
		if (!memcmp(hyper_vendor_id, "VMwareVMware", 12)) {
			if (eax >= CPUID_VMWARE_FEATURES_LEAF)
				vmware_hypercall_mode =
					vmware_select_hypercall();

			pr_info("hypercall mode: 0x%02x\n",
				(unsigned int) vmware_hypercall_mode);

			return CPUID_VMWARE_INFO_LEAF;
		}
	} else if (dmi_available && dmi_name_in_serial("VMware") &&
		   __vmware_platform())
		return 1;

	return 0;
}

static bool __init vmware_legacy_x2apic_available(void)
{
	uint32_t eax, ebx, ecx, edx;
	VMWARE_CMD(GETVCPU_INFO, eax, ebx, ecx, edx);
	return !(eax & BIT(VMWARE_CMD_VCPU_RESERVED)) &&
		(eax & BIT(VMWARE_CMD_LEGACY_X2APIC));
}

#ifdef CONFIG_AMD_MEM_ENCRYPT
static void vmware_sev_es_hcall_prepare(struct ghcb *ghcb,
					struct pt_regs *regs)
{
	/* Copy VMWARE specific Hypercall parameters to the GHCB */
	ghcb_set_rip(ghcb, regs->ip);
	ghcb_set_rbx(ghcb, regs->bx);
	ghcb_set_rcx(ghcb, regs->cx);
	ghcb_set_rdx(ghcb, regs->dx);
	ghcb_set_rsi(ghcb, regs->si);
	ghcb_set_rdi(ghcb, regs->di);
	ghcb_set_rbp(ghcb, regs->bp);
}

static bool vmware_sev_es_hcall_finish(struct ghcb *ghcb, struct pt_regs *regs)
{
	if (!(ghcb_rbx_is_valid(ghcb) &&
	      ghcb_rcx_is_valid(ghcb) &&
	      ghcb_rdx_is_valid(ghcb) &&
	      ghcb_rsi_is_valid(ghcb) &&
	      ghcb_rdi_is_valid(ghcb) &&
	      ghcb_rbp_is_valid(ghcb)))
		return false;

	regs->bx = ghcb_get_rbx(ghcb);
	regs->cx = ghcb_get_rcx(ghcb);
	regs->dx = ghcb_get_rdx(ghcb);
	regs->si = ghcb_get_rsi(ghcb);
	regs->di = ghcb_get_rdi(ghcb);
	regs->bp = ghcb_get_rbp(ghcb);

	return true;
}
#endif

const __initconst struct hypervisor_x86 x86_hyper_vmware = {
	.name				= "VMware",
	.detect				= vmware_platform,
	.type				= X86_HYPER_VMWARE,
	.init.init_platform		= vmware_platform_setup,
	.init.x2apic_available		= vmware_legacy_x2apic_available,
#ifdef CONFIG_AMD_MEM_ENCRYPT
	.runtime.sev_es_hcall_prepare	= vmware_sev_es_hcall_prepare,
	.runtime.sev_es_hcall_finish	= vmware_sev_es_hcall_finish,
#endif
};
