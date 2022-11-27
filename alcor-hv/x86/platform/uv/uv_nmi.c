
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/kdb.h>
#include <linux/kexec.h>
#include <linux/kgdb.h>
#include <linux/moduleparam.h>
#include <linux/nmi.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/slab.h>
#include <linux/clocksource.h>

#include <asm/apic.h>
#include <asm/current.h>
#include <asm/kdebug.h>
#include <asm/local64.h>
#include <asm/nmi.h>
#include <asm/reboot.h>
#include <asm/traps.h>
#include <asm/uv/uv.h>
#include <asm/uv/uv_hub.h>
#include <asm/uv/uv_mmrs.h>


static struct uv_hub_nmi_s **uv_hub_nmi_list;

DEFINE_PER_CPU(struct uv_cpu_nmi_s, uv_cpu_nmi);

static unsigned long uvh_nmi_mmrx;		/* UVH_EVENT_OCCURRED0/1 */
static unsigned long uvh_nmi_mmrx_clear;	/* UVH_EVENT_OCCURRED0/1_ALIAS */
static int uvh_nmi_mmrx_shift;			/* UVH_EVENT_OCCURRED0/1_EXTIO_INT0_SHFT */
static char *uvh_nmi_mmrx_type;			/* "EXTIO_INT0" */

static unsigned long uvh_nmi_mmrx_supported;	/* UVH_EXTIO_INT0_BROADCAST */

static unsigned long uvh_nmi_mmrx_req;		/* UVH_BIOS_KERNEL_MMR_ALIAS_2 */
static int uvh_nmi_mmrx_req_shift;		/* 62 */

#define NMI_CONTROL_PORT	0x70
#define NMI_DUMMY_PORT		0x71
#define PAD_OWN_GPP_D_0		0x2c
#define GPI_NMI_STS_GPP_D_0	0x164
#define GPI_NMI_ENA_GPP_D_0	0x174
#define STS_GPP_D_0_MASK	0x1
#define PAD_CFG_DW0_GPP_D_0	0x4c0
#define GPIROUTNMI		(1ul << 17)
#define PCH_PCR_GPIO_1_BASE	0xfdae0000ul
#define PCH_PCR_GPIO_ADDRESS(offset) (int *)((u64)(pch_base) | (u64)(offset))

static u64 *pch_base;
static unsigned long nmi_mmr;
static unsigned long nmi_mmr_clear;
static unsigned long nmi_mmr_pending;

static atomic_t	uv_in_nmi;
static atomic_t uv_nmi_cpu = ATOMIC_INIT(-1);
static atomic_t uv_nmi_cpus_in_nmi = ATOMIC_INIT(-1);
static atomic_t uv_nmi_slave_continue;
static cpumask_var_t uv_nmi_cpu_mask;

static atomic_t uv_nmi_kexec_failed;

#define SLAVE_CLEAR	0
#define SLAVE_CONTINUE	1
#define SLAVE_EXIT	2

static int uv_nmi_loglevel = CONSOLE_LOGLEVEL_DEFAULT;
module_param_named(dump_loglevel, uv_nmi_loglevel, int, 0644);

static int param_get_local64(char *buffer, const struct kernel_param *kp)
{
	return sprintf(buffer, "%lu\n", local64_read((local64_t *)kp->arg));
}

static int param_set_local64(const char *val, const struct kernel_param *kp)
{
	/* Clear on any write */
	local64_set((local64_t *)kp->arg, 0);
	return 0;
}

static const struct kernel_param_ops param_ops_local64 = {
	.get = param_get_local64,
	.set = param_set_local64,
};
#define param_check_local64(name, p) __param_check(name, p, local64_t)

static local64_t uv_nmi_count;
module_param_named(nmi_count, uv_nmi_count, local64, 0644);

static local64_t uv_nmi_misses;
module_param_named(nmi_misses, uv_nmi_misses, local64, 0644);

static local64_t uv_nmi_ping_count;
module_param_named(ping_count, uv_nmi_ping_count, local64, 0644);

static local64_t uv_nmi_ping_misses;
module_param_named(ping_misses, uv_nmi_ping_misses, local64, 0644);

static int uv_nmi_initial_delay = 100;
module_param_named(initial_delay, uv_nmi_initial_delay, int, 0644);

static int uv_nmi_slave_delay = 100;
module_param_named(slave_delay, uv_nmi_slave_delay, int, 0644);

static int uv_nmi_loop_delay = 100;
module_param_named(loop_delay, uv_nmi_loop_delay, int, 0644);

static int uv_nmi_trigger_delay = 10000;
module_param_named(trigger_delay, uv_nmi_trigger_delay, int, 0644);

static int uv_nmi_wait_count = 100;
module_param_named(wait_count, uv_nmi_wait_count, int, 0644);

static int uv_nmi_retry_count = 500;
module_param_named(retry_count, uv_nmi_retry_count, int, 0644);

static bool uv_pch_intr_enable = true;
static bool uv_pch_intr_now_enabled;
module_param_named(pch_intr_enable, uv_pch_intr_enable, bool, 0644);

static bool uv_pch_init_enable = true;
module_param_named(pch_init_enable, uv_pch_init_enable, bool, 0644);

static int uv_nmi_debug;
module_param_named(debug, uv_nmi_debug, int, 0644);

#define nmi_debug(fmt, ...)				\
	do {						\
		if (uv_nmi_debug)			\
			pr_info(fmt, ##__VA_ARGS__);	\
	} while (0)

#define	ACTION_LEN	16
static struct nmi_action {
	char	*action;
	char	*desc;
} valid_acts[] = {
	{	"kdump",	"do kernel crash dump"			},
	{	"dump",		"dump process stack for each cpu"	},
	{	"ips",		"dump Inst Ptr info for each cpu"	},
	{	"kdb",		"enter KDB (needs kgdboc= assignment)"	},
	{	"kgdb",		"enter KGDB (needs gdb target remote)"	},
	{	"health",	"check if CPUs respond to NMI"		},
};
typedef char action_t[ACTION_LEN];
static action_t uv_nmi_action = { "dump" };

static int param_get_action(char *buffer, const struct kernel_param *kp)
{
	return sprintf(buffer, "%s\n", uv_nmi_action);
}

static int param_set_action(const char *val, const struct kernel_param *kp)
{
	int i;
	int n = ARRAY_SIZE(valid_acts);
	char arg[ACTION_LEN], *p;

	/* (remove possible '\n') */
	strncpy(arg, val, ACTION_LEN - 1);
	arg[ACTION_LEN - 1] = '\0';
	p = strchr(arg, '\n');
	if (p)
		*p = '\0';

	for (i = 0; i < n; i++)
		if (!strcmp(arg, valid_acts[i].action))
			break;

	if (i < n) {
		strcpy(uv_nmi_action, arg);
		pr_info("UV: New NMI action:%s\n", uv_nmi_action);
		return 0;
	}

	pr_err("UV: Invalid NMI action:%s, valid actions are:\n", arg);
	for (i = 0; i < n; i++)
		pr_err("UV: %-8s - %s\n",
			valid_acts[i].action, valid_acts[i].desc);
	return -EINVAL;
}

static const struct kernel_param_ops param_ops_action = {
	.get = param_get_action,
	.set = param_set_action,
};
#define param_check_action(name, p) __param_check(name, p, action_t)

module_param_named(action, uv_nmi_action, action, 0644);

static inline bool uv_nmi_action_is(const char *action)
{
	return (strncmp(uv_nmi_action, action, strlen(action)) == 0);
}

static void uv_nmi_setup_mmrs(void)
{
	bool new_nmi_method_only = false;

	/* First determine arch specific MMRs to handshake with BIOS */
	if (UVH_EVENT_OCCURRED0_EXTIO_INT0_MASK) {	/* UV2,3,4 setup */
		uvh_nmi_mmrx = UVH_EVENT_OCCURRED0;
		uvh_nmi_mmrx_clear = UVH_EVENT_OCCURRED0_ALIAS;
		uvh_nmi_mmrx_shift = UVH_EVENT_OCCURRED0_EXTIO_INT0_SHFT;
		uvh_nmi_mmrx_type = "OCRD0-EXTIO_INT0";

		uvh_nmi_mmrx_supported = UVH_EXTIO_INT0_BROADCAST;
		uvh_nmi_mmrx_req = UVH_BIOS_KERNEL_MMR_ALIAS_2;
		uvh_nmi_mmrx_req_shift = 62;

	} else if (UVH_EVENT_OCCURRED1_EXTIO_INT0_MASK) { /* UV5+ setup */
		uvh_nmi_mmrx = UVH_EVENT_OCCURRED1;
		uvh_nmi_mmrx_clear = UVH_EVENT_OCCURRED1_ALIAS;
		uvh_nmi_mmrx_shift = UVH_EVENT_OCCURRED1_EXTIO_INT0_SHFT;
		uvh_nmi_mmrx_type = "OCRD1-EXTIO_INT0";

		new_nmi_method_only = true;		/* Newer nmi always valid on UV5+ */
		uvh_nmi_mmrx_req = 0;			/* no request bit to clear */

	} else {
		pr_err("UV:%s:NMI support not available on this system\n", __func__);
		return;
	}

	/* Then find out if new NMI is supported */
	if (new_nmi_method_only || uv_read_local_mmr(uvh_nmi_mmrx_supported)) {
		if (uvh_nmi_mmrx_req)
			uv_write_local_mmr(uvh_nmi_mmrx_req,
						1UL << uvh_nmi_mmrx_req_shift);
		nmi_mmr = uvh_nmi_mmrx;
		nmi_mmr_clear = uvh_nmi_mmrx_clear;
		nmi_mmr_pending = 1UL << uvh_nmi_mmrx_shift;
		pr_info("UV: SMI NMI support: %s\n", uvh_nmi_mmrx_type);
	} else {
		nmi_mmr = UVH_NMI_MMR;
		nmi_mmr_clear = UVH_NMI_MMR_CLEAR;
		nmi_mmr_pending = 1UL << UVH_NMI_MMR_SHIFT;
		pr_info("UV: SMI NMI support: %s\n", UVH_NMI_MMR_TYPE);
	}
}

static inline int uv_nmi_test_mmr(struct uv_hub_nmi_s *hub_nmi)
{
	hub_nmi->nmi_value = uv_read_local_mmr(nmi_mmr);
	atomic_inc(&hub_nmi->read_mmr_count);
	return !!(hub_nmi->nmi_value & nmi_mmr_pending);
}

static inline void uv_local_mmr_clear_nmi(void)
{
	uv_write_local_mmr(nmi_mmr_clear, nmi_mmr_pending);
}

static inline void uv_reassert_nmi(void)
{
	/* (from arch/x86/include/asm/mach_traps.h) */
	outb(0x8f, NMI_CONTROL_PORT);
	inb(NMI_DUMMY_PORT);		/* dummy read */
	outb(0x0f, NMI_CONTROL_PORT);
	inb(NMI_DUMMY_PORT);		/* dummy read */
}

static void uv_init_hubless_pch_io(int offset, int mask, int data)
{
	int *addr = PCH_PCR_GPIO_ADDRESS(offset);
	int readd = readl(addr);

	if (mask) {			/* OR in new data */
		int writed = (readd & ~mask) | data;

		nmi_debug("UV:PCH: %p = %x & %x | %x (%x)\n",
			addr, readd, ~mask, data, writed);
		writel(writed, addr);
	} else if (readd & data) {	/* clear status bit */
		nmi_debug("UV:PCH: %p = %x\n", addr, data);
		writel(data, addr);
	}

	(void)readl(addr);		/* flush write data */
}

static void uv_nmi_setup_hubless_intr(void)
{
	uv_pch_intr_now_enabled = uv_pch_intr_enable;

	uv_init_hubless_pch_io(
		PAD_CFG_DW0_GPP_D_0, GPIROUTNMI,
		uv_pch_intr_now_enabled ? GPIROUTNMI : 0);

	nmi_debug("UV:NMI: GPP_D_0 interrupt %s\n",
		uv_pch_intr_now_enabled ? "enabled" : "disabled");
}

static struct init_nmi {
	unsigned int	offset;
	unsigned int	mask;
	unsigned int	data;
} init_nmi[] = {
	{	/* HOSTSW_OWN_GPP_D_0 */
	.offset = 0x84,
	.mask = 0x1,
	.data = 0x0,	/* ACPI Mode */
	},

	{	/* GPI_INT_STS_GPP_D_0 */
	.offset = 0x104,
	.mask = 0x0,
	.data = 0x1,	/* Clear Status */
	},
	{	/* GPI_GPE_STS_GPP_D_0 */
	.offset = 0x124,
	.mask = 0x0,
	.data = 0x1,	/* Clear Status */
	},
	{	/* GPI_SMI_STS_GPP_D_0 */
	.offset = 0x144,
	.mask = 0x0,
	.data = 0x1,	/* Clear Status */
	},
	{	/* GPI_NMI_STS_GPP_D_0 */
	.offset = 0x164,
	.mask = 0x0,
	.data = 0x1,	/* Clear Status */
	},

	{	/* GPI_INT_EN_GPP_D_0 */
	.offset = 0x114,
	.mask = 0x1,
	.data = 0x0,	/* Disable interrupt generation */
	},
	{	/* GPI_GPE_EN_GPP_D_0 */
	.offset = 0x134,
	.mask = 0x1,
	.data = 0x0,	/* Disable interrupt generation */
	},
	{	/* GPI_SMI_EN_GPP_D_0 */
	.offset = 0x154,
	.mask = 0x1,
	.data = 0x0,	/* Disable interrupt generation */
	},
	{	/* GPI_NMI_EN_GPP_D_0 */
	.offset = 0x174,
	.mask = 0x1,
	.data = 0x0,	/* Disable interrupt generation */
	},

	{	/* PAD_CFG_DW0_GPP_D_0 */
	.offset = 0x4c0,
	.mask = 0xffffffff,
	.data = 0x82020100,
	},

	{	/* PAD_CFG_DW1_GPP_D_0 */
	.offset = 0x4c4,
	.mask = 0x3c00,
	.data = 0,	/* Termination = none (default) */
	},
};

static void uv_init_hubless_pch_d0(void)
{
	int i, read;

	read = *PCH_PCR_GPIO_ADDRESS(PAD_OWN_GPP_D_0);
	if (read != 0) {
		pr_info("UV: Hubless NMI already configured\n");
		return;
	}

	nmi_debug("UV: Initializing UV Hubless NMI on PCH\n");
	for (i = 0; i < ARRAY_SIZE(init_nmi); i++) {
		uv_init_hubless_pch_io(init_nmi[i].offset,
					init_nmi[i].mask,
					init_nmi[i].data);
	}
}

static int uv_nmi_test_hubless(struct uv_hub_nmi_s *hub_nmi)
{
	int *pstat = PCH_PCR_GPIO_ADDRESS(GPI_NMI_STS_GPP_D_0);
	int status = *pstat;

	hub_nmi->nmi_value = status;
	atomic_inc(&hub_nmi->read_mmr_count);

	if (!(status & STS_GPP_D_0_MASK))	/* Not a UV external NMI */
		return 0;

	(void)*pstat;			/* Flush write */

	return 1;
}

static int uv_test_nmi(struct uv_hub_nmi_s *hub_nmi)
{
	if (hub_nmi->hub_present)
		return uv_nmi_test_mmr(hub_nmi);

	if (hub_nmi->pch_owner)		/* Only PCH owner can check status */
		return uv_nmi_test_hubless(hub_nmi);

	return -1;
}

static int uv_set_in_nmi(int cpu, struct uv_hub_nmi_s *hub_nmi)
{
	int first = atomic_add_unless(&hub_nmi->in_nmi, 1, 1);

	if (first) {
		atomic_set(&hub_nmi->cpu_owner, cpu);
		if (atomic_add_unless(&uv_in_nmi, 1, 1))
			atomic_set(&uv_nmi_cpu, cpu);

		atomic_inc(&hub_nmi->nmi_count);
	}
	return first;
}

static int uv_check_nmi(struct uv_hub_nmi_s *hub_nmi)
{
	int cpu = smp_processor_id();
	int nmi = 0;
	int nmi_detected = 0;

	local64_inc(&uv_nmi_count);
	this_cpu_inc(uv_cpu_nmi.queries);

	do {
		nmi = atomic_read(&hub_nmi->in_nmi);
		if (nmi)
			break;

		if (raw_spin_trylock(&hub_nmi->nmi_lock)) {
			nmi_detected = uv_test_nmi(hub_nmi);

			/* Check flag for UV external NMI */
			if (nmi_detected > 0) {
				uv_set_in_nmi(cpu, hub_nmi);
				nmi = 1;
				break;
			}

			/* A non-PCH node in a hubless system waits for NMI */
			else if (nmi_detected < 0)
				goto slave_wait;

			/* MMR/PCH NMI flag is clear */
			raw_spin_unlock(&hub_nmi->nmi_lock);

		} else {

			/* Wait a moment for the HUB NMI locker to set flag */
slave_wait:		cpu_relax();
			udelay(uv_nmi_slave_delay);

			/* Re-check hub in_nmi flag */
			nmi = atomic_read(&hub_nmi->in_nmi);
			if (nmi)
				break;
		}

		/*
		if (!nmi) {
			nmi = atomic_read(&uv_in_nmi);
			if (nmi)
				uv_set_in_nmi(cpu, hub_nmi);
		}

		/* If we're holding the hub lock, release it now */
		if (nmi_detected < 0)
			raw_spin_unlock(&hub_nmi->nmi_lock);

	} while (0);

	if (!nmi)
		local64_inc(&uv_nmi_misses);

	return nmi;
}

static inline void uv_clear_nmi(int cpu)
{
	struct uv_hub_nmi_s *hub_nmi = uv_hub_nmi;

	if (cpu == atomic_read(&hub_nmi->cpu_owner)) {
		atomic_set(&hub_nmi->cpu_owner, -1);
		atomic_set(&hub_nmi->in_nmi, 0);
		if (hub_nmi->hub_present)
			uv_local_mmr_clear_nmi();
		else
			uv_reassert_nmi();
		raw_spin_unlock(&hub_nmi->nmi_lock);
	}
}

static void uv_nmi_nr_cpus_ping(void)
{
	int cpu;

	for_each_cpu(cpu, uv_nmi_cpu_mask)
		uv_cpu_nmi_per(cpu).pinging = 1;

	apic->send_IPI_mask(uv_nmi_cpu_mask, APIC_DM_NMI);
}

static void uv_nmi_cleanup_mask(void)
{
	int cpu;

	for_each_cpu(cpu, uv_nmi_cpu_mask) {
		uv_cpu_nmi_per(cpu).pinging =  0;
		uv_cpu_nmi_per(cpu).state = UV_NMI_STATE_OUT;
		cpumask_clear_cpu(cpu, uv_nmi_cpu_mask);
	}
}

static int uv_nmi_wait_cpus(int first)
{
	int i, j, k, n = num_online_cpus();
	int last_k = 0, waiting = 0;
	int cpu = smp_processor_id();

	if (first) {
		cpumask_copy(uv_nmi_cpu_mask, cpu_online_mask);
		k = 0;
	} else {
		k = n - cpumask_weight(uv_nmi_cpu_mask);
	}

	/* PCH NMI causes only one CPU to respond */
	if (first && uv_pch_intr_now_enabled) {
		cpumask_clear_cpu(cpu, uv_nmi_cpu_mask);
		return n - k - 1;
	}

	udelay(uv_nmi_initial_delay);
	for (i = 0; i < uv_nmi_retry_count; i++) {
		int loop_delay = uv_nmi_loop_delay;

		for_each_cpu(j, uv_nmi_cpu_mask) {
			if (uv_cpu_nmi_per(j).state) {
				cpumask_clear_cpu(j, uv_nmi_cpu_mask);
				if (++k >= n)
					break;
			}
		}
		if (k >= n) {		/* all in? */
			k = n;
			break;
		}
		if (last_k != k) {	/* abort if no new CPU's coming in */
			last_k = k;
			waiting = 0;
		} else if (++waiting > uv_nmi_wait_count)
			break;

		/* Extend delay if waiting only for CPU 0: */
		if (waiting && (n - k) == 1 &&
		    cpumask_test_cpu(0, uv_nmi_cpu_mask))
			loop_delay *= 100;

		udelay(loop_delay);
	}
	atomic_set(&uv_nmi_cpus_in_nmi, k);
	return n - k;
}

static void uv_nmi_wait(int master)
{
	/* Indicate this CPU is in: */
	this_cpu_write(uv_cpu_nmi.state, UV_NMI_STATE_IN);

	/* If not the first CPU in (the master), then we are a slave CPU */
	if (!master)
		return;

	do {
		/* Wait for all other CPU's to gather here */
		if (!uv_nmi_wait_cpus(1))
			break;

		/* If not all made it in, send IPI NMI to them */
		pr_alert("UV: Sending NMI IPI to %d CPUs: %*pbl\n",
			 cpumask_weight(uv_nmi_cpu_mask),
			 cpumask_pr_args(uv_nmi_cpu_mask));

		uv_nmi_nr_cpus_ping();

		/* If all CPU's are in, then done */
		if (!uv_nmi_wait_cpus(0))
			break;

		pr_alert("UV: %d CPUs not in NMI loop: %*pbl\n",
			 cpumask_weight(uv_nmi_cpu_mask),
			 cpumask_pr_args(uv_nmi_cpu_mask));
	} while (0);

	pr_alert("UV: %d of %d CPUs in NMI\n",
		atomic_read(&uv_nmi_cpus_in_nmi), num_online_cpus());
}

static void uv_nmi_dump_cpu_ip_hdr(void)
{
	pr_info("\nUV: %4s %6s %-32s %s   (Note: PID 0 not listed)\n",
		"CPU", "PID", "COMMAND", "IP");
}

static void uv_nmi_dump_cpu_ip(int cpu, struct pt_regs *regs)
{
	pr_info("UV: %4d %6d %-32.32s %pS",
		cpu, current->pid, current->comm, (void *)regs->ip);
}

static void uv_nmi_dump_state_cpu(int cpu, struct pt_regs *regs)
{
	const char *dots = " ................................. ";

	if (cpu == 0)
		uv_nmi_dump_cpu_ip_hdr();

	if (current->pid != 0 || !uv_nmi_action_is("ips"))
		uv_nmi_dump_cpu_ip(cpu, regs);

	if (uv_nmi_action_is("dump")) {
		pr_info("UV:%sNMI process trace for CPU %d\n", dots, cpu);
		show_regs(regs);
	}

	this_cpu_write(uv_cpu_nmi.state, UV_NMI_STATE_DUMP_DONE);
}

static void uv_nmi_trigger_dump(int cpu)
{
	int retry = uv_nmi_trigger_delay;

	if (uv_cpu_nmi_per(cpu).state != UV_NMI_STATE_IN)
		return;

	uv_cpu_nmi_per(cpu).state = UV_NMI_STATE_DUMP;
	do {
		cpu_relax();
		udelay(10);
		if (uv_cpu_nmi_per(cpu).state
				!= UV_NMI_STATE_DUMP)
			return;
	} while (--retry > 0);

	pr_crit("UV: CPU %d stuck in process dump function\n", cpu);
	uv_cpu_nmi_per(cpu).state = UV_NMI_STATE_DUMP_DONE;
}

static void uv_nmi_sync_exit(int master)
{
	atomic_dec(&uv_nmi_cpus_in_nmi);
	if (master) {
		while (atomic_read(&uv_nmi_cpus_in_nmi) > 0)
			cpu_relax();
		atomic_set(&uv_nmi_slave_continue, SLAVE_CLEAR);
	} else {
		while (atomic_read(&uv_nmi_slave_continue))
			cpu_relax();
	}
}

static void uv_nmi_action_health(int cpu, struct pt_regs *regs, int master)
{
	if (master) {
		int in = atomic_read(&uv_nmi_cpus_in_nmi);
		int out = num_online_cpus() - in;

		pr_alert("UV: NMI CPU health check (non-responding:%d)\n", out);
		atomic_set(&uv_nmi_slave_continue, SLAVE_EXIT);
	} else {
		while (!atomic_read(&uv_nmi_slave_continue))
			cpu_relax();
	}
	uv_nmi_sync_exit(master);
}

static void uv_nmi_dump_state(int cpu, struct pt_regs *regs, int master)
{
	if (master) {
		int tcpu;
		int ignored = 0;
		int saved_console_loglevel = console_loglevel;

		pr_alert("UV: tracing %s for %d CPUs from CPU %d\n",
			uv_nmi_action_is("ips") ? "IPs" : "processes",
			atomic_read(&uv_nmi_cpus_in_nmi), cpu);

		console_loglevel = uv_nmi_loglevel;
		atomic_set(&uv_nmi_slave_continue, SLAVE_EXIT);
		for_each_online_cpu(tcpu) {
			if (cpumask_test_cpu(tcpu, uv_nmi_cpu_mask))
				ignored++;
			else if (tcpu == cpu)
				uv_nmi_dump_state_cpu(tcpu, regs);
			else
				uv_nmi_trigger_dump(tcpu);
		}
		if (ignored)
			pr_alert("UV: %d CPUs ignored NMI\n", ignored);

		console_loglevel = saved_console_loglevel;
		pr_alert("UV: process trace complete\n");
	} else {
		while (!atomic_read(&uv_nmi_slave_continue))
			cpu_relax();
		while (this_cpu_read(uv_cpu_nmi.state) != UV_NMI_STATE_DUMP)
			cpu_relax();
		uv_nmi_dump_state_cpu(cpu, regs);
	}
	uv_nmi_sync_exit(master);
}

static void uv_nmi_touch_watchdogs(void)
{
	touch_softlockup_watchdog_sync();
	clocksource_touch_watchdog();
	rcu_cpu_stall_reset();
	touch_nmi_watchdog();
}

static void uv_nmi_kdump(int cpu, int main, struct pt_regs *regs)
{
	/* Check if kdump kernel loaded for both main and secondary CPUs */
	if (!kexec_crash_image) {
		if (main)
			pr_err("UV: NMI error: kdump kernel not loaded\n");
		return;
	}

	/* Call crash to dump system state */
	if (main) {
		pr_emerg("UV: NMI executing crash_kexec on CPU%d\n", cpu);
		crash_kexec(regs);

		pr_emerg("UV: crash_kexec unexpectedly returned\n");
		atomic_set(&uv_nmi_kexec_failed, 1);

	} else { /* secondary */

		/* If kdump kernel fails, secondaries will exit this loop */
		while (atomic_read(&uv_nmi_kexec_failed) == 0) {

			/* Once shootdown cpus starts, they do not return */
			run_crash_ipi_callback(regs);

			mdelay(10);
		}
	}
}

#ifdef CONFIG_KGDB
#ifdef CONFIG_KGDB_KDB
static inline int uv_nmi_kdb_reason(void)
{
	return KDB_REASON_SYSTEM_NMI;
}
#else /* !CONFIG_KGDB_KDB */
static inline int uv_nmi_kdb_reason(void)
{
	/* Ensure user is expecting to attach gdb remote */
	if (uv_nmi_action_is("kgdb"))
		return 0;

	pr_err("UV: NMI error: KDB is not enabled in this kernel\n");
	return -1;
}
#endif /* CONFIG_KGDB_KDB */

static void uv_call_kgdb_kdb(int cpu, struct pt_regs *regs, int master)
{
	if (master) {
		int reason = uv_nmi_kdb_reason();
		int ret;

		if (reason < 0)
			return;

		/* Call KGDB NMI handler as MASTER */
		ret = kgdb_nmicallin(cpu, X86_TRAP_NMI, regs, reason,
				&uv_nmi_slave_continue);
		if (ret) {
			pr_alert("KGDB returned error, is kgdboc set?\n");
			atomic_set(&uv_nmi_slave_continue, SLAVE_EXIT);
		}
	} else {
		/* Wait for KGDB signal that it's ready for slaves to enter */
		int sig;

		do {
			cpu_relax();
			sig = atomic_read(&uv_nmi_slave_continue);
		} while (!sig);

		/* Call KGDB as slave */
		if (sig == SLAVE_CONTINUE)
			kgdb_nmicallback(cpu, regs);
	}
	uv_nmi_sync_exit(master);
}

#else /* !CONFIG_KGDB */
static inline void uv_call_kgdb_kdb(int cpu, struct pt_regs *regs, int master)
{
	pr_err("UV: NMI error: KGDB is not enabled in this kernel\n");
}
#endif /* !CONFIG_KGDB */

static int uv_handle_nmi(unsigned int reason, struct pt_regs *regs)
{
	struct uv_hub_nmi_s *hub_nmi = uv_hub_nmi;
	int cpu = smp_processor_id();
	int master = 0;
	unsigned long flags;

	local_irq_save(flags);

	/* If not a UV System NMI, ignore */
	if (!this_cpu_read(uv_cpu_nmi.pinging) && !uv_check_nmi(hub_nmi)) {
		local_irq_restore(flags);
		return NMI_DONE;
	}

	/* Indicate we are the first CPU into the NMI handler */
	master = (atomic_read(&uv_nmi_cpu) == cpu);

	/* If NMI action is "kdump", then attempt to do it */
	if (uv_nmi_action_is("kdump")) {
		uv_nmi_kdump(cpu, master, regs);

		/* Unexpected return, revert action to "dump" */
		if (master)
			strncpy(uv_nmi_action, "dump", strlen(uv_nmi_action));
	}

	/* Pause as all CPU's enter the NMI handler */
	uv_nmi_wait(master);

	/* Process actions other than "kdump": */
	if (uv_nmi_action_is("health")) {
		uv_nmi_action_health(cpu, regs, master);
	} else if (uv_nmi_action_is("ips") || uv_nmi_action_is("dump")) {
		uv_nmi_dump_state(cpu, regs, master);
	} else if (uv_nmi_action_is("kdb") || uv_nmi_action_is("kgdb")) {
		uv_call_kgdb_kdb(cpu, regs, master);
	} else {
		if (master)
			pr_alert("UV: unknown NMI action: %s\n", uv_nmi_action);
		uv_nmi_sync_exit(master);
	}

	/* Clear per_cpu "in_nmi" flag */
	this_cpu_write(uv_cpu_nmi.state, UV_NMI_STATE_OUT);

	/* Clear MMR NMI flag on each hub */
	uv_clear_nmi(cpu);

	/* Clear global flags */
	if (master) {
		if (!cpumask_empty(uv_nmi_cpu_mask))
			uv_nmi_cleanup_mask();
		atomic_set(&uv_nmi_cpus_in_nmi, -1);
		atomic_set(&uv_nmi_cpu, -1);
		atomic_set(&uv_in_nmi, 0);
		atomic_set(&uv_nmi_kexec_failed, 0);
		atomic_set(&uv_nmi_slave_continue, SLAVE_CLEAR);
	}

	uv_nmi_touch_watchdogs();
	local_irq_restore(flags);

	return NMI_HANDLED;
}

static int uv_handle_nmi_ping(unsigned int reason, struct pt_regs *regs)
{
	int ret;

	this_cpu_inc(uv_cpu_nmi.queries);
	if (!this_cpu_read(uv_cpu_nmi.pinging)) {
		local64_inc(&uv_nmi_ping_misses);
		return NMI_DONE;
	}

	this_cpu_inc(uv_cpu_nmi.pings);
	local64_inc(&uv_nmi_ping_count);
	ret = uv_handle_nmi(reason, regs);
	this_cpu_write(uv_cpu_nmi.pinging, 0);
	return ret;
}

static void uv_register_nmi_notifier(void)
{
	if (register_nmi_handler(NMI_UNKNOWN, uv_handle_nmi, 0, "uv"))
		pr_warn("UV: NMI handler failed to register\n");

	if (register_nmi_handler(NMI_LOCAL, uv_handle_nmi_ping, 0, "uvping"))
		pr_warn("UV: PING NMI handler failed to register\n");
}

void uv_nmi_init(void)
{
	unsigned int value;

	/*
	value = apic_read(APIC_LVT1) | APIC_DM_NMI;
	value &= ~APIC_LVT_MASKED;
	apic_write(APIC_LVT1, value);
}

static void __init uv_nmi_setup_common(bool hubbed)
{
	int size = sizeof(void *) * (1 << NODES_SHIFT);
	int cpu;

	uv_hub_nmi_list = kzalloc(size, GFP_KERNEL);
	nmi_debug("UV: NMI hub list @ 0x%p (%d)\n", uv_hub_nmi_list, size);
	BUG_ON(!uv_hub_nmi_list);
	size = sizeof(struct uv_hub_nmi_s);
	for_each_present_cpu(cpu) {
		int nid = cpu_to_node(cpu);
		if (uv_hub_nmi_list[nid] == NULL) {
			uv_hub_nmi_list[nid] = kzalloc_node(size,
							    GFP_KERNEL, nid);
			BUG_ON(!uv_hub_nmi_list[nid]);
			raw_spin_lock_init(&(uv_hub_nmi_list[nid]->nmi_lock));
			atomic_set(&uv_hub_nmi_list[nid]->cpu_owner, -1);
			uv_hub_nmi_list[nid]->hub_present = hubbed;
			uv_hub_nmi_list[nid]->pch_owner = (nid == 0);
		}
		uv_hub_nmi_per(cpu) = uv_hub_nmi_list[nid];
	}
	BUG_ON(!alloc_cpumask_var(&uv_nmi_cpu_mask, GFP_KERNEL));
}

void __init uv_nmi_setup(void)
{
	uv_nmi_setup_mmrs();
	uv_nmi_setup_common(true);
	uv_register_nmi_notifier();
	pr_info("UV: Hub NMI enabled\n");
}

void __init uv_nmi_setup_hubless(void)
{
	uv_nmi_setup_common(false);
	pch_base = xlate_dev_mem_ptr(PCH_PCR_GPIO_1_BASE);
	nmi_debug("UV: PCH base:%p from 0x%lx, GPP_D_0\n",
		pch_base, PCH_PCR_GPIO_1_BASE);
	if (uv_pch_init_enable)
		uv_init_hubless_pch_d0();
	uv_init_hubless_pch_io(GPI_NMI_ENA_GPP_D_0,
				STS_GPP_D_0_MASK, STS_GPP_D_0_MASK);
	uv_nmi_setup_hubless_intr();
	/* Ensure NMI enabled in Processor Interface Reg: */
	uv_reassert_nmi();
	uv_register_nmi_notifier();
	pr_info("UV: PCH NMI enabled\n");
}
