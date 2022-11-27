
#include <linux/suspend.h>
#include <linux/export.h>
#include <linux/smp.h>
#include <linux/perf_event.h>
#include <linux/tboot.h>
#include <linux/dmi.h>
#include <linux/pgtable.h>

#include <asm/proto.h>
#include <asm/mtrr.h>
#include <asm/page.h>
#include <asm/mce.h>
#include <asm/suspend.h>
#include <asm/fpu/api.h>
#include <asm/debugreg.h>
#include <asm/cpu.h>
#include <asm/mmu_context.h>
#include <asm/cpu_device_id.h>
#include <asm/microcode.h>

#ifdef CONFIG_X86_32
__visible unsigned long saved_context_ebx;
__visible unsigned long saved_context_esp, saved_context_ebp;
__visible unsigned long saved_context_esi, saved_context_edi;
__visible unsigned long saved_context_eflags;
#endif
struct saved_context saved_context;

static void msr_save_context(struct saved_context *ctxt)
{
	struct saved_msr *msr = ctxt->saved_msrs.array;
	struct saved_msr *end = msr + ctxt->saved_msrs.num;

	while (msr < end) {
		if (msr->valid)
			rdmsrl(msr->info.msr_no, msr->info.reg.q);
		msr++;
	}
}

static void msr_restore_context(struct saved_context *ctxt)
{
	struct saved_msr *msr = ctxt->saved_msrs.array;
	struct saved_msr *end = msr + ctxt->saved_msrs.num;

	while (msr < end) {
		if (msr->valid)
			wrmsrl(msr->info.msr_no, msr->info.reg.q);
		msr++;
	}
}

static void __save_processor_state(struct saved_context *ctxt)
{
#ifdef CONFIG_X86_32
	mtrr_save_fixed_ranges(NULL);
#endif
	kernel_fpu_begin();

	/*
	store_idt(&ctxt->idt);

	/*
	ctxt->gdt_desc.size = GDT_SIZE - 1;
	ctxt->gdt_desc.address = (unsigned long)get_cpu_gdt_rw(smp_processor_id());

	store_tr(ctxt->tr);

	/* XMM0..XMM15 should be handled by kernel_fpu_begin(). */
	/*
	savesegment(gs, ctxt->gs);
#ifdef CONFIG_X86_64
	savesegment(fs, ctxt->fs);
	savesegment(ds, ctxt->ds);
	savesegment(es, ctxt->es);

	rdmsrl(MSR_FS_BASE, ctxt->fs_base);
	rdmsrl(MSR_GS_BASE, ctxt->kernelmode_gs_base);
	rdmsrl(MSR_KERNEL_GS_BASE, ctxt->usermode_gs_base);
	mtrr_save_fixed_ranges(NULL);

	rdmsrl(MSR_EFER, ctxt->efer);
#endif

	/*
	ctxt->cr0 = read_cr0();
	ctxt->cr2 = read_cr2();
	ctxt->cr3 = __read_cr3();
	ctxt->cr4 = __read_cr4();
	ctxt->misc_enable_saved = !rdmsrl_safe(MSR_IA32_MISC_ENABLE,
					       &ctxt->misc_enable);
	msr_save_context(ctxt);
}

void save_processor_state(void)
{
	__save_processor_state(&saved_context);
	x86_platform.save_sched_clock_state();
}
#ifdef CONFIG_X86_32
EXPORT_SYMBOL(save_processor_state);
#endif

static void do_fpu_end(void)
{
	/*
	kernel_fpu_end();
}

static void fix_processor_context(void)
{
	int cpu = smp_processor_id();
#ifdef CONFIG_X86_64
	struct desc_struct *desc = get_cpu_gdt_rw(cpu);
	tss_desc tss;
#endif

	/*
	set_tss_desc(cpu, &get_cpu_entry_area(cpu)->tss.x86_tss);

#ifdef CONFIG_X86_64
	memcpy(&tss, &desc[GDT_ENTRY_TSS], sizeof(tss_desc));
	tss.type = 0x9; /* The available 64-bit TSS (see AMD vol 2, pg 91 */
	write_gdt_entry(desc, GDT_ENTRY_TSS, &tss, DESC_TSS);

	syscall_init();				/* This sets MSR_*STAR and related */
#else
	if (boot_cpu_has(X86_FEATURE_SEP))
		enable_sep_cpu();
#endif
	load_TR_desc();				/* This does ltr */
	load_mm_ldt(current->active_mm);	/* This does lldt */
	initialize_tlbstate_and_flush();

	fpu__resume_cpu();

	/* The processor is back on the direct GDT, load back the fixmap */
	load_fixmap_gdt(cpu);
}

static void notrace __restore_processor_state(struct saved_context *ctxt)
{
	struct cpuinfo_x86 *c;

	if (ctxt->misc_enable_saved)
		wrmsrl(MSR_IA32_MISC_ENABLE, ctxt->misc_enable);
	/*
	/* cr4 was introduced in the Pentium CPU */
#ifdef CONFIG_X86_32
	if (ctxt->cr4)
		__write_cr4(ctxt->cr4);
#else
	wrmsrl(MSR_EFER, ctxt->efer);
	__write_cr4(ctxt->cr4);
#endif
	write_cr3(ctxt->cr3);
	write_cr2(ctxt->cr2);
	write_cr0(ctxt->cr0);

	/* Restore the IDT. */
	load_idt(&ctxt->idt);

	/*
	loadsegment(ss, __KERNEL_DS);
	loadsegment(ds, __USER_DS);
	loadsegment(es, __USER_DS);

	/*
#ifdef CONFIG_X86_64
	wrmsrl(MSR_GS_BASE, ctxt->kernelmode_gs_base);
#else
	loadsegment(fs, __KERNEL_PERCPU);
#endif

	/* Restore the TSS, RO GDT, LDT, and usermode-relevant MSRs. */
	fix_processor_context();

	/*
#ifdef CONFIG_X86_64
	loadsegment(ds, ctxt->es);
	loadsegment(es, ctxt->es);
	loadsegment(fs, ctxt->fs);
	load_gs_index(ctxt->gs);

	/*
	wrmsrl(MSR_FS_BASE, ctxt->fs_base);
	wrmsrl(MSR_KERNEL_GS_BASE, ctxt->usermode_gs_base);
#else
	loadsegment(gs, ctxt->gs);
#endif

	do_fpu_end();
	tsc_verify_tsc_adjust(true);
	x86_platform.restore_sched_clock_state();
	mtrr_bp_restore();
	perf_restore_debug_store();

	c = &cpu_data(smp_processor_id());
	if (cpu_has(c, X86_FEATURE_MSR_IA32_FEAT_CTL))
		init_ia32_feat_ctl(c);

	microcode_bsp_resume();

	/*
	msr_restore_context(ctxt);
}

void notrace restore_processor_state(void)
{
	__restore_processor_state(&saved_context);
}
#ifdef CONFIG_X86_32
EXPORT_SYMBOL(restore_processor_state);
#endif

#if defined(CONFIG_HIBERNATION) && defined(CONFIG_HOTPLUG_CPU)
static void resume_play_dead(void)
{
	play_dead_common();
	tboot_shutdown(TB_SHUTDOWN_WFS);
	hlt_play_dead();
}

int hibernate_resume_nonboot_cpu_disable(void)
{
	void (*play_dead)(void) = smp_ops.play_dead;
	int ret;

	/*
	ret = cpuhp_smt_enable();
	if (ret)
		return ret;
	smp_ops.play_dead = resume_play_dead;
	ret = freeze_secondary_cpus(0);
	smp_ops.play_dead = play_dead;
	return ret;
}
#endif

static int bsp_check(void)
{
	if (cpumask_first(cpu_online_mask) != 0) {
		pr_warn("CPU0 is offline.\n");
		return -ENODEV;
	}

	return 0;
}

static int bsp_pm_callback(struct notifier_block *nb, unsigned long action,
			   void *ptr)
{
	int ret = 0;

	switch (action) {
	case PM_SUSPEND_PREPARE:
	case PM_HIBERNATION_PREPARE:
		ret = bsp_check();
		break;
#ifdef CONFIG_DEBUG_HOTPLUG_CPU0
	case PM_RESTORE_PREPARE:
		/*
		if (!cpu_online(0))
			_debug_hotplug_cpu(0, 1);
		break;
	case PM_POST_RESTORE:
		/*
		_debug_hotplug_cpu(0, 0);
		break;
#endif
	default:
		break;
	}
	return notifier_from_errno(ret);
}

static int __init bsp_pm_check_init(void)
{
	/*
	pm_notifier(bsp_pm_callback, -INT_MAX);
	return 0;
}

core_initcall(bsp_pm_check_init);

static int msr_build_context(const u32 *msr_id, const int num)
{
	struct saved_msrs *saved_msrs = &saved_context.saved_msrs;
	struct saved_msr *msr_array;
	int total_num;
	int i, j;

	total_num = saved_msrs->num + num;

	msr_array = kmalloc_array(total_num, sizeof(struct saved_msr), GFP_KERNEL);
	if (!msr_array) {
		pr_err("x86/pm: Can not allocate memory to save/restore MSRs during suspend.\n");
		return -ENOMEM;
	}

	if (saved_msrs->array) {
		/*
		memcpy(msr_array, saved_msrs->array,
		       sizeof(struct saved_msr) * saved_msrs->num);

		kfree(saved_msrs->array);
	}

	for (i = saved_msrs->num, j = 0; i < total_num; i++, j++) {
		u64 dummy;

		msr_array[i].info.msr_no	= msr_id[j];
		msr_array[i].valid		= !rdmsrl_safe(msr_id[j], &dummy);
		msr_array[i].info.reg.q		= 0;
	}
	saved_msrs->num   = total_num;
	saved_msrs->array = msr_array;

	return 0;
}

static int msr_initialize_bdw(const struct dmi_system_id *d)
{
	/* Add any extra MSR ids into this array. */
	u32 bdw_msr_id[] = { MSR_IA32_THERM_CONTROL };

	pr_info("x86/pm: %s detected, MSR saving is needed during suspending.\n", d->ident);
	return msr_build_context(bdw_msr_id, ARRAY_SIZE(bdw_msr_id));
}

static const struct dmi_system_id msr_save_dmi_table[] = {
	{
	 .callback = msr_initialize_bdw,
	 .ident = "BROADWELL BDX_EP",
	 .matches = {
		DMI_MATCH(DMI_PRODUCT_NAME, "GRANTLEY"),
		DMI_MATCH(DMI_PRODUCT_VERSION, "E63448-400"),
		},
	},
	{}
};

static int msr_save_cpuid_features(const struct x86_cpu_id *c)
{
	u32 cpuid_msr_id[] = {
		MSR_AMD64_CPUID_FN_1,
	};

	pr_info("x86/pm: family %#hx cpu detected, MSR saving is needed during suspending.\n",
		c->family);

	return msr_build_context(cpuid_msr_id, ARRAY_SIZE(cpuid_msr_id));
}

static const struct x86_cpu_id msr_save_cpu_table[] = {
	X86_MATCH_VENDOR_FAM(AMD, 0x15, &msr_save_cpuid_features),
	X86_MATCH_VENDOR_FAM(AMD, 0x16, &msr_save_cpuid_features),
	{}
};

typedef int (*pm_cpu_match_t)(const struct x86_cpu_id *);
static int pm_cpu_check(const struct x86_cpu_id *c)
{
	const struct x86_cpu_id *m;
	int ret = 0;

	m = x86_match_cpu(msr_save_cpu_table);
	if (m) {
		pm_cpu_match_t fn;

		fn = (pm_cpu_match_t)m->driver_data;
		ret = fn(m);
	}

	return ret;
}

static void pm_save_spec_msr(void)
{
	u32 spec_msr_id[] = {
		MSR_IA32_SPEC_CTRL,
		MSR_IA32_TSX_CTRL,
		MSR_TSX_FORCE_ABORT,
		MSR_IA32_MCU_OPT_CTRL,
		MSR_AMD64_LS_CFG,
	};

	msr_build_context(spec_msr_id, ARRAY_SIZE(spec_msr_id));
}

static int pm_check_save_msr(void)
{
	dmi_check_system(msr_save_dmi_table);
	pm_cpu_check(msr_save_cpu_table);
	pm_save_spec_msr();

	return 0;
}

device_initcall(pm_check_save_msr);
