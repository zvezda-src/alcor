
#include <linux/cpufeature.h>

#include <asm/cmdline.h>

#include "cpu.h"

#undef pr_fmt
#define pr_fmt(fmt) "tsx: " fmt

enum tsx_ctrl_states tsx_ctrl_state __ro_after_init = TSX_CTRL_NOT_SUPPORTED;

static void tsx_disable(void)
{
	u64 tsx;

	rdmsrl(MSR_IA32_TSX_CTRL, tsx);

	/* Force all transactions to immediately abort */
	tsx |= TSX_CTRL_RTM_DISABLE;

	/*
	tsx |= TSX_CTRL_CPUID_CLEAR;

	wrmsrl(MSR_IA32_TSX_CTRL, tsx);
}

static void tsx_enable(void)
{
	u64 tsx;

	rdmsrl(MSR_IA32_TSX_CTRL, tsx);

	/* Enable the RTM feature in the cpu */
	tsx &= ~TSX_CTRL_RTM_DISABLE;

	/*
	tsx &= ~TSX_CTRL_CPUID_CLEAR;

	wrmsrl(MSR_IA32_TSX_CTRL, tsx);
}

static bool tsx_ctrl_is_supported(void)
{
	u64 ia32_cap = x86_read_arch_cap_msr();

	/*
	return !!(ia32_cap & ARCH_CAP_TSX_CTRL_MSR);
}

static enum tsx_ctrl_states x86_get_tsx_auto_mode(void)
{
	if (boot_cpu_has_bug(X86_BUG_TAA))
		return TSX_CTRL_DISABLE;

	return TSX_CTRL_ENABLE;
}

static void tsx_clear_cpuid(void)
{
	u64 msr;

	/*
	if (boot_cpu_has(X86_FEATURE_RTM_ALWAYS_ABORT) &&
	    boot_cpu_has(X86_FEATURE_TSX_FORCE_ABORT)) {
		rdmsrl(MSR_TSX_FORCE_ABORT, msr);
		msr |= MSR_TFA_TSX_CPUID_CLEAR;
		wrmsrl(MSR_TSX_FORCE_ABORT, msr);
	} else if (tsx_ctrl_is_supported()) {
		rdmsrl(MSR_IA32_TSX_CTRL, msr);
		msr |= TSX_CTRL_CPUID_CLEAR;
		wrmsrl(MSR_IA32_TSX_CTRL, msr);
	}
}

static void tsx_dev_mode_disable(void)
{
	u64 mcu_opt_ctrl;

	/* Check if RTM_ALLOW exists */
	if (!boot_cpu_has_bug(X86_BUG_TAA) || !tsx_ctrl_is_supported() ||
	    !cpu_feature_enabled(X86_FEATURE_SRBDS_CTRL))
		return;

	rdmsrl(MSR_IA32_MCU_OPT_CTRL, mcu_opt_ctrl);

	if (mcu_opt_ctrl & RTM_ALLOW) {
		mcu_opt_ctrl &= ~RTM_ALLOW;
		wrmsrl(MSR_IA32_MCU_OPT_CTRL, mcu_opt_ctrl);
		setup_force_cpu_cap(X86_FEATURE_RTM_ALWAYS_ABORT);
	}
}

void __init tsx_init(void)
{
	char arg[5] = {};
	int ret;

	tsx_dev_mode_disable();

	/*
	if (boot_cpu_has(X86_FEATURE_RTM_ALWAYS_ABORT)) {
		tsx_ctrl_state = TSX_CTRL_RTM_ALWAYS_ABORT;
		tsx_clear_cpuid();
		setup_clear_cpu_cap(X86_FEATURE_RTM);
		setup_clear_cpu_cap(X86_FEATURE_HLE);
		return;
	}

	if (!tsx_ctrl_is_supported()) {
		tsx_ctrl_state = TSX_CTRL_NOT_SUPPORTED;
		return;
	}

	ret = cmdline_find_option(boot_command_line, "tsx", arg, sizeof(arg));
	if (ret >= 0) {
		if (!strcmp(arg, "on")) {
			tsx_ctrl_state = TSX_CTRL_ENABLE;
		} else if (!strcmp(arg, "off")) {
			tsx_ctrl_state = TSX_CTRL_DISABLE;
		} else if (!strcmp(arg, "auto")) {
			tsx_ctrl_state = x86_get_tsx_auto_mode();
		} else {
			tsx_ctrl_state = TSX_CTRL_DISABLE;
			pr_err("invalid option, defaulting to off\n");
		}
	} else {
		/* tsx= not provided */
		if (IS_ENABLED(CONFIG_X86_INTEL_TSX_MODE_AUTO))
			tsx_ctrl_state = x86_get_tsx_auto_mode();
		else if (IS_ENABLED(CONFIG_X86_INTEL_TSX_MODE_OFF))
			tsx_ctrl_state = TSX_CTRL_DISABLE;
		else
			tsx_ctrl_state = TSX_CTRL_ENABLE;
	}

	if (tsx_ctrl_state == TSX_CTRL_DISABLE) {
		tsx_disable();

		/*
		setup_clear_cpu_cap(X86_FEATURE_RTM);
		setup_clear_cpu_cap(X86_FEATURE_HLE);
	} else if (tsx_ctrl_state == TSX_CTRL_ENABLE) {

		/*
		tsx_enable();

		/*
		setup_force_cpu_cap(X86_FEATURE_RTM);
		setup_force_cpu_cap(X86_FEATURE_HLE);
	}
}

void tsx_ap_init(void)
{
	tsx_dev_mode_disable();

	if (tsx_ctrl_state == TSX_CTRL_ENABLE)
		tsx_enable();
	else if (tsx_ctrl_state == TSX_CTRL_DISABLE)
		tsx_disable();
	else if (tsx_ctrl_state == TSX_CTRL_RTM_ALWAYS_ABORT)
		/* See comment over that function for more details. */
		tsx_clear_cpuid();
}
