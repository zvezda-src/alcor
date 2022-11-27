#include <linux/bitops.h>
#include <linux/compat.h>
#include <linux/cpu.h>
#include <linux/mman.h>
#include <linux/nospec.h>
#include <linux/pkeys.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>

#include <asm/fpu/api.h>
#include <asm/fpu/regset.h>
#include <asm/fpu/signal.h>
#include <asm/fpu/xcr.h>

#include <asm/tlbflush.h>
#include <asm/prctl.h>
#include <asm/elf.h>

#include "context.h"
#include "internal.h"
#include "legacy.h"
#include "xstate.h"

#define for_each_extended_xfeature(bit, mask)				\
	(bit) = FIRST_EXTENDED_XFEATURE;				\
	for_each_set_bit_from(bit, (unsigned long *)&(mask), 8 * sizeof(mask))

static const char *xfeature_names[] =
{
	"x87 floating point registers"	,
	"SSE registers"			,
	"AVX registers"			,
	"MPX bounds registers"		,
	"MPX CSR"			,
	"AVX-512 opmask"		,
	"AVX-512 Hi256"			,
	"AVX-512 ZMM_Hi256"		,
	"Processor Trace (unused)"	,
	"Protection Keys User registers",
	"PASID state",
	"unknown xstate feature"	,
	"unknown xstate feature"	,
	"unknown xstate feature"	,
	"unknown xstate feature"	,
	"unknown xstate feature"	,
	"unknown xstate feature"	,
	"AMX Tile config"		,
	"AMX Tile data"			,
	"unknown xstate feature"	,
};

static unsigned short xsave_cpuid_features[] __initdata = {
	[XFEATURE_FP]				= X86_FEATURE_FPU,
	[XFEATURE_SSE]				= X86_FEATURE_XMM,
	[XFEATURE_YMM]				= X86_FEATURE_AVX,
	[XFEATURE_BNDREGS]			= X86_FEATURE_MPX,
	[XFEATURE_BNDCSR]			= X86_FEATURE_MPX,
	[XFEATURE_OPMASK]			= X86_FEATURE_AVX512F,
	[XFEATURE_ZMM_Hi256]			= X86_FEATURE_AVX512F,
	[XFEATURE_Hi16_ZMM]			= X86_FEATURE_AVX512F,
	[XFEATURE_PT_UNIMPLEMENTED_SO_FAR]	= X86_FEATURE_INTEL_PT,
	[XFEATURE_PKRU]				= X86_FEATURE_PKU,
	[XFEATURE_PASID]			= X86_FEATURE_ENQCMD,
	[XFEATURE_XTILE_CFG]			= X86_FEATURE_AMX_TILE,
	[XFEATURE_XTILE_DATA]			= X86_FEATURE_AMX_TILE,
};

static unsigned int xstate_offsets[XFEATURE_MAX] __ro_after_init =
	{ [ 0 ... XFEATURE_MAX - 1] = -1};
static unsigned int xstate_sizes[XFEATURE_MAX] __ro_after_init =
	{ [ 0 ... XFEATURE_MAX - 1] = -1};
static unsigned int xstate_flags[XFEATURE_MAX] __ro_after_init;

#define XSTATE_FLAG_SUPERVISOR	BIT(0)
#define XSTATE_FLAG_ALIGNED64	BIT(1)

int cpu_has_xfeatures(u64 xfeatures_needed, const char **feature_name)
{
	u64 xfeatures_missing = xfeatures_needed & ~fpu_kernel_cfg.max_features;

	if (unlikely(feature_name)) {
		long xfeature_idx, max_idx;
		u64 xfeatures_print;
		/*
		if (xfeatures_missing)
			xfeatures_print = xfeatures_missing;
		else
			xfeatures_print = xfeatures_needed;

		xfeature_idx = fls64(xfeatures_print)-1;
		max_idx = ARRAY_SIZE(xfeature_names)-1;
		xfeature_idx = min(xfeature_idx, max_idx);

		*feature_name = xfeature_names[xfeature_idx];
	}

	if (xfeatures_missing)
		return 0;

	return 1;
}
EXPORT_SYMBOL_GPL(cpu_has_xfeatures);

static bool xfeature_is_aligned64(int xfeature_nr)
{
	return xstate_flags[xfeature_nr] & XSTATE_FLAG_ALIGNED64;
}

static bool xfeature_is_supervisor(int xfeature_nr)
{
	return xstate_flags[xfeature_nr] & XSTATE_FLAG_SUPERVISOR;
}

static unsigned int xfeature_get_offset(u64 xcomp_bv, int xfeature)
{
	unsigned int offs, i;

	/*
	if (!cpu_feature_enabled(X86_FEATURE_XCOMPACTED) ||
	    xfeature <= XFEATURE_SSE)
		return xstate_offsets[xfeature];

	/*
	offs = FXSAVE_SIZE + XSAVE_HDR_SIZE;
	for_each_extended_xfeature(i, xcomp_bv) {
		if (xfeature_is_aligned64(i))
			offs = ALIGN(offs, 64);
		if (i == xfeature)
			break;
		offs += xstate_sizes[i];
	}
	return offs;
}

void fpu__init_cpu_xstate(void)
{
	if (!boot_cpu_has(X86_FEATURE_XSAVE) || !fpu_kernel_cfg.max_features)
		return;

	cr4_set_bits(X86_CR4_OSXSAVE);

	/*
	if (cpu_feature_enabled(X86_FEATURE_XFD))
		wrmsrl(MSR_IA32_XFD, init_fpstate.xfd);

	/*
	xsetbv(XCR_XFEATURE_ENABLED_MASK, fpu_user_cfg.max_features);

	/*
	if (boot_cpu_has(X86_FEATURE_XSAVES)) {
		wrmsrl(MSR_IA32_XSS, xfeatures_mask_supervisor() |
				     xfeatures_mask_independent());
	}
}

static bool xfeature_enabled(enum xfeature xfeature)
{
	return fpu_kernel_cfg.max_features & BIT_ULL(xfeature);
}

static void __init setup_xstate_cache(void)
{
	u32 eax, ebx, ecx, edx, i;
	/* start at the beginning of the "extended state" */
	unsigned int last_good_offset = offsetof(struct xregs_state,
						 extended_state_area);
	/*
	xstate_offsets[XFEATURE_FP]	= 0;
	xstate_sizes[XFEATURE_FP]	= offsetof(struct fxregs_state,
						   xmm_space);

	xstate_offsets[XFEATURE_SSE]	= xstate_sizes[XFEATURE_FP];
	xstate_sizes[XFEATURE_SSE]	= sizeof_field(struct fxregs_state,
						       xmm_space);

	for_each_extended_xfeature(i, fpu_kernel_cfg.max_features) {
		cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx);

		xstate_sizes[i] = eax;
		xstate_flags[i] = ecx;

		/*
		if (xfeature_is_supervisor(i))
			continue;

		xstate_offsets[i] = ebx;

		/*
		WARN_ONCE(last_good_offset > xstate_offsets[i],
			  "x86/fpu: misordered xstate at %d\n", last_good_offset);

		last_good_offset = xstate_offsets[i];
	}
}

static void __init print_xstate_feature(u64 xstate_mask)
{
	const char *feature_name;

	if (cpu_has_xfeatures(xstate_mask, &feature_name))
		pr_info("x86/fpu: Supporting XSAVE feature 0x%03Lx: '%s'\n", xstate_mask, feature_name);
}

static void __init print_xstate_features(void)
{
	print_xstate_feature(XFEATURE_MASK_FP);
	print_xstate_feature(XFEATURE_MASK_SSE);
	print_xstate_feature(XFEATURE_MASK_YMM);
	print_xstate_feature(XFEATURE_MASK_BNDREGS);
	print_xstate_feature(XFEATURE_MASK_BNDCSR);
	print_xstate_feature(XFEATURE_MASK_OPMASK);
	print_xstate_feature(XFEATURE_MASK_ZMM_Hi256);
	print_xstate_feature(XFEATURE_MASK_Hi16_ZMM);
	print_xstate_feature(XFEATURE_MASK_PKRU);
	print_xstate_feature(XFEATURE_MASK_PASID);
	print_xstate_feature(XFEATURE_MASK_XTILE_CFG);
	print_xstate_feature(XFEATURE_MASK_XTILE_DATA);
}

#define CHECK_XFEATURE(nr) do {		\
	WARN_ON(nr < FIRST_EXTENDED_XFEATURE);	\
	WARN_ON(nr >= XFEATURE_MAX);	\
} while (0)

static void __init print_xstate_offset_size(void)
{
	int i;

	for_each_extended_xfeature(i, fpu_kernel_cfg.max_features) {
		pr_info("x86/fpu: xstate_offset[%d]: %4d, xstate_sizes[%d]: %4d\n",
			i, xfeature_get_offset(fpu_kernel_cfg.max_features, i),
			i, xstate_sizes[i]);
	}
}

static __init void os_xrstor_booting(struct xregs_state *xstate)
{
	u64 mask = fpu_kernel_cfg.max_features & XFEATURE_MASK_FPSTATE;
	u32 lmask = mask;
	u32 hmask = mask >> 32;
	int err;

	if (cpu_feature_enabled(X86_FEATURE_XSAVES))
		XSTATE_OP(XRSTORS, xstate, lmask, hmask, err);
	else
		XSTATE_OP(XRSTOR, xstate, lmask, hmask, err);

	/*
	WARN_ON_FPU(err);
}

#define XFEATURES_INIT_FPSTATE_HANDLED		\
	(XFEATURE_MASK_FP |			\
	 XFEATURE_MASK_SSE |			\
	 XFEATURE_MASK_YMM |			\
	 XFEATURE_MASK_OPMASK |			\
	 XFEATURE_MASK_ZMM_Hi256 |		\
	 XFEATURE_MASK_Hi16_ZMM	 |		\
	 XFEATURE_MASK_PKRU |			\
	 XFEATURE_MASK_BNDREGS |		\
	 XFEATURE_MASK_BNDCSR |			\
	 XFEATURE_MASK_PASID |			\
	 XFEATURE_MASK_XTILE)

static void __init setup_init_fpu_buf(void)
{
	BUILD_BUG_ON((XFEATURE_MASK_USER_SUPPORTED |
		      XFEATURE_MASK_SUPERVISOR_SUPPORTED) !=
		     XFEATURES_INIT_FPSTATE_HANDLED);

	if (!boot_cpu_has(X86_FEATURE_XSAVE))
		return;

	print_xstate_features();

	xstate_init_xcomp_bv(&init_fpstate.regs.xsave, fpu_kernel_cfg.max_features);

	/*
	os_xrstor_booting(&init_fpstate.regs.xsave);

	/*
	fxsave(&init_fpstate.regs.fxsave);
}

int xfeature_size(int xfeature_nr)
{
	u32 eax, ebx, ecx, edx;

	CHECK_XFEATURE(xfeature_nr);
	cpuid_count(XSTATE_CPUID, xfeature_nr, &eax, &ebx, &ecx, &edx);
	return eax;
}

static int validate_user_xstate_header(const struct xstate_header *hdr,
				       struct fpstate *fpstate)
{
	/* No unknown or supervisor features may be set */
	if (hdr->xfeatures & ~fpstate->user_xfeatures)
		return -EINVAL;

	/* Userspace must use the uncompacted format */
	if (hdr->xcomp_bv)
		return -EINVAL;

	/*
	BUILD_BUG_ON(sizeof(hdr->reserved) != 48);

	/* No reserved bits may be set */
	if (memchr_inv(hdr->reserved, 0, sizeof(hdr->reserved)))
		return -EINVAL;

	return 0;
}

static void __init __xstate_dump_leaves(void)
{
	int i;
	u32 eax, ebx, ecx, edx;
	static int should_dump = 1;

	if (!should_dump)
		return;
	should_dump = 0;
	/*
	for (i = 0; i < XFEATURE_MAX + 10; i++) {
		cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx);
		pr_warn("CPUID[%02x, %02x]: eax=%08x ebx=%08x ecx=%08x edx=%08x\n",
			XSTATE_CPUID, i, eax, ebx, ecx, edx);
	}
}

#define XSTATE_WARN_ON(x) do {							\
	if (WARN_ONCE(x, "XSAVE consistency problem, dumping leaves")) {	\
		__xstate_dump_leaves();						\
	}									\
} while (0)

#define XCHECK_SZ(sz, nr, nr_macro, __struct) do {			\
	if ((nr == nr_macro) &&						\
	    WARN_ONCE(sz != sizeof(__struct),				\
		"%s: struct is %zu bytes, cpu state %d bytes\n",	\
		__stringify(nr_macro), sizeof(__struct), sz)) {		\
		__xstate_dump_leaves();					\
	}								\
} while (0)

static int __init check_xtile_data_against_struct(int size)
{
	u32 max_palid, palid, state_size;
	u32 eax, ebx, ecx, edx;
	u16 max_tile;

	/*
	cpuid_count(TILE_CPUID, 0, &max_palid, &ebx, &ecx, &edx);

	/*
	for (palid = 1, max_tile = 0; palid <= max_palid; palid++) {
		u16 tile_size, max;

		/*
		cpuid_count(TILE_CPUID, palid, &eax, &ebx, &edx, &edx);
		tile_size = eax >> 16;
		max = ebx >> 16;

		if (tile_size != sizeof(struct xtile_data)) {
			pr_err("%s: struct is %zu bytes, cpu xtile %d bytes\n",
			       __stringify(XFEATURE_XTILE_DATA),
			       sizeof(struct xtile_data), tile_size);
			__xstate_dump_leaves();
			return -EINVAL;
		}

		if (max > max_tile)
			max_tile = max;
	}

	state_size = sizeof(struct xtile_data) * max_tile;
	if (size != state_size) {
		pr_err("%s: calculated size is %u bytes, cpu state %d bytes\n",
		       __stringify(XFEATURE_XTILE_DATA), state_size, size);
		__xstate_dump_leaves();
		return -EINVAL;
	}
	return 0;
}

static bool __init check_xstate_against_struct(int nr)
{
	/*
	int sz = xfeature_size(nr);
	/*
	XCHECK_SZ(sz, nr, XFEATURE_YMM,       struct ymmh_struct);
	XCHECK_SZ(sz, nr, XFEATURE_BNDREGS,   struct mpx_bndreg_state);
	XCHECK_SZ(sz, nr, XFEATURE_BNDCSR,    struct mpx_bndcsr_state);
	XCHECK_SZ(sz, nr, XFEATURE_OPMASK,    struct avx_512_opmask_state);
	XCHECK_SZ(sz, nr, XFEATURE_ZMM_Hi256, struct avx_512_zmm_uppers_state);
	XCHECK_SZ(sz, nr, XFEATURE_Hi16_ZMM,  struct avx_512_hi16_state);
	XCHECK_SZ(sz, nr, XFEATURE_PKRU,      struct pkru_state);
	XCHECK_SZ(sz, nr, XFEATURE_PASID,     struct ia32_pasid_state);
	XCHECK_SZ(sz, nr, XFEATURE_XTILE_CFG, struct xtile_cfg);

	/* The tile data size varies between implementations. */
	if (nr == XFEATURE_XTILE_DATA)
		check_xtile_data_against_struct(sz);

	/*
	if ((nr < XFEATURE_YMM) ||
	    (nr >= XFEATURE_MAX) ||
	    (nr == XFEATURE_PT_UNIMPLEMENTED_SO_FAR) ||
	    ((nr >= XFEATURE_RSRVD_COMP_11) && (nr <= XFEATURE_RSRVD_COMP_16))) {
		WARN_ONCE(1, "no structure for xstate: %d\n", nr);
		XSTATE_WARN_ON(1);
		return false;
	}
	return true;
}

static unsigned int xstate_calculate_size(u64 xfeatures, bool compacted)
{
	unsigned int topmost = fls64(xfeatures) -  1;
	unsigned int offset = xstate_offsets[topmost];

	if (topmost <= XFEATURE_SSE)
		return sizeof(struct xregs_state);

	if (compacted)
		offset = xfeature_get_offset(xfeatures, topmost);
	return offset + xstate_sizes[topmost];
}

static bool __init paranoid_xstate_size_valid(unsigned int kernel_size)
{
	bool compacted = cpu_feature_enabled(X86_FEATURE_XCOMPACTED);
	bool xsaves = cpu_feature_enabled(X86_FEATURE_XSAVES);
	unsigned int size = FXSAVE_SIZE + XSAVE_HDR_SIZE;
	int i;

	for_each_extended_xfeature(i, fpu_kernel_cfg.max_features) {
		if (!check_xstate_against_struct(i))
			return false;
		/*
		if (!xsaves && xfeature_is_supervisor(i)) {
			XSTATE_WARN_ON(1);
			return false;
		}
	}
	size = xstate_calculate_size(fpu_kernel_cfg.max_features, compacted);
	XSTATE_WARN_ON(size != kernel_size);
	return size == kernel_size;
}

static unsigned int __init get_compacted_size(void)
{
	unsigned int eax, ebx, ecx, edx;
	/*
	cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
	return ebx;
}

static unsigned int __init get_xsave_compacted_size(void)
{
	u64 mask = xfeatures_mask_independent();
	unsigned int size;

	if (!mask)
		return get_compacted_size();

	/* Disable independent features. */
	wrmsrl(MSR_IA32_XSS, xfeatures_mask_supervisor());

	/*
	size = get_compacted_size();

	/* Re-enable independent features so XSAVES will work on them again. */
	wrmsrl(MSR_IA32_XSS, xfeatures_mask_supervisor() | mask);

	return size;
}

static unsigned int __init get_xsave_size_user(void)
{
	unsigned int eax, ebx, ecx, edx;
	/*
	cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
	return ebx;
}

static bool __init is_supported_xstate_size(unsigned int test_xstate_size)
{
	if (test_xstate_size <= sizeof(init_fpstate.regs))
		return true;

	pr_warn("x86/fpu: xstate buffer too small (%zu < %d), disabling xsave\n",
			sizeof(init_fpstate.regs), test_xstate_size);
	return false;
}

static int __init init_xstate_size(void)
{
	/* Recompute the context size for enabled features: */
	unsigned int user_size, kernel_size, kernel_default_size;
	bool compacted = cpu_feature_enabled(X86_FEATURE_XCOMPACTED);

	/* Uncompacted user space size */
	user_size = get_xsave_size_user();

	/*
	if (compacted)
		kernel_size = get_xsave_compacted_size();
	else
		kernel_size = user_size;

	kernel_default_size =
		xstate_calculate_size(fpu_kernel_cfg.default_features, compacted);

	/* Ensure we have the space to store all default enabled features. */
	if (!is_supported_xstate_size(kernel_default_size))
		return -EINVAL;

	if (!paranoid_xstate_size_valid(kernel_size))
		return -EINVAL;

	fpu_kernel_cfg.max_size = kernel_size;
	fpu_user_cfg.max_size = user_size;

	fpu_kernel_cfg.default_size = kernel_default_size;
	fpu_user_cfg.default_size =
		xstate_calculate_size(fpu_user_cfg.default_features, false);

	return 0;
}

static void __init fpu__init_disable_system_xstate(unsigned int legacy_size)
{
	fpu_kernel_cfg.max_features = 0;
	cr4_clear_bits(X86_CR4_OSXSAVE);
	setup_clear_cpu_cap(X86_FEATURE_XSAVE);

	/* Restore the legacy size.*/
	fpu_kernel_cfg.max_size = legacy_size;
	fpu_kernel_cfg.default_size = legacy_size;
	fpu_user_cfg.max_size = legacy_size;
	fpu_user_cfg.default_size = legacy_size;

	/*
	init_fpstate.xfd = 0;

	fpstate_reset(&current->thread.fpu);
}

void __init fpu__init_system_xstate(unsigned int legacy_size)
{
	unsigned int eax, ebx, ecx, edx;
	u64 xfeatures;
	int err;
	int i;

	if (!boot_cpu_has(X86_FEATURE_FPU)) {
		pr_info("x86/fpu: No FPU detected\n");
		return;
	}

	if (!boot_cpu_has(X86_FEATURE_XSAVE)) {
		pr_info("x86/fpu: x87 FPU will use %s\n",
			boot_cpu_has(X86_FEATURE_FXSR) ? "FXSAVE" : "FSAVE");
		return;
	}

	if (boot_cpu_data.cpuid_level < XSTATE_CPUID) {
		WARN_ON_FPU(1);
		return;
	}

	/*
	cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
	fpu_kernel_cfg.max_features = eax + ((u64)edx << 32);

	/*
	cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
	fpu_kernel_cfg.max_features |= ecx + ((u64)edx << 32);

	if ((fpu_kernel_cfg.max_features & XFEATURE_MASK_FPSSE) != XFEATURE_MASK_FPSSE) {
		/*
		pr_err("x86/fpu: FP/SSE not present amongst the CPU's xstate features: 0x%llx.\n",
		       fpu_kernel_cfg.max_features);
		goto out_disable;
	}

	/*
	for (i = 0; i < ARRAY_SIZE(xsave_cpuid_features); i++) {
		unsigned short cid = xsave_cpuid_features[i];

		/* Careful: X86_FEATURE_FPU is 0! */
		if ((i != XFEATURE_FP && !cid) || !boot_cpu_has(cid))
			fpu_kernel_cfg.max_features &= ~BIT_ULL(i);
	}

	if (!cpu_feature_enabled(X86_FEATURE_XFD))
		fpu_kernel_cfg.max_features &= ~XFEATURE_MASK_USER_DYNAMIC;

	if (!cpu_feature_enabled(X86_FEATURE_XSAVES))
		fpu_kernel_cfg.max_features &= XFEATURE_MASK_USER_SUPPORTED;
	else
		fpu_kernel_cfg.max_features &= XFEATURE_MASK_USER_SUPPORTED |
					XFEATURE_MASK_SUPERVISOR_SUPPORTED;

	fpu_user_cfg.max_features = fpu_kernel_cfg.max_features;
	fpu_user_cfg.max_features &= XFEATURE_MASK_USER_SUPPORTED;

	/* Clean out dynamic features from default */
	fpu_kernel_cfg.default_features = fpu_kernel_cfg.max_features;
	fpu_kernel_cfg.default_features &= ~XFEATURE_MASK_USER_DYNAMIC;

	fpu_user_cfg.default_features = fpu_user_cfg.max_features;
	fpu_user_cfg.default_features &= ~XFEATURE_MASK_USER_DYNAMIC;

	/* Store it for paranoia check at the end */
	xfeatures = fpu_kernel_cfg.max_features;

	/*
	init_fpstate.xfd = fpu_user_cfg.max_features & XFEATURE_MASK_USER_DYNAMIC;

	/* Set up compaction feature bit */
	if (cpu_feature_enabled(X86_FEATURE_XSAVEC) ||
	    cpu_feature_enabled(X86_FEATURE_XSAVES))
		setup_force_cpu_cap(X86_FEATURE_XCOMPACTED);

	/* Enable xstate instructions to be able to continue with initialization: */
	fpu__init_cpu_xstate();

	/* Cache size, offset and flags for initialization */
	setup_xstate_cache();

	err = init_xstate_size();
	if (err)
		goto out_disable;

	/* Reset the state for the current task */
	fpstate_reset(&current->thread.fpu);

	/*
	update_regset_xstate_info(fpu_user_cfg.max_size,
				  fpu_user_cfg.max_features);

	setup_init_fpu_buf();

	/*
	if (xfeatures != fpu_kernel_cfg.max_features) {
		pr_err("x86/fpu: xfeatures modified from 0x%016llx to 0x%016llx during init, disabling XSAVE\n",
		       xfeatures, fpu_kernel_cfg.max_features);
		goto out_disable;
	}

	print_xstate_offset_size();
	pr_info("x86/fpu: Enabled xstate features 0x%llx, context size is %d bytes, using '%s' format.\n",
		fpu_kernel_cfg.max_features,
		fpu_kernel_cfg.max_size,
		boot_cpu_has(X86_FEATURE_XCOMPACTED) ? "compacted" : "standard");
	return;

out_disable:
	/* something went wrong, try to boot without any XSAVE support */
	fpu__init_disable_system_xstate(legacy_size);
}

void fpu__resume_cpu(void)
{
	/*
	if (cpu_feature_enabled(X86_FEATURE_XSAVE))
		xsetbv(XCR_XFEATURE_ENABLED_MASK, fpu_user_cfg.max_features);

	/*
	if (cpu_feature_enabled(X86_FEATURE_XSAVES)) {
		wrmsrl(MSR_IA32_XSS, xfeatures_mask_supervisor()  |
				     xfeatures_mask_independent());
	}

	if (fpu_state_size_dynamic())
		wrmsrl(MSR_IA32_XFD, current->thread.fpu.fpstate->xfd);
}

static void *__raw_xsave_addr(struct xregs_state *xsave, int xfeature_nr)
{
	u64 xcomp_bv = xsave->header.xcomp_bv;

	if (WARN_ON_ONCE(!xfeature_enabled(xfeature_nr)))
		return NULL;

	if (cpu_feature_enabled(X86_FEATURE_XCOMPACTED)) {
		if (WARN_ON_ONCE(!(xcomp_bv & BIT_ULL(xfeature_nr))))
			return NULL;
	}

	return (void *)xsave + xfeature_get_offset(xcomp_bv, xfeature_nr);
}

void *get_xsave_addr(struct xregs_state *xsave, int xfeature_nr)
{
	/*
	if (!boot_cpu_has(X86_FEATURE_XSAVE))
		return NULL;

	/*
	if (WARN_ON_ONCE(!xfeature_enabled(xfeature_nr)))
		return NULL;

	/*
	if (!(xsave->header.xfeatures & BIT_ULL(xfeature_nr)))
		return NULL;

	return __raw_xsave_addr(xsave, xfeature_nr);
}

#ifdef CONFIG_ARCH_HAS_PKEYS

int arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
			      unsigned long init_val)
{
	u32 old_pkru, new_pkru_bits = 0;
	int pkey_shift;

	/*
	if (!cpu_feature_enabled(X86_FEATURE_OSPKE))
		return -EINVAL;

	/*
	if (WARN_ON_ONCE(pkey >= arch_max_pkey()))
		return -EINVAL;

	/* Set the bits we need in PKRU:  */
	if (init_val & PKEY_DISABLE_ACCESS)
		new_pkru_bits |= PKRU_AD_BIT;
	if (init_val & PKEY_DISABLE_WRITE)
		new_pkru_bits |= PKRU_WD_BIT;

	/* Shift the bits in to the correct place in PKRU for pkey: */
	pkey_shift = pkey * PKRU_BITS_PER_PKEY;
	new_pkru_bits <<= pkey_shift;

	/* Get old PKRU and mask off any old bits in place: */
	old_pkru = read_pkru();
	old_pkru &= ~((PKRU_AD_BIT|PKRU_WD_BIT) << pkey_shift);

	/* Write old part along with new part: */
	write_pkru(old_pkru | new_pkru_bits);

	return 0;
}
#endif /* ! CONFIG_ARCH_HAS_PKEYS */

static void copy_feature(bool from_xstate, struct membuf *to, void *xstate,
			 void *init_xstate, unsigned int size)
{
	membuf_write(to, from_xstate ? xstate : init_xstate, size);
}

void __copy_xstate_to_uabi_buf(struct membuf to, struct fpstate *fpstate,
			       u32 pkru_val, enum xstate_copy_mode copy_mode)
{
	const unsigned int off_mxcsr = offsetof(struct fxregs_state, mxcsr);
	struct xregs_state *xinit = &init_fpstate.regs.xsave;
	struct xregs_state *xsave = &fpstate->regs.xsave;
	struct xstate_header header;
	unsigned int zerofrom;
	u64 mask;
	int i;

	memset(&header, 0, sizeof(header));
	header.xfeatures = xsave->header.xfeatures;

	/* Mask out the feature bits depending on copy mode */
	switch (copy_mode) {
	case XSTATE_COPY_FP:
		header.xfeatures &= XFEATURE_MASK_FP;
		break;

	case XSTATE_COPY_FX:
		header.xfeatures &= XFEATURE_MASK_FP | XFEATURE_MASK_SSE;
		break;

	case XSTATE_COPY_XSAVE:
		header.xfeatures &= fpstate->user_xfeatures;
		break;
	}

	/* Copy FP state up to MXCSR */
	copy_feature(header.xfeatures & XFEATURE_MASK_FP, &to, &xsave->i387,
		     &xinit->i387, off_mxcsr);

	/* Copy MXCSR when SSE or YMM are set in the feature mask */
	copy_feature(header.xfeatures & (XFEATURE_MASK_SSE | XFEATURE_MASK_YMM),
		     &to, &xsave->i387.mxcsr, &xinit->i387.mxcsr,
		     MXCSR_AND_FLAGS_SIZE);

	/* Copy the remaining FP state */
	copy_feature(header.xfeatures & XFEATURE_MASK_FP,
		     &to, &xsave->i387.st_space, &xinit->i387.st_space,
		     sizeof(xsave->i387.st_space));

	/* Copy the SSE state - shared with YMM, but independently managed */
	copy_feature(header.xfeatures & XFEATURE_MASK_SSE,
		     &to, &xsave->i387.xmm_space, &xinit->i387.xmm_space,
		     sizeof(xsave->i387.xmm_space));

	if (copy_mode != XSTATE_COPY_XSAVE)
		goto out;

	/* Zero the padding area */
	membuf_zero(&to, sizeof(xsave->i387.padding));

	/* Copy xsave->i387.sw_reserved */
	membuf_write(&to, xstate_fx_sw_bytes, sizeof(xsave->i387.sw_reserved));

	/* Copy the user space relevant state of @xsave->header */
	membuf_write(&to, &header, sizeof(header));

	zerofrom = offsetof(struct xregs_state, extended_state_area);

	/*
	mask = fpstate->user_xfeatures;

	for_each_extended_xfeature(i, mask) {
		/*
		if (zerofrom < xstate_offsets[i])
			membuf_zero(&to, xstate_offsets[i] - zerofrom);

		if (i == XFEATURE_PKRU) {
			struct pkru_state pkru = {0};
			/*
			pkru.pkru = pkru_val;
			membuf_write(&to, &pkru, sizeof(pkru));
		} else {
			copy_feature(header.xfeatures & BIT_ULL(i), &to,
				     __raw_xsave_addr(xsave, i),
				     __raw_xsave_addr(xinit, i),
				     xstate_sizes[i]);
		}
		/*
		zerofrom = xstate_offsets[i] + xstate_sizes[i];
	}

out:
	if (to.left)
		membuf_zero(&to, to.left);
}

void copy_xstate_to_uabi_buf(struct membuf to, struct task_struct *tsk,
			     enum xstate_copy_mode copy_mode)
{
	__copy_xstate_to_uabi_buf(to, tsk->thread.fpu.fpstate,
				  tsk->thread.pkru, copy_mode);
}

static int copy_from_buffer(void *dst, unsigned int offset, unsigned int size,
			    const void *kbuf, const void __user *ubuf)
{
	if (kbuf) {
		memcpy(dst, kbuf + offset, size);
	} else {
		if (copy_from_user(dst, ubuf + offset, size))
			return -EFAULT;
	}
	return 0;
}


static int copy_uabi_to_xstate(struct fpstate *fpstate, const void *kbuf,
			       const void __user *ubuf)
{
	struct xregs_state *xsave = &fpstate->regs.xsave;
	unsigned int offset, size;
	struct xstate_header hdr;
	u64 mask;
	int i;

	offset = offsetof(struct xregs_state, header);
	if (copy_from_buffer(&hdr, offset, sizeof(hdr), kbuf, ubuf))
		return -EFAULT;

	if (validate_user_xstate_header(&hdr, fpstate))
		return -EINVAL;

	/* Validate MXCSR when any of the related features is in use */
	mask = XFEATURE_MASK_FP | XFEATURE_MASK_SSE | XFEATURE_MASK_YMM;
	if (hdr.xfeatures & mask) {
		u32 mxcsr[2];

		offset = offsetof(struct fxregs_state, mxcsr);
		if (copy_from_buffer(mxcsr, offset, sizeof(mxcsr), kbuf, ubuf))
			return -EFAULT;

		/* Reserved bits in MXCSR must be zero. */
		if (mxcsr[0] & ~mxcsr_feature_mask)
			return -EINVAL;

		/* SSE and YMM require MXCSR even when FP is not in use. */
		if (!(hdr.xfeatures & XFEATURE_MASK_FP)) {
			xsave->i387.mxcsr = mxcsr[0];
			xsave->i387.mxcsr_mask = mxcsr[1];
		}
	}

	for (i = 0; i < XFEATURE_MAX; i++) {
		mask = BIT_ULL(i);

		if (hdr.xfeatures & mask) {
			void *dst = __raw_xsave_addr(xsave, i);

			offset = xstate_offsets[i];
			size = xstate_sizes[i];

			if (copy_from_buffer(dst, offset, size, kbuf, ubuf))
				return -EFAULT;
		}
	}

	/*
	xsave->header.xfeatures &= XFEATURE_MASK_SUPERVISOR_ALL;

	/*
	xsave->header.xfeatures |= hdr.xfeatures;

	return 0;
}

int copy_uabi_from_kernel_to_xstate(struct fpstate *fpstate, const void *kbuf)
{
	return copy_uabi_to_xstate(fpstate, kbuf, NULL);
}

int copy_sigframe_from_user_to_xstate(struct fpstate *fpstate,
				      const void __user *ubuf)
{
	return copy_uabi_to_xstate(fpstate, NULL, ubuf);
}

static bool validate_independent_components(u64 mask)
{
	u64 xchk;

	if (WARN_ON_FPU(!cpu_feature_enabled(X86_FEATURE_XSAVES)))
		return false;

	xchk = ~xfeatures_mask_independent();

	if (WARN_ON_ONCE(!mask || mask & xchk))
		return false;

	return true;
}

void xsaves(struct xregs_state *xstate, u64 mask)
{
	int err;

	if (!validate_independent_components(mask))
		return;

	XSTATE_OP(XSAVES, xstate, (u32)mask, (u32)(mask >> 32), err);
	WARN_ON_ONCE(err);
}

void xrstors(struct xregs_state *xstate, u64 mask)
{
	int err;

	if (!validate_independent_components(mask))
		return;

	XSTATE_OP(XRSTORS, xstate, (u32)mask, (u32)(mask >> 32), err);
	WARN_ON_ONCE(err);
}

#if IS_ENABLED(CONFIG_KVM)
void fpstate_clear_xstate_component(struct fpstate *fps, unsigned int xfeature)
{
	void *addr = get_xsave_addr(&fps->regs.xsave, xfeature);

	if (addr)
		memset(addr, 0, xstate_sizes[xfeature]);
}
EXPORT_SYMBOL_GPL(fpstate_clear_xstate_component);
#endif

#ifdef CONFIG_X86_64

#ifdef CONFIG_X86_DEBUG_FPU
static bool xstate_op_valid(struct fpstate *fpstate, u64 mask, bool rstor)
{
	u64 xfd = __this_cpu_read(xfd_state);

	if (fpstate->xfd == xfd)
		return true;

	 /*
	if (fpstate->xfd == current->thread.fpu.fpstate->xfd)
		return false;

	/*
	if (fpstate == &init_fpstate)
		return rstor;

	/*

	/*
	mask &= ~xfd;

	/*
	mask &= ~fpstate->xfeatures;

	/*
	return !mask;
}

void xfd_validate_state(struct fpstate *fpstate, u64 mask, bool rstor)
{
	WARN_ON_ONCE(!xstate_op_valid(fpstate, mask, rstor));
}
#endif /* CONFIG_X86_DEBUG_FPU */

static int __init xfd_update_static_branch(void)
{
	/*
	if (init_fpstate.xfd)
		static_branch_enable(&__fpu_state_size_dynamic);
	return 0;
}
arch_initcall(xfd_update_static_branch)

void fpstate_free(struct fpu *fpu)
{
	if (fpu->fpstate && fpu->fpstate != &fpu->__fpstate)
		vfree(fpu->fpstate);
}

static int fpstate_realloc(u64 xfeatures, unsigned int ksize,
			   unsigned int usize, struct fpu_guest *guest_fpu)
{
	struct fpu *fpu = &current->thread.fpu;
	struct fpstate *curfps, *newfps = NULL;
	unsigned int fpsize;
	bool in_use;

	fpsize = ksize + ALIGN(offsetof(struct fpstate, regs), 64);

	newfps = vzalloc(fpsize);
	if (!newfps)
		return -ENOMEM;
	newfps->size = ksize;
	newfps->user_size = usize;
	newfps->is_valloc = true;

	/*
	curfps = guest_fpu ? guest_fpu->fpstate : fpu->fpstate;

	/* Determine whether @curfps is the active fpstate */
	in_use = fpu->fpstate == curfps;

	if (guest_fpu) {
		newfps->is_guest = true;
		newfps->is_confidential = curfps->is_confidential;
		newfps->in_use = curfps->in_use;
		guest_fpu->xfeatures |= xfeatures;
		guest_fpu->uabi_size = usize;
	}

	fpregs_lock();
	/*
	if (in_use && test_thread_flag(TIF_NEED_FPU_LOAD))
		fpregs_restore_userregs();

	newfps->xfeatures = curfps->xfeatures | xfeatures;

	if (!guest_fpu)
		newfps->user_xfeatures = curfps->user_xfeatures | xfeatures;

	newfps->xfd = curfps->xfd & ~xfeatures;

	/* Do the final updates within the locked region */
	xstate_init_xcomp_bv(&newfps->regs.xsave, newfps->xfeatures);

	if (guest_fpu) {
		guest_fpu->fpstate = newfps;
		/* If curfps is active, update the FPU fpstate pointer */
		if (in_use)
			fpu->fpstate = newfps;
	} else {
		fpu->fpstate = newfps;
	}

	if (in_use)
		xfd_update_state(fpu->fpstate);
	fpregs_unlock();

	/* Only free valloc'ed state */
	if (curfps && curfps->is_valloc)
		vfree(curfps);

	return 0;
}

static int validate_sigaltstack(unsigned int usize)
{
	struct task_struct *thread, *leader = current->group_leader;
	unsigned long framesize = get_sigframe_size();

	lockdep_assert_held(&current->sighand->siglock);

	/* get_sigframe_size() is based on fpu_user_cfg.max_size */
	framesize -= fpu_user_cfg.max_size;
	framesize += usize;
	for_each_thread(leader, thread) {
		if (thread->sas_ss_size && thread->sas_ss_size < framesize)
			return -ENOSPC;
	}
	return 0;
}

static int __xstate_request_perm(u64 permitted, u64 requested, bool guest)
{
	/*
	bool compacted = cpu_feature_enabled(X86_FEATURE_XCOMPACTED);
	struct fpu *fpu = &current->group_leader->thread.fpu;
	struct fpu_state_perm *perm;
	unsigned int ksize, usize;
	u64 mask;
	int ret = 0;

	/* Check whether fully enabled */
	if ((permitted & requested) == requested)
		return 0;

	/* Calculate the resulting kernel state size */
	mask = permitted | requested;
	/* Take supervisor states into account on the host */
	if (!guest)
		mask |= xfeatures_mask_supervisor();
	ksize = xstate_calculate_size(mask, compacted);

	/* Calculate the resulting user state size */
	mask &= XFEATURE_MASK_USER_SUPPORTED;
	usize = xstate_calculate_size(mask, false);

	if (!guest) {
		ret = validate_sigaltstack(usize);
		if (ret)
			return ret;
	}

	perm = guest ? &fpu->guest_perm : &fpu->perm;
	/* Pairs with the READ_ONCE() in xstate_get_group_perm() */
	WRITE_ONCE(perm->__state_perm, mask);
	/* Protected by sighand lock */
	perm->__state_size = ksize;
	perm->__user_state_size = usize;
	return ret;
}

static const u64 xstate_prctl_req[XFEATURE_MAX] = {
	[XFEATURE_XTILE_DATA] = XFEATURE_MASK_XTILE_DATA,
};

static int xstate_request_perm(unsigned long idx, bool guest)
{
	u64 permitted, requested;
	int ret;

	if (idx >= XFEATURE_MAX)
		return -EINVAL;

	/*
	idx = array_index_nospec(idx, ARRAY_SIZE(xstate_prctl_req));
	requested = xstate_prctl_req[idx];
	if (!requested)
		return -EOPNOTSUPP;

	if ((fpu_user_cfg.max_features & requested) != requested)
		return -EOPNOTSUPP;

	/* Lockless quick check */
	permitted = xstate_get_group_perm(guest);
	if ((permitted & requested) == requested)
		return 0;

	/* Protect against concurrent modifications */
	spin_lock_irq(&current->sighand->siglock);
	permitted = xstate_get_group_perm(guest);

	/* First vCPU allocation locks the permissions. */
	if (guest && (permitted & FPU_GUEST_PERM_LOCKED))
		ret = -EBUSY;
	else
		ret = __xstate_request_perm(permitted, requested, guest);
	spin_unlock_irq(&current->sighand->siglock);
	return ret;
}

int __xfd_enable_feature(u64 xfd_err, struct fpu_guest *guest_fpu)
{
	u64 xfd_event = xfd_err & XFEATURE_MASK_USER_DYNAMIC;
	struct fpu_state_perm *perm;
	unsigned int ksize, usize;
	struct fpu *fpu;

	if (!xfd_event) {
		if (!guest_fpu)
			pr_err_once("XFD: Invalid xfd error: %016llx\n", xfd_err);
		return 0;
	}

	/* Protect against concurrent modifications */
	spin_lock_irq(&current->sighand->siglock);

	/* If not permitted let it die */
	if ((xstate_get_group_perm(!!guest_fpu) & xfd_event) != xfd_event) {
		spin_unlock_irq(&current->sighand->siglock);
		return -EPERM;
	}

	fpu = &current->group_leader->thread.fpu;
	perm = guest_fpu ? &fpu->guest_perm : &fpu->perm;
	ksize = perm->__state_size;
	usize = perm->__user_state_size;

	/*
	spin_unlock_irq(&current->sighand->siglock);

	/*
	if (fpstate_realloc(xfd_event, ksize, usize, guest_fpu))
		return -EFAULT;
	return 0;
}

int xfd_enable_feature(u64 xfd_err)
{
	return __xfd_enable_feature(xfd_err, NULL);
}

#else /* CONFIG_X86_64 */
static inline int xstate_request_perm(unsigned long idx, bool guest)
{
	return -EPERM;
}
#endif  /* !CONFIG_X86_64 */

u64 xstate_get_guest_group_perm(void)
{
	return xstate_get_group_perm(true);
}
EXPORT_SYMBOL_GPL(xstate_get_guest_group_perm);

long fpu_xstate_prctl(int option, unsigned long arg2)
{
	u64 __user *uptr = (u64 __user *)arg2;
	u64 permitted, supported;
	unsigned long idx = arg2;
	bool guest = false;

	switch (option) {
	case ARCH_GET_XCOMP_SUPP:
		supported = fpu_user_cfg.max_features |	fpu_user_cfg.legacy_features;
		return put_user(supported, uptr);

	case ARCH_GET_XCOMP_PERM:
		/*
		permitted = xstate_get_host_group_perm();
		permitted &= XFEATURE_MASK_USER_SUPPORTED;
		return put_user(permitted, uptr);

	case ARCH_GET_XCOMP_GUEST_PERM:
		permitted = xstate_get_guest_group_perm();
		permitted &= XFEATURE_MASK_USER_SUPPORTED;
		return put_user(permitted, uptr);

	case ARCH_REQ_XCOMP_GUEST_PERM:
		guest = true;
		fallthrough;

	case ARCH_REQ_XCOMP_PERM:
		if (!IS_ENABLED(CONFIG_X86_64))
			return -EOPNOTSUPP;

		return xstate_request_perm(idx, guest);

	default:
		return -EINVAL;
	}
}

#ifdef CONFIG_PROC_PID_ARCH_STATUS
static void avx512_status(struct seq_file *m, struct task_struct *task)
{
	unsigned long timestamp = READ_ONCE(task->thread.fpu.avx512_timestamp);
	long delta;

	if (!timestamp) {
		/*
		delta = -1;
	} else {
		delta = (long)(jiffies - timestamp);
		/*
		if (delta < 0)
			delta = LONG_MAX;
		delta = jiffies_to_msecs(delta);
	}

	seq_put_decimal_ll(m, "AVX512_elapsed_ms:\t", delta);
	seq_putc(m, '\n');
}

int proc_pid_arch_status(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	/*
	if (cpu_feature_enabled(X86_FEATURE_AVX512F))
		avx512_status(m, task);

	return 0;
}
#endif /* CONFIG_PROC_PID_ARCH_STATUS */
