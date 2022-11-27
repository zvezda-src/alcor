#ifndef __ASM_X86_XSAVE_H
#define __ASM_X86_XSAVE_H

#include <linux/uaccess.h>
#include <linux/types.h>

#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/user.h>

#define XFEATURE_MASK_EXTEND	(~(XFEATURE_MASK_FPSSE | (1ULL << 63)))

#define XSTATE_CPUID		0x0000000d

#define TILE_CPUID		0x0000001d

#define FXSAVE_SIZE	512

#define XSAVE_HDR_SIZE	    64
#define XSAVE_HDR_OFFSET    FXSAVE_SIZE

#define XSAVE_YMM_SIZE	    256
#define XSAVE_YMM_OFFSET    (XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET)

#define XSAVE_ALIGNMENT     64

#define XFEATURE_MASK_USER_SUPPORTED (XFEATURE_MASK_FP | \
				      XFEATURE_MASK_SSE | \
				      XFEATURE_MASK_YMM | \
				      XFEATURE_MASK_OPMASK | \
				      XFEATURE_MASK_ZMM_Hi256 | \
				      XFEATURE_MASK_Hi16_ZMM	 | \
				      XFEATURE_MASK_PKRU | \
				      XFEATURE_MASK_BNDREGS | \
				      XFEATURE_MASK_BNDCSR | \
				      XFEATURE_MASK_XTILE)

#define XFEATURE_MASK_USER_RESTORE	\
	(XFEATURE_MASK_USER_SUPPORTED & ~XFEATURE_MASK_PKRU)

#define XFEATURE_MASK_USER_DYNAMIC	XFEATURE_MASK_XTILE_DATA

#define XFEATURE_MASK_SUPERVISOR_SUPPORTED (XFEATURE_MASK_PASID)

#define XFEATURE_MASK_INDEPENDENT (XFEATURE_MASK_LBR)

#define XFEATURE_MASK_SUPERVISOR_UNSUPPORTED (XFEATURE_MASK_PT)

#define XFEATURE_MASK_SUPERVISOR_ALL (XFEATURE_MASK_SUPERVISOR_SUPPORTED | \
				      XFEATURE_MASK_INDEPENDENT | \
				      XFEATURE_MASK_SUPERVISOR_UNSUPPORTED)

#define XFEATURE_MASK_FPSTATE	(XFEATURE_MASK_USER_RESTORE | \
				 XFEATURE_MASK_SUPERVISOR_SUPPORTED)

#define XFEATURE_MASK_SIGFRAME_INITOPT	(XFEATURE_MASK_XTILE | \
					 XFEATURE_MASK_USER_DYNAMIC)

extern u64 xstate_fx_sw_bytes[USER_XSTATE_FX_SW_WORDS];

extern void __init update_regset_xstate_info(unsigned int size,
					     u64 xstate_mask);

int xfeature_size(int xfeature_nr);

void xsaves(struct xregs_state *xsave, u64 mask);
void xrstors(struct xregs_state *xsave, u64 mask);

int xfd_enable_feature(u64 xfd_err);

#ifdef CONFIG_X86_64
DECLARE_STATIC_KEY_FALSE(__fpu_state_size_dynamic);
#endif

#ifdef CONFIG_X86_64
DECLARE_STATIC_KEY_FALSE(__fpu_state_size_dynamic);

static __always_inline __pure bool fpu_state_size_dynamic(void)
{
	return static_branch_unlikely(&__fpu_state_size_dynamic);
}
#else
static __always_inline __pure bool fpu_state_size_dynamic(void)
{
	return false;
}
#endif

#endif
