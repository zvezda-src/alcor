#ifndef _ASM_X86_USER_H
#define _ASM_X86_USER_H

#ifdef CONFIG_X86_32
# include <asm/user_32.h>
#else
# include <asm/user_64.h>
#endif

#include <asm/types.h>

struct user_ymmh_regs {
	/* 16 * 16 bytes for each YMMH-reg */
	__u32 ymmh_space[64];
};

struct user_xstate_header {
	__u64 xfeatures;
	__u64 reserved1[2];
	__u64 reserved2[5];
};

#define USER_XSTATE_FX_SW_WORDS 6
#define USER_XSTATE_XCR0_WORD	0

struct user_xstateregs {
	struct {
		__u64 fpx_space[58];
		__u64 xstate_fx_sw[USER_XSTATE_FX_SW_WORDS];
	} i387;
	struct user_xstate_header header;
	struct user_ymmh_regs ymmh;
	/* further processor state extensions go here */
};

#endif /* _ASM_X86_USER_H */
