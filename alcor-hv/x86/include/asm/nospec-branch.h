
#ifndef _ASM_X86_NOSPEC_BRANCH_H_
#define _ASM_X86_NOSPEC_BRANCH_H_

#include <linux/static_key.h>
#include <linux/objtool.h>
#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/cpufeatures.h>
#include <asm/msr-index.h>
#include <asm/unwind_hints.h>
#include <asm/percpu.h>

#define RETPOLINE_THUNK_SIZE	32


#define RSB_CLEAR_LOOPS		32	/* To forcibly overwrite all entries */

#define __FILL_RETURN_BUFFER(reg, nr, sp)	\
	mov	$(nr/2), reg;			\
771:						\
	ANNOTATE_INTRA_FUNCTION_CALL;		\
	call	772f;				\
773:	/* speculation trap */			\
	UNWIND_HINT_EMPTY;			\
	pause;					\
	lfence;					\
	jmp	773b;				\
772:						\
	ANNOTATE_INTRA_FUNCTION_CALL;		\
	call	774f;				\
775:	/* speculation trap */			\
	UNWIND_HINT_EMPTY;			\
	pause;					\
	lfence;					\
	jmp	775b;				\
774:						\
	add	$(BITS_PER_LONG/8) * 2, sp;	\
	dec	reg;				\
	jnz	771b;

#ifdef __ASSEMBLY__

.macro ANNOTATE_RETPOLINE_SAFE
	.Lannotate_\@:
	.pushsection .discard.retpoline_safe
	_ASM_PTR .Lannotate_\@
	.popsection
.endm

#define ANNOTATE_UNRET_SAFE ANNOTATE_RETPOLINE_SAFE

.macro ANNOTATE_UNRET_END
#ifdef CONFIG_DEBUG_ENTRY
	ANNOTATE_RETPOLINE_SAFE
	nop
#endif
.endm

.macro __CS_PREFIX reg:req
	.irp rs,r8,r9,r10,r11,r12,r13,r14,r15
	.ifc \reg,\rs
	.byte 0x2e
	.endif
	.endr
.endm

.macro JMP_NOSPEC reg:req
#ifdef CONFIG_RETPOLINE
	__CS_PREFIX \reg
	jmp	__x86_indirect_thunk_\reg
#else
	jmp	*%\reg
	int3
#endif
.endm

.macro CALL_NOSPEC reg:req
#ifdef CONFIG_RETPOLINE
	__CS_PREFIX \reg
	call	__x86_indirect_thunk_\reg
#else
	call	*%\reg
#endif
.endm

 /*
.macro FILL_RETURN_BUFFER reg:req nr:req ftr:req
	ALTERNATIVE "jmp .Lskip_rsb_\@", "", \ftr
	__FILL_RETURN_BUFFER(\reg,\nr,%_ASM_SP)
.Lskip_rsb_\@:
.endm

#ifdef CONFIG_CPU_UNRET_ENTRY
#define CALL_ZEN_UNTRAIN_RET	"call zen_untrain_ret"
#else
#define CALL_ZEN_UNTRAIN_RET	""
#endif

.macro UNTRAIN_RET
#if defined(CONFIG_CPU_UNRET_ENTRY) || defined(CONFIG_CPU_IBPB_ENTRY)
	ANNOTATE_UNRET_END
	ALTERNATIVE_2 "",						\
	              CALL_ZEN_UNTRAIN_RET, X86_FEATURE_UNRET,		\
		      "call entry_ibpb", X86_FEATURE_ENTRY_IBPB
#endif
.endm

#else /* __ASSEMBLY__ */

#define ANNOTATE_RETPOLINE_SAFE					\
	"999:\n\t"						\
	".pushsection .discard.retpoline_safe\n\t"		\
	_ASM_PTR " 999b\n\t"					\
	".popsection\n\t"

typedef u8 retpoline_thunk_t[RETPOLINE_THUNK_SIZE];
extern retpoline_thunk_t __x86_indirect_thunk_array[];

extern void __x86_return_thunk(void);
extern void zen_untrain_ret(void);
extern void entry_ibpb(void);

#ifdef CONFIG_RETPOLINE

#define GEN(reg) \
	extern retpoline_thunk_t __x86_indirect_thunk_ ## reg;
#include <asm/GEN-for-each-reg.h>
#undef GEN

#ifdef CONFIG_X86_64

# define CALL_NOSPEC						\
	ALTERNATIVE_2(						\
	ANNOTATE_RETPOLINE_SAFE					\
	"call *%[thunk_target]\n",				\
	"call __x86_indirect_thunk_%V[thunk_target]\n",		\
	X86_FEATURE_RETPOLINE,					\
	"lfence;\n"						\
	ANNOTATE_RETPOLINE_SAFE					\
	"call *%[thunk_target]\n",				\
	X86_FEATURE_RETPOLINE_LFENCE)

# define THUNK_TARGET(addr) [thunk_target] "r" (addr)

#else /* CONFIG_X86_32 */
# define CALL_NOSPEC						\
	ALTERNATIVE_2(						\
	ANNOTATE_RETPOLINE_SAFE					\
	"call *%[thunk_target]\n",				\
	"       jmp    904f;\n"					\
	"       .align 16\n"					\
	"901:	call   903f;\n"					\
	"902:	pause;\n"					\
	"    	lfence;\n"					\
	"       jmp    902b;\n"					\
	"       .align 16\n"					\
	"903:	lea    4(%%esp), %%esp;\n"			\
	"       pushl  %[thunk_target];\n"			\
	"       ret;\n"						\
	"       .align 16\n"					\
	"904:	call   901b;\n",				\
	X86_FEATURE_RETPOLINE,					\
	"lfence;\n"						\
	ANNOTATE_RETPOLINE_SAFE					\
	"call *%[thunk_target]\n",				\
	X86_FEATURE_RETPOLINE_LFENCE)

# define THUNK_TARGET(addr) [thunk_target] "rm" (addr)
#endif
#else /* No retpoline for C / inline asm */
# define CALL_NOSPEC "call *%[thunk_target]\n"
# define THUNK_TARGET(addr) [thunk_target] "rm" (addr)
#endif

enum spectre_v2_mitigation {
	SPECTRE_V2_NONE,
	SPECTRE_V2_RETPOLINE,
	SPECTRE_V2_LFENCE,
	SPECTRE_V2_EIBRS,
	SPECTRE_V2_EIBRS_RETPOLINE,
	SPECTRE_V2_EIBRS_LFENCE,
	SPECTRE_V2_IBRS,
};

enum spectre_v2_user_mitigation {
	SPECTRE_V2_USER_NONE,
	SPECTRE_V2_USER_STRICT,
	SPECTRE_V2_USER_STRICT_PREFERRED,
	SPECTRE_V2_USER_PRCTL,
	SPECTRE_V2_USER_SECCOMP,
};

enum ssb_mitigation {
	SPEC_STORE_BYPASS_NONE,
	SPEC_STORE_BYPASS_DISABLE,
	SPEC_STORE_BYPASS_PRCTL,
	SPEC_STORE_BYPASS_SECCOMP,
};

extern char __indirect_thunk_start[];
extern char __indirect_thunk_end[];

static __always_inline
void alternative_msr_write(unsigned int msr, u64 val, unsigned int feature)
{
	asm volatile(ALTERNATIVE("", "wrmsr", %c[feature])
		: : "c" (msr),
		    "a" ((u32)val),
		    "d" ((u32)(val >> 32)),
		    [feature] "i" (feature)
		: "memory");
}

static inline void indirect_branch_prediction_barrier(void)
{
	u64 val = PRED_CMD_IBPB;

	alternative_msr_write(MSR_IA32_PRED_CMD, val, X86_FEATURE_USE_IBPB);
}

extern u64 x86_spec_ctrl_base;
DECLARE_PER_CPU(u64, x86_spec_ctrl_current);
extern void write_spec_ctrl_current(u64 val, bool force);
extern u64 spec_ctrl_current(void);

#define firmware_restrict_branch_speculation_start()			\
do {									\
	preempt_disable();						\
	alternative_msr_write(MSR_IA32_SPEC_CTRL,			\
			      spec_ctrl_current() | SPEC_CTRL_IBRS,	\
			      X86_FEATURE_USE_IBRS_FW);			\
	alternative_msr_write(MSR_IA32_PRED_CMD, PRED_CMD_IBPB,		\
			      X86_FEATURE_USE_IBPB_FW);			\
} while (0)

#define firmware_restrict_branch_speculation_end()			\
do {									\
	alternative_msr_write(MSR_IA32_SPEC_CTRL,			\
			      spec_ctrl_current(),			\
			      X86_FEATURE_USE_IBRS_FW);			\
	preempt_enable();						\
} while (0)

DECLARE_STATIC_KEY_FALSE(switch_to_cond_stibp);
DECLARE_STATIC_KEY_FALSE(switch_mm_cond_ibpb);
DECLARE_STATIC_KEY_FALSE(switch_mm_always_ibpb);

DECLARE_STATIC_KEY_FALSE(mds_user_clear);
DECLARE_STATIC_KEY_FALSE(mds_idle_clear);

DECLARE_STATIC_KEY_FALSE(switch_mm_cond_l1d_flush);

DECLARE_STATIC_KEY_FALSE(mmio_stale_data_clear);

#include <asm/segment.h>

static __always_inline void mds_clear_cpu_buffers(void)
{
	static const u16 ds = __KERNEL_DS;

	/*
	asm volatile("verw %[ds]" : : [ds] "m" (ds) : "cc");
}

static __always_inline void mds_user_clear_cpu_buffers(void)
{
	if (static_branch_likely(&mds_user_clear))
		mds_clear_cpu_buffers();
}

static inline void mds_idle_clear_cpu_buffers(void)
{
	if (static_branch_likely(&mds_idle_clear))
		mds_clear_cpu_buffers();
}

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_NOSPEC_BRANCH_H_ */
