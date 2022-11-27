#ifndef _ASM_STATIC_CALL_H
#define _ASM_STATIC_CALL_H

#include <asm/text-patching.h>


#define __ARCH_DEFINE_STATIC_CALL_TRAMP(name, insns)			\
	asm(".pushsection .static_call.text, \"ax\"		\n"	\
	    ".align 4						\n"	\
	    ".globl " STATIC_CALL_TRAMP_STR(name) "		\n"	\
	    STATIC_CALL_TRAMP_STR(name) ":			\n"	\
	    ANNOTATE_NOENDBR						\
	    insns "						\n"	\
	    ".byte 0x0f, 0xb9, 0xcc				\n"	\
	    ".type " STATIC_CALL_TRAMP_STR(name) ", @function	\n"	\
	    ".size " STATIC_CALL_TRAMP_STR(name) ", . - " STATIC_CALL_TRAMP_STR(name) " \n" \
	    ".popsection					\n")

#define ARCH_DEFINE_STATIC_CALL_TRAMP(name, func)			\
	__ARCH_DEFINE_STATIC_CALL_TRAMP(name, ".byte 0xe9; .long " #func " - (. + 4)")

#ifdef CONFIG_RETHUNK
#define ARCH_DEFINE_STATIC_CALL_NULL_TRAMP(name)			\
	__ARCH_DEFINE_STATIC_CALL_TRAMP(name, "jmp __x86_return_thunk")
#else
#define ARCH_DEFINE_STATIC_CALL_NULL_TRAMP(name)			\
	__ARCH_DEFINE_STATIC_CALL_TRAMP(name, "ret; int3; nop; nop; nop")
#endif

#define ARCH_DEFINE_STATIC_CALL_RET0_TRAMP(name)			\
	ARCH_DEFINE_STATIC_CALL_TRAMP(name, __static_call_return0)

#define ARCH_ADD_TRAMP_KEY(name)					\
	asm(".pushsection .static_call_tramp_key, \"a\"		\n"	\
	    ".long " STATIC_CALL_TRAMP_STR(name) " - .		\n"	\
	    ".long " STATIC_CALL_KEY_STR(name) " - .		\n"	\
	    ".popsection					\n")

extern bool __static_call_fixup(void *tramp, u8 op, void *dest);

#endif /* _ASM_STATIC_CALL_H */
