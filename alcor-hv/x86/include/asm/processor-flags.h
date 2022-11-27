#ifndef _ASM_X86_PROCESSOR_FLAGS_H
#define _ASM_X86_PROCESSOR_FLAGS_H

#include <uapi/asm/processor-flags.h>
#include <linux/mem_encrypt.h>

#ifdef CONFIG_VM86
#define X86_VM_MASK	X86_EFLAGS_VM
#else
#define X86_VM_MASK	0 /* No VM86 support */
#endif

#ifdef CONFIG_X86_64
#define CR3_ADDR_MASK	__sme_clr(0x7FFFFFFFFFFFF000ull)
#define CR3_PCID_MASK	0xFFFull
#define CR3_NOFLUSH	BIT_ULL(63)

#else
#define CR3_ADDR_MASK	0xFFFFFFFFull
#define CR3_PCID_MASK	0ull
#define CR3_NOFLUSH	0
#endif

#ifdef CONFIG_PAGE_TABLE_ISOLATION
# define X86_CR3_PTI_PCID_USER_BIT	11
#endif

#endif /* _ASM_X86_PROCESSOR_FLAGS_H */
