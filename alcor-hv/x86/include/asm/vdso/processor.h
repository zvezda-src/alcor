#ifndef __ASM_VDSO_PROCESSOR_H
#define __ASM_VDSO_PROCESSOR_H

#ifndef __ASSEMBLY__

static __always_inline void rep_nop(void)
{
	asm volatile("rep; nop" ::: "memory");
}

static __always_inline void cpu_relax(void)
{
	rep_nop();
}

#endif /* __ASSEMBLY__ */

#endif /* __ASM_VDSO_PROCESSOR_H */
