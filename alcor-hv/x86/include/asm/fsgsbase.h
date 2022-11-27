#ifndef _ASM_FSGSBASE_H
#define _ASM_FSGSBASE_H

#ifndef __ASSEMBLY__

#ifdef CONFIG_X86_64

#include <asm/msr-index.h>

extern unsigned long x86_fsbase_read_task(struct task_struct *task);
extern unsigned long x86_gsbase_read_task(struct task_struct *task);
extern void x86_fsbase_write_task(struct task_struct *task, unsigned long fsbase);
extern void x86_gsbase_write_task(struct task_struct *task, unsigned long gsbase);


static __always_inline unsigned long rdfsbase(void)
{
	unsigned long fsbase;

	asm volatile("rdfsbase %0" : "=r" (fsbase) :: "memory");

	return fsbase;
}

static __always_inline unsigned long rdgsbase(void)
{
	unsigned long gsbase;

	asm volatile("rdgsbase %0" : "=r" (gsbase) :: "memory");

	return gsbase;
}

static __always_inline void wrfsbase(unsigned long fsbase)
{
	asm volatile("wrfsbase %0" :: "r" (fsbase) : "memory");
}

static __always_inline void wrgsbase(unsigned long gsbase)
{
	asm volatile("wrgsbase %0" :: "r" (gsbase) : "memory");
}

#include <asm/cpufeature.h>


static inline unsigned long x86_fsbase_read_cpu(void)
{
	unsigned long fsbase;

	if (boot_cpu_has(X86_FEATURE_FSGSBASE))
		fsbase = rdfsbase();
	else
		rdmsrl(MSR_FS_BASE, fsbase);

	return fsbase;
}

static inline void x86_fsbase_write_cpu(unsigned long fsbase)
{
	if (boot_cpu_has(X86_FEATURE_FSGSBASE))
		wrfsbase(fsbase);
	else
		wrmsrl(MSR_FS_BASE, fsbase);
}

extern unsigned long x86_gsbase_read_cpu_inactive(void);
extern void x86_gsbase_write_cpu_inactive(unsigned long gsbase);
extern unsigned long x86_fsgsbase_read_task(struct task_struct *task,
					    unsigned short selector);

#endif /* CONFIG_X86_64 */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_FSGSBASE_H */
