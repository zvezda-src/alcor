
#ifndef BOOT_MSR_H
#define BOOT_MSR_H

#include <asm/shared/msr.h>

static inline void boot_rdmsr(unsigned int reg, struct msr *m)
{
	asm volatile("rdmsr" : "=a" (m->l), "=d" (m->h) : "c" (reg));
}

static inline void boot_wrmsr(unsigned int reg, const struct msr *m)
{
	asm volatile("wrmsr" : : "c" (reg), "a"(m->l), "d" (m->h) : "memory");
}

#endif /* BOOT_MSR_H */
