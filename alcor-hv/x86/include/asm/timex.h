#ifndef _ASM_X86_TIMEX_H
#define _ASM_X86_TIMEX_H

#include <asm/processor.h>
#include <asm/tsc.h>

static inline unsigned long random_get_entropy(void)
{
	if (!IS_ENABLED(CONFIG_X86_TSC) &&
	    !cpu_feature_enabled(X86_FEATURE_TSC))
		return random_get_entropy_fallback();
	return rdtsc();
}
#define random_get_entropy random_get_entropy

#define CLOCK_TICK_RATE		PIT_TICK_RATE

#define ARCH_HAS_READ_CURRENT_TIMER

#endif /* _ASM_X86_TIMEX_H */
