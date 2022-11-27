
#include <asm/fpu/api.h>

static __must_check inline bool may_use_simd(void)
{
	return irq_fpu_usable();
}
