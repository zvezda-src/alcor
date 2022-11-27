
#define __GENERATING_BOUNDS_H
#include <linux/page-flags.h>
#include <linux/mmzone.h>
#include <linux/kbuild.h>
#include <linux/log2.h>
#include <linux/spinlock_types.h>

int main(void)
{
	/* The enum constants to put into include/generated/bounds.h */
	DEFINE(NR_PAGEFLAGS, __NR_PAGEFLAGS);
	DEFINE(MAX_NR_ZONES, __MAX_NR_ZONES);
#ifdef CONFIG_SMP
	DEFINE(NR_CPUS_BITS, ilog2(CONFIG_NR_CPUS));
#endif
	DEFINE(SPINLOCK_SIZE, sizeof(spinlock_t));
	/* End of constants */

	return 0;
}
