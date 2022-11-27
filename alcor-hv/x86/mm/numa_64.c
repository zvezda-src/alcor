#include <linux/memblock.h>

#include "numa_internal.h"

void __init initmem_init(void)
{
	x86_numa_init();
}
