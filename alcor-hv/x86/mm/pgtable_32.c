#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/nmi.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>

#include <asm/cpu_entry_area.h>
#include <asm/fixmap.h>
#include <asm/e820/api.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/io.h>
#include <linux/vmalloc.h>

unsigned int __VMALLOC_RESERVE = 128 << 20;

	/*
	flush_tlb_one_kernel(vaddr);
}

unsigned long __FIXADDR_TOP = 0xfffff000;
EXPORT_SYMBOL(__FIXADDR_TOP);

static int __init parse_vmalloc(char *arg)
{
	if (!arg)
		return -EINVAL;

	/* Add VMALLOC_OFFSET to the parsed value due to vm area guard hole*/
	__VMALLOC_RESERVE = memparse(arg, &arg) + VMALLOC_OFFSET;
	return 0;
}
early_param("vmalloc", parse_vmalloc);

static int __init parse_reservetop(char *arg)
{
	unsigned long address;

	if (!arg)
		return -EINVAL;

	address = memparse(arg, &arg);
	reserve_top_address(address);
	early_ioremap_init();
	return 0;
}
early_param("reservetop", parse_reservetop);
