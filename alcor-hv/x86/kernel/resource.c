#include <linux/ioport.h>
#include <linux/printk.h>
#include <asm/e820/api.h>
#include <asm/pci_x86.h>

static void resource_clip(struct resource *res, resource_size_t start,
			  resource_size_t end)
{
	resource_size_t low = 0, high = 0;

	if (res->end < start || res->start > end)
		return;		/* no conflict */

	if (res->start < start)
		low = start - res->start;

	if (res->end > end)
		high = res->end - end;

	/* Keep the area above or below the conflict, whichever is larger */
	if (low > high)
		res->end = start - 1;
	else
		res->start = end + 1;
}

static void remove_e820_regions(struct resource *avail)
{
	int i;
	struct e820_entry *entry;
	u64 e820_start, e820_end;
	struct resource orig = *avail;

	if (!pci_use_e820)
		return;

	for (i = 0; i < e820_table->nr_entries; i++) {
		entry = &e820_table->entries[i];
		e820_start = entry->addr;
		e820_end = entry->addr + entry->size - 1;

		resource_clip(avail, e820_start, e820_end);
		if (orig.start != avail->start || orig.end != avail->end) {
			pr_info("clipped %pR to %pR for e820 entry [mem %#010Lx-%#010Lx]\n",
				 &orig, avail, e820_start, e820_end);
			orig = *avail;
		}
	}
}

void arch_remove_reservations(struct resource *avail)
{
	/*
	if (avail->flags & IORESOURCE_MEM) {
		resource_clip(avail, BIOS_ROM_BASE, BIOS_ROM_END);

		remove_e820_regions(avail);
	}
}
