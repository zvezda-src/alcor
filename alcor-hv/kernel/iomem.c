#include <linux/device.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/mm.h>

#ifndef ioremap_cache
__weak void __iomem *ioremap_cache(resource_size_t offset, unsigned long size)
{
	return ioremap(offset, size);
}
#endif

#ifndef arch_memremap_wb
static void *arch_memremap_wb(resource_size_t offset, unsigned long size)
{
	return (__force void *)ioremap_cache(offset, size);
}
#endif

#ifndef arch_memremap_can_ram_remap
static bool arch_memremap_can_ram_remap(resource_size_t offset, size_t size,
					unsigned long flags)
{
	return true;
}
#endif

static void *try_ram_remap(resource_size_t offset, size_t size,
			   unsigned long flags)
{
	unsigned long pfn = PHYS_PFN(offset);

	/* In the simple case just return the existing linear address */
	if (pfn_valid(pfn) && !PageHighMem(pfn_to_page(pfn)) &&
	    arch_memremap_can_ram_remap(offset, size, flags))
		return __va(offset);

	return NULL; /* fallback to arch_memremap_wb */
}

void *memremap(resource_size_t offset, size_t size, unsigned long flags)
{
	int is_ram = region_intersects(offset, size,
				       IORESOURCE_SYSTEM_RAM, IORES_DESC_NONE);
	void *addr = NULL;

	if (!flags)
		return NULL;

	if (is_ram == REGION_MIXED) {
		WARN_ONCE(1, "memremap attempted on mixed range %pa size: %#lx\n",
				&offset, (unsigned long) size);
		return NULL;
	}

	/* Try all mapping types requested until one returns non-NULL */
	if (flags & MEMREMAP_WB) {
		/*
		if (is_ram == REGION_INTERSECTS)
			addr = try_ram_remap(offset, size, flags);
		if (!addr)
			addr = arch_memremap_wb(offset, size);
	}

	/*
	if (!addr && is_ram == REGION_INTERSECTS && flags != MEMREMAP_WB) {
		WARN_ONCE(1, "memremap attempted on ram %pa size: %#lx\n",
				&offset, (unsigned long) size);
		return NULL;
	}

	if (!addr && (flags & MEMREMAP_WT))
		addr = ioremap_wt(offset, size);

	if (!addr && (flags & MEMREMAP_WC))
		addr = ioremap_wc(offset, size);

	return addr;
}
EXPORT_SYMBOL(memremap);

void memunmap(void *addr)
{
	if (is_ioremap_addr(addr))
		iounmap((void __iomem *) addr);
}
EXPORT_SYMBOL(memunmap);

static void devm_memremap_release(struct device *dev, void *res)
{
	memunmap(*(void **)res);
}

static int devm_memremap_match(struct device *dev, void *res, void *match_data)
{
	return *(void **)res == match_data;
}

void *devm_memremap(struct device *dev, resource_size_t offset,
		size_t size, unsigned long flags)
{
	void **ptr, *addr;

	ptr = devres_alloc_node(devm_memremap_release, sizeof(*ptr), GFP_KERNEL,
			dev_to_node(dev));
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	addr = memremap(offset, size, flags);
	if (addr) {
		*ptr = addr;
		devres_add(dev, ptr);
	} else {
		devres_free(ptr);
		return ERR_PTR(-ENXIO);
	}

	return addr;
}
EXPORT_SYMBOL(devm_memremap);

void devm_memunmap(struct device *dev, void *addr)
{
	WARN_ON(devres_release(dev, devm_memremap_release,
				devm_memremap_match, addr));
}
EXPORT_SYMBOL(devm_memunmap);
