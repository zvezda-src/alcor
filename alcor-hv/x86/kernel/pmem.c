#include <linux/platform_device.h>
#include <linux/init.h>
#include <linux/ioport.h>

static int found(struct resource *res, void *data)
{
	return 1;
}

static __init int register_e820_pmem(void)
{
	struct platform_device *pdev;
	int rc;

	rc = walk_iomem_res_desc(IORES_DESC_PERSISTENT_MEMORY_LEGACY,
				 IORESOURCE_MEM, 0, -1, NULL, found);
	if (rc <= 0)
		return 0;

	/*
	pdev = platform_device_alloc("e820_pmem", -1);

	rc = platform_device_add(pdev);
	if (rc)
		platform_device_put(pdev);

	return rc;
}
device_initcall(register_e820_pmem);
