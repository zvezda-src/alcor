
#include <linux/uaccess.h>
#include <linux/kernel.h>

#ifdef CONFIG_X86_64
bool copy_from_kernel_nofault_allowed(const void *unsafe_src, size_t size)
{
	unsigned long vaddr = (unsigned long)unsafe_src;

	/*
	return vaddr >= TASK_SIZE_MAX + PAGE_SIZE &&
	       __is_canonical_address(vaddr, boot_cpu_data.x86_virt_bits);
}
#else
bool copy_from_kernel_nofault_allowed(const void *unsafe_src, size_t size)
{
	return (unsigned long)unsafe_src >= TASK_SIZE_MAX;
}
#endif
