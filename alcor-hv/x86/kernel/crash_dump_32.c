
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/crash_dump.h>
#include <linux/uio.h>

static inline bool is_crashed_pfn_valid(unsigned long pfn)
{
#ifndef CONFIG_X86_PAE
	/*
	return pte_pfn(pfn_pte(pfn, __pgprot(0))) == pfn;
#else
	return true;
#endif
}

ssize_t copy_oldmem_page(struct iov_iter *iter, unsigned long pfn, size_t csize,
			 unsigned long offset)
{
	void  *vaddr;

	if (!csize)
		return 0;

	if (!is_crashed_pfn_valid(pfn))
		return -EFAULT;

	vaddr = kmap_local_pfn(pfn);
	csize = copy_to_iter(vaddr + offset, csize, iter);
	kunmap_local(vaddr);

	return csize;
}
