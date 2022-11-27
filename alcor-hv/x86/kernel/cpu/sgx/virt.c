
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <asm/sgx.h>
#include <uapi/asm/sgx.h>

#include "encls.h"
#include "sgx.h"

struct sgx_vepc {
	struct xarray page_array;
	struct mutex lock;
};

static struct mutex zombie_secs_pages_lock;
static struct list_head zombie_secs_pages;

static int __sgx_vepc_fault(struct sgx_vepc *vepc,
			    struct vm_area_struct *vma, unsigned long addr)
{
	struct sgx_epc_page *epc_page;
	unsigned long index, pfn;
	int ret;

	WARN_ON(!mutex_is_locked(&vepc->lock));

	/* Calculate index of EPC page in virtual EPC's page_array */
	index = vma->vm_pgoff + PFN_DOWN(addr - vma->vm_start);

	epc_page = xa_load(&vepc->page_array, index);
	if (epc_page)
		return 0;

	epc_page = sgx_alloc_epc_page(vepc, false);
	if (IS_ERR(epc_page))
		return PTR_ERR(epc_page);

	ret = xa_err(xa_store(&vepc->page_array, index, epc_page, GFP_KERNEL));
	if (ret)
		goto err_free;

	pfn = PFN_DOWN(sgx_get_epc_phys_addr(epc_page));

	ret = vmf_insert_pfn(vma, addr, pfn);
	if (ret != VM_FAULT_NOPAGE) {
		ret = -EFAULT;
		goto err_delete;
	}

	return 0;

err_delete:
	xa_erase(&vepc->page_array, index);
err_free:
	sgx_free_epc_page(epc_page);
	return ret;
}

static vm_fault_t sgx_vepc_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_vepc *vepc = vma->vm_private_data;
	int ret;

	mutex_lock(&vepc->lock);
	ret = __sgx_vepc_fault(vepc, vma, vmf->address);
	mutex_unlock(&vepc->lock);

	if (!ret)
		return VM_FAULT_NOPAGE;

	if (ret == -EBUSY && (vmf->flags & FAULT_FLAG_ALLOW_RETRY)) {
		mmap_read_unlock(vma->vm_mm);
		return VM_FAULT_RETRY;
	}

	return VM_FAULT_SIGBUS;
}

static const struct vm_operations_struct sgx_vepc_vm_ops = {
	.fault = sgx_vepc_fault,
};

static int sgx_vepc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sgx_vepc *vepc = file->private_data;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	vma->vm_ops = &sgx_vepc_vm_ops;
	/* Don't copy VMA in fork() */
	vma->vm_flags |= VM_PFNMAP | VM_IO | VM_DONTDUMP | VM_DONTCOPY;
	vma->vm_private_data = vepc;

	return 0;
}

static int sgx_vepc_remove_page(struct sgx_epc_page *epc_page)
{
	/*
	return __eremove(sgx_get_epc_virt_addr(epc_page));
}

static int sgx_vepc_free_page(struct sgx_epc_page *epc_page)
{
	int ret = sgx_vepc_remove_page(epc_page);
	if (ret) {
		/*
		WARN_ONCE(ret != SGX_CHILD_PRESENT, EREMOVE_ERROR_MESSAGE,
			  ret, ret);
		return ret;
	}

	sgx_free_epc_page(epc_page);
	return 0;
}

static long sgx_vepc_remove_all(struct sgx_vepc *vepc)
{
	struct sgx_epc_page *entry;
	unsigned long index;
	long failures = 0;

	xa_for_each(&vepc->page_array, index, entry) {
		int ret = sgx_vepc_remove_page(entry);
		if (ret) {
			if (ret == SGX_CHILD_PRESENT) {
				/* The page is a SECS, userspace will retry.  */
				failures++;
			} else {
				/*
				WARN_ON_ONCE(encls_faulted(ret) &&
					     ENCLS_TRAPNR(ret) != X86_TRAP_GP);
				return -EBUSY;
			}
		}
		cond_resched();
	}

	/*
	return failures;
}

static int sgx_vepc_release(struct inode *inode, struct file *file)
{
	struct sgx_vepc *vepc = file->private_data;
	struct sgx_epc_page *epc_page, *tmp, *entry;
	unsigned long index;

	LIST_HEAD(secs_pages);

	xa_for_each(&vepc->page_array, index, entry) {
		/*
		if (sgx_vepc_free_page(entry))
			continue;

		xa_erase(&vepc->page_array, index);
	}

	/*
	xa_for_each(&vepc->page_array, index, entry) {
		epc_page = entry;
		/*
		if (sgx_vepc_free_page(epc_page))
			list_add_tail(&epc_page->list, &secs_pages);

		xa_erase(&vepc->page_array, index);
	}

	/*
	mutex_lock(&zombie_secs_pages_lock);
	list_for_each_entry_safe(epc_page, tmp, &zombie_secs_pages, list) {
		/*
		list_del(&epc_page->list);

		if (sgx_vepc_free_page(epc_page))
			list_add_tail(&epc_page->list, &secs_pages);
	}

	if (!list_empty(&secs_pages))
		list_splice_tail(&secs_pages, &zombie_secs_pages);
	mutex_unlock(&zombie_secs_pages_lock);

	xa_destroy(&vepc->page_array);
	kfree(vepc);

	return 0;
}

static int sgx_vepc_open(struct inode *inode, struct file *file)
{
	struct sgx_vepc *vepc;

	vepc = kzalloc(sizeof(struct sgx_vepc), GFP_KERNEL);
	if (!vepc)
		return -ENOMEM;
	mutex_init(&vepc->lock);
	xa_init(&vepc->page_array);

	file->private_data = vepc;

	return 0;
}

static long sgx_vepc_ioctl(struct file *file,
			   unsigned int cmd, unsigned long arg)
{
	struct sgx_vepc *vepc = file->private_data;

	switch (cmd) {
	case SGX_IOC_VEPC_REMOVE_ALL:
		if (arg)
			return -EINVAL;
		return sgx_vepc_remove_all(vepc);

	default:
		return -ENOTTY;
	}
}

static const struct file_operations sgx_vepc_fops = {
	.owner		= THIS_MODULE,
	.open		= sgx_vepc_open,
	.unlocked_ioctl	= sgx_vepc_ioctl,
	.compat_ioctl	= sgx_vepc_ioctl,
	.release	= sgx_vepc_release,
	.mmap		= sgx_vepc_mmap,
};

static struct miscdevice sgx_vepc_dev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "sgx_vepc",
	.nodename	= "sgx_vepc",
	.fops		= &sgx_vepc_fops,
};

int __init sgx_vepc_init(void)
{
	/* SGX virtualization requires KVM to work */
	if (!cpu_feature_enabled(X86_FEATURE_VMX))
		return -ENODEV;

	INIT_LIST_HEAD(&zombie_secs_pages);
	mutex_init(&zombie_secs_pages_lock);

	return misc_register(&sgx_vepc_dev);
}

int sgx_virt_ecreate(struct sgx_pageinfo *pageinfo, void __user *secs,
		     int *trapnr)
{
	int ret;

	/*
	if (WARN_ON_ONCE(!access_ok(secs, PAGE_SIZE)))
		return -EINVAL;

	__uaccess_begin();
	ret = __ecreate(pageinfo, (void *)secs);
	__uaccess_end();

	if (encls_faulted(ret)) {
		*trapnr = ENCLS_TRAPNR(ret);
		return -EFAULT;
	}

	/* ECREATE doesn't return an error code, it faults or succeeds. */
	WARN_ON_ONCE(ret);
	return 0;
}
EXPORT_SYMBOL_GPL(sgx_virt_ecreate);

static int __sgx_virt_einit(void __user *sigstruct, void __user *token,
			    void __user *secs)
{
	int ret;

	/*
#define SGX_EINITTOKEN_SIZE	304
	if (WARN_ON_ONCE(!access_ok(sigstruct, sizeof(struct sgx_sigstruct)) ||
			 !access_ok(token, SGX_EINITTOKEN_SIZE) ||
			 !access_ok(secs, PAGE_SIZE)))
		return -EINVAL;

	__uaccess_begin();
	ret = __einit((void *)sigstruct, (void *)token, (void *)secs);
	__uaccess_end();

	return ret;
}

int sgx_virt_einit(void __user *sigstruct, void __user *token,
		   void __user *secs, u64 *lepubkeyhash, int *trapnr)
{
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_SGX_LC)) {
		ret = __sgx_virt_einit(sigstruct, token, secs);
	} else {
		preempt_disable();

		sgx_update_lepubkeyhash(lepubkeyhash);

		ret = __sgx_virt_einit(sigstruct, token, secs);
		preempt_enable();
	}

	/* Propagate up the error from the WARN_ON_ONCE in __sgx_virt_einit() */
	if (ret == -EINVAL)
		return ret;

	if (encls_faulted(ret)) {
		*trapnr = ENCLS_TRAPNR(ret);
		return -EFAULT;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sgx_virt_einit);
