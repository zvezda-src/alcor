
#include <asm/mman.h>
#include <asm/sgx.h>
#include <linux/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include "driver.h"
#include "encl.h"
#include "encls.h"

struct sgx_va_page *sgx_encl_grow(struct sgx_encl *encl, bool reclaim)
{
	struct sgx_va_page *va_page = NULL;
	void *err;

	BUILD_BUG_ON(SGX_VA_SLOT_COUNT !=
		(SGX_ENCL_PAGE_VA_OFFSET_MASK >> 3) + 1);

	if (!(encl->page_cnt % SGX_VA_SLOT_COUNT)) {
		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return ERR_PTR(-ENOMEM);

		va_page->epc_page = sgx_alloc_va_page(reclaim);
		if (IS_ERR(va_page->epc_page)) {
			err = ERR_CAST(va_page->epc_page);
			kfree(va_page);
			return err;
		}

		WARN_ON_ONCE(encl->page_cnt % SGX_VA_SLOT_COUNT);
	}
	encl->page_cnt++;
	return va_page;
}

void sgx_encl_shrink(struct sgx_encl *encl, struct sgx_va_page *va_page)
{
	encl->page_cnt--;

	if (va_page) {
		sgx_encl_free_epc_page(va_page->epc_page);
		list_del(&va_page->list);
		kfree(va_page);
	}
}

static int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs)
{
	struct sgx_epc_page *secs_epc;
	struct sgx_va_page *va_page;
	struct sgx_pageinfo pginfo;
	struct sgx_secinfo secinfo;
	unsigned long encl_size;
	struct file *backing;
	long ret;

	va_page = sgx_encl_grow(encl, true);
	if (IS_ERR(va_page))
		return PTR_ERR(va_page);
	else if (va_page)
		list_add(&va_page->list, &encl->va_pages);
	/* else the tail page of the VA page list had free slots. */

	/* The extra page goes to SECS. */
	encl_size = secs->size + PAGE_SIZE;

	backing = shmem_file_setup("SGX backing", encl_size + (encl_size >> 5),
				   VM_NORESERVE);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		goto err_out_shrink;
	}

	encl->backing = backing;

	secs_epc = sgx_alloc_epc_page(&encl->secs, true);
	if (IS_ERR(secs_epc)) {
		ret = PTR_ERR(secs_epc);
		goto err_out_backing;
	}

	encl->secs.epc_page = secs_epc;

	pginfo.addr = 0;
	pginfo.contents = (unsigned long)secs;
	pginfo.metadata = (unsigned long)&secinfo;
	pginfo.secs = 0;
	memset(&secinfo, 0, sizeof(secinfo));

	ret = __ecreate((void *)&pginfo, sgx_get_epc_virt_addr(secs_epc));
	if (ret) {
		ret = -EIO;
		goto err_out;
	}

	if (secs->attributes & SGX_ATTR_DEBUG)
		set_bit(SGX_ENCL_DEBUG, &encl->flags);

	encl->secs.encl = encl;
	encl->secs.type = SGX_PAGE_TYPE_SECS;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->attributes = secs->attributes;
	encl->attributes_mask = SGX_ATTR_DEBUG | SGX_ATTR_MODE64BIT | SGX_ATTR_KSS;

	/* Set only after completion, as encl->lock has not been taken. */
	set_bit(SGX_ENCL_CREATED, &encl->flags);

	return 0;

err_out:
	sgx_encl_free_epc_page(encl->secs.epc_page);
	encl->secs.epc_page = NULL;

err_out_backing:
	fput(encl->backing);
	encl->backing = NULL;

err_out_shrink:
	sgx_encl_shrink(encl, va_page);

	return ret;
}

static long sgx_ioc_enclave_create(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_create create_arg;
	void *secs;
	int ret;

	if (test_bit(SGX_ENCL_CREATED, &encl->flags))
		return -EINVAL;

	if (copy_from_user(&create_arg, arg, sizeof(create_arg)))
		return -EFAULT;

	secs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!secs)
		return -ENOMEM;

	if (copy_from_user(secs, (void __user *)create_arg.src, PAGE_SIZE))
		ret = -EFAULT;
	else
		ret = sgx_encl_create(encl, secs);

	kfree(secs);
	return ret;
}

static int sgx_validate_secinfo(struct sgx_secinfo *secinfo)
{
	u64 perm = secinfo->flags & SGX_SECINFO_PERMISSION_MASK;
	u64 pt   = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;

	if (pt != SGX_SECINFO_REG && pt != SGX_SECINFO_TCS)
		return -EINVAL;

	if ((perm & SGX_SECINFO_W) && !(perm & SGX_SECINFO_R))
		return -EINVAL;

	/*
	if (pt == SGX_SECINFO_TCS && perm)
		return -EINVAL;

	if (secinfo->flags & SGX_SECINFO_RESERVED_MASK)
		return -EINVAL;

	if (memchr_inv(secinfo->reserved, 0, sizeof(secinfo->reserved)))
		return -EINVAL;

	return 0;
}

static int __sgx_encl_add_page(struct sgx_encl *encl,
			       struct sgx_encl_page *encl_page,
			       struct sgx_epc_page *epc_page,
			       struct sgx_secinfo *secinfo, unsigned long src)
{
	struct sgx_pageinfo pginfo;
	struct vm_area_struct *vma;
	struct page *src_page;
	int ret;

	/* Deny noexec. */
	vma = find_vma(current->mm, src);
	if (!vma)
		return -EFAULT;

	if (!(vma->vm_flags & VM_MAYEXEC))
		return -EACCES;

	ret = get_user_pages(src, 1, 0, &src_page, NULL);
	if (ret < 1)
		return -EFAULT;

	pginfo.secs = (unsigned long)sgx_get_epc_virt_addr(encl->secs.epc_page);
	pginfo.addr = encl_page->desc & PAGE_MASK;
	pginfo.metadata = (unsigned long)secinfo;
	pginfo.contents = (unsigned long)kmap_atomic(src_page);

	ret = __eadd(&pginfo, sgx_get_epc_virt_addr(epc_page));

	kunmap_atomic((void *)pginfo.contents);
	put_page(src_page);

	return ret ? -EIO : 0;
}

static int __sgx_encl_extend(struct sgx_encl *encl,
			     struct sgx_epc_page *epc_page)
{
	unsigned long offset;
	int ret;

	for (offset = 0; offset < PAGE_SIZE; offset += SGX_EEXTEND_BLOCK_SIZE) {
		ret = __eextend(sgx_get_epc_virt_addr(encl->secs.epc_page),
				sgx_get_epc_virt_addr(epc_page) + offset);
		if (ret) {
			if (encls_failed(ret))
				ENCLS_WARN(ret, "EEXTEND");

			return -EIO;
		}
	}

	return 0;
}

static int sgx_encl_add_page(struct sgx_encl *encl, unsigned long src,
			     unsigned long offset, struct sgx_secinfo *secinfo,
			     unsigned long flags)
{
	struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page;
	struct sgx_va_page *va_page;
	int ret;

	encl_page = sgx_encl_page_alloc(encl, offset, secinfo->flags);
	if (IS_ERR(encl_page))
		return PTR_ERR(encl_page);

	epc_page = sgx_alloc_epc_page(encl_page, true);
	if (IS_ERR(epc_page)) {
		kfree(encl_page);
		return PTR_ERR(epc_page);
	}

	va_page = sgx_encl_grow(encl, true);
	if (IS_ERR(va_page)) {
		ret = PTR_ERR(va_page);
		goto err_out_free;
	}

	mmap_read_lock(current->mm);
	mutex_lock(&encl->lock);

	/*
	if (va_page)
		list_add(&va_page->list, &encl->va_pages);

	/*
	ret = xa_insert(&encl->page_array, PFN_DOWN(encl_page->desc),
			encl_page, GFP_KERNEL);
	if (ret)
		goto err_out_unlock;

	ret = __sgx_encl_add_page(encl, encl_page, epc_page, secinfo,
				  src);
	if (ret)
		goto err_out;

	/*
	encl_page->encl = encl;
	encl_page->epc_page = epc_page;
	encl_page->type = (secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK) >> 8;
	encl->secs_child_cnt++;

	if (flags & SGX_PAGE_MEASURE) {
		ret = __sgx_encl_extend(encl, epc_page);
		if (ret)
			goto err_out;
	}

	sgx_mark_page_reclaimable(encl_page->epc_page);
	mutex_unlock(&encl->lock);
	mmap_read_unlock(current->mm);
	return ret;

err_out:
	xa_erase(&encl->page_array, PFN_DOWN(encl_page->desc));

err_out_unlock:
	sgx_encl_shrink(encl, va_page);
	mutex_unlock(&encl->lock);
	mmap_read_unlock(current->mm);

err_out_free:
	sgx_encl_free_epc_page(epc_page);
	kfree(encl_page);

	return ret;
}

static int sgx_validate_offset_length(struct sgx_encl *encl,
				      unsigned long offset,
				      unsigned long length)
{
	if (!IS_ALIGNED(offset, PAGE_SIZE))
		return -EINVAL;

	if (!length || !IS_ALIGNED(length, PAGE_SIZE))
		return -EINVAL;

	if (offset + length - PAGE_SIZE >= encl->size)
		return -EINVAL;

	return 0;
}

static long sgx_ioc_enclave_add_pages(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_add_pages add_arg;
	struct sgx_secinfo secinfo;
	unsigned long c;
	int ret;

	if (!test_bit(SGX_ENCL_CREATED, &encl->flags) ||
	    test_bit(SGX_ENCL_INITIALIZED, &encl->flags))
		return -EINVAL;

	if (copy_from_user(&add_arg, arg, sizeof(add_arg)))
		return -EFAULT;

	if (!IS_ALIGNED(add_arg.src, PAGE_SIZE))
		return -EINVAL;

	if (sgx_validate_offset_length(encl, add_arg.offset, add_arg.length))
		return -EINVAL;

	if (copy_from_user(&secinfo, (void __user *)add_arg.secinfo,
			   sizeof(secinfo)))
		return -EFAULT;

	if (sgx_validate_secinfo(&secinfo))
		return -EINVAL;

	for (c = 0 ; c < add_arg.length; c += PAGE_SIZE) {
		if (signal_pending(current)) {
			if (!c)
				ret = -ERESTARTSYS;

			break;
		}

		if (need_resched())
			cond_resched();

		ret = sgx_encl_add_page(encl, add_arg.src + c, add_arg.offset + c,
					&secinfo, add_arg.flags);
		if (ret)
			break;
	}

	add_arg.count = c;

	if (copy_to_user(arg, &add_arg, sizeof(add_arg)))
		return -EFAULT;

	return ret;
}

static int __sgx_get_key_hash(struct crypto_shash *tfm, const void *modulus,
			      void *hash)
{
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;

	return crypto_shash_digest(shash, modulus, SGX_MODULUS_SIZE, hash);
}

static int sgx_get_key_hash(const void *modulus, void *hash)
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = __sgx_get_key_hash(tfm, modulus, hash);

	crypto_free_shash(tfm);
	return ret;
}

static int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
			 void *token)
{
	u64 mrsigner[4];
	int i, j;
	void *addr;
	int ret;

	/*
	if (encl->attributes & ~encl->attributes_mask)
		return -EACCES;

	/*
	if (sigstruct->body.attributes & sigstruct->body.attributes_mask &
	    sgx_attributes_reserved_mask)
		return -EINVAL;

	if (sigstruct->body.miscselect & sigstruct->body.misc_mask &
	    sgx_misc_reserved_mask)
		return -EINVAL;

	if (sigstruct->body.xfrm & sigstruct->body.xfrm_mask &
	    sgx_xfrm_reserved_mask)
		return -EINVAL;

	ret = sgx_get_key_hash(sigstruct->modulus, mrsigner);
	if (ret)
		return ret;

	mutex_lock(&encl->lock);

	/*
	for (i = 0; i < SGX_EINIT_SLEEP_COUNT; i++) {
		for (j = 0; j < SGX_EINIT_SPIN_COUNT; j++) {
			addr = sgx_get_epc_virt_addr(encl->secs.epc_page);

			preempt_disable();

			sgx_update_lepubkeyhash(mrsigner);

			ret = __einit(sigstruct, token, addr);

			preempt_enable();

			if (ret == SGX_UNMASKED_EVENT)
				continue;
			else
				break;
		}

		if (ret != SGX_UNMASKED_EVENT)
			break;

		msleep_interruptible(SGX_EINIT_SLEEP_TIME);

		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			goto err_out;
		}
	}

	if (encls_faulted(ret)) {
		if (encls_failed(ret))
			ENCLS_WARN(ret, "EINIT");

		ret = -EIO;
	} else if (ret) {
		pr_debug("EINIT returned %d\n", ret);
		ret = -EPERM;
	} else {
		set_bit(SGX_ENCL_INITIALIZED, &encl->flags);
	}

err_out:
	mutex_unlock(&encl->lock);
	return ret;
}

static long sgx_ioc_enclave_init(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_sigstruct *sigstruct;
	struct sgx_enclave_init init_arg;
	void *token;
	int ret;

	if (!test_bit(SGX_ENCL_CREATED, &encl->flags) ||
	    test_bit(SGX_ENCL_INITIALIZED, &encl->flags))
		return -EINVAL;

	if (copy_from_user(&init_arg, arg, sizeof(init_arg)))
		return -EFAULT;

	/*
	sigstruct = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sigstruct)
		return -ENOMEM;

	token = (void *)((unsigned long)sigstruct + PAGE_SIZE / 2);
	memset(token, 0, SGX_LAUNCH_TOKEN_SIZE);

	if (copy_from_user(sigstruct, (void __user *)init_arg.sigstruct,
			   sizeof(*sigstruct))) {
		ret = -EFAULT;
		goto out;
	}

	/*
	if (sigstruct->header.vendor != 0x0000 &&
	    sigstruct->header.vendor != 0x8086) {
		ret = -EINVAL;
		goto out;
	}

	ret = sgx_encl_init(encl, sigstruct, token);

out:
	kfree(sigstruct);
	return ret;
}

static long sgx_ioc_enclave_provision(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_provision params;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	return sgx_set_attribute(&encl->attributes_mask, params.fd);
}

static int sgx_ioc_sgx2_ready(struct sgx_encl *encl)
{
	if (!(cpu_feature_enabled(X86_FEATURE_SGX2)))
		return -ENODEV;

	if (!test_bit(SGX_ENCL_INITIALIZED, &encl->flags))
		return -EINVAL;

	return 0;
}

static int sgx_enclave_etrack(struct sgx_encl *encl)
{
	void *epc_virt;
	int ret;

	epc_virt = sgx_get_epc_virt_addr(encl->secs.epc_page);
	ret = __etrack(epc_virt);
	if (ret) {
		/*
		pr_err_once("ETRACK returned %d (0x%x)", ret, ret);
		/*
		on_each_cpu_mask(sgx_encl_cpumask(encl), sgx_ipi_cb, NULL, 1);
		ret = __etrack(epc_virt);
		if (ret) {
			pr_err_once("ETRACK repeat returned %d (0x%x)",
				    ret, ret);
			return -EFAULT;
		}
	}
	on_each_cpu_mask(sgx_encl_cpumask(encl), sgx_ipi_cb, NULL, 1);

	return 0;
}

static long
sgx_enclave_restrict_permissions(struct sgx_encl *encl,
				 struct sgx_enclave_restrict_permissions *modp)
{
	struct sgx_encl_page *entry;
	struct sgx_secinfo secinfo;
	unsigned long addr;
	unsigned long c;
	void *epc_virt;
	int ret;

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = modp->permissions & SGX_SECINFO_PERMISSION_MASK;

	for (c = 0 ; c < modp->length; c += PAGE_SIZE) {
		addr = encl->base + modp->offset + c;

		sgx_reclaim_direct();

		mutex_lock(&encl->lock);

		entry = sgx_encl_load_page(encl, addr);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry) == -EBUSY ? -EAGAIN : -EFAULT;
			goto out_unlock;
		}

		/*
		if (entry->type != SGX_PAGE_TYPE_REG) {
			ret = -EINVAL;
			goto out_unlock;
		}

		/*

		/* Change EPCM permissions. */
		epc_virt = sgx_get_epc_virt_addr(entry->epc_page);
		ret = __emodpr(&secinfo, epc_virt);
		if (encls_faulted(ret)) {
			/*
			pr_err_once("EMODPR encountered exception %d\n",
				    ENCLS_TRAPNR(ret));
			ret = -EFAULT;
			goto out_unlock;
		}
		if (encls_failed(ret)) {
			modp->result = ret;
			ret = -EFAULT;
			goto out_unlock;
		}

		ret = sgx_enclave_etrack(encl);
		if (ret) {
			ret = -EFAULT;
			goto out_unlock;
		}

		mutex_unlock(&encl->lock);
	}

	ret = 0;
	goto out;

out_unlock:
	mutex_unlock(&encl->lock);
out:
	modp->count = c;

	return ret;
}

static long sgx_ioc_enclave_restrict_permissions(struct sgx_encl *encl,
						 void __user *arg)
{
	struct sgx_enclave_restrict_permissions params;
	long ret;

	ret = sgx_ioc_sgx2_ready(encl);
	if (ret)
		return ret;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	if (sgx_validate_offset_length(encl, params.offset, params.length))
		return -EINVAL;

	if (params.permissions & ~SGX_SECINFO_PERMISSION_MASK)
		return -EINVAL;

	/*
	if ((params.permissions & SGX_SECINFO_W) &&
	    !(params.permissions & SGX_SECINFO_R))
		return -EINVAL;

	if (params.result || params.count)
		return -EINVAL;

	ret = sgx_enclave_restrict_permissions(encl, &params);

	if (copy_to_user(arg, &params, sizeof(params)))
		return -EFAULT;

	return ret;
}

static long sgx_enclave_modify_types(struct sgx_encl *encl,
				     struct sgx_enclave_modify_types *modt)
{
	unsigned long max_prot_restore;
	enum sgx_page_type page_type;
	struct sgx_encl_page *entry;
	struct sgx_secinfo secinfo;
	unsigned long prot;
	unsigned long addr;
	unsigned long c;
	void *epc_virt;
	int ret;

	page_type = modt->page_type & SGX_PAGE_TYPE_MASK;

	/*
	if (page_type != SGX_PAGE_TYPE_TCS && page_type != SGX_PAGE_TYPE_TRIM)
		return -EINVAL;

	memset(&secinfo, 0, sizeof(secinfo));

	secinfo.flags = page_type << 8;

	for (c = 0 ; c < modt->length; c += PAGE_SIZE) {
		addr = encl->base + modt->offset + c;

		sgx_reclaim_direct();

		mutex_lock(&encl->lock);

		entry = sgx_encl_load_page(encl, addr);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry) == -EBUSY ? -EAGAIN : -EFAULT;
			goto out_unlock;
		}

		/*
		if (!(entry->type == SGX_PAGE_TYPE_REG ||
		      (entry->type == SGX_PAGE_TYPE_TCS &&
		       page_type == SGX_PAGE_TYPE_TRIM))) {
			ret = -EINVAL;
			goto out_unlock;
		}

		max_prot_restore = entry->vm_max_prot_bits;

		/*
		if (entry->type == SGX_PAGE_TYPE_REG &&
		    page_type == SGX_PAGE_TYPE_TCS) {
			if (~entry->vm_max_prot_bits & (VM_READ | VM_WRITE)) {
				ret = -EPERM;
				goto out_unlock;
			}
			prot = PROT_READ | PROT_WRITE;
			entry->vm_max_prot_bits = calc_vm_prot_bits(prot, 0);

			/*
			if (sgx_unmark_page_reclaimable(entry->epc_page)) {
				ret = -EAGAIN;
				goto out_entry_changed;
			}

			/*
			mutex_unlock(&encl->lock);

			sgx_zap_enclave_ptes(encl, addr);

			mutex_lock(&encl->lock);

			sgx_mark_page_reclaimable(entry->epc_page);
		}

		/* Change EPC type */
		epc_virt = sgx_get_epc_virt_addr(entry->epc_page);
		ret = __emodt(&secinfo, epc_virt);
		if (encls_faulted(ret)) {
			/*
			pr_err_once("EMODT encountered exception %d\n",
				    ENCLS_TRAPNR(ret));
			ret = -EFAULT;
			goto out_entry_changed;
		}
		if (encls_failed(ret)) {
			modt->result = ret;
			ret = -EFAULT;
			goto out_entry_changed;
		}

		ret = sgx_enclave_etrack(encl);
		if (ret) {
			ret = -EFAULT;
			goto out_unlock;
		}

		entry->type = page_type;

		mutex_unlock(&encl->lock);
	}

	ret = 0;
	goto out;

out_entry_changed:
	entry->vm_max_prot_bits = max_prot_restore;
out_unlock:
	mutex_unlock(&encl->lock);
out:
	modt->count = c;

	return ret;
}

static long sgx_ioc_enclave_modify_types(struct sgx_encl *encl,
					 void __user *arg)
{
	struct sgx_enclave_modify_types params;
	long ret;

	ret = sgx_ioc_sgx2_ready(encl);
	if (ret)
		return ret;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	if (sgx_validate_offset_length(encl, params.offset, params.length))
		return -EINVAL;

	if (params.page_type & ~SGX_PAGE_TYPE_MASK)
		return -EINVAL;

	if (params.result || params.count)
		return -EINVAL;

	ret = sgx_enclave_modify_types(encl, &params);

	if (copy_to_user(arg, &params, sizeof(params)))
		return -EFAULT;

	return ret;
}

static long sgx_encl_remove_pages(struct sgx_encl *encl,
				  struct sgx_enclave_remove_pages *params)
{
	struct sgx_encl_page *entry;
	struct sgx_secinfo secinfo;
	unsigned long addr;
	unsigned long c;
	void *epc_virt;
	int ret;

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X;

	for (c = 0 ; c < params->length; c += PAGE_SIZE) {
		addr = encl->base + params->offset + c;

		sgx_reclaim_direct();

		mutex_lock(&encl->lock);

		entry = sgx_encl_load_page(encl, addr);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry) == -EBUSY ? -EAGAIN : -EFAULT;
			goto out_unlock;
		}

		if (entry->type != SGX_PAGE_TYPE_TRIM) {
			ret = -EPERM;
			goto out_unlock;
		}

		/*
		epc_virt = sgx_get_epc_virt_addr(entry->epc_page);
		ret = __emodpr(&secinfo, epc_virt);
		if (!encls_faulted(ret) || ENCLS_TRAPNR(ret) != X86_TRAP_PF) {
			ret = -EPERM;
			goto out_unlock;
		}

		if (sgx_unmark_page_reclaimable(entry->epc_page)) {
			ret = -EBUSY;
			goto out_unlock;
		}

		/*
		mutex_unlock(&encl->lock);

		sgx_zap_enclave_ptes(encl, addr);

		mutex_lock(&encl->lock);

		sgx_encl_free_epc_page(entry->epc_page);
		encl->secs_child_cnt--;
		entry->epc_page = NULL;
		xa_erase(&encl->page_array, PFN_DOWN(entry->desc));
		sgx_encl_shrink(encl, NULL);
		kfree(entry);

		mutex_unlock(&encl->lock);
	}

	ret = 0;
	goto out;

out_unlock:
	mutex_unlock(&encl->lock);
out:
	params->count = c;

	return ret;
}

static long sgx_ioc_enclave_remove_pages(struct sgx_encl *encl,
					 void __user *arg)
{
	struct sgx_enclave_remove_pages params;
	long ret;

	ret = sgx_ioc_sgx2_ready(encl);
	if (ret)
		return ret;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	if (sgx_validate_offset_length(encl, params.offset, params.length))
		return -EINVAL;

	if (params.count)
		return -EINVAL;

	ret = sgx_encl_remove_pages(encl, &params);

	if (copy_to_user(arg, &params, sizeof(params)))
		return -EFAULT;

	return ret;
}

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct sgx_encl *encl = filep->private_data;
	int ret;

	if (test_and_set_bit(SGX_ENCL_IOCTL, &encl->flags))
		return -EBUSY;

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		ret = sgx_ioc_enclave_create(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGES:
		ret = sgx_ioc_enclave_add_pages(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_INIT:
		ret = sgx_ioc_enclave_init(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_PROVISION:
		ret = sgx_ioc_enclave_provision(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS:
		ret = sgx_ioc_enclave_restrict_permissions(encl,
							   (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_MODIFY_TYPES:
		ret = sgx_ioc_enclave_modify_types(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_REMOVE_PAGES:
		ret = sgx_ioc_enclave_remove_pages(encl, (void __user *)arg);
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	clear_bit(SGX_ENCL_IOCTL, &encl->flags);
	return ret;
}
