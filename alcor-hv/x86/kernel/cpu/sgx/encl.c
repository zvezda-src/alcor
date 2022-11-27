
#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include <linux/suspend.h>
#include <linux/sched/mm.h>
#include <asm/sgx.h>
#include "encl.h"
#include "encls.h"
#include "sgx.h"

#define PCMDS_PER_PAGE (PAGE_SIZE / sizeof(struct sgx_pcmd))
#define PCMD_FIRST_MASK GENMASK(4, 0)

static int reclaimer_writing_to_pcmd(struct sgx_encl *encl,
				     unsigned long start_addr)
{
	int reclaimed = 0;
	int i;

	/*
	BUILD_BUG_ON(PCMDS_PER_PAGE != 32);

	for (i = 0; i < PCMDS_PER_PAGE; i++) {
		struct sgx_encl_page *entry;
		unsigned long addr;

		addr = start_addr + i * PAGE_SIZE;

		/*
		if (addr == encl->base + encl->size)
			break;

		entry = xa_load(&encl->page_array, PFN_DOWN(addr));
		if (!entry)
			continue;

		/*
		if (entry->epc_page &&
		    (entry->desc & SGX_ENCL_PAGE_BEING_RECLAIMED)) {
			reclaimed = 1;
			break;
		}
	}

	return reclaimed;
}

static inline pgoff_t sgx_encl_get_backing_page_pcmd_offset(struct sgx_encl *encl,
							    unsigned long page_index)
{
	pgoff_t epc_end_off = encl->size + sizeof(struct sgx_secs);

	return epc_end_off + page_index * sizeof(struct sgx_pcmd);
}

static inline void sgx_encl_truncate_backing_page(struct sgx_encl *encl, unsigned long page_index)
{
	struct inode *inode = file_inode(encl->backing);

	shmem_truncate_range(inode, PFN_PHYS(page_index), PFN_PHYS(page_index) + PAGE_SIZE - 1);
}

static int __sgx_encl_eldu(struct sgx_encl_page *encl_page,
			   struct sgx_epc_page *epc_page,
			   struct sgx_epc_page *secs_page)
{
	unsigned long va_offset = encl_page->desc & SGX_ENCL_PAGE_VA_OFFSET_MASK;
	struct sgx_encl *encl = encl_page->encl;
	pgoff_t page_index, page_pcmd_off;
	unsigned long pcmd_first_page;
	struct sgx_pageinfo pginfo;
	struct sgx_backing b;
	bool pcmd_page_empty;
	u8 *pcmd_page;
	int ret;

	if (secs_page)
		page_index = PFN_DOWN(encl_page->desc - encl_page->encl->base);
	else
		page_index = PFN_DOWN(encl->size);

	/*
	pcmd_first_page = PFN_PHYS(page_index & ~PCMD_FIRST_MASK) + encl->base;

	page_pcmd_off = sgx_encl_get_backing_page_pcmd_offset(encl, page_index);

	ret = sgx_encl_lookup_backing(encl, page_index, &b);
	if (ret)
		return ret;

	pginfo.addr = encl_page->desc & PAGE_MASK;
	pginfo.contents = (unsigned long)kmap_atomic(b.contents);
	pcmd_page = kmap_atomic(b.pcmd);
	pginfo.metadata = (unsigned long)pcmd_page + b.pcmd_offset;

	if (secs_page)
		pginfo.secs = (u64)sgx_get_epc_virt_addr(secs_page);
	else
		pginfo.secs = 0;

	ret = __eldu(&pginfo, sgx_get_epc_virt_addr(epc_page),
		     sgx_get_epc_virt_addr(encl_page->va_page->epc_page) + va_offset);
	if (ret) {
		if (encls_failed(ret))
			ENCLS_WARN(ret, "ELDU");

		ret = -EFAULT;
	}

	memset(pcmd_page + b.pcmd_offset, 0, sizeof(struct sgx_pcmd));
	set_page_dirty(b.pcmd);

	/*
	pcmd_page_empty = !memchr_inv(pcmd_page, 0, PAGE_SIZE);

	kunmap_atomic(pcmd_page);
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	get_page(b.pcmd);
	sgx_encl_put_backing(&b);

	sgx_encl_truncate_backing_page(encl, page_index);

	if (pcmd_page_empty && !reclaimer_writing_to_pcmd(encl, pcmd_first_page)) {
		sgx_encl_truncate_backing_page(encl, PFN_DOWN(page_pcmd_off));
		pcmd_page = kmap_atomic(b.pcmd);
		if (memchr_inv(pcmd_page, 0, PAGE_SIZE))
			pr_warn("PCMD page not empty after truncate.\n");
		kunmap_atomic(pcmd_page);
	}

	put_page(b.pcmd);

	return ret;
}

static struct sgx_epc_page *sgx_encl_eldu(struct sgx_encl_page *encl_page,
					  struct sgx_epc_page *secs_page)
{

	unsigned long va_offset = encl_page->desc & SGX_ENCL_PAGE_VA_OFFSET_MASK;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_epc_page *epc_page;
	int ret;

	epc_page = sgx_alloc_epc_page(encl_page, false);
	if (IS_ERR(epc_page))
		return epc_page;

	ret = __sgx_encl_eldu(encl_page, epc_page, secs_page);
	if (ret) {
		sgx_encl_free_epc_page(epc_page);
		return ERR_PTR(ret);
	}

	sgx_free_va_slot(encl_page->va_page, va_offset);
	list_move(&encl_page->va_page->list, &encl->va_pages);
	encl_page->desc &= ~SGX_ENCL_PAGE_VA_OFFSET_MASK;
	encl_page->epc_page = epc_page;

	return epc_page;
}

static struct sgx_encl_page *__sgx_encl_load_page(struct sgx_encl *encl,
						  struct sgx_encl_page *entry)
{
	struct sgx_epc_page *epc_page;

	/* Entry successfully located. */
	if (entry->epc_page) {
		if (entry->desc & SGX_ENCL_PAGE_BEING_RECLAIMED)
			return ERR_PTR(-EBUSY);

		return entry;
	}

	if (!(encl->secs.epc_page)) {
		epc_page = sgx_encl_eldu(&encl->secs, NULL);
		if (IS_ERR(epc_page))
			return ERR_CAST(epc_page);
	}

	epc_page = sgx_encl_eldu(entry, encl->secs.epc_page);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	encl->secs_child_cnt++;
	sgx_mark_page_reclaimable(entry->epc_page);

	return entry;
}

static struct sgx_encl_page *sgx_encl_load_page_in_vma(struct sgx_encl *encl,
						       unsigned long addr,
						       unsigned long vm_flags)
{
	unsigned long vm_prot_bits = vm_flags & (VM_READ | VM_WRITE | VM_EXEC);
	struct sgx_encl_page *entry;

	entry = xa_load(&encl->page_array, PFN_DOWN(addr));
	if (!entry)
		return ERR_PTR(-EFAULT);

	/*
	if ((entry->vm_max_prot_bits & vm_prot_bits) != vm_prot_bits)
		return ERR_PTR(-EFAULT);

	return __sgx_encl_load_page(encl, entry);
}

struct sgx_encl_page *sgx_encl_load_page(struct sgx_encl *encl,
					 unsigned long addr)
{
	struct sgx_encl_page *entry;

	entry = xa_load(&encl->page_array, PFN_DOWN(addr));
	if (!entry)
		return ERR_PTR(-EFAULT);

	return __sgx_encl_load_page(encl, entry);
}

static vm_fault_t sgx_encl_eaug_page(struct vm_area_struct *vma,
				     struct sgx_encl *encl, unsigned long addr)
{
	vm_fault_t vmret = VM_FAULT_SIGBUS;
	struct sgx_pageinfo pginfo = {0};
	struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page;
	struct sgx_va_page *va_page;
	unsigned long phys_addr;
	u64 secinfo_flags;
	int ret;

	if (!test_bit(SGX_ENCL_INITIALIZED, &encl->flags))
		return VM_FAULT_SIGBUS;

	/*
	secinfo_flags = SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X;
	encl_page = sgx_encl_page_alloc(encl, addr - encl->base, secinfo_flags);
	if (IS_ERR(encl_page))
		return VM_FAULT_OOM;

	mutex_lock(&encl->lock);

	epc_page = sgx_alloc_epc_page(encl_page, false);
	if (IS_ERR(epc_page)) {
		if (PTR_ERR(epc_page) == -EBUSY)
			vmret =  VM_FAULT_NOPAGE;
		goto err_out_unlock;
	}

	va_page = sgx_encl_grow(encl, false);
	if (IS_ERR(va_page))
		goto err_out_epc;

	if (va_page)
		list_add(&va_page->list, &encl->va_pages);

	ret = xa_insert(&encl->page_array, PFN_DOWN(encl_page->desc),
			encl_page, GFP_KERNEL);
	/*
	if (ret)
		goto err_out_shrink;

	pginfo.secs = (unsigned long)sgx_get_epc_virt_addr(encl->secs.epc_page);
	pginfo.addr = encl_page->desc & PAGE_MASK;
	pginfo.metadata = 0;

	ret = __eaug(&pginfo, sgx_get_epc_virt_addr(epc_page));
	if (ret)
		goto err_out;

	encl_page->encl = encl;
	encl_page->epc_page = epc_page;
	encl_page->type = SGX_PAGE_TYPE_REG;
	encl->secs_child_cnt++;

	sgx_mark_page_reclaimable(encl_page->epc_page);

	phys_addr = sgx_get_epc_phys_addr(epc_page);
	/*
	vmret = vmf_insert_pfn(vma, addr, PFN_DOWN(phys_addr));
	if (vmret != VM_FAULT_NOPAGE) {
		mutex_unlock(&encl->lock);
		return VM_FAULT_SIGBUS;
	}
	mutex_unlock(&encl->lock);
	return VM_FAULT_NOPAGE;

err_out:
	xa_erase(&encl->page_array, PFN_DOWN(encl_page->desc));

err_out_shrink:
	sgx_encl_shrink(encl, va_page);
err_out_epc:
	sgx_encl_free_epc_page(epc_page);
err_out_unlock:
	mutex_unlock(&encl->lock);
	kfree(encl_page);

	return vmret;
}

static vm_fault_t sgx_vma_fault(struct vm_fault *vmf)
{
	unsigned long addr = (unsigned long)vmf->address;
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_encl_page *entry;
	unsigned long phys_addr;
	struct sgx_encl *encl;
	vm_fault_t ret;

	encl = vma->vm_private_data;

	/*
	if (unlikely(!encl))
		return VM_FAULT_SIGBUS;

	/*
	if (cpu_feature_enabled(X86_FEATURE_SGX2) &&
	    (!xa_load(&encl->page_array, PFN_DOWN(addr))))
		return sgx_encl_eaug_page(vma, encl, addr);

	mutex_lock(&encl->lock);

	entry = sgx_encl_load_page_in_vma(encl, addr, vma->vm_flags);
	if (IS_ERR(entry)) {
		mutex_unlock(&encl->lock);

		if (PTR_ERR(entry) == -EBUSY)
			return VM_FAULT_NOPAGE;

		return VM_FAULT_SIGBUS;
	}

	phys_addr = sgx_get_epc_phys_addr(entry->epc_page);

	ret = vmf_insert_pfn(vma, addr, PFN_DOWN(phys_addr));
	if (ret != VM_FAULT_NOPAGE) {
		mutex_unlock(&encl->lock);

		return VM_FAULT_SIGBUS;
	}

	sgx_encl_test_and_clear_young(vma->vm_mm, entry);
	mutex_unlock(&encl->lock);

	return VM_FAULT_NOPAGE;
}

static void sgx_vma_open(struct vm_area_struct *vma)
{
	struct sgx_encl *encl = vma->vm_private_data;

	/*
	if (unlikely(!encl))
		return;

	if (sgx_encl_mm_add(encl, vma->vm_mm))
		vma->vm_private_data = NULL;
}


int sgx_encl_may_map(struct sgx_encl *encl, unsigned long start,
		     unsigned long end, unsigned long vm_flags)
{
	unsigned long vm_prot_bits = vm_flags & (VM_READ | VM_WRITE | VM_EXEC);
	struct sgx_encl_page *page;
	unsigned long count = 0;
	int ret = 0;

	XA_STATE(xas, &encl->page_array, PFN_DOWN(start));

	/* Disallow mapping outside enclave's address range. */
	if (test_bit(SGX_ENCL_INITIALIZED, &encl->flags) &&
	    (start < encl->base || end > encl->base + encl->size))
		return -EACCES;

	/*
	if (current->personality & READ_IMPLIES_EXEC)
		return -EACCES;

	mutex_lock(&encl->lock);
	xas_lock(&xas);
	xas_for_each(&xas, page, PFN_DOWN(end - 1)) {
		if (~page->vm_max_prot_bits & vm_prot_bits) {
			ret = -EACCES;
			break;
		}

		/* Reschedule on every XA_CHECK_SCHED iteration. */
		if (!(++count % XA_CHECK_SCHED)) {
			xas_pause(&xas);
			xas_unlock(&xas);
			mutex_unlock(&encl->lock);

			cond_resched();

			mutex_lock(&encl->lock);
			xas_lock(&xas);
		}
	}
	xas_unlock(&xas);
	mutex_unlock(&encl->lock);

	return ret;
}

static int sgx_vma_mprotect(struct vm_area_struct *vma, unsigned long start,
			    unsigned long end, unsigned long newflags)
{
	return sgx_encl_may_map(vma->vm_private_data, start, end, newflags);
}

static int sgx_encl_debug_read(struct sgx_encl *encl, struct sgx_encl_page *page,
			       unsigned long addr, void *data)
{
	unsigned long offset = addr & ~PAGE_MASK;
	int ret;


	ret = __edbgrd(sgx_get_epc_virt_addr(page->epc_page) + offset, data);
	if (ret)
		return -EIO;

	return 0;
}

static int sgx_encl_debug_write(struct sgx_encl *encl, struct sgx_encl_page *page,
				unsigned long addr, void *data)
{
	unsigned long offset = addr & ~PAGE_MASK;
	int ret;

	ret = __edbgwr(sgx_get_epc_virt_addr(page->epc_page) + offset, data);
	if (ret)
		return -EIO;

	return 0;
}

static struct sgx_encl_page *sgx_encl_reserve_page(struct sgx_encl *encl,
						   unsigned long addr,
						   unsigned long vm_flags)
{
	struct sgx_encl_page *entry;

	for ( ; ; ) {
		mutex_lock(&encl->lock);

		entry = sgx_encl_load_page_in_vma(encl, addr, vm_flags);
		if (PTR_ERR(entry) != -EBUSY)
			break;

		mutex_unlock(&encl->lock);
	}

	if (IS_ERR(entry))
		mutex_unlock(&encl->lock);

	return entry;
}

static int sgx_vma_access(struct vm_area_struct *vma, unsigned long addr,
			  void *buf, int len, int write)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry = NULL;
	char data[sizeof(unsigned long)];
	unsigned long align;
	int offset;
	int cnt;
	int ret = 0;
	int i;

	/*
	if (!encl)
		return -EFAULT;

	if (!test_bit(SGX_ENCL_DEBUG, &encl->flags))
		return -EFAULT;

	for (i = 0; i < len; i += cnt) {
		entry = sgx_encl_reserve_page(encl, (addr + i) & PAGE_MASK,
					      vma->vm_flags);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry);
			break;
		}

		align = ALIGN_DOWN(addr + i, sizeof(unsigned long));
		offset = (addr + i) & (sizeof(unsigned long) - 1);
		cnt = sizeof(unsigned long) - offset;
		cnt = min(cnt, len - i);

		ret = sgx_encl_debug_read(encl, entry, align, data);
		if (ret)
			goto out;

		if (write) {
			memcpy(data + offset, buf + i, cnt);
			ret = sgx_encl_debug_write(encl, entry, align, data);
			if (ret)
				goto out;
		} else {
			memcpy(buf + i, data + offset, cnt);
		}

out:
		mutex_unlock(&encl->lock);

		if (ret)
			break;
	}

	return ret < 0 ? ret : i;
}

const struct vm_operations_struct sgx_vm_ops = {
	.fault = sgx_vma_fault,
	.mprotect = sgx_vma_mprotect,
	.open = sgx_vma_open,
	.access = sgx_vma_access,
};

void sgx_encl_release(struct kref *ref)
{
	struct sgx_encl *encl = container_of(ref, struct sgx_encl, refcount);
	struct sgx_va_page *va_page;
	struct sgx_encl_page *entry;
	unsigned long index;

	xa_for_each(&encl->page_array, index, entry) {
		if (entry->epc_page) {
			/*
			if (sgx_unmark_page_reclaimable(entry->epc_page))
				continue;

			sgx_encl_free_epc_page(entry->epc_page);
			encl->secs_child_cnt--;
			entry->epc_page = NULL;
		}

		kfree(entry);
		/* Invoke scheduler to prevent soft lockups. */
		cond_resched();
	}

	xa_destroy(&encl->page_array);

	if (!encl->secs_child_cnt && encl->secs.epc_page) {
		sgx_encl_free_epc_page(encl->secs.epc_page);
		encl->secs.epc_page = NULL;
	}

	while (!list_empty(&encl->va_pages)) {
		va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
					   list);
		list_del(&va_page->list);
		sgx_encl_free_epc_page(va_page->epc_page);
		kfree(va_page);
	}

	if (encl->backing)
		fput(encl->backing);

	cleanup_srcu_struct(&encl->srcu);

	WARN_ON_ONCE(!list_empty(&encl->mm_list));

	/* Detect EPC page leak's. */
	WARN_ON_ONCE(encl->secs_child_cnt);
	WARN_ON_ONCE(encl->secs.epc_page);

	kfree(encl);
}

static void sgx_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm = container_of(mn, struct sgx_encl_mm, mmu_notifier);
	struct sgx_encl_mm *tmp = NULL;

	/*
	spin_lock(&encl_mm->encl->mm_lock);
	list_for_each_entry(tmp, &encl_mm->encl->mm_list, list) {
		if (tmp == encl_mm) {
			list_del_rcu(&encl_mm->list);
			break;
		}
	}
	spin_unlock(&encl_mm->encl->mm_lock);

	if (tmp == encl_mm) {
		synchronize_srcu(&encl_mm->encl->srcu);
		mmu_notifier_put(mn);
	}
}

static void sgx_mmu_notifier_free(struct mmu_notifier *mn)
{
	struct sgx_encl_mm *encl_mm = container_of(mn, struct sgx_encl_mm, mmu_notifier);

	/* 'encl_mm' is going away, put encl_mm->encl reference: */
	kref_put(&encl_mm->encl->refcount, sgx_encl_release);

	kfree(encl_mm);
}

static const struct mmu_notifier_ops sgx_mmu_notifier_ops = {
	.release		= sgx_mmu_notifier_release,
	.free_notifier		= sgx_mmu_notifier_free,
};

static struct sgx_encl_mm *sgx_encl_find_mm(struct sgx_encl *encl,
					    struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm = NULL;
	struct sgx_encl_mm *tmp;
	int idx;

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(tmp, &encl->mm_list, list) {
		if (tmp->mm == mm) {
			encl_mm = tmp;
			break;
		}
	}

	srcu_read_unlock(&encl->srcu, idx);

	return encl_mm;
}

int sgx_encl_mm_add(struct sgx_encl *encl, struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm;
	int ret;

	/*
	mmap_assert_write_locked(mm);

	/*
	if (sgx_encl_find_mm(encl, mm))
		return 0;

	encl_mm = kzalloc(sizeof(*encl_mm), GFP_KERNEL);
	if (!encl_mm)
		return -ENOMEM;

	/* Grab a refcount for the encl_mm->encl reference: */
	kref_get(&encl->refcount);
	encl_mm->encl = encl;
	encl_mm->mm = mm;
	encl_mm->mmu_notifier.ops = &sgx_mmu_notifier_ops;

	ret = __mmu_notifier_register(&encl_mm->mmu_notifier, mm);
	if (ret) {
		kfree(encl_mm);
		return ret;
	}

	spin_lock(&encl->mm_lock);
	list_add_rcu(&encl_mm->list, &encl->mm_list);
	/* Pairs with smp_rmb() in sgx_zap_enclave_ptes(). */
	smp_wmb();
	encl->mm_list_version++;
	spin_unlock(&encl->mm_lock);

	return 0;
}

const cpumask_t *sgx_encl_cpumask(struct sgx_encl *encl)
{
	cpumask_t *cpumask = &encl->cpumask;
	struct sgx_encl_mm *encl_mm;
	int idx;

	cpumask_clear(cpumask);

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;

		cpumask_or(cpumask, cpumask, mm_cpumask(encl_mm->mm));

		mmput_async(encl_mm->mm);
	}

	srcu_read_unlock(&encl->srcu, idx);

	return cpumask;
}

static struct page *sgx_encl_get_backing_page(struct sgx_encl *encl,
					      pgoff_t index)
{
	struct inode *inode = encl->backing->f_path.dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfpmask = mapping_gfp_mask(mapping);

	return shmem_read_mapping_page_gfp(mapping, index, gfpmask);
}

static int sgx_encl_get_backing(struct sgx_encl *encl, unsigned long page_index,
			 struct sgx_backing *backing)
{
	pgoff_t page_pcmd_off = sgx_encl_get_backing_page_pcmd_offset(encl, page_index);
	struct page *contents;
	struct page *pcmd;

	contents = sgx_encl_get_backing_page(encl, page_index);
	if (IS_ERR(contents))
		return PTR_ERR(contents);

	pcmd = sgx_encl_get_backing_page(encl, PFN_DOWN(page_pcmd_off));
	if (IS_ERR(pcmd)) {
		put_page(contents);
		return PTR_ERR(pcmd);
	}

	backing->contents = contents;
	backing->pcmd = pcmd;
	backing->pcmd_offset = page_pcmd_off & (PAGE_SIZE - 1);

	return 0;
}

static struct mem_cgroup *sgx_encl_get_mem_cgroup(struct sgx_encl *encl)
{
	struct mem_cgroup *memcg = NULL;
	struct sgx_encl_mm *encl_mm;
	int idx;

	/*
	if (!current_is_ksgxd())
		return get_mem_cgroup_from_mm(current->mm);

	/*
	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;

		memcg = get_mem_cgroup_from_mm(encl_mm->mm);

		mmput_async(encl_mm->mm);

		break;
	}

	srcu_read_unlock(&encl->srcu, idx);

	/*
	if (!memcg)
		return get_mem_cgroup_from_mm(NULL);

	return memcg;
}

int sgx_encl_alloc_backing(struct sgx_encl *encl, unsigned long page_index,
			   struct sgx_backing *backing)
{
	struct mem_cgroup *encl_memcg = sgx_encl_get_mem_cgroup(encl);
	struct mem_cgroup *memcg = set_active_memcg(encl_memcg);
	int ret;

	ret = sgx_encl_get_backing(encl, page_index, backing);

	set_active_memcg(memcg);
	mem_cgroup_put(encl_memcg);

	return ret;
}

int sgx_encl_lookup_backing(struct sgx_encl *encl, unsigned long page_index,
			   struct sgx_backing *backing)
{
	return sgx_encl_get_backing(encl, page_index, backing);
}

void sgx_encl_put_backing(struct sgx_backing *backing)
{
	put_page(backing->pcmd);
	put_page(backing->contents);
}

static int sgx_encl_test_and_clear_young_cb(pte_t *ptep, unsigned long addr,
					    void *data)
{
	pte_t pte;
	int ret;

	ret = pte_young(*ptep);
	if (ret) {
		pte = pte_mkold(*ptep);
		set_pte_at((struct mm_struct *)data, addr, ptep, pte);
	}

	return ret;
}

int sgx_encl_test_and_clear_young(struct mm_struct *mm,
				  struct sgx_encl_page *page)
{
	unsigned long addr = page->desc & PAGE_MASK;
	struct sgx_encl *encl = page->encl;
	struct vm_area_struct *vma;
	int ret;

	ret = sgx_encl_find(mm, addr, &vma);
	if (ret)
		return 0;

	if (encl != vma->vm_private_data)
		return 0;

	ret = apply_to_page_range(vma->vm_mm, addr, PAGE_SIZE,
				  sgx_encl_test_and_clear_young_cb, vma->vm_mm);
	if (ret < 0)
		return 0;

	return ret;
}

struct sgx_encl_page *sgx_encl_page_alloc(struct sgx_encl *encl,
					  unsigned long offset,
					  u64 secinfo_flags)
{
	struct sgx_encl_page *encl_page;
	unsigned long prot;

	encl_page = kzalloc(sizeof(*encl_page), GFP_KERNEL);
	if (!encl_page)
		return ERR_PTR(-ENOMEM);

	encl_page->desc = encl->base + offset;
	encl_page->encl = encl;

	prot = _calc_vm_trans(secinfo_flags, SGX_SECINFO_R, PROT_READ)  |
	       _calc_vm_trans(secinfo_flags, SGX_SECINFO_W, PROT_WRITE) |
	       _calc_vm_trans(secinfo_flags, SGX_SECINFO_X, PROT_EXEC);

	/*
	if ((secinfo_flags & SGX_SECINFO_PAGE_TYPE_MASK) == SGX_SECINFO_TCS)
		prot |= PROT_READ | PROT_WRITE;

	/* Calculate maximum of the VM flags for the page. */
	encl_page->vm_max_prot_bits = calc_vm_prot_bits(prot, 0);

	return encl_page;
}

void sgx_zap_enclave_ptes(struct sgx_encl *encl, unsigned long addr)
{
	unsigned long mm_list_version;
	struct sgx_encl_mm *encl_mm;
	struct vm_area_struct *vma;
	int idx, ret;

	do {
		mm_list_version = encl->mm_list_version;

		/* Pairs with smp_wmb() in sgx_encl_mm_add(). */
		smp_rmb();

		idx = srcu_read_lock(&encl->srcu);

		list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
			if (!mmget_not_zero(encl_mm->mm))
				continue;

			mmap_read_lock(encl_mm->mm);

			ret = sgx_encl_find(encl_mm->mm, addr, &vma);
			if (!ret && encl == vma->vm_private_data)
				zap_vma_ptes(vma, addr, PAGE_SIZE);

			mmap_read_unlock(encl_mm->mm);

			mmput_async(encl_mm->mm);
		}

		srcu_read_unlock(&encl->srcu, idx);
	} while (unlikely(encl->mm_list_version != mm_list_version));
}

struct sgx_epc_page *sgx_alloc_va_page(bool reclaim)
{
	struct sgx_epc_page *epc_page;
	int ret;

	epc_page = sgx_alloc_epc_page(NULL, reclaim);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	ret = __epa(sgx_get_epc_virt_addr(epc_page));
	if (ret) {
		WARN_ONCE(1, "EPA returned %d (0x%x)", ret, ret);
		sgx_encl_free_epc_page(epc_page);
		return ERR_PTR(-EFAULT);
	}

	return epc_page;
}

unsigned int sgx_alloc_va_slot(struct sgx_va_page *va_page)
{
	int slot = find_first_zero_bit(va_page->slots, SGX_VA_SLOT_COUNT);

	if (slot < SGX_VA_SLOT_COUNT)
		set_bit(slot, va_page->slots);

	return slot << 3;
}

void sgx_free_va_slot(struct sgx_va_page *va_page, unsigned int offset)
{
	clear_bit(offset >> 3, va_page->slots);
}

bool sgx_va_page_full(struct sgx_va_page *va_page)
{
	int slot = find_first_zero_bit(va_page->slots, SGX_VA_SLOT_COUNT);

	return slot == SGX_VA_SLOT_COUNT;
}

void sgx_encl_free_epc_page(struct sgx_epc_page *page)
{
	int ret;

	WARN_ON_ONCE(page->flags & SGX_EPC_PAGE_RECLAIMER_TRACKED);

	ret = __eremove(sgx_get_epc_virt_addr(page));
	if (WARN_ONCE(ret, EREMOVE_ERROR_MESSAGE, ret, ret))
		return;

	sgx_free_epc_page(page);
}
