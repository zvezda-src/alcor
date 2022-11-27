
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/cacheinfo.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <linux/kthread.h>
#include <linux/mman.h>
#include <linux/perf_event.h>
#include <linux/pm_qos.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>
#include <asm/intel-family.h>
#include <asm/resctrl.h>
#include <asm/perf_event.h>

#include "../../events/perf_event.h" /* For X86_CONFIG() */
#include "internal.h"

#define CREATE_TRACE_POINTS
#include "pseudo_lock_event.h"

static u64 prefetch_disable_bits;

static unsigned int pseudo_lock_major;
static unsigned long pseudo_lock_minor_avail = GENMASK(MINORBITS, 0);
static struct class *pseudo_lock_class;

static u64 get_prefetch_disable_bits(void)
{
	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
	    boot_cpu_data.x86 != 6)
		return 0;

	switch (boot_cpu_data.x86_model) {
	case INTEL_FAM6_BROADWELL_X:
		/*
		return 0xF;
	case INTEL_FAM6_ATOM_GOLDMONT:
	case INTEL_FAM6_ATOM_GOLDMONT_PLUS:
		/*
		return 0x5;
	}

	return 0;
}

static int pseudo_lock_minor_get(unsigned int *minor)
{
	unsigned long first_bit;

	first_bit = find_first_bit(&pseudo_lock_minor_avail, MINORBITS);

	if (first_bit == MINORBITS)
		return -ENOSPC;

	__clear_bit(first_bit, &pseudo_lock_minor_avail);

	return 0;
}

static void pseudo_lock_minor_release(unsigned int minor)
{
	__set_bit(minor, &pseudo_lock_minor_avail);
}

static struct rdtgroup *region_find_by_minor(unsigned int minor)
{
	struct rdtgroup *rdtgrp, *rdtgrp_match = NULL;

	list_for_each_entry(rdtgrp, &rdt_all_groups, rdtgroup_list) {
		if (rdtgrp->plr && rdtgrp->plr->minor == minor) {
			rdtgrp_match = rdtgrp;
			break;
		}
	}
	return rdtgrp_match;
}

struct pseudo_lock_pm_req {
	struct list_head list;
	struct dev_pm_qos_request req;
};

static void pseudo_lock_cstates_relax(struct pseudo_lock_region *plr)
{
	struct pseudo_lock_pm_req *pm_req, *next;

	list_for_each_entry_safe(pm_req, next, &plr->pm_reqs, list) {
		dev_pm_qos_remove_request(&pm_req->req);
		list_del(&pm_req->list);
		kfree(pm_req);
	}
}

static int pseudo_lock_cstates_constrain(struct pseudo_lock_region *plr)
{
	struct pseudo_lock_pm_req *pm_req;
	int cpu;
	int ret;

	for_each_cpu(cpu, &plr->d->cpu_mask) {
		pm_req = kzalloc(sizeof(*pm_req), GFP_KERNEL);
		if (!pm_req) {
			rdt_last_cmd_puts("Failure to allocate memory for PM QoS\n");
			ret = -ENOMEM;
			goto out_err;
		}
		ret = dev_pm_qos_add_request(get_cpu_device(cpu),
					     &pm_req->req,
					     DEV_PM_QOS_RESUME_LATENCY,
					     30);
		if (ret < 0) {
			rdt_last_cmd_printf("Failed to add latency req CPU%d\n",
					    cpu);
			kfree(pm_req);
			ret = -1;
			goto out_err;
		}
		list_add(&pm_req->list, &plr->pm_reqs);
	}

	return 0;

out_err:
	pseudo_lock_cstates_relax(plr);
	return ret;
}

static void pseudo_lock_region_clear(struct pseudo_lock_region *plr)
{
	plr->size = 0;
	plr->line_size = 0;
	kfree(plr->kmem);
	plr->kmem = NULL;
	plr->s = NULL;
	if (plr->d)
		plr->d->plr = NULL;
	plr->d = NULL;
	plr->cbm = 0;
	plr->debugfs_dir = NULL;
}

static int pseudo_lock_region_init(struct pseudo_lock_region *plr)
{
	struct cpu_cacheinfo *ci;
	int ret;
	int i;

	/* Pick the first cpu we find that is associated with the cache. */
	plr->cpu = cpumask_first(&plr->d->cpu_mask);

	if (!cpu_online(plr->cpu)) {
		rdt_last_cmd_printf("CPU %u associated with cache not online\n",
				    plr->cpu);
		ret = -ENODEV;
		goto out_region;
	}

	ci = get_cpu_cacheinfo(plr->cpu);

	plr->size = rdtgroup_cbm_to_size(plr->s->res, plr->d, plr->cbm);

	for (i = 0; i < ci->num_leaves; i++) {
		if (ci->info_list[i].level == plr->s->res->cache_level) {
			plr->line_size = ci->info_list[i].coherency_line_size;
			return 0;
		}
	}

	ret = -1;
	rdt_last_cmd_puts("Unable to determine cache line size\n");
out_region:
	pseudo_lock_region_clear(plr);
	return ret;
}

static int pseudo_lock_init(struct rdtgroup *rdtgrp)
{
	struct pseudo_lock_region *plr;

	plr = kzalloc(sizeof(*plr), GFP_KERNEL);
	if (!plr)
		return -ENOMEM;

	init_waitqueue_head(&plr->lock_thread_wq);
	INIT_LIST_HEAD(&plr->pm_reqs);
	rdtgrp->plr = plr;
	return 0;
}

static int pseudo_lock_region_alloc(struct pseudo_lock_region *plr)
{
	int ret;

	ret = pseudo_lock_region_init(plr);
	if (ret < 0)
		return ret;

	/*
	if (plr->size > KMALLOC_MAX_SIZE) {
		rdt_last_cmd_puts("Requested region exceeds maximum size\n");
		ret = -E2BIG;
		goto out_region;
	}

	plr->kmem = kzalloc(plr->size, GFP_KERNEL);
	if (!plr->kmem) {
		rdt_last_cmd_puts("Unable to allocate memory\n");
		ret = -ENOMEM;
		goto out_region;
	}

	ret = 0;
	goto out;
out_region:
	pseudo_lock_region_clear(plr);
out:
	return ret;
}

static void pseudo_lock_free(struct rdtgroup *rdtgrp)
{
	pseudo_lock_region_clear(rdtgrp->plr);
	kfree(rdtgrp->plr);
	rdtgrp->plr = NULL;
}

static int pseudo_lock_fn(void *_rdtgrp)
{
	struct rdtgroup *rdtgrp = _rdtgrp;
	struct pseudo_lock_region *plr = rdtgrp->plr;
	u32 rmid_p, closid_p;
	unsigned long i;
#ifdef CONFIG_KASAN
	/*
	unsigned int line_size;
	unsigned int size;
	void *mem_r;
#else
	register unsigned int line_size asm("esi");
	register unsigned int size asm("edi");
	register void *mem_r asm(_ASM_BX);
#endif /* CONFIG_KASAN */

	/*
	native_wbinvd();

	/*
	local_irq_disable();

	/*
	__wrmsr(MSR_MISC_FEATURE_CONTROL, prefetch_disable_bits, 0x0);
	closid_p = this_cpu_read(pqr_state.cur_closid);
	rmid_p = this_cpu_read(pqr_state.cur_rmid);
	mem_r = plr->kmem;
	size = plr->size;
	line_size = plr->line_size;
	/*
	__wrmsr(IA32_PQR_ASSOC, rmid_p, rdtgrp->closid);
	/*
	for (i = 0; i < size; i += PAGE_SIZE) {
		/*
		rmb();
		asm volatile("mov (%0,%1,1), %%eax\n\t"
			:
			: "r" (mem_r), "r" (i)
			: "%eax", "memory");
	}
	for (i = 0; i < size; i += line_size) {
		/*
		rmb();
		asm volatile("mov (%0,%1,1), %%eax\n\t"
			:
			: "r" (mem_r), "r" (i)
			: "%eax", "memory");
	}
	/*
	__wrmsr(IA32_PQR_ASSOC, rmid_p, closid_p);

	/* Re-enable the hardware prefetcher(s) */
	wrmsr(MSR_MISC_FEATURE_CONTROL, 0x0, 0x0);
	local_irq_enable();

	plr->thread_done = 1;
	wake_up_interruptible(&plr->lock_thread_wq);
	return 0;
}

static int rdtgroup_monitor_in_progress(struct rdtgroup *rdtgrp)
{
	return !list_empty(&rdtgrp->mon.crdtgrp_list);
}

static int rdtgroup_locksetup_user_restrict(struct rdtgroup *rdtgrp)
{
	int ret;

	ret = rdtgroup_kn_mode_restrict(rdtgrp, "tasks");
	if (ret)
		return ret;

	ret = rdtgroup_kn_mode_restrict(rdtgrp, "cpus");
	if (ret)
		goto err_tasks;

	ret = rdtgroup_kn_mode_restrict(rdtgrp, "cpus_list");
	if (ret)
		goto err_cpus;

	if (rdt_mon_capable) {
		ret = rdtgroup_kn_mode_restrict(rdtgrp, "mon_groups");
		if (ret)
			goto err_cpus_list;
	}

	ret = 0;
	goto out;

err_cpus_list:
	rdtgroup_kn_mode_restore(rdtgrp, "cpus_list", 0777);
err_cpus:
	rdtgroup_kn_mode_restore(rdtgrp, "cpus", 0777);
err_tasks:
	rdtgroup_kn_mode_restore(rdtgrp, "tasks", 0777);
out:
	return ret;
}

static int rdtgroup_locksetup_user_restore(struct rdtgroup *rdtgrp)
{
	int ret;

	ret = rdtgroup_kn_mode_restore(rdtgrp, "tasks", 0777);
	if (ret)
		return ret;

	ret = rdtgroup_kn_mode_restore(rdtgrp, "cpus", 0777);
	if (ret)
		goto err_tasks;

	ret = rdtgroup_kn_mode_restore(rdtgrp, "cpus_list", 0777);
	if (ret)
		goto err_cpus;

	if (rdt_mon_capable) {
		ret = rdtgroup_kn_mode_restore(rdtgrp, "mon_groups", 0777);
		if (ret)
			goto err_cpus_list;
	}

	ret = 0;
	goto out;

err_cpus_list:
	rdtgroup_kn_mode_restrict(rdtgrp, "cpus_list");
err_cpus:
	rdtgroup_kn_mode_restrict(rdtgrp, "cpus");
err_tasks:
	rdtgroup_kn_mode_restrict(rdtgrp, "tasks");
out:
	return ret;
}

int rdtgroup_locksetup_enter(struct rdtgroup *rdtgrp)
{
	int ret;

	/*
	if (rdtgrp == &rdtgroup_default) {
		rdt_last_cmd_puts("Cannot pseudo-lock default group\n");
		return -EINVAL;
	}

	/*
	if (resctrl_arch_get_cdp_enabled(RDT_RESOURCE_L3) ||
	    resctrl_arch_get_cdp_enabled(RDT_RESOURCE_L2)) {
		rdt_last_cmd_puts("CDP enabled\n");
		return -EINVAL;
	}

	/*
	prefetch_disable_bits = get_prefetch_disable_bits();
	if (prefetch_disable_bits == 0) {
		rdt_last_cmd_puts("Pseudo-locking not supported\n");
		return -EINVAL;
	}

	if (rdtgroup_monitor_in_progress(rdtgrp)) {
		rdt_last_cmd_puts("Monitoring in progress\n");
		return -EINVAL;
	}

	if (rdtgroup_tasks_assigned(rdtgrp)) {
		rdt_last_cmd_puts("Tasks assigned to resource group\n");
		return -EINVAL;
	}

	if (!cpumask_empty(&rdtgrp->cpu_mask)) {
		rdt_last_cmd_puts("CPUs assigned to resource group\n");
		return -EINVAL;
	}

	if (rdtgroup_locksetup_user_restrict(rdtgrp)) {
		rdt_last_cmd_puts("Unable to modify resctrl permissions\n");
		return -EIO;
	}

	ret = pseudo_lock_init(rdtgrp);
	if (ret) {
		rdt_last_cmd_puts("Unable to init pseudo-lock region\n");
		goto out_release;
	}

	/*
	free_rmid(rdtgrp->mon.rmid);

	ret = 0;
	goto out;

out_release:
	rdtgroup_locksetup_user_restore(rdtgrp);
out:
	return ret;
}

int rdtgroup_locksetup_exit(struct rdtgroup *rdtgrp)
{
	int ret;

	if (rdt_mon_capable) {
		ret = alloc_rmid();
		if (ret < 0) {
			rdt_last_cmd_puts("Out of RMIDs\n");
			return ret;
		}
		rdtgrp->mon.rmid = ret;
	}

	ret = rdtgroup_locksetup_user_restore(rdtgrp);
	if (ret) {
		free_rmid(rdtgrp->mon.rmid);
		return ret;
	}

	pseudo_lock_free(rdtgrp);
	return 0;
}

bool rdtgroup_cbm_overlaps_pseudo_locked(struct rdt_domain *d, unsigned long cbm)
{
	unsigned int cbm_len;
	unsigned long cbm_b;

	if (d->plr) {
		cbm_len = d->plr->s->res->cache.cbm_len;
		cbm_b = d->plr->cbm;
		if (bitmap_intersects(&cbm, &cbm_b, cbm_len))
			return true;
	}
	return false;
}

bool rdtgroup_pseudo_locked_in_hierarchy(struct rdt_domain *d)
{
	cpumask_var_t cpu_with_psl;
	struct rdt_resource *r;
	struct rdt_domain *d_i;
	bool ret = false;

	if (!zalloc_cpumask_var(&cpu_with_psl, GFP_KERNEL))
		return true;

	/*
	for_each_alloc_enabled_rdt_resource(r) {
		list_for_each_entry(d_i, &r->domains, list) {
			if (d_i->plr)
				cpumask_or(cpu_with_psl, cpu_with_psl,
					   &d_i->cpu_mask);
		}
	}

	/*
	if (cpumask_intersects(&d->cpu_mask, cpu_with_psl))
		ret = true;

	free_cpumask_var(cpu_with_psl);
	return ret;
}

static int measure_cycles_lat_fn(void *_plr)
{
	struct pseudo_lock_region *plr = _plr;
	unsigned long i;
	u64 start, end;
	void *mem_r;

	local_irq_disable();
	/*
	wrmsr(MSR_MISC_FEATURE_CONTROL, prefetch_disable_bits, 0x0);
	mem_r = READ_ONCE(plr->kmem);
	/*
	start = rdtsc_ordered();
	for (i = 0; i < plr->size; i += 32) {
		start = rdtsc_ordered();
		asm volatile("mov (%0,%1,1), %%eax\n\t"
			     :
			     : "r" (mem_r), "r" (i)
			     : "%eax", "memory");
		end = rdtsc_ordered();
		trace_pseudo_lock_mem_latency((u32)(end - start));
	}
	wrmsr(MSR_MISC_FEATURE_CONTROL, 0x0, 0x0);
	local_irq_enable();
	plr->thread_done = 1;
	wake_up_interruptible(&plr->lock_thread_wq);
	return 0;
}

static struct perf_event_attr perf_miss_attr = {
	.type		= PERF_TYPE_RAW,
	.size		= sizeof(struct perf_event_attr),
	.pinned		= 1,
	.disabled	= 0,
	.exclude_user	= 1,
};

static struct perf_event_attr perf_hit_attr = {
	.type		= PERF_TYPE_RAW,
	.size		= sizeof(struct perf_event_attr),
	.pinned		= 1,
	.disabled	= 0,
	.exclude_user	= 1,
};

struct residency_counts {
	u64 miss_before, hits_before;
	u64 miss_after,  hits_after;
};

static int measure_residency_fn(struct perf_event_attr *miss_attr,
				struct perf_event_attr *hit_attr,
				struct pseudo_lock_region *plr,
				struct residency_counts *counts)
{
	u64 hits_before = 0, hits_after = 0, miss_before = 0, miss_after = 0;
	struct perf_event *miss_event, *hit_event;
	int hit_pmcnum, miss_pmcnum;
	unsigned int line_size;
	unsigned int size;
	unsigned long i;
	void *mem_r;
	u64 tmp;

	miss_event = perf_event_create_kernel_counter(miss_attr, plr->cpu,
						      NULL, NULL, NULL);
	if (IS_ERR(miss_event))
		goto out;

	hit_event = perf_event_create_kernel_counter(hit_attr, plr->cpu,
						     NULL, NULL, NULL);
	if (IS_ERR(hit_event))
		goto out_miss;

	local_irq_disable();
	/*
	if (perf_event_read_local(miss_event, &tmp, NULL, NULL)) {
		local_irq_enable();
		goto out_hit;
	}
	if (perf_event_read_local(hit_event, &tmp, NULL, NULL)) {
		local_irq_enable();
		goto out_hit;
	}

	/*
	wrmsr(MSR_MISC_FEATURE_CONTROL, prefetch_disable_bits, 0x0);

	/* Initialize rest of local variables */
	/*
	miss_pmcnum = x86_perf_rdpmc_index(miss_event);
	hit_pmcnum = x86_perf_rdpmc_index(hit_event);
	line_size = READ_ONCE(plr->line_size);
	mem_r = READ_ONCE(plr->kmem);
	size = READ_ONCE(plr->size);

	/*
	rdpmcl(hit_pmcnum, hits_before);
	rdpmcl(miss_pmcnum, miss_before);
	/*
	rmb();
	rdpmcl(hit_pmcnum, hits_before);
	rdpmcl(miss_pmcnum, miss_before);
	/*
	rmb();
	for (i = 0; i < size; i += line_size) {
		/*
		rmb();
		asm volatile("mov (%0,%1,1), %%eax\n\t"
			     :
			     : "r" (mem_r), "r" (i)
			     : "%eax", "memory");
	}
	/*
	rmb();
	rdpmcl(hit_pmcnum, hits_after);
	rdpmcl(miss_pmcnum, miss_after);
	/*
	rmb();
	/* Re-enable hardware prefetchers */
	wrmsr(MSR_MISC_FEATURE_CONTROL, 0x0, 0x0);
	local_irq_enable();
out_hit:
	perf_event_release_kernel(hit_event);
out_miss:
	perf_event_release_kernel(miss_event);
out:
	/*
	counts->miss_before = miss_before;
	counts->hits_before = hits_before;
	counts->miss_after  = miss_after;
	counts->hits_after  = hits_after;
	return 0;
}

static int measure_l2_residency(void *_plr)
{
	struct pseudo_lock_region *plr = _plr;
	struct residency_counts counts = {0};

	/*
	switch (boot_cpu_data.x86_model) {
	case INTEL_FAM6_ATOM_GOLDMONT:
	case INTEL_FAM6_ATOM_GOLDMONT_PLUS:
		perf_miss_attr.config = X86_CONFIG(.event = 0xd1,
						   .umask = 0x10);
		perf_hit_attr.config = X86_CONFIG(.event = 0xd1,
						  .umask = 0x2);
		break;
	default:
		goto out;
	}

	measure_residency_fn(&perf_miss_attr, &perf_hit_attr, plr, &counts);
	/*
	trace_pseudo_lock_l2(counts.hits_after - counts.hits_before,
			     counts.miss_after - counts.miss_before);
out:
	plr->thread_done = 1;
	wake_up_interruptible(&plr->lock_thread_wq);
	return 0;
}

static int measure_l3_residency(void *_plr)
{
	struct pseudo_lock_region *plr = _plr;
	struct residency_counts counts = {0};

	/*

	switch (boot_cpu_data.x86_model) {
	case INTEL_FAM6_BROADWELL_X:
		/* On BDW the hit event counts references, not hits */
		perf_hit_attr.config = X86_CONFIG(.event = 0x2e,
						  .umask = 0x4f);
		perf_miss_attr.config = X86_CONFIG(.event = 0x2e,
						   .umask = 0x41);
		break;
	default:
		goto out;
	}

	measure_residency_fn(&perf_miss_attr, &perf_hit_attr, plr, &counts);
	/*

	counts.miss_after -= counts.miss_before;
	if (boot_cpu_data.x86_model == INTEL_FAM6_BROADWELL_X) {
		/*
		/* First compute the number of cache references measured */
		counts.hits_after -= counts.hits_before;
		/* Next convert references to cache hits */
		counts.hits_after -= min(counts.miss_after, counts.hits_after);
	} else {
		counts.hits_after -= counts.hits_before;
	}

	trace_pseudo_lock_l3(counts.hits_after, counts.miss_after);
out:
	plr->thread_done = 1;
	wake_up_interruptible(&plr->lock_thread_wq);
	return 0;
}

static int pseudo_lock_measure_cycles(struct rdtgroup *rdtgrp, int sel)
{
	struct pseudo_lock_region *plr = rdtgrp->plr;
	struct task_struct *thread;
	unsigned int cpu;
	int ret = -1;

	cpus_read_lock();
	mutex_lock(&rdtgroup_mutex);

	if (rdtgrp->flags & RDT_DELETED) {
		ret = -ENODEV;
		goto out;
	}

	if (!plr->d) {
		ret = -ENODEV;
		goto out;
	}

	plr->thread_done = 0;
	cpu = cpumask_first(&plr->d->cpu_mask);
	if (!cpu_online(cpu)) {
		ret = -ENODEV;
		goto out;
	}

	plr->cpu = cpu;

	if (sel == 1)
		thread = kthread_create_on_node(measure_cycles_lat_fn, plr,
						cpu_to_node(cpu),
						"pseudo_lock_measure/%u",
						cpu);
	else if (sel == 2)
		thread = kthread_create_on_node(measure_l2_residency, plr,
						cpu_to_node(cpu),
						"pseudo_lock_measure/%u",
						cpu);
	else if (sel == 3)
		thread = kthread_create_on_node(measure_l3_residency, plr,
						cpu_to_node(cpu),
						"pseudo_lock_measure/%u",
						cpu);
	else
		goto out;

	if (IS_ERR(thread)) {
		ret = PTR_ERR(thread);
		goto out;
	}
	kthread_bind(thread, cpu);
	wake_up_process(thread);

	ret = wait_event_interruptible(plr->lock_thread_wq,
				       plr->thread_done == 1);
	if (ret < 0)
		goto out;

	ret = 0;

out:
	mutex_unlock(&rdtgroup_mutex);
	cpus_read_unlock();
	return ret;
}

static ssize_t pseudo_lock_measure_trigger(struct file *file,
					   const char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	struct rdtgroup *rdtgrp = file->private_data;
	size_t buf_size;
	char buf[32];
	int ret;
	int sel;

	buf_size = min(count, (sizeof(buf) - 1));
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;

	buf[buf_size] = '\0';
	ret = kstrtoint(buf, 10, &sel);
	if (ret == 0) {
		if (sel != 1 && sel != 2 && sel != 3)
			return -EINVAL;
		ret = debugfs_file_get(file->f_path.dentry);
		if (ret)
			return ret;
		ret = pseudo_lock_measure_cycles(rdtgrp, sel);
		if (ret == 0)
			ret = count;
		debugfs_file_put(file->f_path.dentry);
	}

	return ret;
}

static const struct file_operations pseudo_measure_fops = {
	.write = pseudo_lock_measure_trigger,
	.open = simple_open,
	.llseek = default_llseek,
};

int rdtgroup_pseudo_lock_create(struct rdtgroup *rdtgrp)
{
	struct pseudo_lock_region *plr = rdtgrp->plr;
	struct task_struct *thread;
	unsigned int new_minor;
	struct device *dev;
	int ret;

	ret = pseudo_lock_region_alloc(plr);
	if (ret < 0)
		return ret;

	ret = pseudo_lock_cstates_constrain(plr);
	if (ret < 0) {
		ret = -EINVAL;
		goto out_region;
	}

	plr->thread_done = 0;

	thread = kthread_create_on_node(pseudo_lock_fn, rdtgrp,
					cpu_to_node(plr->cpu),
					"pseudo_lock/%u", plr->cpu);
	if (IS_ERR(thread)) {
		ret = PTR_ERR(thread);
		rdt_last_cmd_printf("Locking thread returned error %d\n", ret);
		goto out_cstates;
	}

	kthread_bind(thread, plr->cpu);
	wake_up_process(thread);

	ret = wait_event_interruptible(plr->lock_thread_wq,
				       plr->thread_done == 1);
	if (ret < 0) {
		/*
		rdt_last_cmd_puts("Locking thread interrupted\n");
		goto out_cstates;
	}

	ret = pseudo_lock_minor_get(&new_minor);
	if (ret < 0) {
		rdt_last_cmd_puts("Unable to obtain a new minor number\n");
		goto out_cstates;
	}

	/*
	mutex_unlock(&rdtgroup_mutex);

	if (!IS_ERR_OR_NULL(debugfs_resctrl)) {
		plr->debugfs_dir = debugfs_create_dir(rdtgrp->kn->name,
						      debugfs_resctrl);
		if (!IS_ERR_OR_NULL(plr->debugfs_dir))
			debugfs_create_file("pseudo_lock_measure", 0200,
					    plr->debugfs_dir, rdtgrp,
					    &pseudo_measure_fops);
	}

	dev = device_create(pseudo_lock_class, NULL,
			    MKDEV(pseudo_lock_major, new_minor),
			    rdtgrp, "%s", rdtgrp->kn->name);

	mutex_lock(&rdtgroup_mutex);

	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		rdt_last_cmd_printf("Failed to create character device: %d\n",
				    ret);
		goto out_debugfs;
	}

	/* We released the mutex - check if group was removed while we did so */
	if (rdtgrp->flags & RDT_DELETED) {
		ret = -ENODEV;
		goto out_device;
	}

	plr->minor = new_minor;

	rdtgrp->mode = RDT_MODE_PSEUDO_LOCKED;
	closid_free(rdtgrp->closid);
	rdtgroup_kn_mode_restore(rdtgrp, "cpus", 0444);
	rdtgroup_kn_mode_restore(rdtgrp, "cpus_list", 0444);

	ret = 0;
	goto out;

out_device:
	device_destroy(pseudo_lock_class, MKDEV(pseudo_lock_major, new_minor));
out_debugfs:
	debugfs_remove_recursive(plr->debugfs_dir);
	pseudo_lock_minor_release(new_minor);
out_cstates:
	pseudo_lock_cstates_relax(plr);
out_region:
	pseudo_lock_region_clear(plr);
out:
	return ret;
}

void rdtgroup_pseudo_lock_remove(struct rdtgroup *rdtgrp)
{
	struct pseudo_lock_region *plr = rdtgrp->plr;

	if (rdtgrp->mode == RDT_MODE_PSEUDO_LOCKSETUP) {
		/*
		closid_free(rdtgrp->closid);
		goto free;
	}

	pseudo_lock_cstates_relax(plr);
	debugfs_remove_recursive(rdtgrp->plr->debugfs_dir);
	device_destroy(pseudo_lock_class, MKDEV(pseudo_lock_major, plr->minor));
	pseudo_lock_minor_release(plr->minor);

free:
	pseudo_lock_free(rdtgrp);
}

static int pseudo_lock_dev_open(struct inode *inode, struct file *filp)
{
	struct rdtgroup *rdtgrp;

	mutex_lock(&rdtgroup_mutex);

	rdtgrp = region_find_by_minor(iminor(inode));
	if (!rdtgrp) {
		mutex_unlock(&rdtgroup_mutex);
		return -ENODEV;
	}

	filp->private_data = rdtgrp;
	atomic_inc(&rdtgrp->waitcount);
	/* Perform a non-seekable open - llseek is not supported */
	filp->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	mutex_unlock(&rdtgroup_mutex);

	return 0;
}

static int pseudo_lock_dev_release(struct inode *inode, struct file *filp)
{
	struct rdtgroup *rdtgrp;

	mutex_lock(&rdtgroup_mutex);
	rdtgrp = filp->private_data;
	WARN_ON(!rdtgrp);
	if (!rdtgrp) {
		mutex_unlock(&rdtgroup_mutex);
		return -ENODEV;
	}
	filp->private_data = NULL;
	atomic_dec(&rdtgrp->waitcount);
	mutex_unlock(&rdtgroup_mutex);
	return 0;
}

static int pseudo_lock_dev_mremap(struct vm_area_struct *area)
{
	/* Not supported */
	return -EINVAL;
}

static const struct vm_operations_struct pseudo_mmap_ops = {
	.mremap = pseudo_lock_dev_mremap,
};

static int pseudo_lock_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long vsize = vma->vm_end - vma->vm_start;
	unsigned long off = vma->vm_pgoff << PAGE_SHIFT;
	struct pseudo_lock_region *plr;
	struct rdtgroup *rdtgrp;
	unsigned long physical;
	unsigned long psize;

	mutex_lock(&rdtgroup_mutex);

	rdtgrp = filp->private_data;
	WARN_ON(!rdtgrp);
	if (!rdtgrp) {
		mutex_unlock(&rdtgroup_mutex);
		return -ENODEV;
	}

	plr = rdtgrp->plr;

	if (!plr->d) {
		mutex_unlock(&rdtgroup_mutex);
		return -ENODEV;
	}

	/*
	if (!cpumask_subset(current->cpus_ptr, &plr->d->cpu_mask)) {
		mutex_unlock(&rdtgroup_mutex);
		return -EINVAL;
	}

	physical = __pa(plr->kmem) >> PAGE_SHIFT;
	psize = plr->size - off;

	if (off > plr->size) {
		mutex_unlock(&rdtgroup_mutex);
		return -ENOSPC;
	}

	/*
	if (!(vma->vm_flags & VM_SHARED)) {
		mutex_unlock(&rdtgroup_mutex);
		return -EINVAL;
	}

	if (vsize > psize) {
		mutex_unlock(&rdtgroup_mutex);
		return -ENOSPC;
	}

	memset(plr->kmem + off, 0, vsize);

	if (remap_pfn_range(vma, vma->vm_start, physical + vma->vm_pgoff,
			    vsize, vma->vm_page_prot)) {
		mutex_unlock(&rdtgroup_mutex);
		return -EAGAIN;
	}
	vma->vm_ops = &pseudo_mmap_ops;
	mutex_unlock(&rdtgroup_mutex);
	return 0;
}

static const struct file_operations pseudo_lock_dev_fops = {
	.owner =	THIS_MODULE,
	.llseek =	no_llseek,
	.read =		NULL,
	.write =	NULL,
	.open =		pseudo_lock_dev_open,
	.release =	pseudo_lock_dev_release,
	.mmap =		pseudo_lock_dev_mmap,
};

static char *pseudo_lock_devnode(struct device *dev, umode_t *mode)
{
	struct rdtgroup *rdtgrp;

	rdtgrp = dev_get_drvdata(dev);
	if (mode)
		*mode = 0600;
	return kasprintf(GFP_KERNEL, "pseudo_lock/%s", rdtgrp->kn->name);
}

int rdt_pseudo_lock_init(void)
{
	int ret;

	ret = register_chrdev(0, "pseudo_lock", &pseudo_lock_dev_fops);
	if (ret < 0)
		return ret;

	pseudo_lock_major = ret;

	pseudo_lock_class = class_create(THIS_MODULE, "pseudo_lock");
	if (IS_ERR(pseudo_lock_class)) {
		ret = PTR_ERR(pseudo_lock_class);
		unregister_chrdev(pseudo_lock_major, "pseudo_lock");
		return ret;
	}

	pseudo_lock_class->devnode = pseudo_lock_devnode;
	return 0;
}

void rdt_pseudo_lock_release(void)
{
	class_destroy(pseudo_lock_class);
	pseudo_lock_class = NULL;
	unregister_chrdev(pseudo_lock_major, "pseudo_lock");
	pseudo_lock_major = 0;
}
