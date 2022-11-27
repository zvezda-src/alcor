
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/cpu_device_id.h>
#include "internal.h"

struct rmid_entry {
	u32				rmid;
	int				busy;
	struct list_head		list;
};

static LIST_HEAD(rmid_free_lru);

static unsigned int rmid_limbo_count;

static struct rmid_entry	*rmid_ptrs;

bool rdt_mon_capable;

unsigned int rdt_mon_features;

unsigned int resctrl_cqm_threshold;

#define CF(cf)	((unsigned long)(1048576 * (cf) + 0.5))

static const struct mbm_correction_factor_table {
	u32 rmidthreshold;
	u64 cf;
} mbm_cf_table[] __initconst = {
	{7,	CF(1.000000)},
	{15,	CF(1.000000)},
	{15,	CF(0.969650)},
	{31,	CF(1.000000)},
	{31,	CF(1.066667)},
	{31,	CF(0.969650)},
	{47,	CF(1.142857)},
	{63,	CF(1.000000)},
	{63,	CF(1.185115)},
	{63,	CF(1.066553)},
	{79,	CF(1.454545)},
	{95,	CF(1.000000)},
	{95,	CF(1.230769)},
	{95,	CF(1.142857)},
	{95,	CF(1.066667)},
	{127,	CF(1.000000)},
	{127,	CF(1.254863)},
	{127,	CF(1.185255)},
	{151,	CF(1.000000)},
	{127,	CF(1.066667)},
	{167,	CF(1.000000)},
	{159,	CF(1.454334)},
	{183,	CF(1.000000)},
	{127,	CF(0.969744)},
	{191,	CF(1.280246)},
	{191,	CF(1.230921)},
	{215,	CF(1.000000)},
	{191,	CF(1.143118)},
};

static u32 mbm_cf_rmidthreshold __read_mostly = UINT_MAX;
static u64 mbm_cf __read_mostly;

static inline u64 get_corrected_mbm_count(u32 rmid, unsigned long val)
{
	/* Correct MBM value. */
	if (rmid > mbm_cf_rmidthreshold)
		val = (val * mbm_cf) >> 20;

	return val;
}

static inline struct rmid_entry *__rmid_entry(u32 rmid)
{
	struct rmid_entry *entry;

	entry = &rmid_ptrs[rmid];
	WARN_ON(entry->rmid != rmid);

	return entry;
}

static u64 __rmid_read(u32 rmid, u32 eventid)
{
	u64 val;

	/*
	wrmsr(MSR_IA32_QM_EVTSEL, eventid, rmid);
	rdmsrl(MSR_IA32_QM_CTR, val);

	return val;
}

static bool rmid_dirty(struct rmid_entry *entry)
{
	u64 val = __rmid_read(entry->rmid, QOS_L3_OCCUP_EVENT_ID);

	return val >= resctrl_cqm_threshold;
}

void __check_limbo(struct rdt_domain *d, bool force_free)
{
	struct rmid_entry *entry;
	struct rdt_resource *r;
	u32 crmid = 1, nrmid;

	r = &rdt_resources_all[RDT_RESOURCE_L3].r_resctrl;

	/*
	for (;;) {
		nrmid = find_next_bit(d->rmid_busy_llc, r->num_rmid, crmid);
		if (nrmid >= r->num_rmid)
			break;

		entry = __rmid_entry(nrmid);
		if (force_free || !rmid_dirty(entry)) {
			clear_bit(entry->rmid, d->rmid_busy_llc);
			if (!--entry->busy) {
				rmid_limbo_count--;
				list_add_tail(&entry->list, &rmid_free_lru);
			}
		}
		crmid = nrmid + 1;
	}
}

bool has_busy_rmid(struct rdt_resource *r, struct rdt_domain *d)
{
	return find_first_bit(d->rmid_busy_llc, r->num_rmid) != r->num_rmid;
}

int alloc_rmid(void)
{
	struct rmid_entry *entry;

	lockdep_assert_held(&rdtgroup_mutex);

	if (list_empty(&rmid_free_lru))
		return rmid_limbo_count ? -EBUSY : -ENOSPC;

	entry = list_first_entry(&rmid_free_lru,
				 struct rmid_entry, list);
	list_del(&entry->list);

	return entry->rmid;
}

static void add_rmid_to_limbo(struct rmid_entry *entry)
{
	struct rdt_resource *r;
	struct rdt_domain *d;
	int cpu;
	u64 val;

	r = &rdt_resources_all[RDT_RESOURCE_L3].r_resctrl;

	entry->busy = 0;
	cpu = get_cpu();
	list_for_each_entry(d, &r->domains, list) {
		if (cpumask_test_cpu(cpu, &d->cpu_mask)) {
			val = __rmid_read(entry->rmid, QOS_L3_OCCUP_EVENT_ID);
			if (val <= resctrl_cqm_threshold)
				continue;
		}

		/*
		if (!has_busy_rmid(r, d))
			cqm_setup_limbo_handler(d, CQM_LIMBOCHECK_INTERVAL);
		set_bit(entry->rmid, d->rmid_busy_llc);
		entry->busy++;
	}
	put_cpu();

	if (entry->busy)
		rmid_limbo_count++;
	else
		list_add_tail(&entry->list, &rmid_free_lru);
}

void free_rmid(u32 rmid)
{
	struct rmid_entry *entry;

	if (!rmid)
		return;

	lockdep_assert_held(&rdtgroup_mutex);

	entry = __rmid_entry(rmid);

	if (is_llc_occupancy_enabled())
		add_rmid_to_limbo(entry);
	else
		list_add_tail(&entry->list, &rmid_free_lru);
}

static u64 mbm_overflow_count(u64 prev_msr, u64 cur_msr, unsigned int width)
{
	u64 shift = 64 - width, chunks;

	chunks = (cur_msr << shift) - (prev_msr << shift);
	return chunks >> shift;
}

static u64 __mon_event_count(u32 rmid, struct rmid_read *rr)
{
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(rr->r);
	struct mbm_state *m;
	u64 chunks, tval;

	tval = __rmid_read(rmid, rr->evtid);
	if (tval & (RMID_VAL_ERROR | RMID_VAL_UNAVAIL)) {
		return tval;
	}
	switch (rr->evtid) {
	case QOS_L3_OCCUP_EVENT_ID:
		rr->val += tval;
		return 0;
	case QOS_L3_MBM_TOTAL_EVENT_ID:
		m = &rr->d->mbm_total[rmid];
		break;
	case QOS_L3_MBM_LOCAL_EVENT_ID:
		m = &rr->d->mbm_local[rmid];
		break;
	default:
		/*
		return RMID_VAL_ERROR;
	}

	if (rr->first) {
		memset(m, 0, sizeof(struct mbm_state));
		m->prev_bw_msr = m->prev_msr = tval;
		return 0;
	}

	chunks = mbm_overflow_count(m->prev_msr, tval, hw_res->mbm_width);
	m->chunks += chunks;
	m->prev_msr = tval;

	rr->val += get_corrected_mbm_count(rmid, m->chunks);

	return 0;
}

static void mbm_bw_count(u32 rmid, struct rmid_read *rr)
{
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(rr->r);
	struct mbm_state *m = &rr->d->mbm_local[rmid];
	u64 tval, cur_bw, chunks;

	tval = __rmid_read(rmid, rr->evtid);
	if (tval & (RMID_VAL_ERROR | RMID_VAL_UNAVAIL))
		return;

	chunks = mbm_overflow_count(m->prev_bw_msr, tval, hw_res->mbm_width);
	cur_bw = (get_corrected_mbm_count(rmid, chunks) * hw_res->mon_scale) >> 20;

	if (m->delta_comp)
		m->delta_bw = abs(cur_bw - m->prev_bw);
	m->delta_comp = false;
	m->prev_bw = cur_bw;
	m->prev_bw_msr = tval;
}

void mon_event_count(void *info)
{
	struct rdtgroup *rdtgrp, *entry;
	struct rmid_read *rr = info;
	struct list_head *head;
	u64 ret_val;

	rdtgrp = rr->rgrp;

	ret_val = __mon_event_count(rdtgrp->mon.rmid, rr);

	/*
	head = &rdtgrp->mon.crdtgrp_list;

	if (rdtgrp->type == RDTCTRL_GROUP) {
		list_for_each_entry(entry, head, mon.crdtgrp_list) {
			if (__mon_event_count(entry->mon.rmid, rr) == 0)
				ret_val = 0;
		}
	}

	/* Report error if none of rmid_reads are successful */
	if (ret_val)
		rr->val = ret_val;
}

static void update_mba_bw(struct rdtgroup *rgrp, struct rdt_domain *dom_mbm)
{
	u32 closid, rmid, cur_msr, cur_msr_val, new_msr_val;
	struct mbm_state *pmbm_data, *cmbm_data;
	struct rdt_hw_resource *hw_r_mba;
	struct rdt_hw_domain *hw_dom_mba;
	u32 cur_bw, delta_bw, user_bw;
	struct rdt_resource *r_mba;
	struct rdt_domain *dom_mba;
	struct list_head *head;
	struct rdtgroup *entry;

	if (!is_mbm_local_enabled())
		return;

	hw_r_mba = &rdt_resources_all[RDT_RESOURCE_MBA];
	r_mba = &hw_r_mba->r_resctrl;
	closid = rgrp->closid;
	rmid = rgrp->mon.rmid;
	pmbm_data = &dom_mbm->mbm_local[rmid];

	dom_mba = get_domain_from_cpu(smp_processor_id(), r_mba);
	if (!dom_mba) {
		pr_warn_once("Failure to get domain for MBA update\n");
		return;
	}
	hw_dom_mba = resctrl_to_arch_dom(dom_mba);

	cur_bw = pmbm_data->prev_bw;
	user_bw = resctrl_arch_get_config(r_mba, dom_mba, closid, CDP_NONE);
	delta_bw = pmbm_data->delta_bw;
	/*
	cur_msr_val = hw_dom_mba->ctrl_val[closid];

	/*
	head = &rgrp->mon.crdtgrp_list;
	list_for_each_entry(entry, head, mon.crdtgrp_list) {
		cmbm_data = &dom_mbm->mbm_local[entry->mon.rmid];
		cur_bw += cmbm_data->prev_bw;
		delta_bw += cmbm_data->delta_bw;
	}

	/*
	if (cur_msr_val > r_mba->membw.min_bw && user_bw < cur_bw) {
		new_msr_val = cur_msr_val - r_mba->membw.bw_gran;
	} else if (cur_msr_val < MAX_MBA_BW &&
		   (user_bw > (cur_bw + delta_bw))) {
		new_msr_val = cur_msr_val + r_mba->membw.bw_gran;
	} else {
		return;
	}

	cur_msr = hw_r_mba->msr_base + closid;
	wrmsrl(cur_msr, delay_bw_map(new_msr_val, r_mba));
	hw_dom_mba->ctrl_val[closid] = new_msr_val;

	/*
	pmbm_data->delta_comp = true;
	list_for_each_entry(entry, head, mon.crdtgrp_list) {
		cmbm_data = &dom_mbm->mbm_local[entry->mon.rmid];
		cmbm_data->delta_comp = true;
	}
}

static void mbm_update(struct rdt_resource *r, struct rdt_domain *d, int rmid)
{
	struct rmid_read rr;

	rr.first = false;
	rr.r = r;
	rr.d = d;

	/*
	if (is_mbm_total_enabled()) {
		rr.evtid = QOS_L3_MBM_TOTAL_EVENT_ID;
		__mon_event_count(rmid, &rr);
	}
	if (is_mbm_local_enabled()) {
		rr.evtid = QOS_L3_MBM_LOCAL_EVENT_ID;
		__mon_event_count(rmid, &rr);

		/*
		if (is_mba_sc(NULL))
			mbm_bw_count(rmid, &rr);
	}
}

void cqm_handle_limbo(struct work_struct *work)
{
	unsigned long delay = msecs_to_jiffies(CQM_LIMBOCHECK_INTERVAL);
	int cpu = smp_processor_id();
	struct rdt_resource *r;
	struct rdt_domain *d;

	mutex_lock(&rdtgroup_mutex);

	r = &rdt_resources_all[RDT_RESOURCE_L3].r_resctrl;
	d = container_of(work, struct rdt_domain, cqm_limbo.work);

	__check_limbo(d, false);

	if (has_busy_rmid(r, d))
		schedule_delayed_work_on(cpu, &d->cqm_limbo, delay);

	mutex_unlock(&rdtgroup_mutex);
}

void cqm_setup_limbo_handler(struct rdt_domain *dom, unsigned long delay_ms)
{
	unsigned long delay = msecs_to_jiffies(delay_ms);
	int cpu;

	cpu = cpumask_any(&dom->cpu_mask);
	dom->cqm_work_cpu = cpu;

	schedule_delayed_work_on(cpu, &dom->cqm_limbo, delay);
}

void mbm_handle_overflow(struct work_struct *work)
{
	unsigned long delay = msecs_to_jiffies(MBM_OVERFLOW_INTERVAL);
	struct rdtgroup *prgrp, *crgrp;
	int cpu = smp_processor_id();
	struct list_head *head;
	struct rdt_resource *r;
	struct rdt_domain *d;

	mutex_lock(&rdtgroup_mutex);

	if (!static_branch_likely(&rdt_mon_enable_key))
		goto out_unlock;

	r = &rdt_resources_all[RDT_RESOURCE_L3].r_resctrl;
	d = container_of(work, struct rdt_domain, mbm_over.work);

	list_for_each_entry(prgrp, &rdt_all_groups, rdtgroup_list) {
		mbm_update(r, d, prgrp->mon.rmid);

		head = &prgrp->mon.crdtgrp_list;
		list_for_each_entry(crgrp, head, mon.crdtgrp_list)
			mbm_update(r, d, crgrp->mon.rmid);

		if (is_mba_sc(NULL))
			update_mba_bw(prgrp, d);
	}

	schedule_delayed_work_on(cpu, &d->mbm_over, delay);

out_unlock:
	mutex_unlock(&rdtgroup_mutex);
}

void mbm_setup_overflow_handler(struct rdt_domain *dom, unsigned long delay_ms)
{
	unsigned long delay = msecs_to_jiffies(delay_ms);
	int cpu;

	if (!static_branch_likely(&rdt_mon_enable_key))
		return;
	cpu = cpumask_any(&dom->cpu_mask);
	dom->mbm_work_cpu = cpu;
	schedule_delayed_work_on(cpu, &dom->mbm_over, delay);
}

static int dom_data_init(struct rdt_resource *r)
{
	struct rmid_entry *entry = NULL;
	int i, nr_rmids;

	nr_rmids = r->num_rmid;
	rmid_ptrs = kcalloc(nr_rmids, sizeof(struct rmid_entry), GFP_KERNEL);
	if (!rmid_ptrs)
		return -ENOMEM;

	for (i = 0; i < nr_rmids; i++) {
		entry = &rmid_ptrs[i];
		INIT_LIST_HEAD(&entry->list);

		entry->rmid = i;
		list_add_tail(&entry->list, &rmid_free_lru);
	}

	/*
	entry = __rmid_entry(0);
	list_del(&entry->list);

	return 0;
}

static struct mon_evt llc_occupancy_event = {
	.name		= "llc_occupancy",
	.evtid		= QOS_L3_OCCUP_EVENT_ID,
};

static struct mon_evt mbm_total_event = {
	.name		= "mbm_total_bytes",
	.evtid		= QOS_L3_MBM_TOTAL_EVENT_ID,
};

static struct mon_evt mbm_local_event = {
	.name		= "mbm_local_bytes",
	.evtid		= QOS_L3_MBM_LOCAL_EVENT_ID,
};

static void l3_mon_evt_init(struct rdt_resource *r)
{
	INIT_LIST_HEAD(&r->evt_list);

	if (is_llc_occupancy_enabled())
		list_add_tail(&llc_occupancy_event.list, &r->evt_list);
	if (is_mbm_total_enabled())
		list_add_tail(&mbm_total_event.list, &r->evt_list);
	if (is_mbm_local_enabled())
		list_add_tail(&mbm_local_event.list, &r->evt_list);
}

int rdt_get_mon_l3_config(struct rdt_resource *r)
{
	unsigned int mbm_offset = boot_cpu_data.x86_cache_mbm_width_offset;
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(r);
	unsigned int cl_size = boot_cpu_data.x86_cache_size;
	int ret;

	hw_res->mon_scale = boot_cpu_data.x86_cache_occ_scale;
	r->num_rmid = boot_cpu_data.x86_cache_max_rmid + 1;
	hw_res->mbm_width = MBM_CNTR_WIDTH_BASE;

	if (mbm_offset > 0 && mbm_offset <= MBM_CNTR_WIDTH_OFFSET_MAX)
		hw_res->mbm_width += mbm_offset;
	else if (mbm_offset > MBM_CNTR_WIDTH_OFFSET_MAX)
		pr_warn("Ignoring impossible MBM counter offset\n");

	/*
	resctrl_cqm_threshold = cl_size * 1024 / r->num_rmid;

	/* h/w works in units of "boot_cpu_data.x86_cache_occ_scale" */
	resctrl_cqm_threshold /= hw_res->mon_scale;

	ret = dom_data_init(r);
	if (ret)
		return ret;

	l3_mon_evt_init(r);

	r->mon_capable = true;
	r->mon_enabled = true;

	return 0;
}

void __init intel_rdt_mbm_apply_quirk(void)
{
	int cf_index;

	cf_index = (boot_cpu_data.x86_cache_max_rmid + 1) / 8 - 1;
	if (cf_index >= ARRAY_SIZE(mbm_cf_table)) {
		pr_info("No MBM correction factor available\n");
		return;
	}

	mbm_cf_rmidthreshold = mbm_cf_table[cf_index].rmidthreshold;
	mbm_cf = mbm_cf_table[cf_index].cf;
}
