#ifndef _ASM_X86_RESCTRL_INTERNAL_H
#define _ASM_X86_RESCTRL_INTERNAL_H

#include <linux/resctrl.h>
#include <linux/sched.h>
#include <linux/kernfs.h>
#include <linux/fs_context.h>
#include <linux/jump_label.h>

#define MSR_IA32_L3_QOS_CFG		0xc81
#define MSR_IA32_L2_QOS_CFG		0xc82
#define MSR_IA32_L3_CBM_BASE		0xc90
#define MSR_IA32_L2_CBM_BASE		0xd10
#define MSR_IA32_MBA_THRTL_BASE		0xd50
#define MSR_IA32_MBA_BW_BASE		0xc0000200

#define MSR_IA32_QM_CTR			0x0c8e
#define MSR_IA32_QM_EVTSEL		0x0c8d

#define L3_QOS_CDP_ENABLE		0x01ULL

#define L2_QOS_CDP_ENABLE		0x01ULL

#define QOS_L3_OCCUP_EVENT_ID		0x01
#define QOS_L3_MBM_TOTAL_EVENT_ID	0x02
#define QOS_L3_MBM_LOCAL_EVENT_ID	0x03

#define CQM_LIMBOCHECK_INTERVAL	1000

#define MBM_CNTR_WIDTH_BASE		24
#define MBM_OVERFLOW_INTERVAL		1000
#define MAX_MBA_BW			100u
#define MBA_IS_LINEAR			0x4
#define MBA_MAX_MBPS			U32_MAX
#define MAX_MBA_BW_AMD			0x800
#define MBM_CNTR_WIDTH_OFFSET_AMD	20

#define RMID_VAL_ERROR			BIT_ULL(63)
#define RMID_VAL_UNAVAIL		BIT_ULL(62)
#define MBM_CNTR_WIDTH_OFFSET_MAX (62 - MBM_CNTR_WIDTH_BASE)


struct rdt_fs_context {
	struct kernfs_fs_context	kfc;
	bool				enable_cdpl2;
	bool				enable_cdpl3;
	bool				enable_mba_mbps;
};

static inline struct rdt_fs_context *rdt_fc2context(struct fs_context *fc)
{
	struct kernfs_fs_context *kfc = fc->fs_private;

	return container_of(kfc, struct rdt_fs_context, kfc);
}

DECLARE_STATIC_KEY_FALSE(rdt_enable_key);
DECLARE_STATIC_KEY_FALSE(rdt_mon_enable_key);

struct mon_evt {
	u32			evtid;
	char			*name;
	struct list_head	list;
};

union mon_data_bits {
	void *priv;
	struct {
		unsigned int rid	: 10;
		unsigned int evtid	: 8;
		unsigned int domid	: 14;
	} u;
};

struct rmid_read {
	struct rdtgroup		*rgrp;
	struct rdt_resource	*r;
	struct rdt_domain	*d;
	int			evtid;
	bool			first;
	u64			val;
};

extern unsigned int resctrl_cqm_threshold;
extern bool rdt_alloc_capable;
extern bool rdt_mon_capable;
extern unsigned int rdt_mon_features;
extern struct list_head resctrl_schema_all;

enum rdt_group_type {
	RDTCTRL_GROUP = 0,
	RDTMON_GROUP,
	RDT_NUM_GROUP,
};

enum rdtgrp_mode {
	RDT_MODE_SHAREABLE = 0,
	RDT_MODE_EXCLUSIVE,
	RDT_MODE_PSEUDO_LOCKSETUP,
	RDT_MODE_PSEUDO_LOCKED,

	/* Must be last */
	RDT_NUM_MODES,
};

struct mongroup {
	struct kernfs_node	*mon_data_kn;
	struct rdtgroup		*parent;
	struct list_head	crdtgrp_list;
	u32			rmid;
};

struct pseudo_lock_region {
	struct resctrl_schema	*s;
	struct rdt_domain	*d;
	u32			cbm;
	wait_queue_head_t	lock_thread_wq;
	int			thread_done;
	int			cpu;
	unsigned int		line_size;
	unsigned int		size;
	void			*kmem;
	unsigned int		minor;
	struct dentry		*debugfs_dir;
	struct list_head	pm_reqs;
};

struct rdtgroup {
	struct kernfs_node		*kn;
	struct list_head		rdtgroup_list;
	u32				closid;
	struct cpumask			cpu_mask;
	int				flags;
	atomic_t			waitcount;
	enum rdt_group_type		type;
	struct mongroup			mon;
	enum rdtgrp_mode		mode;
	struct pseudo_lock_region	*plr;
};

#define	RDT_DELETED		1

#define RFTYPE_FLAGS_CPUS_LIST	1

#define RFTYPE_INFO			BIT(0)
#define RFTYPE_BASE			BIT(1)
#define RF_CTRLSHIFT			4
#define RF_MONSHIFT			5
#define RF_TOPSHIFT			6
#define RFTYPE_CTRL			BIT(RF_CTRLSHIFT)
#define RFTYPE_MON			BIT(RF_MONSHIFT)
#define RFTYPE_TOP			BIT(RF_TOPSHIFT)
#define RFTYPE_RES_CACHE		BIT(8)
#define RFTYPE_RES_MB			BIT(9)
#define RF_CTRL_INFO			(RFTYPE_INFO | RFTYPE_CTRL)
#define RF_MON_INFO			(RFTYPE_INFO | RFTYPE_MON)
#define RF_TOP_INFO			(RFTYPE_INFO | RFTYPE_TOP)
#define RF_CTRL_BASE			(RFTYPE_BASE | RFTYPE_CTRL)

extern struct list_head rdt_all_groups;

extern int max_name_width, max_data_width;

int __init rdtgroup_init(void);
void __exit rdtgroup_exit(void);

struct rftype {
	char			*name;
	umode_t			mode;
	const struct kernfs_ops	*kf_ops;
	unsigned long		flags;
	unsigned long		fflags;

	int (*seq_show)(struct kernfs_open_file *of,
			struct seq_file *sf, void *v);
	/*
	ssize_t (*write)(struct kernfs_open_file *of,
			 char *buf, size_t nbytes, loff_t off);
};

struct mbm_state {
	u64	chunks;
	u64	prev_msr;
	u64	prev_bw_msr;
	u32	prev_bw;
	u32	delta_bw;
	bool	delta_comp;
};

struct rdt_hw_domain {
	struct rdt_domain		d_resctrl;
	u32				*ctrl_val;
	u32				*mbps_val;
};

static inline struct rdt_hw_domain *resctrl_to_arch_dom(struct rdt_domain *r)
{
	return container_of(r, struct rdt_hw_domain, d_resctrl);
}

struct msr_param {
	struct rdt_resource	*res;
	u32			low;
	u32			high;
};

static inline bool is_llc_occupancy_enabled(void)
{
	return (rdt_mon_features & (1 << QOS_L3_OCCUP_EVENT_ID));
}

static inline bool is_mbm_total_enabled(void)
{
	return (rdt_mon_features & (1 << QOS_L3_MBM_TOTAL_EVENT_ID));
}

static inline bool is_mbm_local_enabled(void)
{
	return (rdt_mon_features & (1 << QOS_L3_MBM_LOCAL_EVENT_ID));
}

static inline bool is_mbm_enabled(void)
{
	return (is_mbm_total_enabled() || is_mbm_local_enabled());
}

static inline bool is_mbm_event(int e)
{
	return (e >= QOS_L3_MBM_TOTAL_EVENT_ID &&
		e <= QOS_L3_MBM_LOCAL_EVENT_ID);
}

struct rdt_parse_data {
	struct rdtgroup		*rdtgrp;
	char			*buf;
};

struct rdt_hw_resource {
	struct rdt_resource	r_resctrl;
	u32			num_closid;
	unsigned int		msr_base;
	void (*msr_update)	(struct rdt_domain *d, struct msr_param *m,
				 struct rdt_resource *r);
	unsigned int		mon_scale;
	unsigned int		mbm_width;
	bool			cdp_enabled;
};

static inline struct rdt_hw_resource *resctrl_to_arch_res(struct rdt_resource *r)
{
	return container_of(r, struct rdt_hw_resource, r_resctrl);
}

int parse_cbm(struct rdt_parse_data *data, struct resctrl_schema *s,
	      struct rdt_domain *d);
int parse_bw(struct rdt_parse_data *data, struct resctrl_schema *s,
	     struct rdt_domain *d);

extern struct mutex rdtgroup_mutex;

extern struct rdt_hw_resource rdt_resources_all[];
extern struct rdtgroup rdtgroup_default;
DECLARE_STATIC_KEY_FALSE(rdt_alloc_enable_key);

extern struct dentry *debugfs_resctrl;

enum resctrl_res_level {
	RDT_RESOURCE_L3,
	RDT_RESOURCE_L2,
	RDT_RESOURCE_MBA,

	/* Must be the last */
	RDT_NUM_RESOURCES,
};

static inline struct rdt_resource *resctrl_inc(struct rdt_resource *res)
{
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(res);

	hw_res++;
	return &hw_res->r_resctrl;
}

static inline bool resctrl_arch_get_cdp_enabled(enum resctrl_res_level l)
{
	return rdt_resources_all[l].cdp_enabled;
}

int resctrl_arch_set_cdp_enabled(enum resctrl_res_level l, bool enable);

#define for_each_rdt_resource(r)					      \
	for (r = &rdt_resources_all[0].r_resctrl;			      \
	     r <= &rdt_resources_all[RDT_NUM_RESOURCES - 1].r_resctrl;	      \
	     r = resctrl_inc(r))

#define for_each_capable_rdt_resource(r)				      \
	for_each_rdt_resource(r)					      \
		if (r->alloc_capable || r->mon_capable)

#define for_each_alloc_capable_rdt_resource(r)				      \
	for_each_rdt_resource(r)					      \
		if (r->alloc_capable)

#define for_each_mon_capable_rdt_resource(r)				      \
	for_each_rdt_resource(r)					      \
		if (r->mon_capable)

#define for_each_alloc_enabled_rdt_resource(r)				      \
	for_each_rdt_resource(r)					      \
		if (r->alloc_enabled)

#define for_each_mon_enabled_rdt_resource(r)				      \
	for_each_rdt_resource(r)					      \
		if (r->mon_enabled)

union cpuid_0x10_1_eax {
	struct {
		unsigned int cbm_len:5;
	} split;
	unsigned int full;
};

union cpuid_0x10_3_eax {
	struct {
		unsigned int max_delay:12;
	} split;
	unsigned int full;
};

union cpuid_0x10_x_edx {
	struct {
		unsigned int cos_max:16;
	} split;
	unsigned int full;
};

void rdt_last_cmd_clear(void);
void rdt_last_cmd_puts(const char *s);
__printf(1, 2)
void rdt_last_cmd_printf(const char *fmt, ...);

void rdt_ctrl_update(void *arg);
struct rdtgroup *rdtgroup_kn_lock_live(struct kernfs_node *kn);
void rdtgroup_kn_unlock(struct kernfs_node *kn);
int rdtgroup_kn_mode_restrict(struct rdtgroup *r, const char *name);
int rdtgroup_kn_mode_restore(struct rdtgroup *r, const char *name,
			     umode_t mask);
struct rdt_domain *rdt_find_domain(struct rdt_resource *r, int id,
				   struct list_head **pos);
ssize_t rdtgroup_schemata_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off);
int rdtgroup_schemata_show(struct kernfs_open_file *of,
			   struct seq_file *s, void *v);
bool rdtgroup_cbm_overlaps(struct resctrl_schema *s, struct rdt_domain *d,
			   unsigned long cbm, int closid, bool exclusive);
unsigned int rdtgroup_cbm_to_size(struct rdt_resource *r, struct rdt_domain *d,
				  unsigned long cbm);
enum rdtgrp_mode rdtgroup_mode_by_closid(int closid);
int rdtgroup_tasks_assigned(struct rdtgroup *r);
int rdtgroup_locksetup_enter(struct rdtgroup *rdtgrp);
int rdtgroup_locksetup_exit(struct rdtgroup *rdtgrp);
bool rdtgroup_cbm_overlaps_pseudo_locked(struct rdt_domain *d, unsigned long cbm);
bool rdtgroup_pseudo_locked_in_hierarchy(struct rdt_domain *d);
int rdt_pseudo_lock_init(void);
void rdt_pseudo_lock_release(void);
int rdtgroup_pseudo_lock_create(struct rdtgroup *rdtgrp);
void rdtgroup_pseudo_lock_remove(struct rdtgroup *rdtgrp);
struct rdt_domain *get_domain_from_cpu(int cpu, struct rdt_resource *r);
int closids_supported(void);
void closid_free(int closid);
int alloc_rmid(void);
void free_rmid(u32 rmid);
int rdt_get_mon_l3_config(struct rdt_resource *r);
void mon_event_count(void *info);
int rdtgroup_mondata_show(struct seq_file *m, void *arg);
void rmdir_mondata_subdir_allrdtgrp(struct rdt_resource *r,
				    unsigned int dom_id);
void mkdir_mondata_subdir_allrdtgrp(struct rdt_resource *r,
				    struct rdt_domain *d);
void mon_event_read(struct rmid_read *rr, struct rdt_resource *r,
		    struct rdt_domain *d, struct rdtgroup *rdtgrp,
		    int evtid, int first);
void mbm_setup_overflow_handler(struct rdt_domain *dom,
				unsigned long delay_ms);
void mbm_handle_overflow(struct work_struct *work);
void __init intel_rdt_mbm_apply_quirk(void);
bool is_mba_sc(struct rdt_resource *r);
void setup_default_ctrlval(struct rdt_resource *r, u32 *dc, u32 *dm);
u32 delay_bw_map(unsigned long bw, struct rdt_resource *r);
void cqm_setup_limbo_handler(struct rdt_domain *dom, unsigned long delay_ms);
void cqm_handle_limbo(struct work_struct *work);
bool has_busy_rmid(struct rdt_resource *r, struct rdt_domain *d);
void __check_limbo(struct rdt_domain *d, bool force_free);
void rdt_domain_reconfigure_cdp(struct rdt_resource *r);
void __init thread_throttle_mode_init(void);

#endif /* _ASM_X86_RESCTRL_INTERNAL_H */
