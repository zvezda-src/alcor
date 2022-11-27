
#include <linux/limits.h>
#include <linux/cgroup.h>
#include <linux/errno.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/misc_cgroup.h>

#define MAX_STR "max"
#define MAX_NUM ULONG_MAX

static const char *const misc_res_name[] = {
#ifdef CONFIG_KVM_AMD_SEV
	/* AMD SEV ASIDs resource */
	"sev",
	/* AMD SEV-ES ASIDs resource */
	"sev_es",
#endif
};

static struct misc_cg root_cg;

static unsigned long misc_res_capacity[MISC_CG_RES_TYPES];

static struct misc_cg *parent_misc(struct misc_cg *cgroup)
{
	return cgroup ? css_misc(cgroup->css.parent) : NULL;
}

static inline bool valid_type(enum misc_res_type type)
{
	return type >= 0 && type < MISC_CG_RES_TYPES;
}

unsigned long misc_cg_res_total_usage(enum misc_res_type type)
{
	if (valid_type(type))
		return atomic_long_read(&root_cg.res[type].usage);

	return 0;
}
EXPORT_SYMBOL_GPL(misc_cg_res_total_usage);

int misc_cg_set_capacity(enum misc_res_type type, unsigned long capacity)
{
	if (!valid_type(type))
		return -EINVAL;

	WRITE_ONCE(misc_res_capacity[type], capacity);
	return 0;
}
EXPORT_SYMBOL_GPL(misc_cg_set_capacity);

static void misc_cg_cancel_charge(enum misc_res_type type, struct misc_cg *cg,
				  unsigned long amount)
{
	WARN_ONCE(atomic_long_add_negative(-amount, &cg->res[type].usage),
		  "misc cgroup resource %s became less than 0",
		  misc_res_name[type]);
}

int misc_cg_try_charge(enum misc_res_type type, struct misc_cg *cg,
		       unsigned long amount)
{
	struct misc_cg *i, *j;
	int ret;
	struct misc_res *res;
	int new_usage;

	if (!(valid_type(type) && cg && READ_ONCE(misc_res_capacity[type])))
		return -EINVAL;

	if (!amount)
		return 0;

	for (i = cg; i; i = parent_misc(i)) {
		res = &i->res[type];

		new_usage = atomic_long_add_return(amount, &res->usage);
		if (new_usage > READ_ONCE(res->max) ||
		    new_usage > READ_ONCE(misc_res_capacity[type])) {
			ret = -EBUSY;
			goto err_charge;
		}
	}
	return 0;

err_charge:
	for (j = i; j; j = parent_misc(j)) {
		atomic_long_inc(&j->res[type].events);
		cgroup_file_notify(&j->events_file);
	}

	for (j = cg; j != i; j = parent_misc(j))
		misc_cg_cancel_charge(type, j, amount);
	misc_cg_cancel_charge(type, i, amount);
	return ret;
}
EXPORT_SYMBOL_GPL(misc_cg_try_charge);

void misc_cg_uncharge(enum misc_res_type type, struct misc_cg *cg,
		      unsigned long amount)
{
	struct misc_cg *i;

	if (!(amount && valid_type(type) && cg))
		return;

	for (i = cg; i; i = parent_misc(i))
		misc_cg_cancel_charge(type, i, amount);
}
EXPORT_SYMBOL_GPL(misc_cg_uncharge);

static int misc_cg_max_show(struct seq_file *sf, void *v)
{
	int i;
	struct misc_cg *cg = css_misc(seq_css(sf));
	unsigned long max;

	for (i = 0; i < MISC_CG_RES_TYPES; i++) {
		if (READ_ONCE(misc_res_capacity[i])) {
			max = READ_ONCE(cg->res[i].max);
			if (max == MAX_NUM)
				seq_printf(sf, "%s max\n", misc_res_name[i]);
			else
				seq_printf(sf, "%s %lu\n", misc_res_name[i],
					   max);
		}
	}

	return 0;
}

static ssize_t misc_cg_max_write(struct kernfs_open_file *of, char *buf,
				 size_t nbytes, loff_t off)
{
	struct misc_cg *cg;
	unsigned long max;
	int ret = 0, i;
	enum misc_res_type type = MISC_CG_RES_TYPES;
	char *token;

	buf = strstrip(buf);
	token = strsep(&buf, " ");

	if (!token || !buf)
		return -EINVAL;

	for (i = 0; i < MISC_CG_RES_TYPES; i++) {
		if (!strcmp(misc_res_name[i], token)) {
			type = i;
			break;
		}
	}

	if (type == MISC_CG_RES_TYPES)
		return -EINVAL;

	if (!strcmp(MAX_STR, buf)) {
		max = MAX_NUM;
	} else {
		ret = kstrtoul(buf, 0, &max);
		if (ret)
			return ret;
	}

	cg = css_misc(of_css(of));

	if (READ_ONCE(misc_res_capacity[type]))
		WRITE_ONCE(cg->res[type].max, max);
	else
		ret = -EINVAL;

	return ret ? ret : nbytes;
}

static int misc_cg_current_show(struct seq_file *sf, void *v)
{
	int i;
	unsigned long usage;
	struct misc_cg *cg = css_misc(seq_css(sf));

	for (i = 0; i < MISC_CG_RES_TYPES; i++) {
		usage = atomic_long_read(&cg->res[i].usage);
		if (READ_ONCE(misc_res_capacity[i]) || usage)
			seq_printf(sf, "%s %lu\n", misc_res_name[i], usage);
	}

	return 0;
}

static int misc_cg_capacity_show(struct seq_file *sf, void *v)
{
	int i;
	unsigned long cap;

	for (i = 0; i < MISC_CG_RES_TYPES; i++) {
		cap = READ_ONCE(misc_res_capacity[i]);
		if (cap)
			seq_printf(sf, "%s %lu\n", misc_res_name[i], cap);
	}

	return 0;
}

static int misc_events_show(struct seq_file *sf, void *v)
{
	struct misc_cg *cg = css_misc(seq_css(sf));
	unsigned long events, i;

	for (i = 0; i < MISC_CG_RES_TYPES; i++) {
		events = atomic_long_read(&cg->res[i].events);
		if (READ_ONCE(misc_res_capacity[i]) || events)
			seq_printf(sf, "%s.max %lu\n", misc_res_name[i], events);
	}
	return 0;
}

static struct cftype misc_cg_files[] = {
	{
		.name = "max",
		.write = misc_cg_max_write,
		.seq_show = misc_cg_max_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "current",
		.seq_show = misc_cg_current_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "capacity",
		.seq_show = misc_cg_capacity_show,
		.flags = CFTYPE_ONLY_ON_ROOT,
	},
	{
		.name = "events",
		.flags = CFTYPE_NOT_ON_ROOT,
		.file_offset = offsetof(struct misc_cg, events_file),
		.seq_show = misc_events_show,
	},
	{}
};

static struct cgroup_subsys_state *
misc_cg_alloc(struct cgroup_subsys_state *parent_css)
{
	enum misc_res_type i;
	struct misc_cg *cg;

	if (!parent_css) {
		cg = &root_cg;
	} else {
		cg = kzalloc(sizeof(*cg), GFP_KERNEL);
		if (!cg)
			return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < MISC_CG_RES_TYPES; i++) {
		WRITE_ONCE(cg->res[i].max, MAX_NUM);
		atomic_long_set(&cg->res[i].usage, 0);
	}

	return &cg->css;
}

static void misc_cg_free(struct cgroup_subsys_state *css)
{
	kfree(css_misc(css));
}

struct cgroup_subsys misc_cgrp_subsys = {
	.css_alloc = misc_cg_alloc,
	.css_free = misc_cg_free,
	.legacy_cftypes = misc_cg_files,
	.dfl_cftypes = misc_cg_files,
};
