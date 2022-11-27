
#define pr_fmt(fmt)	"gcov: " fmt

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include "gcov.h"

typedef void (*llvm_gcov_callback)(void);

struct gcov_info {
	struct list_head head;

	const char *filename;
	unsigned int version;
	u32 checksum;

	struct list_head functions;
};

struct gcov_fn_info {
	struct list_head head;

	u32 ident;
	u32 checksum;
	u32 cfg_checksum;

	u32 num_counters;
	u64 *counters;
};

static struct gcov_info *current_info;

static LIST_HEAD(clang_gcov_list);

void llvm_gcov_init(llvm_gcov_callback writeout, llvm_gcov_callback flush)
{
	struct gcov_info *info = kzalloc(sizeof(*info), GFP_KERNEL);

	if (!info)
		return;

	INIT_LIST_HEAD(&info->head);
	INIT_LIST_HEAD(&info->functions);

	mutex_lock(&gcov_lock);

	list_add_tail(&info->head, &clang_gcov_list);
	current_info = info;
	writeout();
	current_info = NULL;
	if (gcov_events_enabled)
		gcov_event(GCOV_ADD, info);

	mutex_unlock(&gcov_lock);
}
EXPORT_SYMBOL(llvm_gcov_init);

void llvm_gcda_start_file(const char *orig_filename, u32 version, u32 checksum)
{
	current_info->filename = orig_filename;
	current_info->version = version;
	current_info->checksum = checksum;
}
EXPORT_SYMBOL(llvm_gcda_start_file);

void llvm_gcda_emit_function(u32 ident, u32 func_checksum, u32 cfg_checksum)
{
	struct gcov_fn_info *info = kzalloc(sizeof(*info), GFP_KERNEL);

	if (!info)
		return;

	INIT_LIST_HEAD(&info->head);
	info->ident = ident;
	info->checksum = func_checksum;
	info->cfg_checksum = cfg_checksum;
	list_add_tail(&info->head, &current_info->functions);
}
EXPORT_SYMBOL(llvm_gcda_emit_function);

void llvm_gcda_emit_arcs(u32 num_counters, u64 *counters)
{
	struct gcov_fn_info *info = list_last_entry(&current_info->functions,
			struct gcov_fn_info, head);

	info->num_counters = num_counters;
	info->counters = counters;
}
EXPORT_SYMBOL(llvm_gcda_emit_arcs);

void llvm_gcda_summary_info(void)
{
}
EXPORT_SYMBOL(llvm_gcda_summary_info);

void llvm_gcda_end_file(void)
{
}
EXPORT_SYMBOL(llvm_gcda_end_file);

const char *gcov_info_filename(struct gcov_info *info)
{
	return info->filename;
}

unsigned int gcov_info_version(struct gcov_info *info)
{
	return info->version;
}

struct gcov_info *gcov_info_next(struct gcov_info *info)
{
	if (!info)
		return list_first_entry_or_null(&clang_gcov_list,
				struct gcov_info, head);
	if (list_is_last(&info->head, &clang_gcov_list))
		return NULL;
	return list_next_entry(info, head);
}

void gcov_info_link(struct gcov_info *info)
{
	list_add_tail(&info->head, &clang_gcov_list);
}

void gcov_info_unlink(struct gcov_info *prev, struct gcov_info *info)
{
	/* Generic code unlinks while iterating. */
	__list_del_entry(&info->head);
}

bool gcov_info_within_module(struct gcov_info *info, struct module *mod)
{
	return within_module((unsigned long)info->filename, mod);
}

const struct gcov_link gcov_link[] = {
	{ OBJ_TREE, "gcno" },	/* Link to .gcno file in $(objtree). */
	{ 0, NULL},
};

void gcov_info_reset(struct gcov_info *info)
{
	struct gcov_fn_info *fn;

	list_for_each_entry(fn, &info->functions, head)
		memset(fn->counters, 0,
				sizeof(fn->counters[0]) * fn->num_counters);
}

int gcov_info_is_compatible(struct gcov_info *info1, struct gcov_info *info2)
{
	struct gcov_fn_info *fn_ptr1 = list_first_entry_or_null(
			&info1->functions, struct gcov_fn_info, head);
	struct gcov_fn_info *fn_ptr2 = list_first_entry_or_null(
			&info2->functions, struct gcov_fn_info, head);

	if (info1->checksum != info2->checksum)
		return false;
	if (!fn_ptr1)
		return fn_ptr1 == fn_ptr2;
	while (!list_is_last(&fn_ptr1->head, &info1->functions) &&
		!list_is_last(&fn_ptr2->head, &info2->functions)) {
		if (fn_ptr1->checksum != fn_ptr2->checksum)
			return false;
		if (fn_ptr1->cfg_checksum != fn_ptr2->cfg_checksum)
			return false;
		fn_ptr1 = list_next_entry(fn_ptr1, head);
		fn_ptr2 = list_next_entry(fn_ptr2, head);
	}
	return list_is_last(&fn_ptr1->head, &info1->functions) &&
		list_is_last(&fn_ptr2->head, &info2->functions);
}

void gcov_info_add(struct gcov_info *dst, struct gcov_info *src)
{
	struct gcov_fn_info *dfn_ptr;
	struct gcov_fn_info *sfn_ptr = list_first_entry_or_null(&src->functions,
			struct gcov_fn_info, head);

	list_for_each_entry(dfn_ptr, &dst->functions, head) {
		u32 i;

		for (i = 0; i < sfn_ptr->num_counters; i++)
			dfn_ptr->counters[i] += sfn_ptr->counters[i];
	}
}

static struct gcov_fn_info *gcov_fn_info_dup(struct gcov_fn_info *fn)
{
	size_t cv_size; /* counter values size */
	struct gcov_fn_info *fn_dup = kmemdup(fn, sizeof(*fn),
			GFP_KERNEL);
	if (!fn_dup)
		return NULL;
	INIT_LIST_HEAD(&fn_dup->head);

	cv_size = fn->num_counters * sizeof(fn->counters[0]);
	fn_dup->counters = kvmalloc(cv_size, GFP_KERNEL);
	if (!fn_dup->counters) {
		kfree(fn_dup);
		return NULL;
	}

	memcpy(fn_dup->counters, fn->counters, cv_size);

	return fn_dup;
}

struct gcov_info *gcov_info_dup(struct gcov_info *info)
{
	struct gcov_info *dup;
	struct gcov_fn_info *fn;

	dup = kmemdup(info, sizeof(*dup), GFP_KERNEL);
	if (!dup)
		return NULL;
	INIT_LIST_HEAD(&dup->head);
	INIT_LIST_HEAD(&dup->functions);
	dup->filename = kstrdup(info->filename, GFP_KERNEL);
	if (!dup->filename)
		goto err;

	list_for_each_entry(fn, &info->functions, head) {
		struct gcov_fn_info *fn_dup = gcov_fn_info_dup(fn);

		if (!fn_dup)
			goto err;
		list_add_tail(&fn_dup->head, &dup->functions);
	}

	return dup;

err:
	gcov_info_free(dup);
	return NULL;
}

void gcov_info_free(struct gcov_info *info)
{
	struct gcov_fn_info *fn, *tmp;

	list_for_each_entry_safe(fn, tmp, &info->functions, head) {
		kvfree(fn->counters);
		list_del(&fn->head);
		kfree(fn);
	}
	kfree(info->filename);
	kfree(info);
}

size_t convert_to_gcda(char *buffer, struct gcov_info *info)
{
	struct gcov_fn_info *fi_ptr;
	size_t pos = 0;

	/* File header. */
	pos += store_gcov_u32(buffer, pos, GCOV_DATA_MAGIC);
	pos += store_gcov_u32(buffer, pos, info->version);
	pos += store_gcov_u32(buffer, pos, info->checksum);

	list_for_each_entry(fi_ptr, &info->functions, head) {
		u32 i;

		pos += store_gcov_u32(buffer, pos, GCOV_TAG_FUNCTION);
		pos += store_gcov_u32(buffer, pos, 3);
		pos += store_gcov_u32(buffer, pos, fi_ptr->ident);
		pos += store_gcov_u32(buffer, pos, fi_ptr->checksum);
		pos += store_gcov_u32(buffer, pos, fi_ptr->cfg_checksum);
		pos += store_gcov_u32(buffer, pos, GCOV_TAG_COUNTER_BASE);
		pos += store_gcov_u32(buffer, pos, fi_ptr->num_counters * 2);
		for (i = 0; i < fi_ptr->num_counters; i++)
			pos += store_gcov_u64(buffer, pos, fi_ptr->counters[i]);
	}

	return pos;
}
