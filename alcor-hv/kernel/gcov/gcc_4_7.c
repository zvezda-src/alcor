
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mm.h>
#include "gcov.h"

#if (__GNUC__ >= 10)
#define GCOV_COUNTERS			8
#elif (__GNUC__ >= 7)
#define GCOV_COUNTERS			9
#elif (__GNUC__ > 5) || (__GNUC__ == 5 && __GNUC_MINOR__ >= 1)
#define GCOV_COUNTERS			10
#else
#define GCOV_COUNTERS			9
#endif

#define GCOV_TAG_FUNCTION_LENGTH	3

static struct gcov_info *gcov_info_head;

struct gcov_ctr_info {
	unsigned int num;
	gcov_type *values;
};

struct gcov_fn_info {
	const struct gcov_info *key;
	unsigned int ident;
	unsigned int lineno_checksum;
	unsigned int cfg_checksum;
	struct gcov_ctr_info ctrs[];
};

struct gcov_info {
	unsigned int version;
	struct gcov_info *next;
	unsigned int stamp;
	const char *filename;
	void (*merge[GCOV_COUNTERS])(gcov_type *, unsigned int);
	unsigned int n_functions;
	struct gcov_fn_info **functions;
};

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
		return gcov_info_head;

	return info->next;
}

void gcov_info_link(struct gcov_info *info)
{
	info->next = gcov_info_head;
	gcov_info_head = info;
}

void gcov_info_unlink(struct gcov_info *prev, struct gcov_info *info)
{
	if (prev)
		prev->next = info->next;
	else
		gcov_info_head = info->next;
}

bool gcov_info_within_module(struct gcov_info *info, struct module *mod)
{
	return within_module((unsigned long)info, mod);
}

const struct gcov_link gcov_link[] = {
	{ OBJ_TREE, "gcno" },	/* Link to .gcno file in $(objtree). */
	{ 0, NULL},
};

static int counter_active(struct gcov_info *info, unsigned int type)
{
	return info->merge[type] ? 1 : 0;
}

static unsigned int num_counter_active(struct gcov_info *info)
{
	unsigned int i;
	unsigned int result = 0;

	for (i = 0; i < GCOV_COUNTERS; i++) {
		if (counter_active(info, i))
			result++;
	}
	return result;
}

void gcov_info_reset(struct gcov_info *info)
{
	struct gcov_ctr_info *ci_ptr;
	unsigned int fi_idx;
	unsigned int ct_idx;

	for (fi_idx = 0; fi_idx < info->n_functions; fi_idx++) {
		ci_ptr = info->functions[fi_idx]->ctrs;

		for (ct_idx = 0; ct_idx < GCOV_COUNTERS; ct_idx++) {
			if (!counter_active(info, ct_idx))
				continue;

			memset(ci_ptr->values, 0,
					sizeof(gcov_type) * ci_ptr->num);
			ci_ptr++;
		}
	}
}

int gcov_info_is_compatible(struct gcov_info *info1, struct gcov_info *info2)
{
	return (info1->stamp == info2->stamp);
}

void gcov_info_add(struct gcov_info *dst, struct gcov_info *src)
{
	struct gcov_ctr_info *dci_ptr;
	struct gcov_ctr_info *sci_ptr;
	unsigned int fi_idx;
	unsigned int ct_idx;
	unsigned int val_idx;

	for (fi_idx = 0; fi_idx < src->n_functions; fi_idx++) {
		dci_ptr = dst->functions[fi_idx]->ctrs;
		sci_ptr = src->functions[fi_idx]->ctrs;

		for (ct_idx = 0; ct_idx < GCOV_COUNTERS; ct_idx++) {
			if (!counter_active(src, ct_idx))
				continue;

			for (val_idx = 0; val_idx < sci_ptr->num; val_idx++)
				dci_ptr->values[val_idx] +=
					sci_ptr->values[val_idx];

			dci_ptr++;
			sci_ptr++;
		}
	}
}

struct gcov_info *gcov_info_dup(struct gcov_info *info)
{
	struct gcov_info *dup;
	struct gcov_ctr_info *dci_ptr; /* dst counter info */
	struct gcov_ctr_info *sci_ptr; /* src counter info */
	unsigned int active;
	unsigned int fi_idx; /* function info idx */
	unsigned int ct_idx; /* counter type idx */
	size_t fi_size; /* function info size */
	size_t cv_size; /* counter values size */

	dup = kmemdup(info, sizeof(*dup), GFP_KERNEL);
	if (!dup)
		return NULL;

	dup->next = NULL;
	dup->filename = NULL;
	dup->functions = NULL;

	dup->filename = kstrdup(info->filename, GFP_KERNEL);
	if (!dup->filename)
		goto err_free;

	dup->functions = kcalloc(info->n_functions,
				 sizeof(struct gcov_fn_info *), GFP_KERNEL);
	if (!dup->functions)
		goto err_free;

	active = num_counter_active(info);
	fi_size = sizeof(struct gcov_fn_info);
	fi_size += sizeof(struct gcov_ctr_info) * active;

	for (fi_idx = 0; fi_idx < info->n_functions; fi_idx++) {
		dup->functions[fi_idx] = kzalloc(fi_size, GFP_KERNEL);
		if (!dup->functions[fi_idx])
			goto err_free;

		*(dup->functions[fi_idx]) = *(info->functions[fi_idx]);

		sci_ptr = info->functions[fi_idx]->ctrs;
		dci_ptr = dup->functions[fi_idx]->ctrs;

		for (ct_idx = 0; ct_idx < active; ct_idx++) {

			cv_size = sizeof(gcov_type) * sci_ptr->num;

			dci_ptr->values = kvmalloc(cv_size, GFP_KERNEL);

			if (!dci_ptr->values)
				goto err_free;

			dci_ptr->num = sci_ptr->num;
			memcpy(dci_ptr->values, sci_ptr->values, cv_size);

			sci_ptr++;
			dci_ptr++;
		}
	}

	return dup;
err_free:
	gcov_info_free(dup);
	return NULL;
}

void gcov_info_free(struct gcov_info *info)
{
	unsigned int active;
	unsigned int fi_idx;
	unsigned int ct_idx;
	struct gcov_ctr_info *ci_ptr;

	if (!info->functions)
		goto free_info;

	active = num_counter_active(info);

	for (fi_idx = 0; fi_idx < info->n_functions; fi_idx++) {
		if (!info->functions[fi_idx])
			continue;

		ci_ptr = info->functions[fi_idx]->ctrs;

		for (ct_idx = 0; ct_idx < active; ct_idx++, ci_ptr++)
			kvfree(ci_ptr->values);

		kfree(info->functions[fi_idx]);
	}

free_info:
	kfree(info->functions);
	kfree(info->filename);
	kfree(info);
}

size_t convert_to_gcda(char *buffer, struct gcov_info *info)
{
	struct gcov_fn_info *fi_ptr;
	struct gcov_ctr_info *ci_ptr;
	unsigned int fi_idx;
	unsigned int ct_idx;
	unsigned int cv_idx;
	size_t pos = 0;

	/* File header. */
	pos += store_gcov_u32(buffer, pos, GCOV_DATA_MAGIC);
	pos += store_gcov_u32(buffer, pos, info->version);
	pos += store_gcov_u32(buffer, pos, info->stamp);

	for (fi_idx = 0; fi_idx < info->n_functions; fi_idx++) {
		fi_ptr = info->functions[fi_idx];

		/* Function record. */
		pos += store_gcov_u32(buffer, pos, GCOV_TAG_FUNCTION);
		pos += store_gcov_u32(buffer, pos, GCOV_TAG_FUNCTION_LENGTH);
		pos += store_gcov_u32(buffer, pos, fi_ptr->ident);
		pos += store_gcov_u32(buffer, pos, fi_ptr->lineno_checksum);
		pos += store_gcov_u32(buffer, pos, fi_ptr->cfg_checksum);

		ci_ptr = fi_ptr->ctrs;

		for (ct_idx = 0; ct_idx < GCOV_COUNTERS; ct_idx++) {
			if (!counter_active(info, ct_idx))
				continue;

			/* Counter record. */
			pos += store_gcov_u32(buffer, pos,
					      GCOV_TAG_FOR_COUNTER(ct_idx));
			pos += store_gcov_u32(buffer, pos, ci_ptr->num * 2);

			for (cv_idx = 0; cv_idx < ci_ptr->num; cv_idx++) {
				pos += store_gcov_u64(buffer, pos,
						      ci_ptr->values[cv_idx]);
			}

			ci_ptr++;
		}
	}

	return pos;
}
