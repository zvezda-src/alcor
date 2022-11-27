
#ifndef GCOV_H
#define GCOV_H GCOV_H

#include <linux/module.h>
#include <linux/types.h>

#define GCOV_DATA_MAGIC		((unsigned int) 0x67636461)
#define GCOV_TAG_FUNCTION	((unsigned int) 0x01000000)
#define GCOV_TAG_COUNTER_BASE	((unsigned int) 0x01a10000)
#define GCOV_TAG_FOR_COUNTER(count)					\
	(GCOV_TAG_COUNTER_BASE + ((unsigned int) (count) << 17))

#if BITS_PER_LONG >= 64
typedef long gcov_type;
#else
typedef long long gcov_type;
#endif

struct gcov_info;

const char *gcov_info_filename(struct gcov_info *info);
unsigned int gcov_info_version(struct gcov_info *info);
struct gcov_info *gcov_info_next(struct gcov_info *info);
void gcov_info_link(struct gcov_info *info);
void gcov_info_unlink(struct gcov_info *prev, struct gcov_info *info);
bool gcov_info_within_module(struct gcov_info *info, struct module *mod);
size_t convert_to_gcda(char *buffer, struct gcov_info *info);

enum gcov_action {
	GCOV_ADD,
	GCOV_REMOVE,
};

void gcov_event(enum gcov_action action, struct gcov_info *info);
void gcov_enable_events(void);

size_t store_gcov_u32(void *buffer, size_t off, u32 v);
size_t store_gcov_u64(void *buffer, size_t off, u64 v);

void gcov_info_reset(struct gcov_info *info);
int gcov_info_is_compatible(struct gcov_info *info1, struct gcov_info *info2);
void gcov_info_add(struct gcov_info *dest, struct gcov_info *source);
struct gcov_info *gcov_info_dup(struct gcov_info *info);
void gcov_info_free(struct gcov_info *info);

struct gcov_link {
	enum {
		OBJ_TREE,
		SRC_TREE,
	} dir;
	const char *ext;
};
extern const struct gcov_link gcov_link[];

extern int gcov_events_enabled;
extern struct mutex gcov_lock;

#endif /* GCOV_H */
