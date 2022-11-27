
#ifndef _KERNEL_KCSAN_PERMISSIVE_H
#define _KERNEL_KCSAN_PERMISSIVE_H

#include <linux/bitops.h>
#include <linux/sched.h>
#include <linux/types.h>

static __always_inline bool kcsan_ignore_address(const volatile void *ptr)
{
	if (!IS_ENABLED(CONFIG_KCSAN_PERMISSIVE))
		return false;

	/*
	return ptr == &current->flags;
}

static bool
kcsan_ignore_data_race(size_t size, int type, u64 old, u64 new, u64 diff)
{
	if (!IS_ENABLED(CONFIG_KCSAN_PERMISSIVE))
		return false;

	/*
	if (type || size > sizeof(long))
		return false;

	/*
	if (hweight64(diff) == 1) {
		/*
		if (!((!old || !new) && diff == 1))
			return true;
	}

	return false;
}

#endif /* _KERNEL_KCSAN_PERMISSIVE_H */
