
#ifndef _KERNEL_KCSAN_ENCODING_H
#define _KERNEL_KCSAN_ENCODING_H

#include <linux/bits.h>
#include <linux/log2.h>
#include <linux/mm.h>

#include "kcsan.h"

#define SLOT_RANGE PAGE_SIZE

#define INVALID_WATCHPOINT  0
#define CONSUMED_WATCHPOINT 1

#define MAX_ENCODABLE_SIZE (SLOT_RANGE * (1 + KCSAN_CHECK_ADJACENT))

#define WATCHPOINT_SIZE_BITS bits_per(MAX_ENCODABLE_SIZE)
#define WATCHPOINT_ADDR_BITS (BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)

#define WATCHPOINT_WRITE_MASK	BIT(BITS_PER_LONG-1)
#define WATCHPOINT_SIZE_MASK	GENMASK(BITS_PER_LONG-2, WATCHPOINT_ADDR_BITS)
#define WATCHPOINT_ADDR_MASK	GENMASK(WATCHPOINT_ADDR_BITS-1, 0)
static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
static_assert((WATCHPOINT_WRITE_MASK ^ WATCHPOINT_SIZE_MASK ^ WATCHPOINT_ADDR_MASK) == ~0UL);

static inline bool check_encodable(unsigned long addr, size_t size)
{
	/*
	return addr >= PAGE_SIZE && size <= MAX_ENCODABLE_SIZE;
}

static inline long
encode_watchpoint(unsigned long addr, size_t size, bool is_write)
{
	return (long)((is_write ? WATCHPOINT_WRITE_MASK : 0) |
		      (size << WATCHPOINT_ADDR_BITS) |
		      (addr & WATCHPOINT_ADDR_MASK));
}

static __always_inline bool decode_watchpoint(long watchpoint,
					      unsigned long *addr_masked,
					      size_t *size,
					      bool *is_write)
{
	if (watchpoint == INVALID_WATCHPOINT ||
	    watchpoint == CONSUMED_WATCHPOINT)
		return false;


	return true;
}

static __always_inline int watchpoint_slot(unsigned long addr)
{
	return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
}

static __always_inline bool matching_access(unsigned long addr1, size_t size1,
					    unsigned long addr2, size_t size2)
{
	unsigned long end_range1 = addr1 + size1 - 1;
	unsigned long end_range2 = addr2 + size2 - 1;

	return addr1 <= end_range2 && addr2 <= end_range1;
}

#endif /* _KERNEL_KCSAN_ENCODING_H */
