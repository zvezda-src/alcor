
#ifndef _KERNEL_KCSAN_KCSAN_H
#define _KERNEL_KCSAN_KCSAN_H

#include <linux/atomic.h>
#include <linux/kcsan.h>
#include <linux/sched.h>

#define KCSAN_CHECK_ADJACENT 1
#define NUM_SLOTS (1 + 2*KCSAN_CHECK_ADJACENT)

extern unsigned int kcsan_udelay_task;
extern unsigned int kcsan_udelay_interrupt;

extern bool kcsan_enabled;

void kcsan_save_irqtrace(struct task_struct *task);
void kcsan_restore_irqtrace(struct task_struct *task);

enum kcsan_counter_id {
	/*
	KCSAN_COUNTER_USED_WATCHPOINTS,

	/*
	KCSAN_COUNTER_SETUP_WATCHPOINTS,

	/*
	KCSAN_COUNTER_DATA_RACES,

	/*
	KCSAN_COUNTER_ASSERT_FAILURES,

	/*
	KCSAN_COUNTER_NO_CAPACITY,

	/*
	KCSAN_COUNTER_REPORT_RACES,

	/*
	KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN,

	/*
	KCSAN_COUNTER_UNENCODABLE_ACCESSES,

	/*
	KCSAN_COUNTER_ENCODING_FALSE_POSITIVES,

	KCSAN_COUNTER_COUNT, /* number of counters */
};
extern atomic_long_t kcsan_counters[KCSAN_COUNTER_COUNT];

extern bool kcsan_skip_report_debugfs(unsigned long func_addr);

enum kcsan_value_change {
	/*
	KCSAN_VALUE_CHANGE_MAYBE,

	/*
	KCSAN_VALUE_CHANGE_FALSE,

	/*
	KCSAN_VALUE_CHANGE_TRUE,
};

void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_type,
			   unsigned long ip, int watchpoint_idx);

void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
			       unsigned long ip, enum kcsan_value_change value_change,
			       int watchpoint_idx, u64 old, u64 new, u64 mask);

void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type,
				 unsigned long ip, u64 old, u64 new, u64 mask);

#endif /* _KERNEL_KCSAN_KCSAN_H */
