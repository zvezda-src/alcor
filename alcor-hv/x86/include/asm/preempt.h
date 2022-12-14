#ifndef __ASM_PREEMPT_H
#define __ASM_PREEMPT_H

#include <asm/rmwcc.h>
#include <asm/percpu.h>
#include <linux/thread_info.h>
#include <linux/static_call_types.h>

DECLARE_PER_CPU(int, __preempt_count);

#define PREEMPT_NEED_RESCHED	0x80000000

#define PREEMPT_ENABLED	(0 + PREEMPT_NEED_RESCHED)

static __always_inline int preempt_count(void)
{
	return raw_cpu_read_4(__preempt_count) & ~PREEMPT_NEED_RESCHED;
}

static __always_inline void preempt_count_set(int pc)
{
	int old, new;

	do {
		old = raw_cpu_read_4(__preempt_count);
		new = (old & PREEMPT_NEED_RESCHED) |
			(pc & ~PREEMPT_NEED_RESCHED);
	} while (raw_cpu_cmpxchg_4(__preempt_count, old, new) != old);
}

#define init_task_preempt_count(p) do { } while (0)

#define init_idle_preempt_count(p, cpu) do { \
	per_cpu(__preempt_count, (cpu)) = PREEMPT_DISABLED; \
} while (0)


static __always_inline void set_preempt_need_resched(void)
{
	raw_cpu_and_4(__preempt_count, ~PREEMPT_NEED_RESCHED);
}

static __always_inline void clear_preempt_need_resched(void)
{
	raw_cpu_or_4(__preempt_count, PREEMPT_NEED_RESCHED);
}

static __always_inline bool test_preempt_need_resched(void)
{
	return !(raw_cpu_read_4(__preempt_count) & PREEMPT_NEED_RESCHED);
}


static __always_inline void __preempt_count_add(int val)
{
	raw_cpu_add_4(__preempt_count, val);
}

static __always_inline void __preempt_count_sub(int val)
{
	raw_cpu_add_4(__preempt_count, -val);
}

static __always_inline bool __preempt_count_dec_and_test(void)
{
	return GEN_UNARY_RMWcc("decl", __preempt_count, e, __percpu_arg([var]));
}

static __always_inline bool should_resched(int preempt_offset)
{
	return unlikely(raw_cpu_read_4(__preempt_count) == preempt_offset);
}

#ifdef CONFIG_PREEMPTION

extern asmlinkage void preempt_schedule(void);
extern asmlinkage void preempt_schedule_thunk(void);

#define preempt_schedule_dynamic_enabled	preempt_schedule_thunk
#define preempt_schedule_dynamic_disabled	NULL

extern asmlinkage void preempt_schedule_notrace(void);
extern asmlinkage void preempt_schedule_notrace_thunk(void);

#define preempt_schedule_notrace_dynamic_enabled	preempt_schedule_notrace_thunk
#define preempt_schedule_notrace_dynamic_disabled	NULL

#ifdef CONFIG_PREEMPT_DYNAMIC

DECLARE_STATIC_CALL(preempt_schedule, preempt_schedule_dynamic_enabled);

#define __preempt_schedule() \
do { \
	__STATIC_CALL_MOD_ADDRESSABLE(preempt_schedule); \
	asm volatile ("call " STATIC_CALL_TRAMP_STR(preempt_schedule) : ASM_CALL_CONSTRAINT); \
} while (0)

DECLARE_STATIC_CALL(preempt_schedule_notrace, preempt_schedule_notrace_dynamic_enabled);

#define __preempt_schedule_notrace() \
do { \
	__STATIC_CALL_MOD_ADDRESSABLE(preempt_schedule_notrace); \
	asm volatile ("call " STATIC_CALL_TRAMP_STR(preempt_schedule_notrace) : ASM_CALL_CONSTRAINT); \
} while (0)

#else /* PREEMPT_DYNAMIC */

#define __preempt_schedule() \
	asm volatile ("call preempt_schedule_thunk" : ASM_CALL_CONSTRAINT);

#define __preempt_schedule_notrace() \
	asm volatile ("call preempt_schedule_notrace_thunk" : ASM_CALL_CONSTRAINT);

#endif /* PREEMPT_DYNAMIC */

#endif /* PREEMPTION */

#endif /* __ASM_PREEMPT_H */
