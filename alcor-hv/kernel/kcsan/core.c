
#define pr_fmt(fmt) "kcsan: " fmt

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "encoding.h"
#include "kcsan.h"
#include "permissive.h"

static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "kcsan."
module_param_named(early_enable, kcsan_early_enable, bool, 0);
module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
module_param_named(interrupt_watcher, kcsan_interrupt_watcher, bool, 0444);

#ifdef CONFIG_KCSAN_WEAK_MEMORY
static bool kcsan_weak_memory = true;
module_param_named(weak_memory, kcsan_weak_memory, bool, 0644);
#else
#define kcsan_weak_memory false
#endif

bool kcsan_enabled;

static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
	.scoped_accesses	= {LIST_POISON1, NULL},
};

#define SLOT_IDX(slot, i) (slot + ((i + KCSAN_CHECK_ADJACENT) % NUM_SLOTS))

#define SLOT_IDX_FAST(slot, i) (slot + i)

static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];

static DEFINE_PER_CPU(long, kcsan_skip);

static DEFINE_PER_CPU(u32, kcsan_rand_state);

static __always_inline atomic_long_t *find_watchpoint(unsigned long addr,
						      size_t size,
						      bool expect_write,
						      long *encoded_watchpoint)
{
	const int slot = watchpoint_slot(addr);
	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
	atomic_long_t *watchpoint;
	unsigned long wp_addr_masked;
	size_t wp_size;
	bool is_write;
	int i;

	BUILD_BUG_ON(CONFIG_KCSAN_NUM_WATCHPOINTS < NUM_SLOTS);

	for (i = 0; i < NUM_SLOTS; ++i) {
		watchpoint = &watchpoints[SLOT_IDX_FAST(slot, i)];
		*encoded_watchpoint = atomic_long_read(watchpoint);
		if (!decode_watchpoint(*encoded_watchpoint, &wp_addr_masked,
				       &wp_size, &is_write))
			continue;

		if (expect_write && !is_write)
			continue;

		/* Check if the watchpoint matches the access. */
		if (matching_access(wp_addr_masked, wp_size, addr_masked, size))
			return watchpoint;
	}

	return NULL;
}

static inline atomic_long_t *
insert_watchpoint(unsigned long addr, size_t size, bool is_write)
{
	const int slot = watchpoint_slot(addr);
	const long encoded_watchpoint = encode_watchpoint(addr, size, is_write);
	atomic_long_t *watchpoint;
	int i;

	/* Check slot index logic, ensuring we stay within array bounds. */
	BUILD_BUG_ON(SLOT_IDX(0, 0) != KCSAN_CHECK_ADJACENT);
	BUILD_BUG_ON(SLOT_IDX(0, KCSAN_CHECK_ADJACENT+1) != 0);
	BUILD_BUG_ON(SLOT_IDX(CONFIG_KCSAN_NUM_WATCHPOINTS-1, KCSAN_CHECK_ADJACENT) != ARRAY_SIZE(watchpoints)-1);
	BUILD_BUG_ON(SLOT_IDX(CONFIG_KCSAN_NUM_WATCHPOINTS-1, KCSAN_CHECK_ADJACENT+1) != ARRAY_SIZE(watchpoints) - NUM_SLOTS);

	for (i = 0; i < NUM_SLOTS; ++i) {
		long expect_val = INVALID_WATCHPOINT;

		/* Try to acquire this slot. */
		watchpoint = &watchpoints[SLOT_IDX(slot, i)];
		if (atomic_long_try_cmpxchg_relaxed(watchpoint, &expect_val, encoded_watchpoint))
			return watchpoint;
	}

	return NULL;
}

static __always_inline bool
try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
{
	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
}

static inline bool consume_watchpoint(atomic_long_t *watchpoint)
{
	return atomic_long_xchg_relaxed(watchpoint, CONSUMED_WATCHPOINT) != CONSUMED_WATCHPOINT;
}

static inline void remove_watchpoint(atomic_long_t *watchpoint)
{
	atomic_long_set(watchpoint, INVALID_WATCHPOINT);
}

static __always_inline struct kcsan_ctx *get_ctx(void)
{
	/*
	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
}

static __always_inline void
check_access(const volatile void *ptr, size_t size, int type, unsigned long ip);

static noinline void kcsan_check_scoped_accesses(void)
{
	struct kcsan_ctx *ctx = get_ctx();
	struct kcsan_scoped_access *scoped_access;

	if (ctx->disable_scoped)
		return;

	ctx->disable_scoped++;
	list_for_each_entry(scoped_access, &ctx->scoped_accesses, list) {
		check_access(scoped_access->ptr, scoped_access->size,
			     scoped_access->type, scoped_access->ip);
	}
	ctx->disable_scoped--;
}

static __always_inline bool
is_atomic(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size, int type)
{
	if (type & KCSAN_ACCESS_ATOMIC)
		return true;

	/*
	if (type & KCSAN_ACCESS_ASSERT)
		return false;

	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
	    (type & KCSAN_ACCESS_WRITE) && size <= sizeof(long) &&
	    !(type & KCSAN_ACCESS_COMPOUND) && IS_ALIGNED((unsigned long)ptr, size))
		return true; /* Assume aligned writes up to word size are atomic. */

	if (ctx->atomic_next > 0) {
		/*
		if ((hardirq_count() >> HARDIRQ_SHIFT) < 2)
			--ctx->atomic_next; /* in task, or outer interrupt */
		return true;
	}

	return ctx->atomic_nest_count > 0 || ctx->in_flat_atomic;
}

static __always_inline bool
should_watch(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size, int type)
{
	/*
	if (is_atomic(ctx, ptr, size, type))
		return false;

	if (this_cpu_dec_return(kcsan_skip) >= 0)
		return false;

	/*

	/* this operation should be watched */
	return true;
}

static u32 kcsan_prandom_u32_max(u32 ep_ro)
{
	u32 state = this_cpu_read(kcsan_rand_state);

	state = 1664525 * state + 1013904223;
	this_cpu_write(kcsan_rand_state, state);

	return state % ep_ro;
}

static inline void reset_kcsan_skip(void)
{
	long skip_count = kcsan_skip_watch -
			  (IS_ENABLED(CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE) ?
				   kcsan_prandom_u32_max(kcsan_skip_watch) :
				   0);
	this_cpu_write(kcsan_skip, skip_count);
}

static __always_inline bool kcsan_is_enabled(struct kcsan_ctx *ctx)
{
	return READ_ONCE(kcsan_enabled) && !ctx->disable_count;
}

static void delay_access(int type)
{
	unsigned int delay = in_task() ? kcsan_udelay_task : kcsan_udelay_interrupt;
	/* For certain access types, skew the random delay to be longer. */
	unsigned int skew_delay_order =
		(type & (KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_ASSERT)) ? 1 : 0;

	delay -= IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
			       kcsan_prandom_u32_max(delay >> skew_delay_order) :
			       0;
	udelay(delay);
}

static __always_inline u64 read_instrumented_memory(const volatile void *ptr, size_t size)
{
	switch (size) {
	case 1:  return READ_ONCE(*(const u8 *)ptr);
	case 2:  return READ_ONCE(*(const u16 *)ptr);
	case 4:  return READ_ONCE(*(const u32 *)ptr);
	case 8:  return READ_ONCE(*(const u64 *)ptr);
	default: return 0; /* Ignore; we do not diff the values. */
	}
}

void kcsan_save_irqtrace(struct task_struct *task)
{
#ifdef CONFIG_TRACE_IRQFLAGS
	task->kcsan_save_irqtrace = task->irqtrace;
#endif
}

void kcsan_restore_irqtrace(struct task_struct *task)
{
#ifdef CONFIG_TRACE_IRQFLAGS
	task->irqtrace = task->kcsan_save_irqtrace;
#endif
}

static __always_inline int get_kcsan_stack_depth(void)
{
#ifdef CONFIG_KCSAN_WEAK_MEMORY
	return current->kcsan_stack_depth;
#else
	BUILD_BUG();
	return 0;
#endif
}

static __always_inline void add_kcsan_stack_depth(int val)
{
#ifdef CONFIG_KCSAN_WEAK_MEMORY
	current->kcsan_stack_depth += val;
#else
	BUILD_BUG();
#endif
}

static __always_inline struct kcsan_scoped_access *get_reorder_access(struct kcsan_ctx *ctx)
{
#ifdef CONFIG_KCSAN_WEAK_MEMORY
	return ctx->disable_scoped ? NULL : &ctx->reorder_access;
#else
	return NULL;
#endif
}

static __always_inline bool
find_reorder_access(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size,
		    int type, unsigned long ip)
{
	struct kcsan_scoped_access *reorder_access = get_reorder_access(ctx);

	if (!reorder_access)
		return false;

	/*
	return reorder_access->ptr == ptr && reorder_access->size == size &&
	       reorder_access->type == type && reorder_access->ip == ip;
}

static inline void
set_reorder_access(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size,
		   int type, unsigned long ip)
{
	struct kcsan_scoped_access *reorder_access = get_reorder_access(ctx);

	if (!reorder_access || !kcsan_weak_memory)
		return;

	/*
	ctx->disable_scoped++;
	barrier();
	reorder_access->ptr		= ptr;
	reorder_access->size		= size;
	reorder_access->type		= type | KCSAN_ACCESS_SCOPED;
	reorder_access->ip		= ip;
	reorder_access->stack_depth	= get_kcsan_stack_depth();
	barrier();
	ctx->disable_scoped--;
}


static noinline void kcsan_found_watchpoint(const volatile void *ptr,
					    size_t size,
					    int type,
					    unsigned long ip,
					    atomic_long_t *watchpoint,
					    long encoded_watchpoint)
{
	const bool is_assert = (type & KCSAN_ACCESS_ASSERT) != 0;
	struct kcsan_ctx *ctx = get_ctx();
	unsigned long flags;
	bool consumed;

	/*

	if (!kcsan_is_enabled(ctx))
		return;

	/*
	if (ctx->access_mask && !find_reorder_access(ctx, ptr, size, type, ip))
		return;

	/*
	if (!is_assert && kcsan_ignore_address(ptr))
		return;

	/*
	consumed = try_consume_watchpoint(watchpoint, encoded_watchpoint);

	/* keep this after try_consume_watchpoint */
	flags = user_access_save();

	if (consumed) {
		kcsan_save_irqtrace(current);
		kcsan_report_set_info(ptr, size, type, ip, watchpoint - watchpoints);
		kcsan_restore_irqtrace(current);
	} else {
		/*
		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_REPORT_RACES]);
	}

	if (is_assert)
		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
	else
		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_DATA_RACES]);

	user_access_restore(flags);
}

static noinline void
kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned long ip)
{
	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
	const bool is_assert = (type & KCSAN_ACCESS_ASSERT) != 0;
	atomic_long_t *watchpoint;
	u64 old, new, diff;
	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
	bool interrupt_watcher = kcsan_interrupt_watcher;
	unsigned long ua_flags = user_access_save();
	struct kcsan_ctx *ctx = get_ctx();
	unsigned long access_mask = ctx->access_mask;
	unsigned long irq_flags = 0;
	bool is_reorder_access;

	/*
	reset_kcsan_skip();

	if (!kcsan_is_enabled(ctx))
		goto out;

	/*
	if (!is_assert && kcsan_ignore_address(ptr))
		goto out;

	if (!check_encodable((unsigned long)ptr, size)) {
		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_UNENCODABLE_ACCESSES]);
		goto out;
	}

	/*
	is_reorder_access = find_reorder_access(ctx, ptr, size, type, ip);
	if (is_reorder_access)
		interrupt_watcher = false;
	/*
	ctx->disable_scoped++;

	/*
	kcsan_save_irqtrace(current);
	if (!interrupt_watcher)
		local_irq_save(irq_flags);

	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
	if (watchpoint == NULL) {
		/*
		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_NO_CAPACITY]);
		goto out_unlock;
	}

	atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_SETUP_WATCHPOINTS]);
	atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_USED_WATCHPOINTS]);

	/*
	old = is_reorder_access ? 0 : read_instrumented_memory(ptr, size);

	/*
	delay_access(type);

	/*
	if (!is_reorder_access) {
		new = read_instrumented_memory(ptr, size);
	} else {
		/*
		new = 0;
		access_mask = 0;
	}

	diff = old ^ new;
	if (access_mask)
		diff &= access_mask;

	/*
	if (diff && !kcsan_ignore_data_race(size, type, old, new, diff))
		value_change = KCSAN_VALUE_CHANGE_TRUE;

	/* Check if this access raced with another. */
	if (!consume_watchpoint(watchpoint)) {
		/*
		if (value_change == KCSAN_VALUE_CHANGE_MAYBE) {
			if (access_mask != 0) {
				/*
				value_change = KCSAN_VALUE_CHANGE_FALSE;
			} else if (size > 8 || is_assert) {
				/* Always assume a value-change. */
				value_change = KCSAN_VALUE_CHANGE_TRUE;
			}
		}

		/*
		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);

		kcsan_report_known_origin(ptr, size, type, ip,
					  value_change, watchpoint - watchpoints,
					  old, new, access_mask);
	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
		/* Inferring a race, since the value should not have changed. */

		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN]);
		if (is_assert)
			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);

		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert) {
			kcsan_report_unknown_origin(ptr, size, type, ip,
						    old, new, access_mask);
		}
	}

	/*
	remove_watchpoint(watchpoint);
	atomic_long_dec(&kcsan_counters[KCSAN_COUNTER_USED_WATCHPOINTS]);

out_unlock:
	if (!interrupt_watcher)
		local_irq_restore(irq_flags);
	kcsan_restore_irqtrace(current);
	ctx->disable_scoped--;

	/*
	if (!access_mask && !is_assert)
		set_reorder_access(ctx, ptr, size, type, ip);
out:
	user_access_restore(ua_flags);
}

static __always_inline void
check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
{
	atomic_long_t *watchpoint;
	long encoded_watchpoint;

	/*
	if (unlikely(size == 0))
		return;

again:
	/*
	watchpoint = find_watchpoint((unsigned long)ptr, size,
				     !(type & KCSAN_ACCESS_WRITE),
				     &encoded_watchpoint);
	/*

	if (unlikely(watchpoint != NULL))
		kcsan_found_watchpoint(ptr, size, type, ip, watchpoint, encoded_watchpoint);
	else {
		struct kcsan_ctx *ctx = get_ctx(); /* Call only once in fast-path. */

		if (unlikely(should_watch(ctx, ptr, size, type))) {
			kcsan_setup_watchpoint(ptr, size, type, ip);
			return;
		}

		if (!(type & KCSAN_ACCESS_SCOPED)) {
			struct kcsan_scoped_access *reorder_access = get_reorder_access(ctx);

			if (reorder_access) {
				/*
				ptr = reorder_access->ptr;
				type = reorder_access->type;
				ip = reorder_access->ip;
				/*
				barrier();
				size = READ_ONCE(reorder_access->size);
				if (size)
					goto again;
			}
		}

		/*
		if (unlikely(ctx->scoped_accesses.prev))
			kcsan_check_scoped_accesses();
	}
}


void __init kcsan_init(void)
{
	int cpu;

	BUG_ON(!in_task());

	for_each_possible_cpu(cpu)
		per_cpu(kcsan_rand_state, cpu) = (u32)get_cycles();

	/*
	if (kcsan_early_enable) {
		pr_info("enabled early\n");
		WRITE_ONCE(kcsan_enabled, true);
	}

	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) ||
	    IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) ||
	    IS_ENABLED(CONFIG_KCSAN_PERMISSIVE) ||
	    IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {
		pr_warn("non-strict mode configured - use CONFIG_KCSAN_STRICT=y to see all data races\n");
	} else {
		pr_info("strict mode configured\n");
	}
}


void kcsan_disable_current(void)
{
	++get_ctx()->disable_count;
}
EXPORT_SYMBOL(kcsan_disable_current);

void kcsan_enable_current(void)
{
	if (get_ctx()->disable_count-- == 0) {
		/*
		kcsan_disable_current(); /* restore to 0, KCSAN still enabled */
		kcsan_disable_current(); /* disable to generate warning */
		WARN(1, "Unbalanced %s()", __func__);
		kcsan_enable_current();
	}
}
EXPORT_SYMBOL(kcsan_enable_current);

void kcsan_enable_current_nowarn(void)
{
	if (get_ctx()->disable_count-- == 0)
		kcsan_disable_current();
}
EXPORT_SYMBOL(kcsan_enable_current_nowarn);

void kcsan_nestable_atomic_begin(void)
{
	/*

	++get_ctx()->atomic_nest_count;
}
EXPORT_SYMBOL(kcsan_nestable_atomic_begin);

void kcsan_nestable_atomic_end(void)
{
	if (get_ctx()->atomic_nest_count-- == 0) {
		/*
		kcsan_nestable_atomic_begin(); /* restore to 0 */
		kcsan_disable_current(); /* disable to generate warning */
		WARN(1, "Unbalanced %s()", __func__);
		kcsan_enable_current();
	}
}
EXPORT_SYMBOL(kcsan_nestable_atomic_end);

void kcsan_flat_atomic_begin(void)
{
	get_ctx()->in_flat_atomic = true;
}
EXPORT_SYMBOL(kcsan_flat_atomic_begin);

void kcsan_flat_atomic_end(void)
{
	get_ctx()->in_flat_atomic = false;
}
EXPORT_SYMBOL(kcsan_flat_atomic_end);

void kcsan_atomic_next(int n)
{
	get_ctx()->atomic_next = n;
}
EXPORT_SYMBOL(kcsan_atomic_next);

void kcsan_set_access_mask(unsigned long mask)
{
	get_ctx()->access_mask = mask;
}
EXPORT_SYMBOL(kcsan_set_access_mask);

struct kcsan_scoped_access *
kcsan_begin_scoped_access(const volatile void *ptr, size_t size, int type,
			  struct kcsan_scoped_access *sa)
{
	struct kcsan_ctx *ctx = get_ctx();

	check_access(ptr, size, type, _RET_IP_);

	ctx->disable_count++; /* Disable KCSAN, in case list debugging is on. */

	INIT_LIST_HEAD(&sa->list);
	sa->ptr = ptr;
	sa->size = size;
	sa->type = type;
	sa->ip = _RET_IP_;

	if (!ctx->scoped_accesses.prev) /* Lazy initialize list head. */
		INIT_LIST_HEAD(&ctx->scoped_accesses);
	list_add(&sa->list, &ctx->scoped_accesses);

	ctx->disable_count--;
	return sa;
}
EXPORT_SYMBOL(kcsan_begin_scoped_access);

void kcsan_end_scoped_access(struct kcsan_scoped_access *sa)
{
	struct kcsan_ctx *ctx = get_ctx();

	if (WARN(!ctx->scoped_accesses.prev, "Unbalanced %s()?", __func__))
		return;

	ctx->disable_count++; /* Disable KCSAN, in case list debugging is on. */

	list_del(&sa->list);
	if (list_empty(&ctx->scoped_accesses))
		/*
		ctx->scoped_accesses.prev = NULL;

	ctx->disable_count--;

	check_access(sa->ptr, sa->size, sa->type, sa->ip);
}
EXPORT_SYMBOL(kcsan_end_scoped_access);

void __kcsan_check_access(const volatile void *ptr, size_t size, int type)
{
	check_access(ptr, size, type, _RET_IP_);
}
EXPORT_SYMBOL(__kcsan_check_access);

#define DEFINE_MEMORY_BARRIER(name, order_before_cond)				\
	void __kcsan_##name(void)						\
	{									\
		struct kcsan_scoped_access *sa = get_reorder_access(get_ctx());	\
		if (!sa)							\
			return;							\
		if (order_before_cond)						\
			sa->size = 0;						\
	}									\
	EXPORT_SYMBOL(__kcsan_##name)

DEFINE_MEMORY_BARRIER(mb, true);
DEFINE_MEMORY_BARRIER(wmb, sa->type & (KCSAN_ACCESS_WRITE | KCSAN_ACCESS_COMPOUND));
DEFINE_MEMORY_BARRIER(rmb, !(sa->type & KCSAN_ACCESS_WRITE) || (sa->type & KCSAN_ACCESS_COMPOUND));
DEFINE_MEMORY_BARRIER(release, true);


#define DEFINE_TSAN_READ_WRITE(size)                                           \
	void __tsan_read##size(void *ptr);                                     \
	void __tsan_read##size(void *ptr)                                      \
	{                                                                      \
		check_access(ptr, size, 0, _RET_IP_);                          \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_read##size);                                      \
	void __tsan_unaligned_read##size(void *ptr)                            \
		__alias(__tsan_read##size);                                    \
	EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
	void __tsan_write##size(void *ptr);                                    \
	void __tsan_write##size(void *ptr)                                     \
	{                                                                      \
		check_access(ptr, size, KCSAN_ACCESS_WRITE, _RET_IP_);         \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_write##size);                                     \
	void __tsan_unaligned_write##size(void *ptr)                           \
		__alias(__tsan_write##size);                                   \
	EXPORT_SYMBOL(__tsan_unaligned_write##size);                           \
	void __tsan_read_write##size(void *ptr);                               \
	void __tsan_read_write##size(void *ptr)                                \
	{                                                                      \
		check_access(ptr, size,                                        \
			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE,       \
			     _RET_IP_);                                        \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_read_write##size);                                \
	void __tsan_unaligned_read_write##size(void *ptr)                      \
		__alias(__tsan_read_write##size);                              \
	EXPORT_SYMBOL(__tsan_unaligned_read_write##size)

DEFINE_TSAN_READ_WRITE(1);
DEFINE_TSAN_READ_WRITE(2);
DEFINE_TSAN_READ_WRITE(4);
DEFINE_TSAN_READ_WRITE(8);
DEFINE_TSAN_READ_WRITE(16);

void __tsan_read_range(void *ptr, size_t size);
void __tsan_read_range(void *ptr, size_t size)
{
	check_access(ptr, size, 0, _RET_IP_);
}
EXPORT_SYMBOL(__tsan_read_range);

void __tsan_write_range(void *ptr, size_t size);
void __tsan_write_range(void *ptr, size_t size)
{
	check_access(ptr, size, KCSAN_ACCESS_WRITE, _RET_IP_);
}
EXPORT_SYMBOL(__tsan_write_range);

#define DEFINE_TSAN_VOLATILE_READ_WRITE(size)                                  \
	void __tsan_volatile_read##size(void *ptr);                            \
	void __tsan_volatile_read##size(void *ptr)                             \
	{                                                                      \
		const bool is_atomic = size <= sizeof(long long) &&            \
				       IS_ALIGNED((unsigned long)ptr, size);   \
		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
			return;                                                \
		check_access(ptr, size, is_atomic ? KCSAN_ACCESS_ATOMIC : 0,   \
			     _RET_IP_);                                        \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
		__alias(__tsan_volatile_read##size);                           \
	EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
	void __tsan_volatile_write##size(void *ptr);                           \
	void __tsan_volatile_write##size(void *ptr)                            \
	{                                                                      \
		const bool is_atomic = size <= sizeof(long long) &&            \
				       IS_ALIGNED((unsigned long)ptr, size);   \
		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
			return;                                                \
		check_access(ptr, size,                                        \
			     KCSAN_ACCESS_WRITE |                              \
				     (is_atomic ? KCSAN_ACCESS_ATOMIC : 0),    \
			     _RET_IP_);                                        \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
	void __tsan_unaligned_volatile_write##size(void *ptr)                  \
		__alias(__tsan_volatile_write##size);                          \
	EXPORT_SYMBOL(__tsan_unaligned_volatile_write##size)

DEFINE_TSAN_VOLATILE_READ_WRITE(1);
DEFINE_TSAN_VOLATILE_READ_WRITE(2);
DEFINE_TSAN_VOLATILE_READ_WRITE(4);
DEFINE_TSAN_VOLATILE_READ_WRITE(8);
DEFINE_TSAN_VOLATILE_READ_WRITE(16);

void __tsan_func_entry(void *call_pc);
noinline void __tsan_func_entry(void *call_pc)
{
	if (!IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
		return;

	add_kcsan_stack_depth(1);
}
EXPORT_SYMBOL(__tsan_func_entry);

void __tsan_func_exit(void);
noinline void __tsan_func_exit(void)
{
	struct kcsan_scoped_access *reorder_access;

	if (!IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
		return;

	reorder_access = get_reorder_access(get_ctx());
	if (!reorder_access)
		goto out;

	if (get_kcsan_stack_depth() <= reorder_access->stack_depth) {
		/*
		check_access(reorder_access->ptr, reorder_access->size,
			     reorder_access->type, reorder_access->ip);
		reorder_access->size = 0;
		reorder_access->stack_depth = INT_MIN;
	}
out:
	add_kcsan_stack_depth(-1);
}
EXPORT_SYMBOL(__tsan_func_exit);

void __tsan_init(void);
void __tsan_init(void)
{
}
EXPORT_SYMBOL(__tsan_init);


static __always_inline void kcsan_atomic_builtin_memorder(int memorder)
{
	if (memorder == __ATOMIC_RELEASE ||
	    memorder == __ATOMIC_SEQ_CST ||
	    memorder == __ATOMIC_ACQ_REL)
		__kcsan_release();
}

#define DEFINE_TSAN_ATOMIC_LOAD_STORE(bits)                                                        \
	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
	{                                                                                          \
		kcsan_atomic_builtin_memorder(memorder);                                           \
		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC, _RET_IP_);    \
		}                                                                                  \
		return __atomic_load_n(ptr, memorder);                                             \
	}                                                                                          \
	EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
	{                                                                                          \
		kcsan_atomic_builtin_memorder(memorder);                                           \
		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
			check_access(ptr, bits / BITS_PER_BYTE,                                    \
				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
		}                                                                                  \
		__atomic_store_n(ptr, v, memorder);                                                \
	}                                                                                          \
	EXPORT_SYMBOL(__tsan_atomic##bits##_store)

#define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
	{                                                                                          \
		kcsan_atomic_builtin_memorder(memorder);                                           \
		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
			check_access(ptr, bits / BITS_PER_BYTE,                                    \
				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
					     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
		}                                                                                  \
		return __atomic_##op##suffix(ptr, v, memorder);                                    \
	}                                                                                          \
	EXPORT_SYMBOL(__tsan_atomic##bits##_##op)

#define DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strength, weak)                                           \
	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
							      u##bits val, int mo, int fail_mo);   \
	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
							      u##bits val, int mo, int fail_mo)    \
	{                                                                                          \
		kcsan_atomic_builtin_memorder(mo);                                                 \
		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
			check_access(ptr, bits / BITS_PER_BYTE,                                    \
				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
					     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
		}                                                                                  \
		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
	}                                                                                          \
	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)

#define DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)                                                       \
	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
							   int mo, int fail_mo);                   \
	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
							   int mo, int fail_mo)                    \
	{                                                                                          \
		kcsan_atomic_builtin_memorder(mo);                                                 \
		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
			check_access(ptr, bits / BITS_PER_BYTE,                                    \
				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
					     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
		}                                                                                  \
		__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
		return exp;                                                                        \
	}                                                                                          \
	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_val)

#define DEFINE_TSAN_ATOMIC_OPS(bits)                                                               \
	DEFINE_TSAN_ATOMIC_LOAD_STORE(bits);                                                       \
	DEFINE_TSAN_ATOMIC_RMW(exchange, bits, _n);                                                \
	DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits, );                                                 \
	DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits, );                                                 \
	DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits, );                                                 \
	DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits, );                                                  \
	DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits, );                                                 \
	DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits, );                                                \
	DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strong, 0);                                               \
	DEFINE_TSAN_ATOMIC_CMPXCHG(bits, weak, 1);                                                 \
	DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)

DEFINE_TSAN_ATOMIC_OPS(8);
DEFINE_TSAN_ATOMIC_OPS(16);
DEFINE_TSAN_ATOMIC_OPS(32);
DEFINE_TSAN_ATOMIC_OPS(64);

void __tsan_atomic_thread_fence(int memorder);
void __tsan_atomic_thread_fence(int memorder)
{
	kcsan_atomic_builtin_memorder(memorder);
	__atomic_thread_fence(memorder);
}
EXPORT_SYMBOL(__tsan_atomic_thread_fence);

void __tsan_atomic_signal_fence(int memorder);
noinline void __tsan_atomic_signal_fence(int memorder)
{
	switch (memorder) {
	case __KCSAN_BARRIER_TO_SIGNAL_FENCE_mb:
		__kcsan_mb();
		break;
	case __KCSAN_BARRIER_TO_SIGNAL_FENCE_wmb:
		__kcsan_wmb();
		break;
	case __KCSAN_BARRIER_TO_SIGNAL_FENCE_rmb:
		__kcsan_rmb();
		break;
	case __KCSAN_BARRIER_TO_SIGNAL_FENCE_release:
		__kcsan_release();
		break;
	default:
		break;
	}
}
EXPORT_SYMBOL(__tsan_atomic_signal_fence);
