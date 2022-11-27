#define pr_fmt(fmt) "irq_timings: " fmt

#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/static_key.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/idr.h>
#include <linux/irq.h>
#include <linux/math64.h>
#include <linux/log2.h>

#include <trace/events/irq.h>

#include "internals.h"

DEFINE_STATIC_KEY_FALSE(irq_timing_enabled);

DEFINE_PER_CPU(struct irq_timings, irq_timings);

static DEFINE_IDR(irqt_stats);

void irq_timings_enable(void)
{
	static_branch_enable(&irq_timing_enabled);
}

void irq_timings_disable(void)
{
	static_branch_disable(&irq_timing_enabled);
}

#define EMA_ALPHA_VAL		64
#define EMA_ALPHA_SHIFT		7

#define PREDICTION_PERIOD_MIN	3
#define PREDICTION_PERIOD_MAX	5
#define PREDICTION_FACTOR	4
#define PREDICTION_MAX		10 /* 2 ^ PREDICTION_MAX useconds */
#define PREDICTION_BUFFER_SIZE	16 /* slots for EMAs, hardly more than 16 */

#define for_each_irqts(i, irqts)					\
	for (i = irqts->count < IRQ_TIMINGS_SIZE ?			\
		     0 : irqts->count & IRQ_TIMINGS_MASK,		\
		     irqts->count = min(IRQ_TIMINGS_SIZE,		\
					irqts->count);			\
	     irqts->count > 0; irqts->count--,				\
		     i = (i + 1) & IRQ_TIMINGS_MASK)

struct irqt_stat {
	u64	last_ts;
	u64	ema_time[PREDICTION_BUFFER_SIZE];
	int	timings[IRQ_TIMINGS_SIZE];
	int	circ_timings[IRQ_TIMINGS_SIZE];
	int	count;
};

static u64 irq_timings_ema_new(u64 value, u64 ema_old)
{
	s64 diff;

	if (unlikely(!ema_old))
		return value;

	diff = (value - ema_old) * EMA_ALPHA_VAL;
	/*
	return ema_old + (diff >> EMA_ALPHA_SHIFT);
}

static int irq_timings_next_event_index(int *buffer, size_t len, int period_max)
{
	int period;

	/*
	buffer = &buffer[len - (period_max * 3)];

	/* Adjust the length to the maximum allowed period x 3 */
	len = period_max * 3;

	/*
	for (period = period_max; period >= PREDICTION_PERIOD_MIN; period--) {

		/*
		int idx = period;
		size_t size = period;

		/*
		while (!memcmp(buffer, &buffer[idx], size * sizeof(int))) {

			/*
			idx += size;

			/*
			if (idx == len)
				return buffer[len % period];

			/*
			if (len - idx < period)
				size = len - idx;
		}
	}

	return -1;
}

static u64 __irq_timings_next_event(struct irqt_stat *irqs, int irq, u64 now)
{
	int index, i, period_max, count, start, min = INT_MAX;

	if ((now - irqs->last_ts) >= NSEC_PER_SEC) {
		irqs->count = irqs->last_ts = 0;
		return U64_MAX;
	}

	/*
	period_max = irqs->count > (3 * PREDICTION_PERIOD_MAX) ?
		PREDICTION_PERIOD_MAX : irqs->count / 3;

	/*
	if (period_max <= PREDICTION_PERIOD_MIN)
		return U64_MAX;

	/*
	count = irqs->count < IRQ_TIMINGS_SIZE ?
		irqs->count : IRQ_TIMINGS_SIZE;

	start = irqs->count < IRQ_TIMINGS_SIZE ?
		0 : (irqs->count & IRQ_TIMINGS_MASK);

	/*
	for (i = 0; i < count; i++) {
		int index = (start + i) & IRQ_TIMINGS_MASK;

		irqs->timings[i] = irqs->circ_timings[index];
		min = min_t(int, irqs->timings[i], min);
	}

	index = irq_timings_next_event_index(irqs->timings, count, period_max);
	if (index < 0)
		return irqs->last_ts + irqs->ema_time[min];

	return irqs->last_ts + irqs->ema_time[index];
}

static __always_inline int irq_timings_interval_index(u64 interval)
{
	/*
	u64 interval_us = (interval >> 10) / PREDICTION_FACTOR;

	return likely(interval_us) ? ilog2(interval_us) : 0;
}

static __always_inline void __irq_timings_store(int irq, struct irqt_stat *irqs,
						u64 interval)
{
	int index;

	/*
	index = irq_timings_interval_index(interval);

	if (index > PREDICTION_BUFFER_SIZE - 1) {
		irqs->count = 0;
		return;
	}

	/*
	irqs->circ_timings[irqs->count & IRQ_TIMINGS_MASK] = index;

	irqs->ema_time[index] = irq_timings_ema_new(interval,
						    irqs->ema_time[index]);

	irqs->count++;
}

static inline void irq_timings_store(int irq, struct irqt_stat *irqs, u64 ts)
{
	u64 old_ts = irqs->last_ts;
	u64 interval;

	/*
	irqs->last_ts = ts;

	/*
	interval = ts - old_ts;

	/*
	if (interval >= NSEC_PER_SEC) {
		irqs->count = 0;
		return;
	}

	__irq_timings_store(irq, irqs, interval);
}

u64 irq_timings_next_event(u64 now)
{
	struct irq_timings *irqts = this_cpu_ptr(&irq_timings);
	struct irqt_stat *irqs;
	struct irqt_stat __percpu *s;
	u64 ts, next_evt = U64_MAX;
	int i, irq = 0;

	/*
	lockdep_assert_irqs_disabled();

	if (!irqts->count)
		return next_evt;

	/*
	for_each_irqts(i, irqts) {
		irq = irq_timing_decode(irqts->values[i], &ts);
		s = idr_find(&irqt_stats, irq);
		if (s)
			irq_timings_store(irq, this_cpu_ptr(s), ts);
	}

	/*
	idr_for_each_entry(&irqt_stats, s, i) {

		irqs = this_cpu_ptr(s);

		ts = __irq_timings_next_event(irqs, i, now);
		if (ts <= now)
			return now;

		if (ts < next_evt)
			next_evt = ts;
	}

	return next_evt;
}

void irq_timings_free(int irq)
{
	struct irqt_stat __percpu *s;

	s = idr_find(&irqt_stats, irq);
	if (s) {
		free_percpu(s);
		idr_remove(&irqt_stats, irq);
	}
}

int irq_timings_alloc(int irq)
{
	struct irqt_stat __percpu *s;
	int id;

	/*
	s = idr_find(&irqt_stats, irq);
	if (s)
		return 0;

	s = alloc_percpu(*s);
	if (!s)
		return -ENOMEM;

	idr_preload(GFP_KERNEL);
	id = idr_alloc(&irqt_stats, s, irq, irq + 1, GFP_NOWAIT);
	idr_preload_end();

	if (id < 0) {
		free_percpu(s);
		return id;
	}

	return 0;
}

#ifdef CONFIG_TEST_IRQ_TIMINGS
struct timings_intervals {
	u64 *intervals;
	size_t count;
};

static u64 intervals0[] __initdata = {
	10000, 50000, 200000, 500000,
	10000, 50000, 200000, 500000,
	10000, 50000, 200000, 500000,
	10000, 50000, 200000, 500000,
	10000, 50000, 200000, 500000,
	10000, 50000, 200000, 500000,
	10000, 50000, 200000, 500000,
	10000, 50000, 200000, 500000,
	10000, 50000, 200000,
};

static u64 intervals1[] __initdata = {
	223947000, 1240000, 1384000, 1386000, 1386000,
	217416000, 1236000, 1384000, 1386000, 1387000,
	214719000, 1241000, 1386000, 1387000, 1384000,
	213696000, 1234000, 1384000, 1386000, 1388000,
	219904000, 1240000, 1385000, 1389000, 1385000,
	212240000, 1240000, 1386000, 1386000, 1386000,
	214415000, 1236000, 1384000, 1386000, 1387000,
	214276000, 1234000,
};

static u64 intervals2[] __initdata = {
	4000, 3000, 5000, 100000,
	3000, 3000, 5000, 117000,
	4000, 4000, 5000, 112000,
	4000, 3000, 4000, 110000,
	3000, 5000, 3000, 117000,
	4000, 4000, 5000, 112000,
	4000, 3000, 4000, 110000,
	3000, 4000, 5000, 112000,
	4000,
};

static u64 intervals3[] __initdata = {
	1385000, 212240000, 1240000,
	1386000, 214415000, 1236000,
	1384000, 214276000, 1234000,
	1386000, 214415000, 1236000,
	1385000, 212240000, 1240000,
	1386000, 214415000, 1236000,
	1384000, 214276000, 1234000,
	1386000, 214415000, 1236000,
	1385000, 212240000, 1240000,
};

static u64 intervals4[] __initdata = {
	10000, 50000, 10000, 50000,
	10000, 50000, 10000, 50000,
	10000, 50000, 10000, 50000,
	10000, 50000, 10000, 50000,
	10000, 50000, 10000, 50000,
	10000, 50000, 10000, 50000,
	10000, 50000, 10000, 50000,
	10000, 50000, 10000, 50000,
	10000,
};

static struct timings_intervals tis[] __initdata = {
	{ intervals0, ARRAY_SIZE(intervals0) },
	{ intervals1, ARRAY_SIZE(intervals1) },
	{ intervals2, ARRAY_SIZE(intervals2) },
	{ intervals3, ARRAY_SIZE(intervals3) },
	{ intervals4, ARRAY_SIZE(intervals4) },
};

static int __init irq_timings_test_next_index(struct timings_intervals *ti)
{
	int _buffer[IRQ_TIMINGS_SIZE];
	int buffer[IRQ_TIMINGS_SIZE];
	int index, start, i, count, period_max;

	count = ti->count - 1;

	period_max = count > (3 * PREDICTION_PERIOD_MAX) ?
		PREDICTION_PERIOD_MAX : count / 3;

	/*
	pr_debug("index suite: ");

	for (i = 0; i < count; i++) {
		index = irq_timings_interval_index(ti->intervals[i]);
		_buffer[i & IRQ_TIMINGS_MASK] = index;
		pr_cont("%d ", index);
	}

	start = count < IRQ_TIMINGS_SIZE ? 0 :
		count & IRQ_TIMINGS_MASK;

	count = min_t(int, count, IRQ_TIMINGS_SIZE);

	for (i = 0; i < count; i++) {
		int index = (start + i) & IRQ_TIMINGS_MASK;
		buffer[i] = _buffer[index];
	}

	index = irq_timings_next_event_index(buffer, count, period_max);
	i = irq_timings_interval_index(ti->intervals[ti->count - 1]);

	if (index != i) {
		pr_err("Expected (%d) and computed (%d) next indexes differ\n",
		       i, index);
		return -EINVAL;
	}

	return 0;
}

static int __init irq_timings_next_index_selftest(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(tis); i++) {

		pr_info("---> Injecting intervals number #%d (count=%zd)\n",
			i, tis[i].count);

		ret = irq_timings_test_next_index(&tis[i]);
		if (ret)
			break;
	}

	return ret;
}

static int __init irq_timings_test_irqs(struct timings_intervals *ti)
{
	struct irqt_stat __percpu *s;
	struct irqt_stat *irqs;
	int i, index, ret, irq = 0xACE5;

	ret = irq_timings_alloc(irq);
	if (ret) {
		pr_err("Failed to allocate irq timings\n");
		return ret;
	}

	s = idr_find(&irqt_stats, irq);
	if (!s) {
		ret = -EIDRM;
		goto out;
	}

	irqs = this_cpu_ptr(s);

	for (i = 0; i < ti->count; i++) {

		index = irq_timings_interval_index(ti->intervals[i]);
		pr_debug("%d: interval=%llu ema_index=%d\n",
			 i, ti->intervals[i], index);

		__irq_timings_store(irq, irqs, ti->intervals[i]);
		if (irqs->circ_timings[i & IRQ_TIMINGS_MASK] != index) {
			ret = -EBADSLT;
			pr_err("Failed to store in the circular buffer\n");
			goto out;
		}
	}

	if (irqs->count != ti->count) {
		ret = -ERANGE;
		pr_err("Count differs\n");
		goto out;
	}

	ret = 0;
out:
	irq_timings_free(irq);

	return ret;
}

static int __init irq_timings_irqs_selftest(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(tis); i++) {
		pr_info("---> Injecting intervals number #%d (count=%zd)\n",
			i, tis[i].count);
		ret = irq_timings_test_irqs(&tis[i]);
		if (ret)
			break;
	}

	return ret;
}

static int __init irq_timings_test_irqts(struct irq_timings *irqts,
					 unsigned count)
{
	int start = count >= IRQ_TIMINGS_SIZE ? count - IRQ_TIMINGS_SIZE : 0;
	int i, irq, oirq = 0xBEEF;
	u64 ots = 0xDEAD, ts;

	/*
	for (i = 0; i < count; i++) {
		pr_debug("%d: index=%d, ts=%llX irq=%X\n",
			 i, i & IRQ_TIMINGS_MASK, ots + i, oirq + i);

		irq_timings_push(ots + i, oirq + i);
	}

	/*
	ots += start;
	oirq += start;

	/*
	pr_debug("---> Checking timings array count (%d) is right\n", count);
	if (WARN_ON(irqts->count != count))
		return -EINVAL;

	/*
	pr_debug("---> Checking the for_each_irqts() macro\n");
	for_each_irqts(i, irqts) {

		irq = irq_timing_decode(irqts->values[i], &ts);

		pr_debug("index=%d, ts=%llX / %llX, irq=%X / %X\n",
			 i, ts, ots, irq, oirq);

		if (WARN_ON(ts != ots || irq != oirq))
			return -EINVAL;

		ots++; oirq++;
	}

	/*
	pr_debug("---> Checking timings array is empty after browsing it\n");
	if (WARN_ON(irqts->count))
		return -EINVAL;

	return 0;
}

static int __init irq_timings_irqts_selftest(void)
{
	struct irq_timings *irqts = this_cpu_ptr(&irq_timings);
	int i, ret;

	/*
	int count[] = { 0,
			IRQ_TIMINGS_SIZE >> 1,
			IRQ_TIMINGS_SIZE,
			IRQ_TIMINGS_SIZE + (IRQ_TIMINGS_SIZE >> 1),
			2 * IRQ_TIMINGS_SIZE,
			(2 * IRQ_TIMINGS_SIZE) + 3,
	};

	for (i = 0; i < ARRAY_SIZE(count); i++) {

		pr_info("---> Checking the timings with %d/%d values\n",
			count[i], IRQ_TIMINGS_SIZE);

		ret = irq_timings_test_irqts(irqts, count[i]);
		if (ret)
			break;
	}

	return ret;
}

static int __init irq_timings_selftest(void)
{
	int ret;

	pr_info("------------------- selftest start -----------------\n");

	/*
	if (static_branch_unlikely(&irq_timing_enabled)) {
		pr_warn("irq timings already initialized, skipping selftest\n");
		return 0;
	}

	ret = irq_timings_irqts_selftest();
	if (ret)
		goto out;

	ret = irq_timings_irqs_selftest();
	if (ret)
		goto out;

	ret = irq_timings_next_index_selftest();
out:
	pr_info("---------- selftest end with %s -----------\n",
		ret ? "failure" : "success");

	return ret;
}
early_initcall(irq_timings_selftest);
#endif
