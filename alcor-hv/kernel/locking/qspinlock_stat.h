
#include "lock_events.h"

#ifdef CONFIG_LOCK_EVENT_COUNTS
#ifdef CONFIG_PARAVIRT_SPINLOCKS
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/fs.h>

#define EVENT_COUNT(ev)	lockevents[LOCKEVENT_ ## ev]

static DEFINE_PER_CPU(u64, pv_kick_time);

ssize_t lockevent_read(struct file *file, char __user *user_buf,
		       size_t count, loff_t *ppos)
{
	char buf[64];
	int cpu, id, len;
	u64 sum = 0, kicks = 0;

	/*
	id = (long)file_inode(file)->i_private;

	if (id >= lockevent_num)
		return -EBADF;

	for_each_possible_cpu(cpu) {
		sum += per_cpu(lockevents[id], cpu);
		/*
		switch (id) {

		case LOCKEVENT_pv_latency_kick:
		case LOCKEVENT_pv_hash_hops:
			kicks += per_cpu(EVENT_COUNT(pv_kick_unlock), cpu);
			break;

		case LOCKEVENT_pv_latency_wake:
			kicks += per_cpu(EVENT_COUNT(pv_kick_wake), cpu);
			break;
		}
	}

	if (id == LOCKEVENT_pv_hash_hops) {
		u64 frac = 0;

		if (kicks) {
			frac = 100ULL * do_div(sum, kicks);
			frac = DIV_ROUND_CLOSEST_ULL(frac, kicks);
		}

		/*
		len = snprintf(buf, sizeof(buf) - 1, "%llu.%02llu\n",
			       sum, frac);
	} else {
		/*
		if ((id == LOCKEVENT_pv_latency_kick) ||
		    (id == LOCKEVENT_pv_latency_wake)) {
			if (kicks)
				sum = DIV_ROUND_CLOSEST_ULL(sum, kicks);
		}
		len = snprintf(buf, sizeof(buf) - 1, "%llu\n", sum);
	}

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static inline void lockevent_pv_hop(int hopcnt)
{
	this_cpu_add(EVENT_COUNT(pv_hash_hops), hopcnt);
}

static inline void __pv_kick(int cpu)
{
	u64 start = sched_clock();

	per_cpu(pv_kick_time, cpu) = start;
	pv_kick(cpu);
	this_cpu_add(EVENT_COUNT(pv_latency_kick), sched_clock() - start);
}

static inline void __pv_wait(u8 *ptr, u8 val)
{
	u64 *pkick_time = this_cpu_ptr(&pv_kick_time);

	pv_wait(ptr, val);
	if (*pkick_time) {
		this_cpu_add(EVENT_COUNT(pv_latency_wake),
			     sched_clock() - *pkick_time);
		lockevent_inc(pv_kick_wake);
	}
}

#define pv_kick(c)	__pv_kick(c)
#define pv_wait(p, v)	__pv_wait(p, v)

#endif /* CONFIG_PARAVIRT_SPINLOCKS */

#else /* CONFIG_LOCK_EVENT_COUNTS */

static inline void lockevent_pv_hop(int hopcnt)	{ }

#endif /* CONFIG_LOCK_EVENT_COUNTS */
