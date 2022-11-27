#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/clockchips.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/module.h>

#include "tick-internal.h"

static struct hrtimer bctimer;

static int bc_shutdown(struct clock_event_device *evt)
{
	/*
	hrtimer_try_to_cancel(&bctimer);
	return 0;
}

static int bc_set_next(ktime_t expires, struct clock_event_device *bc)
{
	/*
	RCU_NONIDLE( {
		hrtimer_start(&bctimer, expires, HRTIMER_MODE_ABS_PINNED_HARD);
		/*
		bc->bound_on = bctimer.base->cpu_base->cpu;
	} );
	return 0;
}

static struct clock_event_device ce_broadcast_hrtimer = {
	.name			= "bc_hrtimer",
	.set_state_shutdown	= bc_shutdown,
	.set_next_ktime		= bc_set_next,
	.features		= CLOCK_EVT_FEAT_ONESHOT |
				  CLOCK_EVT_FEAT_KTIME |
				  CLOCK_EVT_FEAT_HRTIMER,
	.rating			= 0,
	.bound_on		= -1,
	.min_delta_ns		= 1,
	.max_delta_ns		= KTIME_MAX,
	.min_delta_ticks	= 1,
	.max_delta_ticks	= ULONG_MAX,
	.mult			= 1,
	.shift			= 0,
	.cpumask		= cpu_possible_mask,
};

static enum hrtimer_restart bc_handler(struct hrtimer *t)
{
	ce_broadcast_hrtimer.event_handler(&ce_broadcast_hrtimer);

	return HRTIMER_NORESTART;
}

void tick_setup_hrtimer_broadcast(void)
{
	hrtimer_init(&bctimer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_HARD);
	bctimer.function = bc_handler;
	clockevents_register_device(&ce_broadcast_hrtimer);
}
