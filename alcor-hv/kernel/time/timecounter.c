#include <linux/export.h>
#include <linux/timecounter.h>

void timecounter_init(struct timecounter *tc,
		      const struct cyclecounter *cc,
		      u64 start_tstamp)
{
	tc->cc = cc;
	tc->cycle_last = cc->read(cc);
	tc->nsec = start_tstamp;
	tc->mask = (1ULL << cc->shift) - 1;
	tc->frac = 0;
}
EXPORT_SYMBOL_GPL(timecounter_init);

static u64 timecounter_read_delta(struct timecounter *tc)
{
	u64 cycle_now, cycle_delta;
	u64 ns_offset;

	/* read cycle counter: */
	cycle_now = tc->cc->read(tc->cc);

	/* calculate the delta since the last timecounter_read_delta(): */
	cycle_delta = (cycle_now - tc->cycle_last) & tc->cc->mask;

	/* convert to nanoseconds: */
	ns_offset = cyclecounter_cyc2ns(tc->cc, cycle_delta,
					tc->mask, &tc->frac);

	/* update time stamp of timecounter_read_delta() call: */
	tc->cycle_last = cycle_now;

	return ns_offset;
}

u64 timecounter_read(struct timecounter *tc)
{
	u64 nsec;

	/* increment time by nanoseconds since last call */
	nsec = timecounter_read_delta(tc);
	nsec += tc->nsec;
	tc->nsec = nsec;

	return nsec;
}
EXPORT_SYMBOL_GPL(timecounter_read);

static u64 cc_cyc2ns_backwards(const struct cyclecounter *cc,
			       u64 cycles, u64 mask, u64 frac)
{
	u64 ns = (u64) cycles;

	ns = ((ns * cc->mult) - frac) >> cc->shift;

	return ns;
}

u64 timecounter_cyc2time(const struct timecounter *tc,
			 u64 cycle_tstamp)
{
	u64 delta = (cycle_tstamp - tc->cycle_last) & tc->cc->mask;
	u64 nsec = tc->nsec, frac = tc->frac;

	/*
	if (delta > tc->cc->mask / 2) {
		delta = (tc->cycle_last - cycle_tstamp) & tc->cc->mask;
		nsec -= cc_cyc2ns_backwards(tc->cc, delta, tc->mask, frac);
	} else {
		nsec += cyclecounter_cyc2ns(tc->cc, delta, tc->mask, &frac);
	}

	return nsec;
}
EXPORT_SYMBOL_GPL(timecounter_cyc2time);
