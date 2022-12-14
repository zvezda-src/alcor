
#include <linux/irq.h>
#include <linux/profile.h>
#include <linux/timekeeper_internal.h>

#include "tick-internal.h"

void legacy_timer_tick(unsigned long ticks)
{
	if (ticks) {
		raw_spin_lock(&jiffies_lock);
		write_seqcount_begin(&jiffies_seq);
		do_timer(ticks);
		write_seqcount_end(&jiffies_seq);
		raw_spin_unlock(&jiffies_lock);
		update_wall_time();
	}
	update_process_times(user_mode(get_irq_regs()));
	profile_tick(CPU_PROFILING);
}
