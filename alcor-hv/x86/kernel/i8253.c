#include <linux/clockchips.h>
#include <linux/init.h>
#include <linux/timex.h>
#include <linux/i8253.h>

#include <asm/apic.h>
#include <asm/hpet.h>
#include <asm/time.h>
#include <asm/smp.h>

struct clock_event_device *global_clock_event;

static bool __init use_pit(void)
{
	if (!IS_ENABLED(CONFIG_X86_TSC) || !boot_cpu_has(X86_FEATURE_TSC))
		return true;

	/* This also returns true when APIC is disabled */
	return apic_needs_pit();
}

bool __init pit_timer_init(void)
{
	if (!use_pit())
		return false;

	clockevent_i8253_init(true);
	global_clock_event = &i8253_clockevent;
	return true;
}

#ifndef CONFIG_X86_64
static int __init init_pit_clocksource(void)
{
	 /*
	if (num_possible_cpus() > 1 || is_hpet_enabled() ||
	    !clockevent_state_periodic(&i8253_clockevent))
		return 0;

	return clocksource_i8253_init();
}
arch_initcall(init_pit_clocksource);
#endif /* !CONFIG_X86_64 */
