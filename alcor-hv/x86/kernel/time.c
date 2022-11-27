
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/i8253.h>
#include <linux/time.h>
#include <linux/export.h>

#include <asm/vsyscall.h>
#include <asm/x86_init.h>
#include <asm/i8259.h>
#include <asm/timer.h>
#include <asm/hpet.h>
#include <asm/time.h>

unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	if (!user_mode(regs) && in_lock_functions(pc)) {
#ifdef CONFIG_FRAME_POINTER
		return *(unsigned long *)(regs->bp + sizeof(long));
#else
		unsigned long *sp = (unsigned long *)regs->sp;
		/*
		if (sp[0] >> 22)
			return sp[0];
		if (sp[1] >> 22)
			return sp[1];
#endif
	}
	return pc;
}
EXPORT_SYMBOL(profile_pc);

static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	global_clock_event->event_handler(global_clock_event);
	return IRQ_HANDLED;
}

static void __init setup_default_timer_irq(void)
{
	unsigned long flags = IRQF_NOBALANCING | IRQF_IRQPOLL | IRQF_TIMER;

	/*
	if (request_irq(0, timer_interrupt, flags, "timer", NULL))
		pr_info("Failed to register legacy timer interrupt\n");
}

void __init hpet_time_init(void)
{
	if (!hpet_enable()) {
		if (!pit_timer_init())
			return;
	}

	setup_default_timer_irq();
}

static __init void x86_late_time_init(void)
{
	/*
	x86_init.irqs.intr_mode_select();

	/* Setup the legacy timers */
	x86_init.timers.timer_init();

	/*
	x86_init.irqs.intr_mode_init();
	tsc_init();

	if (static_cpu_has(X86_FEATURE_WAITPKG))
		use_tpause_delay();
}

void __init time_init(void)
{
	late_time_init = x86_late_time_init;
}

void clocksource_arch_init(struct clocksource *cs)
{
	if (cs->vdso_clock_mode == VDSO_CLOCKMODE_NONE)
		return;

	if (cs->mask != CLOCKSOURCE_MASK(64)) {
		pr_warn("clocksource %s registered with invalid mask %016llx for VDSO. Disabling VDSO support.\n",
			cs->name, cs->mask);
		cs->vdso_clock_mode = VDSO_CLOCKMODE_NONE;
	}
}
