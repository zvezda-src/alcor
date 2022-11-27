
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/suspend.h>
#include <linux/syscore_ops.h>

#include "internals.h"

bool irq_pm_check_wakeup(struct irq_desc *desc)
{
	if (irqd_is_wakeup_armed(&desc->irq_data)) {
		irqd_clear(&desc->irq_data, IRQD_WAKEUP_ARMED);
		desc->istate |= IRQS_SUSPENDED | IRQS_PENDING;
		desc->depth++;
		irq_disable(desc);
		pm_system_irq_wakeup(irq_desc_get_irq(desc));
		return true;
	}
	return false;
}

void irq_pm_install_action(struct irq_desc *desc, struct irqaction *action)
{
	desc->nr_actions++;

	if (action->flags & IRQF_FORCE_RESUME)
		desc->force_resume_depth++;

	WARN_ON_ONCE(desc->force_resume_depth &&
		     desc->force_resume_depth != desc->nr_actions);

	if (action->flags & IRQF_NO_SUSPEND)
		desc->no_suspend_depth++;
	else if (action->flags & IRQF_COND_SUSPEND)
		desc->cond_suspend_depth++;

	WARN_ON_ONCE(desc->no_suspend_depth &&
		     (desc->no_suspend_depth +
			desc->cond_suspend_depth) != desc->nr_actions);
}

void irq_pm_remove_action(struct irq_desc *desc, struct irqaction *action)
{
	desc->nr_actions--;

	if (action->flags & IRQF_FORCE_RESUME)
		desc->force_resume_depth--;

	if (action->flags & IRQF_NO_SUSPEND)
		desc->no_suspend_depth--;
	else if (action->flags & IRQF_COND_SUSPEND)
		desc->cond_suspend_depth--;
}

static bool suspend_device_irq(struct irq_desc *desc)
{
	unsigned long chipflags = irq_desc_get_chip(desc)->flags;
	struct irq_data *irqd = &desc->irq_data;

	if (!desc->action || irq_desc_is_chained(desc) ||
	    desc->no_suspend_depth)
		return false;

	if (irqd_is_wakeup_set(irqd)) {
		irqd_set(irqd, IRQD_WAKEUP_ARMED);

		if ((chipflags & IRQCHIP_ENABLE_WAKEUP_ON_SUSPEND) &&
		     irqd_irq_disabled(irqd)) {
			/*
			__enable_irq(desc);
			irqd_set(irqd, IRQD_IRQ_ENABLED_ON_SUSPEND);
		}
		/*
		return true;
	}

	desc->istate |= IRQS_SUSPENDED;
	__disable_irq(desc);

	/*
	if (chipflags & IRQCHIP_MASK_ON_SUSPEND)
		mask_irq(desc);
	return true;
}

void suspend_device_irqs(void)
{
	struct irq_desc *desc;
	int irq;

	for_each_irq_desc(irq, desc) {
		unsigned long flags;
		bool sync;

		if (irq_settings_is_nested_thread(desc))
			continue;
		raw_spin_lock_irqsave(&desc->lock, flags);
		sync = suspend_device_irq(desc);
		raw_spin_unlock_irqrestore(&desc->lock, flags);

		if (sync)
			synchronize_irq(irq);
	}
}

static void resume_irq(struct irq_desc *desc)
{
	struct irq_data *irqd = &desc->irq_data;

	irqd_clear(irqd, IRQD_WAKEUP_ARMED);

	if (irqd_is_enabled_on_suspend(irqd)) {
		/*
		__disable_irq(desc);
		irqd_clear(irqd, IRQD_IRQ_ENABLED_ON_SUSPEND);
	}

	if (desc->istate & IRQS_SUSPENDED)
		goto resume;

	/* Force resume the interrupt? */
	if (!desc->force_resume_depth)
		return;

	/* Pretend that it got disabled ! */
	desc->depth++;
	irq_state_set_disabled(desc);
	irq_state_set_masked(desc);
resume:
	desc->istate &= ~IRQS_SUSPENDED;
	__enable_irq(desc);
}

static void resume_irqs(bool want_early)
{
	struct irq_desc *desc;
	int irq;

	for_each_irq_desc(irq, desc) {
		unsigned long flags;
		bool is_early = desc->action &&
			desc->action->flags & IRQF_EARLY_RESUME;

		if (!is_early && want_early)
			continue;
		if (irq_settings_is_nested_thread(desc))
			continue;

		raw_spin_lock_irqsave(&desc->lock, flags);
		resume_irq(desc);
		raw_spin_unlock_irqrestore(&desc->lock, flags);
	}
}

void rearm_wake_irq(unsigned int irq)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, IRQ_GET_DESC_CHECK_GLOBAL);

	if (!desc)
		return;

	if (!(desc->istate & IRQS_SUSPENDED) ||
	    !irqd_is_wakeup_set(&desc->irq_data))
		goto unlock;

	desc->istate &= ~IRQS_SUSPENDED;
	irqd_set(&desc->irq_data, IRQD_WAKEUP_ARMED);
	__enable_irq(desc);

unlock:
	irq_put_desc_busunlock(desc, flags);
}

static void irq_pm_syscore_resume(void)
{
	resume_irqs(true);
}

static struct syscore_ops irq_pm_syscore_ops = {
	.resume		= irq_pm_syscore_resume,
};

static int __init irq_pm_init_ops(void)
{
	register_syscore_ops(&irq_pm_syscore_ops);
	return 0;
}

device_initcall(irq_pm_init_ops);

void resume_device_irqs(void)
{
	resume_irqs(false);
}
