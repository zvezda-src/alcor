
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/interrupt.h>

#include "internals.h"

#ifdef CONFIG_HARDIRQS_SW_RESEND

static DECLARE_BITMAP(irqs_resend, IRQ_BITMAP_BITS);

static void resend_irqs(struct tasklet_struct *unused)
{
	struct irq_desc *desc;
	int irq;

	while (!bitmap_empty(irqs_resend, nr_irqs)) {
		irq = find_first_bit(irqs_resend, nr_irqs);
		clear_bit(irq, irqs_resend);
		desc = irq_to_desc(irq);
		if (!desc)
			continue;
		local_irq_disable();
		desc->handle_irq(desc);
		local_irq_enable();
	}
}

static DECLARE_TASKLET(resend_tasklet, resend_irqs);

static int irq_sw_resend(struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);

	/*
	if (handle_enforce_irqctx(&desc->irq_data))
		return -EINVAL;

	/*
	if (irq_settings_is_nested_thread(desc)) {
		/*
		if (!desc->parent_irq)
			return -EINVAL;
		irq = desc->parent_irq;
	}

	/* Set it pending and activate the softirq: */
	set_bit(irq, irqs_resend);
	tasklet_schedule(&resend_tasklet);
	return 0;
}

#else
static int irq_sw_resend(struct irq_desc *desc)
{
	return -EINVAL;
}
#endif

static int try_retrigger(struct irq_desc *desc)
{
	if (desc->irq_data.chip->irq_retrigger)
		return desc->irq_data.chip->irq_retrigger(&desc->irq_data);

#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
	return irq_chip_retrigger_hierarchy(&desc->irq_data);
#else
	return 0;
#endif
}

int check_irq_resend(struct irq_desc *desc, bool inject)
{
	int err = 0;

	/*
	if (irq_settings_is_level(desc)) {
		desc->istate &= ~IRQS_PENDING;
		return -EINVAL;
	}

	if (desc->istate & IRQS_REPLAY)
		return -EBUSY;

	if (!(desc->istate & IRQS_PENDING) && !inject)
		return 0;

	desc->istate &= ~IRQS_PENDING;

	if (!try_retrigger(desc))
		err = irq_sw_resend(desc);

	/* If the retrigger was successful, mark it with the REPLAY bit */
	if (!err)
		desc->istate |= IRQS_REPLAY;
	return err;
}

#ifdef CONFIG_GENERIC_IRQ_INJECTION
int irq_inject_interrupt(unsigned int irq)
{
	struct irq_desc *desc;
	unsigned long flags;
	int err;

	/* Try the state injection hardware interface first */
	if (!irq_set_irqchip_state(irq, IRQCHIP_STATE_PENDING, true))
		return 0;

	/* That failed, try via the resend mechanism */
	desc = irq_get_desc_buslock(irq, &flags, 0);
	if (!desc)
		return -EINVAL;

	/*
	if ((desc->istate & IRQS_NMI) || !irqd_is_activated(&desc->irq_data))
		err = -EINVAL;
	else
		err = check_irq_resend(desc, true);

	irq_put_desc_busunlock(desc, flags);
	return err;
}
EXPORT_SYMBOL_GPL(irq_inject_interrupt);
#endif
