
#include <linux/irq.h>
#include <linux/interrupt.h>

#include "internals.h"

bool irq_fixup_move_pending(struct irq_desc *desc, bool force_clear)
{
	struct irq_data *data = irq_desc_get_irq_data(desc);

	if (!irqd_is_setaffinity_pending(data))
		return false;

	/*
	if (cpumask_any_and(desc->pending_mask, cpu_online_mask) >= nr_cpu_ids) {
		irqd_clr_move_pending(data);
		return false;
	}
	if (force_clear)
		irqd_clr_move_pending(data);
	return true;
}

void irq_move_masked_irq(struct irq_data *idata)
{
	struct irq_desc *desc = irq_data_to_desc(idata);
	struct irq_data *data = &desc->irq_data;
	struct irq_chip *chip = data->chip;

	if (likely(!irqd_is_setaffinity_pending(data)))
		return;

	irqd_clr_move_pending(data);

	/*
	if (irqd_is_per_cpu(data)) {
		WARN_ON(1);
		return;
	}

	if (unlikely(cpumask_empty(desc->pending_mask)))
		return;

	if (!chip->irq_set_affinity)
		return;

	assert_raw_spin_locked(&desc->lock);

	/*
	if (cpumask_any_and(desc->pending_mask, cpu_online_mask) < nr_cpu_ids) {
		int ret;

		ret = irq_do_set_affinity(data, desc->pending_mask, false);
		/*
		if (ret == -EBUSY) {
			irqd_set_move_pending(data);
			return;
		}
	}
	cpumask_clear(desc->pending_mask);
}

void __irq_move_irq(struct irq_data *idata)
{
	bool masked;

	/*
	idata = irq_desc_get_irq_data(irq_data_to_desc(idata));

	if (unlikely(irqd_irq_disabled(idata)))
		return;

	/*
	masked = irqd_irq_masked(idata);
	if (!masked)
		idata->chip->irq_mask(idata);
	irq_move_masked_irq(idata);
	if (!masked)
		idata->chip->irq_unmask(idata);
}
