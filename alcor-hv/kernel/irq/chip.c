
#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/irqdomain.h>

#include <trace/events/irq.h>

#include "internals.h"

static irqreturn_t bad_chained_irq(int irq, void *dev_id)
{
	WARN_ONCE(1, "Chained irq %d should not call an action\n", irq);
	return IRQ_NONE;
}

struct irqaction chained_action = {
	.handler = bad_chained_irq,
};

int irq_set_chip(unsigned int irq, const struct irq_chip *chip)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

	if (!desc)
		return -EINVAL;

	desc->irq_data.chip = (struct irq_chip *)(chip ?: &no_irq_chip);
	irq_put_desc_unlock(desc, flags);
	/*
	irq_mark_irq(irq);
	return 0;
}
EXPORT_SYMBOL(irq_set_chip);

int irq_set_irq_type(unsigned int irq, unsigned int type)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, IRQ_GET_DESC_CHECK_GLOBAL);
	int ret = 0;

	if (!desc)
		return -EINVAL;

	ret = __irq_set_trigger(desc, type);
	irq_put_desc_busunlock(desc, flags);
	return ret;
}
EXPORT_SYMBOL(irq_set_irq_type);

int irq_set_handler_data(unsigned int irq, void *data)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

	if (!desc)
		return -EINVAL;
	desc->irq_common_data.handler_data = data;
	irq_put_desc_unlock(desc, flags);
	return 0;
}
EXPORT_SYMBOL(irq_set_handler_data);

int irq_set_msi_desc_off(unsigned int irq_base, unsigned int irq_offset,
			 struct msi_desc *entry)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_lock(irq_base + irq_offset, &flags, IRQ_GET_DESC_CHECK_GLOBAL);

	if (!desc)
		return -EINVAL;
	desc->irq_common_data.msi_desc = entry;
	if (entry && !irq_offset)
		entry->irq = irq_base;
	irq_put_desc_unlock(desc, flags);
	return 0;
}

int irq_set_msi_desc(unsigned int irq, struct msi_desc *entry)
{
	return irq_set_msi_desc_off(irq, 0, entry);
}

int irq_set_chip_data(unsigned int irq, void *data)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

	if (!desc)
		return -EINVAL;
	desc->irq_data.chip_data = data;
	irq_put_desc_unlock(desc, flags);
	return 0;
}
EXPORT_SYMBOL(irq_set_chip_data);

struct irq_data *irq_get_irq_data(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	return desc ? &desc->irq_data : NULL;
}
EXPORT_SYMBOL_GPL(irq_get_irq_data);

static void irq_state_clr_disabled(struct irq_desc *desc)
{
	irqd_clear(&desc->irq_data, IRQD_IRQ_DISABLED);
}

static void irq_state_clr_masked(struct irq_desc *desc)
{
	irqd_clear(&desc->irq_data, IRQD_IRQ_MASKED);
}

static void irq_state_clr_started(struct irq_desc *desc)
{
	irqd_clear(&desc->irq_data, IRQD_IRQ_STARTED);
}

static void irq_state_set_started(struct irq_desc *desc)
{
	irqd_set(&desc->irq_data, IRQD_IRQ_STARTED);
}

enum {
	IRQ_STARTUP_NORMAL,
	IRQ_STARTUP_MANAGED,
	IRQ_STARTUP_ABORT,
};

#ifdef CONFIG_SMP
static int
__irq_startup_managed(struct irq_desc *desc, const struct cpumask *aff,
		      bool force)
{
	struct irq_data *d = irq_desc_get_irq_data(desc);

	if (!irqd_affinity_is_managed(d))
		return IRQ_STARTUP_NORMAL;

	irqd_clr_managed_shutdown(d);

	if (cpumask_any_and(aff, cpu_online_mask) >= nr_cpu_ids) {
		/*
		if (WARN_ON_ONCE(force))
			return IRQ_STARTUP_ABORT;
		/*
		return IRQ_STARTUP_ABORT;
	}
	/*
	if (WARN_ON(irq_domain_activate_irq(d, false)))
		return IRQ_STARTUP_ABORT;
	return IRQ_STARTUP_MANAGED;
}
#else
static __always_inline int
__irq_startup_managed(struct irq_desc *desc, const struct cpumask *aff,
		      bool force)
{
	return IRQ_STARTUP_NORMAL;
}
#endif

static int __irq_startup(struct irq_desc *desc)
{
	struct irq_data *d = irq_desc_get_irq_data(desc);
	int ret = 0;

	/* Warn if this interrupt is not activated but try nevertheless */
	WARN_ON_ONCE(!irqd_is_activated(d));

	if (d->chip->irq_startup) {
		ret = d->chip->irq_startup(d);
		irq_state_clr_disabled(desc);
		irq_state_clr_masked(desc);
	} else {
		irq_enable(desc);
	}
	irq_state_set_started(desc);
	return ret;
}

int irq_startup(struct irq_desc *desc, bool resend, bool force)
{
	struct irq_data *d = irq_desc_get_irq_data(desc);
	const struct cpumask *aff = irq_data_get_affinity_mask(d);
	int ret = 0;

	desc->depth = 0;

	if (irqd_is_started(d)) {
		irq_enable(desc);
	} else {
		switch (__irq_startup_managed(desc, aff, force)) {
		case IRQ_STARTUP_NORMAL:
			if (d->chip->flags & IRQCHIP_AFFINITY_PRE_STARTUP)
				irq_setup_affinity(desc);
			ret = __irq_startup(desc);
			if (!(d->chip->flags & IRQCHIP_AFFINITY_PRE_STARTUP))
				irq_setup_affinity(desc);
			break;
		case IRQ_STARTUP_MANAGED:
			irq_do_set_affinity(d, aff, false);
			ret = __irq_startup(desc);
			break;
		case IRQ_STARTUP_ABORT:
			irqd_set_managed_shutdown(d);
			return 0;
		}
	}
	if (resend)
		check_irq_resend(desc, false);

	return ret;
}

int irq_activate(struct irq_desc *desc)
{
	struct irq_data *d = irq_desc_get_irq_data(desc);

	if (!irqd_affinity_is_managed(d))
		return irq_domain_activate_irq(d, false);
	return 0;
}

int irq_activate_and_startup(struct irq_desc *desc, bool resend)
{
	if (WARN_ON(irq_activate(desc)))
		return 0;
	return irq_startup(desc, resend, IRQ_START_FORCE);
}

static void __irq_disable(struct irq_desc *desc, bool mask);

void irq_shutdown(struct irq_desc *desc)
{
	if (irqd_is_started(&desc->irq_data)) {
		desc->depth = 1;
		if (desc->irq_data.chip->irq_shutdown) {
			desc->irq_data.chip->irq_shutdown(&desc->irq_data);
			irq_state_set_disabled(desc);
			irq_state_set_masked(desc);
		} else {
			__irq_disable(desc, true);
		}
		irq_state_clr_started(desc);
	}
}


void irq_shutdown_and_deactivate(struct irq_desc *desc)
{
	irq_shutdown(desc);
	/*
	irq_domain_deactivate_irq(&desc->irq_data);
}

void irq_enable(struct irq_desc *desc)
{
	if (!irqd_irq_disabled(&desc->irq_data)) {
		unmask_irq(desc);
	} else {
		irq_state_clr_disabled(desc);
		if (desc->irq_data.chip->irq_enable) {
			desc->irq_data.chip->irq_enable(&desc->irq_data);
			irq_state_clr_masked(desc);
		} else {
			unmask_irq(desc);
		}
	}
}

static void __irq_disable(struct irq_desc *desc, bool mask)
{
	if (irqd_irq_disabled(&desc->irq_data)) {
		if (mask)
			mask_irq(desc);
	} else {
		irq_state_set_disabled(desc);
		if (desc->irq_data.chip->irq_disable) {
			desc->irq_data.chip->irq_disable(&desc->irq_data);
			irq_state_set_masked(desc);
		} else if (mask) {
			mask_irq(desc);
		}
	}
}

void irq_disable(struct irq_desc *desc)
{
	__irq_disable(desc, irq_settings_disable_unlazy(desc));
}

void irq_percpu_enable(struct irq_desc *desc, unsigned int cpu)
{
	if (desc->irq_data.chip->irq_enable)
		desc->irq_data.chip->irq_enable(&desc->irq_data);
	else
		desc->irq_data.chip->irq_unmask(&desc->irq_data);
	cpumask_set_cpu(cpu, desc->percpu_enabled);
}

void irq_percpu_disable(struct irq_desc *desc, unsigned int cpu)
{
	if (desc->irq_data.chip->irq_disable)
		desc->irq_data.chip->irq_disable(&desc->irq_data);
	else
		desc->irq_data.chip->irq_mask(&desc->irq_data);
	cpumask_clear_cpu(cpu, desc->percpu_enabled);
}

static inline void mask_ack_irq(struct irq_desc *desc)
{
	if (desc->irq_data.chip->irq_mask_ack) {
		desc->irq_data.chip->irq_mask_ack(&desc->irq_data);
		irq_state_set_masked(desc);
	} else {
		mask_irq(desc);
		if (desc->irq_data.chip->irq_ack)
			desc->irq_data.chip->irq_ack(&desc->irq_data);
	}
}

void mask_irq(struct irq_desc *desc)
{
	if (irqd_irq_masked(&desc->irq_data))
		return;

	if (desc->irq_data.chip->irq_mask) {
		desc->irq_data.chip->irq_mask(&desc->irq_data);
		irq_state_set_masked(desc);
	}
}

void unmask_irq(struct irq_desc *desc)
{
	if (!irqd_irq_masked(&desc->irq_data))
		return;

	if (desc->irq_data.chip->irq_unmask) {
		desc->irq_data.chip->irq_unmask(&desc->irq_data);
		irq_state_clr_masked(desc);
	}
}

void unmask_threaded_irq(struct irq_desc *desc)
{
	struct irq_chip *chip = desc->irq_data.chip;

	if (chip->flags & IRQCHIP_EOI_THREADED)
		chip->irq_eoi(&desc->irq_data);

	unmask_irq(desc);
}

void handle_nested_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	struct irqaction *action;
	irqreturn_t action_ret;

	might_sleep();

	raw_spin_lock_irq(&desc->lock);

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

	action = desc->action;
	if (unlikely(!action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		goto out_unlock;
	}

	kstat_incr_irqs_this_cpu(desc);
	irqd_set(&desc->irq_data, IRQD_IRQ_INPROGRESS);
	raw_spin_unlock_irq(&desc->lock);

	action_ret = IRQ_NONE;
	for_each_action_of_desc(desc, action)
		action_ret |= action->thread_fn(action->irq, action->dev_id);

	if (!irq_settings_no_debug(desc))
		note_interrupt(desc, action_ret);

	raw_spin_lock_irq(&desc->lock);
	irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);

out_unlock:
	raw_spin_unlock_irq(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_nested_irq);

static bool irq_check_poll(struct irq_desc *desc)
{
	if (!(desc->istate & IRQS_POLL_INPROGRESS))
		return false;
	return irq_wait_for_poll(desc);
}

static bool irq_may_run(struct irq_desc *desc)
{
	unsigned int mask = IRQD_IRQ_INPROGRESS | IRQD_WAKEUP_ARMED;

	/*
	if (!irqd_has_set(&desc->irq_data, mask))
		return true;

	/*
	if (irq_pm_check_wakeup(desc))
		return false;

	/*
	return irq_check_poll(desc);
}

void handle_simple_irq(struct irq_desc *desc)
{
	raw_spin_lock(&desc->lock);

	if (!irq_may_run(desc))
		goto out_unlock;

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

	if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		goto out_unlock;
	}

	kstat_incr_irqs_this_cpu(desc);
	handle_irq_event(desc);

out_unlock:
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_simple_irq);

void handle_untracked_irq(struct irq_desc *desc)
{
	raw_spin_lock(&desc->lock);

	if (!irq_may_run(desc))
		goto out_unlock;

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

	if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		goto out_unlock;
	}

	desc->istate &= ~IRQS_PENDING;
	irqd_set(&desc->irq_data, IRQD_IRQ_INPROGRESS);
	raw_spin_unlock(&desc->lock);

	__handle_irq_event_percpu(desc);

	raw_spin_lock(&desc->lock);
	irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);

out_unlock:
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_untracked_irq);

static void cond_unmask_irq(struct irq_desc *desc)
{
	/*
	if (!irqd_irq_disabled(&desc->irq_data) &&
	    irqd_irq_masked(&desc->irq_data) && !desc->threads_oneshot)
		unmask_irq(desc);
}

void handle_level_irq(struct irq_desc *desc)
{
	raw_spin_lock(&desc->lock);
	mask_ack_irq(desc);

	if (!irq_may_run(desc))
		goto out_unlock;

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

	/*
	if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		goto out_unlock;
	}

	kstat_incr_irqs_this_cpu(desc);
	handle_irq_event(desc);

	cond_unmask_irq(desc);

out_unlock:
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_level_irq);

static void cond_unmask_eoi_irq(struct irq_desc *desc, struct irq_chip *chip)
{
	if (!(desc->istate & IRQS_ONESHOT)) {
		chip->irq_eoi(&desc->irq_data);
		return;
	}
	/*
	if (!irqd_irq_disabled(&desc->irq_data) &&
	    irqd_irq_masked(&desc->irq_data) && !desc->threads_oneshot) {
		chip->irq_eoi(&desc->irq_data);
		unmask_irq(desc);
	} else if (!(chip->flags & IRQCHIP_EOI_THREADED)) {
		chip->irq_eoi(&desc->irq_data);
	}
}

void handle_fasteoi_irq(struct irq_desc *desc)
{
	struct irq_chip *chip = desc->irq_data.chip;

	raw_spin_lock(&desc->lock);

	if (!irq_may_run(desc))
		goto out;

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

	/*
	if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		mask_irq(desc);
		goto out;
	}

	kstat_incr_irqs_this_cpu(desc);
	if (desc->istate & IRQS_ONESHOT)
		mask_irq(desc);

	handle_irq_event(desc);

	cond_unmask_eoi_irq(desc, chip);

	raw_spin_unlock(&desc->lock);
	return;
out:
	if (!(chip->flags & IRQCHIP_EOI_IF_HANDLED))
		chip->irq_eoi(&desc->irq_data);
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_fasteoi_irq);

void handle_fasteoi_nmi(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct irqaction *action = desc->action;
	unsigned int irq = irq_desc_get_irq(desc);
	irqreturn_t res;

	__kstat_incr_irqs_this_cpu(desc);

	trace_irq_handler_entry(irq, action);
	/*
	res = action->handler(irq, action->dev_id);
	trace_irq_handler_exit(irq, action, res);

	if (chip->irq_eoi)
		chip->irq_eoi(&desc->irq_data);
}
EXPORT_SYMBOL_GPL(handle_fasteoi_nmi);

void handle_edge_irq(struct irq_desc *desc)
{
	raw_spin_lock(&desc->lock);

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

	if (!irq_may_run(desc)) {
		desc->istate |= IRQS_PENDING;
		mask_ack_irq(desc);
		goto out_unlock;
	}

	/*
	if (irqd_irq_disabled(&desc->irq_data) || !desc->action) {
		desc->istate |= IRQS_PENDING;
		mask_ack_irq(desc);
		goto out_unlock;
	}

	kstat_incr_irqs_this_cpu(desc);

	/* Start handling the irq */
	desc->irq_data.chip->irq_ack(&desc->irq_data);

	do {
		if (unlikely(!desc->action)) {
			mask_irq(desc);
			goto out_unlock;
		}

		/*
		if (unlikely(desc->istate & IRQS_PENDING)) {
			if (!irqd_irq_disabled(&desc->irq_data) &&
			    irqd_irq_masked(&desc->irq_data))
				unmask_irq(desc);
		}

		handle_irq_event(desc);

	} while ((desc->istate & IRQS_PENDING) &&
		 !irqd_irq_disabled(&desc->irq_data));

out_unlock:
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL(handle_edge_irq);

#ifdef CONFIG_IRQ_EDGE_EOI_HANDLER
void handle_edge_eoi_irq(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);

	raw_spin_lock(&desc->lock);

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

	if (!irq_may_run(desc)) {
		desc->istate |= IRQS_PENDING;
		goto out_eoi;
	}

	/*
	if (irqd_irq_disabled(&desc->irq_data) || !desc->action) {
		desc->istate |= IRQS_PENDING;
		goto out_eoi;
	}

	kstat_incr_irqs_this_cpu(desc);

	do {
		if (unlikely(!desc->action))
			goto out_eoi;

		handle_irq_event(desc);

	} while ((desc->istate & IRQS_PENDING) &&
		 !irqd_irq_disabled(&desc->irq_data));

out_eoi:
	chip->irq_eoi(&desc->irq_data);
	raw_spin_unlock(&desc->lock);
}
#endif

void handle_percpu_irq(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);

	/*
	__kstat_incr_irqs_this_cpu(desc);

	if (chip->irq_ack)
		chip->irq_ack(&desc->irq_data);

	handle_irq_event_percpu(desc);

	if (chip->irq_eoi)
		chip->irq_eoi(&desc->irq_data);
}

void handle_percpu_devid_irq(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct irqaction *action = desc->action;
	unsigned int irq = irq_desc_get_irq(desc);
	irqreturn_t res;

	/*
	__kstat_incr_irqs_this_cpu(desc);

	if (chip->irq_ack)
		chip->irq_ack(&desc->irq_data);

	if (likely(action)) {
		trace_irq_handler_entry(irq, action);
		res = action->handler(irq, raw_cpu_ptr(action->percpu_dev_id));
		trace_irq_handler_exit(irq, action, res);
	} else {
		unsigned int cpu = smp_processor_id();
		bool enabled = cpumask_test_cpu(cpu, desc->percpu_enabled);

		if (enabled)
			irq_percpu_disable(desc, cpu);

		pr_err_once("Spurious%s percpu IRQ%u on CPU%u\n",
			    enabled ? " and unmasked" : "", irq, cpu);
	}

	if (chip->irq_eoi)
		chip->irq_eoi(&desc->irq_data);
}

void handle_percpu_devid_fasteoi_nmi(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct irqaction *action = desc->action;
	unsigned int irq = irq_desc_get_irq(desc);
	irqreturn_t res;

	__kstat_incr_irqs_this_cpu(desc);

	trace_irq_handler_entry(irq, action);
	res = action->handler(irq, raw_cpu_ptr(action->percpu_dev_id));
	trace_irq_handler_exit(irq, action, res);

	if (chip->irq_eoi)
		chip->irq_eoi(&desc->irq_data);
}

static void
__irq_do_set_handler(struct irq_desc *desc, irq_flow_handler_t handle,
		     int is_chained, const char *name)
{
	if (!handle) {
		handle = handle_bad_irq;
	} else {
		struct irq_data *irq_data = &desc->irq_data;
#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
		/*
		while (irq_data) {
			if (irq_data->chip != &no_irq_chip)
				break;
			/*
			if (WARN_ON(is_chained))
				return;
			/* Try the parent */
			irq_data = irq_data->parent_data;
		}
#endif
		if (WARN_ON(!irq_data || irq_data->chip == &no_irq_chip))
			return;
	}

	/* Uninstall? */
	if (handle == handle_bad_irq) {
		if (desc->irq_data.chip != &no_irq_chip)
			mask_ack_irq(desc);
		irq_state_set_disabled(desc);
		if (is_chained) {
			desc->action = NULL;
			WARN_ON(irq_chip_pm_put(irq_desc_get_irq_data(desc)));
		}
		desc->depth = 1;
	}
	desc->handle_irq = handle;
	desc->name = name;

	if (handle != handle_bad_irq && is_chained) {
		unsigned int type = irqd_get_trigger_type(&desc->irq_data);

		/*
		if (type != IRQ_TYPE_NONE) {
			__irq_set_trigger(desc, type);
			desc->handle_irq = handle;
		}

		irq_settings_set_noprobe(desc);
		irq_settings_set_norequest(desc);
		irq_settings_set_nothread(desc);
		desc->action = &chained_action;
		WARN_ON(irq_chip_pm_get(irq_desc_get_irq_data(desc)));
		irq_activate_and_startup(desc, IRQ_RESEND);
	}
}

void
__irq_set_handler(unsigned int irq, irq_flow_handler_t handle, int is_chained,
		  const char *name)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, 0);

	if (!desc)
		return;

	__irq_do_set_handler(desc, handle, is_chained, name);
	irq_put_desc_busunlock(desc, flags);
}
EXPORT_SYMBOL_GPL(__irq_set_handler);

void
irq_set_chained_handler_and_data(unsigned int irq, irq_flow_handler_t handle,
				 void *data)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, 0);

	if (!desc)
		return;

	desc->irq_common_data.handler_data = data;
	__irq_do_set_handler(desc, handle, 1, NULL);

	irq_put_desc_busunlock(desc, flags);
}
EXPORT_SYMBOL_GPL(irq_set_chained_handler_and_data);

void
irq_set_chip_and_handler_name(unsigned int irq, const struct irq_chip *chip,
			      irq_flow_handler_t handle, const char *name)
{
	irq_set_chip(irq, chip);
	__irq_set_handler(irq, handle, 0, name);
}
EXPORT_SYMBOL_GPL(irq_set_chip_and_handler_name);

void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set)
{
	unsigned long flags, trigger, tmp;
	struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

	if (!desc)
		return;

	/*
	WARN_ON_ONCE(!desc->depth && (set & _IRQ_NOAUTOEN));

	irq_settings_clr_and_set(desc, clr, set);

	trigger = irqd_get_trigger_type(&desc->irq_data);

	irqd_clear(&desc->irq_data, IRQD_NO_BALANCING | IRQD_PER_CPU |
		   IRQD_TRIGGER_MASK | IRQD_LEVEL | IRQD_MOVE_PCNTXT);
	if (irq_settings_has_no_balance_set(desc))
		irqd_set(&desc->irq_data, IRQD_NO_BALANCING);
	if (irq_settings_is_per_cpu(desc))
		irqd_set(&desc->irq_data, IRQD_PER_CPU);
	if (irq_settings_can_move_pcntxt(desc))
		irqd_set(&desc->irq_data, IRQD_MOVE_PCNTXT);
	if (irq_settings_is_level(desc))
		irqd_set(&desc->irq_data, IRQD_LEVEL);

	tmp = irq_settings_get_trigger_mask(desc);
	if (tmp != IRQ_TYPE_NONE)
		trigger = tmp;

	irqd_set(&desc->irq_data, trigger);

	irq_put_desc_unlock(desc, flags);
}
EXPORT_SYMBOL_GPL(irq_modify_status);

#ifdef CONFIG_DEPRECATED_IRQ_CPU_ONOFFLINE
void irq_cpu_online(void)
{
	struct irq_desc *desc;
	struct irq_chip *chip;
	unsigned long flags;
	unsigned int irq;

	for_each_active_irq(irq) {
		desc = irq_to_desc(irq);
		if (!desc)
			continue;

		raw_spin_lock_irqsave(&desc->lock, flags);

		chip = irq_data_get_irq_chip(&desc->irq_data);
		if (chip && chip->irq_cpu_online &&
		    (!(chip->flags & IRQCHIP_ONOFFLINE_ENABLED) ||
		     !irqd_irq_disabled(&desc->irq_data)))
			chip->irq_cpu_online(&desc->irq_data);

		raw_spin_unlock_irqrestore(&desc->lock, flags);
	}
}

void irq_cpu_offline(void)
{
	struct irq_desc *desc;
	struct irq_chip *chip;
	unsigned long flags;
	unsigned int irq;

	for_each_active_irq(irq) {
		desc = irq_to_desc(irq);
		if (!desc)
			continue;

		raw_spin_lock_irqsave(&desc->lock, flags);

		chip = irq_data_get_irq_chip(&desc->irq_data);
		if (chip && chip->irq_cpu_offline &&
		    (!(chip->flags & IRQCHIP_ONOFFLINE_ENABLED) ||
		     !irqd_irq_disabled(&desc->irq_data)))
			chip->irq_cpu_offline(&desc->irq_data);

		raw_spin_unlock_irqrestore(&desc->lock, flags);
	}
}
#endif

#ifdef	CONFIG_IRQ_DOMAIN_HIERARCHY

#ifdef CONFIG_IRQ_FASTEOI_HIERARCHY_HANDLERS
void handle_fasteoi_ack_irq(struct irq_desc *desc)
{
	struct irq_chip *chip = desc->irq_data.chip;

	raw_spin_lock(&desc->lock);

	if (!irq_may_run(desc))
		goto out;

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

	/*
	if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		mask_irq(desc);
		goto out;
	}

	kstat_incr_irqs_this_cpu(desc);
	if (desc->istate & IRQS_ONESHOT)
		mask_irq(desc);

	/* Start handling the irq */
	desc->irq_data.chip->irq_ack(&desc->irq_data);

	handle_irq_event(desc);

	cond_unmask_eoi_irq(desc, chip);

	raw_spin_unlock(&desc->lock);
	return;
out:
	if (!(chip->flags & IRQCHIP_EOI_IF_HANDLED))
		chip->irq_eoi(&desc->irq_data);
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_fasteoi_ack_irq);

void handle_fasteoi_mask_irq(struct irq_desc *desc)
{
	struct irq_chip *chip = desc->irq_data.chip;

	raw_spin_lock(&desc->lock);
	mask_ack_irq(desc);

	if (!irq_may_run(desc))
		goto out;

	desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

	/*
	if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
		desc->istate |= IRQS_PENDING;
		mask_irq(desc);
		goto out;
	}

	kstat_incr_irqs_this_cpu(desc);
	if (desc->istate & IRQS_ONESHOT)
		mask_irq(desc);

	handle_irq_event(desc);

	cond_unmask_eoi_irq(desc, chip);

	raw_spin_unlock(&desc->lock);
	return;
out:
	if (!(chip->flags & IRQCHIP_EOI_IF_HANDLED))
		chip->irq_eoi(&desc->irq_data);
	raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_fasteoi_mask_irq);

#endif /* CONFIG_IRQ_FASTEOI_HIERARCHY_HANDLERS */

int irq_chip_set_parent_state(struct irq_data *data,
			      enum irqchip_irq_state which,
			      bool val)
{
	data = data->parent_data;

	if (!data || !data->chip->irq_set_irqchip_state)
		return 0;

	return data->chip->irq_set_irqchip_state(data, which, val);
}
EXPORT_SYMBOL_GPL(irq_chip_set_parent_state);

int irq_chip_get_parent_state(struct irq_data *data,
			      enum irqchip_irq_state which,
			      bool *state)
{
	data = data->parent_data;

	if (!data || !data->chip->irq_get_irqchip_state)
		return 0;

	return data->chip->irq_get_irqchip_state(data, which, state);
}
EXPORT_SYMBOL_GPL(irq_chip_get_parent_state);

void irq_chip_enable_parent(struct irq_data *data)
{
	data = data->parent_data;
	if (data->chip->irq_enable)
		data->chip->irq_enable(data);
	else
		data->chip->irq_unmask(data);
}
EXPORT_SYMBOL_GPL(irq_chip_enable_parent);

void irq_chip_disable_parent(struct irq_data *data)
{
	data = data->parent_data;
	if (data->chip->irq_disable)
		data->chip->irq_disable(data);
	else
		data->chip->irq_mask(data);
}
EXPORT_SYMBOL_GPL(irq_chip_disable_parent);

void irq_chip_ack_parent(struct irq_data *data)
{
	data = data->parent_data;
	data->chip->irq_ack(data);
}
EXPORT_SYMBOL_GPL(irq_chip_ack_parent);

void irq_chip_mask_parent(struct irq_data *data)
{
	data = data->parent_data;
	data->chip->irq_mask(data);
}
EXPORT_SYMBOL_GPL(irq_chip_mask_parent);

void irq_chip_mask_ack_parent(struct irq_data *data)
{
	data = data->parent_data;
	data->chip->irq_mask_ack(data);
}
EXPORT_SYMBOL_GPL(irq_chip_mask_ack_parent);

void irq_chip_unmask_parent(struct irq_data *data)
{
	data = data->parent_data;
	data->chip->irq_unmask(data);
}
EXPORT_SYMBOL_GPL(irq_chip_unmask_parent);

void irq_chip_eoi_parent(struct irq_data *data)
{
	data = data->parent_data;
	data->chip->irq_eoi(data);
}
EXPORT_SYMBOL_GPL(irq_chip_eoi_parent);

int irq_chip_set_affinity_parent(struct irq_data *data,
				 const struct cpumask *dest, bool force)
{
	data = data->parent_data;
	if (data->chip->irq_set_affinity)
		return data->chip->irq_set_affinity(data, dest, force);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(irq_chip_set_affinity_parent);

int irq_chip_set_type_parent(struct irq_data *data, unsigned int type)
{
	data = data->parent_data;

	if (data->chip->irq_set_type)
		return data->chip->irq_set_type(data, type);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(irq_chip_set_type_parent);

int irq_chip_retrigger_hierarchy(struct irq_data *data)
{
	for (data = data->parent_data; data; data = data->parent_data)
		if (data->chip && data->chip->irq_retrigger)
			return data->chip->irq_retrigger(data);

	return 0;
}
EXPORT_SYMBOL_GPL(irq_chip_retrigger_hierarchy);

int irq_chip_set_vcpu_affinity_parent(struct irq_data *data, void *vcpu_info)
{
	data = data->parent_data;
	if (data->chip->irq_set_vcpu_affinity)
		return data->chip->irq_set_vcpu_affinity(data, vcpu_info);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(irq_chip_set_vcpu_affinity_parent);
int irq_chip_set_wake_parent(struct irq_data *data, unsigned int on)
{
	data = data->parent_data;

	if (data->chip->flags & IRQCHIP_SKIP_SET_WAKE)
		return 0;

	if (data->chip->irq_set_wake)
		return data->chip->irq_set_wake(data, on);

	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(irq_chip_set_wake_parent);

int irq_chip_request_resources_parent(struct irq_data *data)
{
	data = data->parent_data;

	if (data->chip->irq_request_resources)
		return data->chip->irq_request_resources(data);

	/* no error on missing optional irq_chip::irq_request_resources */
	return 0;
}
EXPORT_SYMBOL_GPL(irq_chip_request_resources_parent);

void irq_chip_release_resources_parent(struct irq_data *data)
{
	data = data->parent_data;
	if (data->chip->irq_release_resources)
		data->chip->irq_release_resources(data);
}
EXPORT_SYMBOL_GPL(irq_chip_release_resources_parent);
#endif

int irq_chip_compose_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct irq_data *pos;

	for (pos = NULL; !pos && data; data = irqd_get_parent_data(data)) {
		if (data->chip && data->chip->irq_compose_msi_msg)
			pos = data;
	}

	if (!pos)
		return -ENOSYS;

	pos->chip->irq_compose_msi_msg(pos, msg);
	return 0;
}

static struct device *irq_get_parent_device(struct irq_data *data)
{
	if (data->domain)
		return data->domain->dev;

	return NULL;
}

int irq_chip_pm_get(struct irq_data *data)
{
	struct device *dev = irq_get_parent_device(data);
	int retval = 0;

	if (IS_ENABLED(CONFIG_PM) && dev)
		retval = pm_runtime_resume_and_get(dev);

	return retval;
}

int irq_chip_pm_put(struct irq_data *data)
{
	struct device *dev = irq_get_parent_device(data);
	int retval = 0;

	if (IS_ENABLED(CONFIG_PM) && dev)
		retval = pm_runtime_put(dev);

	return (retval < 0) ? retval : 0;
}
