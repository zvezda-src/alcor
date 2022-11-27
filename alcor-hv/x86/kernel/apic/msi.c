#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/pci.h>
#include <linux/dmar.h>
#include <linux/hpet.h>
#include <linux/msi.h>
#include <asm/irqdomain.h>
#include <asm/hpet.h>
#include <asm/hw_irq.h>
#include <asm/apic.h>
#include <asm/irq_remapping.h>
#include <asm/xen/hypervisor.h>

struct irq_domain *x86_pci_msi_default_domain __ro_after_init;

static void irq_msi_update_msg(struct irq_data *irqd, struct irq_cfg *cfg)
{
	struct msi_msg msg[2] = { [1] = { }, };

	__irq_msi_compose_msg(cfg, msg, false);
	irq_data_get_irq_chip(irqd)->irq_write_msi_msg(irqd, msg);
}

static int
msi_set_affinity(struct irq_data *irqd, const struct cpumask *mask, bool force)
{
	struct irq_cfg old_cfg, *cfg = irqd_cfg(irqd);
	struct irq_data *parent = irqd->parent_data;
	unsigned int cpu;
	int ret;

	/* Save the current configuration */
	cpu = cpumask_first(irq_data_get_effective_affinity_mask(irqd));
	old_cfg = *cfg;

	/* Allocate a new target vector */
	ret = parent->chip->irq_set_affinity(parent, mask, force);
	if (ret < 0 || ret == IRQ_SET_MASK_OK_DONE)
		return ret;

	/*
	if (!irqd_msi_nomask_quirk(irqd) ||
	    cfg->vector == old_cfg.vector ||
	    old_cfg.vector == MANAGED_IRQ_SHUTDOWN_VECTOR ||
	    !irqd_is_started(irqd) ||
	    cfg->dest_apicid == old_cfg.dest_apicid) {
		irq_msi_update_msg(irqd, cfg);
		return ret;
	}

	/*
	if (WARN_ON_ONCE(cpu != smp_processor_id())) {
		irq_msi_update_msg(irqd, cfg);
		return ret;
	}

	/*
	lock_vector_lock();

	/*
	if (IS_ERR_OR_NULL(this_cpu_read(vector_irq[cfg->vector])))
		this_cpu_write(vector_irq[cfg->vector], VECTOR_RETRIGGERED);

	/* Redirect it to the new vector on the local CPU temporarily */
	old_cfg.vector = cfg->vector;
	irq_msi_update_msg(irqd, &old_cfg);

	/* Now transition it to the target CPU */
	irq_msi_update_msg(irqd, cfg);

	/*
	unlock_vector_lock();

	/*
	if (lapic_vector_set_in_irr(cfg->vector))
		irq_data_get_irq_chip(irqd)->irq_retrigger(irqd);

	return ret;
}

static struct irq_chip pci_msi_controller = {
	.name			= "PCI-MSI",
	.irq_unmask		= pci_msi_unmask_irq,
	.irq_mask		= pci_msi_mask_irq,
	.irq_ack		= irq_chip_ack_parent,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_set_affinity	= msi_set_affinity,
	.flags			= IRQCHIP_SKIP_SET_WAKE |
				  IRQCHIP_AFFINITY_PRE_STARTUP,
};

int pci_msi_prepare(struct irq_domain *domain, struct device *dev, int nvec,
		    msi_alloc_info_t *arg)
{
	init_irq_alloc_info(arg, NULL);
	if (to_pci_dev(dev)->msix_enabled) {
		arg->type = X86_IRQ_ALLOC_TYPE_PCI_MSIX;
	} else {
		arg->type = X86_IRQ_ALLOC_TYPE_PCI_MSI;
		arg->flags |= X86_IRQ_ALLOC_CONTIGUOUS_VECTORS;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(pci_msi_prepare);

static struct msi_domain_ops pci_msi_domain_ops = {
	.msi_prepare	= pci_msi_prepare,
};

static struct msi_domain_info pci_msi_domain_info = {
	.flags		= MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
			  MSI_FLAG_PCI_MSIX,
	.ops		= &pci_msi_domain_ops,
	.chip		= &pci_msi_controller,
	.handler	= handle_edge_irq,
	.handler_name	= "edge",
};

struct irq_domain * __init native_create_pci_msi_domain(void)
{
	struct fwnode_handle *fn;
	struct irq_domain *d;

	if (disable_apic)
		return NULL;

	fn = irq_domain_alloc_named_fwnode("PCI-MSI");
	if (!fn)
		return NULL;

	d = pci_msi_create_irq_domain(fn, &pci_msi_domain_info,
				      x86_vector_domain);
	if (!d) {
		irq_domain_free_fwnode(fn);
		pr_warn("Failed to initialize PCI-MSI irqdomain.\n");
	} else {
		d->flags |= IRQ_DOMAIN_MSI_NOMASK_QUIRK;
	}
	return d;
}

void __init x86_create_pci_msi_domain(void)
{
	x86_pci_msi_default_domain = x86_init.irqs.create_pci_msi_domain();
}

#ifdef CONFIG_IRQ_REMAP
static struct irq_chip pci_msi_ir_controller = {
	.name			= "IR-PCI-MSI",
	.irq_unmask		= pci_msi_unmask_irq,
	.irq_mask		= pci_msi_mask_irq,
	.irq_ack		= irq_chip_ack_parent,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.flags			= IRQCHIP_SKIP_SET_WAKE |
				  IRQCHIP_AFFINITY_PRE_STARTUP,
};

static struct msi_domain_info pci_msi_ir_domain_info = {
	.flags		= MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
			  MSI_FLAG_MULTI_PCI_MSI | MSI_FLAG_PCI_MSIX,
	.ops		= &pci_msi_domain_ops,
	.chip		= &pci_msi_ir_controller,
	.handler	= handle_edge_irq,
	.handler_name	= "edge",
};

struct irq_domain *arch_create_remap_msi_irq_domain(struct irq_domain *parent,
						    const char *name, int id)
{
	struct fwnode_handle *fn;
	struct irq_domain *d;

	fn = irq_domain_alloc_named_id_fwnode(name, id);
	if (!fn)
		return NULL;
	d = pci_msi_create_irq_domain(fn, &pci_msi_ir_domain_info, parent);
	if (!d)
		irq_domain_free_fwnode(fn);
	return d;
}
#endif

#ifdef CONFIG_DMAR_TABLE
static void dmar_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
	__irq_msi_compose_msg(irqd_cfg(data), msg, true);
}

static void dmar_msi_write_msg(struct irq_data *data, struct msi_msg *msg)
{
	dmar_msi_write(data->irq, msg);
}

static struct irq_chip dmar_msi_controller = {
	.name			= "DMAR-MSI",
	.irq_unmask		= dmar_msi_unmask,
	.irq_mask		= dmar_msi_mask,
	.irq_ack		= irq_chip_ack_parent,
	.irq_set_affinity	= msi_domain_set_affinity,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_compose_msi_msg	= dmar_msi_compose_msg,
	.irq_write_msi_msg	= dmar_msi_write_msg,
	.flags			= IRQCHIP_SKIP_SET_WAKE |
				  IRQCHIP_AFFINITY_PRE_STARTUP,
};

static int dmar_msi_init(struct irq_domain *domain,
			 struct msi_domain_info *info, unsigned int virq,
			 irq_hw_number_t hwirq, msi_alloc_info_t *arg)
{
	irq_domain_set_info(domain, virq, arg->devid, info->chip, NULL,
			    handle_edge_irq, arg->data, "edge");

	return 0;
}

static struct msi_domain_ops dmar_msi_domain_ops = {
	.msi_init	= dmar_msi_init,
};

static struct msi_domain_info dmar_msi_domain_info = {
	.ops		= &dmar_msi_domain_ops,
	.chip		= &dmar_msi_controller,
	.flags		= MSI_FLAG_USE_DEF_DOM_OPS,
};

static struct irq_domain *dmar_get_irq_domain(void)
{
	static struct irq_domain *dmar_domain;
	static DEFINE_MUTEX(dmar_lock);
	struct fwnode_handle *fn;

	mutex_lock(&dmar_lock);
	if (dmar_domain)
		goto out;

	fn = irq_domain_alloc_named_fwnode("DMAR-MSI");
	if (fn) {
		dmar_domain = msi_create_irq_domain(fn, &dmar_msi_domain_info,
						    x86_vector_domain);
		if (!dmar_domain)
			irq_domain_free_fwnode(fn);
	}
out:
	mutex_unlock(&dmar_lock);
	return dmar_domain;
}

int dmar_alloc_hwirq(int id, int node, void *arg)
{
	struct irq_domain *domain = dmar_get_irq_domain();
	struct irq_alloc_info info;

	if (!domain)
		return -1;

	init_irq_alloc_info(&info, NULL);
	info.type = X86_IRQ_ALLOC_TYPE_DMAR;
	info.devid = id;
	info.hwirq = id;
	info.data = arg;

	return irq_domain_alloc_irqs(domain, 1, node, &info);
}

void dmar_free_hwirq(int irq)
{
	irq_domain_free_irqs(irq, 1);
}
#endif

bool arch_restore_msi_irqs(struct pci_dev *dev)
{
	return xen_initdom_restore_msi(dev);
}
