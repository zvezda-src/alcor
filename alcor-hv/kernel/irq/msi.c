#include <linux/types.h>
#include <linux/device.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/pci.h>

#include "internals.h"

static inline int msi_sysfs_create_group(struct device *dev);

static struct msi_desc *msi_alloc_desc(struct device *dev, int nvec,
					const struct irq_affinity_desc *affinity)
{
	struct msi_desc *desc = kzalloc(sizeof(*desc), GFP_KERNEL);

	if (!desc)
		return NULL;

	desc->dev = dev;
	desc->nvec_used = nvec;
	if (affinity) {
		desc->affinity = kmemdup(affinity, nvec * sizeof(*desc->affinity), GFP_KERNEL);
		if (!desc->affinity) {
			kfree(desc);
			return NULL;
		}
	}
	return desc;
}

static void msi_free_desc(struct msi_desc *desc)
{
	kfree(desc->affinity);
	kfree(desc);
}

static int msi_insert_desc(struct msi_device_data *md, struct msi_desc *desc, unsigned int index)
{
	int ret;

	desc->msi_index = index;
	ret = xa_insert(&md->__store, index, desc, GFP_KERNEL);
	if (ret)
		msi_free_desc(desc);
	return ret;
}

int msi_add_msi_desc(struct device *dev, struct msi_desc *init_desc)
{
	struct msi_desc *desc;

	lockdep_assert_held(&dev->msi.data->mutex);

	desc = msi_alloc_desc(dev, init_desc->nvec_used, init_desc->affinity);
	if (!desc)
		return -ENOMEM;

	/* Copy type specific data to the new descriptor. */
	desc->pci = init_desc->pci;
	return msi_insert_desc(dev->msi.data, desc, init_desc->msi_index);
}

static int msi_add_simple_msi_descs(struct device *dev, unsigned int index, unsigned int ndesc)
{
	unsigned int idx, last = index + ndesc - 1;
	struct msi_desc *desc;
	int ret;

	lockdep_assert_held(&dev->msi.data->mutex);

	for (idx = index; idx <= last; idx++) {
		desc = msi_alloc_desc(dev, 1, NULL);
		if (!desc)
			goto fail_mem;
		ret = msi_insert_desc(dev->msi.data, desc, idx);
		if (ret)
			goto fail;
	}
	return 0;

fail_mem:
	ret = -ENOMEM;
fail:
	msi_free_msi_descs_range(dev, MSI_DESC_NOTASSOCIATED, index, last);
	return ret;
}

static bool msi_desc_match(struct msi_desc *desc, enum msi_desc_filter filter)
{
	switch (filter) {
	case MSI_DESC_ALL:
		return true;
	case MSI_DESC_NOTASSOCIATED:
		return !desc->irq;
	case MSI_DESC_ASSOCIATED:
		return !!desc->irq;
	}
	WARN_ON_ONCE(1);
	return false;
}

void msi_free_msi_descs_range(struct device *dev, enum msi_desc_filter filter,
			      unsigned int first_index, unsigned int last_index)
{
	struct xarray *xa = &dev->msi.data->__store;
	struct msi_desc *desc;
	unsigned long idx;

	lockdep_assert_held(&dev->msi.data->mutex);

	xa_for_each_range(xa, idx, desc, first_index, last_index) {
		if (msi_desc_match(desc, filter)) {
			xa_erase(xa, idx);
			msi_free_desc(desc);
		}
	}
}

void __get_cached_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
}

void get_cached_msi_msg(unsigned int irq, struct msi_msg *msg)
{
	struct msi_desc *entry = irq_get_msi_desc(irq);

	__get_cached_msi_msg(entry, msg);
}
EXPORT_SYMBOL_GPL(get_cached_msi_msg);

static void msi_device_data_release(struct device *dev, void *res)
{
	struct msi_device_data *md = res;

	WARN_ON_ONCE(!xa_empty(&md->__store));
	xa_destroy(&md->__store);
	dev->msi.data = NULL;
}

int msi_setup_device_data(struct device *dev)
{
	struct msi_device_data *md;
	int ret;

	if (dev->msi.data)
		return 0;

	md = devres_alloc(msi_device_data_release, sizeof(*md), GFP_KERNEL);
	if (!md)
		return -ENOMEM;

	ret = msi_sysfs_create_group(dev);
	if (ret) {
		devres_free(md);
		return ret;
	}

	xa_init(&md->__store);
	mutex_init(&md->mutex);
	dev->msi.data = md;
	devres_add(dev, md);
	return 0;
}

void msi_lock_descs(struct device *dev)
{
	mutex_lock(&dev->msi.data->mutex);
}
EXPORT_SYMBOL_GPL(msi_lock_descs);

void msi_unlock_descs(struct device *dev)
{
	/* Invalidate the index wich was cached by the iterator */
	dev->msi.data->__iter_idx = MSI_MAX_INDEX;
	mutex_unlock(&dev->msi.data->mutex);
}
EXPORT_SYMBOL_GPL(msi_unlock_descs);

static struct msi_desc *msi_find_desc(struct msi_device_data *md, enum msi_desc_filter filter)
{
	struct msi_desc *desc;

	xa_for_each_start(&md->__store, md->__iter_idx, desc, md->__iter_idx) {
		if (msi_desc_match(desc, filter))
			return desc;
	}
	md->__iter_idx = MSI_MAX_INDEX;
	return NULL;
}

struct msi_desc *msi_first_desc(struct device *dev, enum msi_desc_filter filter)
{
	struct msi_device_data *md = dev->msi.data;

	if (WARN_ON_ONCE(!md))
		return NULL;

	lockdep_assert_held(&md->mutex);

	md->__iter_idx = 0;
	return msi_find_desc(md, filter);
}
EXPORT_SYMBOL_GPL(msi_first_desc);

struct msi_desc *msi_next_desc(struct device *dev, enum msi_desc_filter filter)
{
	struct msi_device_data *md = dev->msi.data;

	if (WARN_ON_ONCE(!md))
		return NULL;

	lockdep_assert_held(&md->mutex);

	if (md->__iter_idx >= (unsigned long)MSI_MAX_INDEX)
		return NULL;

	md->__iter_idx++;
	return msi_find_desc(md, filter);
}
EXPORT_SYMBOL_GPL(msi_next_desc);

unsigned int msi_get_virq(struct device *dev, unsigned int index)
{
	struct msi_desc *desc;
	unsigned int ret = 0;
	bool pcimsi;

	if (!dev->msi.data)
		return 0;

	pcimsi = dev_is_pci(dev) ? to_pci_dev(dev)->msi_enabled : false;

	msi_lock_descs(dev);
	desc = xa_load(&dev->msi.data->__store, pcimsi ? 0 : index);
	if (desc && desc->irq) {
		/*
		if (pcimsi) {
			if (index < desc->nvec_used)
				ret = desc->irq + index;
		} else {
			ret = desc->irq;
		}
	}
	msi_unlock_descs(dev);
	return ret;
}
EXPORT_SYMBOL_GPL(msi_get_virq);

#ifdef CONFIG_SYSFS
static struct attribute *msi_dev_attrs[] = {
	NULL
};

static const struct attribute_group msi_irqs_group = {
	.name	= "msi_irqs",
	.attrs	= msi_dev_attrs,
};

static inline int msi_sysfs_create_group(struct device *dev)
{
	return devm_device_add_group(dev, &msi_irqs_group);
}

static ssize_t msi_mode_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	/* MSI vs. MSIX is per device not per interrupt */
	bool is_msix = dev_is_pci(dev) ? to_pci_dev(dev)->msix_enabled : false;

	return sysfs_emit(buf, "%s\n", is_msix ? "msix" : "msi");
}

static void msi_sysfs_remove_desc(struct device *dev, struct msi_desc *desc)
{
	struct device_attribute *attrs = desc->sysfs_attrs;
	int i;

	if (!attrs)
		return;

	desc->sysfs_attrs = NULL;
	for (i = 0; i < desc->nvec_used; i++) {
		if (attrs[i].show)
			sysfs_remove_file_from_group(&dev->kobj, &attrs[i].attr, msi_irqs_group.name);
		kfree(attrs[i].attr.name);
	}
	kfree(attrs);
}

static int msi_sysfs_populate_desc(struct device *dev, struct msi_desc *desc)
{
	struct device_attribute *attrs;
	int ret, i;

	attrs = kcalloc(desc->nvec_used, sizeof(*attrs), GFP_KERNEL);
	if (!attrs)
		return -ENOMEM;

	desc->sysfs_attrs = attrs;
	for (i = 0; i < desc->nvec_used; i++) {
		sysfs_attr_init(&attrs[i].attr);
		attrs[i].attr.name = kasprintf(GFP_KERNEL, "%d", desc->irq + i);
		if (!attrs[i].attr.name) {
			ret = -ENOMEM;
			goto fail;
		}

		attrs[i].attr.mode = 0444;
		attrs[i].show = msi_mode_show;

		ret = sysfs_add_file_to_group(&dev->kobj, &attrs[i].attr, msi_irqs_group.name);
		if (ret) {
			attrs[i].show = NULL;
			goto fail;
		}
	}
	return 0;

fail:
	msi_sysfs_remove_desc(dev, desc);
	return ret;
}

#ifdef CONFIG_PCI_MSI_ARCH_FALLBACKS
int msi_device_populate_sysfs(struct device *dev)
{
	struct msi_desc *desc;
	int ret;

	msi_for_each_desc(desc, dev, MSI_DESC_ASSOCIATED) {
		if (desc->sysfs_attrs)
			continue;
		ret = msi_sysfs_populate_desc(dev, desc);
		if (ret)
			return ret;
	}
	return 0;
}

void msi_device_destroy_sysfs(struct device *dev)
{
	struct msi_desc *desc;

	msi_for_each_desc(desc, dev, MSI_DESC_ALL)
		msi_sysfs_remove_desc(dev, desc);
}
#endif /* CONFIG_PCI_MSI_ARCH_FALLBACK */
#else /* CONFIG_SYSFS */
static inline int msi_sysfs_create_group(struct device *dev) { return 0; }
static inline int msi_sysfs_populate_desc(struct device *dev, struct msi_desc *desc) { return 0; }
static inline void msi_sysfs_remove_desc(struct device *dev, struct msi_desc *desc) { }
#endif /* !CONFIG_SYSFS */

#ifdef CONFIG_GENERIC_MSI_IRQ_DOMAIN
static inline void irq_chip_write_msi_msg(struct irq_data *data,
					  struct msi_msg *msg)
{
	data->chip->irq_write_msi_msg(data, msg);
}

static void msi_check_level(struct irq_domain *domain, struct msi_msg *msg)
{
	struct msi_domain_info *info = domain->host_data;

	/*
	WARN_ON(!((info->flags & MSI_FLAG_LEVEL_CAPABLE) &&
		  (info->chip->flags & IRQCHIP_SUPPORTS_LEVEL_MSI)) &&
		(msg[1].address_lo || msg[1].address_hi || msg[1].data));
}

int msi_domain_set_affinity(struct irq_data *irq_data,
			    const struct cpumask *mask, bool force)
{
	struct irq_data *parent = irq_data->parent_data;
	struct msi_msg msg[2] = { [1] = { }, };
	int ret;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	if (ret >= 0 && ret != IRQ_SET_MASK_OK_DONE) {
		BUG_ON(irq_chip_compose_msi_msg(irq_data, msg));
		msi_check_level(irq_data->domain, msg);
		irq_chip_write_msi_msg(irq_data, msg);
	}

	return ret;
}

static int msi_domain_activate(struct irq_domain *domain,
			       struct irq_data *irq_data, bool early)
{
	struct msi_msg msg[2] = { [1] = { }, };

	BUG_ON(irq_chip_compose_msi_msg(irq_data, msg));
	msi_check_level(irq_data->domain, msg);
	irq_chip_write_msi_msg(irq_data, msg);
	return 0;
}

static void msi_domain_deactivate(struct irq_domain *domain,
				  struct irq_data *irq_data)
{
	struct msi_msg msg[2];

	memset(msg, 0, sizeof(msg));
	irq_chip_write_msi_msg(irq_data, msg);
}

static int msi_domain_alloc(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs, void *arg)
{
	struct msi_domain_info *info = domain->host_data;
	struct msi_domain_ops *ops = info->ops;
	irq_hw_number_t hwirq = ops->get_hwirq(info, arg);
	int i, ret;

	if (irq_find_mapping(domain, hwirq) > 0)
		return -EEXIST;

	if (domain->parent) {
		ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, arg);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < nr_irqs; i++) {
		ret = ops->msi_init(domain, info, virq + i, hwirq + i, arg);
		if (ret < 0) {
			if (ops->msi_free) {
				for (i--; i > 0; i--)
					ops->msi_free(domain, info, virq + i);
			}
			irq_domain_free_irqs_top(domain, virq, nr_irqs);
			return ret;
		}
	}

	return 0;
}

static void msi_domain_free(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs)
{
	struct msi_domain_info *info = domain->host_data;
	int i;

	if (info->ops->msi_free) {
		for (i = 0; i < nr_irqs; i++)
			info->ops->msi_free(domain, info, virq + i);
	}
	irq_domain_free_irqs_top(domain, virq, nr_irqs);
}

static const struct irq_domain_ops msi_domain_ops = {
	.alloc		= msi_domain_alloc,
	.free		= msi_domain_free,
	.activate	= msi_domain_activate,
	.deactivate	= msi_domain_deactivate,
};

static irq_hw_number_t msi_domain_ops_get_hwirq(struct msi_domain_info *info,
						msi_alloc_info_t *arg)
{
	return arg->hwirq;
}

static int msi_domain_ops_prepare(struct irq_domain *domain, struct device *dev,
				  int nvec, msi_alloc_info_t *arg)
{
	memset(arg, 0, sizeof(*arg));
	return 0;
}

static void msi_domain_ops_set_desc(msi_alloc_info_t *arg,
				    struct msi_desc *desc)
{
	arg->desc = desc;
}

static int msi_domain_ops_init(struct irq_domain *domain,
			       struct msi_domain_info *info,
			       unsigned int virq, irq_hw_number_t hwirq,
			       msi_alloc_info_t *arg)
{
	irq_domain_set_hwirq_and_chip(domain, virq, hwirq, info->chip,
				      info->chip_data);
	if (info->handler && info->handler_name) {
		__irq_set_handler(virq, info->handler, 0, info->handler_name);
		if (info->handler_data)
			irq_set_handler_data(virq, info->handler_data);
	}
	return 0;
}

static int msi_domain_ops_check(struct irq_domain *domain,
				struct msi_domain_info *info,
				struct device *dev)
{
	return 0;
}

static struct msi_domain_ops msi_domain_ops_default = {
	.get_hwirq		= msi_domain_ops_get_hwirq,
	.msi_init		= msi_domain_ops_init,
	.msi_check		= msi_domain_ops_check,
	.msi_prepare		= msi_domain_ops_prepare,
	.set_desc		= msi_domain_ops_set_desc,
	.domain_alloc_irqs	= __msi_domain_alloc_irqs,
	.domain_free_irqs	= __msi_domain_free_irqs,
};

static void msi_domain_update_dom_ops(struct msi_domain_info *info)
{
	struct msi_domain_ops *ops = info->ops;

	if (ops == NULL) {
		info->ops = &msi_domain_ops_default;
		return;
	}

	if (ops->domain_alloc_irqs == NULL)
		ops->domain_alloc_irqs = msi_domain_ops_default.domain_alloc_irqs;
	if (ops->domain_free_irqs == NULL)
		ops->domain_free_irqs = msi_domain_ops_default.domain_free_irqs;

	if (!(info->flags & MSI_FLAG_USE_DEF_DOM_OPS))
		return;

	if (ops->get_hwirq == NULL)
		ops->get_hwirq = msi_domain_ops_default.get_hwirq;
	if (ops->msi_init == NULL)
		ops->msi_init = msi_domain_ops_default.msi_init;
	if (ops->msi_check == NULL)
		ops->msi_check = msi_domain_ops_default.msi_check;
	if (ops->msi_prepare == NULL)
		ops->msi_prepare = msi_domain_ops_default.msi_prepare;
	if (ops->set_desc == NULL)
		ops->set_desc = msi_domain_ops_default.set_desc;
}

static void msi_domain_update_chip_ops(struct msi_domain_info *info)
{
	struct irq_chip *chip = info->chip;

	BUG_ON(!chip || !chip->irq_mask || !chip->irq_unmask);
	if (!chip->irq_set_affinity)
		chip->irq_set_affinity = msi_domain_set_affinity;
}

struct irq_domain *msi_create_irq_domain(struct fwnode_handle *fwnode,
					 struct msi_domain_info *info,
					 struct irq_domain *parent)
{
	struct irq_domain *domain;

	msi_domain_update_dom_ops(info);
	if (info->flags & MSI_FLAG_USE_DEF_CHIP_OPS)
		msi_domain_update_chip_ops(info);

	domain = irq_domain_create_hierarchy(parent, IRQ_DOMAIN_FLAG_MSI, 0,
					     fwnode, &msi_domain_ops, info);

	if (domain && !domain->name && info->chip)
		domain->name = info->chip->name;

	return domain;
}

int msi_domain_prepare_irqs(struct irq_domain *domain, struct device *dev,
			    int nvec, msi_alloc_info_t *arg)
{
	struct msi_domain_info *info = domain->host_data;
	struct msi_domain_ops *ops = info->ops;
	int ret;

	ret = ops->msi_check(domain, info, dev);
	if (ret == 0)
		ret = ops->msi_prepare(domain, dev, nvec, arg);

	return ret;
}

int msi_domain_populate_irqs(struct irq_domain *domain, struct device *dev,
			     int virq_base, int nvec, msi_alloc_info_t *arg)
{
	struct msi_domain_info *info = domain->host_data;
	struct msi_domain_ops *ops = info->ops;
	struct msi_desc *desc;
	int ret, virq;

	msi_lock_descs(dev);
	ret = msi_add_simple_msi_descs(dev, virq_base, nvec);
	if (ret)
		goto unlock;

	for (virq = virq_base; virq < virq_base + nvec; virq++) {
		desc = xa_load(&dev->msi.data->__store, virq);
		desc->irq = virq;

		ops->set_desc(arg, desc);
		ret = irq_domain_alloc_irqs_hierarchy(domain, virq, 1, arg);
		if (ret)
			goto fail;

		irq_set_msi_desc(virq, desc);
	}
	msi_unlock_descs(dev);
	return 0;

fail:
	for (--virq; virq >= virq_base; virq--)
		irq_domain_free_irqs_common(domain, virq, 1);
	msi_free_msi_descs_range(dev, MSI_DESC_ALL, virq_base, virq_base + nvec - 1);
unlock:
	msi_unlock_descs(dev);
	return ret;
}

static bool msi_check_reservation_mode(struct irq_domain *domain,
				       struct msi_domain_info *info,
				       struct device *dev)
{
	struct msi_desc *desc;

	switch(domain->bus_token) {
	case DOMAIN_BUS_PCI_MSI:
	case DOMAIN_BUS_VMD_MSI:
		break;
	default:
		return false;
	}

	if (!(info->flags & MSI_FLAG_MUST_REACTIVATE))
		return false;

	if (IS_ENABLED(CONFIG_PCI_MSI) && pci_msi_ignore_mask)
		return false;

	/*
	desc = msi_first_desc(dev, MSI_DESC_ALL);
	return desc->pci.msi_attrib.is_msix || desc->pci.msi_attrib.can_mask;
}

static int msi_handle_pci_fail(struct irq_domain *domain, struct msi_desc *desc,
			       int allocated)
{
	switch(domain->bus_token) {
	case DOMAIN_BUS_PCI_MSI:
	case DOMAIN_BUS_VMD_MSI:
		if (IS_ENABLED(CONFIG_PCI_MSI))
			break;
		fallthrough;
	default:
		return -ENOSPC;
	}

	/* Let a failed PCI multi MSI allocation retry */
	if (desc->nvec_used > 1)
		return 1;

	/* If there was a successful allocation let the caller know */
	return allocated ? allocated : -ENOSPC;
}

#define VIRQ_CAN_RESERVE	0x01
#define VIRQ_ACTIVATE		0x02
#define VIRQ_NOMASK_QUIRK	0x04

static int msi_init_virq(struct irq_domain *domain, int virq, unsigned int vflags)
{
	struct irq_data *irqd = irq_domain_get_irq_data(domain, virq);
	int ret;

	if (!(vflags & VIRQ_CAN_RESERVE)) {
		irqd_clr_can_reserve(irqd);
		if (vflags & VIRQ_NOMASK_QUIRK)
			irqd_set_msi_nomask_quirk(irqd);

		/*
		if ((vflags & VIRQ_ACTIVATE) &&
		    irqd_affinity_is_managed(irqd) &&
		    !cpumask_intersects(irq_data_get_affinity_mask(irqd),
					cpu_online_mask)) {
			    irqd_set_managed_shutdown(irqd);
			    return 0;
		    }
	}

	if (!(vflags & VIRQ_ACTIVATE))
		return 0;

	ret = irq_domain_activate_irq(irqd, vflags & VIRQ_CAN_RESERVE);
	if (ret)
		return ret;
	/*
	if (vflags & VIRQ_CAN_RESERVE)
		irqd_clr_activated(irqd);
	return 0;
}

int __msi_domain_alloc_irqs(struct irq_domain *domain, struct device *dev,
			    int nvec)
{
	struct msi_domain_info *info = domain->host_data;
	struct msi_domain_ops *ops = info->ops;
	msi_alloc_info_t arg = { };
	unsigned int vflags = 0;
	struct msi_desc *desc;
	int allocated = 0;
	int i, ret, virq;

	ret = msi_domain_prepare_irqs(domain, dev, nvec, &arg);
	if (ret)
		return ret;

	/*
	if (info->flags & MSI_FLAG_ACTIVATE_EARLY)
		vflags |= VIRQ_ACTIVATE;

	/*
	if (msi_check_reservation_mode(domain, info, dev)) {
		vflags |= VIRQ_CAN_RESERVE;
		/*
		if (domain->flags & IRQ_DOMAIN_MSI_NOMASK_QUIRK)
			vflags |= VIRQ_NOMASK_QUIRK;
	}

	msi_for_each_desc(desc, dev, MSI_DESC_NOTASSOCIATED) {
		ops->set_desc(&arg, desc);

		virq = __irq_domain_alloc_irqs(domain, -1, desc->nvec_used,
					       dev_to_node(dev), &arg, false,
					       desc->affinity);
		if (virq < 0)
			return msi_handle_pci_fail(domain, desc, allocated);

		for (i = 0; i < desc->nvec_used; i++) {
			irq_set_msi_desc_off(virq, i, desc);
			irq_debugfs_copy_devname(virq + i, dev);
			ret = msi_init_virq(domain, virq + i, vflags);
			if (ret)
				return ret;
		}
		if (info->flags & MSI_FLAG_DEV_SYSFS) {
			ret = msi_sysfs_populate_desc(dev, desc);
			if (ret)
				return ret;
		}
		allocated++;
	}
	return 0;
}

static int msi_domain_add_simple_msi_descs(struct msi_domain_info *info,
					   struct device *dev,
					   unsigned int num_descs)
{
	if (!(info->flags & MSI_FLAG_ALLOC_SIMPLE_MSI_DESCS))
		return 0;

	return msi_add_simple_msi_descs(dev, 0, num_descs);
}

int msi_domain_alloc_irqs_descs_locked(struct irq_domain *domain, struct device *dev,
				       int nvec)
{
	struct msi_domain_info *info = domain->host_data;
	struct msi_domain_ops *ops = info->ops;
	int ret;

	lockdep_assert_held(&dev->msi.data->mutex);

	ret = msi_domain_add_simple_msi_descs(info, dev, nvec);
	if (ret)
		return ret;

	ret = ops->domain_alloc_irqs(domain, dev, nvec);
	if (ret)
		msi_domain_free_irqs_descs_locked(domain, dev);
	return ret;
}

int msi_domain_alloc_irqs(struct irq_domain *domain, struct device *dev, int nvec)
{
	int ret;

	msi_lock_descs(dev);
	ret = msi_domain_alloc_irqs_descs_locked(domain, dev, nvec);
	msi_unlock_descs(dev);
	return ret;
}

void __msi_domain_free_irqs(struct irq_domain *domain, struct device *dev)
{
	struct msi_domain_info *info = domain->host_data;
	struct irq_data *irqd;
	struct msi_desc *desc;
	int i;

	/* Only handle MSI entries which have an interrupt associated */
	msi_for_each_desc(desc, dev, MSI_DESC_ASSOCIATED) {
		/* Make sure all interrupts are deactivated */
		for (i = 0; i < desc->nvec_used; i++) {
			irqd = irq_domain_get_irq_data(domain, desc->irq + i);
			if (irqd && irqd_is_activated(irqd))
				irq_domain_deactivate_irq(irqd);
		}

		irq_domain_free_irqs(desc->irq, desc->nvec_used);
		if (info->flags & MSI_FLAG_DEV_SYSFS)
			msi_sysfs_remove_desc(dev, desc);
		desc->irq = 0;
	}
}

static void msi_domain_free_msi_descs(struct msi_domain_info *info,
				      struct device *dev)
{
	if (info->flags & MSI_FLAG_FREE_MSI_DESCS)
		msi_free_msi_descs(dev);
}

void msi_domain_free_irqs_descs_locked(struct irq_domain *domain, struct device *dev)
{
	struct msi_domain_info *info = domain->host_data;
	struct msi_domain_ops *ops = info->ops;

	lockdep_assert_held(&dev->msi.data->mutex);

	ops->domain_free_irqs(domain, dev);
	msi_domain_free_msi_descs(info, dev);
}

void msi_domain_free_irqs(struct irq_domain *domain, struct device *dev)
{
	msi_lock_descs(dev);
	msi_domain_free_irqs_descs_locked(domain, dev);
	msi_unlock_descs(dev);
}

struct msi_domain_info *msi_get_domain_info(struct irq_domain *domain)
{
	return (struct msi_domain_info *)domain->host_data;
}

#endif /* CONFIG_GENERIC_MSI_IRQ_DOMAIN */
