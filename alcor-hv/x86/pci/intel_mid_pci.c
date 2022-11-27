
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/dmi.h>
#include <linux/acpi.h>
#include <linux/io.h>
#include <linux/smp.h>

#include <asm/cpu_device_id.h>
#include <asm/segment.h>
#include <asm/pci_x86.h>
#include <asm/hw_irq.h>
#include <asm/io_apic.h>
#include <asm/intel-family.h>
#include <asm/intel-mid.h>
#include <asm/acpi.h>

#define PCIE_CAP_OFFSET	0x100

#define PCI_DEVICE_ID_INTEL_MRFLD_MMC	0x1190
#define PCI_DEVICE_ID_INTEL_MRFLD_HSU	0x1191

#define PCIE_VNDR_CAP_ID_FIXED_BAR 0x00	/* Fixed BAR (TBD) */
#define PCI_FIXED_BAR_0_SIZE	0x04
#define PCI_FIXED_BAR_1_SIZE	0x08
#define PCI_FIXED_BAR_2_SIZE	0x0c
#define PCI_FIXED_BAR_3_SIZE	0x10
#define PCI_FIXED_BAR_4_SIZE	0x14
#define PCI_FIXED_BAR_5_SIZE	0x1c

static int pci_soc_mode;

static int fixed_bar_cap(struct pci_bus *bus, unsigned int devfn)
{
	int pos;
	u32 pcie_cap = 0, cap_data;

	pos = PCIE_CAP_OFFSET;

	if (!raw_pci_ext_ops)
		return 0;

	while (pos) {
		if (raw_pci_ext_ops->read(pci_domain_nr(bus), bus->number,
					  devfn, pos, 4, &pcie_cap))
			return 0;

		if (PCI_EXT_CAP_ID(pcie_cap) == 0x0000 ||
			PCI_EXT_CAP_ID(pcie_cap) == 0xffff)
			break;

		if (PCI_EXT_CAP_ID(pcie_cap) == PCI_EXT_CAP_ID_VNDR) {
			raw_pci_ext_ops->read(pci_domain_nr(bus), bus->number,
					      devfn, pos + 4, 4, &cap_data);
			if ((cap_data & 0xffff) == PCIE_VNDR_CAP_ID_FIXED_BAR)
				return pos;
		}

		pos = PCI_EXT_CAP_NEXT(pcie_cap);
	}

	return 0;
}

static int pci_device_update_fixed(struct pci_bus *bus, unsigned int devfn,
				   int reg, int len, u32 val, int offset)
{
	u32 size;
	unsigned int domain, busnum;
	int bar = (reg - PCI_BASE_ADDRESS_0) >> 2;

	domain = pci_domain_nr(bus);
	busnum = bus->number;

	if (val == ~0 && len == 4) {
		unsigned long decode;

		raw_pci_ext_ops->read(domain, busnum, devfn,
			       offset + 8 + (bar * 4), 4, &size);

		/* Turn the size into a decode pattern for the sizing code */
		if (size) {
			decode = size - 1;
			decode |= decode >> 1;
			decode |= decode >> 2;
			decode |= decode >> 4;
			decode |= decode >> 8;
			decode |= decode >> 16;
			decode++;
			decode = ~(decode - 1);
		} else {
			decode = 0;
		}

		/*
		return raw_pci_ext_ops->write(domain, busnum, devfn, reg, 4,
				       decode);
	}

	/* This is some other kind of BAR write, so just do it. */
	return raw_pci_ext_ops->write(domain, busnum, devfn, reg, len, val);
}

static bool type1_access_ok(unsigned int bus, unsigned int devfn, int reg)
{
	/*
	if (reg >= 0x100 || reg == PCI_STATUS || reg == PCI_HEADER_TYPE)
		return false;
	if (bus == 0 && (devfn == PCI_DEVFN(2, 0)
				|| devfn == PCI_DEVFN(0, 0)
				|| devfn == PCI_DEVFN(3, 0)))
		return true;
	return false; /* Langwell on others */
}

static int pci_read(struct pci_bus *bus, unsigned int devfn, int where,
		    int size, u32 *value)
{
	if (type1_access_ok(bus->number, devfn, where))
		return pci_direct_conf1.read(pci_domain_nr(bus), bus->number,
					devfn, where, size, value);
	return raw_pci_ext_ops->read(pci_domain_nr(bus), bus->number,
			      devfn, where, size, value);
}

static int pci_write(struct pci_bus *bus, unsigned int devfn, int where,
		     int size, u32 value)
{
	int offset;

	/*
	if (where == PCI_ROM_ADDRESS)
		return 0;

	/*
	offset = fixed_bar_cap(bus, devfn);
	if (offset &&
	    (where >= PCI_BASE_ADDRESS_0 && where <= PCI_BASE_ADDRESS_5)) {
		return pci_device_update_fixed(bus, devfn, where, size, value,
					       offset);
	}

	/*
	if (type1_access_ok(bus->number, devfn, where))
		return pci_direct_conf1.write(pci_domain_nr(bus), bus->number,
					      devfn, where, size, value);
	return raw_pci_ext_ops->write(pci_domain_nr(bus), bus->number, devfn,
			       where, size, value);
}

static const struct x86_cpu_id intel_mid_cpu_ids[] = {
	X86_MATCH_INTEL_FAM6_MODEL(ATOM_SILVERMONT_MID, NULL),
	{}
};

static int intel_mid_pci_irq_enable(struct pci_dev *dev)
{
	const struct x86_cpu_id *id;
	struct irq_alloc_info info;
	bool polarity_low;
	u16 model = 0;
	int ret;
	u8 gsi;

	if (dev->irq_managed && dev->irq > 0)
		return 0;

	ret = pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &gsi);
	if (ret < 0) {
		dev_warn(&dev->dev, "Failed to read interrupt line: %d\n", ret);
		return ret;
	}

	id = x86_match_cpu(intel_mid_cpu_ids);
	if (id)
		model = id->model;

	switch (model) {
	case INTEL_FAM6_ATOM_SILVERMONT_MID:
		polarity_low = false;

		/* Special treatment for IRQ0 */
		if (gsi == 0) {
			/*
			if (dev->device == PCI_DEVICE_ID_INTEL_MRFLD_HSU)
				return -EBUSY;
			/*
			if (dev->device != PCI_DEVICE_ID_INTEL_MRFLD_MMC)
				return 0;
		}
		break;
	default:
		polarity_low = true;
		break;
	}

	ioapic_set_alloc_attr(&info, dev_to_node(&dev->dev), 1, polarity_low);

	/*
	ret = mp_map_gsi_to_irq(gsi, IOAPIC_MAP_ALLOC, &info);
	if (ret < 0)
		return ret;

	dev->irq = ret;
	dev->irq_managed = 1;

	return 0;
}

static void intel_mid_pci_irq_disable(struct pci_dev *dev)
{
	if (!mp_should_keep_irq(&dev->dev) && dev->irq_managed &&
	    dev->irq > 0) {
		mp_unmap_irq(dev->irq);
		dev->irq_managed = 0;
	}
}

static const struct pci_ops intel_mid_pci_ops __initconst = {
	.read = pci_read,
	.write = pci_write,
};

int __init intel_mid_pci_init(void)
{
	pr_info("Intel MID platform detected, using MID PCI ops\n");
	pci_mmcfg_late_init();
	pcibios_enable_irq = intel_mid_pci_irq_enable;
	pcibios_disable_irq = intel_mid_pci_irq_disable;
	pci_root_ops = intel_mid_pci_ops;
	pci_soc_mode = 1;
	/* Continue with standard init */
	acpi_noirq_set();
	return 1;
}

static void pci_d3delay_fixup(struct pci_dev *dev)
{
	/*
	if (!pci_soc_mode)
		return;
	/*
	if (type1_access_ok(dev->bus->number, dev->devfn, PCI_DEVICE_ID))
		return;
	dev->d3hot_delay = 0;
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, pci_d3delay_fixup);

static void mid_power_off_one_device(struct pci_dev *dev)
{
	u16 pmcsr;

	/*
	pci_read_config_word(dev, dev->pm_cap + PCI_PM_CTRL, &pmcsr);
	dev->current_state = (pci_power_t __force)(pmcsr & PCI_PM_CTRL_STATE_MASK);

	pci_set_power_state(dev, PCI_D3hot);
}

static void mid_power_off_devices(struct pci_dev *dev)
{
	int id;

	if (!pci_soc_mode)
		return;

	id = intel_mid_pwr_get_lss_id(dev);
	if (id < 0)
		return;

	/*
	mid_power_off_one_device(dev);
}

DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, mid_power_off_devices);

static void pci_fixed_bar_fixup(struct pci_dev *dev)
{
	unsigned long offset;
	u32 size;
	int i;

	if (!pci_soc_mode)
		return;

	/* Must have extended configuration space */
	if (dev->cfg_size < PCIE_CAP_OFFSET + 4)
		return;

	/* Fixup the BAR sizes for fixed BAR devices and make them unmoveable */
	offset = fixed_bar_cap(dev->bus, dev->devfn);
	if (!offset || PCI_DEVFN(2, 0) == dev->devfn ||
	    PCI_DEVFN(2, 2) == dev->devfn)
		return;

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		pci_read_config_dword(dev, offset + 8 + (i * 4), &size);
		dev->resource[i].end = dev->resource[i].start + size - 1;
		dev->resource[i].flags |= IORESOURCE_PCI_FIXED;
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, pci_fixed_bar_fixup);
