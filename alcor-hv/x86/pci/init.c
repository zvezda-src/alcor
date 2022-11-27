#include <linux/pci.h>
#include <linux/init.h>
#include <asm/pci_x86.h>
#include <asm/x86_init.h>
#include <asm/irqdomain.h>

   in the right sequence from here. */
static __init int pci_arch_init(void)
{
	int type, pcbios = 1;

	type = pci_direct_probe();

	if (!(pci_probe & PCI_PROBE_NOEARLY))
		pci_mmcfg_early_init();

	if (x86_init.pci.arch_init)
		pcbios = x86_init.pci.arch_init();

	/*
	x86_create_pci_msi_domain();

	if (!pcbios)
		return 0;

	pci_pcbios_init();

	/*
	pci_direct_init(type);

	if (!raw_pci_ops && !raw_pci_ext_ops)
		printk(KERN_ERR
		"PCI: Fatal: No config space access function found\n");

	dmi_check_pciprobe();

	dmi_check_skip_isa_align();

	return 0;
}
arch_initcall(pci_arch_init);
