#include <linux/acpi.h>

#include <xen/hvc-console.h>

#include <asm/io_apic.h>
#include <asm/hypervisor.h>
#include <asm/e820/api.h>
#include <asm/x86_init.h>

#include <asm/xen/interface.h>

#include <xen/xen.h>
#include <xen/interface/hvm/start_info.h>

struct boot_params __initdata pvh_bootparams;
struct hvm_start_info __initdata pvh_start_info;

const unsigned int __initconst pvh_start_info_sz = sizeof(pvh_start_info);

static u64 __init pvh_get_root_pointer(void)
{
	return pvh_start_info.rsdp_paddr;
}

void __init __weak mem_map_via_hcall(struct boot_params *ptr __maybe_unused)
{
	xen_raw_printk("Error: Could not find memory map\n");
	BUG();
}

static void __init init_pvh_bootparams(bool xen_guest)
{
	if ((pvh_start_info.version > 0) && (pvh_start_info.memmap_entries)) {
		struct hvm_memmap_table_entry *ep;
		int i;

		ep = __va(pvh_start_info.memmap_paddr);
		pvh_bootparams.e820_entries = pvh_start_info.memmap_entries;

		for (i = 0; i < pvh_bootparams.e820_entries ; i++, ep++) {
			pvh_bootparams.e820_table[i].addr = ep->addr;
			pvh_bootparams.e820_table[i].size = ep->size;
			pvh_bootparams.e820_table[i].type = ep->type;
		}
	} else if (xen_guest) {
		mem_map_via_hcall(&pvh_bootparams);
	} else {
		/* Non-xen guests are not supported by version 0 */
		BUG();
	}

	if (pvh_bootparams.e820_entries < E820_MAX_ENTRIES_ZEROPAGE - 1) {
		pvh_bootparams.e820_table[pvh_bootparams.e820_entries].addr =
			ISA_START_ADDRESS;
		pvh_bootparams.e820_table[pvh_bootparams.e820_entries].size =
			ISA_END_ADDRESS - ISA_START_ADDRESS;
		pvh_bootparams.e820_table[pvh_bootparams.e820_entries].type =
			E820_TYPE_RESERVED;
		pvh_bootparams.e820_entries++;
	} else
		xen_raw_printk("Warning: Can fit ISA range into e820\n");

	pvh_bootparams.hdr.cmd_line_ptr =
		pvh_start_info.cmdline_paddr;

	/* The first module is always ramdisk. */
	if (pvh_start_info.nr_modules) {
		struct hvm_modlist_entry *modaddr =
			__va(pvh_start_info.modlist_paddr);
		pvh_bootparams.hdr.ramdisk_image = modaddr->paddr;
		pvh_bootparams.hdr.ramdisk_size = modaddr->size;
	}

	/*
	pvh_bootparams.hdr.version = (2 << 8) | 12;
	pvh_bootparams.hdr.type_of_loader = ((xen_guest ? 0x9 : 0xb) << 4) | 0;

	x86_init.acpi.get_root_pointer = pvh_get_root_pointer;
}

void __init __weak xen_pvh_init(struct boot_params *boot_params)
{
	xen_raw_printk("Error: Missing xen PVH initialization\n");
	BUG();
}

static void __init hypervisor_specific_init(bool xen_guest)
{
	if (xen_guest)
		xen_pvh_init(&pvh_bootparams);
}

void __init xen_prepare_pvh(void)
{

	u32 msr = xen_cpuid_base();
	bool xen_guest = !!msr;

	if (pvh_start_info.magic != XEN_HVM_START_MAGIC_VALUE) {
		xen_raw_printk("Error: Unexpected magic value (0x%08x)\n",
				pvh_start_info.magic);
		BUG();
	}

	memset(&pvh_bootparams, 0, sizeof(pvh_bootparams));

	hypervisor_specific_init(xen_guest);

	init_pvh_bootparams(xen_guest);
}
