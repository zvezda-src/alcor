#define pr_fmt(fmt) "efi: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/efi.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/acpi.h>
#include <linux/dmi.h>

#include <asm/e820/api.h>
#include <asm/efi.h>
#include <asm/uv/uv.h>
#include <asm/cpu_device_id.h>
#include <asm/realmode.h>
#include <asm/reboot.h>

#define EFI_MIN_RESERVE 5120

#define EFI_DUMMY_GUID \
	EFI_GUID(0x4424ac57, 0xbe4b, 0x47dd, 0x9e, 0x97, 0xed, 0x50, 0xf0, 0x9f, 0x92, 0xa9)

#define QUARK_CSH_SIGNATURE		0x5f435348	/* _CSH */
#define QUARK_SECURITY_HEADER_SIZE	0x400

struct quark_security_header {
	u32 csh_signature;
	u32 version;
	u32 modulesize;
	u32 security_version_number_index;
	u32 security_version_number;
	u32 rsvd_module_id;
	u32 rsvd_module_vendor;
	u32 rsvd_date;
	u32 headersize;
	u32 hash_algo;
	u32 cryp_algo;
	u32 keysize;
	u32 signaturesize;
	u32 rsvd_next_header;
	u32 rsvd[2];
};

static const efi_char16_t efi_dummy_name[] = L"DUMMY";

static bool efi_no_storage_paranoia;

static int __init setup_storage_paranoia(char *arg)
{
	efi_no_storage_paranoia = true;
	return 0;
}
early_param("efi_no_storage_paranoia", setup_storage_paranoia);

void efi_delete_dummy_variable(void)
{
	efi.set_variable_nonblocking((efi_char16_t *)efi_dummy_name,
				     &EFI_DUMMY_GUID,
				     EFI_VARIABLE_NON_VOLATILE |
				     EFI_VARIABLE_BOOTSERVICE_ACCESS |
				     EFI_VARIABLE_RUNTIME_ACCESS, 0, NULL);
}

static efi_status_t
query_variable_store_nonblocking(u32 attributes, unsigned long size)
{
	efi_status_t status;
	u64 storage_size, remaining_size, max_size;

	status = efi.query_variable_info_nonblocking(attributes, &storage_size,
						     &remaining_size,
						     &max_size);
	if (status != EFI_SUCCESS)
		return status;

	if (remaining_size - size < EFI_MIN_RESERVE)
		return EFI_OUT_OF_RESOURCES;

	return EFI_SUCCESS;
}

efi_status_t efi_query_variable_store(u32 attributes, unsigned long size,
				      bool nonblocking)
{
	efi_status_t status;
	u64 storage_size, remaining_size, max_size;

	if (!(attributes & EFI_VARIABLE_NON_VOLATILE))
		return 0;

	if (nonblocking)
		return query_variable_store_nonblocking(attributes, size);

	status = efi.query_variable_info(attributes, &storage_size,
					 &remaining_size, &max_size);
	if (status != EFI_SUCCESS)
		return status;

	/*
	if ((remaining_size - size < EFI_MIN_RESERVE) &&
		!efi_no_storage_paranoia) {

		/*
		unsigned long dummy_size = remaining_size + 1024;
		void *dummy = kzalloc(dummy_size, GFP_KERNEL);

		if (!dummy)
			return EFI_OUT_OF_RESOURCES;

		status = efi.set_variable((efi_char16_t *)efi_dummy_name,
					  &EFI_DUMMY_GUID,
					  EFI_VARIABLE_NON_VOLATILE |
					  EFI_VARIABLE_BOOTSERVICE_ACCESS |
					  EFI_VARIABLE_RUNTIME_ACCESS,
					  dummy_size, dummy);

		if (status == EFI_SUCCESS) {
			/*
			efi_delete_dummy_variable();
		}

		kfree(dummy);

		/*
		status = efi.query_variable_info(attributes, &storage_size,
						 &remaining_size, &max_size);

		if (status != EFI_SUCCESS)
			return status;

		/*
		if (remaining_size - size < EFI_MIN_RESERVE)
			return EFI_OUT_OF_RESOURCES;
	}

	return EFI_SUCCESS;
}
EXPORT_SYMBOL_GPL(efi_query_variable_store);

void __init efi_arch_mem_reserve(phys_addr_t addr, u64 size)
{
	struct efi_memory_map_data data = { 0 };
	struct efi_mem_range mr;
	efi_memory_desc_t md;
	int num_entries;
	void *new;

	if (efi_mem_desc_lookup(addr, &md) ||
	    md.type != EFI_BOOT_SERVICES_DATA) {
		pr_err("Failed to lookup EFI memory descriptor for %pa\n", &addr);
		return;
	}

	if (addr + size > md.phys_addr + (md.num_pages << EFI_PAGE_SHIFT)) {
		pr_err("Region spans EFI memory descriptors, %pa\n", &addr);
		return;
	}

	size += addr % EFI_PAGE_SIZE;
	size = round_up(size, EFI_PAGE_SIZE);
	addr = round_down(addr, EFI_PAGE_SIZE);

	mr.range.start = addr;
	mr.range.end = addr + size - 1;
	mr.attribute = md.attribute | EFI_MEMORY_RUNTIME;

	num_entries = efi_memmap_split_count(&md, &mr.range);
	num_entries += efi.memmap.nr_map;

	if (efi_memmap_alloc(num_entries, &data) != 0) {
		pr_err("Could not allocate boot services memmap\n");
		return;
	}

	new = early_memremap_prot(data.phys_map, data.size,
				  pgprot_val(pgprot_encrypted(FIXMAP_PAGE_NORMAL)));
	if (!new) {
		pr_err("Failed to map new boot services memmap\n");
		return;
	}

	efi_memmap_insert(&efi.memmap, new, &mr);
	early_memunmap(new, data.size);

	efi_memmap_install(&data);
	e820__range_update(addr, size, E820_TYPE_RAM, E820_TYPE_RESERVED);
	e820__update_table(e820_table);
}

static __init bool can_free_region(u64 start, u64 size)
{
	if (start + size > __pa_symbol(_text) && start <= __pa_symbol(_end))
		return false;

	if (!e820__mapped_all(start, start+size, E820_TYPE_RAM))
		return false;

	return true;
}

void __init efi_reserve_boot_services(void)
{
	efi_memory_desc_t *md;

	if (!efi_enabled(EFI_MEMMAP))
		return;

	for_each_efi_memory_desc(md) {
		u64 start = md->phys_addr;
		u64 size = md->num_pages << EFI_PAGE_SHIFT;
		bool already_reserved;

		if (md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA)
			continue;

		already_reserved = memblock_is_region_reserved(start, size);

		/*
		if (!already_reserved) {
			memblock_reserve(start, size);

			/*
			if (can_free_region(start, size))
				continue;
		}

		/*
		md->attribute |= EFI_MEMORY_RUNTIME;
	}
}

static void __init efi_unmap_pages(efi_memory_desc_t *md)
{
	pgd_t *pgd = efi_mm.pgd;
	u64 pa = md->phys_addr;
	u64 va = md->virt_addr;

	/*
	if (efi_is_mixed())
		return;

	if (kernel_unmap_pages_in_pgd(pgd, pa, md->num_pages))
		pr_err("Failed to unmap 1:1 mapping for 0x%llx\n", pa);

	if (kernel_unmap_pages_in_pgd(pgd, va, md->num_pages))
		pr_err("Failed to unmap VA mapping for 0x%llx\n", va);
}

void __init efi_free_boot_services(void)
{
	struct efi_memory_map_data data = { 0 };
	efi_memory_desc_t *md;
	int num_entries = 0;
	void *new, *new_md;

	/* Keep all regions for /sys/kernel/debug/efi */
	if (efi_enabled(EFI_DBG))
		return;

	for_each_efi_memory_desc(md) {
		unsigned long long start = md->phys_addr;
		unsigned long long size = md->num_pages << EFI_PAGE_SHIFT;
		size_t rm_size;

		if (md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA) {
			num_entries++;
			continue;
		}

		/* Do not free, someone else owns it: */
		if (md->attribute & EFI_MEMORY_RUNTIME) {
			num_entries++;
			continue;
		}

		/*
		efi_unmap_pages(md);

		/*
		rm_size = real_mode_size_needed();
		if (rm_size && (start + rm_size) < (1<<20) && size >= rm_size) {
			set_real_mode_mem(start);
			start += rm_size;
			size -= rm_size;
		}

		/*
		if (start + size < SZ_1M)
			continue;
		if (start < SZ_1M) {
			size -= (SZ_1M - start);
			start = SZ_1M;
		}

		memblock_free_late(start, size);
	}

	if (!num_entries)
		return;

	if (efi_memmap_alloc(num_entries, &data) != 0) {
		pr_err("Failed to allocate new EFI memmap\n");
		return;
	}

	new = memremap(data.phys_map, data.size, MEMREMAP_WB);
	if (!new) {
		pr_err("Failed to map new EFI memmap\n");
		return;
	}

	/*
	new_md = new;
	for_each_efi_memory_desc(md) {
		if (!(md->attribute & EFI_MEMORY_RUNTIME) &&
		    (md->type == EFI_BOOT_SERVICES_CODE ||
		     md->type == EFI_BOOT_SERVICES_DATA))
			continue;

		memcpy(new_md, md, efi.memmap.desc_size);
		new_md += efi.memmap.desc_size;
	}

	memunmap(new);

	if (efi_memmap_install(&data) != 0) {
		pr_err("Could not install new EFI memmap\n");
		return;
	}
}

int __init efi_reuse_config(u64 tables, int nr_tables)
{
	int i, sz, ret = 0;
	void *p, *tablep;
	struct efi_setup_data *data;

	if (nr_tables == 0)
		return 0;

	if (!efi_setup)
		return 0;

	if (!efi_enabled(EFI_64BIT))
		return 0;

	data = early_memremap(efi_setup, sizeof(*data));
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	if (!data->smbios)
		goto out_memremap;

	sz = sizeof(efi_config_table_64_t);

	p = tablep = early_memremap(tables, nr_tables * sz);
	if (!p) {
		pr_err("Could not map Configuration table!\n");
		ret = -ENOMEM;
		goto out_memremap;
	}

	for (i = 0; i < nr_tables; i++) {
		efi_guid_t guid;

		guid = ((efi_config_table_64_t *)p)->guid;

		if (!efi_guidcmp(guid, SMBIOS_TABLE_GUID))
			((efi_config_table_64_t *)p)->table = data->smbios;
		p += sz;
	}
	early_memunmap(tablep, nr_tables * sz);

out_memremap:
	early_memunmap(data, sizeof(*data));
out:
	return ret;
}

void __init efi_apply_memmap_quirks(void)
{
	/*
	if (!efi_runtime_supported()) {
		pr_info("Setup done, disabling due to 32/64-bit mismatch\n");
		efi_memmap_unmap();
	}
}

bool efi_reboot_required(void)
{
	if (!acpi_gbl_reduced_hardware)
		return false;

	efi_reboot_quirk_mode = EFI_RESET_WARM;
	return true;
}

bool efi_poweroff_required(void)
{
	return acpi_gbl_reduced_hardware || acpi_no_s5;
}

#ifdef CONFIG_EFI_CAPSULE_QUIRK_QUARK_CSH

static int qrk_capsule_setup_info(struct capsule_info *cap_info, void **pkbuff,
				  size_t hdr_bytes)
{
	struct quark_security_header *csh = *pkbuff;

	/* Only process data block that is larger than the security header */
	if (hdr_bytes < sizeof(struct quark_security_header))
		return 0;

	if (csh->csh_signature != QUARK_CSH_SIGNATURE ||
	    csh->headersize != QUARK_SECURITY_HEADER_SIZE)
		return 1;

	/* Only process data block if EFI header is included */
	if (hdr_bytes < QUARK_SECURITY_HEADER_SIZE +
			sizeof(efi_capsule_header_t))
		return 0;

	pr_debug("Quark security header detected\n");

	if (csh->rsvd_next_header != 0) {
		pr_err("multiple Quark security headers not supported\n");
		return -EINVAL;
	}

	cap_info->total_size = csh->headersize;

	/*
	cap_info->phys[0] += csh->headersize;

	/*
	cap_info->capsule = &cap_info->header;

	return 1;
}

static const struct x86_cpu_id efi_capsule_quirk_ids[] = {
	X86_MATCH_VENDOR_FAM_MODEL(INTEL, 5, INTEL_FAM5_QUARK_X1000,
				   &qrk_capsule_setup_info),
	{ }
};

int efi_capsule_setup_info(struct capsule_info *cap_info, void *kbuff,
			   size_t hdr_bytes)
{
	int (*quirk_handler)(struct capsule_info *, void **, size_t);
	const struct x86_cpu_id *id;
	int ret;

	if (hdr_bytes < sizeof(efi_capsule_header_t))
		return 0;

	cap_info->total_size = 0;

	id = x86_match_cpu(efi_capsule_quirk_ids);
	if (id) {
		/*
		quirk_handler = (typeof(quirk_handler))id->driver_data;
		ret = quirk_handler(cap_info, &kbuff, hdr_bytes);
		if (ret <= 0)
			return ret;
	}

	memcpy(&cap_info->header, kbuff, sizeof(cap_info->header));

	cap_info->total_size += cap_info->header.imagesize;

	return __efi_capsule_setup_info(cap_info);
}

#endif

void efi_crash_gracefully_on_page_fault(unsigned long phys_addr)
{
	if (!IS_ENABLED(CONFIG_X86_64))
		return;

	/*
	if (in_interrupt())
		return;

	/*
	if (READ_ONCE(efi_rts_work.efi_rts_id) == EFI_NONE ||
	    current_work() != &efi_rts_work.work)
		return;

	/*
	if (phys_addr <= 0x0fff)
		return;

	/*
	WARN(1, FW_BUG "Page fault caused by firmware at PA: 0x%lx\n",
	     phys_addr);

	/*
	if (efi_rts_work.efi_rts_id == EFI_RESET_SYSTEM) {
		pr_info("efi_reset_system() buggy! Reboot through BIOS\n");
		machine_real_restart(MRR_BIOS);
		return;
	}

	/*
	arch_efi_call_virt_teardown();

	/* Signal error status to the efi caller process */
	efi_rts_work.status = EFI_ABORTED;
	complete(&efi_rts_work.efi_rts_comp);

	clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
	pr_info("Froze efi_rts_wq and disabled EFI Runtime Services\n");

	/*
	for (;;) {
		set_current_state(TASK_IDLE);
		schedule();
	}
}
