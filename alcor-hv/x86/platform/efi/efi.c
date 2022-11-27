
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/efi.h>
#include <linux/efi-bgrt.h>
#include <linux/export.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/io.h>
#include <linux/reboot.h>
#include <linux/bcd.h>

#include <asm/setup.h>
#include <asm/efi.h>
#include <asm/e820/api.h>
#include <asm/time.h>
#include <asm/tlbflush.h>
#include <asm/x86_init.h>
#include <asm/uv/uv.h>

static unsigned long efi_systab_phys __initdata;
static unsigned long prop_phys = EFI_INVALID_TABLE_ADDR;
static unsigned long uga_phys = EFI_INVALID_TABLE_ADDR;
static unsigned long efi_runtime, efi_nr_tables;

unsigned long efi_fw_vendor, efi_config_table;

static const efi_config_table_type_t arch_tables[] __initconst = {
	{EFI_PROPERTIES_TABLE_GUID,	&prop_phys,		"PROP"		},
	{UGA_IO_PROTOCOL_GUID,		&uga_phys,		"UGA"		},
#ifdef CONFIG_X86_UV
	{UV_SYSTEM_TABLE_GUID,		&uv_systab_phys,	"UVsystab"	},
#endif
	{},
};

static const unsigned long * const efi_tables[] = {
	&efi.acpi,
	&efi.acpi20,
	&efi.smbios,
	&efi.smbios3,
	&uga_phys,
#ifdef CONFIG_X86_UV
	&uv_systab_phys,
#endif
	&efi_fw_vendor,
	&efi_runtime,
	&efi_config_table,
	&efi.esrt,
	&prop_phys,
	&efi_mem_attr_table,
#ifdef CONFIG_EFI_RCI2_TABLE
	&rci2_table_phys,
#endif
	&efi.tpm_log,
	&efi.tpm_final_log,
	&efi_rng_seed,
#ifdef CONFIG_LOAD_UEFI_KEYS
	&efi.mokvar_table,
#endif
#ifdef CONFIG_EFI_COCO_SECRET
	&efi.coco_secret,
#endif
};

u64 efi_setup;		/* efi setup_data physical address */

static int add_efi_memmap __initdata;
static int __init setup_add_efi_memmap(char *arg)
{
	add_efi_memmap = 1;
	return 0;
}
early_param("add_efi_memmap", setup_add_efi_memmap);


static void __init do_add_efi_memmap(void)
{
	efi_memory_desc_t *md;

	if (!efi_enabled(EFI_MEMMAP))
		return;

	for_each_efi_memory_desc(md) {
		unsigned long long start = md->phys_addr;
		unsigned long long size = md->num_pages << EFI_PAGE_SHIFT;
		int e820_type;

		switch (md->type) {
		case EFI_LOADER_CODE:
		case EFI_LOADER_DATA:
		case EFI_BOOT_SERVICES_CODE:
		case EFI_BOOT_SERVICES_DATA:
		case EFI_CONVENTIONAL_MEMORY:
			if (efi_soft_reserve_enabled()
			    && (md->attribute & EFI_MEMORY_SP))
				e820_type = E820_TYPE_SOFT_RESERVED;
			else if (md->attribute & EFI_MEMORY_WB)
				e820_type = E820_TYPE_RAM;
			else
				e820_type = E820_TYPE_RESERVED;
			break;
		case EFI_ACPI_RECLAIM_MEMORY:
			e820_type = E820_TYPE_ACPI;
			break;
		case EFI_ACPI_MEMORY_NVS:
			e820_type = E820_TYPE_NVS;
			break;
		case EFI_UNUSABLE_MEMORY:
			e820_type = E820_TYPE_UNUSABLE;
			break;
		case EFI_PERSISTENT_MEMORY:
			e820_type = E820_TYPE_PMEM;
			break;
		default:
			/*
			e820_type = E820_TYPE_RESERVED;
			break;
		}

		e820__range_add(start, size, e820_type);
	}
	e820__update_table(e820_table);
}

static bool do_efi_soft_reserve(void)
{
	efi_memory_desc_t *md;

	if (!efi_enabled(EFI_MEMMAP))
		return false;

	if (!efi_soft_reserve_enabled())
		return false;

	for_each_efi_memory_desc(md)
		if (md->type == EFI_CONVENTIONAL_MEMORY &&
		    (md->attribute & EFI_MEMORY_SP))
			return true;
	return false;
}

int __init efi_memblock_x86_reserve_range(void)
{
	struct efi_info *e = &boot_params.efi_info;
	struct efi_memory_map_data data;
	phys_addr_t pmap;
	int rv;

	if (efi_enabled(EFI_PARAVIRT))
		return 0;

	/* Can't handle firmware tables above 4GB on i386 */
	if (IS_ENABLED(CONFIG_X86_32) && e->efi_memmap_hi > 0) {
		pr_err("Memory map is above 4GB, disabling EFI.\n");
		return -EINVAL;
	}
	pmap = (phys_addr_t)(e->efi_memmap | ((u64)e->efi_memmap_hi << 32));

	data.phys_map		= pmap;
	data.size 		= e->efi_memmap_size;
	data.desc_size		= e->efi_memdesc_size;
	data.desc_version	= e->efi_memdesc_version;

	rv = efi_memmap_init_early(&data);
	if (rv)
		return rv;

	if (add_efi_memmap || do_efi_soft_reserve())
		do_add_efi_memmap();

	efi_fake_memmap_early();

	WARN(efi.memmap.desc_version != 1,
	     "Unexpected EFI_MEMORY_DESCRIPTOR version %ld",
	     efi.memmap.desc_version);

	memblock_reserve(pmap, efi.memmap.nr_map * efi.memmap.desc_size);
	set_bit(EFI_PRESERVE_BS_REGIONS, &efi.flags);

	return 0;
}

#define OVERFLOW_ADDR_SHIFT	(64 - EFI_PAGE_SHIFT)
#define OVERFLOW_ADDR_MASK	(U64_MAX << OVERFLOW_ADDR_SHIFT)
#define U64_HIGH_BIT		(~(U64_MAX >> 1))

static bool __init efi_memmap_entry_valid(const efi_memory_desc_t *md, int i)
{
	u64 end = (md->num_pages << EFI_PAGE_SHIFT) + md->phys_addr - 1;
	u64 end_hi = 0;
	char buf[64];

	if (md->num_pages == 0) {
		end = 0;
	} else if (md->num_pages > EFI_PAGES_MAX ||
		   EFI_PAGES_MAX - md->num_pages <
		   (md->phys_addr >> EFI_PAGE_SHIFT)) {
		end_hi = (md->num_pages & OVERFLOW_ADDR_MASK)
			>> OVERFLOW_ADDR_SHIFT;

		if ((md->phys_addr & U64_HIGH_BIT) && !(end & U64_HIGH_BIT))
			end_hi += 1;
	} else {
		return true;
	}

	pr_warn_once(FW_BUG "Invalid EFI memory map entries:\n");

	if (end_hi) {
		pr_warn("mem%02u: %s range=[0x%016llx-0x%llx%016llx] (invalid)\n",
			i, efi_md_typeattr_format(buf, sizeof(buf), md),
			md->phys_addr, end_hi, end);
	} else {
		pr_warn("mem%02u: %s range=[0x%016llx-0x%016llx] (invalid)\n",
			i, efi_md_typeattr_format(buf, sizeof(buf), md),
			md->phys_addr, end);
	}
	return false;
}

static void __init efi_clean_memmap(void)
{
	efi_memory_desc_t *out = efi.memmap.map;
	const efi_memory_desc_t *in = out;
	const efi_memory_desc_t *end = efi.memmap.map_end;
	int i, n_removal;

	for (i = n_removal = 0; in < end; i++) {
		if (efi_memmap_entry_valid(in, i)) {
			if (out != in)
				memcpy(out, in, efi.memmap.desc_size);
			out = (void *)out + efi.memmap.desc_size;
		} else {
			n_removal++;
		}
		in = (void *)in + efi.memmap.desc_size;
	}

	if (n_removal > 0) {
		struct efi_memory_map_data data = {
			.phys_map	= efi.memmap.phys_map,
			.desc_version	= efi.memmap.desc_version,
			.desc_size	= efi.memmap.desc_size,
			.size		= efi.memmap.desc_size * (efi.memmap.nr_map - n_removal),
			.flags		= 0,
		};

		pr_warn("Removing %d invalid memory map entries.\n", n_removal);
		efi_memmap_install(&data);
	}
}

void __init efi_print_memmap(void)
{
	efi_memory_desc_t *md;
	int i = 0;

	for_each_efi_memory_desc(md) {
		char buf[64];

		pr_info("mem%02u: %s range=[0x%016llx-0x%016llx] (%lluMB)\n",
			i++, efi_md_typeattr_format(buf, sizeof(buf), md),
			md->phys_addr,
			md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT) - 1,
			(md->num_pages >> (20 - EFI_PAGE_SHIFT)));
	}
}

static int __init efi_systab_init(unsigned long phys)
{
	int size = efi_enabled(EFI_64BIT) ? sizeof(efi_system_table_64_t)
					  : sizeof(efi_system_table_32_t);
	const efi_table_hdr_t *hdr;
	bool over4g = false;
	void *p;
	int ret;

	hdr = p = early_memremap_ro(phys, size);
	if (p == NULL) {
		pr_err("Couldn't map the system table!\n");
		return -ENOMEM;
	}

	ret = efi_systab_check_header(hdr, 1);
	if (ret) {
		early_memunmap(p, size);
		return ret;
	}

	if (efi_enabled(EFI_64BIT)) {
		const efi_system_table_64_t *systab64 = p;

		efi_runtime	= systab64->runtime;
		over4g		= systab64->runtime > U32_MAX;

		if (efi_setup) {
			struct efi_setup_data *data;

			data = early_memremap_ro(efi_setup, sizeof(*data));
			if (!data) {
				early_memunmap(p, size);
				return -ENOMEM;
			}

			efi_fw_vendor		= (unsigned long)data->fw_vendor;
			efi_config_table	= (unsigned long)data->tables;

			over4g |= data->fw_vendor	> U32_MAX ||
				  data->tables		> U32_MAX;

			early_memunmap(data, sizeof(*data));
		} else {
			efi_fw_vendor		= systab64->fw_vendor;
			efi_config_table	= systab64->tables;

			over4g |= systab64->fw_vendor	> U32_MAX ||
				  systab64->tables	> U32_MAX;
		}
		efi_nr_tables = systab64->nr_tables;
	} else {
		const efi_system_table_32_t *systab32 = p;

		efi_fw_vendor		= systab32->fw_vendor;
		efi_runtime		= systab32->runtime;
		efi_config_table	= systab32->tables;
		efi_nr_tables		= systab32->nr_tables;
	}

	efi.runtime_version = hdr->revision;

	efi_systab_report_header(hdr, efi_fw_vendor);
	early_memunmap(p, size);

	if (IS_ENABLED(CONFIG_X86_32) && over4g) {
		pr_err("EFI data located above 4GB, disabling EFI.\n");
		return -EINVAL;
	}

	return 0;
}

static int __init efi_config_init(const efi_config_table_type_t *arch_tables)
{
	void *config_tables;
	int sz, ret;

	if (efi_nr_tables == 0)
		return 0;

	if (efi_enabled(EFI_64BIT))
		sz = sizeof(efi_config_table_64_t);
	else
		sz = sizeof(efi_config_table_32_t);

	/*
	config_tables = early_memremap(efi_config_table, efi_nr_tables * sz);
	if (config_tables == NULL) {
		pr_err("Could not map Configuration table!\n");
		return -ENOMEM;
	}

	ret = efi_config_parse_tables(config_tables, efi_nr_tables,
				      arch_tables);

	early_memunmap(config_tables, efi_nr_tables * sz);
	return ret;
}

void __init efi_init(void)
{
	if (IS_ENABLED(CONFIG_X86_32) &&
	    (boot_params.efi_info.efi_systab_hi ||
	     boot_params.efi_info.efi_memmap_hi)) {
		pr_info("Table located above 4GB, disabling EFI.\n");
		return;
	}

	efi_systab_phys = boot_params.efi_info.efi_systab |
			  ((__u64)boot_params.efi_info.efi_systab_hi << 32);

	if (efi_systab_init(efi_systab_phys))
		return;

	if (efi_reuse_config(efi_config_table, efi_nr_tables))
		return;

	if (efi_config_init(arch_tables))
		return;

	/*

	if (!efi_runtime_supported())
		pr_err("No EFI runtime due to 32/64-bit mismatch with kernel\n");

	if (!efi_runtime_supported() || efi_runtime_disabled()) {
		efi_memmap_unmap();
		return;
	}

	/* Parse the EFI Properties table if it exists */
	if (prop_phys != EFI_INVALID_TABLE_ADDR) {
		efi_properties_table_t *tbl;

		tbl = early_memremap_ro(prop_phys, sizeof(*tbl));
		if (tbl == NULL) {
			pr_err("Could not map Properties table!\n");
		} else {
			if (tbl->memory_protection_attribute &
			    EFI_PROPERTIES_RUNTIME_MEMORY_PROTECTION_NON_EXECUTABLE_PE_DATA)
				set_bit(EFI_NX_PE_DATA, &efi.flags);

			early_memunmap(tbl, sizeof(*tbl));
		}
	}

	set_bit(EFI_RUNTIME_SERVICES, &efi.flags);
	efi_clean_memmap();

	if (efi_enabled(EFI_DBG))
		efi_print_memmap();
}

static void __init efi_merge_regions(void)
{
	efi_memory_desc_t *md, *prev_md = NULL;

	for_each_efi_memory_desc(md) {
		u64 prev_size;

		if (!prev_md) {
			prev_md = md;
			continue;
		}

		if (prev_md->type != md->type ||
		    prev_md->attribute != md->attribute) {
			prev_md = md;
			continue;
		}

		prev_size = prev_md->num_pages << EFI_PAGE_SHIFT;

		if (md->phys_addr == (prev_md->phys_addr + prev_size)) {
			prev_md->num_pages += md->num_pages;
			md->type = EFI_RESERVED_TYPE;
			md->attribute = 0;
			continue;
		}
		prev_md = md;
	}
}

static void *realloc_pages(void *old_memmap, int old_shift)
{
	void *ret;

	ret = (void *)__get_free_pages(GFP_KERNEL, old_shift + 1);
	if (!ret)
		goto out;

	/*
	if (!old_memmap)
		return ret;

	memcpy(ret, old_memmap, PAGE_SIZE << old_shift);

out:
	free_pages((unsigned long)old_memmap, old_shift);
	return ret;
}

static inline void *efi_map_next_entry_reverse(void *entry)
{
	/* Initial call */
	if (!entry)
		return efi.memmap.map_end - efi.memmap.desc_size;

	entry -= efi.memmap.desc_size;
	if (entry < efi.memmap.map)
		return NULL;

	return entry;
}

static void *efi_map_next_entry(void *entry)
{
	if (efi_enabled(EFI_64BIT)) {
		/*
		return efi_map_next_entry_reverse(entry);
	}

	/* Initial call */
	if (!entry)
		return efi.memmap.map;

	entry += efi.memmap.desc_size;
	if (entry >= efi.memmap.map_end)
		return NULL;

	return entry;
}

static bool should_map_region(efi_memory_desc_t *md)
{
	/*
	if (md->attribute & EFI_MEMORY_RUNTIME)
		return true;

	/*
	if (IS_ENABLED(CONFIG_X86_32))
		return false;

	/*
	if (md->type == EFI_CONVENTIONAL_MEMORY &&
	    efi_soft_reserve_enabled() &&
	    (md->attribute & EFI_MEMORY_SP))
		return false;

	/*
	if (efi_is_mixed()) {
		if (md->type == EFI_CONVENTIONAL_MEMORY ||
		    md->type == EFI_LOADER_DATA ||
		    md->type == EFI_LOADER_CODE)
			return true;
	}

	/*
	if (md->type == EFI_BOOT_SERVICES_CODE ||
	    md->type == EFI_BOOT_SERVICES_DATA)
		return true;

	return false;
}

static void * __init efi_map_regions(int *count, int *pg_shift)
{
	void *p, *new_memmap = NULL;
	unsigned long left = 0;
	unsigned long desc_size;
	efi_memory_desc_t *md;

	desc_size = efi.memmap.desc_size;

	p = NULL;
	while ((p = efi_map_next_entry(p))) {
		md = p;

		if (!should_map_region(md))
			continue;

		efi_map_region(md);

		if (left < desc_size) {
			new_memmap = realloc_pages(new_memmap, *pg_shift);
			if (!new_memmap)
				return NULL;

			left += PAGE_SIZE << *pg_shift;
			(*pg_shift)++;
		}

		memcpy(new_memmap + (*count * desc_size), md, desc_size);

		left -= desc_size;
		(*count)++;
	}

	return new_memmap;
}

static void __init kexec_enter_virtual_mode(void)
{
#ifdef CONFIG_KEXEC_CORE
	efi_memory_desc_t *md;
	unsigned int num_pages;

	/*
	if (efi_is_mixed()) {
		efi_memmap_unmap();
		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
		return;
	}

	if (efi_alloc_page_tables()) {
		pr_err("Failed to allocate EFI page tables\n");
		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
		return;
	}

	/*
	for_each_efi_memory_desc(md)
		efi_map_region_fixed(md); /* FIXME: add error handling */

	/*
	efi_memmap_unmap();

	if (efi_memmap_init_late(efi.memmap.phys_map,
				 efi.memmap.desc_size * efi.memmap.nr_map)) {
		pr_err("Failed to remap late EFI memory map\n");
		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
		return;
	}

	num_pages = ALIGN(efi.memmap.nr_map * efi.memmap.desc_size, PAGE_SIZE);
	num_pages >>= PAGE_SHIFT;

	if (efi_setup_page_tables(efi.memmap.phys_map, num_pages)) {
		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
		return;
	}

	efi_sync_low_kernel_mappings();
	efi_native_runtime_setup();
#endif
}

static void __init __efi_enter_virtual_mode(void)
{
	int count = 0, pg_shift = 0;
	void *new_memmap = NULL;
	efi_status_t status;
	unsigned long pa;

	if (efi_alloc_page_tables()) {
		pr_err("Failed to allocate EFI page tables\n");
		goto err;
	}

	efi_merge_regions();
	new_memmap = efi_map_regions(&count, &pg_shift);
	if (!new_memmap) {
		pr_err("Error reallocating memory, EFI runtime non-functional!\n");
		goto err;
	}

	pa = __pa(new_memmap);

	/*
	efi_memmap_unmap();

	if (efi_memmap_init_late(pa, efi.memmap.desc_size * count)) {
		pr_err("Failed to remap late EFI memory map\n");
		goto err;
	}

	if (efi_enabled(EFI_DBG)) {
		pr_info("EFI runtime memory map:\n");
		efi_print_memmap();
	}

	if (efi_setup_page_tables(pa, 1 << pg_shift))
		goto err;

	efi_sync_low_kernel_mappings();

	status = efi_set_virtual_address_map(efi.memmap.desc_size * count,
					     efi.memmap.desc_size,
					     efi.memmap.desc_version,
					     (efi_memory_desc_t *)pa,
					     efi_systab_phys);
	if (status != EFI_SUCCESS) {
		pr_err("Unable to switch EFI into virtual mode (status=%lx)!\n",
		       status);
		goto err;
	}

	efi_check_for_embedded_firmwares();
	efi_free_boot_services();

	if (!efi_is_mixed())
		efi_native_runtime_setup();
	else
		efi_thunk_runtime_setup();

	/*
	efi_runtime_update_mappings();

	/* clean DUMMY object */
	efi_delete_dummy_variable();
	return;

err:
	clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
}

void __init efi_enter_virtual_mode(void)
{
	if (efi_enabled(EFI_PARAVIRT))
		return;

	efi.runtime = (efi_runtime_services_t *)efi_runtime;

	if (efi_setup)
		kexec_enter_virtual_mode();
	else
		__efi_enter_virtual_mode();

	efi_dump_pagetable();
}

bool efi_is_table_address(unsigned long phys_addr)
{
	unsigned int i;

	if (phys_addr == EFI_INVALID_TABLE_ADDR)
		return false;

	for (i = 0; i < ARRAY_SIZE(efi_tables); i++)
		if (*(efi_tables[i]) == phys_addr)
			return true;

	return false;
}

char *efi_systab_show_arch(char *str)
{
	if (uga_phys != EFI_INVALID_TABLE_ADDR)
		str += sprintf(str, "UGA=0x%lx\n", uga_phys);
	return str;
}

#define EFI_FIELD(var) efi_ ## var

#define EFI_ATTR_SHOW(name) \
static ssize_t name##_show(struct kobject *kobj, \
				struct kobj_attribute *attr, char *buf) \
{ \
	return sprintf(buf, "0x%lx\n", EFI_FIELD(name)); \
}

EFI_ATTR_SHOW(fw_vendor);
EFI_ATTR_SHOW(runtime);
EFI_ATTR_SHOW(config_table);

struct kobj_attribute efi_attr_fw_vendor = __ATTR_RO(fw_vendor);
struct kobj_attribute efi_attr_runtime = __ATTR_RO(runtime);
struct kobj_attribute efi_attr_config_table = __ATTR_RO(config_table);

umode_t efi_attr_is_visible(struct kobject *kobj, struct attribute *attr, int n)
{
	if (attr == &efi_attr_fw_vendor.attr) {
		if (efi_enabled(EFI_PARAVIRT) ||
				efi_fw_vendor == EFI_INVALID_TABLE_ADDR)
			return 0;
	} else if (attr == &efi_attr_runtime.attr) {
		if (efi_runtime == EFI_INVALID_TABLE_ADDR)
			return 0;
	} else if (attr == &efi_attr_config_table.attr) {
		if (efi_config_table == EFI_INVALID_TABLE_ADDR)
			return 0;
	}
	return attr->mode;
}
