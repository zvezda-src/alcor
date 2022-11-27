
#include "misc.h"

enum efi_type efi_get_type(struct boot_params *bp)
{
	struct efi_info *ei;
	enum efi_type et;
	const char *sig;

	ei = &bp->efi_info;
	sig = (char *)&ei->efi_loader_signature;

	if (!strncmp(sig, EFI64_LOADER_SIGNATURE, 4)) {
		et = EFI_TYPE_64;
	} else if (!strncmp(sig, EFI32_LOADER_SIGNATURE, 4)) {
		et = EFI_TYPE_32;
	} else {
		debug_putstr("No EFI environment detected.\n");
		et = EFI_TYPE_NONE;
	}

#ifndef CONFIG_X86_64
	/*
	if (ei->efi_systab_hi || ei->efi_memmap_hi) {
		debug_putstr("EFI system table is located above 4GB and cannot be accessed.\n");
		et = EFI_TYPE_NONE;
	}
#endif

	return et;
}

unsigned long efi_get_system_table(struct boot_params *bp)
{
	unsigned long sys_tbl_pa;
	struct efi_info *ei;
	enum efi_type et;

	/* Get systab from boot params. */
	ei = &bp->efi_info;
#ifdef CONFIG_X86_64
	sys_tbl_pa = ei->efi_systab | ((__u64)ei->efi_systab_hi << 32);
#else
	sys_tbl_pa = ei->efi_systab;
#endif
	if (!sys_tbl_pa) {
		debug_putstr("EFI system table not found.");
		return 0;
	}

	return sys_tbl_pa;
}

static struct efi_setup_data *get_kexec_setup_data(struct boot_params *bp,
						   enum efi_type et)
{
#ifdef CONFIG_X86_64
	struct efi_setup_data *esd = NULL;
	struct setup_data *data;
	u64 pa_data;

	pa_data = bp->hdr.setup_data;
	while (pa_data) {
		data = (struct setup_data *)pa_data;
		if (data->type == SETUP_EFI) {
			esd = (struct efi_setup_data *)(pa_data + sizeof(struct setup_data));
			break;
		}

		pa_data = data->next;
	}

	/*
	if (esd && !esd->tables) {
		debug_putstr("kexec EFI environment missing valid configuration table.\n");
		return NULL;
	}

	return esd;
#endif
	return NULL;
}

int efi_get_conf_table(struct boot_params *bp, unsigned long *cfg_tbl_pa,
		       unsigned int *cfg_tbl_len)
{
	unsigned long sys_tbl_pa;
	enum efi_type et;
	int ret;

	if (!cfg_tbl_pa || !cfg_tbl_len)
		return -EINVAL;

	sys_tbl_pa = efi_get_system_table(bp);
	if (!sys_tbl_pa)
		return -EINVAL;

	/* Handle EFI bitness properly */
	et = efi_get_type(bp);
	if (et == EFI_TYPE_64) {
		efi_system_table_64_t *stbl = (efi_system_table_64_t *)sys_tbl_pa;
		struct efi_setup_data *esd;

		/* kexec provides an alternative EFI conf table, check for it. */
		esd = get_kexec_setup_data(bp, et);

		*cfg_tbl_pa = esd ? esd->tables : stbl->tables;
		*cfg_tbl_len = stbl->nr_tables;
	} else if (et == EFI_TYPE_32) {
		efi_system_table_32_t *stbl = (efi_system_table_32_t *)sys_tbl_pa;

		*cfg_tbl_pa = stbl->tables;
		*cfg_tbl_len = stbl->nr_tables;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int get_vendor_table(void *cfg_tbl, unsigned int idx,
			    unsigned long *vendor_tbl_pa,
			    efi_guid_t *vendor_tbl_guid,
			    enum efi_type et)
{
	if (et == EFI_TYPE_64) {
		efi_config_table_64_t *tbl_entry = (efi_config_table_64_t *)cfg_tbl + idx;

		if (!IS_ENABLED(CONFIG_X86_64) && tbl_entry->table >> 32) {
			debug_putstr("Error: EFI config table entry located above 4GB.\n");
			return -EINVAL;
		}

		*vendor_tbl_pa = tbl_entry->table;
		*vendor_tbl_guid = tbl_entry->guid;

	} else if (et == EFI_TYPE_32) {
		efi_config_table_32_t *tbl_entry = (efi_config_table_32_t *)cfg_tbl + idx;

		*vendor_tbl_pa = tbl_entry->table;
		*vendor_tbl_guid = tbl_entry->guid;
	} else {
		return -EINVAL;
	}

	return 0;
}

unsigned long efi_find_vendor_table(struct boot_params *bp,
				    unsigned long cfg_tbl_pa,
				    unsigned int cfg_tbl_len,
				    efi_guid_t guid)
{
	enum efi_type et;
	unsigned int i;

	et = efi_get_type(bp);
	if (et == EFI_TYPE_NONE)
		return 0;

	for (i = 0; i < cfg_tbl_len; i++) {
		unsigned long vendor_tbl_pa;
		efi_guid_t vendor_tbl_guid;
		int ret;

		ret = get_vendor_table((void *)cfg_tbl_pa, i,
				       &vendor_tbl_pa,
				       &vendor_tbl_guid, et);
		if (ret)
			return 0;

		if (!efi_guidcmp(guid, vendor_tbl_guid))
			return vendor_tbl_pa;
	}

	return 0;
}
