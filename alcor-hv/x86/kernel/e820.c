#include <linux/crash_dump.h>
#include <linux/memblock.h>
#include <linux/suspend.h>
#include <linux/acpi.h>
#include <linux/firmware-map.h>
#include <linux/sort.h>
#include <linux/memory_hotplug.h>

#include <asm/e820/api.h>
#include <asm/setup.h>

static struct e820_table e820_table_init		__initdata;
static struct e820_table e820_table_kexec_init		__initdata;
static struct e820_table e820_table_firmware_init	__initdata;

struct e820_table *e820_table __refdata			= &e820_table_init;
struct e820_table *e820_table_kexec __refdata		= &e820_table_kexec_init;
struct e820_table *e820_table_firmware __refdata	= &e820_table_firmware_init;

unsigned long pci_mem_start = 0xaeedbabe;
#ifdef CONFIG_PCI
EXPORT_SYMBOL(pci_mem_start);
#endif

static bool _e820__mapped_any(struct e820_table *table,
			      u64 start, u64 end, enum e820_type type)
{
	int i;

	for (i = 0; i < table->nr_entries; i++) {
		struct e820_entry *entry = &table->entries[i];

		if (type && entry->type != type)
			continue;
		if (entry->addr >= end || entry->addr + entry->size <= start)
			continue;
		return true;
	}
	return false;
}

bool e820__mapped_raw_any(u64 start, u64 end, enum e820_type type)
{
	return _e820__mapped_any(e820_table_firmware, start, end, type);
}
EXPORT_SYMBOL_GPL(e820__mapped_raw_any);

bool e820__mapped_any(u64 start, u64 end, enum e820_type type)
{
	return _e820__mapped_any(e820_table, start, end, type);
}
EXPORT_SYMBOL_GPL(e820__mapped_any);

static struct e820_entry *__e820__mapped_all(u64 start, u64 end,
					     enum e820_type type)
{
	int i;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (type && entry->type != type)
			continue;

		/* Is the region (part) in overlap with the current region? */
		if (entry->addr >= end || entry->addr + entry->size <= start)
			continue;

		/*
		if (entry->addr <= start)
			start = entry->addr + entry->size;

		/*
		if (start >= end)
			return entry;
	}

	return NULL;
}

bool __init e820__mapped_all(u64 start, u64 end, enum e820_type type)
{
	return __e820__mapped_all(start, end, type);
}

int e820__get_entry_type(u64 start, u64 end)
{
	struct e820_entry *entry = __e820__mapped_all(start, end, 0);

	return entry ? entry->type : -EINVAL;
}

static void __init __e820__range_add(struct e820_table *table, u64 start, u64 size, enum e820_type type)
{
	int x = table->nr_entries;

	if (x >= ARRAY_SIZE(table->entries)) {
		pr_err("too many entries; ignoring [mem %#010llx-%#010llx]\n",
		       start, start + size - 1);
		return;
	}

	table->entries[x].addr = start;
	table->entries[x].size = size;
	table->entries[x].type = type;
	table->nr_entries++;
}

void __init e820__range_add(u64 start, u64 size, enum e820_type type)
{
	__e820__range_add(e820_table, start, size, type);
}

static void __init e820_print_type(enum e820_type type)
{
	switch (type) {
	case E820_TYPE_RAM:		/* Fall through: */
	case E820_TYPE_RESERVED_KERN:	pr_cont("usable");			break;
	case E820_TYPE_RESERVED:	pr_cont("reserved");			break;
	case E820_TYPE_SOFT_RESERVED:	pr_cont("soft reserved");		break;
	case E820_TYPE_ACPI:		pr_cont("ACPI data");			break;
	case E820_TYPE_NVS:		pr_cont("ACPI NVS");			break;
	case E820_TYPE_UNUSABLE:	pr_cont("unusable");			break;
	case E820_TYPE_PMEM:		/* Fall through: */
	case E820_TYPE_PRAM:		pr_cont("persistent (type %u)", type);	break;
	default:			pr_cont("type %u", type);		break;
	}
}

void __init e820__print_table(char *who)
{
	int i;

	for (i = 0; i < e820_table->nr_entries; i++) {
		pr_info("%s: [mem %#018Lx-%#018Lx] ",
			who,
			e820_table->entries[i].addr,
			e820_table->entries[i].addr + e820_table->entries[i].size - 1);

		e820_print_type(e820_table->entries[i].type);
		pr_cont("\n");
	}
}

struct change_member {
	/* Pointer to the original entry: */
	struct e820_entry	*entry;
	/* Address for this change point: */
	unsigned long long	addr;
};

static struct change_member	change_point_list[2*E820_MAX_ENTRIES]	__initdata;
static struct change_member	*change_point[2*E820_MAX_ENTRIES]	__initdata;
static struct e820_entry	*overlap_list[E820_MAX_ENTRIES]		__initdata;
static struct e820_entry	new_entries[E820_MAX_ENTRIES]		__initdata;

static int __init cpcompare(const void *a, const void *b)
{
	struct change_member * const *app = a, * const *bpp = b;
	const struct change_member *ap = *app, *bp = *bpp;

	/*
	if (ap->addr != bp->addr)
		return ap->addr > bp->addr ? 1 : -1;

	return (ap->addr != ap->entry->addr) - (bp->addr != bp->entry->addr);
}

static bool e820_nomerge(enum e820_type type)
{
	/*
	if (type == E820_TYPE_PRAM)
		return true;
	if (type == E820_TYPE_SOFT_RESERVED)
		return true;
	return false;
}

int __init e820__update_table(struct e820_table *table)
{
	struct e820_entry *entries = table->entries;
	u32 max_nr_entries = ARRAY_SIZE(table->entries);
	enum e820_type current_type, last_type;
	unsigned long long last_addr;
	u32 new_nr_entries, overlap_entries;
	u32 i, chg_idx, chg_nr;

	/* If there's only one memory region, don't bother: */
	if (table->nr_entries < 2)
		return -1;

	BUG_ON(table->nr_entries > max_nr_entries);

	/* Bail out if we find any unreasonable addresses in the map: */
	for (i = 0; i < table->nr_entries; i++) {
		if (entries[i].addr + entries[i].size < entries[i].addr)
			return -1;
	}

	/* Create pointers for initial change-point information (for sorting): */
	for (i = 0; i < 2 * table->nr_entries; i++)
		change_point[i] = &change_point_list[i];

	/*
	chg_idx = 0;
	for (i = 0; i < table->nr_entries; i++)	{
		if (entries[i].size != 0) {
			change_point[chg_idx]->addr	= entries[i].addr;
			change_point[chg_idx++]->entry	= &entries[i];
			change_point[chg_idx]->addr	= entries[i].addr + entries[i].size;
			change_point[chg_idx++]->entry	= &entries[i];
		}
	}
	chg_nr = chg_idx;

	/* Sort change-point list by memory addresses (low -> high): */
	sort(change_point, chg_nr, sizeof(*change_point), cpcompare, NULL);

	/* Create a new memory map, removing overlaps: */
	overlap_entries = 0;	 /* Number of entries in the overlap table */
	new_nr_entries = 0;	 /* Index for creating new map entries */
	last_type = 0;		 /* Start with undefined memory type */
	last_addr = 0;		 /* Start with 0 as last starting address */

	/* Loop through change-points, determining effect on the new map: */
	for (chg_idx = 0; chg_idx < chg_nr; chg_idx++) {
		/* Keep track of all overlapping entries */
		if (change_point[chg_idx]->addr == change_point[chg_idx]->entry->addr) {
			/* Add map entry to overlap list (> 1 entry implies an overlap) */
			overlap_list[overlap_entries++] = change_point[chg_idx]->entry;
		} else {
			/* Remove entry from list (order independent, so swap with last): */
			for (i = 0; i < overlap_entries; i++) {
				if (overlap_list[i] == change_point[chg_idx]->entry)
					overlap_list[i] = overlap_list[overlap_entries-1];
			}
			overlap_entries--;
		}
		/*
		current_type = 0;
		for (i = 0; i < overlap_entries; i++) {
			if (overlap_list[i]->type > current_type)
				current_type = overlap_list[i]->type;
		}

		/* Continue building up new map based on this information: */
		if (current_type != last_type || e820_nomerge(current_type)) {
			if (last_type != 0)	 {
				new_entries[new_nr_entries].size = change_point[chg_idx]->addr - last_addr;
				/* Move forward only if the new size was non-zero: */
				if (new_entries[new_nr_entries].size != 0)
					/* No more space left for new entries? */
					if (++new_nr_entries >= max_nr_entries)
						break;
			}
			if (current_type != 0)	{
				new_entries[new_nr_entries].addr = change_point[chg_idx]->addr;
				new_entries[new_nr_entries].type = current_type;
				last_addr = change_point[chg_idx]->addr;
			}
			last_type = current_type;
		}
	}

	/* Copy the new entries into the original location: */
	memcpy(entries, new_entries, new_nr_entries*sizeof(*entries));
	table->nr_entries = new_nr_entries;

	return 0;
}

static int __init __append_e820_table(struct boot_e820_entry *entries, u32 nr_entries)
{
	struct boot_e820_entry *entry = entries;

	while (nr_entries) {
		u64 start = entry->addr;
		u64 size = entry->size;
		u64 end = start + size - 1;
		u32 type = entry->type;

		/* Ignore the entry on 64-bit overflow: */
		if (start > end && likely(size))
			return -1;

		e820__range_add(start, size, type);

		entry++;
		nr_entries--;
	}
	return 0;
}

static int __init append_e820_table(struct boot_e820_entry *entries, u32 nr_entries)
{
	/* Only one memory region (or negative)? Ignore it */
	if (nr_entries < 2)
		return -1;

	return __append_e820_table(entries, nr_entries);
}

static u64 __init
__e820__range_update(struct e820_table *table, u64 start, u64 size, enum e820_type old_type, enum e820_type new_type)
{
	u64 end;
	unsigned int i;
	u64 real_updated_size = 0;

	BUG_ON(old_type == new_type);

	if (size > (ULLONG_MAX - start))
		size = ULLONG_MAX - start;

	end = start + size;
	printk(KERN_DEBUG "e820: update [mem %#010Lx-%#010Lx] ", start, end - 1);
	e820_print_type(old_type);
	pr_cont(" ==> ");
	e820_print_type(new_type);
	pr_cont("\n");

	for (i = 0; i < table->nr_entries; i++) {
		struct e820_entry *entry = &table->entries[i];
		u64 final_start, final_end;
		u64 entry_end;

		if (entry->type != old_type)
			continue;

		entry_end = entry->addr + entry->size;

		/* Completely covered by new range? */
		if (entry->addr >= start && entry_end <= end) {
			entry->type = new_type;
			real_updated_size += entry->size;
			continue;
		}

		/* New range is completely covered? */
		if (entry->addr < start && entry_end > end) {
			__e820__range_add(table, start, size, new_type);
			__e820__range_add(table, end, entry_end - end, entry->type);
			entry->size = start - entry->addr;
			real_updated_size += size;
			continue;
		}

		/* Partially covered: */
		final_start = max(start, entry->addr);
		final_end = min(end, entry_end);
		if (final_start >= final_end)
			continue;

		__e820__range_add(table, final_start, final_end - final_start, new_type);

		real_updated_size += final_end - final_start;

		/*
		entry->size -= final_end - final_start;
		if (entry->addr < final_start)
			continue;

		entry->addr = final_end;
	}
	return real_updated_size;
}

u64 __init e820__range_update(u64 start, u64 size, enum e820_type old_type, enum e820_type new_type)
{
	return __e820__range_update(e820_table, start, size, old_type, new_type);
}

static u64 __init e820__range_update_kexec(u64 start, u64 size, enum e820_type old_type, enum e820_type  new_type)
{
	return __e820__range_update(e820_table_kexec, start, size, old_type, new_type);
}

u64 __init e820__range_remove(u64 start, u64 size, enum e820_type old_type, bool check_type)
{
	int i;
	u64 end;
	u64 real_removed_size = 0;

	if (size > (ULLONG_MAX - start))
		size = ULLONG_MAX - start;

	end = start + size;
	printk(KERN_DEBUG "e820: remove [mem %#010Lx-%#010Lx] ", start, end - 1);
	if (check_type)
		e820_print_type(old_type);
	pr_cont("\n");

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		u64 final_start, final_end;
		u64 entry_end;

		if (check_type && entry->type != old_type)
			continue;

		entry_end = entry->addr + entry->size;

		/* Completely covered? */
		if (entry->addr >= start && entry_end <= end) {
			real_removed_size += entry->size;
			memset(entry, 0, sizeof(*entry));
			continue;
		}

		/* Is the new range completely covered? */
		if (entry->addr < start && entry_end > end) {
			e820__range_add(end, entry_end - end, entry->type);
			entry->size = start - entry->addr;
			real_removed_size += size;
			continue;
		}

		/* Partially covered: */
		final_start = max(start, entry->addr);
		final_end = min(end, entry_end);
		if (final_start >= final_end)
			continue;

		real_removed_size += final_end - final_start;

		/*
		entry->size -= final_end - final_start;
		if (entry->addr < final_start)
			continue;

		entry->addr = final_end;
	}
	return real_removed_size;
}

void __init e820__update_table_print(void)
{
	if (e820__update_table(e820_table))
		return;

	pr_info("modified physical RAM map:\n");
	e820__print_table("modified");
}

static void __init e820__update_table_kexec(void)
{
	e820__update_table(e820_table_kexec);
}

#define MAX_GAP_END 0x100000000ull

static int __init e820_search_gap(unsigned long *gapstart, unsigned long *gapsize)
{
	unsigned long long last = MAX_GAP_END;
	int i = e820_table->nr_entries;
	int found = 0;

	while (--i >= 0) {
		unsigned long long start = e820_table->entries[i].addr;
		unsigned long long end = start + e820_table->entries[i].size;

		/*
		if (last > end) {
			unsigned long gap = last - end;

			if (gap >= *gapsize) {
				*gapsize = gap;
				*gapstart = end;
				found = 1;
			}
		}
		if (start < last)
			last = start;
	}
	return found;
}

__init void e820__setup_pci_gap(void)
{
	unsigned long gapstart, gapsize;
	int found;

	gapsize = 0x400000;
	found  = e820_search_gap(&gapstart, &gapsize);

	if (!found) {
#ifdef CONFIG_X86_64
		gapstart = (max_pfn << PAGE_SHIFT) + 1024*1024;
		pr_err("Cannot find an available gap in the 32-bit address range\n");
		pr_err("PCI devices with unassigned 32-bit BARs may not work!\n");
#else
		gapstart = 0x10000000;
#endif
	}

	/*
	pci_mem_start = gapstart;

	pr_info("[mem %#010lx-%#010lx] available for PCI devices\n",
		gapstart, gapstart + gapsize - 1);
}

__init void e820__reallocate_tables(void)
{
	struct e820_table *n;
	int size;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table->nr_entries;
	n = kmemdup(e820_table, size, GFP_KERNEL);
	BUG_ON(!n);
	e820_table = n;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table_kexec->nr_entries;
	n = kmemdup(e820_table_kexec, size, GFP_KERNEL);
	BUG_ON(!n);
	e820_table_kexec = n;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table_firmware->nr_entries;
	n = kmemdup(e820_table_firmware, size, GFP_KERNEL);
	BUG_ON(!n);
	e820_table_firmware = n;
}

void __init e820__memory_setup_extended(u64 phys_addr, u32 data_len)
{
	int entries;
	struct boot_e820_entry *extmap;
	struct setup_data *sdata;

	sdata = early_memremap(phys_addr, data_len);
	entries = sdata->len / sizeof(*extmap);
	extmap = (struct boot_e820_entry *)(sdata->data);

	__append_e820_table(extmap, entries);
	e820__update_table(e820_table);

	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	early_memunmap(sdata, data_len);
	pr_info("extended physical RAM map:\n");
	e820__print_table("extended");
}

void __init e820__register_nosave_regions(unsigned long limit_pfn)
{
	int i;
	unsigned long pfn = 0;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (pfn < PFN_UP(entry->addr))
			register_nosave_region(pfn, PFN_UP(entry->addr));

		pfn = PFN_DOWN(entry->addr + entry->size);

		if (entry->type != E820_TYPE_RAM && entry->type != E820_TYPE_RESERVED_KERN)
			register_nosave_region(PFN_UP(entry->addr), pfn);

		if (pfn >= limit_pfn)
			break;
	}
}

#ifdef CONFIG_ACPI
static int __init e820__register_nvs_regions(void)
{
	int i;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (entry->type == E820_TYPE_NVS)
			acpi_nvs_register(entry->addr, entry->size);
	}

	return 0;
}
core_initcall(e820__register_nvs_regions);
#endif

u64 __init e820__memblock_alloc_reserved(u64 size, u64 align)
{
	u64 addr;

	addr = memblock_phys_alloc(size, align);
	if (addr) {
		e820__range_update_kexec(addr, size, E820_TYPE_RAM, E820_TYPE_RESERVED);
		pr_info("update e820_table_kexec for e820__memblock_alloc_reserved()\n");
		e820__update_table_kexec();
	}

	return addr;
}

#ifdef CONFIG_X86_32
# ifdef CONFIG_X86_PAE
#  define MAX_ARCH_PFN		(1ULL<<(36-PAGE_SHIFT))
# else
#  define MAX_ARCH_PFN		(1ULL<<(32-PAGE_SHIFT))
# endif
#else /* CONFIG_X86_32 */
# define MAX_ARCH_PFN MAXMEM>>PAGE_SHIFT
#endif

static unsigned long __init e820_end_pfn(unsigned long limit_pfn, enum e820_type type)
{
	int i;
	unsigned long last_pfn = 0;
	unsigned long max_arch_pfn = MAX_ARCH_PFN;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		unsigned long start_pfn;
		unsigned long end_pfn;

		if (entry->type != type)
			continue;

		start_pfn = entry->addr >> PAGE_SHIFT;
		end_pfn = (entry->addr + entry->size) >> PAGE_SHIFT;

		if (start_pfn >= limit_pfn)
			continue;
		if (end_pfn > limit_pfn) {
			last_pfn = limit_pfn;
			break;
		}
		if (end_pfn > last_pfn)
			last_pfn = end_pfn;
	}

	if (last_pfn > max_arch_pfn)
		last_pfn = max_arch_pfn;

	pr_info("last_pfn = %#lx max_arch_pfn = %#lx\n",
		last_pfn, max_arch_pfn);
	return last_pfn;
}

unsigned long __init e820__end_of_ram_pfn(void)
{
	return e820_end_pfn(MAX_ARCH_PFN, E820_TYPE_RAM);
}

unsigned long __init e820__end_of_low_ram_pfn(void)
{
	return e820_end_pfn(1UL << (32 - PAGE_SHIFT), E820_TYPE_RAM);
}

static void __init early_panic(char *msg)
{
	early_printk(msg);
	panic(msg);
}

static int userdef __initdata;

static int __init parse_memopt(char *p)
{
	u64 mem_size;

	if (!p)
		return -EINVAL;

	if (!strcmp(p, "nopentium")) {
#ifdef CONFIG_X86_32
		setup_clear_cpu_cap(X86_FEATURE_PSE);
		return 0;
#else
		pr_warn("mem=nopentium ignored! (only supported on x86_32)\n");
		return -EINVAL;
#endif
	}

	userdef = 1;
	mem_size = memparse(p, &p);

	/* Don't remove all memory when getting "mem={invalid}" parameter: */
	if (mem_size == 0)
		return -EINVAL;

	e820__range_remove(mem_size, ULLONG_MAX - mem_size, E820_TYPE_RAM, 1);

#ifdef CONFIG_MEMORY_HOTPLUG
	max_mem_size = mem_size;
#endif

	return 0;
}
early_param("mem", parse_memopt);

static int __init parse_memmap_one(char *p)
{
	char *oldp;
	u64 start_at, mem_size;

	if (!p)
		return -EINVAL;

	if (!strncmp(p, "exactmap", 8)) {
		e820_table->nr_entries = 0;
		userdef = 1;
		return 0;
	}

	oldp = p;
	mem_size = memparse(p, &p);
	if (p == oldp)
		return -EINVAL;

	userdef = 1;
	if (*p == '@') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_RAM);
	} else if (*p == '#') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_ACPI);
	} else if (*p == '$') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_RESERVED);
	} else if (*p == '!') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_PRAM);
	} else if (*p == '%') {
		enum e820_type from = 0, to = 0;

		start_at = memparse(p + 1, &p);
		if (*p == '-')
			from = simple_strtoull(p + 1, &p, 0);
		if (*p == '+')
			to = simple_strtoull(p + 1, &p, 0);
		if (*p != '\0')
			return -EINVAL;
		if (from && to)
			e820__range_update(start_at, mem_size, from, to);
		else if (to)
			e820__range_add(start_at, mem_size, to);
		else if (from)
			e820__range_remove(start_at, mem_size, from, 1);
		else
			e820__range_remove(start_at, mem_size, 0, 0);
	} else {
		e820__range_remove(mem_size, ULLONG_MAX - mem_size, E820_TYPE_RAM, 1);
	}

	return *p == '\0' ? 0 : -EINVAL;
}

static int __init parse_memmap_opt(char *str)
{
	while (str) {
		char *k = strchr(str, ',');

		if (k)
			*k++ = 0;

		parse_memmap_one(str);
		str = k;
	}

	return 0;
}
early_param("memmap", parse_memmap_opt);

void __init e820__reserve_setup_data(void)
{
	struct setup_indirect *indirect;
	struct setup_data *data;
	u64 pa_data, pa_next;
	u32 len;

	pa_data = boot_params.hdr.setup_data;
	if (!pa_data)
		return;

	while (pa_data) {
		data = early_memremap(pa_data, sizeof(*data));
		if (!data) {
			pr_warn("e820: failed to memremap setup_data entry\n");
			return;
		}

		len = sizeof(*data);
		pa_next = data->next;

		e820__range_update(pa_data, sizeof(*data)+data->len, E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);

		/*
		if (data->type != SETUP_EFI && data->type != SETUP_IMA)
			e820__range_update_kexec(pa_data,
						 sizeof(*data) + data->len,
						 E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);

		if (data->type == SETUP_INDIRECT) {
			len += data->len;
			early_memunmap(data, sizeof(*data));
			data = early_memremap(pa_data, len);
			if (!data) {
				pr_warn("e820: failed to memremap indirect setup_data\n");
				return;
			}

			indirect = (struct setup_indirect *)data->data;

			if (indirect->type != SETUP_INDIRECT) {
				e820__range_update(indirect->addr, indirect->len,
						   E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);
				e820__range_update_kexec(indirect->addr, indirect->len,
							 E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);
			}
		}

		pa_data = pa_next;
		early_memunmap(data, len);
	}

	e820__update_table(e820_table);
	e820__update_table(e820_table_kexec);

	pr_info("extended physical RAM map:\n");
	e820__print_table("reserve setup_data");
}

void __init e820__finish_early_params(void)
{
	if (userdef) {
		if (e820__update_table(e820_table) < 0)
			early_panic("Invalid user supplied memory map");

		pr_info("user-defined physical RAM map:\n");
		e820__print_table("user");
	}
}

static const char *__init e820_type_to_string(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_RESERVED_KERN:	/* Fall-through: */
	case E820_TYPE_RAM:		return "System RAM";
	case E820_TYPE_ACPI:		return "ACPI Tables";
	case E820_TYPE_NVS:		return "ACPI Non-volatile Storage";
	case E820_TYPE_UNUSABLE:	return "Unusable memory";
	case E820_TYPE_PRAM:		return "Persistent Memory (legacy)";
	case E820_TYPE_PMEM:		return "Persistent Memory";
	case E820_TYPE_RESERVED:	return "Reserved";
	case E820_TYPE_SOFT_RESERVED:	return "Soft Reserved";
	default:			return "Unknown E820 type";
	}
}

static unsigned long __init e820_type_to_iomem_type(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_RESERVED_KERN:	/* Fall-through: */
	case E820_TYPE_RAM:		return IORESOURCE_SYSTEM_RAM;
	case E820_TYPE_ACPI:		/* Fall-through: */
	case E820_TYPE_NVS:		/* Fall-through: */
	case E820_TYPE_UNUSABLE:	/* Fall-through: */
	case E820_TYPE_PRAM:		/* Fall-through: */
	case E820_TYPE_PMEM:		/* Fall-through: */
	case E820_TYPE_RESERVED:	/* Fall-through: */
	case E820_TYPE_SOFT_RESERVED:	/* Fall-through: */
	default:			return IORESOURCE_MEM;
	}
}

static unsigned long __init e820_type_to_iores_desc(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_ACPI:		return IORES_DESC_ACPI_TABLES;
	case E820_TYPE_NVS:		return IORES_DESC_ACPI_NV_STORAGE;
	case E820_TYPE_PMEM:		return IORES_DESC_PERSISTENT_MEMORY;
	case E820_TYPE_PRAM:		return IORES_DESC_PERSISTENT_MEMORY_LEGACY;
	case E820_TYPE_RESERVED:	return IORES_DESC_RESERVED;
	case E820_TYPE_SOFT_RESERVED:	return IORES_DESC_SOFT_RESERVED;
	case E820_TYPE_RESERVED_KERN:	/* Fall-through: */
	case E820_TYPE_RAM:		/* Fall-through: */
	case E820_TYPE_UNUSABLE:	/* Fall-through: */
	default:			return IORES_DESC_NONE;
	}
}

static bool __init do_mark_busy(enum e820_type type, struct resource *res)
{
	/* this is the legacy bios/dos rom-shadow + mmio region */
	if (res->start < (1ULL<<20))
		return true;

	/*
	switch (type) {
	case E820_TYPE_RESERVED:
	case E820_TYPE_SOFT_RESERVED:
	case E820_TYPE_PRAM:
	case E820_TYPE_PMEM:
		return false;
	case E820_TYPE_RESERVED_KERN:
	case E820_TYPE_RAM:
	case E820_TYPE_ACPI:
	case E820_TYPE_NVS:
	case E820_TYPE_UNUSABLE:
	default:
		return true;
	}
}


static struct resource __initdata *e820_res;

void __init e820__reserve_resources(void)
{
	int i;
	struct resource *res;
	u64 end;

	res = memblock_alloc(sizeof(*res) * e820_table->nr_entries,
			     SMP_CACHE_BYTES);
	if (!res)
		panic("%s: Failed to allocate %zu bytes\n", __func__,
		      sizeof(*res) * e820_table->nr_entries);
	e820_res = res;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = e820_table->entries + i;

		end = entry->addr + entry->size - 1;
		if (end != (resource_size_t)end) {
			res++;
			continue;
		}
		res->start = entry->addr;
		res->end   = end;
		res->name  = e820_type_to_string(entry);
		res->flags = e820_type_to_iomem_type(entry);
		res->desc  = e820_type_to_iores_desc(entry);

		/*
		if (do_mark_busy(entry->type, res)) {
			res->flags |= IORESOURCE_BUSY;
			insert_resource(&iomem_resource, res);
		}
		res++;
	}

	/* Expose the bootloader-provided memory layout to the sysfs. */
	for (i = 0; i < e820_table_firmware->nr_entries; i++) {
		struct e820_entry *entry = e820_table_firmware->entries + i;

		firmware_map_add_early(entry->addr, entry->addr + entry->size, e820_type_to_string(entry));
	}
}

static unsigned long __init ram_alignment(resource_size_t pos)
{
	unsigned long mb = pos >> 20;

	/* To 64kB in the first megabyte */
	if (!mb)
		return 64*1024;

	/* To 1MB in the first 16MB */
	if (mb < 16)
		return 1024*1024;

	/* To 64MB for anything above that */
	return 64*1024*1024;
}

#define MAX_RESOURCE_SIZE ((resource_size_t)-1)

void __init e820__reserve_resources_late(void)
{
	int i;
	struct resource *res;

	res = e820_res;
	for (i = 0; i < e820_table->nr_entries; i++) {
		if (!res->parent && res->end)
			insert_resource_expand_to_fit(&iomem_resource, res);
		res++;
	}

	/*
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		u64 start, end;

		if (entry->type != E820_TYPE_RAM)
			continue;

		start = entry->addr + entry->size;
		end = round_up(start, ram_alignment(start)) - 1;
		if (end > MAX_RESOURCE_SIZE)
			end = MAX_RESOURCE_SIZE;
		if (start >= end)
			continue;

		printk(KERN_DEBUG "e820: reserve RAM buffer [mem %#010llx-%#010llx]\n", start, end);
		reserve_region_with_split(&iomem_resource, start, end, "RAM buffer");
	}
}

char *__init e820__memory_setup_default(void)
{
	char *who = "BIOS-e820";

	/*
	if (append_e820_table(boot_params.e820_table, boot_params.e820_entries) < 0) {
		u64 mem_size;

		/* Compare results from other methods and take the one that gives more RAM: */
		if (boot_params.alt_mem_k < boot_params.screen_info.ext_mem_k) {
			mem_size = boot_params.screen_info.ext_mem_k;
			who = "BIOS-88";
		} else {
			mem_size = boot_params.alt_mem_k;
			who = "BIOS-e801";
		}

		e820_table->nr_entries = 0;
		e820__range_add(0, LOWMEMSIZE(), E820_TYPE_RAM);
		e820__range_add(HIGH_MEMORY, mem_size << 10, E820_TYPE_RAM);
	}

	/* We just appended a lot of ranges, sanitize the table: */
	e820__update_table(e820_table);

	return who;
}

void __init e820__memory_setup(void)
{
	char *who;

	/* This is a firmware interface ABI - make sure we don't break it: */
	BUILD_BUG_ON(sizeof(struct boot_e820_entry) != 20);

	who = x86_init.resources.memory_setup();

	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	pr_info("BIOS-provided physical RAM map:\n");
	e820__print_table(who);
}

void __init e820__memblock_setup(void)
{
	int i;
	u64 end;

	/*
	memblock_allow_resize();

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		end = entry->addr + entry->size;
		if (end != (resource_size_t)end)
			continue;

		if (entry->type == E820_TYPE_SOFT_RESERVED)
			memblock_reserve(entry->addr, entry->size);

		if (entry->type != E820_TYPE_RAM && entry->type != E820_TYPE_RESERVED_KERN)
			continue;

		memblock_add(entry->addr, entry->size);
	}

	/* Throw away partial pages: */
	memblock_trim_memory(PAGE_SIZE);

	memblock_dump_all();
}
