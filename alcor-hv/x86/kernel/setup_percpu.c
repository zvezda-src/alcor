#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/percpu.h>
#include <linux/kexec.h>
#include <linux/crash_dump.h>
#include <linux/smp.h>
#include <linux/topology.h>
#include <linux/pfn.h>
#include <asm/sections.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/setup.h>
#include <asm/mpspec.h>
#include <asm/apicdef.h>
#include <asm/highmem.h>
#include <asm/proto.h>
#include <asm/cpumask.h>
#include <asm/cpu.h>
#include <asm/stackprotector.h>

DEFINE_PER_CPU_READ_MOSTLY(int, cpu_number);
EXPORT_PER_CPU_SYMBOL(cpu_number);

#ifdef CONFIG_X86_64
#define BOOT_PERCPU_OFFSET ((unsigned long)__per_cpu_load)
#else
#define BOOT_PERCPU_OFFSET 0
#endif

DEFINE_PER_CPU_READ_MOSTLY(unsigned long, this_cpu_off) = BOOT_PERCPU_OFFSET;
EXPORT_PER_CPU_SYMBOL(this_cpu_off);

unsigned long __per_cpu_offset[NR_CPUS] __ro_after_init = {
	[0 ... NR_CPUS-1] = BOOT_PERCPU_OFFSET,
};
EXPORT_SYMBOL(__per_cpu_offset);

#ifdef CONFIG_X86_64
#define PERCPU_FIRST_CHUNK_RESERVE	PERCPU_MODULE_RESERVE
#else
#define PERCPU_FIRST_CHUNK_RESERVE	0
#endif

#ifdef CONFIG_X86_32
static bool __init pcpu_need_numa(void)
{
#ifdef CONFIG_NUMA
	pg_data_t *last = NULL;
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		int node = early_cpu_to_node(cpu);

		if (node_online(node) && NODE_DATA(node) &&
		    last && last != NODE_DATA(node))
			return true;

		last = NODE_DATA(node);
	}
#endif
	return false;
}
#endif

static int __init pcpu_cpu_distance(unsigned int from, unsigned int to)
{
#ifdef CONFIG_NUMA
	if (early_cpu_to_node(from) == early_cpu_to_node(to))
		return LOCAL_DISTANCE;
	else
		return REMOTE_DISTANCE;
#else
	return LOCAL_DISTANCE;
#endif
}

static int __init pcpu_cpu_to_node(int cpu)
{
	return early_cpu_to_node(cpu);
}

void __init pcpu_populate_pte(unsigned long addr)
{
	populate_extra_pte(addr);
}

static inline void setup_percpu_segment(int cpu)
{
#ifdef CONFIG_X86_32
	struct desc_struct d = GDT_ENTRY_INIT(0x8092, per_cpu_offset(cpu),
					      0xFFFFF);

	write_gdt_entry(get_cpu_gdt_rw(cpu), GDT_ENTRY_PERCPU, &d, DESCTYPE_S);
#endif
}

void __init setup_per_cpu_areas(void)
{
	unsigned int cpu;
	unsigned long delta;
	int rc;

	pr_info("NR_CPUS:%d nr_cpumask_bits:%d nr_cpu_ids:%u nr_node_ids:%u\n",
		NR_CPUS, nr_cpumask_bits, nr_cpu_ids, nr_node_ids);

	/*
#ifdef CONFIG_X86_32
	if (pcpu_chosen_fc == PCPU_FC_AUTO && pcpu_need_numa())
		pcpu_chosen_fc = PCPU_FC_PAGE;
#endif
	rc = -EINVAL;
	if (pcpu_chosen_fc != PCPU_FC_PAGE) {
		const size_t dyn_size = PERCPU_MODULE_RESERVE +
			PERCPU_DYNAMIC_RESERVE - PERCPU_FIRST_CHUNK_RESERVE;
		size_t atom_size;

		/*
#ifdef CONFIG_X86_64
		atom_size = PMD_SIZE;
#else
		atom_size = PAGE_SIZE;
#endif
		rc = pcpu_embed_first_chunk(PERCPU_FIRST_CHUNK_RESERVE,
					    dyn_size, atom_size,
					    pcpu_cpu_distance,
					    pcpu_cpu_to_node);
		if (rc < 0)
			pr_warn("%s allocator failed (%d), falling back to page size\n",
				pcpu_fc_names[pcpu_chosen_fc], rc);
	}
	if (rc < 0)
		rc = pcpu_page_first_chunk(PERCPU_FIRST_CHUNK_RESERVE,
					   pcpu_cpu_to_node);
	if (rc < 0)
		panic("cannot initialize percpu area (err=%d)", rc);

	/* alrighty, percpu areas up and running */
	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
	for_each_possible_cpu(cpu) {
		per_cpu_offset(cpu) = delta + pcpu_unit_offsets[cpu];
		per_cpu(this_cpu_off, cpu) = per_cpu_offset(cpu);
		per_cpu(cpu_number, cpu) = cpu;
		setup_percpu_segment(cpu);
		/*
#ifdef CONFIG_X86_LOCAL_APIC
		per_cpu(x86_cpu_to_apicid, cpu) =
			early_per_cpu_map(x86_cpu_to_apicid, cpu);
		per_cpu(x86_bios_cpu_apicid, cpu) =
			early_per_cpu_map(x86_bios_cpu_apicid, cpu);
		per_cpu(x86_cpu_to_acpiid, cpu) =
			early_per_cpu_map(x86_cpu_to_acpiid, cpu);
#endif
#ifdef CONFIG_X86_32
		per_cpu(x86_cpu_to_logical_apicid, cpu) =
			early_per_cpu_map(x86_cpu_to_logical_apicid, cpu);
#endif
#ifdef CONFIG_NUMA
		per_cpu(x86_cpu_to_node_map, cpu) =
			early_per_cpu_map(x86_cpu_to_node_map, cpu);
		/*
		set_cpu_numa_node(cpu, early_cpu_to_node(cpu));
#endif
		/*
		if (!cpu)
			switch_to_new_gdt(cpu);
	}

	/* indicate the early static arrays will soon be gone */
#ifdef CONFIG_X86_LOCAL_APIC
	early_per_cpu_ptr(x86_cpu_to_apicid) = NULL;
	early_per_cpu_ptr(x86_bios_cpu_apicid) = NULL;
	early_per_cpu_ptr(x86_cpu_to_acpiid) = NULL;
#endif
#ifdef CONFIG_X86_32
	early_per_cpu_ptr(x86_cpu_to_logical_apicid) = NULL;
#endif
#ifdef CONFIG_NUMA
	early_per_cpu_ptr(x86_cpu_to_node_map) = NULL;
#endif

	/* Setup node to cpumask map */
	setup_node_to_cpumask_map();

	/* Setup cpu initialized, callin, callout masks */
	setup_cpu_local_masks();

	/*
	sync_initial_page_table();
}
