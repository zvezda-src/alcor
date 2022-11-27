
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/kallsyms.h>
#include <linux/kcore.h>
#include <linux/pgtable.h>

#include <asm/cpu_entry_area.h>
#include <asm/fixmap.h>
#include <asm/desc.h>

static DEFINE_PER_CPU_PAGE_ALIGNED(struct entry_stack_page, entry_stack_storage);

#ifdef CONFIG_X86_64
static DEFINE_PER_CPU_PAGE_ALIGNED(struct exception_stacks, exception_stacks);
DEFINE_PER_CPU(struct cea_exception_stacks*, cea_exception_stacks);
#endif

#ifdef CONFIG_X86_32
DECLARE_PER_CPU_PAGE_ALIGNED(struct doublefault_stack, doublefault_stack);
#endif

noinstr struct cpu_entry_area *get_cpu_entry_area(int cpu)
{
	unsigned long va = CPU_ENTRY_AREA_PER_CPU + cpu * CPU_ENTRY_AREA_SIZE;
	BUILD_BUG_ON(sizeof(struct cpu_entry_area) % PAGE_SIZE != 0);

	return (struct cpu_entry_area *) va;
}
EXPORT_SYMBOL(get_cpu_entry_area);

void cea_set_pte(void *cea_vaddr, phys_addr_t pa, pgprot_t flags)
{
	unsigned long va = (unsigned long) cea_vaddr;
	pte_t pte = pfn_pte(pa >> PAGE_SHIFT, flags);

	/*
	if (boot_cpu_has(X86_FEATURE_PGE) &&
	    (pgprot_val(flags) & _PAGE_PRESENT))
		pte = pte_set_flags(pte, _PAGE_GLOBAL);

	set_pte_vaddr(va, pte);
}

static void __init
cea_map_percpu_pages(void *cea_vaddr, void *ptr, int pages, pgprot_t prot)
{
	for ( ; pages; pages--, cea_vaddr+= PAGE_SIZE, ptr += PAGE_SIZE)
		cea_set_pte(cea_vaddr, per_cpu_ptr_to_phys(ptr), prot);
}

static void __init percpu_setup_debug_store(unsigned int cpu)
{
#ifdef CONFIG_CPU_SUP_INTEL
	unsigned int npages;
	void *cea;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return;

	cea = &get_cpu_entry_area(cpu)->cpu_debug_store;
	npages = sizeof(struct debug_store) / PAGE_SIZE;
	BUILD_BUG_ON(sizeof(struct debug_store) % PAGE_SIZE != 0);
	cea_map_percpu_pages(cea, &per_cpu(cpu_debug_store, cpu), npages,
			     PAGE_KERNEL);

	cea = &get_cpu_entry_area(cpu)->cpu_debug_buffers;
	/*
	npages = sizeof(struct debug_store_buffers) / PAGE_SIZE;
	for (; npages; npages--, cea += PAGE_SIZE)
		cea_set_pte(cea, 0, PAGE_NONE);
#endif
}

#ifdef CONFIG_X86_64

#define cea_map_stack(name) do {					\
	npages = sizeof(estacks->name## _stack) / PAGE_SIZE;		\
	cea_map_percpu_pages(cea->estacks.name## _stack,		\
			estacks->name## _stack, npages, PAGE_KERNEL);	\
	} while (0)

static void __init percpu_setup_exception_stacks(unsigned int cpu)
{
	struct exception_stacks *estacks = per_cpu_ptr(&exception_stacks, cpu);
	struct cpu_entry_area *cea = get_cpu_entry_area(cpu);
	unsigned int npages;

	BUILD_BUG_ON(sizeof(exception_stacks) % PAGE_SIZE != 0);

	per_cpu(cea_exception_stacks, cpu) = &cea->estacks;

	/*
	cea_map_stack(DF);
	cea_map_stack(NMI);
	cea_map_stack(DB);
	cea_map_stack(MCE);

	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
		if (cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT)) {
			cea_map_stack(VC);
			cea_map_stack(VC2);
		}
	}
}
#else
static inline void percpu_setup_exception_stacks(unsigned int cpu)
{
	struct cpu_entry_area *cea = get_cpu_entry_area(cpu);

	cea_map_percpu_pages(&cea->doublefault_stack,
			     &per_cpu(doublefault_stack, cpu), 1, PAGE_KERNEL);
}
#endif

static void __init setup_cpu_entry_area(unsigned int cpu)
{
	struct cpu_entry_area *cea = get_cpu_entry_area(cpu);
#ifdef CONFIG_X86_64
	/* On 64-bit systems, we use a read-only fixmap GDT and TSS. */
	pgprot_t gdt_prot = PAGE_KERNEL_RO;
	pgprot_t tss_prot = PAGE_KERNEL_RO;
#else
	/*
	pgprot_t gdt_prot = boot_cpu_has(X86_FEATURE_XENPV) ?
		PAGE_KERNEL_RO : PAGE_KERNEL;
	pgprot_t tss_prot = PAGE_KERNEL;
#endif

	cea_set_pte(&cea->gdt, get_cpu_gdt_paddr(cpu), gdt_prot);

	cea_map_percpu_pages(&cea->entry_stack_page,
			     per_cpu_ptr(&entry_stack_storage, cpu), 1,
			     PAGE_KERNEL);

	/*
	BUILD_BUG_ON((offsetof(struct tss_struct, x86_tss) ^
		      offsetofend(struct tss_struct, x86_tss)) & PAGE_MASK);
	BUILD_BUG_ON(sizeof(struct tss_struct) % PAGE_SIZE != 0);
	/*
	BUILD_BUG_ON(offsetof(struct tss_struct, x86_tss) != 0);
	BUILD_BUG_ON(sizeof(struct x86_hw_tss) != 0x68);

	cea_map_percpu_pages(&cea->tss, &per_cpu(cpu_tss_rw, cpu),
			     sizeof(struct tss_struct) / PAGE_SIZE, tss_prot);

#ifdef CONFIG_X86_32
	per_cpu(cpu_entry_area, cpu) = cea;
#endif

	percpu_setup_exception_stacks(cpu);

	percpu_setup_debug_store(cpu);
}

static __init void setup_cpu_entry_area_ptes(void)
{
#ifdef CONFIG_X86_32
	unsigned long start, end;

	/* The +1 is for the readonly IDT: */
	BUILD_BUG_ON((CPU_ENTRY_AREA_PAGES+1)*PAGE_SIZE != CPU_ENTRY_AREA_MAP_SIZE);
	BUILD_BUG_ON(CPU_ENTRY_AREA_TOTAL_SIZE != CPU_ENTRY_AREA_MAP_SIZE);
	BUG_ON(CPU_ENTRY_AREA_BASE & ~PMD_MASK);

	start = CPU_ENTRY_AREA_BASE;
	end = start + CPU_ENTRY_AREA_MAP_SIZE;

	/* Careful here: start + PMD_SIZE might wrap around */
	for (; start < end && start >= CPU_ENTRY_AREA_BASE; start += PMD_SIZE)
		populate_extra_pte(start);
#endif
}

void __init setup_cpu_entry_areas(void)
{
	unsigned int cpu;

	setup_cpu_entry_area_ptes();

	for_each_possible_cpu(cpu)
		setup_cpu_entry_area(cpu);

	/*
	sync_initial_page_table();
}
