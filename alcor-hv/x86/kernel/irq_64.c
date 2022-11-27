
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/smp.h>
#include <linux/sched/task_stack.h>

#include <asm/cpu_entry_area.h>
#include <asm/softirq_stack.h>
#include <asm/irq_stack.h>
#include <asm/io_apic.h>
#include <asm/apic.h>

DEFINE_PER_CPU_PAGE_ALIGNED(struct irq_stack, irq_stack_backing_store) __visible;
DECLARE_INIT_PER_CPU(irq_stack_backing_store);

#ifdef CONFIG_VMAP_STACK
static int map_irq_stack(unsigned int cpu)
{
	char *stack = (char *)per_cpu_ptr(&irq_stack_backing_store, cpu);
	struct page *pages[IRQ_STACK_SIZE / PAGE_SIZE];
	void *va;
	int i;

	for (i = 0; i < IRQ_STACK_SIZE / PAGE_SIZE; i++) {
		phys_addr_t pa = per_cpu_ptr_to_phys(stack + (i << PAGE_SHIFT));

		pages[i] = pfn_to_page(pa >> PAGE_SHIFT);
	}

	va = vmap(pages, IRQ_STACK_SIZE / PAGE_SIZE, VM_MAP, PAGE_KERNEL);
	if (!va)
		return -ENOMEM;

	/* Store actual TOS to avoid adjustment in the hotpath */
	per_cpu(hardirq_stack_ptr, cpu) = va + IRQ_STACK_SIZE - 8;
	return 0;
}
#else
static int map_irq_stack(unsigned int cpu)
{
	void *va = per_cpu_ptr(&irq_stack_backing_store, cpu);

	/* Store actual TOS to avoid adjustment in the hotpath */
	per_cpu(hardirq_stack_ptr, cpu) = va + IRQ_STACK_SIZE - 8;
	return 0;
}
#endif

int irq_init_percpu_irqstack(unsigned int cpu)
{
	if (per_cpu(hardirq_stack_ptr, cpu))
		return 0;
	return map_irq_stack(cpu);
}
