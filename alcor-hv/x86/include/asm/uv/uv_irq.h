
#ifndef _ASM_X86_UV_UV_IRQ_H
#define _ASM_X86_UV_UV_IRQ_H

struct uv_IO_APIC_route_entry {
	__u64	vector		:  8,
		delivery_mode	:  3,
		dest_mode	:  1,
		delivery_status	:  1,
		polarity	:  1,
		__reserved_1	:  1,
		trigger		:  1,
		mask		:  1,
		__reserved_2	: 15,
		dest		: 32;
};

enum {
	UV_AFFINITY_ALL,
	UV_AFFINITY_NODE,
	UV_AFFINITY_CPU
};

extern int uv_irq_2_mmr_info(int, unsigned long *, int *);
extern int uv_setup_irq(char *, int, int, unsigned long, int);
extern void uv_teardown_irq(unsigned int);

#endif /* _ASM_X86_UV_UV_IRQ_H */
