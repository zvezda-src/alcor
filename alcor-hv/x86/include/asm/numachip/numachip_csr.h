
#ifndef _ASM_X86_NUMACHIP_NUMACHIP_CSR_H
#define _ASM_X86_NUMACHIP_NUMACHIP_CSR_H

#include <linux/smp.h>
#include <linux/io.h>

#define CSR_NODE_SHIFT		16
#define CSR_NODE_BITS(p)	(((unsigned long)(p)) << CSR_NODE_SHIFT)
#define CSR_NODE_MASK		0x0fff		/* 4K nodes */

#define CSR_OFFSET_MASK	0x7fffUL
#define CSR_G0_NODE_IDS (0x008 + (0 << 12))
#define CSR_G3_EXT_IRQ_GEN (0x030 + (3 << 12))

#define NUMACHIP_LCSR_BASE	0x3ffffe000000ULL
#define NUMACHIP_LCSR_LIM	0x3fffffffffffULL
#define NUMACHIP_LCSR_SIZE	(NUMACHIP_LCSR_LIM - NUMACHIP_LCSR_BASE + 1)
#define NUMACHIP_LAPIC_BITS	8

static inline void *lcsr_address(unsigned long offset)
{
	return __va(NUMACHIP_LCSR_BASE | (1UL << 15) |
		CSR_NODE_BITS(0xfff0) | (offset & CSR_OFFSET_MASK));
}

static inline unsigned int read_lcsr(unsigned long offset)
{
	return swab32(readl(lcsr_address(offset)));
}

static inline void write_lcsr(unsigned long offset, unsigned int val)
{
	writel(swab32(val), lcsr_address(offset));
}


#define NUMACHIP2_LCSR_BASE       0xf0000000UL
#define NUMACHIP2_LCSR_SIZE       0x1000000UL
#define NUMACHIP2_APIC_ICR        0x100000
#define NUMACHIP2_TIMER_DEADLINE  0x200000
#define NUMACHIP2_TIMER_INT       0x200008
#define NUMACHIP2_TIMER_NOW       0x200018
#define NUMACHIP2_TIMER_RESET     0x200020

static inline void __iomem *numachip2_lcsr_address(unsigned long offset)
{
	return (void __iomem *)__va(NUMACHIP2_LCSR_BASE |
		(offset & (NUMACHIP2_LCSR_SIZE - 1)));
}

static inline u32 numachip2_read32_lcsr(unsigned long offset)
{
	return readl(numachip2_lcsr_address(offset));
}

static inline u64 numachip2_read64_lcsr(unsigned long offset)
{
	return readq(numachip2_lcsr_address(offset));
}

static inline void numachip2_write32_lcsr(unsigned long offset, u32 val)
{
	writel(val, numachip2_lcsr_address(offset));
}

static inline void numachip2_write64_lcsr(unsigned long offset, u64 val)
{
	writeq(val, numachip2_lcsr_address(offset));
}

static inline unsigned int numachip2_timer(void)
{
	return (smp_processor_id() % 48) << 6;
}

#endif /* _ASM_X86_NUMACHIP_NUMACHIP_CSR_H */
