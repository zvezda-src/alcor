#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/hardirq.h>

#include <asm/processor.h>
#include <asm/traps.h>
#include <asm/tlbflush.h>
#include <asm/mce.h>
#include <asm/msr.h>

#include "internal.h"

noinstr void winchip_machine_check(struct pt_regs *regs)
{
	instrumentation_begin();
	pr_emerg("CPU0: Machine Check Exception.\n");
	add_taint(TAINT_MACHINE_CHECK, LOCKDEP_NOW_UNRELIABLE);
	instrumentation_end();
}

void winchip_mcheck_init(struct cpuinfo_x86 *c)
{
	u32 lo, hi;

	rdmsr(MSR_IDT_FCR1, lo, hi);
	lo |= (1<<2);	/* Enable EIERRINT (int 18 MCE) */
	lo &= ~(1<<4);	/* Enable MCE */
	wrmsr(MSR_IDT_FCR1, lo, hi);

	cr4_set_bits(X86_CR4_MCE);

	pr_info("Winchip machine check reporting enabled on CPU#0.\n");
}
