
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/timex.h>
#include <linux/preempt.h>
#include <linux/delay.h>

#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/timer.h>
#include <asm/mwait.h>

#ifdef CONFIG_SMP
# include <asm/smp.h>
#endif

static void delay_loop(u64 __loops);

static void (*delay_fn)(u64) __ro_after_init = delay_loop;
static void (*delay_halt_fn)(u64 start, u64 cycles) __ro_after_init;

static void delay_loop(u64 __loops)
{
	unsigned long loops = (unsigned long)__loops;

	asm volatile(
		"	test %0,%0	\n"
		"	jz 3f		\n"
		"	jmp 1f		\n"

		".align 16		\n"
		"1:	jmp 2f		\n"

		".align 16		\n"
		"2:	dec %0		\n"
		"	jnz 2b		\n"
		"3:	dec %0		\n"

		: "+a" (loops)
		:
	);
}

static void delay_tsc(u64 cycles)
{
	u64 bclock, now;
	int cpu;

	preempt_disable();
	cpu = smp_processor_id();
	bclock = rdtsc_ordered();
	for (;;) {
		now = rdtsc_ordered();
		if ((now - bclock) >= cycles)
			break;

		/* Allow RT tasks to run */
		preempt_enable();
		rep_nop();
		preempt_disable();

		/*
		if (unlikely(cpu != smp_processor_id())) {
			cycles -= (now - bclock);
			cpu = smp_processor_id();
			bclock = rdtsc_ordered();
		}
	}
	preempt_enable();
}

static void delay_halt_tpause(u64 start, u64 cycles)
{
	u64 until = start + cycles;
	u32 eax, edx;

	eax = lower_32_bits(until);
	edx = upper_32_bits(until);

	/*
	__tpause(TPAUSE_C02_STATE, edx, eax);
}

static void delay_halt_mwaitx(u64 unused, u64 cycles)
{
	u64 delay;

	delay = min_t(u64, MWAITX_MAX_WAIT_CYCLES, cycles);
	/*
	 __monitorx(raw_cpu_ptr(&cpu_tss_rw), 0, 0);

	/*
	__mwaitx(MWAITX_DISABLE_CSTATES, delay, MWAITX_ECX_TIMER_ENABLE);
}

static void delay_halt(u64 __cycles)
{
	u64 start, end, cycles = __cycles;

	/*
	if (!cycles)
		return;

	start = rdtsc_ordered();

	for (;;) {
		delay_halt_fn(start, cycles);
		end = rdtsc_ordered();

		if (cycles <= end - start)
			break;

		cycles -= end - start;
		start = end;
	}
}

void __init use_tsc_delay(void)
{
	if (delay_fn == delay_loop)
		delay_fn = delay_tsc;
}

void __init use_tpause_delay(void)
{
	delay_halt_fn = delay_halt_tpause;
	delay_fn = delay_halt;
}

void use_mwaitx_delay(void)
{
	delay_halt_fn = delay_halt_mwaitx;
	delay_fn = delay_halt;
}

int read_current_timer(unsigned long *timer_val)
{
	if (delay_fn == delay_tsc) {
		*timer_val = rdtsc();
		return 0;
	}
	return -1;
}

void __delay(unsigned long loops)
{
	delay_fn(loops);
}
EXPORT_SYMBOL(__delay);

noinline void __const_udelay(unsigned long xloops)
{
	unsigned long lpj = this_cpu_read(cpu_info.loops_per_jiffy) ? : loops_per_jiffy;
	int d0;

	xloops *= 4;
	asm("mull %%edx"
		:"=d" (xloops), "=&a" (d0)
		:"1" (xloops), "0" (lpj * (HZ / 4)));

	__delay(++xloops);
}
EXPORT_SYMBOL(__const_udelay);

void __udelay(unsigned long usecs)
{
	__const_udelay(usecs * 0x000010c7); /* 2**32 / 1000000 (rounded up) */
}
EXPORT_SYMBOL(__udelay);

void __ndelay(unsigned long nsecs)
{
	__const_udelay(nsecs * 0x00005); /* 2**32 / 1000000000 (rounded up) */
}
EXPORT_SYMBOL(__ndelay);
