#include <asm/trace_clock.h>
#include <asm/barrier.h>
#include <asm/msr.h>

u64 notrace trace_clock_x86_tsc(void)
{
	return rdtsc_ordered();
}
