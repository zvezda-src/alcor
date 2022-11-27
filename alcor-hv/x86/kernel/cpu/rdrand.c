
#include <asm/processor.h>
#include <asm/archrandom.h>
#include <asm/sections.h>


void x86_init_rdrand(struct cpuinfo_x86 *c)
{
	enum { SAMPLES = 8, MIN_CHANGE = 5 };
	unsigned long sample, prev;
	bool failure = false;
	size_t i, changed;

	if (!cpu_has(c, X86_FEATURE_RDRAND))
		return;

	for (changed = 0, i = 0; i < SAMPLES; ++i) {
		if (!rdrand_long(&sample)) {
			failure = true;
			break;
		}
		changed += i && sample != prev;
		prev = sample;
	}
	if (changed < MIN_CHANGE)
		failure = true;

	if (failure) {
		clear_cpu_cap(c, X86_FEATURE_RDRAND);
		clear_cpu_cap(c, X86_FEATURE_RDSEED);
		pr_emerg("RDRAND is not reliable on this platform; disabling.\n");
	}
}
