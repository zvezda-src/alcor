#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/memblock.h>

#include <asm/setup.h>
#include <asm/bios_ebda.h>


#define BIOS_RAM_SIZE_KB_PTR	0x413

#define BIOS_START_MIN		0x20000U	/* 128K, less than this is insane */
#define BIOS_START_MAX		0x9f000U	/* 640K, absolute maximum */

void __init reserve_bios_regions(void)
{
	unsigned int bios_start, ebda_start;

	/*
	if (!x86_platform.legacy.reserve_bios_regions)
		return;

	/*
	bios_start = *(unsigned short *)__va(BIOS_RAM_SIZE_KB_PTR);
	bios_start <<= 10;

	/*
	if (bios_start < BIOS_START_MIN || bios_start > BIOS_START_MAX)
		bios_start = BIOS_START_MAX;

	/* Get the start address of the EBDA page: */
	ebda_start = get_bios_ebda();

	/*
	if (ebda_start >= BIOS_START_MIN && ebda_start < bios_start)
		bios_start = ebda_start;

	/* Reserve all memory between bios_start and the 1MB mark: */
	memblock_reserve(bios_start, 0x100000 - bios_start);
}
