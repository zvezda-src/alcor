#include <linux/kernel.h>
#include <asm/processor.h>
#include "cpu.h"


static const struct cpu_dev vortex_cpu_dev = {
	.c_vendor	= "Vortex",
	.c_ident	= { "Vortex86 SoC" },
	.legacy_models	= {
		{
			.family = 5,
			.model_names = {
				[2] = "Vortex86DX",
				[8] = "Vortex86MX",
			},
		},
		{
			.family = 6,
			.model_names = {
				/*
				[0] = "Vortex86EX",
			},
		},
	},
	.c_x86_vendor	= X86_VENDOR_VORTEX,
};

cpu_dev_register(vortex_cpu_dev);
