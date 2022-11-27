#ifndef _ASM_X86_SERIAL_H
#define _ASM_X86_SERIAL_H

#define BASE_BAUD (1843200/16)

#ifdef CONFIG_SERIAL_8250_DETECT_IRQ
# define STD_COMX_FLAGS	(UPF_BOOT_AUTOCONF |	UPF_SKIP_TEST	| UPF_AUTO_IRQ)
# define STD_COM4_FLAGS	(UPF_BOOT_AUTOCONF |	0		| UPF_AUTO_IRQ)
#else
# define STD_COMX_FLAGS	(UPF_BOOT_AUTOCONF |	UPF_SKIP_TEST	| 0		)
# define STD_COM4_FLAGS	(UPF_BOOT_AUTOCONF |	0		| 0		)
#endif

#define SERIAL_PORT_DFNS								\
	/* UART		CLK		PORT	IRQ	FLAGS			    */	\
	{ .uart = 0,	BASE_BAUD,	0x3F8,	4,	STD_COMX_FLAGS	}, /* ttyS0 */	\
	{ .uart = 0,	BASE_BAUD,	0x2F8,	3,	STD_COMX_FLAGS	}, /* ttyS1 */	\
	{ .uart = 0,	BASE_BAUD,	0x3E8,	4,	STD_COMX_FLAGS	}, /* ttyS2 */	\
	{ .uart = 0,	BASE_BAUD,	0x2E8,	3,	STD_COM4_FLAGS	}, /* ttyS3 */

#endif /* _ASM_X86_SERIAL_H */
