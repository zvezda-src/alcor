#ifndef BOOT_IO_H
#define BOOT_IO_H

#include <asm/shared/io.h>

#undef inb
#undef inw
#undef inl
#undef outb
#undef outw
#undef outl

struct port_io_ops {
	u8	(*f_inb)(u16 port);
	void	(*f_outb)(u8 v, u16 port);
	void	(*f_outw)(u16 v, u16 port);
};

extern struct port_io_ops pio_ops;

static inline void init_default_io_ops(void)
{
	pio_ops.f_inb  = __inb;
	pio_ops.f_outb = __outb;
	pio_ops.f_outw = __outw;
}

#define inb  pio_ops.f_inb
#define outb pio_ops.f_outb
#define outw pio_ops.f_outw

#endif
