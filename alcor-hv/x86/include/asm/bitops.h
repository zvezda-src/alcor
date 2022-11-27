#ifndef _ASM_X86_BITOPS_H
#define _ASM_X86_BITOPS_H


#ifndef _LINUX_BITOPS_H
#error only <linux/bitops.h> can be included directly
#endif

#include <linux/compiler.h>
#include <asm/alternative.h>
#include <asm/rmwcc.h>
#include <asm/barrier.h>

#if BITS_PER_LONG == 32
# define _BITOPS_LONG_SHIFT 5
#elif BITS_PER_LONG == 64
# define _BITOPS_LONG_SHIFT 6
#else
# error "Unexpected BITS_PER_LONG"
#endif

#define BIT_64(n)			(U64_C(1) << (n))


#define RLONG_ADDR(x)			 "m" (*(volatile long *) (x))
#define WBYTE_ADDR(x)			"+m" (*(volatile char *) (x))

#define ADDR				RLONG_ADDR(addr)

#define CONST_MASK_ADDR(nr, addr)	WBYTE_ADDR((void *)(addr) + ((nr)>>3))
#define CONST_MASK(nr)			(1 << ((nr) & 7))

static __always_inline void
arch_set_bit(long nr, volatile unsigned long *addr)
{
	if (__builtin_constant_p(nr)) {
		asm volatile(LOCK_PREFIX "orb %b1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" (CONST_MASK(nr))
			: "memory");
	} else {
		asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
	}
}

static __always_inline void
arch___set_bit(long nr, volatile unsigned long *addr)
{
	asm volatile(__ASM_SIZE(bts) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
}

static __always_inline void
arch_clear_bit(long nr, volatile unsigned long *addr)
{
	if (__builtin_constant_p(nr)) {
		asm volatile(LOCK_PREFIX "andb %b1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" (~CONST_MASK(nr)));
	} else {
		asm volatile(LOCK_PREFIX __ASM_SIZE(btr) " %1,%0"
			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
	}
}

static __always_inline void
arch_clear_bit_unlock(long nr, volatile unsigned long *addr)
{
	barrier();
	arch_clear_bit(nr, addr);
}

static __always_inline void
arch___clear_bit(long nr, volatile unsigned long *addr)
{
	asm volatile(__ASM_SIZE(btr) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
}

static __always_inline bool
arch_clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
{
	bool negative;
	asm volatile(LOCK_PREFIX "andb %2,%1"
		CC_SET(s)
		: CC_OUT(s) (negative), WBYTE_ADDR(addr)
		: "ir" ((char) ~(1 << nr)) : "memory");
	return negative;
}
#define arch_clear_bit_unlock_is_negative_byte                                 \
	arch_clear_bit_unlock_is_negative_byte

static __always_inline void
arch___clear_bit_unlock(long nr, volatile unsigned long *addr)
{
	arch___clear_bit(nr, addr);
}

static __always_inline void
arch___change_bit(long nr, volatile unsigned long *addr)
{
	asm volatile(__ASM_SIZE(btc) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
}

static __always_inline void
arch_change_bit(long nr, volatile unsigned long *addr)
{
	if (__builtin_constant_p(nr)) {
		asm volatile(LOCK_PREFIX "xorb %b1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" (CONST_MASK(nr)));
	} else {
		asm volatile(LOCK_PREFIX __ASM_SIZE(btc) " %1,%0"
			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
	}
}

static __always_inline bool
arch_test_and_set_bit(long nr, volatile unsigned long *addr)
{
	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(bts), *addr, c, "Ir", nr);
}

static __always_inline bool
arch_test_and_set_bit_lock(long nr, volatile unsigned long *addr)
{
	return arch_test_and_set_bit(nr, addr);
}

static __always_inline bool
arch___test_and_set_bit(long nr, volatile unsigned long *addr)
{
	bool oldbit;

	asm(__ASM_SIZE(bts) " %2,%1"
	    CC_SET(c)
	    : CC_OUT(c) (oldbit)
	    : ADDR, "Ir" (nr) : "memory");
	return oldbit;
}

static __always_inline bool
arch_test_and_clear_bit(long nr, volatile unsigned long *addr)
{
	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btr), *addr, c, "Ir", nr);
}

static __always_inline bool
arch___test_and_clear_bit(long nr, volatile unsigned long *addr)
{
	bool oldbit;

	asm volatile(__ASM_SIZE(btr) " %2,%1"
		     CC_SET(c)
		     : CC_OUT(c) (oldbit)
		     : ADDR, "Ir" (nr) : "memory");
	return oldbit;
}

static __always_inline bool
arch___test_and_change_bit(long nr, volatile unsigned long *addr)
{
	bool oldbit;

	asm volatile(__ASM_SIZE(btc) " %2,%1"
		     CC_SET(c)
		     : CC_OUT(c) (oldbit)
		     : ADDR, "Ir" (nr) : "memory");

	return oldbit;
}

static __always_inline bool
arch_test_and_change_bit(long nr, volatile unsigned long *addr)
{
	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btc), *addr, c, "Ir", nr);
}

static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
{
	return ((1UL << (nr & (BITS_PER_LONG-1))) &
		(addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
}

static __always_inline bool variable_test_bit(long nr, volatile const unsigned long *addr)
{
	bool oldbit;

	asm volatile(__ASM_SIZE(bt) " %2,%1"
		     CC_SET(c)
		     : CC_OUT(c) (oldbit)
		     : "m" (*(unsigned long *)addr), "Ir" (nr) : "memory");

	return oldbit;
}

#define arch_test_bit(nr, addr)			\
	(__builtin_constant_p((nr))		\
	 ? constant_test_bit((nr), (addr))	\
	 : variable_test_bit((nr), (addr)))

static __always_inline unsigned long __ffs(unsigned long word)
{
	asm("rep; bsf %1,%0"
		: "=r" (word)
		: "rm" (word));
	return word;
}

static __always_inline unsigned long ffz(unsigned long word)
{
	asm("rep; bsf %1,%0"
		: "=r" (word)
		: "r" (~word));
	return word;
}

static __always_inline unsigned long __fls(unsigned long word)
{
	asm("bsr %1,%0"
	    : "=r" (word)
	    : "rm" (word));
	return word;
}

#undef ADDR

#ifdef __KERNEL__
static __always_inline int ffs(int x)
{
	int r;

#ifdef CONFIG_X86_64
	/*
	asm("bsfl %1,%0"
	    : "=r" (r)
	    : "rm" (x), "0" (-1));
#elif defined(CONFIG_X86_CMOV)
	asm("bsfl %1,%0\n\t"
	    "cmovzl %2,%0"
	    : "=&r" (r) : "rm" (x), "r" (-1));
#else
	asm("bsfl %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movl $-1,%0\n"
	    "1:" : "=r" (r) : "rm" (x));
#endif
	return r + 1;
}

static __always_inline int fls(unsigned int x)
{
	int r;

#ifdef CONFIG_X86_64
	/*
	asm("bsrl %1,%0"
	    : "=r" (r)
	    : "rm" (x), "0" (-1));
#elif defined(CONFIG_X86_CMOV)
	asm("bsrl %1,%0\n\t"
	    "cmovzl %2,%0"
	    : "=&r" (r) : "rm" (x), "rm" (-1));
#else
	asm("bsrl %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movl $-1,%0\n"
	    "1:" : "=r" (r) : "rm" (x));
#endif
	return r + 1;
}

#ifdef CONFIG_X86_64
static __always_inline int fls64(__u64 x)
{
	int bitpos = -1;
	/*
	asm("bsrq %1,%q0"
	    : "+r" (bitpos)
	    : "rm" (x));
	return bitpos + 1;
}
#else
#include <asm-generic/bitops/fls64.h>
#endif

#include <asm-generic/bitops/sched.h>

#include <asm/arch_hweight.h>

#include <asm-generic/bitops/const_hweight.h>

#include <asm-generic/bitops/instrumented-atomic.h>
#include <asm-generic/bitops/instrumented-non-atomic.h>
#include <asm-generic/bitops/instrumented-lock.h>

#include <asm-generic/bitops/le.h>

#include <asm-generic/bitops/ext2-atomic-setbit.h>

#endif /* __KERNEL__ */
#endif /* _ASM_X86_BITOPS_H */
