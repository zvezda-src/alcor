#ifndef _UAPI_ASM_X86_SIGCONTEXT_H
#define _UAPI_ASM_X86_SIGCONTEXT_H


#include <linux/compiler.h>
#include <linux/types.h>

#define FP_XSTATE_MAGIC1		0x46505853U
#define FP_XSTATE_MAGIC2		0x46505845U
#define FP_XSTATE_MAGIC2_SIZE		sizeof(FP_XSTATE_MAGIC2)

struct _fpx_sw_bytes {
	/*
	__u32				magic1;

	/*
	__u32				extended_size;

	/*
	__u64				xfeatures;

	/*
	__u32				xstate_size;

	/* For future use: */
	__u32				padding[7];
};


struct _fpreg {
	__u16				significand[4];
	__u16				exponent;
};

struct _fpxreg {
	__u16				significand[4];
	__u16				exponent;
	__u16				padding[3];
};

struct _xmmreg {
	__u32				element[4];
};

#define X86_FXSR_MAGIC			0x0000

struct _fpstate_32 {
	/* Legacy FPU environment: */
	__u32				cw;
	__u32				sw;
	__u32				tag;
	__u32				ipoff;
	__u32				cssel;
	__u32				dataoff;
	__u32				datasel;
	struct _fpreg			_st[8];
	__u16				status;
	__u16				magic;		/* 0xffff: regular FPU data only */
							/* 0x0000: FXSR FPU data */

	/* FXSR FPU environment */
	__u32				_fxsr_env[6];	/* FXSR FPU env is ignored */
	__u32				mxcsr;
	__u32				reserved;
	struct _fpxreg			_fxsr_st[8];	/* FXSR FPU reg data is ignored */
	struct _xmmreg			_xmm[8];	/* First 8 XMM registers */
	union {
		__u32			padding1[44];	/* Second 8 XMM registers plus padding */
		__u32			padding[44];	/* Alias name for old user-space */
	};

	union {
		__u32			padding2[12];
		struct _fpx_sw_bytes	sw_reserved;	/* Potential extended state is encoded here */
	};
};

struct _fpstate_64 {
	__u16				cwd;
	__u16				swd;
	/* Note this is not the same as the 32-bit/x87/FSAVE twd: */
	__u16				twd;
	__u16				fop;
	__u64				rip;
	__u64				rdp;
	__u32				mxcsr;
	__u32				mxcsr_mask;
	__u32				st_space[32];	/*  8x  FP registers, 16 bytes each */
	__u32				xmm_space[64];	/* 16x XMM registers, 16 bytes each */
	__u32				reserved2[12];
	union {
		__u32			reserved3[12];
		struct _fpx_sw_bytes	sw_reserved;	/* Potential extended state is encoded here */
	};
};

#ifdef __i386__
# define _fpstate _fpstate_32
#else
# define _fpstate _fpstate_64
#endif

struct _header {
	__u64				xfeatures;
	__u64				reserved1[2];
	__u64				reserved2[5];
};

struct _ymmh_state {
	/* 16x YMM registers, 16 bytes each: */
	__u32				ymmh_space[64];
};

struct _xstate {
	struct _fpstate			fpstate;
	struct _header			xstate_hdr;
	struct _ymmh_state		ymmh;
	/* New processor state extensions go here: */
};

struct sigcontext_32 {
	__u16				gs, __gsh;
	__u16				fs, __fsh;
	__u16				es, __esh;
	__u16				ds, __dsh;
	__u32				di;
	__u32				si;
	__u32				bp;
	__u32				sp;
	__u32				bx;
	__u32				dx;
	__u32				cx;
	__u32				ax;
	__u32				trapno;
	__u32				err;
	__u32				ip;
	__u16				cs, __csh;
	__u32				flags;
	__u32				sp_at_signal;
	__u16				ss, __ssh;

	/*
	__u32				fpstate; /* Zero when no FPU/extended context */
	__u32				oldmask;
	__u32				cr2;
};

struct sigcontext_64 {
	__u64				r8;
	__u64				r9;
	__u64				r10;
	__u64				r11;
	__u64				r12;
	__u64				r13;
	__u64				r14;
	__u64				r15;
	__u64				di;
	__u64				si;
	__u64				bp;
	__u64				bx;
	__u64				dx;
	__u64				ax;
	__u64				cx;
	__u64				sp;
	__u64				ip;
	__u64				flags;
	__u16				cs;
	__u16				gs;
	__u16				fs;
	__u16				ss;
	__u64				err;
	__u64				trapno;
	__u64				oldmask;
	__u64				cr2;

	/*
	__u64				fpstate; /* Zero when no FPU/extended context */
	__u64				reserved1[8];
};

#ifdef __KERNEL__
# ifdef __i386__
#  define sigcontext sigcontext_32
# else
#  define sigcontext sigcontext_64
# endif
#endif

#ifndef __KERNEL__

#define _fpstate_ia32			_fpstate_32
#define sigcontext_ia32			sigcontext_32


# ifdef __i386__
struct sigcontext {
	__u16				gs, __gsh;
	__u16				fs, __fsh;
	__u16				es, __esh;
	__u16				ds, __dsh;
	__u32				edi;
	__u32				esi;
	__u32				ebp;
	__u32				esp;
	__u32				ebx;
	__u32				edx;
	__u32				ecx;
	__u32				eax;
	__u32				trapno;
	__u32				err;
	__u32				eip;
	__u16				cs, __csh;
	__u32				eflags;
	__u32				esp_at_signal;
	__u16				ss, __ssh;
	struct _fpstate __user		*fpstate;
	__u32				oldmask;
	__u32				cr2;
};
# else /* __x86_64__: */
struct sigcontext {
	__u64				r8;
	__u64				r9;
	__u64				r10;
	__u64				r11;
	__u64				r12;
	__u64				r13;
	__u64				r14;
	__u64				r15;
	__u64				rdi;
	__u64				rsi;
	__u64				rbp;
	__u64				rbx;
	__u64				rdx;
	__u64				rax;
	__u64				rcx;
	__u64				rsp;
	__u64				rip;
	__u64				eflags;		/* RFLAGS */
	__u16				cs;

	/*
	__u16				gs;
	__u16				fs;
	union {
		__u16			ss;	/* If UC_SIGCONTEXT_SS */
		__u16			__pad0;	/* Alias name for old (!UC_SIGCONTEXT_SS) user-space */
	};
	__u64				err;
	__u64				trapno;
	__u64				oldmask;
	__u64				cr2;
	struct _fpstate __user		*fpstate;	/* Zero when no FPU context */
#  ifdef __ILP32__
	__u32				__fpstate_pad;
#  endif
	__u64				reserved1[8];
};
# endif /* __x86_64__ */
#endif /* !__KERNEL__ */

#endif /* _UAPI_ASM_X86_SIGCONTEXT_H */
