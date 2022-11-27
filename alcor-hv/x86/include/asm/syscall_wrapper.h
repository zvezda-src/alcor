
#ifndef _ASM_X86_SYSCALL_WRAPPER_H
#define _ASM_X86_SYSCALL_WRAPPER_H

struct pt_regs;

extern long __x64_sys_ni_syscall(const struct pt_regs *regs);
extern long __ia32_sys_ni_syscall(const struct pt_regs *regs);


#define SC_X86_64_REGS_TO_ARGS(x, ...)					\
	__MAP(x,__SC_ARGS						\
		,,regs->di,,regs->si,,regs->dx				\
		,,regs->r10,,regs->r8,,regs->r9)			\

#define SC_IA32_REGS_TO_ARGS(x, ...)					\
	__MAP(x,__SC_ARGS						\
	      ,,(unsigned int)regs->bx,,(unsigned int)regs->cx		\
	      ,,(unsigned int)regs->dx,,(unsigned int)regs->si		\
	      ,,(unsigned int)regs->di,,(unsigned int)regs->bp)

#define __SYS_STUB0(abi, name)						\
	long __##abi##_##name(const struct pt_regs *regs);		\
	ALLOW_ERROR_INJECTION(__##abi##_##name, ERRNO);			\
	long __##abi##_##name(const struct pt_regs *regs)		\
		__alias(__do_##name);

#define __SYS_STUBx(abi, name, ...)					\
	long __##abi##_##name(const struct pt_regs *regs);		\
	ALLOW_ERROR_INJECTION(__##abi##_##name, ERRNO);			\
	long __##abi##_##name(const struct pt_regs *regs)		\
	{								\
		return __se_##name(__VA_ARGS__);			\
	}

#define __COND_SYSCALL(abi, name)					\
	__weak long __##abi##_##name(const struct pt_regs *__unused);	\
	__weak long __##abi##_##name(const struct pt_regs *__unused)	\
	{								\
		return sys_ni_syscall();				\
	}

#define __SYS_NI(abi, name)						\
	SYSCALL_ALIAS(__##abi##_##name, sys_ni_posix_timers);

#ifdef CONFIG_X86_64
#define __X64_SYS_STUB0(name)						\
	__SYS_STUB0(x64, sys_##name)

#define __X64_SYS_STUBx(x, name, ...)					\
	__SYS_STUBx(x64, sys##name,					\
		    SC_X86_64_REGS_TO_ARGS(x, __VA_ARGS__))

#define __X64_COND_SYSCALL(name)					\
	__COND_SYSCALL(x64, sys_##name)

#define __X64_SYS_NI(name)						\
	__SYS_NI(x64, sys_##name)
#else /* CONFIG_X86_64 */
#define __X64_SYS_STUB0(name)
#define __X64_SYS_STUBx(x, name, ...)
#define __X64_COND_SYSCALL(name)
#define __X64_SYS_NI(name)
#endif /* CONFIG_X86_64 */

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
#define __IA32_SYS_STUB0(name)						\
	__SYS_STUB0(ia32, sys_##name)

#define __IA32_SYS_STUBx(x, name, ...)					\
	__SYS_STUBx(ia32, sys##name,					\
		    SC_IA32_REGS_TO_ARGS(x, __VA_ARGS__))

#define __IA32_COND_SYSCALL(name)					\
	__COND_SYSCALL(ia32, sys_##name)

#define __IA32_SYS_NI(name)						\
	__SYS_NI(ia32, sys_##name)
#else /* CONFIG_X86_32 || CONFIG_IA32_EMULATION */
#define __IA32_SYS_STUB0(name)
#define __IA32_SYS_STUBx(x, name, ...)
#define __IA32_COND_SYSCALL(name)
#define __IA32_SYS_NI(name)
#endif /* CONFIG_X86_32 || CONFIG_IA32_EMULATION */

#ifdef CONFIG_IA32_EMULATION
#define __IA32_COMPAT_SYS_STUB0(name)					\
	__SYS_STUB0(ia32, compat_sys_##name)

#define __IA32_COMPAT_SYS_STUBx(x, name, ...)				\
	__SYS_STUBx(ia32, compat_sys##name,				\
		    SC_IA32_REGS_TO_ARGS(x, __VA_ARGS__))

#define __IA32_COMPAT_COND_SYSCALL(name)				\
	__COND_SYSCALL(ia32, compat_sys_##name)

#define __IA32_COMPAT_SYS_NI(name)					\
	__SYS_NI(ia32, compat_sys_##name)

#else /* CONFIG_IA32_EMULATION */
#define __IA32_COMPAT_SYS_STUB0(name)
#define __IA32_COMPAT_SYS_STUBx(x, name, ...)
#define __IA32_COMPAT_COND_SYSCALL(name)
#define __IA32_COMPAT_SYS_NI(name)
#endif /* CONFIG_IA32_EMULATION */


#ifdef CONFIG_X86_X32_ABI
#define __X32_COMPAT_SYS_STUB0(name)					\
	__SYS_STUB0(x64, compat_sys_##name)

#define __X32_COMPAT_SYS_STUBx(x, name, ...)				\
	__SYS_STUBx(x64, compat_sys##name,				\
		    SC_X86_64_REGS_TO_ARGS(x, __VA_ARGS__))

#define __X32_COMPAT_COND_SYSCALL(name)					\
	__COND_SYSCALL(x64, compat_sys_##name)

#define __X32_COMPAT_SYS_NI(name)					\
	__SYS_NI(x64, compat_sys_##name)
#else /* CONFIG_X86_X32_ABI */
#define __X32_COMPAT_SYS_STUB0(name)
#define __X32_COMPAT_SYS_STUBx(x, name, ...)
#define __X32_COMPAT_COND_SYSCALL(name)
#define __X32_COMPAT_SYS_NI(name)
#endif /* CONFIG_X86_X32_ABI */


#ifdef CONFIG_COMPAT
#define COMPAT_SYSCALL_DEFINE0(name)					\
	static long							\
	__do_compat_sys_##name(const struct pt_regs *__unused);		\
	__IA32_COMPAT_SYS_STUB0(name)					\
	__X32_COMPAT_SYS_STUB0(name)					\
	static long							\
	__do_compat_sys_##name(const struct pt_regs *__unused)

#define COMPAT_SYSCALL_DEFINEx(x, name, ...)					\
	static long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	__IA32_COMPAT_SYS_STUBx(x, name, __VA_ARGS__)				\
	__X32_COMPAT_SYS_STUBx(x, name, __VA_ARGS__)				\
	static long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{									\
		return __do_compat_sys##name(__MAP(x,__SC_DELOUSE,__VA_ARGS__));\
	}									\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

#define COND_SYSCALL_COMPAT(name) 					\
	__IA32_COMPAT_COND_SYSCALL(name)				\
	__X32_COMPAT_COND_SYSCALL(name)

#define COMPAT_SYS_NI(name)						\
	__IA32_COMPAT_SYS_NI(name)					\
	__X32_COMPAT_SYS_NI(name)

#endif /* CONFIG_COMPAT */

#define __SYSCALL_DEFINEx(x, name, ...)					\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	__X64_SYS_STUBx(x, name, __VA_ARGS__)				\
	__IA32_SYS_STUBx(x, name, __VA_ARGS__)				\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

#define SYSCALL_DEFINE0(sname)						\
	SYSCALL_METADATA(_##sname, 0);					\
	static long __do_sys_##sname(const struct pt_regs *__unused);	\
	__X64_SYS_STUB0(sname)						\
	__IA32_SYS_STUB0(sname)						\
	static long __do_sys_##sname(const struct pt_regs *__unused)

#define COND_SYSCALL(name)						\
	__X64_COND_SYSCALL(name)					\
	__IA32_COND_SYSCALL(name)

#define SYS_NI(name)							\
	__X64_SYS_NI(name)						\
	__IA32_SYS_NI(name)


long __x64_sys_getcpu(const struct pt_regs *regs);
long __x64_sys_gettimeofday(const struct pt_regs *regs);
long __x64_sys_time(const struct pt_regs *regs);

#endif /* _ASM_X86_SYSCALL_WRAPPER_H */
