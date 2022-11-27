
#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <asm/syscall.h>


#define sys_iopl sys_ni_syscall
#define sys_ioperm sys_ni_syscall

#define __SYSCALL(nr, sym) extern asmlinkage long sym(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
#include <asm/syscalls_64.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym) sym,

extern asmlinkage long sys_ni_syscall(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);

const sys_call_ptr_t sys_call_table[] ____cacheline_aligned = {
#include <asm/syscalls_64.h>
};

int syscall_table_size = sizeof(sys_call_table);
