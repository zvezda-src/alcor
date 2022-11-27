
#include <sys/ptrace.h>
#include <asm/ptrace.h>

int os_arch_prctl(int pid, int option, unsigned long *arg2)
{
	return ptrace(PTRACE_ARCH_PRCTL, pid, (unsigned long) arg2, option);
}
