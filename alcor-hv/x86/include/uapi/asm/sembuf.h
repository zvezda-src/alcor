#ifndef _ASM_X86_SEMBUF_H
#define _ASM_X86_SEMBUF_H

#include <asm/ipcbuf.h>

struct semid64_ds {
	struct ipc64_perm sem_perm;	/* permissions .. see ipc.h */
#ifdef __i386__
	unsigned long	sem_otime;	/* last semop time */
	unsigned long	sem_otime_high;
	unsigned long	sem_ctime;	/* last change time */
	unsigned long	sem_ctime_high;
#else
	__kernel_long_t sem_otime;	/* last semop time */
	__kernel_ulong_t __unused1;
	__kernel_long_t sem_ctime;	/* last change time */
	__kernel_ulong_t __unused2;
#endif
	__kernel_ulong_t sem_nsems;	/* no. of semaphores in array */
	__kernel_ulong_t __unused3;
	__kernel_ulong_t __unused4;
};

#endif /* _ASM_X86_SEMBUF_H */
