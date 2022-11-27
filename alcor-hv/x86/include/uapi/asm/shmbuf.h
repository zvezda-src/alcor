#ifndef __ASM_X86_SHMBUF_H
#define __ASM_X86_SHMBUF_H

#if !defined(__x86_64__) || !defined(__ILP32__)
#include <asm-generic/shmbuf.h>
#else

#include <asm/ipcbuf.h>
#include <asm/posix_types.h>


struct shmid64_ds {
	struct ipc64_perm	shm_perm;	/* operation perms */
	__kernel_size_t		shm_segsz;	/* size of segment (bytes) */
	__kernel_long_t		shm_atime;	/* last attach time */
	__kernel_long_t		shm_dtime;	/* last detach time */
	__kernel_long_t		shm_ctime;	/* last change time */
	__kernel_pid_t		shm_cpid;	/* pid of creator */
	__kernel_pid_t		shm_lpid;	/* pid of last operator */
	__kernel_ulong_t	shm_nattch;	/* no. of current attaches */
	__kernel_ulong_t	__unused4;
	__kernel_ulong_t	__unused5;
};

struct shminfo64 {
	__kernel_ulong_t	shmmax;
	__kernel_ulong_t	shmmin;
	__kernel_ulong_t	shmmni;
	__kernel_ulong_t	shmseg;
	__kernel_ulong_t	shmall;
	__kernel_ulong_t	__unused1;
	__kernel_ulong_t	__unused2;
	__kernel_ulong_t	__unused3;
	__kernel_ulong_t	__unused4;
};

#endif

#endif /* __ASM_X86_SHMBUF_H */
