#ifndef __ASM_X64_MSGBUF_H
#define __ASM_X64_MSGBUF_H

#if !defined(__x86_64__) || !defined(__ILP32__)
#include <asm-generic/msgbuf.h>
#else

#include <asm/ipcbuf.h>


struct msqid64_ds {
	struct ipc64_perm msg_perm;
	__kernel_long_t msg_stime;	/* last msgsnd time */
	__kernel_long_t msg_rtime;	/* last msgrcv time */
	__kernel_long_t msg_ctime;	/* last change time */
	__kernel_ulong_t msg_cbytes;	/* current number of bytes on queue */
	__kernel_ulong_t msg_qnum;	/* number of messages in queue */
	__kernel_ulong_t msg_qbytes;	/* max number of bytes on queue */
	__kernel_pid_t msg_lspid;	/* pid of last msgsnd */
	__kernel_pid_t msg_lrpid;	/* last receive pid */
	__kernel_ulong_t __unused4;
	__kernel_ulong_t __unused5;
};

#endif

#endif /* __ASM_GENERIC_MSGBUF_H */
