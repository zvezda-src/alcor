
#include <linux/linkage.h>
#include <linux/errno.h>

#include <asm/unistd.h>

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
#include <asm/syscall_wrapper.h>
#endif /* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */

    but tell gcc to not warn with -Wmissing-prototypes  */
asmlinkage long sys_ni_syscall(void);

asmlinkage long sys_ni_syscall(void)
{
	return -ENOSYS;
}

#ifndef COND_SYSCALL
#define COND_SYSCALL(name) cond_syscall(sys_##name)
#endif /* COND_SYSCALL */

#ifndef COND_SYSCALL_COMPAT
#define COND_SYSCALL_COMPAT(name) cond_syscall(compat_sys_##name)
#endif /* COND_SYSCALL_COMPAT */


COND_SYSCALL(io_setup);
COND_SYSCALL_COMPAT(io_setup);
COND_SYSCALL(io_destroy);
COND_SYSCALL(io_submit);
COND_SYSCALL_COMPAT(io_submit);
COND_SYSCALL(io_cancel);
COND_SYSCALL(io_getevents_time32);
COND_SYSCALL(io_getevents);
COND_SYSCALL(io_pgetevents_time32);
COND_SYSCALL(io_pgetevents);
COND_SYSCALL_COMPAT(io_pgetevents_time32);
COND_SYSCALL_COMPAT(io_pgetevents);
COND_SYSCALL(io_uring_setup);
COND_SYSCALL(io_uring_enter);
COND_SYSCALL(io_uring_register);



COND_SYSCALL(lookup_dcookie);
COND_SYSCALL_COMPAT(lookup_dcookie);

COND_SYSCALL(eventfd2);

COND_SYSCALL(epoll_create1);
COND_SYSCALL(epoll_ctl);
COND_SYSCALL(epoll_pwait);
COND_SYSCALL_COMPAT(epoll_pwait);
COND_SYSCALL(epoll_pwait2);
COND_SYSCALL_COMPAT(epoll_pwait2);


COND_SYSCALL(inotify_init1);
COND_SYSCALL(inotify_add_watch);
COND_SYSCALL(inotify_rm_watch);


COND_SYSCALL(ioprio_set);
COND_SYSCALL(ioprio_get);

COND_SYSCALL(flock);






COND_SYSCALL(quotactl);
COND_SYSCALL(quotactl_fd);





COND_SYSCALL(signalfd4);
COND_SYSCALL_COMPAT(signalfd4);




COND_SYSCALL(timerfd_create);
COND_SYSCALL(timerfd_settime);
COND_SYSCALL(timerfd_settime32);
COND_SYSCALL(timerfd_gettime);
COND_SYSCALL(timerfd_gettime32);


COND_SYSCALL(acct);

COND_SYSCALL(capget);
COND_SYSCALL(capset);



COND_SYSCALL(clone3);

COND_SYSCALL(futex);
COND_SYSCALL(futex_time32);
COND_SYSCALL(set_robust_list);
COND_SYSCALL_COMPAT(set_robust_list);
COND_SYSCALL(get_robust_list);
COND_SYSCALL_COMPAT(get_robust_list);
COND_SYSCALL(futex_waitv);



COND_SYSCALL(kexec_load);
COND_SYSCALL_COMPAT(kexec_load);

COND_SYSCALL(init_module);
COND_SYSCALL(delete_module);


COND_SYSCALL(syslog);



COND_SYSCALL(setregid);
COND_SYSCALL(setgid);
COND_SYSCALL(setreuid);
COND_SYSCALL(setuid);
COND_SYSCALL(setresuid);
COND_SYSCALL(getresuid);
COND_SYSCALL(setresgid);
COND_SYSCALL(getresgid);
COND_SYSCALL(setfsuid);
COND_SYSCALL(setfsgid);
COND_SYSCALL(setgroups);
COND_SYSCALL(getgroups);



COND_SYSCALL(mq_open);
COND_SYSCALL_COMPAT(mq_open);
COND_SYSCALL(mq_unlink);
COND_SYSCALL(mq_timedsend);
COND_SYSCALL(mq_timedsend_time32);
COND_SYSCALL(mq_timedreceive);
COND_SYSCALL(mq_timedreceive_time32);
COND_SYSCALL(mq_notify);
COND_SYSCALL_COMPAT(mq_notify);
COND_SYSCALL(mq_getsetattr);
COND_SYSCALL_COMPAT(mq_getsetattr);

COND_SYSCALL(msgget);
COND_SYSCALL(old_msgctl);
COND_SYSCALL(msgctl);
COND_SYSCALL_COMPAT(msgctl);
COND_SYSCALL_COMPAT(old_msgctl);
COND_SYSCALL(msgrcv);
COND_SYSCALL_COMPAT(msgrcv);
COND_SYSCALL(msgsnd);
COND_SYSCALL_COMPAT(msgsnd);

COND_SYSCALL(semget);
COND_SYSCALL(old_semctl);
COND_SYSCALL(semctl);
COND_SYSCALL_COMPAT(semctl);
COND_SYSCALL_COMPAT(old_semctl);
COND_SYSCALL(semtimedop);
COND_SYSCALL(semtimedop_time32);
COND_SYSCALL(semop);

COND_SYSCALL(shmget);
COND_SYSCALL(old_shmctl);
COND_SYSCALL(shmctl);
COND_SYSCALL_COMPAT(shmctl);
COND_SYSCALL_COMPAT(old_shmctl);
COND_SYSCALL(shmat);
COND_SYSCALL_COMPAT(shmat);
COND_SYSCALL(shmdt);

COND_SYSCALL(socket);
COND_SYSCALL(socketpair);
COND_SYSCALL(bind);
COND_SYSCALL(listen);
COND_SYSCALL(accept);
COND_SYSCALL(connect);
COND_SYSCALL(getsockname);
COND_SYSCALL(getpeername);
COND_SYSCALL(setsockopt);
COND_SYSCALL_COMPAT(setsockopt);
COND_SYSCALL(getsockopt);
COND_SYSCALL_COMPAT(getsockopt);
COND_SYSCALL(sendto);
COND_SYSCALL(shutdown);
COND_SYSCALL(recvfrom);
COND_SYSCALL_COMPAT(recvfrom);
COND_SYSCALL(sendmsg);
COND_SYSCALL_COMPAT(sendmsg);
COND_SYSCALL(recvmsg);
COND_SYSCALL_COMPAT(recvmsg);


COND_SYSCALL(mremap);

COND_SYSCALL(add_key);
COND_SYSCALL(request_key);
COND_SYSCALL(keyctl);
COND_SYSCALL_COMPAT(keyctl);

COND_SYSCALL(landlock_create_ruleset);
COND_SYSCALL(landlock_add_rule);
COND_SYSCALL(landlock_restrict_self);


COND_SYSCALL(fadvise64_64);

COND_SYSCALL(swapon);
COND_SYSCALL(swapoff);
COND_SYSCALL(mprotect);
COND_SYSCALL(msync);
COND_SYSCALL(mlock);
COND_SYSCALL(munlock);
COND_SYSCALL(mlockall);
COND_SYSCALL(munlockall);
COND_SYSCALL(mincore);
COND_SYSCALL(madvise);
COND_SYSCALL(process_madvise);
COND_SYSCALL(process_mrelease);
COND_SYSCALL(remap_file_pages);
COND_SYSCALL(mbind);
COND_SYSCALL(get_mempolicy);
COND_SYSCALL(set_mempolicy);
COND_SYSCALL(migrate_pages);
COND_SYSCALL(move_pages);
COND_SYSCALL(set_mempolicy_home_node);

COND_SYSCALL(perf_event_open);
COND_SYSCALL(accept4);
COND_SYSCALL(recvmmsg);
COND_SYSCALL(recvmmsg_time32);
COND_SYSCALL_COMPAT(recvmmsg_time32);
COND_SYSCALL_COMPAT(recvmmsg_time64);


COND_SYSCALL(fanotify_init);
COND_SYSCALL(fanotify_mark);

COND_SYSCALL(name_to_handle_at);
COND_SYSCALL(open_by_handle_at);
COND_SYSCALL_COMPAT(open_by_handle_at);

COND_SYSCALL(sendmmsg);
COND_SYSCALL_COMPAT(sendmmsg);
COND_SYSCALL(process_vm_readv);
COND_SYSCALL_COMPAT(process_vm_readv);
COND_SYSCALL(process_vm_writev);
COND_SYSCALL_COMPAT(process_vm_writev);

COND_SYSCALL(kcmp);

COND_SYSCALL(finit_module);

COND_SYSCALL(seccomp);

COND_SYSCALL(memfd_create);

COND_SYSCALL(bpf);

COND_SYSCALL(execveat);

COND_SYSCALL(userfaultfd);

COND_SYSCALL(membarrier);

COND_SYSCALL(mlock2);

COND_SYSCALL(copy_file_range);

COND_SYSCALL(pkey_mprotect);
COND_SYSCALL(pkey_alloc);
COND_SYSCALL(pkey_free);

COND_SYSCALL(memfd_secret);


COND_SYSCALL(pciconfig_read);
COND_SYSCALL(pciconfig_write);
COND_SYSCALL(pciconfig_iobase);

COND_SYSCALL(socketcall);
COND_SYSCALL_COMPAT(socketcall);

COND_SYSCALL_COMPAT(fanotify_mark);

COND_SYSCALL(vm86old);
COND_SYSCALL(modify_ldt);
COND_SYSCALL(vm86);
COND_SYSCALL(kexec_file_load);

COND_SYSCALL(s390_pci_mmio_read);
COND_SYSCALL(s390_pci_mmio_write);
COND_SYSCALL(s390_ipc);
COND_SYSCALL_COMPAT(s390_ipc);

COND_SYSCALL(rtas);
COND_SYSCALL(spu_run);
COND_SYSCALL(spu_create);
COND_SYSCALL(subpage_prot);



COND_SYSCALL(epoll_create);
COND_SYSCALL(inotify_init);
COND_SYSCALL(eventfd);
COND_SYSCALL(signalfd);
COND_SYSCALL_COMPAT(signalfd);

COND_SYSCALL(fadvise64);

COND_SYSCALL(epoll_wait);
COND_SYSCALL(recv);
COND_SYSCALL_COMPAT(recv);
COND_SYSCALL(send);
COND_SYSCALL(uselib);

COND_SYSCALL(time32);
COND_SYSCALL(stime32);
COND_SYSCALL(utime32);
COND_SYSCALL(adjtimex_time32);
COND_SYSCALL(sched_rr_get_interval_time32);
COND_SYSCALL(nanosleep_time32);
COND_SYSCALL(rt_sigtimedwait_time32);
COND_SYSCALL_COMPAT(rt_sigtimedwait_time32);
COND_SYSCALL(timer_settime32);
COND_SYSCALL(timer_gettime32);
COND_SYSCALL(clock_settime32);
COND_SYSCALL(clock_gettime32);
COND_SYSCALL(clock_getres_time32);
COND_SYSCALL(clock_nanosleep_time32);
COND_SYSCALL(utimes_time32);
COND_SYSCALL(futimesat_time32);
COND_SYSCALL(pselect6_time32);
COND_SYSCALL_COMPAT(pselect6_time32);
COND_SYSCALL(ppoll_time32);
COND_SYSCALL_COMPAT(ppoll_time32);
COND_SYSCALL(utimensat_time32);
COND_SYSCALL(clock_adjtime32);


COND_SYSCALL(sgetmask);
COND_SYSCALL(ssetmask);

COND_SYSCALL(sysfs);

COND_SYSCALL(ipc);
COND_SYSCALL_COMPAT(ipc);

COND_SYSCALL(chown16);
COND_SYSCALL(fchown16);
COND_SYSCALL(getegid16);
COND_SYSCALL(geteuid16);
COND_SYSCALL(getgid16);
COND_SYSCALL(getgroups16);
COND_SYSCALL(getresgid16);
COND_SYSCALL(getresuid16);
COND_SYSCALL(getuid16);
COND_SYSCALL(lchown16);
COND_SYSCALL(setfsgid16);
COND_SYSCALL(setfsuid16);
COND_SYSCALL(setgid16);
COND_SYSCALL(setgroups16);
COND_SYSCALL(setregid16);
COND_SYSCALL(setresgid16);
COND_SYSCALL(setresuid16);
COND_SYSCALL(setreuid16);
COND_SYSCALL(setuid16);

COND_SYSCALL(rseq);
