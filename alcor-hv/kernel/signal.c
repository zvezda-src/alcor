
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/user.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/tty.h>
#include <linux/binfmts.h>
#include <linux/coredump.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/signalfd.h>
#include <linux/ratelimit.h>
#include <linux/task_work.h>
#include <linux/capability.h>
#include <linux/freezer.h>
#include <linux/pid_namespace.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
#include <linux/uprobes.h>
#include <linux/compat.h>
#include <linux/cn_proc.h>
#include <linux/compiler.h>
#include <linux/posix-timers.h>
#include <linux/cgroup.h>
#include <linux/audit.h>

#define CREATE_TRACE_POINTS
#include <trace/events/signal.h>

#include <asm/param.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>
#include <asm/siginfo.h>
#include <asm/cacheflush.h>
#include <asm/syscall.h>	/* for syscall_get_* */


static struct kmem_cache *sigqueue_cachep;

int print_fatal_signals __read_mostly;

static void __user *sig_handler(struct task_struct *t, int sig)
{
	return t->sighand->action[sig - 1].sa.sa_handler;
}

static inline bool sig_handler_ignored(void __user *handler, int sig)
{
	/* Is it explicitly or implicitly ignored? */
	return handler == SIG_IGN ||
	       (handler == SIG_DFL && sig_kernel_ignore(sig));
}

static bool sig_task_ignored(struct task_struct *t, int sig, bool force)
{
	void __user *handler;

	handler = sig_handler(t, sig);

	/* SIGKILL and SIGSTOP may not be sent to the global init */
	if (unlikely(is_global_init(t) && sig_kernel_only(sig)))
		return true;

	if (unlikely(t->signal->flags & SIGNAL_UNKILLABLE) &&
	    handler == SIG_DFL && !(force && sig_kernel_only(sig)))
		return true;

	/* Only allow kernel generated signals to this kthread */
	if (unlikely((t->flags & PF_KTHREAD) &&
		     (handler == SIG_KTHREAD_KERNEL) && !force))
		return true;

	return sig_handler_ignored(handler, sig);
}

static bool sig_ignored(struct task_struct *t, int sig, bool force)
{
	/*
	if (sigismember(&t->blocked, sig) || sigismember(&t->real_blocked, sig))
		return false;

	/*
	if (t->ptrace && sig != SIGKILL)
		return false;

	return sig_task_ignored(t, sig, force);
}

static inline bool has_pending_signals(sigset_t *signal, sigset_t *blocked)
{
	unsigned long ready;
	long i;

	switch (_NSIG_WORDS) {
	default:
		for (i = _NSIG_WORDS, ready = 0; --i >= 0 ;)
			ready |= signal->sig[i] &~ blocked->sig[i];
		break;

	case 4: ready  = signal->sig[3] &~ blocked->sig[3];
		ready |= signal->sig[2] &~ blocked->sig[2];
		ready |= signal->sig[1] &~ blocked->sig[1];
		ready |= signal->sig[0] &~ blocked->sig[0];
		break;

	case 2: ready  = signal->sig[1] &~ blocked->sig[1];
		ready |= signal->sig[0] &~ blocked->sig[0];
		break;

	case 1: ready  = signal->sig[0] &~ blocked->sig[0];
	}
	return ready !=	0;
}

#define PENDING(p,b) has_pending_signals(&(p)->signal, (b))

static bool recalc_sigpending_tsk(struct task_struct *t)
{
	if ((t->jobctl & (JOBCTL_PENDING_MASK | JOBCTL_TRAP_FREEZE)) ||
	    PENDING(&t->pending, &t->blocked) ||
	    PENDING(&t->signal->shared_pending, &t->blocked) ||
	    cgroup_task_frozen(t)) {
		set_tsk_thread_flag(t, TIF_SIGPENDING);
		return true;
	}

	/*
	return false;
}

void recalc_sigpending_and_wake(struct task_struct *t)
{
	if (recalc_sigpending_tsk(t))
		signal_wake_up(t, 0);
}

void recalc_sigpending(void)
{
	if (!recalc_sigpending_tsk(current) && !freezing(current))
		clear_thread_flag(TIF_SIGPENDING);

}
EXPORT_SYMBOL(recalc_sigpending);

void calculate_sigpending(void)
{
	/* Have any signals or users of TIF_SIGPENDING been delayed
	 * until after fork?
	 */
	spin_lock_irq(&current->sighand->siglock);
	set_tsk_thread_flag(current, TIF_SIGPENDING);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}


#define SYNCHRONOUS_MASK \
	(sigmask(SIGSEGV) | sigmask(SIGBUS) | sigmask(SIGILL) | \
	 sigmask(SIGTRAP) | sigmask(SIGFPE) | sigmask(SIGSYS))

int next_signal(struct sigpending *pending, sigset_t *mask)
{
	unsigned long i, *s, *m, x;
	int sig = 0;

	s = pending->signal.sig;
	m = mask->sig;

	/*
	x = *s &~ *m;
	if (x) {
		if (x & SYNCHRONOUS_MASK)
			x &= SYNCHRONOUS_MASK;
		sig = ffz(~x) + 1;
		return sig;
	}

	switch (_NSIG_WORDS) {
	default:
		for (i = 1; i < _NSIG_WORDS; ++i) {
			x = *++s &~ *++m;
			if (!x)
				continue;
			sig = ffz(~x) + i*_NSIG_BPW + 1;
			break;
		}
		break;

	case 2:
		x = s[1] &~ m[1];
		if (!x)
			break;
		sig = ffz(~x) + _NSIG_BPW + 1;
		break;

	case 1:
		/* Nothing to do */
		break;
	}

	return sig;
}

static inline void print_dropped_signal(int sig)
{
	static DEFINE_RATELIMIT_STATE(ratelimit_state, 5 * HZ, 10);

	if (!print_fatal_signals)
		return;

	if (!__ratelimit(&ratelimit_state))
		return;

	pr_info("%s/%d: reached RLIMIT_SIGPENDING, dropped signal %d\n",
				current->comm, current->pid, sig);
}

bool task_set_jobctl_pending(struct task_struct *task, unsigned long mask)
{
	BUG_ON(mask & ~(JOBCTL_PENDING_MASK | JOBCTL_STOP_CONSUME |
			JOBCTL_STOP_SIGMASK | JOBCTL_TRAPPING));
	BUG_ON((mask & JOBCTL_TRAPPING) && !(mask & JOBCTL_PENDING_MASK));

	if (unlikely(fatal_signal_pending(task) || (task->flags & PF_EXITING)))
		return false;

	if (mask & JOBCTL_STOP_SIGMASK)
		task->jobctl &= ~JOBCTL_STOP_SIGMASK;

	task->jobctl |= mask;
	return true;
}

void task_clear_jobctl_trapping(struct task_struct *task)
{
	if (unlikely(task->jobctl & JOBCTL_TRAPPING)) {
		task->jobctl &= ~JOBCTL_TRAPPING;
		smp_mb();	/* advised by wake_up_bit() */
		wake_up_bit(&task->jobctl, JOBCTL_TRAPPING_BIT);
	}
}

void task_clear_jobctl_pending(struct task_struct *task, unsigned long mask)
{
	BUG_ON(mask & ~JOBCTL_PENDING_MASK);

	if (mask & JOBCTL_STOP_PENDING)
		mask |= JOBCTL_STOP_CONSUME | JOBCTL_STOP_DEQUEUED;

	task->jobctl &= ~mask;

	if (!(task->jobctl & JOBCTL_PENDING_MASK))
		task_clear_jobctl_trapping(task);
}

static bool task_participate_group_stop(struct task_struct *task)
{
	struct signal_struct *sig = task->signal;
	bool consume = task->jobctl & JOBCTL_STOP_CONSUME;

	WARN_ON_ONCE(!(task->jobctl & JOBCTL_STOP_PENDING));

	task_clear_jobctl_pending(task, JOBCTL_STOP_PENDING);

	if (!consume)
		return false;

	if (!WARN_ON_ONCE(sig->group_stop_count == 0))
		sig->group_stop_count--;

	/*
	if (!sig->group_stop_count && !(sig->flags & SIGNAL_STOP_STOPPED)) {
		signal_set_stop_flags(sig, SIGNAL_STOP_STOPPED);
		return true;
	}
	return false;
}

void task_join_group_stop(struct task_struct *task)
{
	unsigned long mask = current->jobctl & JOBCTL_STOP_SIGMASK;
	struct signal_struct *sig = current->signal;

	if (sig->group_stop_count) {
		sig->group_stop_count++;
		mask |= JOBCTL_STOP_CONSUME;
	} else if (!(sig->flags & SIGNAL_STOP_STOPPED))
		return;

	/* Have the new thread join an on-going signal group stop */
	task_set_jobctl_pending(task, mask | JOBCTL_STOP_PENDING);
}

static struct sigqueue *
__sigqueue_alloc(int sig, struct task_struct *t, gfp_t gfp_flags,
		 int override_rlimit, const unsigned int sigqueue_flags)
{
	struct sigqueue *q = NULL;
	struct ucounts *ucounts = NULL;
	long sigpending;

	/*
	rcu_read_lock();
	ucounts = task_ucounts(t);
	sigpending = inc_rlimit_get_ucounts(ucounts, UCOUNT_RLIMIT_SIGPENDING);
	rcu_read_unlock();
	if (!sigpending)
		return NULL;

	if (override_rlimit || likely(sigpending <= task_rlimit(t, RLIMIT_SIGPENDING))) {
		q = kmem_cache_alloc(sigqueue_cachep, gfp_flags);
	} else {
		print_dropped_signal(sig);
	}

	if (unlikely(q == NULL)) {
		dec_rlimit_put_ucounts(ucounts, UCOUNT_RLIMIT_SIGPENDING);
	} else {
		INIT_LIST_HEAD(&q->list);
		q->flags = sigqueue_flags;
		q->ucounts = ucounts;
	}
	return q;
}

static void __sigqueue_free(struct sigqueue *q)
{
	if (q->flags & SIGQUEUE_PREALLOC)
		return;
	if (q->ucounts) {
		dec_rlimit_put_ucounts(q->ucounts, UCOUNT_RLIMIT_SIGPENDING);
		q->ucounts = NULL;
	}
	kmem_cache_free(sigqueue_cachep, q);
}

void flush_sigqueue(struct sigpending *queue)
{
	struct sigqueue *q;

	sigemptyset(&queue->signal);
	while (!list_empty(&queue->list)) {
		q = list_entry(queue->list.next, struct sigqueue , list);
		list_del_init(&q->list);
		__sigqueue_free(q);
	}
}

void flush_signals(struct task_struct *t)
{
	unsigned long flags;

	spin_lock_irqsave(&t->sighand->siglock, flags);
	clear_tsk_thread_flag(t, TIF_SIGPENDING);
	flush_sigqueue(&t->pending);
	flush_sigqueue(&t->signal->shared_pending);
	spin_unlock_irqrestore(&t->sighand->siglock, flags);
}
EXPORT_SYMBOL(flush_signals);

#ifdef CONFIG_POSIX_TIMERS
static void __flush_itimer_signals(struct sigpending *pending)
{
	sigset_t signal, retain;
	struct sigqueue *q, *n;

	signal = pending->signal;
	sigemptyset(&retain);

	list_for_each_entry_safe(q, n, &pending->list, list) {
		int sig = q->info.si_signo;

		if (likely(q->info.si_code != SI_TIMER)) {
			sigaddset(&retain, sig);
		} else {
			sigdelset(&signal, sig);
			list_del_init(&q->list);
			__sigqueue_free(q);
		}
	}

	sigorsets(&pending->signal, &signal, &retain);
}

void flush_itimer_signals(void)
{
	struct task_struct *tsk = current;
	unsigned long flags;

	spin_lock_irqsave(&tsk->sighand->siglock, flags);
	__flush_itimer_signals(&tsk->pending);
	__flush_itimer_signals(&tsk->signal->shared_pending);
	spin_unlock_irqrestore(&tsk->sighand->siglock, flags);
}
#endif

void ignore_signals(struct task_struct *t)
{
	int i;

	for (i = 0; i < _NSIG; ++i)
		t->sighand->action[i].sa.sa_handler = SIG_IGN;

	flush_signals(t);
}


void
flush_signal_handlers(struct task_struct *t, int force_default)
{
	int i;
	struct k_sigaction *ka = &t->sighand->action[0];
	for (i = _NSIG ; i != 0 ; i--) {
		if (force_default || ka->sa.sa_handler != SIG_IGN)
			ka->sa.sa_handler = SIG_DFL;
		ka->sa.sa_flags = 0;
#ifdef __ARCH_HAS_SA_RESTORER
		ka->sa.sa_restorer = NULL;
#endif
		sigemptyset(&ka->sa.sa_mask);
		ka++;
	}
}

bool unhandled_signal(struct task_struct *tsk, int sig)
{
	void __user *handler = tsk->sighand->action[sig-1].sa.sa_handler;
	if (is_global_init(tsk))
		return true;

	if (handler != SIG_IGN && handler != SIG_DFL)
		return false;

	/* if ptraced, let the tracer determine */
	return !tsk->ptrace;
}

static void collect_signal(int sig, struct sigpending *list, kernel_siginfo_t *info,
			   bool *resched_timer)
{
	struct sigqueue *q, *first = NULL;

	/*
	list_for_each_entry(q, &list->list, list) {
		if (q->info.si_signo == sig) {
			if (first)
				goto still_pending;
			first = q;
		}
	}

	sigdelset(&list->signal, sig);

	if (first) {
still_pending:
		list_del_init(&first->list);
		copy_siginfo(info, &first->info);

		*resched_timer =
			(first->flags & SIGQUEUE_PREALLOC) &&
			(info->si_code == SI_TIMER) &&
			(info->si_sys_private);

		__sigqueue_free(first);
	} else {
		/*
		clear_siginfo(info);
		info->si_signo = sig;
		info->si_errno = 0;
		info->si_code = SI_USER;
		info->si_pid = 0;
		info->si_uid = 0;
	}
}

static int __dequeue_signal(struct sigpending *pending, sigset_t *mask,
			kernel_siginfo_t *info, bool *resched_timer)
{
	int sig = next_signal(pending, mask);

	if (sig)
		collect_signal(sig, pending, info, resched_timer);
	return sig;
}

int dequeue_signal(struct task_struct *tsk, sigset_t *mask,
		   kernel_siginfo_t *info, enum pid_type *type)
{
	bool resched_timer = false;
	int signr;

	/* We only dequeue private signals from ourselves, we don't let
	 * signalfd steal them
	 */
	signr = __dequeue_signal(&tsk->pending, mask, info, &resched_timer);
	if (!signr) {
		*type = PIDTYPE_TGID;
		signr = __dequeue_signal(&tsk->signal->shared_pending,
					 mask, info, &resched_timer);
#ifdef CONFIG_POSIX_TIMERS
		/*
		if (unlikely(signr == SIGALRM)) {
			struct hrtimer *tmr = &tsk->signal->real_timer;

			if (!hrtimer_is_queued(tmr) &&
			    tsk->signal->it_real_incr != 0) {
				hrtimer_forward(tmr, tmr->base->get_time(),
						tsk->signal->it_real_incr);
				hrtimer_restart(tmr);
			}
		}
#endif
	}

	recalc_sigpending();
	if (!signr)
		return 0;

	if (unlikely(sig_kernel_stop(signr))) {
		/*
		current->jobctl |= JOBCTL_STOP_DEQUEUED;
	}
#ifdef CONFIG_POSIX_TIMERS
	if (resched_timer) {
		/*
		spin_unlock(&tsk->sighand->siglock);
		posixtimer_rearm(info);
		spin_lock(&tsk->sighand->siglock);

		/* Don't expose the si_sys_private value to userspace */
		info->si_sys_private = 0;
	}
#endif
	return signr;
}
EXPORT_SYMBOL_GPL(dequeue_signal);

static int dequeue_synchronous_signal(kernel_siginfo_t *info)
{
	struct task_struct *tsk = current;
	struct sigpending *pending = &tsk->pending;
	struct sigqueue *q, *sync = NULL;

	/*
	if (!((pending->signal.sig[0] & ~tsk->blocked.sig[0]) & SYNCHRONOUS_MASK))
		return 0;

	/*
	list_for_each_entry(q, &pending->list, list) {
		/* Synchronous signals have a positive si_code */
		if ((q->info.si_code > SI_USER) &&
		    (sigmask(q->info.si_signo) & SYNCHRONOUS_MASK)) {
			sync = q;
			goto next;
		}
	}
	return 0;
next:
	/*
	list_for_each_entry_continue(q, &pending->list, list) {
		if (q->info.si_signo == sync->info.si_signo)
			goto still_pending;
	}

	sigdelset(&pending->signal, sync->info.si_signo);
	recalc_sigpending();
still_pending:
	list_del_init(&sync->list);
	copy_siginfo(info, &sync->info);
	__sigqueue_free(sync);
	return info->si_signo;
}

void signal_wake_up_state(struct task_struct *t, unsigned int state)
{
	lockdep_assert_held(&t->sighand->siglock);

	set_tsk_thread_flag(t, TIF_SIGPENDING);

	/*
	if (!wake_up_state(t, state | TASK_INTERRUPTIBLE))
		kick_process(t);
}

static void flush_sigqueue_mask(sigset_t *mask, struct sigpending *s)
{
	struct sigqueue *q, *n;
	sigset_t m;

	sigandsets(&m, mask, &s->signal);
	if (sigisemptyset(&m))
		return;

	sigandnsets(&s->signal, &s->signal, mask);
	list_for_each_entry_safe(q, n, &s->list, list) {
		if (sigismember(mask, q->info.si_signo)) {
			list_del_init(&q->list);
			__sigqueue_free(q);
		}
	}
}

static inline int is_si_special(const struct kernel_siginfo *info)
{
	return info <= SEND_SIG_PRIV;
}

static inline bool si_fromuser(const struct kernel_siginfo *info)
{
	return info == SEND_SIG_NOINFO ||
		(!is_si_special(info) && SI_FROMUSER(info));
}

static bool kill_ok_by_cred(struct task_struct *t)
{
	const struct cred *cred = current_cred();
	const struct cred *tcred = __task_cred(t);

	return uid_eq(cred->euid, tcred->suid) ||
	       uid_eq(cred->euid, tcred->uid) ||
	       uid_eq(cred->uid, tcred->suid) ||
	       uid_eq(cred->uid, tcred->uid) ||
	       ns_capable(tcred->user_ns, CAP_KILL);
}

static int check_kill_permission(int sig, struct kernel_siginfo *info,
				 struct task_struct *t)
{
	struct pid *sid;
	int error;

	if (!valid_signal(sig))
		return -EINVAL;

	if (!si_fromuser(info))
		return 0;

	error = audit_signal_info(sig, t); /* Let audit system see the signal */
	if (error)
		return error;

	if (!same_thread_group(current, t) &&
	    !kill_ok_by_cred(t)) {
		switch (sig) {
		case SIGCONT:
			sid = task_session(t);
			/*
			if (!sid || sid == task_session(current))
				break;
			fallthrough;
		default:
			return -EPERM;
		}
	}

	return security_task_kill(t, info, sig, NULL);
}

static void ptrace_trap_notify(struct task_struct *t)
{
	WARN_ON_ONCE(!(t->ptrace & PT_SEIZED));
	lockdep_assert_held(&t->sighand->siglock);

	task_set_jobctl_pending(t, JOBCTL_TRAP_NOTIFY);
	ptrace_signal_wake_up(t, t->jobctl & JOBCTL_LISTENING);
}

static bool prepare_signal(int sig, struct task_struct *p, bool force)
{
	struct signal_struct *signal = p->signal;
	struct task_struct *t;
	sigset_t flush;

	if (signal->flags & SIGNAL_GROUP_EXIT) {
		if (signal->core_state)
			return sig == SIGKILL;
		/*
	} else if (sig_kernel_stop(sig)) {
		/*
		siginitset(&flush, sigmask(SIGCONT));
		flush_sigqueue_mask(&flush, &signal->shared_pending);
		for_each_thread(p, t)
			flush_sigqueue_mask(&flush, &t->pending);
	} else if (sig == SIGCONT) {
		unsigned int why;
		/*
		siginitset(&flush, SIG_KERNEL_STOP_MASK);
		flush_sigqueue_mask(&flush, &signal->shared_pending);
		for_each_thread(p, t) {
			flush_sigqueue_mask(&flush, &t->pending);
			task_clear_jobctl_pending(t, JOBCTL_STOP_PENDING);
			if (likely(!(t->ptrace & PT_SEIZED))) {
				t->jobctl &= ~JOBCTL_STOPPED;
				wake_up_state(t, __TASK_STOPPED);
			} else
				ptrace_trap_notify(t);
		}

		/*
		why = 0;
		if (signal->flags & SIGNAL_STOP_STOPPED)
			why |= SIGNAL_CLD_CONTINUED;
		else if (signal->group_stop_count)
			why |= SIGNAL_CLD_STOPPED;

		if (why) {
			/*
			signal_set_stop_flags(signal, why | SIGNAL_STOP_CONTINUED);
			signal->group_stop_count = 0;
			signal->group_exit_code = 0;
		}
	}

	return !sig_ignored(p, sig, force);
}

static inline bool wants_signal(int sig, struct task_struct *p)
{
	if (sigismember(&p->blocked, sig))
		return false;

	if (p->flags & PF_EXITING)
		return false;

	if (sig == SIGKILL)
		return true;

	if (task_is_stopped_or_traced(p))
		return false;

	return task_curr(p) || !task_sigpending(p);
}

static void complete_signal(int sig, struct task_struct *p, enum pid_type type)
{
	struct signal_struct *signal = p->signal;
	struct task_struct *t;

	/*
	if (wants_signal(sig, p))
		t = p;
	else if ((type == PIDTYPE_PID) || thread_group_empty(p))
		/*
		return;
	else {
		/*
		t = signal->curr_target;
		while (!wants_signal(sig, t)) {
			t = next_thread(t);
			if (t == signal->curr_target)
				/*
				return;
		}
		signal->curr_target = t;
	}

	/*
	if (sig_fatal(p, sig) &&
	    (signal->core_state || !(signal->flags & SIGNAL_GROUP_EXIT)) &&
	    !sigismember(&t->real_blocked, sig) &&
	    (sig == SIGKILL || !p->ptrace)) {
		/*
		if (!sig_kernel_coredump(sig)) {
			/*
			signal->flags = SIGNAL_GROUP_EXIT;
			signal->group_exit_code = sig;
			signal->group_stop_count = 0;
			t = p;
			do {
				task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
				sigaddset(&t->pending.signal, SIGKILL);
				signal_wake_up(t, 1);
			} while_each_thread(p, t);
			return;
		}
	}

	/*
	signal_wake_up(t, sig == SIGKILL);
	return;
}

static inline bool legacy_queue(struct sigpending *signals, int sig)
{
	return (sig < SIGRTMIN) && sigismember(&signals->signal, sig);
}

static int __send_signal_locked(int sig, struct kernel_siginfo *info,
				struct task_struct *t, enum pid_type type, bool force)
{
	struct sigpending *pending;
	struct sigqueue *q;
	int override_rlimit;
	int ret = 0, result;

	lockdep_assert_held(&t->sighand->siglock);

	result = TRACE_SIGNAL_IGNORED;
	if (!prepare_signal(sig, t, force))
		goto ret;

	pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;
	/*
	result = TRACE_SIGNAL_ALREADY_PENDING;
	if (legacy_queue(pending, sig))
		goto ret;

	result = TRACE_SIGNAL_DELIVERED;
	/*
	if ((sig == SIGKILL) || (t->flags & PF_KTHREAD))
		goto out_set;

	/*
	if (sig < SIGRTMIN)
		override_rlimit = (is_si_special(info) || info->si_code >= 0);
	else
		override_rlimit = 0;

	q = __sigqueue_alloc(sig, t, GFP_ATOMIC, override_rlimit, 0);

	if (q) {
		list_add_tail(&q->list, &pending->list);
		switch ((unsigned long) info) {
		case (unsigned long) SEND_SIG_NOINFO:
			clear_siginfo(&q->info);
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_USER;
			q->info.si_pid = task_tgid_nr_ns(current,
							task_active_pid_ns(t));
			rcu_read_lock();
			q->info.si_uid =
				from_kuid_munged(task_cred_xxx(t, user_ns),
						 current_uid());
			rcu_read_unlock();
			break;
		case (unsigned long) SEND_SIG_PRIV:
			clear_siginfo(&q->info);
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_KERNEL;
			q->info.si_pid = 0;
			q->info.si_uid = 0;
			break;
		default:
			copy_siginfo(&q->info, info);
			break;
		}
	} else if (!is_si_special(info) &&
		   sig >= SIGRTMIN && info->si_code != SI_USER) {
		/*
		result = TRACE_SIGNAL_OVERFLOW_FAIL;
		ret = -EAGAIN;
		goto ret;
	} else {
		/*
		result = TRACE_SIGNAL_LOSE_INFO;
	}

out_set:
	signalfd_notify(t, sig);
	sigaddset(&pending->signal, sig);

	/* Let multiprocess signals appear after on-going forks */
	if (type > PIDTYPE_TGID) {
		struct multiprocess_signals *delayed;
		hlist_for_each_entry(delayed, &t->signal->multiprocess, node) {
			sigset_t *signal = &delayed->signal;
			/* Can't queue both a stop and a continue signal */
			if (sig == SIGCONT)
				sigdelsetmask(signal, SIG_KERNEL_STOP_MASK);
			else if (sig_kernel_stop(sig))
				sigdelset(signal, SIGCONT);
			sigaddset(signal, sig);
		}
	}

	complete_signal(sig, t, type);
ret:
	trace_signal_generate(sig, info, t, type != PIDTYPE_PID, result);
	return ret;
}

static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
{
	bool ret = false;
	switch (siginfo_layout(info->si_signo, info->si_code)) {
	case SIL_KILL:
	case SIL_CHLD:
	case SIL_RT:
		ret = true;
		break;
	case SIL_TIMER:
	case SIL_POLL:
	case SIL_FAULT:
	case SIL_FAULT_TRAPNO:
	case SIL_FAULT_MCEERR:
	case SIL_FAULT_BNDERR:
	case SIL_FAULT_PKUERR:
	case SIL_FAULT_PERF_EVENT:
	case SIL_SYS:
		ret = false;
		break;
	}
	return ret;
}

int send_signal_locked(int sig, struct kernel_siginfo *info,
		       struct task_struct *t, enum pid_type type)
{
	/* Should SIGKILL or SIGSTOP be received by a pid namespace init? */
	bool force = false;

	if (info == SEND_SIG_NOINFO) {
		/* Force if sent from an ancestor pid namespace */
		force = !task_pid_nr_ns(current, task_active_pid_ns(t));
	} else if (info == SEND_SIG_PRIV) {
		/* Don't ignore kernel generated signals */
		force = true;
	} else if (has_si_pid_and_uid(info)) {
		/* SIGKILL and SIGSTOP is special or has ids */
		struct user_namespace *t_user_ns;

		rcu_read_lock();
		t_user_ns = task_cred_xxx(t, user_ns);
		if (current_user_ns() != t_user_ns) {
			kuid_t uid = make_kuid(current_user_ns(), info->si_uid);
			info->si_uid = from_kuid_munged(t_user_ns, uid);
		}
		rcu_read_unlock();

		/* A kernel generated signal? */
		force = (info->si_code == SI_KERNEL);

		/* From an ancestor pid namespace? */
		if (!task_pid_nr_ns(current, task_active_pid_ns(t))) {
			info->si_pid = 0;
			force = true;
		}
	}
	return __send_signal_locked(sig, info, t, type, force);
}

static void print_fatal_signal(int signr)
{
	struct pt_regs *regs = signal_pt_regs();
	pr_info("potentially unexpected fatal signal %d.\n", signr);

#if defined(__i386__) && !defined(__arch_um__)
	pr_info("code at %08lx: ", regs->ip);
	{
		int i;
		for (i = 0; i < 16; i++) {
			unsigned char insn;

			if (get_user(insn, (unsigned char *)(regs->ip + i)))
				break;
			pr_cont("%02x ", insn);
		}
	}
	pr_cont("\n");
#endif
	preempt_disable();
	show_regs(regs);
	preempt_enable();
}

static int __init setup_print_fatal_signals(char *str)
{
	get_option (&str, &print_fatal_signals);

	return 1;
}

__setup("print-fatal-signals=", setup_print_fatal_signals);

int do_send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p,
			enum pid_type type)
{
	unsigned long flags;
	int ret = -ESRCH;

	if (lock_task_sighand(p, &flags)) {
		ret = send_signal_locked(sig, info, p, type);
		unlock_task_sighand(p, &flags);
	}

	return ret;
}

enum sig_handler {
	HANDLER_CURRENT, /* If reachable use the current handler */
	HANDLER_SIG_DFL, /* Always use SIG_DFL handler semantics */
	HANDLER_EXIT,	 /* Only visible as the process exit code */
};

static int
force_sig_info_to_task(struct kernel_siginfo *info, struct task_struct *t,
	enum sig_handler handler)
{
	unsigned long int flags;
	int ret, blocked, ignored;
	struct k_sigaction *action;
	int sig = info->si_signo;

	spin_lock_irqsave(&t->sighand->siglock, flags);
	action = &t->sighand->action[sig-1];
	ignored = action->sa.sa_handler == SIG_IGN;
	blocked = sigismember(&t->blocked, sig);
	if (blocked || ignored || (handler != HANDLER_CURRENT)) {
		action->sa.sa_handler = SIG_DFL;
		if (handler == HANDLER_EXIT)
			action->sa.sa_flags |= SA_IMMUTABLE;
		if (blocked) {
			sigdelset(&t->blocked, sig);
			recalc_sigpending_and_wake(t);
		}
	}
	/*
	if (action->sa.sa_handler == SIG_DFL &&
	    (!t->ptrace || (handler == HANDLER_EXIT)))
		t->signal->flags &= ~SIGNAL_UNKILLABLE;
	ret = send_signal_locked(sig, info, t, PIDTYPE_PID);
	spin_unlock_irqrestore(&t->sighand->siglock, flags);

	return ret;
}

int force_sig_info(struct kernel_siginfo *info)
{
	return force_sig_info_to_task(info, current, HANDLER_CURRENT);
}

int zap_other_threads(struct task_struct *p)
{
	struct task_struct *t = p;
	int count = 0;

	p->signal->group_stop_count = 0;

	while_each_thread(p, t) {
		task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
		count++;

		/* Don't bother with already dead threads */
		if (t->exit_state)
			continue;
		sigaddset(&t->pending.signal, SIGKILL);
		signal_wake_up(t, 1);
	}

	return count;
}

struct sighand_struct *__lock_task_sighand(struct task_struct *tsk,
					   unsigned long *flags)
{
	struct sighand_struct *sighand;

	rcu_read_lock();
	for (;;) {
		sighand = rcu_dereference(tsk->sighand);
		if (unlikely(sighand == NULL))
			break;

		/*
		spin_lock_irqsave(&sighand->siglock, *flags);
		if (likely(sighand == rcu_access_pointer(tsk->sighand)))
			break;
		spin_unlock_irqrestore(&sighand->siglock, *flags);
	}
	rcu_read_unlock();

	return sighand;
}

#ifdef CONFIG_LOCKDEP
void lockdep_assert_task_sighand_held(struct task_struct *task)
{
	struct sighand_struct *sighand;

	rcu_read_lock();
	sighand = rcu_dereference(task->sighand);
	if (sighand)
		lockdep_assert_held(&sighand->siglock);
	else
		WARN_ON_ONCE(1);
	rcu_read_unlock();
}
#endif

int group_send_sig_info(int sig, struct kernel_siginfo *info,
			struct task_struct *p, enum pid_type type)
{
	int ret;

	rcu_read_lock();
	ret = check_kill_permission(sig, info, p);
	rcu_read_unlock();

	if (!ret && sig)
		ret = do_send_sig_info(sig, info, p, type);

	return ret;
}

int __kill_pgrp_info(int sig, struct kernel_siginfo *info, struct pid *pgrp)
{
	struct task_struct *p = NULL;
	int retval, success;

	success = 0;
	retval = -ESRCH;
	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
		int err = group_send_sig_info(sig, info, p, PIDTYPE_PGID);
		success |= !err;
		retval = err;
	} while_each_pid_task(pgrp, PIDTYPE_PGID, p);
	return success ? 0 : retval;
}

int kill_pid_info(int sig, struct kernel_siginfo *info, struct pid *pid)
{
	int error = -ESRCH;
	struct task_struct *p;

	for (;;) {
		rcu_read_lock();
		p = pid_task(pid, PIDTYPE_PID);
		if (p)
			error = group_send_sig_info(sig, info, p, PIDTYPE_TGID);
		rcu_read_unlock();
		if (likely(!p || error != -ESRCH))
			return error;

		/*
	}
}

static int kill_proc_info(int sig, struct kernel_siginfo *info, pid_t pid)
{
	int error;
	rcu_read_lock();
	error = kill_pid_info(sig, info, find_vpid(pid));
	rcu_read_unlock();
	return error;
}

static inline bool kill_as_cred_perm(const struct cred *cred,
				     struct task_struct *target)
{
	const struct cred *pcred = __task_cred(target);

	return uid_eq(cred->euid, pcred->suid) ||
	       uid_eq(cred->euid, pcred->uid) ||
	       uid_eq(cred->uid, pcred->suid) ||
	       uid_eq(cred->uid, pcred->uid);
}

int kill_pid_usb_asyncio(int sig, int errno, sigval_t addr,
			 struct pid *pid, const struct cred *cred)
{
	struct kernel_siginfo info;
	struct task_struct *p;
	unsigned long flags;
	int ret = -EINVAL;

	if (!valid_signal(sig))
		return ret;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = errno;
	info.si_code = SI_ASYNCIO;

	rcu_read_lock();
	p = pid_task(pid, PIDTYPE_PID);
	if (!p) {
		ret = -ESRCH;
		goto out_unlock;
	}
	if (!kill_as_cred_perm(cred, p)) {
		ret = -EPERM;
		goto out_unlock;
	}
	ret = security_task_kill(p, &info, sig, cred);
	if (ret)
		goto out_unlock;

	if (sig) {
		if (lock_task_sighand(p, &flags)) {
			ret = __send_signal_locked(sig, &info, p, PIDTYPE_TGID, false);
			unlock_task_sighand(p, &flags);
		} else
			ret = -ESRCH;
	}
out_unlock:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(kill_pid_usb_asyncio);


static int kill_something_info(int sig, struct kernel_siginfo *info, pid_t pid)
{
	int ret;

	if (pid > 0)
		return kill_proc_info(sig, info, pid);

	/* -INT_MIN is undefined.  Exclude this case to avoid a UBSAN warning */
	if (pid == INT_MIN)
		return -ESRCH;

	read_lock(&tasklist_lock);
	if (pid != -1) {
		ret = __kill_pgrp_info(sig, info,
				pid ? find_vpid(-pid) : task_pgrp(current));
	} else {
		int retval = 0, count = 0;
		struct task_struct * p;

		for_each_process(p) {
			if (task_pid_vnr(p) > 1 &&
					!same_thread_group(p, current)) {
				int err = group_send_sig_info(sig, info, p,
							      PIDTYPE_MAX);
				++count;
				if (err != -EPERM)
					retval = err;
			}
		}
		ret = count ? retval : -ESRCH;
	}
	read_unlock(&tasklist_lock);

	return ret;
}


int send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p)
{
	/*
	if (!valid_signal(sig))
		return -EINVAL;

	return do_send_sig_info(sig, info, p, PIDTYPE_PID);
}
EXPORT_SYMBOL(send_sig_info);

#define __si_special(priv) \
	((priv) ? SEND_SIG_PRIV : SEND_SIG_NOINFO)

int
send_sig(int sig, struct task_struct *p, int priv)
{
	return send_sig_info(sig, __si_special(priv), p);
}
EXPORT_SYMBOL(send_sig);

void force_sig(int sig)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_KERNEL;
	info.si_pid = 0;
	info.si_uid = 0;
	force_sig_info(&info);
}
EXPORT_SYMBOL(force_sig);

void force_fatal_sig(int sig)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_KERNEL;
	info.si_pid = 0;
	info.si_uid = 0;
	force_sig_info_to_task(&info, current, HANDLER_SIG_DFL);
}

void force_exit_sig(int sig)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_KERNEL;
	info.si_pid = 0;
	info.si_uid = 0;
	force_sig_info_to_task(&info, current, HANDLER_EXIT);
}

void force_sigsegv(int sig)
{
	if (sig == SIGSEGV)
		force_fatal_sig(SIGSEGV);
	else
		force_sig(SIGSEGV);
}

int force_sig_fault_to_task(int sig, int code, void __user *addr
	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
	, struct task_struct *t)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code  = code;
	info.si_addr  = addr;
#ifdef __ia64__
	info.si_imm = imm;
	info.si_flags = flags;
	info.si_isr = isr;
#endif
	return force_sig_info_to_task(&info, t, HANDLER_CURRENT);
}

int force_sig_fault(int sig, int code, void __user *addr
	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr))
{
	return force_sig_fault_to_task(sig, code, addr
				       ___ARCH_SI_IA64(imm, flags, isr), current);
}

int send_sig_fault(int sig, int code, void __user *addr
	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
	, struct task_struct *t)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code  = code;
	info.si_addr  = addr;
#ifdef __ia64__
	info.si_imm = imm;
	info.si_flags = flags;
	info.si_isr = isr;
#endif
	return send_sig_info(info.si_signo, &info, t);
}

int force_sig_mceerr(int code, void __user *addr, short lsb)
{
	struct kernel_siginfo info;

	WARN_ON((code != BUS_MCEERR_AO) && (code != BUS_MCEERR_AR));
	clear_siginfo(&info);
	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code = code;
	info.si_addr = addr;
	info.si_addr_lsb = lsb;
	return force_sig_info(&info);
}

int send_sig_mceerr(int code, void __user *addr, short lsb, struct task_struct *t)
{
	struct kernel_siginfo info;

	WARN_ON((code != BUS_MCEERR_AO) && (code != BUS_MCEERR_AR));
	clear_siginfo(&info);
	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code = code;
	info.si_addr = addr;
	info.si_addr_lsb = lsb;
	return send_sig_info(info.si_signo, &info, t);
}
EXPORT_SYMBOL(send_sig_mceerr);

int force_sig_bnderr(void __user *addr, void __user *lower, void __user *upper)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = SIGSEGV;
	info.si_errno = 0;
	info.si_code  = SEGV_BNDERR;
	info.si_addr  = addr;
	info.si_lower = lower;
	info.si_upper = upper;
	return force_sig_info(&info);
}

#ifdef SEGV_PKUERR
int force_sig_pkuerr(void __user *addr, u32 pkey)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = SIGSEGV;
	info.si_errno = 0;
	info.si_code  = SEGV_PKUERR;
	info.si_addr  = addr;
	info.si_pkey  = pkey;
	return force_sig_info(&info);
}
#endif

int send_sig_perf(void __user *addr, u32 type, u64 sig_data)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo     = SIGTRAP;
	info.si_errno     = 0;
	info.si_code      = TRAP_PERF;
	info.si_addr      = addr;
	info.si_perf_data = sig_data;
	info.si_perf_type = type;

	/*
	info.si_perf_flags = sigismember(&current->blocked, info.si_signo) ?
				     TRAP_PERF_FLAG_ASYNC :
				     0;

	return send_sig_info(info.si_signo, &info, current);
}

int force_sig_seccomp(int syscall, int reason, bool force_coredump)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = SIGSYS;
	info.si_code = SYS_SECCOMP;
	info.si_call_addr = (void __user *)KSTK_EIP(current);
	info.si_errno = reason;
	info.si_arch = syscall_get_arch(current);
	info.si_syscall = syscall;
	return force_sig_info_to_task(&info, current,
		force_coredump ? HANDLER_EXIT : HANDLER_CURRENT);
}

int force_sig_ptrace_errno_trap(int errno, void __user *addr)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = SIGTRAP;
	info.si_errno = errno;
	info.si_code  = TRAP_HWBKPT;
	info.si_addr  = addr;
	return force_sig_info(&info);
}

int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code  = code;
	info.si_addr  = addr;
	info.si_trapno = trapno;
	return force_sig_info(&info);
}

int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
			  struct task_struct *t)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code  = code;
	info.si_addr  = addr;
	info.si_trapno = trapno;
	return send_sig_info(info.si_signo, &info, t);
}

int kill_pgrp(struct pid *pid, int sig, int priv)
{
	int ret;

	read_lock(&tasklist_lock);
	ret = __kill_pgrp_info(sig, __si_special(priv), pid);
	read_unlock(&tasklist_lock);

	return ret;
}
EXPORT_SYMBOL(kill_pgrp);

int kill_pid(struct pid *pid, int sig, int priv)
{
	return kill_pid_info(sig, __si_special(priv), pid);
}
EXPORT_SYMBOL(kill_pid);

struct sigqueue *sigqueue_alloc(void)
{
	return __sigqueue_alloc(-1, current, GFP_KERNEL, 0, SIGQUEUE_PREALLOC);
}

void sigqueue_free(struct sigqueue *q)
{
	unsigned long flags;
	spinlock_t *lock = &current->sighand->siglock;

	BUG_ON(!(q->flags & SIGQUEUE_PREALLOC));
	/*
	spin_lock_irqsave(lock, flags);
	q->flags &= ~SIGQUEUE_PREALLOC;
	/*
	if (!list_empty(&q->list))
		q = NULL;
	spin_unlock_irqrestore(lock, flags);

	if (q)
		__sigqueue_free(q);
}

int send_sigqueue(struct sigqueue *q, struct pid *pid, enum pid_type type)
{
	int sig = q->info.si_signo;
	struct sigpending *pending;
	struct task_struct *t;
	unsigned long flags;
	int ret, result;

	BUG_ON(!(q->flags & SIGQUEUE_PREALLOC));

	ret = -1;
	rcu_read_lock();
	t = pid_task(pid, type);
	if (!t || !likely(lock_task_sighand(t, &flags)))
		goto ret;

	ret = 1; /* the signal is ignored */
	result = TRACE_SIGNAL_IGNORED;
	if (!prepare_signal(sig, t, false))
		goto out;

	ret = 0;
	if (unlikely(!list_empty(&q->list))) {
		/*
		BUG_ON(q->info.si_code != SI_TIMER);
		q->info.si_overrun++;
		result = TRACE_SIGNAL_ALREADY_PENDING;
		goto out;
	}
	q->info.si_overrun = 0;

	signalfd_notify(t, sig);
	pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;
	list_add_tail(&q->list, &pending->list);
	sigaddset(&pending->signal, sig);
	complete_signal(sig, t, type);
	result = TRACE_SIGNAL_DELIVERED;
out:
	trace_signal_generate(sig, &q->info, t, type != PIDTYPE_PID, result);
	unlock_task_sighand(t, &flags);
ret:
	rcu_read_unlock();
	return ret;
}

static void do_notify_pidfd(struct task_struct *task)
{
	struct pid *pid;

	WARN_ON(task->exit_state == 0);
	pid = task_pid(task);
	wake_up_all(&pid->wait_pidfd);
}

bool do_notify_parent(struct task_struct *tsk, int sig)
{
	struct kernel_siginfo info;
	unsigned long flags;
	struct sighand_struct *psig;
	bool autoreap = false;
	u64 utime, stime;

	WARN_ON_ONCE(sig == -1);

	/* do_notify_parent_cldstop should have been called instead.  */
	WARN_ON_ONCE(task_is_stopped_or_traced(tsk));

	WARN_ON_ONCE(!tsk->ptrace &&
	       (tsk->group_leader != tsk || !thread_group_empty(tsk)));

	/* Wake up all pidfd waiters */
	do_notify_pidfd(tsk);

	if (sig != SIGCHLD) {
		/*
		if (tsk->parent_exec_id != READ_ONCE(tsk->parent->self_exec_id))
			sig = SIGCHLD;
	}

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	/*
	rcu_read_lock();
	info.si_pid = task_pid_nr_ns(tsk, task_active_pid_ns(tsk->parent));
	info.si_uid = from_kuid_munged(task_cred_xxx(tsk->parent, user_ns),
				       task_uid(tsk));
	rcu_read_unlock();

	task_cputime(tsk, &utime, &stime);
	info.si_utime = nsec_to_clock_t(utime + tsk->signal->utime);
	info.si_stime = nsec_to_clock_t(stime + tsk->signal->stime);

	info.si_status = tsk->exit_code & 0x7f;
	if (tsk->exit_code & 0x80)
		info.si_code = CLD_DUMPED;
	else if (tsk->exit_code & 0x7f)
		info.si_code = CLD_KILLED;
	else {
		info.si_code = CLD_EXITED;
		info.si_status = tsk->exit_code >> 8;
	}

	psig = tsk->parent->sighand;
	spin_lock_irqsave(&psig->siglock, flags);
	if (!tsk->ptrace && sig == SIGCHLD &&
	    (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN ||
	     (psig->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDWAIT))) {
		/*
		autoreap = true;
		if (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN)
			sig = 0;
	}
	/*
	if (valid_signal(sig) && sig)
		__send_signal_locked(sig, &info, tsk->parent, PIDTYPE_TGID, false);
	__wake_up_parent(tsk, tsk->parent);
	spin_unlock_irqrestore(&psig->siglock, flags);

	return autoreap;
}

static void do_notify_parent_cldstop(struct task_struct *tsk,
				     bool for_ptracer, int why)
{
	struct kernel_siginfo info;
	unsigned long flags;
	struct task_struct *parent;
	struct sighand_struct *sighand;
	u64 utime, stime;

	if (for_ptracer) {
		parent = tsk->parent;
	} else {
		tsk = tsk->group_leader;
		parent = tsk->real_parent;
	}

	clear_siginfo(&info);
	info.si_signo = SIGCHLD;
	info.si_errno = 0;
	/*
	rcu_read_lock();
	info.si_pid = task_pid_nr_ns(tsk, task_active_pid_ns(parent));
	info.si_uid = from_kuid_munged(task_cred_xxx(parent, user_ns), task_uid(tsk));
	rcu_read_unlock();

	task_cputime(tsk, &utime, &stime);
	info.si_utime = nsec_to_clock_t(utime);
	info.si_stime = nsec_to_clock_t(stime);

 	info.si_code = why;
 	switch (why) {
 	case CLD_CONTINUED:
 		info.si_status = SIGCONT;
 		break;
 	case CLD_STOPPED:
 		info.si_status = tsk->signal->group_exit_code & 0x7f;
 		break;
 	case CLD_TRAPPED:
 		info.si_status = tsk->exit_code & 0x7f;
 		break;
 	default:
 		BUG();
 	}

	sighand = parent->sighand;
	spin_lock_irqsave(&sighand->siglock, flags);
	if (sighand->action[SIGCHLD-1].sa.sa_handler != SIG_IGN &&
	    !(sighand->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDSTOP))
		send_signal_locked(SIGCHLD, &info, parent, PIDTYPE_TGID);
	/*
	__wake_up_parent(tsk, parent);
	spin_unlock_irqrestore(&sighand->siglock, flags);
}

static int ptrace_stop(int exit_code, int why, unsigned long message,
		       kernel_siginfo_t *info)
	__releases(&current->sighand->siglock)
	__acquires(&current->sighand->siglock)
{
	bool gstop_done = false;

	if (arch_ptrace_stop_needed()) {
		/*
		spin_unlock_irq(&current->sighand->siglock);
		arch_ptrace_stop();
		spin_lock_irq(&current->sighand->siglock);
	}

	/*
	if (!current->ptrace || __fatal_signal_pending(current))
		return exit_code;

	set_special_state(TASK_TRACED);
	current->jobctl |= JOBCTL_TRACED;

	/*
	smp_wmb();

	current->ptrace_message = message;
	current->last_siginfo = info;
	current->exit_code = exit_code;

	/*
	if (why == CLD_STOPPED && (current->jobctl & JOBCTL_STOP_PENDING))
		gstop_done = task_participate_group_stop(current);

	/* any trap clears pending STOP trap, STOP trap clears NOTIFY */
	task_clear_jobctl_pending(current, JOBCTL_TRAP_STOP);
	if (info && info->si_code >> 8 == PTRACE_EVENT_STOP)
		task_clear_jobctl_pending(current, JOBCTL_TRAP_NOTIFY);

	/* entering a trap, clear TRAPPING */
	task_clear_jobctl_trapping(current);

	spin_unlock_irq(&current->sighand->siglock);
	read_lock(&tasklist_lock);
	/*
	if (current->ptrace)
		do_notify_parent_cldstop(current, true, why);
	if (gstop_done && (!current->ptrace || ptrace_reparented(current)))
		do_notify_parent_cldstop(current, false, why);

	/*
	preempt_disable();
	read_unlock(&tasklist_lock);
	cgroup_enter_frozen();
	preempt_enable_no_resched();
	freezable_schedule();
	cgroup_leave_frozen(true);

	/*
	spin_lock_irq(&current->sighand->siglock);
	exit_code = current->exit_code;
	current->last_siginfo = NULL;
	current->ptrace_message = 0;
	current->exit_code = 0;

	/* LISTENING can be set only during STOP traps, clear it */
	current->jobctl &= ~(JOBCTL_LISTENING | JOBCTL_PTRACE_FROZEN);

	/*
	recalc_sigpending_tsk(current);
	return exit_code;
}

static int ptrace_do_notify(int signr, int exit_code, int why, unsigned long message)
{
	kernel_siginfo_t info;

	clear_siginfo(&info);
	info.si_signo = signr;
	info.si_code = exit_code;
	info.si_pid = task_pid_vnr(current);
	info.si_uid = from_kuid_munged(current_user_ns(), current_uid());

	/* Let the debugger run.  */
	return ptrace_stop(exit_code, why, message, &info);
}

int ptrace_notify(int exit_code, unsigned long message)
{
	int signr;

	BUG_ON((exit_code & (0x7f | ~0xffff)) != SIGTRAP);
	if (unlikely(task_work_pending(current)))
		task_work_run();

	spin_lock_irq(&current->sighand->siglock);
	signr = ptrace_do_notify(SIGTRAP, exit_code, CLD_TRAPPED, message);
	spin_unlock_irq(&current->sighand->siglock);
	return signr;
}

static bool do_signal_stop(int signr)
	__releases(&current->sighand->siglock)
{
	struct signal_struct *sig = current->signal;

	if (!(current->jobctl & JOBCTL_STOP_PENDING)) {
		unsigned long gstop = JOBCTL_STOP_PENDING | JOBCTL_STOP_CONSUME;
		struct task_struct *t;

		/* signr will be recorded in task->jobctl for retries */
		WARN_ON_ONCE(signr & ~JOBCTL_STOP_SIGMASK);

		if (!likely(current->jobctl & JOBCTL_STOP_DEQUEUED) ||
		    unlikely(sig->flags & SIGNAL_GROUP_EXIT) ||
		    unlikely(sig->group_exec_task))
			return false;
		/*
		if (!(sig->flags & SIGNAL_STOP_STOPPED))
			sig->group_exit_code = signr;

		sig->group_stop_count = 0;

		if (task_set_jobctl_pending(current, signr | gstop))
			sig->group_stop_count++;

		t = current;
		while_each_thread(current, t) {
			/*
			if (!task_is_stopped(t) &&
			    task_set_jobctl_pending(t, signr | gstop)) {
				sig->group_stop_count++;
				if (likely(!(t->ptrace & PT_SEIZED)))
					signal_wake_up(t, 0);
				else
					ptrace_trap_notify(t);
			}
		}
	}

	if (likely(!current->ptrace)) {
		int notify = 0;

		/*
		if (task_participate_group_stop(current))
			notify = CLD_STOPPED;

		current->jobctl |= JOBCTL_STOPPED;
		set_special_state(TASK_STOPPED);
		spin_unlock_irq(&current->sighand->siglock);

		/*
		if (notify) {
			read_lock(&tasklist_lock);
			do_notify_parent_cldstop(current, false, notify);
			read_unlock(&tasklist_lock);
		}

		/* Now we don't run again until woken by SIGCONT or SIGKILL */
		cgroup_enter_frozen();
		freezable_schedule();
		return true;
	} else {
		/*
		task_set_jobctl_pending(current, JOBCTL_TRAP_STOP);
		return false;
	}
}

static void do_jobctl_trap(void)
{
	struct signal_struct *signal = current->signal;
	int signr = current->jobctl & JOBCTL_STOP_SIGMASK;

	if (current->ptrace & PT_SEIZED) {
		if (!signal->group_stop_count &&
		    !(signal->flags & SIGNAL_STOP_STOPPED))
			signr = SIGTRAP;
		WARN_ON_ONCE(!signr);
		ptrace_do_notify(signr, signr | (PTRACE_EVENT_STOP << 8),
				 CLD_STOPPED, 0);
	} else {
		WARN_ON_ONCE(!signr);
		ptrace_stop(signr, CLD_STOPPED, 0, NULL);
	}
}

static void do_freezer_trap(void)
	__releases(&current->sighand->siglock)
{
	/*
	if ((current->jobctl & (JOBCTL_PENDING_MASK | JOBCTL_TRAP_FREEZE)) !=
	     JOBCTL_TRAP_FREEZE) {
		spin_unlock_irq(&current->sighand->siglock);
		return;
	}

	/*
	__set_current_state(TASK_INTERRUPTIBLE);
	clear_thread_flag(TIF_SIGPENDING);
	spin_unlock_irq(&current->sighand->siglock);
	cgroup_enter_frozen();
	freezable_schedule();
}

static int ptrace_signal(int signr, kernel_siginfo_t *info, enum pid_type type)
{
	/*
	current->jobctl |= JOBCTL_STOP_DEQUEUED;
	signr = ptrace_stop(signr, CLD_TRAPPED, 0, info);

	/* We're back.  Did the debugger cancel the sig?  */
	if (signr == 0)
		return signr;

	/*
	if (signr != info->si_signo) {
		clear_siginfo(info);
		info->si_signo = signr;
		info->si_errno = 0;
		info->si_code = SI_USER;
		rcu_read_lock();
		info->si_pid = task_pid_vnr(current->parent);
		info->si_uid = from_kuid_munged(current_user_ns(),
						task_uid(current->parent));
		rcu_read_unlock();
	}

	/* If the (new) signal is now blocked, requeue it.  */
	if (sigismember(&current->blocked, signr) ||
	    fatal_signal_pending(current)) {
		send_signal_locked(signr, info, current, type);
		signr = 0;
	}

	return signr;
}

static void hide_si_addr_tag_bits(struct ksignal *ksig)
{
	switch (siginfo_layout(ksig->sig, ksig->info.si_code)) {
	case SIL_FAULT:
	case SIL_FAULT_TRAPNO:
	case SIL_FAULT_MCEERR:
	case SIL_FAULT_BNDERR:
	case SIL_FAULT_PKUERR:
	case SIL_FAULT_PERF_EVENT:
		ksig->info.si_addr = arch_untagged_si_addr(
			ksig->info.si_addr, ksig->sig, ksig->info.si_code);
		break;
	case SIL_KILL:
	case SIL_TIMER:
	case SIL_POLL:
	case SIL_CHLD:
	case SIL_RT:
	case SIL_SYS:
		break;
	}
}

bool get_signal(struct ksignal *ksig)
{
	struct sighand_struct *sighand = current->sighand;
	struct signal_struct *signal = current->signal;
	int signr;

	clear_notify_signal();
	if (unlikely(task_work_pending(current)))
		task_work_run();

	if (!task_sigpending(current))
		return false;

	if (unlikely(uprobe_deny_signal()))
		return false;

	/*
	try_to_freeze();

relock:
	spin_lock_irq(&sighand->siglock);

	/*
	if (unlikely(signal->flags & SIGNAL_CLD_MASK)) {
		int why;

		if (signal->flags & SIGNAL_CLD_CONTINUED)
			why = CLD_CONTINUED;
		else
			why = CLD_STOPPED;

		signal->flags &= ~SIGNAL_CLD_MASK;

		spin_unlock_irq(&sighand->siglock);

		/*
		read_lock(&tasklist_lock);
		do_notify_parent_cldstop(current, false, why);

		if (ptrace_reparented(current->group_leader))
			do_notify_parent_cldstop(current->group_leader,
						true, why);
		read_unlock(&tasklist_lock);

		goto relock;
	}

	for (;;) {
		struct k_sigaction *ka;
		enum pid_type type;

		/* Has this task already been marked for death? */
		if ((signal->flags & SIGNAL_GROUP_EXIT) ||
		     signal->group_exec_task) {
			ksig->info.si_signo = signr = SIGKILL;
			sigdelset(&current->pending.signal, SIGKILL);
			trace_signal_deliver(SIGKILL, SEND_SIG_NOINFO,
				&sighand->action[SIGKILL - 1]);
			recalc_sigpending();
			goto fatal;
		}

		if (unlikely(current->jobctl & JOBCTL_STOP_PENDING) &&
		    do_signal_stop(0))
			goto relock;

		if (unlikely(current->jobctl &
			     (JOBCTL_TRAP_MASK | JOBCTL_TRAP_FREEZE))) {
			if (current->jobctl & JOBCTL_TRAP_MASK) {
				do_jobctl_trap();
				spin_unlock_irq(&sighand->siglock);
			} else if (current->jobctl & JOBCTL_TRAP_FREEZE)
				do_freezer_trap();

			goto relock;
		}

		/*
		if (unlikely(cgroup_task_frozen(current))) {
			spin_unlock_irq(&sighand->siglock);
			cgroup_leave_frozen(false);
			goto relock;
		}

		/*
		type = PIDTYPE_PID;
		signr = dequeue_synchronous_signal(&ksig->info);
		if (!signr)
			signr = dequeue_signal(current, &current->blocked,
					       &ksig->info, &type);

		if (!signr)
			break; /* will return 0 */

		if (unlikely(current->ptrace) && (signr != SIGKILL) &&
		    !(sighand->action[signr -1].sa.sa_flags & SA_IMMUTABLE)) {
			signr = ptrace_signal(signr, &ksig->info, type);
			if (!signr)
				continue;
		}

		ka = &sighand->action[signr-1];

		/* Trace actually delivered signals. */
		trace_signal_deliver(signr, &ksig->info, ka);

		if (ka->sa.sa_handler == SIG_IGN) /* Do nothing.  */
			continue;
		if (ka->sa.sa_handler != SIG_DFL) {
			/* Run the handler.  */
			ksig->ka = *ka;

			if (ka->sa.sa_flags & SA_ONESHOT)
				ka->sa.sa_handler = SIG_DFL;

			break; /* will return non-zero "signr" value */
		}

		/*
		if (sig_kernel_ignore(signr)) /* Default is nothing. */
			continue;

		/*
		if (unlikely(signal->flags & SIGNAL_UNKILLABLE) &&
				!sig_kernel_only(signr))
			continue;

		if (sig_kernel_stop(signr)) {
			/*
			if (signr != SIGSTOP) {
				spin_unlock_irq(&sighand->siglock);

				/* signals can be posted during this window */

				if (is_current_pgrp_orphaned())
					goto relock;

				spin_lock_irq(&sighand->siglock);
			}

			if (likely(do_signal_stop(ksig->info.si_signo))) {
				/* It released the siglock.  */
				goto relock;
			}

			/*
			continue;
		}

	fatal:
		spin_unlock_irq(&sighand->siglock);
		if (unlikely(cgroup_task_frozen(current)))
			cgroup_leave_frozen(true);

		/*
		current->flags |= PF_SIGNALED;

		if (sig_kernel_coredump(signr)) {
			if (print_fatal_signals)
				print_fatal_signal(ksig->info.si_signo);
			proc_coredump_connector(current);
			/*
			do_coredump(&ksig->info);
		}

		/*
		if (current->flags & PF_IO_WORKER)
			goto out;

		/*
		do_group_exit(ksig->info.si_signo);
		/* NOTREACHED */
	}
	spin_unlock_irq(&sighand->siglock);
out:
	ksig->sig = signr;

	if (!(ksig->ka.sa.sa_flags & SA_EXPOSE_TAGBITS))
		hide_si_addr_tag_bits(ksig);

	return ksig->sig > 0;
}

static void signal_delivered(struct ksignal *ksig, int stepping)
{
	sigset_t blocked;

	/* A signal was successfully delivered, and the
	   saved sigmask was stored on the signal frame,
	   and will be restored by sigreturn.  So we can
	   simply clear the restore sigmask flag.  */
	clear_restore_sigmask();

	sigorsets(&blocked, &current->blocked, &ksig->ka.sa.sa_mask);
	if (!(ksig->ka.sa.sa_flags & SA_NODEFER))
		sigaddset(&blocked, ksig->sig);
	set_current_blocked(&blocked);
	if (current->sas_ss_flags & SS_AUTODISARM)
		sas_ss_reset(current);
	if (stepping)
		ptrace_notify(SIGTRAP, 0);
}

void signal_setup_done(int failed, struct ksignal *ksig, int stepping)
{
	if (failed)
		force_sigsegv(ksig->sig);
	else
		signal_delivered(ksig, stepping);
}

static void retarget_shared_pending(struct task_struct *tsk, sigset_t *which)
{
	sigset_t retarget;
	struct task_struct *t;

	sigandsets(&retarget, &tsk->signal->shared_pending.signal, which);
	if (sigisemptyset(&retarget))
		return;

	t = tsk;
	while_each_thread(tsk, t) {
		if (t->flags & PF_EXITING)
			continue;

		if (!has_pending_signals(&retarget, &t->blocked))
			continue;
		/* Remove the signals this thread can handle. */
		sigandsets(&retarget, &retarget, &t->blocked);

		if (!task_sigpending(t))
			signal_wake_up(t, 0);

		if (sigisemptyset(&retarget))
			break;
	}
}

void exit_signals(struct task_struct *tsk)
{
	int group_stop = 0;
	sigset_t unblocked;

	/*
	cgroup_threadgroup_change_begin(tsk);

	if (thread_group_empty(tsk) || (tsk->signal->flags & SIGNAL_GROUP_EXIT)) {
		tsk->flags |= PF_EXITING;
		cgroup_threadgroup_change_end(tsk);
		return;
	}

	spin_lock_irq(&tsk->sighand->siglock);
	/*
	tsk->flags |= PF_EXITING;

	cgroup_threadgroup_change_end(tsk);

	if (!task_sigpending(tsk))
		goto out;

	unblocked = tsk->blocked;
	signotset(&unblocked);
	retarget_shared_pending(tsk, &unblocked);

	if (unlikely(tsk->jobctl & JOBCTL_STOP_PENDING) &&
	    task_participate_group_stop(tsk))
		group_stop = CLD_STOPPED;
out:
	spin_unlock_irq(&tsk->sighand->siglock);

	/*
	if (unlikely(group_stop)) {
		read_lock(&tasklist_lock);
		do_notify_parent_cldstop(tsk, false, group_stop);
		read_unlock(&tasklist_lock);
	}
}


SYSCALL_DEFINE0(restart_syscall)
{
	struct restart_block *restart = &current->restart_block;
	return restart->fn(restart);
}

long do_no_restart_syscall(struct restart_block *param)
{
	return -EINTR;
}

static void __set_task_blocked(struct task_struct *tsk, const sigset_t *newset)
{
	if (task_sigpending(tsk) && !thread_group_empty(tsk)) {
		sigset_t newblocked;
		/* A set of now blocked but previously unblocked signals. */
		sigandnsets(&newblocked, newset, &current->blocked);
		retarget_shared_pending(tsk, &newblocked);
	}
	tsk->blocked = *newset;
	recalc_sigpending();
}

void set_current_blocked(sigset_t *newset)
{
	sigdelsetmask(newset, sigmask(SIGKILL) | sigmask(SIGSTOP));
	__set_current_blocked(newset);
}

void __set_current_blocked(const sigset_t *newset)
{
	struct task_struct *tsk = current;

	/*
	if (sigequalsets(&tsk->blocked, newset))
		return;

	spin_lock_irq(&tsk->sighand->siglock);
	__set_task_blocked(tsk, newset);
	spin_unlock_irq(&tsk->sighand->siglock);
}

int sigprocmask(int how, sigset_t *set, sigset_t *oldset)
{
	struct task_struct *tsk = current;
	sigset_t newset;

	/* Lockless, only current can change ->blocked, never from irq */
	if (oldset)
		*oldset = tsk->blocked;

	switch (how) {
	case SIG_BLOCK:
		sigorsets(&newset, &tsk->blocked, set);
		break;
	case SIG_UNBLOCK:
		sigandnsets(&newset, &tsk->blocked, set);
		break;
	case SIG_SETMASK:
		newset = *set;
		break;
	default:
		return -EINVAL;
	}

	__set_current_blocked(&newset);
	return 0;
}
EXPORT_SYMBOL(sigprocmask);

int set_user_sigmask(const sigset_t __user *umask, size_t sigsetsize)
{
	sigset_t kmask;

	if (!umask)
		return 0;
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;
	if (copy_from_user(&kmask, umask, sizeof(sigset_t)))
		return -EFAULT;

	set_restore_sigmask();
	current->saved_sigmask = current->blocked;
	set_current_blocked(&kmask);

	return 0;
}

#ifdef CONFIG_COMPAT
int set_compat_user_sigmask(const compat_sigset_t __user *umask,
			    size_t sigsetsize)
{
	sigset_t kmask;

	if (!umask)
		return 0;
	if (sigsetsize != sizeof(compat_sigset_t))
		return -EINVAL;
	if (get_compat_sigset(&kmask, umask))
		return -EFAULT;

	set_restore_sigmask();
	current->saved_sigmask = current->blocked;
	set_current_blocked(&kmask);

	return 0;
}
#endif

SYSCALL_DEFINE4(rt_sigprocmask, int, how, sigset_t __user *, nset,
		sigset_t __user *, oset, size_t, sigsetsize)
{
	sigset_t old_set, new_set;
	int error;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	old_set = current->blocked;

	if (nset) {
		if (copy_from_user(&new_set, nset, sizeof(sigset_t)))
			return -EFAULT;
		sigdelsetmask(&new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));

		error = sigprocmask(how, &new_set, NULL);
		if (error)
			return error;
	}

	if (oset) {
		if (copy_to_user(oset, &old_set, sizeof(sigset_t)))
			return -EFAULT;
	}

	return 0;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(rt_sigprocmask, int, how, compat_sigset_t __user *, nset,
		compat_sigset_t __user *, oset, compat_size_t, sigsetsize)
{
	sigset_t old_set = current->blocked;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (nset) {
		sigset_t new_set;
		int error;
		if (get_compat_sigset(&new_set, nset))
			return -EFAULT;
		sigdelsetmask(&new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));

		error = sigprocmask(how, &new_set, NULL);
		if (error)
			return error;
	}
	return oset ? put_compat_sigset(oset, &old_set, sizeof(*oset)) : 0;
}
#endif

static void do_sigpending(sigset_t *set)
{
	spin_lock_irq(&current->sighand->siglock);
	sigorsets(set, &current->pending.signal,
		  &current->signal->shared_pending.signal);
	spin_unlock_irq(&current->sighand->siglock);

	/* Outside the lock because only this thread touches it.  */
	sigandsets(set, &current->blocked, set);
}

SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, uset, size_t, sigsetsize)
{
	sigset_t set;

	if (sigsetsize > sizeof(*uset))
		return -EINVAL;

	do_sigpending(&set);

	if (copy_to_user(uset, &set, sigsetsize))
		return -EFAULT;

	return 0;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(rt_sigpending, compat_sigset_t __user *, uset,
		compat_size_t, sigsetsize)
{
	sigset_t set;

	if (sigsetsize > sizeof(*uset))
		return -EINVAL;

	do_sigpending(&set);

	return put_compat_sigset(uset, &set, sigsetsize);
}
#endif

static const struct {
	unsigned char limit, layout;
} sig_sicodes[] = {
	[SIGILL]  = { NSIGILL,  SIL_FAULT },
	[SIGFPE]  = { NSIGFPE,  SIL_FAULT },
	[SIGSEGV] = { NSIGSEGV, SIL_FAULT },
	[SIGBUS]  = { NSIGBUS,  SIL_FAULT },
	[SIGTRAP] = { NSIGTRAP, SIL_FAULT },
#if defined(SIGEMT)
	[SIGEMT]  = { NSIGEMT,  SIL_FAULT },
#endif
	[SIGCHLD] = { NSIGCHLD, SIL_CHLD },
	[SIGPOLL] = { NSIGPOLL, SIL_POLL },
	[SIGSYS]  = { NSIGSYS,  SIL_SYS },
};

static bool known_siginfo_layout(unsigned sig, int si_code)
{
	if (si_code == SI_KERNEL)
		return true;
	else if ((si_code > SI_USER)) {
		if (sig_specific_sicodes(sig)) {
			if (si_code <= sig_sicodes[sig].limit)
				return true;
		}
		else if (si_code <= NSIGPOLL)
			return true;
	}
	else if (si_code >= SI_DETHREAD)
		return true;
	else if (si_code == SI_ASYNCNL)
		return true;
	return false;
}

enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
{
	enum siginfo_layout layout = SIL_KILL;
	if ((si_code > SI_USER) && (si_code < SI_KERNEL)) {
		if ((sig < ARRAY_SIZE(sig_sicodes)) &&
		    (si_code <= sig_sicodes[sig].limit)) {
			layout = sig_sicodes[sig].layout;
			/* Handle the exceptions */
			if ((sig == SIGBUS) &&
			    (si_code >= BUS_MCEERR_AR) && (si_code <= BUS_MCEERR_AO))
				layout = SIL_FAULT_MCEERR;
			else if ((sig == SIGSEGV) && (si_code == SEGV_BNDERR))
				layout = SIL_FAULT_BNDERR;
#ifdef SEGV_PKUERR
			else if ((sig == SIGSEGV) && (si_code == SEGV_PKUERR))
				layout = SIL_FAULT_PKUERR;
#endif
			else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
				layout = SIL_FAULT_PERF_EVENT;
			else if (IS_ENABLED(CONFIG_SPARC) &&
				 (sig == SIGILL) && (si_code == ILL_ILLTRP))
				layout = SIL_FAULT_TRAPNO;
			else if (IS_ENABLED(CONFIG_ALPHA) &&
				 ((sig == SIGFPE) ||
				  ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
				layout = SIL_FAULT_TRAPNO;
		}
		else if (si_code <= NSIGPOLL)
			layout = SIL_POLL;
	} else {
		if (si_code == SI_TIMER)
			layout = SIL_TIMER;
		else if (si_code == SI_SIGIO)
			layout = SIL_POLL;
		else if (si_code < 0)
			layout = SIL_RT;
	}
	return layout;
}

static inline char __user *si_expansion(const siginfo_t __user *info)
{
	return ((char __user *)info) + sizeof(struct kernel_siginfo);
}

int copy_siginfo_to_user(siginfo_t __user *to, const kernel_siginfo_t *from)
{
	char __user *expansion = si_expansion(to);
	if (copy_to_user(to, from , sizeof(struct kernel_siginfo)))
		return -EFAULT;
	if (clear_user(expansion, SI_EXPANSION_SIZE))
		return -EFAULT;
	return 0;
}

static int post_copy_siginfo_from_user(kernel_siginfo_t *info,
				       const siginfo_t __user *from)
{
	if (unlikely(!known_siginfo_layout(info->si_signo, info->si_code))) {
		char __user *expansion = si_expansion(from);
		char buf[SI_EXPANSION_SIZE];
		int i;
		/*
		if (copy_from_user(&buf, expansion, SI_EXPANSION_SIZE))
			return -EFAULT;
		for (i = 0; i < SI_EXPANSION_SIZE; i++) {
			if (buf[i] != 0)
				return -E2BIG;
		}
	}
	return 0;
}

static int __copy_siginfo_from_user(int signo, kernel_siginfo_t *to,
				    const siginfo_t __user *from)
{
	if (copy_from_user(to, from, sizeof(struct kernel_siginfo)))
		return -EFAULT;
	to->si_signo = signo;
	return post_copy_siginfo_from_user(to, from);
}

int copy_siginfo_from_user(kernel_siginfo_t *to, const siginfo_t __user *from)
{
	if (copy_from_user(to, from, sizeof(struct kernel_siginfo)))
		return -EFAULT;
	return post_copy_siginfo_from_user(to, from);
}

#ifdef CONFIG_COMPAT
void copy_siginfo_to_external32(struct compat_siginfo *to,
		const struct kernel_siginfo *from)
{
	memset(to, 0, sizeof(*to));

	to->si_signo = from->si_signo;
	to->si_errno = from->si_errno;
	to->si_code  = from->si_code;
	switch(siginfo_layout(from->si_signo, from->si_code)) {
	case SIL_KILL:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		break;
	case SIL_TIMER:
		to->si_tid     = from->si_tid;
		to->si_overrun = from->si_overrun;
		to->si_int     = from->si_int;
		break;
	case SIL_POLL:
		to->si_band = from->si_band;
		to->si_fd   = from->si_fd;
		break;
	case SIL_FAULT:
		to->si_addr = ptr_to_compat(from->si_addr);
		break;
	case SIL_FAULT_TRAPNO:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_trapno = from->si_trapno;
		break;
	case SIL_FAULT_MCEERR:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_addr_lsb = from->si_addr_lsb;
		break;
	case SIL_FAULT_BNDERR:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_lower = ptr_to_compat(from->si_lower);
		to->si_upper = ptr_to_compat(from->si_upper);
		break;
	case SIL_FAULT_PKUERR:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_pkey = from->si_pkey;
		break;
	case SIL_FAULT_PERF_EVENT:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_perf_data = from->si_perf_data;
		to->si_perf_type = from->si_perf_type;
		to->si_perf_flags = from->si_perf_flags;
		break;
	case SIL_CHLD:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		to->si_status = from->si_status;
		to->si_utime = from->si_utime;
		to->si_stime = from->si_stime;
		break;
	case SIL_RT:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		to->si_int = from->si_int;
		break;
	case SIL_SYS:
		to->si_call_addr = ptr_to_compat(from->si_call_addr);
		to->si_syscall   = from->si_syscall;
		to->si_arch      = from->si_arch;
		break;
	}
}

int __copy_siginfo_to_user32(struct compat_siginfo __user *to,
			   const struct kernel_siginfo *from)
{
	struct compat_siginfo new;

	copy_siginfo_to_external32(&new, from);
	if (copy_to_user(to, &new, sizeof(struct compat_siginfo)))
		return -EFAULT;
	return 0;
}

static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
					 const struct compat_siginfo *from)
{
	clear_siginfo(to);
	to->si_signo = from->si_signo;
	to->si_errno = from->si_errno;
	to->si_code  = from->si_code;
	switch(siginfo_layout(from->si_signo, from->si_code)) {
	case SIL_KILL:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		break;
	case SIL_TIMER:
		to->si_tid     = from->si_tid;
		to->si_overrun = from->si_overrun;
		to->si_int     = from->si_int;
		break;
	case SIL_POLL:
		to->si_band = from->si_band;
		to->si_fd   = from->si_fd;
		break;
	case SIL_FAULT:
		to->si_addr = compat_ptr(from->si_addr);
		break;
	case SIL_FAULT_TRAPNO:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_trapno = from->si_trapno;
		break;
	case SIL_FAULT_MCEERR:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_addr_lsb = from->si_addr_lsb;
		break;
	case SIL_FAULT_BNDERR:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_lower = compat_ptr(from->si_lower);
		to->si_upper = compat_ptr(from->si_upper);
		break;
	case SIL_FAULT_PKUERR:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_pkey = from->si_pkey;
		break;
	case SIL_FAULT_PERF_EVENT:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_perf_data = from->si_perf_data;
		to->si_perf_type = from->si_perf_type;
		to->si_perf_flags = from->si_perf_flags;
		break;
	case SIL_CHLD:
		to->si_pid    = from->si_pid;
		to->si_uid    = from->si_uid;
		to->si_status = from->si_status;
#ifdef CONFIG_X86_X32_ABI
		if (in_x32_syscall()) {
			to->si_utime = from->_sifields._sigchld_x32._utime;
			to->si_stime = from->_sifields._sigchld_x32._stime;
		} else
#endif
		{
			to->si_utime = from->si_utime;
			to->si_stime = from->si_stime;
		}
		break;
	case SIL_RT:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		to->si_int = from->si_int;
		break;
	case SIL_SYS:
		to->si_call_addr = compat_ptr(from->si_call_addr);
		to->si_syscall   = from->si_syscall;
		to->si_arch      = from->si_arch;
		break;
	}
	return 0;
}

static int __copy_siginfo_from_user32(int signo, struct kernel_siginfo *to,
				      const struct compat_siginfo __user *ufrom)
{
	struct compat_siginfo from;

	if (copy_from_user(&from, ufrom, sizeof(struct compat_siginfo)))
		return -EFAULT;

	from.si_signo = signo;
	return post_copy_siginfo_from_user32(to, &from);
}

int copy_siginfo_from_user32(struct kernel_siginfo *to,
			     const struct compat_siginfo __user *ufrom)
{
	struct compat_siginfo from;

	if (copy_from_user(&from, ufrom, sizeof(struct compat_siginfo)))
		return -EFAULT;

	return post_copy_siginfo_from_user32(to, &from);
}
#endif /* CONFIG_COMPAT */

static int do_sigtimedwait(const sigset_t *which, kernel_siginfo_t *info,
		    const struct timespec64 *ts)
{
	ktime_t *to = NULL, timeout = KTIME_MAX;
	struct task_struct *tsk = current;
	sigset_t mask = *which;
	enum pid_type type;
	int sig, ret = 0;

	if (ts) {
		if (!timespec64_valid(ts))
			return -EINVAL;
		timeout = timespec64_to_ktime(*ts);
		to = &timeout;
	}

	/*
	sigdelsetmask(&mask, sigmask(SIGKILL) | sigmask(SIGSTOP));
	signotset(&mask);

	spin_lock_irq(&tsk->sighand->siglock);
	sig = dequeue_signal(tsk, &mask, info, &type);
	if (!sig && timeout) {
		/*
		tsk->real_blocked = tsk->blocked;
		sigandsets(&tsk->blocked, &tsk->blocked, &mask);
		recalc_sigpending();
		spin_unlock_irq(&tsk->sighand->siglock);

		__set_current_state(TASK_INTERRUPTIBLE);
		ret = freezable_schedule_hrtimeout_range(to, tsk->timer_slack_ns,
							 HRTIMER_MODE_REL);
		spin_lock_irq(&tsk->sighand->siglock);
		__set_task_blocked(tsk, &tsk->real_blocked);
		sigemptyset(&tsk->real_blocked);
		sig = dequeue_signal(tsk, &mask, info, &type);
	}
	spin_unlock_irq(&tsk->sighand->siglock);

	if (sig)
		return sig;
	return ret ? -EINTR : -EAGAIN;
}

SYSCALL_DEFINE4(rt_sigtimedwait, const sigset_t __user *, uthese,
		siginfo_t __user *, uinfo,
		const struct __kernel_timespec __user *, uts,
		size_t, sigsetsize)
{
	sigset_t these;
	struct timespec64 ts;
	kernel_siginfo_t info;
	int ret;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&these, uthese, sizeof(these)))
		return -EFAULT;

	if (uts) {
		if (get_timespec64(&ts, uts))
			return -EFAULT;
	}

	ret = do_sigtimedwait(&these, &info, uts ? &ts : NULL);

	if (ret > 0 && uinfo) {
		if (copy_siginfo_to_user(uinfo, &info))
			ret = -EFAULT;
	}

	return ret;
}

#ifdef CONFIG_COMPAT_32BIT_TIME
SYSCALL_DEFINE4(rt_sigtimedwait_time32, const sigset_t __user *, uthese,
		siginfo_t __user *, uinfo,
		const struct old_timespec32 __user *, uts,
		size_t, sigsetsize)
{
	sigset_t these;
	struct timespec64 ts;
	kernel_siginfo_t info;
	int ret;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&these, uthese, sizeof(these)))
		return -EFAULT;

	if (uts) {
		if (get_old_timespec32(&ts, uts))
			return -EFAULT;
	}

	ret = do_sigtimedwait(&these, &info, uts ? &ts : NULL);

	if (ret > 0 && uinfo) {
		if (copy_siginfo_to_user(uinfo, &info))
			ret = -EFAULT;
	}

	return ret;
}
#endif

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(rt_sigtimedwait_time64, compat_sigset_t __user *, uthese,
		struct compat_siginfo __user *, uinfo,
		struct __kernel_timespec __user *, uts, compat_size_t, sigsetsize)
{
	sigset_t s;
	struct timespec64 t;
	kernel_siginfo_t info;
	long ret;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (get_compat_sigset(&s, uthese))
		return -EFAULT;

	if (uts) {
		if (get_timespec64(&t, uts))
			return -EFAULT;
	}

	ret = do_sigtimedwait(&s, &info, uts ? &t : NULL);

	if (ret > 0 && uinfo) {
		if (copy_siginfo_to_user32(uinfo, &info))
			ret = -EFAULT;
	}

	return ret;
}

#ifdef CONFIG_COMPAT_32BIT_TIME
COMPAT_SYSCALL_DEFINE4(rt_sigtimedwait_time32, compat_sigset_t __user *, uthese,
		struct compat_siginfo __user *, uinfo,
		struct old_timespec32 __user *, uts, compat_size_t, sigsetsize)
{
	sigset_t s;
	struct timespec64 t;
	kernel_siginfo_t info;
	long ret;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (get_compat_sigset(&s, uthese))
		return -EFAULT;

	if (uts) {
		if (get_old_timespec32(&t, uts))
			return -EFAULT;
	}

	ret = do_sigtimedwait(&s, &info, uts ? &t : NULL);

	if (ret > 0 && uinfo) {
		if (copy_siginfo_to_user32(uinfo, &info))
			ret = -EFAULT;
	}

	return ret;
}
#endif
#endif

static inline void prepare_kill_siginfo(int sig, struct kernel_siginfo *info)
{
	clear_siginfo(info);
	info->si_signo = sig;
	info->si_errno = 0;
	info->si_code = SI_USER;
	info->si_pid = task_tgid_vnr(current);
	info->si_uid = from_kuid_munged(current_user_ns(), current_uid());
}

SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
{
	struct kernel_siginfo info;

	prepare_kill_siginfo(sig, &info);

	return kill_something_info(sig, &info, pid);
}

static bool access_pidfd_pidns(struct pid *pid)
{
	struct pid_namespace *active = task_active_pid_ns(current);
	struct pid_namespace *p = ns_of_pid(pid);

	for (;;) {
		if (!p)
			return false;
		if (p == active)
			break;
		p = p->parent;
	}

	return true;
}

static int copy_siginfo_from_user_any(kernel_siginfo_t *kinfo,
		siginfo_t __user *info)
{
#ifdef CONFIG_COMPAT
	/*
	if (in_compat_syscall())
		return copy_siginfo_from_user32(
			kinfo, (struct compat_siginfo __user *)info);
#endif
	return copy_siginfo_from_user(kinfo, info);
}

static struct pid *pidfd_to_pid(const struct file *file)
{
	struct pid *pid;

	pid = pidfd_pid(file);
	if (!IS_ERR(pid))
		return pid;

	return tgid_pidfd_to_pid(file);
}

SYSCALL_DEFINE4(pidfd_send_signal, int, pidfd, int, sig,
		siginfo_t __user *, info, unsigned int, flags)
{
	int ret;
	struct fd f;
	struct pid *pid;
	kernel_siginfo_t kinfo;

	/* Enforce flags be set to 0 until we add an extension. */
	if (flags)
		return -EINVAL;

	f = fdget(pidfd);
	if (!f.file)
		return -EBADF;

	/* Is this a pidfd? */
	pid = pidfd_to_pid(f.file);
	if (IS_ERR(pid)) {
		ret = PTR_ERR(pid);
		goto err;
	}

	ret = -EINVAL;
	if (!access_pidfd_pidns(pid))
		goto err;

	if (info) {
		ret = copy_siginfo_from_user_any(&kinfo, info);
		if (unlikely(ret))
			goto err;

		ret = -EINVAL;
		if (unlikely(sig != kinfo.si_signo))
			goto err;

		/* Only allow sending arbitrary signals to yourself. */
		ret = -EPERM;
		if ((task_pid(current) != pid) &&
		    (kinfo.si_code >= 0 || kinfo.si_code == SI_TKILL))
			goto err;
	} else {
		prepare_kill_siginfo(sig, &kinfo);
	}

	ret = kill_pid_info(sig, &kinfo, pid);

err:
	fdput(f);
	return ret;
}

static int
do_send_specific(pid_t tgid, pid_t pid, int sig, struct kernel_siginfo *info)
{
	struct task_struct *p;
	int error = -ESRCH;

	rcu_read_lock();
	p = find_task_by_vpid(pid);
	if (p && (tgid <= 0 || task_tgid_vnr(p) == tgid)) {
		error = check_kill_permission(sig, info, p);
		/*
		if (!error && sig) {
			error = do_send_sig_info(sig, info, p, PIDTYPE_PID);
			/*
			if (unlikely(error == -ESRCH))
				error = 0;
		}
	}
	rcu_read_unlock();

	return error;
}

static int do_tkill(pid_t tgid, pid_t pid, int sig)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_TKILL;
	info.si_pid = task_tgid_vnr(current);
	info.si_uid = from_kuid_munged(current_user_ns(), current_uid());

	return do_send_specific(tgid, pid, sig, &info);
}

SYSCALL_DEFINE3(tgkill, pid_t, tgid, pid_t, pid, int, sig)
{
	/* This is only valid for single tasks */
	if (pid <= 0 || tgid <= 0)
		return -EINVAL;

	return do_tkill(tgid, pid, sig);
}

SYSCALL_DEFINE2(tkill, pid_t, pid, int, sig)
{
	/* This is only valid for single tasks */
	if (pid <= 0)
		return -EINVAL;

	return do_tkill(0, pid, sig);
}

static int do_rt_sigqueueinfo(pid_t pid, int sig, kernel_siginfo_t *info)
{
	/* Not even root can pretend to send signals from the kernel.
	 * Nor can they impersonate a kill()/tgkill(), which adds source info.
	 */
	if ((info->si_code >= 0 || info->si_code == SI_TKILL) &&
	    (task_pid_vnr(current) != pid))
		return -EPERM;

	/* POSIX.1b doesn't mention process groups.  */
	return kill_proc_info(sig, info, pid);
}

SYSCALL_DEFINE3(rt_sigqueueinfo, pid_t, pid, int, sig,
		siginfo_t __user *, uinfo)
{
	kernel_siginfo_t info;
	int ret = __copy_siginfo_from_user(sig, &info, uinfo);
	if (unlikely(ret))
		return ret;
	return do_rt_sigqueueinfo(pid, sig, &info);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE3(rt_sigqueueinfo,
			compat_pid_t, pid,
			int, sig,
			struct compat_siginfo __user *, uinfo)
{
	kernel_siginfo_t info;
	int ret = __copy_siginfo_from_user32(sig, &info, uinfo);
	if (unlikely(ret))
		return ret;
	return do_rt_sigqueueinfo(pid, sig, &info);
}
#endif

static int do_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, kernel_siginfo_t *info)
{
	/* This is only valid for single tasks */
	if (pid <= 0 || tgid <= 0)
		return -EINVAL;

	/* Not even root can pretend to send signals from the kernel.
	 * Nor can they impersonate a kill()/tgkill(), which adds source info.
	 */
	if ((info->si_code >= 0 || info->si_code == SI_TKILL) &&
	    (task_pid_vnr(current) != pid))
		return -EPERM;

	return do_send_specific(tgid, pid, sig, info);
}

SYSCALL_DEFINE4(rt_tgsigqueueinfo, pid_t, tgid, pid_t, pid, int, sig,
		siginfo_t __user *, uinfo)
{
	kernel_siginfo_t info;
	int ret = __copy_siginfo_from_user(sig, &info, uinfo);
	if (unlikely(ret))
		return ret;
	return do_rt_tgsigqueueinfo(tgid, pid, sig, &info);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(rt_tgsigqueueinfo,
			compat_pid_t, tgid,
			compat_pid_t, pid,
			int, sig,
			struct compat_siginfo __user *, uinfo)
{
	kernel_siginfo_t info;
	int ret = __copy_siginfo_from_user32(sig, &info, uinfo);
	if (unlikely(ret))
		return ret;
	return do_rt_tgsigqueueinfo(tgid, pid, sig, &info);
}
#endif

void kernel_sigaction(int sig, __sighandler_t action)
{
	spin_lock_irq(&current->sighand->siglock);
	current->sighand->action[sig - 1].sa.sa_handler = action;
	if (action == SIG_IGN) {
		sigset_t mask;

		sigemptyset(&mask);
		sigaddset(&mask, sig);

		flush_sigqueue_mask(&mask, &current->signal->shared_pending);
		flush_sigqueue_mask(&mask, &current->pending);
		recalc_sigpending();
	}
	spin_unlock_irq(&current->sighand->siglock);
}
EXPORT_SYMBOL(kernel_sigaction);

void __weak sigaction_compat_abi(struct k_sigaction *act,
		struct k_sigaction *oact)
{
}

int do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact)
{
	struct task_struct *p = current, *t;
	struct k_sigaction *k;
	sigset_t mask;

	if (!valid_signal(sig) || sig < 1 || (act && sig_kernel_only(sig)))
		return -EINVAL;

	k = &p->sighand->action[sig-1];

	spin_lock_irq(&p->sighand->siglock);
	if (k->sa.sa_flags & SA_IMMUTABLE) {
		spin_unlock_irq(&p->sighand->siglock);
		return -EINVAL;
	}
	if (oact)
		*oact = *k;

	/*
	BUILD_BUG_ON(UAPI_SA_FLAGS & SA_UNSUPPORTED);

	/*
	if (act)
		act->sa.sa_flags &= UAPI_SA_FLAGS;
	if (oact)
		oact->sa.sa_flags &= UAPI_SA_FLAGS;

	sigaction_compat_abi(act, oact);

	if (act) {
		sigdelsetmask(&act->sa.sa_mask,
			      sigmask(SIGKILL) | sigmask(SIGSTOP));
		*k = *act;
		/*
		if (sig_handler_ignored(sig_handler(p, sig), sig)) {
			sigemptyset(&mask);
			sigaddset(&mask, sig);
			flush_sigqueue_mask(&mask, &p->signal->shared_pending);
			for_each_thread(p, t)
				flush_sigqueue_mask(&mask, &t->pending);
		}
	}

	spin_unlock_irq(&p->sighand->siglock);
	return 0;
}

#ifdef CONFIG_DYNAMIC_SIGFRAME
static inline void sigaltstack_lock(void)
	__acquires(&current->sighand->siglock)
{
	spin_lock_irq(&current->sighand->siglock);
}

static inline void sigaltstack_unlock(void)
	__releases(&current->sighand->siglock)
{
	spin_unlock_irq(&current->sighand->siglock);
}
#else
static inline void sigaltstack_lock(void) { }
static inline void sigaltstack_unlock(void) { }
#endif

static int
do_sigaltstack (const stack_t *ss, stack_t *oss, unsigned long sp,
		size_t min_ss_size)
{
	struct task_struct *t = current;
	int ret = 0;

	if (oss) {
		memset(oss, 0, sizeof(stack_t));
		oss->ss_sp = (void __user *) t->sas_ss_sp;
		oss->ss_size = t->sas_ss_size;
		oss->ss_flags = sas_ss_flags(sp) |
			(current->sas_ss_flags & SS_FLAG_BITS);
	}

	if (ss) {
		void __user *ss_sp = ss->ss_sp;
		size_t ss_size = ss->ss_size;
		unsigned ss_flags = ss->ss_flags;
		int ss_mode;

		if (unlikely(on_sig_stack(sp)))
			return -EPERM;

		ss_mode = ss_flags & ~SS_FLAG_BITS;
		if (unlikely(ss_mode != SS_DISABLE && ss_mode != SS_ONSTACK &&
				ss_mode != 0))
			return -EINVAL;

		/*
		if (t->sas_ss_sp == (unsigned long)ss_sp &&
		    t->sas_ss_size == ss_size &&
		    t->sas_ss_flags == ss_flags)
			return 0;

		sigaltstack_lock();
		if (ss_mode == SS_DISABLE) {
			ss_size = 0;
			ss_sp = NULL;
		} else {
			if (unlikely(ss_size < min_ss_size))
				ret = -ENOMEM;
			if (!sigaltstack_size_valid(ss_size))
				ret = -ENOMEM;
		}
		if (!ret) {
			t->sas_ss_sp = (unsigned long) ss_sp;
			t->sas_ss_size = ss_size;
			t->sas_ss_flags = ss_flags;
		}
		sigaltstack_unlock();
	}
	return ret;
}

SYSCALL_DEFINE2(sigaltstack,const stack_t __user *,uss, stack_t __user *,uoss)
{
	stack_t new, old;
	int err;
	if (uss && copy_from_user(&new, uss, sizeof(stack_t)))
		return -EFAULT;
	err = do_sigaltstack(uss ? &new : NULL, uoss ? &old : NULL,
			      current_user_stack_pointer(),
			      MINSIGSTKSZ);
	if (!err && uoss && copy_to_user(uoss, &old, sizeof(stack_t)))
		err = -EFAULT;
	return err;
}

int restore_altstack(const stack_t __user *uss)
{
	stack_t new;
	if (copy_from_user(&new, uss, sizeof(stack_t)))
		return -EFAULT;
	(void)do_sigaltstack(&new, NULL, current_user_stack_pointer(),
			     MINSIGSTKSZ);
	/* squash all but EFAULT for now */
	return 0;
}

int __save_altstack(stack_t __user *uss, unsigned long sp)
{
	struct task_struct *t = current;
	int err = __put_user((void __user *)t->sas_ss_sp, &uss->ss_sp) |
		__put_user(t->sas_ss_flags, &uss->ss_flags) |
		__put_user(t->sas_ss_size, &uss->ss_size);
	return err;
}

#ifdef CONFIG_COMPAT
static int do_compat_sigaltstack(const compat_stack_t __user *uss_ptr,
				 compat_stack_t __user *uoss_ptr)
{
	stack_t uss, uoss;
	int ret;

	if (uss_ptr) {
		compat_stack_t uss32;
		if (copy_from_user(&uss32, uss_ptr, sizeof(compat_stack_t)))
			return -EFAULT;
		uss.ss_sp = compat_ptr(uss32.ss_sp);
		uss.ss_flags = uss32.ss_flags;
		uss.ss_size = uss32.ss_size;
	}
	ret = do_sigaltstack(uss_ptr ? &uss : NULL, &uoss,
			     compat_user_stack_pointer(),
			     COMPAT_MINSIGSTKSZ);
	if (ret >= 0 && uoss_ptr)  {
		compat_stack_t old;
		memset(&old, 0, sizeof(old));
		old.ss_sp = ptr_to_compat(uoss.ss_sp);
		old.ss_flags = uoss.ss_flags;
		old.ss_size = uoss.ss_size;
		if (copy_to_user(uoss_ptr, &old, sizeof(compat_stack_t)))
			ret = -EFAULT;
	}
	return ret;
}

COMPAT_SYSCALL_DEFINE2(sigaltstack,
			const compat_stack_t __user *, uss_ptr,
			compat_stack_t __user *, uoss_ptr)
{
	return do_compat_sigaltstack(uss_ptr, uoss_ptr);
}

int compat_restore_altstack(const compat_stack_t __user *uss)
{
	int err = do_compat_sigaltstack(uss, NULL);
	/* squash all but -EFAULT for now */
	return err == -EFAULT ? err : 0;
}

int __compat_save_altstack(compat_stack_t __user *uss, unsigned long sp)
{
	int err;
	struct task_struct *t = current;
	err = __put_user(ptr_to_compat((void __user *)t->sas_ss_sp),
			 &uss->ss_sp) |
		__put_user(t->sas_ss_flags, &uss->ss_flags) |
		__put_user(t->sas_ss_size, &uss->ss_size);
	return err;
}
#endif

#ifdef __ARCH_WANT_SYS_SIGPENDING

SYSCALL_DEFINE1(sigpending, old_sigset_t __user *, uset)
{
	sigset_t set;

	if (sizeof(old_sigset_t) > sizeof(*uset))
		return -EINVAL;

	do_sigpending(&set);

	if (copy_to_user(uset, &set, sizeof(old_sigset_t)))
		return -EFAULT;

	return 0;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE1(sigpending, compat_old_sigset_t __user *, set32)
{
	sigset_t set;

	do_sigpending(&set);

	return put_user(set.sig[0], set32);
}
#endif

#endif

#ifdef __ARCH_WANT_SYS_SIGPROCMASK

SYSCALL_DEFINE3(sigprocmask, int, how, old_sigset_t __user *, nset,
		old_sigset_t __user *, oset)
{
	old_sigset_t old_set, new_set;
	sigset_t new_blocked;

	old_set = current->blocked.sig[0];

	if (nset) {
		if (copy_from_user(&new_set, nset, sizeof(*nset)))
			return -EFAULT;

		new_blocked = current->blocked;

		switch (how) {
		case SIG_BLOCK:
			sigaddsetmask(&new_blocked, new_set);
			break;
		case SIG_UNBLOCK:
			sigdelsetmask(&new_blocked, new_set);
			break;
		case SIG_SETMASK:
			new_blocked.sig[0] = new_set;
			break;
		default:
			return -EINVAL;
		}

		set_current_blocked(&new_blocked);
	}

	if (oset) {
		if (copy_to_user(oset, &old_set, sizeof(*oset)))
			return -EFAULT;
	}

	return 0;
}
#endif /* __ARCH_WANT_SYS_SIGPROCMASK */

#ifndef CONFIG_ODD_RT_SIGACTION
SYSCALL_DEFINE4(rt_sigaction, int, sig,
		const struct sigaction __user *, act,
		struct sigaction __user *, oact,
		size_t, sigsetsize)
{
	struct k_sigaction new_sa, old_sa;
	int ret;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (act && copy_from_user(&new_sa.sa, act, sizeof(new_sa.sa)))
		return -EFAULT;

	ret = do_sigaction(sig, act ? &new_sa : NULL, oact ? &old_sa : NULL);
	if (ret)
		return ret;

	if (oact && copy_to_user(oact, &old_sa.sa, sizeof(old_sa.sa)))
		return -EFAULT;

	return 0;
}
#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(rt_sigaction, int, sig,
		const struct compat_sigaction __user *, act,
		struct compat_sigaction __user *, oact,
		compat_size_t, sigsetsize)
{
	struct k_sigaction new_ka, old_ka;
#ifdef __ARCH_HAS_SA_RESTORER
	compat_uptr_t restorer;
#endif
	int ret;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(compat_sigset_t))
		return -EINVAL;

	if (act) {
		compat_uptr_t handler;
		ret = get_user(handler, &act->sa_handler);
		new_ka.sa.sa_handler = compat_ptr(handler);
#ifdef __ARCH_HAS_SA_RESTORER
		ret |= get_user(restorer, &act->sa_restorer);
		new_ka.sa.sa_restorer = compat_ptr(restorer);
#endif
		ret |= get_compat_sigset(&new_ka.sa.sa_mask, &act->sa_mask);
		ret |= get_user(new_ka.sa.sa_flags, &act->sa_flags);
		if (ret)
			return -EFAULT;
	}

	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);
	if (!ret && oact) {
		ret = put_user(ptr_to_compat(old_ka.sa.sa_handler), 
			       &oact->sa_handler);
		ret |= put_compat_sigset(&oact->sa_mask, &old_ka.sa.sa_mask,
					 sizeof(oact->sa_mask));
		ret |= put_user(old_ka.sa.sa_flags, &oact->sa_flags);
#ifdef __ARCH_HAS_SA_RESTORER
		ret |= put_user(ptr_to_compat(old_ka.sa.sa_restorer),
				&oact->sa_restorer);
#endif
	}
	return ret;
}
#endif
#endif /* !CONFIG_ODD_RT_SIGACTION */

#ifdef CONFIG_OLD_SIGACTION
SYSCALL_DEFINE3(sigaction, int, sig,
		const struct old_sigaction __user *, act,
	        struct old_sigaction __user *, oact)
{
	struct k_sigaction new_ka, old_ka;
	int ret;

	if (act) {
		old_sigset_t mask;
		if (!access_ok(act, sizeof(*act)) ||
		    __get_user(new_ka.sa.sa_handler, &act->sa_handler) ||
		    __get_user(new_ka.sa.sa_restorer, &act->sa_restorer) ||
		    __get_user(new_ka.sa.sa_flags, &act->sa_flags) ||
		    __get_user(mask, &act->sa_mask))
			return -EFAULT;
#ifdef __ARCH_HAS_KA_RESTORER
		new_ka.ka_restorer = NULL;
#endif
		siginitset(&new_ka.sa.sa_mask, mask);
	}

	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

	if (!ret && oact) {
		if (!access_ok(oact, sizeof(*oact)) ||
		    __put_user(old_ka.sa.sa_handler, &oact->sa_handler) ||
		    __put_user(old_ka.sa.sa_restorer, &oact->sa_restorer) ||
		    __put_user(old_ka.sa.sa_flags, &oact->sa_flags) ||
		    __put_user(old_ka.sa.sa_mask.sig[0], &oact->sa_mask))
			return -EFAULT;
	}

	return ret;
}
#endif
#ifdef CONFIG_COMPAT_OLD_SIGACTION
COMPAT_SYSCALL_DEFINE3(sigaction, int, sig,
		const struct compat_old_sigaction __user *, act,
	        struct compat_old_sigaction __user *, oact)
{
	struct k_sigaction new_ka, old_ka;
	int ret;
	compat_old_sigset_t mask;
	compat_uptr_t handler, restorer;

	if (act) {
		if (!access_ok(act, sizeof(*act)) ||
		    __get_user(handler, &act->sa_handler) ||
		    __get_user(restorer, &act->sa_restorer) ||
		    __get_user(new_ka.sa.sa_flags, &act->sa_flags) ||
		    __get_user(mask, &act->sa_mask))
			return -EFAULT;

#ifdef __ARCH_HAS_KA_RESTORER
		new_ka.ka_restorer = NULL;
#endif
		new_ka.sa.sa_handler = compat_ptr(handler);
		new_ka.sa.sa_restorer = compat_ptr(restorer);
		siginitset(&new_ka.sa.sa_mask, mask);
	}

	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

	if (!ret && oact) {
		if (!access_ok(oact, sizeof(*oact)) ||
		    __put_user(ptr_to_compat(old_ka.sa.sa_handler),
			       &oact->sa_handler) ||
		    __put_user(ptr_to_compat(old_ka.sa.sa_restorer),
			       &oact->sa_restorer) ||
		    __put_user(old_ka.sa.sa_flags, &oact->sa_flags) ||
		    __put_user(old_ka.sa.sa_mask.sig[0], &oact->sa_mask))
			return -EFAULT;
	}
	return ret;
}
#endif

#ifdef CONFIG_SGETMASK_SYSCALL

SYSCALL_DEFINE0(sgetmask)
{
	/* SMP safe */
	return current->blocked.sig[0];
}

SYSCALL_DEFINE1(ssetmask, int, newmask)
{
	int old = current->blocked.sig[0];
	sigset_t newset;

	siginitset(&newset, newmask);
	set_current_blocked(&newset);

	return old;
}
#endif /* CONFIG_SGETMASK_SYSCALL */

#ifdef __ARCH_WANT_SYS_SIGNAL
SYSCALL_DEFINE2(signal, int, sig, __sighandler_t, handler)
{
	struct k_sigaction new_sa, old_sa;
	int ret;

	new_sa.sa.sa_handler = handler;
	new_sa.sa.sa_flags = SA_ONESHOT | SA_NOMASK;
	sigemptyset(&new_sa.sa.sa_mask);

	ret = do_sigaction(sig, &new_sa, &old_sa);

	return ret ? ret : (unsigned long)old_sa.sa.sa_handler;
}
#endif /* __ARCH_WANT_SYS_SIGNAL */

#ifdef __ARCH_WANT_SYS_PAUSE

SYSCALL_DEFINE0(pause)
{
	while (!signal_pending(current)) {
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return -ERESTARTNOHAND;
}

#endif

static int sigsuspend(sigset_t *set)
{
	current->saved_sigmask = current->blocked;
	set_current_blocked(set);

	while (!signal_pending(current)) {
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	set_restore_sigmask();
	return -ERESTARTNOHAND;
}

SYSCALL_DEFINE2(rt_sigsuspend, sigset_t __user *, unewset, size_t, sigsetsize)
{
	sigset_t newset;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&newset, unewset, sizeof(newset)))
		return -EFAULT;
	return sigsuspend(&newset);
}
 
#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(rt_sigsuspend, compat_sigset_t __user *, unewset, compat_size_t, sigsetsize)
{
	sigset_t newset;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (get_compat_sigset(&newset, unewset))
		return -EFAULT;
	return sigsuspend(&newset);
}
#endif

#ifdef CONFIG_OLD_SIGSUSPEND
SYSCALL_DEFINE1(sigsuspend, old_sigset_t, mask)
{
	sigset_t blocked;
	siginitset(&blocked, mask);
	return sigsuspend(&blocked);
}
#endif
#ifdef CONFIG_OLD_SIGSUSPEND3
SYSCALL_DEFINE3(sigsuspend, int, unused1, int, unused2, old_sigset_t, mask)
{
	sigset_t blocked;
	siginitset(&blocked, mask);
	return sigsuspend(&blocked);
}
#endif

__weak const char *arch_vma_name(struct vm_area_struct *vma)
{
	return NULL;
}

static inline void siginfo_buildtime_checks(void)
{
	BUILD_BUG_ON(sizeof(struct siginfo) != SI_MAX_SIZE);

	/* Verify the offsets in the two siginfos match */
#define CHECK_OFFSET(field) \
	BUILD_BUG_ON(offsetof(siginfo_t, field) != offsetof(kernel_siginfo_t, field))

	/* kill */
	CHECK_OFFSET(si_pid);
	CHECK_OFFSET(si_uid);

	/* timer */
	CHECK_OFFSET(si_tid);
	CHECK_OFFSET(si_overrun);
	CHECK_OFFSET(si_value);

	/* rt */
	CHECK_OFFSET(si_pid);
	CHECK_OFFSET(si_uid);
	CHECK_OFFSET(si_value);

	/* sigchld */
	CHECK_OFFSET(si_pid);
	CHECK_OFFSET(si_uid);
	CHECK_OFFSET(si_status);
	CHECK_OFFSET(si_utime);
	CHECK_OFFSET(si_stime);

	/* sigfault */
	CHECK_OFFSET(si_addr);
	CHECK_OFFSET(si_trapno);
	CHECK_OFFSET(si_addr_lsb);
	CHECK_OFFSET(si_lower);
	CHECK_OFFSET(si_upper);
	CHECK_OFFSET(si_pkey);
	CHECK_OFFSET(si_perf_data);
	CHECK_OFFSET(si_perf_type);
	CHECK_OFFSET(si_perf_flags);

	/* sigpoll */
	CHECK_OFFSET(si_band);
	CHECK_OFFSET(si_fd);

	/* sigsys */
	CHECK_OFFSET(si_call_addr);
	CHECK_OFFSET(si_syscall);
	CHECK_OFFSET(si_arch);
#undef CHECK_OFFSET

	/* usb asyncio */
	BUILD_BUG_ON(offsetof(struct siginfo, si_pid) !=
		     offsetof(struct siginfo, si_addr));
	if (sizeof(int) == sizeof(void __user *)) {
		BUILD_BUG_ON(sizeof_field(struct siginfo, si_pid) !=
			     sizeof(void __user *));
	} else {
		BUILD_BUG_ON((sizeof_field(struct siginfo, si_pid) +
			      sizeof_field(struct siginfo, si_uid)) !=
			     sizeof(void __user *));
		BUILD_BUG_ON(offsetofend(struct siginfo, si_pid) !=
			     offsetof(struct siginfo, si_uid));
	}
#ifdef CONFIG_COMPAT
	BUILD_BUG_ON(offsetof(struct compat_siginfo, si_pid) !=
		     offsetof(struct compat_siginfo, si_addr));
	BUILD_BUG_ON(sizeof_field(struct compat_siginfo, si_pid) !=
		     sizeof(compat_uptr_t));
	BUILD_BUG_ON(sizeof_field(struct compat_siginfo, si_pid) !=
		     sizeof_field(struct siginfo, si_pid));
#endif
}

void __init signals_init(void)
{
	siginfo_buildtime_checks();

	sigqueue_cachep = KMEM_CACHE(sigqueue, SLAB_PANIC | SLAB_ACCOUNT);
}

#ifdef CONFIG_KGDB_KDB
#include <linux/kdb.h>
void kdb_send_sig(struct task_struct *t, int sig)
{
	static struct task_struct *kdb_prev_t;
	int new_t, ret;
	if (!spin_trylock(&t->sighand->siglock)) {
		kdb_printf("Can't do kill command now.\n"
			   "The sigmask lock is held somewhere else in "
			   "kernel, try again later\n");
		return;
	}
	new_t = kdb_prev_t != t;
	kdb_prev_t = t;
	if (!task_is_running(t) && new_t) {
		spin_unlock(&t->sighand->siglock);
		kdb_printf("Process is not RUNNING, sending a signal from "
			   "kdb risks deadlock\n"
			   "on the run queue locks. "
			   "The signal has _not_ been sent.\n"
			   "Reissue the kill command if you want to risk "
			   "the deadlock.\n");
		return;
	}
	ret = send_signal_locked(sig, SEND_SIG_PRIV, t, PIDTYPE_PID);
	spin_unlock(&t->sighand->siglock);
	if (ret)
		kdb_printf("Fail to deliver Signal %d to process %d.\n",
			   sig, t->pid);
	else
		kdb_printf("Signal %d is sent to process %d.\n", sig, t->pid);
}
#endif	/* CONFIG_KGDB_KDB */
