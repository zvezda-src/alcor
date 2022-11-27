
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/mm.h>
#include <linux/sched/stat.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/tty.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/cpu.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/freezer.h>
#include <linux/binfmts.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/profile.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/cgroup.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/posix-timers.h>
#include <linux/cn_proc.h>
#include <linux/mutex.h>
#include <linux/futex.h>
#include <linux/pipe_fs_i.h>
#include <linux/audit.h> /* for audit_free() */
#include <linux/resource.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/blkdev.h>
#include <linux/task_work.h>
#include <linux/fs_struct.h>
#include <linux/init_task.h>
#include <linux/perf_event.h>
#include <trace/events/sched.h>
#include <linux/hw_breakpoint.h>
#include <linux/oom.h>
#include <linux/writeback.h>
#include <linux/shm.h>
#include <linux/kcov.h>
#include <linux/random.h>
#include <linux/rcuwait.h>
#include <linux/compat.h>
#include <linux/io_uring.h>
#include <linux/kprobes.h>
#include <linux/rethook.h>

#include <linux/uaccess.h>
#include <asm/unistd.h>
#include <asm/mmu_context.h>

static void __unhash_process(struct task_struct *p, bool group_dead)
{
	nr_threads--;
	detach_pid(p, PIDTYPE_PID);
	if (group_dead) {
		detach_pid(p, PIDTYPE_TGID);
		detach_pid(p, PIDTYPE_PGID);
		detach_pid(p, PIDTYPE_SID);

		list_del_rcu(&p->tasks);
		list_del_init(&p->sibling);
		__this_cpu_dec(process_counts);
	}
	list_del_rcu(&p->thread_group);
	list_del_rcu(&p->thread_node);
}

static void __exit_signal(struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;
	bool group_dead = thread_group_leader(tsk);
	struct sighand_struct *sighand;
	struct tty_struct *tty;
	u64 utime, stime;

	sighand = rcu_dereference_check(tsk->sighand,
					lockdep_tasklist_lock_is_held());
	spin_lock(&sighand->siglock);

#ifdef CONFIG_POSIX_TIMERS
	posix_cpu_timers_exit(tsk);
	if (group_dead)
		posix_cpu_timers_exit_group(tsk);
#endif

	if (group_dead) {
		tty = sig->tty;
		sig->tty = NULL;
	} else {
		/*
		if (sig->notify_count > 0 && !--sig->notify_count)
			wake_up_process(sig->group_exec_task);

		if (tsk == sig->curr_target)
			sig->curr_target = next_thread(tsk);
	}

	add_device_randomness((const void*) &tsk->se.sum_exec_runtime,
			      sizeof(unsigned long long));

	/*
	task_cputime(tsk, &utime, &stime);
	write_seqlock(&sig->stats_lock);
	sig->utime += utime;
	sig->stime += stime;
	sig->gtime += task_gtime(tsk);
	sig->min_flt += tsk->min_flt;
	sig->maj_flt += tsk->maj_flt;
	sig->nvcsw += tsk->nvcsw;
	sig->nivcsw += tsk->nivcsw;
	sig->inblock += task_io_get_inblock(tsk);
	sig->oublock += task_io_get_oublock(tsk);
	task_io_accounting_add(&sig->ioac, &tsk->ioac);
	sig->sum_sched_runtime += tsk->se.sum_exec_runtime;
	sig->nr_threads--;
	__unhash_process(tsk, group_dead);
	write_sequnlock(&sig->stats_lock);

	/*
	flush_sigqueue(&tsk->pending);
	tsk->sighand = NULL;
	spin_unlock(&sighand->siglock);

	__cleanup_sighand(sighand);
	clear_tsk_thread_flag(tsk, TIF_SIGPENDING);
	if (group_dead) {
		flush_sigqueue(&sig->shared_pending);
		tty_kref_put(tty);
	}
}

static void delayed_put_task_struct(struct rcu_head *rhp)
{
	struct task_struct *tsk = container_of(rhp, struct task_struct, rcu);

	kprobe_flush_task(tsk);
	rethook_flush_task(tsk);
	perf_event_delayed_put(tsk);
	trace_sched_process_free(tsk);
	put_task_struct(tsk);
}

void put_task_struct_rcu_user(struct task_struct *task)
{
	if (refcount_dec_and_test(&task->rcu_users))
		call_rcu(&task->rcu, delayed_put_task_struct);
}

void release_task(struct task_struct *p)
{
	struct task_struct *leader;
	struct pid *thread_pid;
	int zap_leader;
repeat:
	/* don't need to get the RCU readlock here - the process is dead and
	 * can't be modifying its own credentials. But shut RCU-lockdep up */
	rcu_read_lock();
	dec_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
	rcu_read_unlock();

	cgroup_release(p);

	write_lock_irq(&tasklist_lock);
	ptrace_release_task(p);
	thread_pid = get_pid(p->thread_pid);
	__exit_signal(p);

	/*
	zap_leader = 0;
	leader = p->group_leader;
	if (leader != p && thread_group_empty(leader)
			&& leader->exit_state == EXIT_ZOMBIE) {
		/*
		zap_leader = do_notify_parent(leader, leader->exit_signal);
		if (zap_leader)
			leader->exit_state = EXIT_DEAD;
	}

	write_unlock_irq(&tasklist_lock);
	seccomp_filter_release(p);
	proc_flush_pid(thread_pid);
	put_pid(thread_pid);
	release_thread(p);
	put_task_struct_rcu_user(p);

	p = leader;
	if (unlikely(zap_leader))
		goto repeat;
}

int rcuwait_wake_up(struct rcuwait *w)
{
	int ret = 0;
	struct task_struct *task;

	rcu_read_lock();

	/*
	smp_mb(); /* (B) */

	task = rcu_dereference(w->task);
	if (task)
		ret = wake_up_process(task);
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(rcuwait_wake_up);

static int will_become_orphaned_pgrp(struct pid *pgrp,
					struct task_struct *ignored_task)
{
	struct task_struct *p;

	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
		if ((p == ignored_task) ||
		    (p->exit_state && thread_group_empty(p)) ||
		    is_global_init(p->real_parent))
			continue;

		if (task_pgrp(p->real_parent) != pgrp &&
		    task_session(p->real_parent) == task_session(p))
			return 0;
	} while_each_pid_task(pgrp, PIDTYPE_PGID, p);

	return 1;
}

int is_current_pgrp_orphaned(void)
{
	int retval;

	read_lock(&tasklist_lock);
	retval = will_become_orphaned_pgrp(task_pgrp(current), NULL);
	read_unlock(&tasklist_lock);

	return retval;
}

static bool has_stopped_jobs(struct pid *pgrp)
{
	struct task_struct *p;

	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
		if (p->signal->flags & SIGNAL_STOP_STOPPED)
			return true;
	} while_each_pid_task(pgrp, PIDTYPE_PGID, p);

	return false;
}

static void
kill_orphaned_pgrp(struct task_struct *tsk, struct task_struct *parent)
{
	struct pid *pgrp = task_pgrp(tsk);
	struct task_struct *ignored_task = tsk;

	if (!parent)
		/* exit: our father is in a different pgrp than
		 * we are and we were the only connection outside.
		 */
		parent = tsk->real_parent;
	else
		/* reparent: our child is in a different pgrp than
		 * we are, and it was the only connection outside.
		 */
		ignored_task = NULL;

	if (task_pgrp(parent) != pgrp &&
	    task_session(parent) == task_session(tsk) &&
	    will_become_orphaned_pgrp(pgrp, ignored_task) &&
	    has_stopped_jobs(pgrp)) {
		__kill_pgrp_info(SIGHUP, SEND_SIG_PRIV, pgrp);
		__kill_pgrp_info(SIGCONT, SEND_SIG_PRIV, pgrp);
	}
}

static void coredump_task_exit(struct task_struct *tsk)
{
	struct core_state *core_state;

	/*
	spin_lock_irq(&tsk->sighand->siglock);
	tsk->flags |= PF_POSTCOREDUMP;
	core_state = tsk->signal->core_state;
	spin_unlock_irq(&tsk->sighand->siglock);
	if (core_state) {
		struct core_thread self;

		self.task = current;
		if (self.task->flags & PF_SIGNALED)
			self.next = xchg(&core_state->dumper.next, &self);
		else
			self.task = NULL;
		/*
		if (atomic_dec_and_test(&core_state->nr_threads))
			complete(&core_state->startup);

		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (!self.task) /* see coredump_finish() */
				break;
			freezable_schedule();
		}
		__set_current_state(TASK_RUNNING);
	}
}

#ifdef CONFIG_MEMCG
void mm_update_next_owner(struct mm_struct *mm)
{
	struct task_struct *c, *g, *p = current;

retry:
	/*
	if (mm->owner != p)
		return;
	/*
	if (atomic_read(&mm->mm_users) <= 1) {
		WRITE_ONCE(mm->owner, NULL);
		return;
	}

	read_lock(&tasklist_lock);
	/*
	list_for_each_entry(c, &p->children, sibling) {
		if (c->mm == mm)
			goto assign_new_owner;
	}

	/*
	list_for_each_entry(c, &p->real_parent->children, sibling) {
		if (c->mm == mm)
			goto assign_new_owner;
	}

	/*
	for_each_process(g) {
		if (g->flags & PF_KTHREAD)
			continue;
		for_each_thread(g, c) {
			if (c->mm == mm)
				goto assign_new_owner;
			if (c->mm)
				break;
		}
	}
	read_unlock(&tasklist_lock);
	/*
	WRITE_ONCE(mm->owner, NULL);
	return;

assign_new_owner:
	BUG_ON(c == p);
	get_task_struct(c);
	/*
	task_lock(c);
	/*
	read_unlock(&tasklist_lock);
	if (c->mm != mm) {
		task_unlock(c);
		put_task_struct(c);
		goto retry;
	}
	WRITE_ONCE(mm->owner, c);
	task_unlock(c);
	put_task_struct(c);
}
#endif /* CONFIG_MEMCG */

static void exit_mm(void)
{
	struct mm_struct *mm = current->mm;

	exit_mm_release(current, mm);
	if (!mm)
		return;
	sync_mm_rss(mm);
	mmap_read_lock(mm);
	mmgrab(mm);
	BUG_ON(mm != current->active_mm);
	/* more a memory barrier than a real lock */
	task_lock(current);
	/*
	smp_mb__after_spinlock();
	local_irq_disable();
	current->mm = NULL;
	membarrier_update_current_mm(NULL);
	enter_lazy_tlb(mm, current);
	local_irq_enable();
	task_unlock(current);
	mmap_read_unlock(mm);
	mm_update_next_owner(mm);
	mmput(mm);
	if (test_thread_flag(TIF_MEMDIE))
		exit_oom_victim();
}

static struct task_struct *find_alive_thread(struct task_struct *p)
{
	struct task_struct *t;

	for_each_thread(p, t) {
		if (!(t->flags & PF_EXITING))
			return t;
	}
	return NULL;
}

static struct task_struct *find_child_reaper(struct task_struct *father,
						struct list_head *dead)
	__releases(&tasklist_lock)
	__acquires(&tasklist_lock)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(father);
	struct task_struct *reaper = pid_ns->child_reaper;
	struct task_struct *p, *n;

	if (likely(reaper != father))
		return reaper;

	reaper = find_alive_thread(father);
	if (reaper) {
		pid_ns->child_reaper = reaper;
		return reaper;
	}

	write_unlock_irq(&tasklist_lock);

	list_for_each_entry_safe(p, n, dead, ptrace_entry) {
		list_del_init(&p->ptrace_entry);
		release_task(p);
	}

	zap_pid_ns_processes(pid_ns);
	write_lock_irq(&tasklist_lock);

	return father;
}

static struct task_struct *find_new_reaper(struct task_struct *father,
					   struct task_struct *child_reaper)
{
	struct task_struct *thread, *reaper;

	thread = find_alive_thread(father);
	if (thread)
		return thread;

	if (father->signal->has_child_subreaper) {
		unsigned int ns_level = task_pid(father)->level;
		/*
		for (reaper = father->real_parent;
		     task_pid(reaper)->level == ns_level;
		     reaper = reaper->real_parent) {
			if (reaper == &init_task)
				break;
			if (!reaper->signal->is_child_subreaper)
				continue;
			thread = find_alive_thread(reaper);
			if (thread)
				return thread;
		}
	}

	return child_reaper;
}

static void reparent_leader(struct task_struct *father, struct task_struct *p,
				struct list_head *dead)
{
	if (unlikely(p->exit_state == EXIT_DEAD))
		return;

	/* We don't want people slaying init. */
	p->exit_signal = SIGCHLD;

	/* If it has exited notify the new parent about this child's death. */
	if (!p->ptrace &&
	    p->exit_state == EXIT_ZOMBIE && thread_group_empty(p)) {
		if (do_notify_parent(p, p->exit_signal)) {
			p->exit_state = EXIT_DEAD;
			list_add(&p->ptrace_entry, dead);
		}
	}

	kill_orphaned_pgrp(p, father);
}

static void forget_original_parent(struct task_struct *father,
					struct list_head *dead)
{
	struct task_struct *p, *t, *reaper;

	if (unlikely(!list_empty(&father->ptraced)))
		exit_ptrace(father, dead);

	/* Can drop and reacquire tasklist_lock */
	reaper = find_child_reaper(father, dead);
	if (list_empty(&father->children))
		return;

	reaper = find_new_reaper(father, reaper);
	list_for_each_entry(p, &father->children, sibling) {
		for_each_thread(p, t) {
			RCU_INIT_POINTER(t->real_parent, reaper);
			BUG_ON((!t->ptrace) != (rcu_access_pointer(t->parent) == father));
			if (likely(!t->ptrace))
				t->parent = t->real_parent;
			if (t->pdeath_signal)
				group_send_sig_info(t->pdeath_signal,
						    SEND_SIG_NOINFO, t,
						    PIDTYPE_TGID);
		}
		/*
		if (!same_thread_group(reaper, father))
			reparent_leader(father, p, dead);
	}
	list_splice_tail_init(&father->children, &reaper->children);
}

static void exit_notify(struct task_struct *tsk, int group_dead)
{
	bool autoreap;
	struct task_struct *p, *n;
	LIST_HEAD(dead);

	write_lock_irq(&tasklist_lock);
	forget_original_parent(tsk, &dead);

	if (group_dead)
		kill_orphaned_pgrp(tsk->group_leader, NULL);

	tsk->exit_state = EXIT_ZOMBIE;
	if (unlikely(tsk->ptrace)) {
		int sig = thread_group_leader(tsk) &&
				thread_group_empty(tsk) &&
				!ptrace_reparented(tsk) ?
			tsk->exit_signal : SIGCHLD;
		autoreap = do_notify_parent(tsk, sig);
	} else if (thread_group_leader(tsk)) {
		autoreap = thread_group_empty(tsk) &&
			do_notify_parent(tsk, tsk->exit_signal);
	} else {
		autoreap = true;
	}

	if (autoreap) {
		tsk->exit_state = EXIT_DEAD;
		list_add(&tsk->ptrace_entry, &dead);
	}

	/* mt-exec, de_thread() is waiting for group leader */
	if (unlikely(tsk->signal->notify_count < 0))
		wake_up_process(tsk->signal->group_exec_task);
	write_unlock_irq(&tasklist_lock);

	list_for_each_entry_safe(p, n, &dead, ptrace_entry) {
		list_del_init(&p->ptrace_entry);
		release_task(p);
	}
}

#ifdef CONFIG_DEBUG_STACK_USAGE
static void check_stack_usage(void)
{
	static DEFINE_SPINLOCK(low_water_lock);
	static int lowest_to_date = THREAD_SIZE;
	unsigned long free;

	free = stack_not_used(current);

	if (free >= lowest_to_date)
		return;

	spin_lock(&low_water_lock);
	if (free < lowest_to_date) {
		pr_info("%s (%d) used greatest stack depth: %lu bytes left\n",
			current->comm, task_pid_nr(current), free);
		lowest_to_date = free;
	}
	spin_unlock(&low_water_lock);
}
#else
static inline void check_stack_usage(void) {}
#endif

void __noreturn do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;

	WARN_ON(tsk->plug);

	kcov_task_exit(tsk);

	coredump_task_exit(tsk);
	ptrace_event(PTRACE_EVENT_EXIT, code);

	validate_creds_for_do_exit(tsk);

	io_uring_files_cancel();
	exit_signals(tsk);  /* sets PF_EXITING */

	/* sync mm's RSS info before statistics gathering */
	if (tsk->mm)
		sync_mm_rss(tsk->mm);
	acct_update_integrals(tsk);
	group_dead = atomic_dec_and_test(&tsk->signal->live);
	if (group_dead) {
		/*
		if (unlikely(is_global_init(tsk)))
			panic("Attempted to kill init! exitcode=0x%08x\n",
				tsk->signal->group_exit_code ?: (int)code);

#ifdef CONFIG_POSIX_TIMERS
		hrtimer_cancel(&tsk->signal->real_timer);
		exit_itimers(tsk);
#endif
		if (tsk->mm)
			setmax_mm_hiwater_rss(&tsk->signal->maxrss, tsk->mm);
	}
	acct_collect(code, group_dead);
	if (group_dead)
		tty_audit_exit();
	audit_free(tsk);

	tsk->exit_code = code;
	taskstats_exit(tsk, group_dead);

	exit_mm();

	if (group_dead)
		acct_process();
	trace_sched_process_exit(tsk);

	exit_sem(tsk);
	exit_shm(tsk);
	exit_files(tsk);
	exit_fs(tsk);
	if (group_dead)
		disassociate_ctty(1);
	exit_task_namespaces(tsk);
	exit_task_work(tsk);
	exit_thread(tsk);

	/*
	perf_event_exit_task(tsk);

	sched_autogroup_exit_task(tsk);
	cgroup_exit(tsk);

	/*
	flush_ptrace_hw_breakpoint(tsk);

	exit_tasks_rcu_start();
	exit_notify(tsk, group_dead);
	proc_exit_connector(tsk);
	mpol_put_task_policy(tsk);
#ifdef CONFIG_FUTEX
	if (unlikely(current->pi_state_cache))
		kfree(current->pi_state_cache);
#endif
	/*
	debug_check_no_locks_held();

	if (tsk->io_context)
		exit_io_context(tsk);

	if (tsk->splice_pipe)
		free_pipe_info(tsk->splice_pipe);

	if (tsk->task_frag.page)
		put_page(tsk->task_frag.page);

	validate_creds_for_do_exit(tsk);
	exit_task_stack_account(tsk);

	check_stack_usage();
	preempt_disable();
	if (tsk->nr_dirtied)
		__this_cpu_add(dirty_throttle_leaks, tsk->nr_dirtied);
	exit_rcu();
	exit_tasks_rcu_finish();

	lockdep_free_task(tsk);
	do_task_dead();
}

void __noreturn make_task_dead(int signr)
{
	/*
	struct task_struct *tsk = current;

	if (unlikely(in_interrupt()))
		panic("Aiee, killing interrupt handler!");
	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");

	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, task_pid_nr(current),
			preempt_count());
		preempt_count_set(PREEMPT_ENABLED);
	}

	/*
	if (unlikely(tsk->flags & PF_EXITING)) {
		pr_alert("Fixing recursive fault but reboot is needed!\n");
		futex_exit_recursive(tsk);
		tsk->exit_state = EXIT_DEAD;
		refcount_inc(&tsk->rcu_users);
		do_task_dead();
	}

	do_exit(signr);
}

SYSCALL_DEFINE1(exit, int, error_code)
{
	do_exit((error_code&0xff)<<8);
}

void __noreturn
do_group_exit(int exit_code)
{
	struct signal_struct *sig = current->signal;

	if (sig->flags & SIGNAL_GROUP_EXIT)
		exit_code = sig->group_exit_code;
	else if (sig->group_exec_task)
		exit_code = 0;
	else if (!thread_group_empty(current)) {
		struct sighand_struct *const sighand = current->sighand;

		spin_lock_irq(&sighand->siglock);
		if (sig->flags & SIGNAL_GROUP_EXIT)
			/* Another thread got here before we took the lock.  */
			exit_code = sig->group_exit_code;
		else if (sig->group_exec_task)
			exit_code = 0;
		else {
			sig->group_exit_code = exit_code;
			sig->flags = SIGNAL_GROUP_EXIT;
			zap_other_threads(current);
		}
		spin_unlock_irq(&sighand->siglock);
	}

	do_exit(exit_code);
	/* NOTREACHED */
}

SYSCALL_DEFINE1(exit_group, int, error_code)
{
	do_group_exit((error_code & 0xff) << 8);
	/* NOTREACHED */
	return 0;
}

struct waitid_info {
	pid_t pid;
	uid_t uid;
	int status;
	int cause;
};

struct wait_opts {
	enum pid_type		wo_type;
	int			wo_flags;
	struct pid		*wo_pid;

	struct waitid_info	*wo_info;
	int			wo_stat;
	struct rusage		*wo_rusage;

	wait_queue_entry_t		child_wait;
	int			notask_error;
};

static int eligible_pid(struct wait_opts *wo, struct task_struct *p)
{
	return	wo->wo_type == PIDTYPE_MAX ||
		task_pid_type(p, wo->wo_type) == wo->wo_pid;
}

static int
eligible_child(struct wait_opts *wo, bool ptrace, struct task_struct *p)
{
	if (!eligible_pid(wo, p))
		return 0;

	/*
	if (ptrace || (wo->wo_flags & __WALL))
		return 1;

	/*
	if ((p->exit_signal != SIGCHLD) ^ !!(wo->wo_flags & __WCLONE))
		return 0;

	return 1;
}

static int wait_task_zombie(struct wait_opts *wo, struct task_struct *p)
{
	int state, status;
	pid_t pid = task_pid_vnr(p);
	uid_t uid = from_kuid_munged(current_user_ns(), task_uid(p));
	struct waitid_info *infop;

	if (!likely(wo->wo_flags & WEXITED))
		return 0;

	if (unlikely(wo->wo_flags & WNOWAIT)) {
		status = (p->signal->flags & SIGNAL_GROUP_EXIT)
			? p->signal->group_exit_code : p->exit_code;
		get_task_struct(p);
		read_unlock(&tasklist_lock);
		sched_annotate_sleep();
		if (wo->wo_rusage)
			getrusage(p, RUSAGE_BOTH, wo->wo_rusage);
		put_task_struct(p);
		goto out_info;
	}
	/*
	state = (ptrace_reparented(p) && thread_group_leader(p)) ?
		EXIT_TRACE : EXIT_DEAD;
	if (cmpxchg(&p->exit_state, EXIT_ZOMBIE, state) != EXIT_ZOMBIE)
		return 0;
	/*
	read_unlock(&tasklist_lock);
	sched_annotate_sleep();

	/*
	if (state == EXIT_DEAD && thread_group_leader(p)) {
		struct signal_struct *sig = p->signal;
		struct signal_struct *psig = current->signal;
		unsigned long maxrss;
		u64 tgutime, tgstime;

		/*
		thread_group_cputime_adjusted(p, &tgutime, &tgstime);
		spin_lock_irq(&current->sighand->siglock);
		write_seqlock(&psig->stats_lock);
		psig->cutime += tgutime + sig->cutime;
		psig->cstime += tgstime + sig->cstime;
		psig->cgtime += task_gtime(p) + sig->gtime + sig->cgtime;
		psig->cmin_flt +=
			p->min_flt + sig->min_flt + sig->cmin_flt;
		psig->cmaj_flt +=
			p->maj_flt + sig->maj_flt + sig->cmaj_flt;
		psig->cnvcsw +=
			p->nvcsw + sig->nvcsw + sig->cnvcsw;
		psig->cnivcsw +=
			p->nivcsw + sig->nivcsw + sig->cnivcsw;
		psig->cinblock +=
			task_io_get_inblock(p) +
			sig->inblock + sig->cinblock;
		psig->coublock +=
			task_io_get_oublock(p) +
			sig->oublock + sig->coublock;
		maxrss = max(sig->maxrss, sig->cmaxrss);
		if (psig->cmaxrss < maxrss)
			psig->cmaxrss = maxrss;
		task_io_accounting_add(&psig->ioac, &p->ioac);
		task_io_accounting_add(&psig->ioac, &sig->ioac);
		write_sequnlock(&psig->stats_lock);
		spin_unlock_irq(&current->sighand->siglock);
	}

	if (wo->wo_rusage)
		getrusage(p, RUSAGE_BOTH, wo->wo_rusage);
	status = (p->signal->flags & SIGNAL_GROUP_EXIT)
		? p->signal->group_exit_code : p->exit_code;
	wo->wo_stat = status;

	if (state == EXIT_TRACE) {
		write_lock_irq(&tasklist_lock);
		/* We dropped tasklist, ptracer could die and untrace */
		ptrace_unlink(p);

		/* If parent wants a zombie, don't release it now */
		state = EXIT_ZOMBIE;
		if (do_notify_parent(p, p->exit_signal))
			state = EXIT_DEAD;
		p->exit_state = state;
		write_unlock_irq(&tasklist_lock);
	}
	if (state == EXIT_DEAD)
		release_task(p);

out_info:
	infop = wo->wo_info;
	if (infop) {
		if ((status & 0x7f) == 0) {
			infop->cause = CLD_EXITED;
			infop->status = status >> 8;
		} else {
			infop->cause = (status & 0x80) ? CLD_DUMPED : CLD_KILLED;
			infop->status = status & 0x7f;
		}
		infop->pid = pid;
		infop->uid = uid;
	}

	return pid;
}

static int *task_stopped_code(struct task_struct *p, bool ptrace)
{
	if (ptrace) {
		if (task_is_traced(p) && !(p->jobctl & JOBCTL_LISTENING))
			return &p->exit_code;
	} else {
		if (p->signal->flags & SIGNAL_STOP_STOPPED)
			return &p->signal->group_exit_code;
	}
	return NULL;
}

static int wait_task_stopped(struct wait_opts *wo,
				int ptrace, struct task_struct *p)
{
	struct waitid_info *infop;
	int exit_code, *p_code, why;
	uid_t uid = 0; /* unneeded, required by compiler */
	pid_t pid;

	/*
	if (!ptrace && !(wo->wo_flags & WUNTRACED))
		return 0;

	if (!task_stopped_code(p, ptrace))
		return 0;

	exit_code = 0;
	spin_lock_irq(&p->sighand->siglock);

	p_code = task_stopped_code(p, ptrace);
	if (unlikely(!p_code))
		goto unlock_sig;

	exit_code = *p_code;
	if (!exit_code)
		goto unlock_sig;

	if (!unlikely(wo->wo_flags & WNOWAIT))
		*p_code = 0;

	uid = from_kuid_munged(current_user_ns(), task_uid(p));
unlock_sig:
	spin_unlock_irq(&p->sighand->siglock);
	if (!exit_code)
		return 0;

	/*
	get_task_struct(p);
	pid = task_pid_vnr(p);
	why = ptrace ? CLD_TRAPPED : CLD_STOPPED;
	read_unlock(&tasklist_lock);
	sched_annotate_sleep();
	if (wo->wo_rusage)
		getrusage(p, RUSAGE_BOTH, wo->wo_rusage);
	put_task_struct(p);

	if (likely(!(wo->wo_flags & WNOWAIT)))
		wo->wo_stat = (exit_code << 8) | 0x7f;

	infop = wo->wo_info;
	if (infop) {
		infop->cause = why;
		infop->status = exit_code;
		infop->pid = pid;
		infop->uid = uid;
	}
	return pid;
}

static int wait_task_continued(struct wait_opts *wo, struct task_struct *p)
{
	struct waitid_info *infop;
	pid_t pid;
	uid_t uid;

	if (!unlikely(wo->wo_flags & WCONTINUED))
		return 0;

	if (!(p->signal->flags & SIGNAL_STOP_CONTINUED))
		return 0;

	spin_lock_irq(&p->sighand->siglock);
	/* Re-check with the lock held.  */
	if (!(p->signal->flags & SIGNAL_STOP_CONTINUED)) {
		spin_unlock_irq(&p->sighand->siglock);
		return 0;
	}
	if (!unlikely(wo->wo_flags & WNOWAIT))
		p->signal->flags &= ~SIGNAL_STOP_CONTINUED;
	uid = from_kuid_munged(current_user_ns(), task_uid(p));
	spin_unlock_irq(&p->sighand->siglock);

	pid = task_pid_vnr(p);
	get_task_struct(p);
	read_unlock(&tasklist_lock);
	sched_annotate_sleep();
	if (wo->wo_rusage)
		getrusage(p, RUSAGE_BOTH, wo->wo_rusage);
	put_task_struct(p);

	infop = wo->wo_info;
	if (!infop) {
		wo->wo_stat = 0xffff;
	} else {
		infop->cause = CLD_CONTINUED;
		infop->pid = pid;
		infop->uid = uid;
		infop->status = SIGCONT;
	}
	return pid;
}

static int wait_consider_task(struct wait_opts *wo, int ptrace,
				struct task_struct *p)
{
	/*
	int exit_state = READ_ONCE(p->exit_state);
	int ret;

	if (unlikely(exit_state == EXIT_DEAD))
		return 0;

	ret = eligible_child(wo, ptrace, p);
	if (!ret)
		return ret;

	if (unlikely(exit_state == EXIT_TRACE)) {
		/*
		if (likely(!ptrace))
			wo->notask_error = 0;
		return 0;
	}

	if (likely(!ptrace) && unlikely(p->ptrace)) {
		/*
		if (!ptrace_reparented(p))
			ptrace = 1;
	}

	/* slay zombie? */
	if (exit_state == EXIT_ZOMBIE) {
		/* we don't reap group leaders with subthreads */
		if (!delay_group_leader(p)) {
			/*
			if (unlikely(ptrace) || likely(!p->ptrace))
				return wait_task_zombie(wo, p);
		}

		/*
		if (likely(!ptrace) || (wo->wo_flags & (WCONTINUED | WEXITED)))
			wo->notask_error = 0;
	} else {
		/*
		wo->notask_error = 0;
	}

	/*
	ret = wait_task_stopped(wo, ptrace, p);
	if (ret)
		return ret;

	/*
	return wait_task_continued(wo, p);
}

static int do_wait_thread(struct wait_opts *wo, struct task_struct *tsk)
{
	struct task_struct *p;

	list_for_each_entry(p, &tsk->children, sibling) {
		int ret = wait_consider_task(wo, 0, p);

		if (ret)
			return ret;
	}

	return 0;
}

static int ptrace_do_wait(struct wait_opts *wo, struct task_struct *tsk)
{
	struct task_struct *p;

	list_for_each_entry(p, &tsk->ptraced, ptrace_entry) {
		int ret = wait_consider_task(wo, 1, p);

		if (ret)
			return ret;
	}

	return 0;
}

static int child_wait_callback(wait_queue_entry_t *wait, unsigned mode,
				int sync, void *key)
{
	struct wait_opts *wo = container_of(wait, struct wait_opts,
						child_wait);
	struct task_struct *p = key;

	if (!eligible_pid(wo, p))
		return 0;

	if ((wo->wo_flags & __WNOTHREAD) && wait->private != p->parent)
		return 0;

	return default_wake_function(wait, mode, sync, key);
}

void __wake_up_parent(struct task_struct *p, struct task_struct *parent)
{
	__wake_up_sync_key(&parent->signal->wait_chldexit,
			   TASK_INTERRUPTIBLE, p);
}

static bool is_effectively_child(struct wait_opts *wo, bool ptrace,
				 struct task_struct *target)
{
	struct task_struct *parent =
		!ptrace ? target->real_parent : target->parent;

	return current == parent || (!(wo->wo_flags & __WNOTHREAD) &&
				     same_thread_group(current, parent));
}

static int do_wait_pid(struct wait_opts *wo)
{
	bool ptrace;
	struct task_struct *target;
	int retval;

	ptrace = false;
	target = pid_task(wo->wo_pid, PIDTYPE_TGID);
	if (target && is_effectively_child(wo, ptrace, target)) {
		retval = wait_consider_task(wo, ptrace, target);
		if (retval)
			return retval;
	}

	ptrace = true;
	target = pid_task(wo->wo_pid, PIDTYPE_PID);
	if (target && target->ptrace &&
	    is_effectively_child(wo, ptrace, target)) {
		retval = wait_consider_task(wo, ptrace, target);
		if (retval)
			return retval;
	}

	return 0;
}

static long do_wait(struct wait_opts *wo)
{
	int retval;

	trace_sched_process_wait(wo->wo_pid);

	init_waitqueue_func_entry(&wo->child_wait, child_wait_callback);
	wo->child_wait.private = current;
	add_wait_queue(&current->signal->wait_chldexit, &wo->child_wait);
repeat:
	/*
	wo->notask_error = -ECHILD;
	if ((wo->wo_type < PIDTYPE_MAX) &&
	   (!wo->wo_pid || !pid_has_task(wo->wo_pid, wo->wo_type)))
		goto notask;

	set_current_state(TASK_INTERRUPTIBLE);
	read_lock(&tasklist_lock);

	if (wo->wo_type == PIDTYPE_PID) {
		retval = do_wait_pid(wo);
		if (retval)
			goto end;
	} else {
		struct task_struct *tsk = current;

		do {
			retval = do_wait_thread(wo, tsk);
			if (retval)
				goto end;

			retval = ptrace_do_wait(wo, tsk);
			if (retval)
				goto end;

			if (wo->wo_flags & __WNOTHREAD)
				break;
		} while_each_thread(current, tsk);
	}
	read_unlock(&tasklist_lock);

notask:
	retval = wo->notask_error;
	if (!retval && !(wo->wo_flags & WNOHANG)) {
		retval = -ERESTARTSYS;
		if (!signal_pending(current)) {
			schedule();
			goto repeat;
		}
	}
end:
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&current->signal->wait_chldexit, &wo->child_wait);
	return retval;
}

static long kernel_waitid(int which, pid_t upid, struct waitid_info *infop,
			  int options, struct rusage *ru)
{
	struct wait_opts wo;
	struct pid *pid = NULL;
	enum pid_type type;
	long ret;
	unsigned int f_flags = 0;

	if (options & ~(WNOHANG|WNOWAIT|WEXITED|WSTOPPED|WCONTINUED|
			__WNOTHREAD|__WCLONE|__WALL))
		return -EINVAL;
	if (!(options & (WEXITED|WSTOPPED|WCONTINUED)))
		return -EINVAL;

	switch (which) {
	case P_ALL:
		type = PIDTYPE_MAX;
		break;
	case P_PID:
		type = PIDTYPE_PID;
		if (upid <= 0)
			return -EINVAL;

		pid = find_get_pid(upid);
		break;
	case P_PGID:
		type = PIDTYPE_PGID;
		if (upid < 0)
			return -EINVAL;

		if (upid)
			pid = find_get_pid(upid);
		else
			pid = get_task_pid(current, PIDTYPE_PGID);
		break;
	case P_PIDFD:
		type = PIDTYPE_PID;
		if (upid < 0)
			return -EINVAL;

		pid = pidfd_get_pid(upid, &f_flags);
		if (IS_ERR(pid))
			return PTR_ERR(pid);

		break;
	default:
		return -EINVAL;
	}

	wo.wo_type	= type;
	wo.wo_pid	= pid;
	wo.wo_flags	= options;
	wo.wo_info	= infop;
	wo.wo_rusage	= ru;
	if (f_flags & O_NONBLOCK)
		wo.wo_flags |= WNOHANG;

	ret = do_wait(&wo);
	if (!ret && !(options & WNOHANG) && (f_flags & O_NONBLOCK))
		ret = -EAGAIN;

	put_pid(pid);
	return ret;
}

SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
		infop, int, options, struct rusage __user *, ru)
{
	struct rusage r;
	struct waitid_info info = {.status = 0};
	long err = kernel_waitid(which, upid, &info, options, ru ? &r : NULL);
	int signo = 0;

	if (err > 0) {
		signo = SIGCHLD;
		err = 0;
		if (ru && copy_to_user(ru, &r, sizeof(struct rusage)))
			return -EFAULT;
	}
	if (!infop)
		return err;

	if (!user_write_access_begin(infop, sizeof(*infop)))
		return -EFAULT;

	unsafe_put_user(signo, &infop->si_signo, Efault);
	unsafe_put_user(0, &infop->si_errno, Efault);
	unsafe_put_user(info.cause, &infop->si_code, Efault);
	unsafe_put_user(info.pid, &infop->si_pid, Efault);
	unsafe_put_user(info.uid, &infop->si_uid, Efault);
	unsafe_put_user(info.status, &infop->si_status, Efault);
	user_write_access_end();
	return err;
Efault:
	user_write_access_end();
	return -EFAULT;
}

long kernel_wait4(pid_t upid, int __user *stat_addr, int options,
		  struct rusage *ru)
{
	struct wait_opts wo;
	struct pid *pid = NULL;
	enum pid_type type;
	long ret;

	if (options & ~(WNOHANG|WUNTRACED|WCONTINUED|
			__WNOTHREAD|__WCLONE|__WALL))
		return -EINVAL;

	/* -INT_MIN is not defined */
	if (upid == INT_MIN)
		return -ESRCH;

	if (upid == -1)
		type = PIDTYPE_MAX;
	else if (upid < 0) {
		type = PIDTYPE_PGID;
		pid = find_get_pid(-upid);
	} else if (upid == 0) {
		type = PIDTYPE_PGID;
		pid = get_task_pid(current, PIDTYPE_PGID);
	} else /* upid > 0 */ {
		type = PIDTYPE_PID;
		pid = find_get_pid(upid);
	}

	wo.wo_type	= type;
	wo.wo_pid	= pid;
	wo.wo_flags	= options | WEXITED;
	wo.wo_info	= NULL;
	wo.wo_stat	= 0;
	wo.wo_rusage	= ru;
	ret = do_wait(&wo);
	put_pid(pid);
	if (ret > 0 && stat_addr && put_user(wo.wo_stat, stat_addr))
		ret = -EFAULT;

	return ret;
}

int kernel_wait(pid_t pid, int *stat)
{
	struct wait_opts wo = {
		.wo_type	= PIDTYPE_PID,
		.wo_pid		= find_get_pid(pid),
		.wo_flags	= WEXITED,
	};
	int ret;

	ret = do_wait(&wo);
	if (ret > 0 && wo.wo_stat)
		*stat = wo.wo_stat;
	put_pid(wo.wo_pid);
	return ret;
}

SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
		int, options, struct rusage __user *, ru)
{
	struct rusage r;
	long err = kernel_wait4(upid, stat_addr, options, ru ? &r : NULL);

	if (err > 0) {
		if (ru && copy_to_user(ru, &r, sizeof(struct rusage)))
			return -EFAULT;
	}
	return err;
}

#ifdef __ARCH_WANT_SYS_WAITPID

SYSCALL_DEFINE3(waitpid, pid_t, pid, int __user *, stat_addr, int, options)
{
	return kernel_wait4(pid, stat_addr, options, NULL);
}

#endif

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(wait4,
	compat_pid_t, pid,
	compat_uint_t __user *, stat_addr,
	int, options,
	struct compat_rusage __user *, ru)
{
	struct rusage r;
	long err = kernel_wait4(pid, stat_addr, options, ru ? &r : NULL);
	if (err > 0) {
		if (ru && put_compat_rusage(&r, ru))
			return -EFAULT;
	}
	return err;
}

COMPAT_SYSCALL_DEFINE5(waitid,
		int, which, compat_pid_t, pid,
		struct compat_siginfo __user *, infop, int, options,
		struct compat_rusage __user *, uru)
{
	struct rusage ru;
	struct waitid_info info = {.status = 0};
	long err = kernel_waitid(which, pid, &info, options, uru ? &ru : NULL);
	int signo = 0;
	if (err > 0) {
		signo = SIGCHLD;
		err = 0;
		if (uru) {
			/* kernel_waitid() overwrites everything in ru */
			if (COMPAT_USE_64BIT_TIME)
				err = copy_to_user(uru, &ru, sizeof(ru));
			else
				err = put_compat_rusage(&ru, uru);
			if (err)
				return -EFAULT;
		}
	}

	if (!infop)
		return err;

	if (!user_write_access_begin(infop, sizeof(*infop)))
		return -EFAULT;

	unsafe_put_user(signo, &infop->si_signo, Efault);
	unsafe_put_user(0, &infop->si_errno, Efault);
	unsafe_put_user(info.cause, &infop->si_code, Efault);
	unsafe_put_user(info.pid, &infop->si_pid, Efault);
	unsafe_put_user(info.uid, &infop->si_uid, Efault);
	unsafe_put_user(info.status, &infop->si_status, Efault);
	user_write_access_end();
	return err;
Efault:
	user_write_access_end();
	return -EFAULT;
}
#endif

bool thread_group_exited(struct pid *pid)
{
	struct task_struct *task;
	bool exited;

	rcu_read_lock();
	task = pid_task(pid, PIDTYPE_PID);
	exited = !task ||
		(READ_ONCE(task->exit_state) && thread_group_empty(task));
	rcu_read_unlock();

	return exited;
}
EXPORT_SYMBOL(thread_group_exited);

__weak void abort(void)
{
	BUG();

	/* if that doesn't kill us, halt */
	panic("Oops failed to kill thread");
}
EXPORT_SYMBOL(abort);
