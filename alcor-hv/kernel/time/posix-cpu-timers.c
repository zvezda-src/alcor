
#include <linux/sched/signal.h>
#include <linux/sched/cputime.h>
#include <linux/posix-timers.h>
#include <linux/errno.h>
#include <linux/math64.h>
#include <linux/uaccess.h>
#include <linux/kernel_stat.h>
#include <trace/events/timer.h>
#include <linux/tick.h>
#include <linux/workqueue.h>
#include <linux/compat.h>
#include <linux/sched/deadline.h>
#include <linux/task_work.h>

#include "posix-timers.h"

static void posix_cpu_timer_rearm(struct k_itimer *timer);

void posix_cputimers_group_init(struct posix_cputimers *pct, u64 cpu_limit)
{
	posix_cputimers_init(pct);
	if (cpu_limit != RLIM_INFINITY) {
		pct->bases[CPUCLOCK_PROF].nextevt = cpu_limit * NSEC_PER_SEC;
		pct->timers_active = true;
	}
}

int update_rlimit_cpu(struct task_struct *task, unsigned long rlim_new)
{
	u64 nsecs = rlim_new * NSEC_PER_SEC;
	unsigned long irq_fl;

	if (!lock_task_sighand(task, &irq_fl))
		return -ESRCH;
	set_process_cpu_timer(task, CPUCLOCK_PROF, &nsecs, NULL);
	unlock_task_sighand(task, &irq_fl);
	return 0;
}

static struct pid *pid_for_clock(const clockid_t clock, bool gettime)
{
	const bool thread = !!CPUCLOCK_PERTHREAD(clock);
	const pid_t upid = CPUCLOCK_PID(clock);
	struct pid *pid;

	if (CPUCLOCK_WHICH(clock) >= CPUCLOCK_MAX)
		return NULL;

	/*
	if (upid == 0)
		return thread ? task_pid(current) : task_tgid(current);

	pid = find_vpid(upid);
	if (!pid)
		return NULL;

	if (thread) {
		struct task_struct *tsk = pid_task(pid, PIDTYPE_PID);
		return (tsk && same_thread_group(tsk, current)) ? pid : NULL;
	}

	/*
	if (gettime && (pid == task_pid(current)))
		return task_tgid(current);

	/*
	return pid_has_task(pid, PIDTYPE_TGID) ? pid : NULL;
}

static inline int validate_clock_permissions(const clockid_t clock)
{
	int ret;

	rcu_read_lock();
	ret = pid_for_clock(clock, false) ? 0 : -EINVAL;
	rcu_read_unlock();

	return ret;
}

static inline enum pid_type clock_pid_type(const clockid_t clock)
{
	return CPUCLOCK_PERTHREAD(clock) ? PIDTYPE_PID : PIDTYPE_TGID;
}

static inline struct task_struct *cpu_timer_task_rcu(struct k_itimer *timer)
{
	return pid_task(timer->it.cpu.pid, clock_pid_type(timer->it_clock));
}

static u64 bump_cpu_timer(struct k_itimer *timer, u64 now)
{
	u64 delta, incr, expires = timer->it.cpu.node.expires;
	int i;

	if (!timer->it_interval)
		return expires;

	if (now < expires)
		return expires;

	incr = timer->it_interval;
	delta = now + incr - expires;

	/* Don't use (incr*2 < delta), incr*2 might overflow. */
	for (i = 0; incr < delta - incr; i++)
		incr = incr << 1;

	for (; i >= 0; incr >>= 1, i--) {
		if (delta < incr)
			continue;

		timer->it.cpu.node.expires += incr;
		timer->it_overrun += 1LL << i;
		delta -= incr;
	}
	return timer->it.cpu.node.expires;
}

static inline bool expiry_cache_is_inactive(const struct posix_cputimers *pct)
{
	return !(~pct->bases[CPUCLOCK_PROF].nextevt |
		 ~pct->bases[CPUCLOCK_VIRT].nextevt |
		 ~pct->bases[CPUCLOCK_SCHED].nextevt);
}

static int
posix_cpu_clock_getres(const clockid_t which_clock, struct timespec64 *tp)
{
	int error = validate_clock_permissions(which_clock);

	if (!error) {
		tp->tv_sec = 0;
		tp->tv_nsec = ((NSEC_PER_SEC + HZ - 1) / HZ);
		if (CPUCLOCK_WHICH(which_clock) == CPUCLOCK_SCHED) {
			/*
			tp->tv_nsec = 1;
		}
	}
	return error;
}

static int
posix_cpu_clock_set(const clockid_t clock, const struct timespec64 *tp)
{
	int error = validate_clock_permissions(clock);

	/*
	return error ? : -EPERM;
}

static u64 cpu_clock_sample(const clockid_t clkid, struct task_struct *p)
{
	u64 utime, stime;

	if (clkid == CPUCLOCK_SCHED)
		return task_sched_runtime(p);

	task_cputime(p, &utime, &stime);

	switch (clkid) {
	case CPUCLOCK_PROF:
		return utime + stime;
	case CPUCLOCK_VIRT:
		return utime;
	default:
		WARN_ON_ONCE(1);
	}
	return 0;
}

static inline void store_samples(u64 *samples, u64 stime, u64 utime, u64 rtime)
{
	samples[CPUCLOCK_PROF] = stime + utime;
	samples[CPUCLOCK_VIRT] = utime;
	samples[CPUCLOCK_SCHED] = rtime;
}

static void task_sample_cputime(struct task_struct *p, u64 *samples)
{
	u64 stime, utime;

	task_cputime(p, &utime, &stime);
	store_samples(samples, stime, utime, p->se.sum_exec_runtime);
}

static void proc_sample_cputime_atomic(struct task_cputime_atomic *at,
				       u64 *samples)
{
	u64 stime, utime, rtime;

	utime = atomic64_read(&at->utime);
	stime = atomic64_read(&at->stime);
	rtime = atomic64_read(&at->sum_exec_runtime);
	store_samples(samples, stime, utime, rtime);
}

static inline void __update_gt_cputime(atomic64_t *cputime, u64 sum_cputime)
{
	u64 curr_cputime;
retry:
	curr_cputime = atomic64_read(cputime);
	if (sum_cputime > curr_cputime) {
		if (atomic64_cmpxchg(cputime, curr_cputime, sum_cputime) != curr_cputime)
			goto retry;
	}
}

static void update_gt_cputime(struct task_cputime_atomic *cputime_atomic,
			      struct task_cputime *sum)
{
	__update_gt_cputime(&cputime_atomic->utime, sum->utime);
	__update_gt_cputime(&cputime_atomic->stime, sum->stime);
	__update_gt_cputime(&cputime_atomic->sum_exec_runtime, sum->sum_exec_runtime);
}

void thread_group_sample_cputime(struct task_struct *tsk, u64 *samples)
{
	struct thread_group_cputimer *cputimer = &tsk->signal->cputimer;
	struct posix_cputimers *pct = &tsk->signal->posix_cputimers;

	WARN_ON_ONCE(!pct->timers_active);

	proc_sample_cputime_atomic(&cputimer->cputime_atomic, samples);
}

static void thread_group_start_cputime(struct task_struct *tsk, u64 *samples)
{
	struct thread_group_cputimer *cputimer = &tsk->signal->cputimer;
	struct posix_cputimers *pct = &tsk->signal->posix_cputimers;

	lockdep_assert_task_sighand_held(tsk);

	/* Check if cputimer isn't running. This is accessed without locking. */
	if (!READ_ONCE(pct->timers_active)) {
		struct task_cputime sum;

		/*
		thread_group_cputime(tsk, &sum);
		update_gt_cputime(&cputimer->cputime_atomic, &sum);

		/*
		WRITE_ONCE(pct->timers_active, true);
	}
	proc_sample_cputime_atomic(&cputimer->cputime_atomic, samples);
}

static void __thread_group_cputime(struct task_struct *tsk, u64 *samples)
{
	struct task_cputime ct;

	thread_group_cputime(tsk, &ct);
	store_samples(samples, ct.stime, ct.utime, ct.sum_exec_runtime);
}

static u64 cpu_clock_sample_group(const clockid_t clkid, struct task_struct *p,
				  bool start)
{
	struct thread_group_cputimer *cputimer = &p->signal->cputimer;
	struct posix_cputimers *pct = &p->signal->posix_cputimers;
	u64 samples[CPUCLOCK_MAX];

	if (!READ_ONCE(pct->timers_active)) {
		if (start)
			thread_group_start_cputime(p, samples);
		else
			__thread_group_cputime(p, samples);
	} else {
		proc_sample_cputime_atomic(&cputimer->cputime_atomic, samples);
	}

	return samples[clkid];
}

static int posix_cpu_clock_get(const clockid_t clock, struct timespec64 *tp)
{
	const clockid_t clkid = CPUCLOCK_WHICH(clock);
	struct task_struct *tsk;
	u64 t;

	rcu_read_lock();
	tsk = pid_task(pid_for_clock(clock, true), clock_pid_type(clock));
	if (!tsk) {
		rcu_read_unlock();
		return -EINVAL;
	}

	if (CPUCLOCK_PERTHREAD(clock))
		t = cpu_clock_sample(clkid, tsk);
	else
		t = cpu_clock_sample_group(clkid, tsk, false);
	rcu_read_unlock();

	return 0;
}

static int posix_cpu_timer_create(struct k_itimer *new_timer)
{
	static struct lock_class_key posix_cpu_timers_key;
	struct pid *pid;

	rcu_read_lock();
	pid = pid_for_clock(new_timer->it_clock, false);
	if (!pid) {
		rcu_read_unlock();
		return -EINVAL;
	}

	/*
	if (IS_ENABLED(CONFIG_POSIX_CPU_TIMERS_TASK_WORK))
		lockdep_set_class(&new_timer->it_lock, &posix_cpu_timers_key);

	new_timer->kclock = &clock_posix_cpu;
	timerqueue_init(&new_timer->it.cpu.node);
	new_timer->it.cpu.pid = get_pid(pid);
	rcu_read_unlock();
	return 0;
}

static struct posix_cputimer_base *timer_base(struct k_itimer *timer,
					      struct task_struct *tsk)
{
	int clkidx = CPUCLOCK_WHICH(timer->it_clock);

	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		return tsk->posix_cputimers.bases + clkidx;
	else
		return tsk->signal->posix_cputimers.bases + clkidx;
}

static void trigger_base_recalc_expires(struct k_itimer *timer,
					struct task_struct *tsk)
{
	struct posix_cputimer_base *base = timer_base(timer, tsk);

	base->nextevt = 0;
}

static void disarm_timer(struct k_itimer *timer, struct task_struct *p)
{
	struct cpu_timer *ctmr = &timer->it.cpu;
	struct posix_cputimer_base *base;

	if (!cpu_timer_dequeue(ctmr))
		return;

	base = timer_base(timer, p);
	if (cpu_timer_getexpires(ctmr) == base->nextevt)
		trigger_base_recalc_expires(timer, p);
}


static int posix_cpu_timer_del(struct k_itimer *timer)
{
	struct cpu_timer *ctmr = &timer->it.cpu;
	struct sighand_struct *sighand;
	struct task_struct *p;
	unsigned long flags;
	int ret = 0;

	rcu_read_lock();
	p = cpu_timer_task_rcu(timer);
	if (!p)
		goto out;

	/*
	sighand = lock_task_sighand(p, &flags);
	if (unlikely(sighand == NULL)) {
		/*
		WARN_ON_ONCE(ctmr->head || timerqueue_node_queued(&ctmr->node));
	} else {
		if (timer->it.cpu.firing)
			ret = TIMER_RETRY;
		else
			disarm_timer(timer, p);

		unlock_task_sighand(p, &flags);
	}

out:
	rcu_read_unlock();
	if (!ret)
		put_pid(ctmr->pid);

	return ret;
}

static void cleanup_timerqueue(struct timerqueue_head *head)
{
	struct timerqueue_node *node;
	struct cpu_timer *ctmr;

	while ((node = timerqueue_getnext(head))) {
		timerqueue_del(head, node);
		ctmr = container_of(node, struct cpu_timer, node);
		ctmr->head = NULL;
	}
}

static void cleanup_timers(struct posix_cputimers *pct)
{
	cleanup_timerqueue(&pct->bases[CPUCLOCK_PROF].tqhead);
	cleanup_timerqueue(&pct->bases[CPUCLOCK_VIRT].tqhead);
	cleanup_timerqueue(&pct->bases[CPUCLOCK_SCHED].tqhead);
}

void posix_cpu_timers_exit(struct task_struct *tsk)
{
	cleanup_timers(&tsk->posix_cputimers);
}
void posix_cpu_timers_exit_group(struct task_struct *tsk)
{
	cleanup_timers(&tsk->signal->posix_cputimers);
}

static void arm_timer(struct k_itimer *timer, struct task_struct *p)
{
	struct posix_cputimer_base *base = timer_base(timer, p);
	struct cpu_timer *ctmr = &timer->it.cpu;
	u64 newexp = cpu_timer_getexpires(ctmr);

	if (!cpu_timer_enqueue(&base->tqhead, ctmr))
		return;

	/*
	if (newexp < base->nextevt)
		base->nextevt = newexp;

	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		tick_dep_set_task(p, TICK_DEP_BIT_POSIX_TIMER);
	else
		tick_dep_set_signal(p, TICK_DEP_BIT_POSIX_TIMER);
}

static void cpu_timer_fire(struct k_itimer *timer)
{
	struct cpu_timer *ctmr = &timer->it.cpu;

	if ((timer->it_sigev_notify & ~SIGEV_THREAD_ID) == SIGEV_NONE) {
		/*
		cpu_timer_setexpires(ctmr, 0);
	} else if (unlikely(timer->sigq == NULL)) {
		/*
		wake_up_process(timer->it_process);
		cpu_timer_setexpires(ctmr, 0);
	} else if (!timer->it_interval) {
		/*
		posix_timer_event(timer, 0);
		cpu_timer_setexpires(ctmr, 0);
	} else if (posix_timer_event(timer, ++timer->it_requeue_pending)) {
		/*
		posix_cpu_timer_rearm(timer);
		++timer->it_requeue_pending;
	}
}

static int posix_cpu_timer_set(struct k_itimer *timer, int timer_flags,
			       struct itimerspec64 *new, struct itimerspec64 *old)
{
	clockid_t clkid = CPUCLOCK_WHICH(timer->it_clock);
	u64 old_expires, new_expires, old_incr, val;
	struct cpu_timer *ctmr = &timer->it.cpu;
	struct sighand_struct *sighand;
	struct task_struct *p;
	unsigned long flags;
	int ret = 0;

	rcu_read_lock();
	p = cpu_timer_task_rcu(timer);
	if (!p) {
		/*
		rcu_read_unlock();
		return -ESRCH;
	}

	/*
	new_expires = ktime_to_ns(timespec64_to_ktime(new->it_value));

	/*
	sighand = lock_task_sighand(p, &flags);
	/*
	if (unlikely(sighand == NULL)) {
		rcu_read_unlock();
		return -ESRCH;
	}

	/*
	old_incr = timer->it_interval;
	old_expires = cpu_timer_getexpires(ctmr);

	if (unlikely(timer->it.cpu.firing)) {
		timer->it.cpu.firing = -1;
		ret = TIMER_RETRY;
	} else {
		cpu_timer_dequeue(ctmr);
	}

	/*
	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		val = cpu_clock_sample(clkid, p);
	else
		val = cpu_clock_sample_group(clkid, p, true);

	if (old) {
		if (old_expires == 0) {
			old->it_value.tv_sec = 0;
			old->it_value.tv_nsec = 0;
		} else {
			/*
			u64 exp = bump_cpu_timer(timer, val);

			if (val < exp) {
				old_expires = exp - val;
				old->it_value = ns_to_timespec64(old_expires);
			} else {
				old->it_value.tv_nsec = 1;
				old->it_value.tv_sec = 0;
			}
		}
	}

	if (unlikely(ret)) {
		/*
		unlock_task_sighand(p, &flags);
		goto out;
	}

	if (new_expires != 0 && !(timer_flags & TIMER_ABSTIME)) {
		new_expires += val;
	}

	/*
	cpu_timer_setexpires(ctmr, new_expires);
	if (new_expires != 0 && val < new_expires) {
		arm_timer(timer, p);
	}

	unlock_task_sighand(p, &flags);
	/*
	timer->it_interval = timespec64_to_ktime(new->it_interval);

	/*
	timer->it_requeue_pending = (timer->it_requeue_pending + 2) &
		~REQUEUE_PENDING;
	timer->it_overrun_last = 0;
	timer->it_overrun = -1;

	if (val >= new_expires) {
		if (new_expires != 0) {
			/*
			cpu_timer_fire(timer);
		}

		/*
		sighand = lock_task_sighand(p, &flags);
		if (!sighand)
			goto out;

		if (!cpu_timer_queued(ctmr))
			trigger_base_recalc_expires(timer, p);

		unlock_task_sighand(p, &flags);
	}
 out:
	rcu_read_unlock();
	if (old)
		old->it_interval = ns_to_timespec64(old_incr);

	return ret;
}

static void posix_cpu_timer_get(struct k_itimer *timer, struct itimerspec64 *itp)
{
	clockid_t clkid = CPUCLOCK_WHICH(timer->it_clock);
	struct cpu_timer *ctmr = &timer->it.cpu;
	u64 now, expires = cpu_timer_getexpires(ctmr);
	struct task_struct *p;

	rcu_read_lock();
	p = cpu_timer_task_rcu(timer);
	if (!p)
		goto out;

	/*
	itp->it_interval = ktime_to_timespec64(timer->it_interval);

	if (!expires)
		goto out;

	/*
	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		now = cpu_clock_sample(clkid, p);
	else
		now = cpu_clock_sample_group(clkid, p, false);

	if (now < expires) {
		itp->it_value = ns_to_timespec64(expires - now);
	} else {
		/*
		itp->it_value.tv_nsec = 1;
		itp->it_value.tv_sec = 0;
	}
out:
	rcu_read_unlock();
}

#define MAX_COLLECTED	20

static u64 collect_timerqueue(struct timerqueue_head *head,
			      struct list_head *firing, u64 now)
{
	struct timerqueue_node *next;
	int i = 0;

	while ((next = timerqueue_getnext(head))) {
		struct cpu_timer *ctmr;
		u64 expires;

		ctmr = container_of(next, struct cpu_timer, node);
		expires = cpu_timer_getexpires(ctmr);
		/* Limit the number of timers to expire at once */
		if (++i == MAX_COLLECTED || now < expires)
			return expires;

		ctmr->firing = 1;
		cpu_timer_dequeue(ctmr);
		list_add_tail(&ctmr->elist, firing);
	}

	return U64_MAX;
}

static void collect_posix_cputimers(struct posix_cputimers *pct, u64 *samples,
				    struct list_head *firing)
{
	struct posix_cputimer_base *base = pct->bases;
	int i;

	for (i = 0; i < CPUCLOCK_MAX; i++, base++) {
		base->nextevt = collect_timerqueue(&base->tqhead, firing,
						    samples[i]);
	}
}

static inline void check_dl_overrun(struct task_struct *tsk)
{
	if (tsk->dl.dl_overrun) {
		tsk->dl.dl_overrun = 0;
		send_signal_locked(SIGXCPU, SEND_SIG_PRIV, tsk, PIDTYPE_TGID);
	}
}

static bool check_rlimit(u64 time, u64 limit, int signo, bool rt, bool hard)
{
	if (time < limit)
		return false;

	if (print_fatal_signals) {
		pr_info("%s Watchdog Timeout (%s): %s[%d]\n",
			rt ? "RT" : "CPU", hard ? "hard" : "soft",
			current->comm, task_pid_nr(current));
	}
	send_signal_locked(signo, SEND_SIG_PRIV, current, PIDTYPE_TGID);
	return true;
}

static void check_thread_timers(struct task_struct *tsk,
				struct list_head *firing)
{
	struct posix_cputimers *pct = &tsk->posix_cputimers;
	u64 samples[CPUCLOCK_MAX];
	unsigned long soft;

	if (dl_task(tsk))
		check_dl_overrun(tsk);

	if (expiry_cache_is_inactive(pct))
		return;

	task_sample_cputime(tsk, samples);
	collect_posix_cputimers(pct, samples, firing);

	/*
	soft = task_rlimit(tsk, RLIMIT_RTTIME);
	if (soft != RLIM_INFINITY) {
		/* Task RT timeout is accounted in jiffies. RTTIME is usec */
		unsigned long rttime = tsk->rt.timeout * (USEC_PER_SEC / HZ);
		unsigned long hard = task_rlimit_max(tsk, RLIMIT_RTTIME);

		/* At the hard limit, send SIGKILL. No further action. */
		if (hard != RLIM_INFINITY &&
		    check_rlimit(rttime, hard, SIGKILL, true, true))
			return;

		/* At the soft limit, send a SIGXCPU every second */
		if (check_rlimit(rttime, soft, SIGXCPU, true, false)) {
			soft += USEC_PER_SEC;
			tsk->signal->rlim[RLIMIT_RTTIME].rlim_cur = soft;
		}
	}

	if (expiry_cache_is_inactive(pct))
		tick_dep_clear_task(tsk, TICK_DEP_BIT_POSIX_TIMER);
}

static inline void stop_process_timers(struct signal_struct *sig)
{
	struct posix_cputimers *pct = &sig->posix_cputimers;

	/* Turn off the active flag. This is done without locking. */
	WRITE_ONCE(pct->timers_active, false);
	tick_dep_clear_signal(sig, TICK_DEP_BIT_POSIX_TIMER);
}

static void check_cpu_itimer(struct task_struct *tsk, struct cpu_itimer *it,
			     u64 *expires, u64 cur_time, int signo)
{
	if (!it->expires)
		return;

	if (cur_time >= it->expires) {
		if (it->incr)
			it->expires += it->incr;
		else
			it->expires = 0;

		trace_itimer_expire(signo == SIGPROF ?
				    ITIMER_PROF : ITIMER_VIRTUAL,
				    task_tgid(tsk), cur_time);
		send_signal_locked(signo, SEND_SIG_PRIV, tsk, PIDTYPE_TGID);
	}

	if (it->expires && it->expires < *expires)
		*expires = it->expires;
}

static void check_process_timers(struct task_struct *tsk,
				 struct list_head *firing)
{
	struct signal_struct *const sig = tsk->signal;
	struct posix_cputimers *pct = &sig->posix_cputimers;
	u64 samples[CPUCLOCK_MAX];
	unsigned long soft;

	/*
	if (!READ_ONCE(pct->timers_active) || pct->expiry_active)
		return;

	/*
	pct->expiry_active = true;

	/*
	proc_sample_cputime_atomic(&sig->cputimer.cputime_atomic, samples);
	collect_posix_cputimers(pct, samples, firing);

	/*
	check_cpu_itimer(tsk, &sig->it[CPUCLOCK_PROF],
			 &pct->bases[CPUCLOCK_PROF].nextevt,
			 samples[CPUCLOCK_PROF], SIGPROF);
	check_cpu_itimer(tsk, &sig->it[CPUCLOCK_VIRT],
			 &pct->bases[CPUCLOCK_VIRT].nextevt,
			 samples[CPUCLOCK_VIRT], SIGVTALRM);

	soft = task_rlimit(tsk, RLIMIT_CPU);
	if (soft != RLIM_INFINITY) {
		/* RLIMIT_CPU is in seconds. Samples are nanoseconds */
		unsigned long hard = task_rlimit_max(tsk, RLIMIT_CPU);
		u64 ptime = samples[CPUCLOCK_PROF];
		u64 softns = (u64)soft * NSEC_PER_SEC;
		u64 hardns = (u64)hard * NSEC_PER_SEC;

		/* At the hard limit, send SIGKILL. No further action. */
		if (hard != RLIM_INFINITY &&
		    check_rlimit(ptime, hardns, SIGKILL, false, true))
			return;

		/* At the soft limit, send a SIGXCPU every second */
		if (check_rlimit(ptime, softns, SIGXCPU, false, false)) {
			sig->rlim[RLIMIT_CPU].rlim_cur = soft + 1;
			softns += NSEC_PER_SEC;
		}

		/* Update the expiry cache */
		if (softns < pct->bases[CPUCLOCK_PROF].nextevt)
			pct->bases[CPUCLOCK_PROF].nextevt = softns;
	}

	if (expiry_cache_is_inactive(pct))
		stop_process_timers(sig);

	pct->expiry_active = false;
}

static void posix_cpu_timer_rearm(struct k_itimer *timer)
{
	clockid_t clkid = CPUCLOCK_WHICH(timer->it_clock);
	struct task_struct *p;
	struct sighand_struct *sighand;
	unsigned long flags;
	u64 now;

	rcu_read_lock();
	p = cpu_timer_task_rcu(timer);
	if (!p)
		goto out;

	/* Protect timer list r/w in arm_timer() */
	sighand = lock_task_sighand(p, &flags);
	if (unlikely(sighand == NULL))
		goto out;

	/*
	if (CPUCLOCK_PERTHREAD(timer->it_clock))
		now = cpu_clock_sample(clkid, p);
	else
		now = cpu_clock_sample_group(clkid, p, true);

	bump_cpu_timer(timer, now);

	/*
	arm_timer(timer, p);
	unlock_task_sighand(p, &flags);
out:
	rcu_read_unlock();
}

static inline bool
task_cputimers_expired(const u64 *samples, struct posix_cputimers *pct)
{
	int i;

	for (i = 0; i < CPUCLOCK_MAX; i++) {
		if (samples[i] >= pct->bases[i].nextevt)
			return true;
	}
	return false;
}

static inline bool fastpath_timer_check(struct task_struct *tsk)
{
	struct posix_cputimers *pct = &tsk->posix_cputimers;
	struct signal_struct *sig;

	if (!expiry_cache_is_inactive(pct)) {
		u64 samples[CPUCLOCK_MAX];

		task_sample_cputime(tsk, samples);
		if (task_cputimers_expired(samples, pct))
			return true;
	}

	sig = tsk->signal;
	pct = &sig->posix_cputimers;
	/*
	if (READ_ONCE(pct->timers_active) && !READ_ONCE(pct->expiry_active)) {
		u64 samples[CPUCLOCK_MAX];

		proc_sample_cputime_atomic(&sig->cputimer.cputime_atomic,
					   samples);

		if (task_cputimers_expired(samples, pct))
			return true;
	}

	if (dl_task(tsk) && tsk->dl.dl_overrun)
		return true;

	return false;
}

static void handle_posix_cpu_timers(struct task_struct *tsk);

#ifdef CONFIG_POSIX_CPU_TIMERS_TASK_WORK
static void posix_cpu_timers_work(struct callback_head *work)
{
	handle_posix_cpu_timers(current);
}

void clear_posix_cputimers_work(struct task_struct *p)
{
	/*
	memset(&p->posix_cputimers_work.work, 0,
	       sizeof(p->posix_cputimers_work.work));
	init_task_work(&p->posix_cputimers_work.work,
		       posix_cpu_timers_work);
	p->posix_cputimers_work.scheduled = false;
}

void __init posix_cputimers_init_work(void)
{
	clear_posix_cputimers_work(current);
}

static inline bool posix_cpu_timers_work_scheduled(struct task_struct *tsk)
{
	return tsk->posix_cputimers_work.scheduled;
}

static inline void __run_posix_cpu_timers(struct task_struct *tsk)
{
	if (WARN_ON_ONCE(tsk->posix_cputimers_work.scheduled))
		return;

	/* Schedule task work to actually expire the timers */
	tsk->posix_cputimers_work.scheduled = true;
	task_work_add(tsk, &tsk->posix_cputimers_work.work, TWA_RESUME);
}

static inline bool posix_cpu_timers_enable_work(struct task_struct *tsk,
						unsigned long start)
{
	bool ret = true;

	/*
	if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
		tsk->posix_cputimers_work.scheduled = false;
		return true;
	}

	/*
	local_irq_disable();
	if (start != jiffies && fastpath_timer_check(tsk))
		ret = false;
	else
		tsk->posix_cputimers_work.scheduled = false;
	local_irq_enable();

	return ret;
}
#else /* CONFIG_POSIX_CPU_TIMERS_TASK_WORK */
static inline void __run_posix_cpu_timers(struct task_struct *tsk)
{
	lockdep_posixtimer_enter();
	handle_posix_cpu_timers(tsk);
	lockdep_posixtimer_exit();
}

static inline bool posix_cpu_timers_work_scheduled(struct task_struct *tsk)
{
	return false;
}

static inline bool posix_cpu_timers_enable_work(struct task_struct *tsk,
						unsigned long start)
{
	return true;
}
#endif /* CONFIG_POSIX_CPU_TIMERS_TASK_WORK */

static void handle_posix_cpu_timers(struct task_struct *tsk)
{
	struct k_itimer *timer, *next;
	unsigned long flags, start;
	LIST_HEAD(firing);

	if (!lock_task_sighand(tsk, &flags))
		return;

	do {
		/*
		start = READ_ONCE(jiffies);
		barrier();

		/*
		check_thread_timers(tsk, &firing);

		check_process_timers(tsk, &firing);

		/*
	} while (!posix_cpu_timers_enable_work(tsk, start));

	/*
	unlock_task_sighand(tsk, &flags);

	/*
	list_for_each_entry_safe(timer, next, &firing, it.cpu.elist) {
		int cpu_firing;

		/*
		spin_lock(&timer->it_lock);
		list_del_init(&timer->it.cpu.elist);
		cpu_firing = timer->it.cpu.firing;
		timer->it.cpu.firing = 0;
		/*
		if (likely(cpu_firing >= 0))
			cpu_timer_fire(timer);
		spin_unlock(&timer->it_lock);
	}
}

void run_posix_cpu_timers(void)
{
	struct task_struct *tsk = current;

	lockdep_assert_irqs_disabled();

	/*
	if (posix_cpu_timers_work_scheduled(tsk))
		return;

	/*
	if (!fastpath_timer_check(tsk))
		return;

	__run_posix_cpu_timers(tsk);
}

void set_process_cpu_timer(struct task_struct *tsk, unsigned int clkid,
			   u64 *newval, u64 *oldval)
{
	u64 now, *nextevt;

	if (WARN_ON_ONCE(clkid >= CPUCLOCK_SCHED))
		return;

	nextevt = &tsk->signal->posix_cputimers.bases[clkid].nextevt;
	now = cpu_clock_sample_group(clkid, tsk, true);

	if (oldval) {
		/*
		if (*oldval) {
			if (*oldval <= now) {
				/* Just about to fire. */
				*oldval = TICK_NSEC;
			} else {
				*oldval -= now;
			}
		}

		if (*newval)
			*newval += now;
	}

	/*
	if (*newval < *nextevt)
		*nextevt = *newval;

	tick_dep_set_signal(tsk, TICK_DEP_BIT_POSIX_TIMER);
}

static int do_cpu_nanosleep(const clockid_t which_clock, int flags,
			    const struct timespec64 *rqtp)
{
	struct itimerspec64 it;
	struct k_itimer timer;
	u64 expires;
	int error;

	/*
	memset(&timer, 0, sizeof timer);
	spin_lock_init(&timer.it_lock);
	timer.it_clock = which_clock;
	timer.it_overrun = -1;
	error = posix_cpu_timer_create(&timer);
	timer.it_process = current;

	if (!error) {
		static struct itimerspec64 zero_it;
		struct restart_block *restart;

		memset(&it, 0, sizeof(it));
		it.it_value = *rqtp;

		spin_lock_irq(&timer.it_lock);
		error = posix_cpu_timer_set(&timer, flags, &it, NULL);
		if (error) {
			spin_unlock_irq(&timer.it_lock);
			return error;
		}

		while (!signal_pending(current)) {
			if (!cpu_timer_getexpires(&timer.it.cpu)) {
				/*
				posix_cpu_timer_del(&timer);
				spin_unlock_irq(&timer.it_lock);
				return 0;
			}

			/*
			__set_current_state(TASK_INTERRUPTIBLE);
			spin_unlock_irq(&timer.it_lock);
			schedule();
			spin_lock_irq(&timer.it_lock);
		}

		/*
		expires = cpu_timer_getexpires(&timer.it.cpu);
		error = posix_cpu_timer_set(&timer, 0, &zero_it, &it);
		if (!error) {
			/*
			posix_cpu_timer_del(&timer);
		}
		spin_unlock_irq(&timer.it_lock);

		while (error == TIMER_RETRY) {
			/*
			spin_lock_irq(&timer.it_lock);
			error = posix_cpu_timer_del(&timer);
			spin_unlock_irq(&timer.it_lock);
		}

		if ((it.it_value.tv_sec | it.it_value.tv_nsec) == 0) {
			/*
			return 0;
		}

		error = -ERESTART_RESTARTBLOCK;
		/*
		restart = &current->restart_block;
		restart->nanosleep.expires = expires;
		if (restart->nanosleep.type != TT_NONE)
			error = nanosleep_copyout(restart, &it.it_value);
	}

	return error;
}

static long posix_cpu_nsleep_restart(struct restart_block *restart_block);

static int posix_cpu_nsleep(const clockid_t which_clock, int flags,
			    const struct timespec64 *rqtp)
{
	struct restart_block *restart_block = &current->restart_block;
	int error;

	/*
	if (CPUCLOCK_PERTHREAD(which_clock) &&
	    (CPUCLOCK_PID(which_clock) == 0 ||
	     CPUCLOCK_PID(which_clock) == task_pid_vnr(current)))
		return -EINVAL;

	error = do_cpu_nanosleep(which_clock, flags, rqtp);

	if (error == -ERESTART_RESTARTBLOCK) {

		if (flags & TIMER_ABSTIME)
			return -ERESTARTNOHAND;

		restart_block->nanosleep.clockid = which_clock;
		set_restart_fn(restart_block, posix_cpu_nsleep_restart);
	}
	return error;
}

static long posix_cpu_nsleep_restart(struct restart_block *restart_block)
{
	clockid_t which_clock = restart_block->nanosleep.clockid;
	struct timespec64 t;

	t = ns_to_timespec64(restart_block->nanosleep.expires);

	return do_cpu_nanosleep(which_clock, TIMER_ABSTIME, &t);
}

#define PROCESS_CLOCK	make_process_cpuclock(0, CPUCLOCK_SCHED)
#define THREAD_CLOCK	make_thread_cpuclock(0, CPUCLOCK_SCHED)

static int process_cpu_clock_getres(const clockid_t which_clock,
				    struct timespec64 *tp)
{
	return posix_cpu_clock_getres(PROCESS_CLOCK, tp);
}
static int process_cpu_clock_get(const clockid_t which_clock,
				 struct timespec64 *tp)
{
	return posix_cpu_clock_get(PROCESS_CLOCK, tp);
}
static int process_cpu_timer_create(struct k_itimer *timer)
{
	timer->it_clock = PROCESS_CLOCK;
	return posix_cpu_timer_create(timer);
}
static int process_cpu_nsleep(const clockid_t which_clock, int flags,
			      const struct timespec64 *rqtp)
{
	return posix_cpu_nsleep(PROCESS_CLOCK, flags, rqtp);
}
static int thread_cpu_clock_getres(const clockid_t which_clock,
				   struct timespec64 *tp)
{
	return posix_cpu_clock_getres(THREAD_CLOCK, tp);
}
static int thread_cpu_clock_get(const clockid_t which_clock,
				struct timespec64 *tp)
{
	return posix_cpu_clock_get(THREAD_CLOCK, tp);
}
static int thread_cpu_timer_create(struct k_itimer *timer)
{
	timer->it_clock = THREAD_CLOCK;
	return posix_cpu_timer_create(timer);
}

const struct k_clock clock_posix_cpu = {
	.clock_getres		= posix_cpu_clock_getres,
	.clock_set		= posix_cpu_clock_set,
	.clock_get_timespec	= posix_cpu_clock_get,
	.timer_create		= posix_cpu_timer_create,
	.nsleep			= posix_cpu_nsleep,
	.timer_set		= posix_cpu_timer_set,
	.timer_del		= posix_cpu_timer_del,
	.timer_get		= posix_cpu_timer_get,
	.timer_rearm		= posix_cpu_timer_rearm,
};

const struct k_clock clock_process = {
	.clock_getres		= process_cpu_clock_getres,
	.clock_get_timespec	= process_cpu_clock_get,
	.timer_create		= process_cpu_timer_create,
	.nsleep			= process_cpu_nsleep,
};

const struct k_clock clock_thread = {
	.clock_getres		= thread_cpu_clock_getres,
	.clock_get_timespec	= thread_cpu_clock_get,
	.timer_create		= thread_cpu_timer_create,
};
