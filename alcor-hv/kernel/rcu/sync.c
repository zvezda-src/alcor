
#include <linux/rcu_sync.h>
#include <linux/sched.h>

enum { GP_IDLE = 0, GP_ENTER, GP_PASSED, GP_EXIT, GP_REPLAY };

#define	rss_lock	gp_wait.lock

void rcu_sync_init(struct rcu_sync *rsp)
{
	memset(rsp, 0, sizeof(*rsp));
	init_waitqueue_head(&rsp->gp_wait);
}

void rcu_sync_enter_start(struct rcu_sync *rsp)
{
	rsp->gp_count++;
	rsp->gp_state = GP_PASSED;
}


static void rcu_sync_func(struct rcu_head *rhp);

static void rcu_sync_call(struct rcu_sync *rsp)
{
	call_rcu(&rsp->cb_head, rcu_sync_func);
}

static void rcu_sync_func(struct rcu_head *rhp)
{
	struct rcu_sync *rsp = container_of(rhp, struct rcu_sync, cb_head);
	unsigned long flags;

	WARN_ON_ONCE(READ_ONCE(rsp->gp_state) == GP_IDLE);
	WARN_ON_ONCE(READ_ONCE(rsp->gp_state) == GP_PASSED);

	spin_lock_irqsave(&rsp->rss_lock, flags);
	if (rsp->gp_count) {
		/*
		WRITE_ONCE(rsp->gp_state, GP_PASSED);
		wake_up_locked(&rsp->gp_wait);
	} else if (rsp->gp_state == GP_REPLAY) {
		/*
		WRITE_ONCE(rsp->gp_state, GP_EXIT);
		rcu_sync_call(rsp);
	} else {
		/*
		WRITE_ONCE(rsp->gp_state, GP_IDLE);
	}
	spin_unlock_irqrestore(&rsp->rss_lock, flags);
}

void rcu_sync_enter(struct rcu_sync *rsp)
{
	int gp_state;

	spin_lock_irq(&rsp->rss_lock);
	gp_state = rsp->gp_state;
	if (gp_state == GP_IDLE) {
		WRITE_ONCE(rsp->gp_state, GP_ENTER);
		WARN_ON_ONCE(rsp->gp_count);
		/*
	}
	rsp->gp_count++;
	spin_unlock_irq(&rsp->rss_lock);

	if (gp_state == GP_IDLE) {
		/*
		synchronize_rcu();
		rcu_sync_func(&rsp->cb_head);
		/* Not really needed, wait_event() would see GP_PASSED. */
		return;
	}

	wait_event(rsp->gp_wait, READ_ONCE(rsp->gp_state) >= GP_PASSED);
}

void rcu_sync_exit(struct rcu_sync *rsp)
{
	WARN_ON_ONCE(READ_ONCE(rsp->gp_state) == GP_IDLE);
	WARN_ON_ONCE(READ_ONCE(rsp->gp_count) == 0);

	spin_lock_irq(&rsp->rss_lock);
	if (!--rsp->gp_count) {
		if (rsp->gp_state == GP_PASSED) {
			WRITE_ONCE(rsp->gp_state, GP_EXIT);
			rcu_sync_call(rsp);
		} else if (rsp->gp_state == GP_EXIT) {
			WRITE_ONCE(rsp->gp_state, GP_REPLAY);
		}
	}
	spin_unlock_irq(&rsp->rss_lock);
}

void rcu_sync_dtor(struct rcu_sync *rsp)
{
	int gp_state;

	WARN_ON_ONCE(READ_ONCE(rsp->gp_count));
	WARN_ON_ONCE(READ_ONCE(rsp->gp_state) == GP_PASSED);

	spin_lock_irq(&rsp->rss_lock);
	if (rsp->gp_state == GP_REPLAY)
		WRITE_ONCE(rsp->gp_state, GP_EXIT);
	gp_state = rsp->gp_state;
	spin_unlock_irq(&rsp->rss_lock);

	if (gp_state != GP_IDLE) {
		rcu_barrier();
		WARN_ON_ONCE(rsp->gp_state != GP_IDLE);
	}
}
