
#include <linux/kernel.h>
#include <linux/cpu_pm.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/spinlock.h>
#include <linux/syscore_ops.h>

static struct {
	struct raw_notifier_head chain;
	raw_spinlock_t lock;
} cpu_pm_notifier = {
	.chain = RAW_NOTIFIER_INIT(cpu_pm_notifier.chain),
	.lock  = __RAW_SPIN_LOCK_UNLOCKED(cpu_pm_notifier.lock),
};

static int cpu_pm_notify(enum cpu_pm_event event)
{
	int ret;

	/*
	ct_irq_enter_irqson();
	rcu_read_lock();
	ret = raw_notifier_call_chain(&cpu_pm_notifier.chain, event, NULL);
	rcu_read_unlock();
	ct_irq_exit_irqson();

	return notifier_to_errno(ret);
}

static int cpu_pm_notify_robust(enum cpu_pm_event event_up, enum cpu_pm_event event_down)
{
	unsigned long flags;
	int ret;

	ct_irq_enter_irqson();
	raw_spin_lock_irqsave(&cpu_pm_notifier.lock, flags);
	ret = raw_notifier_call_chain_robust(&cpu_pm_notifier.chain, event_up, event_down, NULL);
	raw_spin_unlock_irqrestore(&cpu_pm_notifier.lock, flags);
	ct_irq_exit_irqson();

	return notifier_to_errno(ret);
}

int cpu_pm_register_notifier(struct notifier_block *nb)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&cpu_pm_notifier.lock, flags);
	ret = raw_notifier_chain_register(&cpu_pm_notifier.chain, nb);
	raw_spin_unlock_irqrestore(&cpu_pm_notifier.lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(cpu_pm_register_notifier);

int cpu_pm_unregister_notifier(struct notifier_block *nb)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&cpu_pm_notifier.lock, flags);
	ret = raw_notifier_chain_unregister(&cpu_pm_notifier.chain, nb);
	raw_spin_unlock_irqrestore(&cpu_pm_notifier.lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(cpu_pm_unregister_notifier);

int cpu_pm_enter(void)
{
	return cpu_pm_notify_robust(CPU_PM_ENTER, CPU_PM_ENTER_FAILED);
}
EXPORT_SYMBOL_GPL(cpu_pm_enter);

int cpu_pm_exit(void)
{
	return cpu_pm_notify(CPU_PM_EXIT);
}
EXPORT_SYMBOL_GPL(cpu_pm_exit);

int cpu_cluster_pm_enter(void)
{
	return cpu_pm_notify_robust(CPU_CLUSTER_PM_ENTER, CPU_CLUSTER_PM_ENTER_FAILED);
}
EXPORT_SYMBOL_GPL(cpu_cluster_pm_enter);

int cpu_cluster_pm_exit(void)
{
	return cpu_pm_notify(CPU_CLUSTER_PM_EXIT);
}
EXPORT_SYMBOL_GPL(cpu_cluster_pm_exit);

#ifdef CONFIG_PM
static int cpu_pm_suspend(void)
{
	int ret;

	ret = cpu_pm_enter();
	if (ret)
		return ret;

	ret = cpu_cluster_pm_enter();
	return ret;
}

static void cpu_pm_resume(void)
{
	cpu_cluster_pm_exit();
	cpu_pm_exit();
}

static struct syscore_ops cpu_pm_syscore_ops = {
	.suspend = cpu_pm_suspend,
	.resume = cpu_pm_resume,
};

static int cpu_pm_init(void)
{
	register_syscore_ops(&cpu_pm_syscore_ops);
	return 0;
}
core_initcall(cpu_pm_init);
#endif
