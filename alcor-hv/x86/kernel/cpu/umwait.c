#include <linux/syscore_ops.h>
#include <linux/suspend.h>
#include <linux/cpu.h>

#include <asm/msr.h>
#include <asm/mwait.h>

#define UMWAIT_C02_ENABLE	0

#define UMWAIT_CTRL_VAL(max_time, c02_disable)				\
	(((max_time) & MSR_IA32_UMWAIT_CONTROL_TIME_MASK) |		\
	((c02_disable) & MSR_IA32_UMWAIT_CONTROL_C02_DISABLE))

static u32 umwait_control_cached = UMWAIT_CTRL_VAL(100000, UMWAIT_C02_ENABLE);

static u32 orig_umwait_control_cached __ro_after_init;

static DEFINE_MUTEX(umwait_lock);

static void umwait_update_control_msr(void * unused)
{
	lockdep_assert_irqs_disabled();
	wrmsr(MSR_IA32_UMWAIT_CONTROL, READ_ONCE(umwait_control_cached), 0);
}

static int umwait_cpu_online(unsigned int cpu)
{
	local_irq_disable();
	umwait_update_control_msr(NULL);
	local_irq_enable();
	return 0;
}

static int umwait_cpu_offline(unsigned int cpu)
{
	/*
	wrmsr(MSR_IA32_UMWAIT_CONTROL, orig_umwait_control_cached, 0);

	return 0;
}

static void umwait_syscore_resume(void)
{
	umwait_update_control_msr(NULL);
}

static struct syscore_ops umwait_syscore_ops = {
	.resume	= umwait_syscore_resume,
};


static inline bool umwait_ctrl_c02_enabled(u32 ctrl)
{
	return !(ctrl & MSR_IA32_UMWAIT_CONTROL_C02_DISABLE);
}

static inline u32 umwait_ctrl_max_time(u32 ctrl)
{
	return ctrl & MSR_IA32_UMWAIT_CONTROL_TIME_MASK;
}

static inline void umwait_update_control(u32 maxtime, bool c02_enable)
{
	u32 ctrl = maxtime & MSR_IA32_UMWAIT_CONTROL_TIME_MASK;

	if (!c02_enable)
		ctrl |= MSR_IA32_UMWAIT_CONTROL_C02_DISABLE;

	WRITE_ONCE(umwait_control_cached, ctrl);
	/* Propagate to all CPUs */
	on_each_cpu(umwait_update_control_msr, NULL, 1);
}

static ssize_t
enable_c02_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	u32 ctrl = READ_ONCE(umwait_control_cached);

	return sprintf(buf, "%d\n", umwait_ctrl_c02_enabled(ctrl));
}

static ssize_t enable_c02_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	bool c02_enable;
	u32 ctrl;
	int ret;

	ret = kstrtobool(buf, &c02_enable);
	if (ret)
		return ret;

	mutex_lock(&umwait_lock);

	ctrl = READ_ONCE(umwait_control_cached);
	if (c02_enable != umwait_ctrl_c02_enabled(ctrl))
		umwait_update_control(ctrl, c02_enable);

	mutex_unlock(&umwait_lock);

	return count;
}
static DEVICE_ATTR_RW(enable_c02);

static ssize_t
max_time_show(struct device *kobj, struct device_attribute *attr, char *buf)
{
	u32 ctrl = READ_ONCE(umwait_control_cached);

	return sprintf(buf, "%u\n", umwait_ctrl_max_time(ctrl));
}

static ssize_t max_time_store(struct device *kobj,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	u32 max_time, ctrl;
	int ret;

	ret = kstrtou32(buf, 0, &max_time);
	if (ret)
		return ret;

	/* bits[1:0] must be zero */
	if (max_time & ~MSR_IA32_UMWAIT_CONTROL_TIME_MASK)
		return -EINVAL;

	mutex_lock(&umwait_lock);

	ctrl = READ_ONCE(umwait_control_cached);
	if (max_time != umwait_ctrl_max_time(ctrl))
		umwait_update_control(max_time, umwait_ctrl_c02_enabled(ctrl));

	mutex_unlock(&umwait_lock);

	return count;
}
static DEVICE_ATTR_RW(max_time);

static struct attribute *umwait_attrs[] = {
	&dev_attr_enable_c02.attr,
	&dev_attr_max_time.attr,
	NULL
};

static struct attribute_group umwait_attr_group = {
	.attrs = umwait_attrs,
	.name = "umwait_control",
};

static int __init umwait_init(void)
{
	struct device *dev;
	int ret;

	if (!boot_cpu_has(X86_FEATURE_WAITPKG))
		return -ENODEV;

	/*
	rdmsrl(MSR_IA32_UMWAIT_CONTROL, orig_umwait_control_cached);

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "umwait:online",
				umwait_cpu_online, umwait_cpu_offline);
	if (ret < 0) {
		/*
		return ret;
	}

	register_syscore_ops(&umwait_syscore_ops);

	/*
	dev = cpu_subsys.dev_root;
	return sysfs_create_group(&dev->kobj, &umwait_attr_group);
}
device_initcall(umwait_init);
