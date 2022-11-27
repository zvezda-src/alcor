#include <linux/suspend.h>
#include <linux/suspend_ioctls.h>
#include <linux/utsname.h>
#include <linux/freezer.h>
#include <linux/compiler.h>
#include <linux/cpu.h>
#include <linux/cpuidle.h>

struct swsusp_info {
	struct new_utsname	uts;
	u32			version_code;
	unsigned long		num_physpages;
	int			cpus;
	unsigned long		image_pages;
	unsigned long		pages;
	unsigned long		size;
} __aligned(PAGE_SIZE);

#ifdef CONFIG_HIBERNATION
extern void __init hibernate_reserved_size_init(void);
extern void __init hibernate_image_size_init(void);

#ifdef CONFIG_ARCH_HIBERNATION_HEADER
#define MAX_ARCH_HEADER_SIZE	(sizeof(struct new_utsname) + 4)

extern int arch_hibernation_header_save(void *addr, unsigned int max_size);
extern int arch_hibernation_header_restore(void *addr);

static inline int init_header_complete(struct swsusp_info *info)
{
	return arch_hibernation_header_save(info, MAX_ARCH_HEADER_SIZE);
}

static inline const char *check_image_kernel(struct swsusp_info *info)
{
	return arch_hibernation_header_restore(info) ?
			"architecture specific data" : NULL;
}
#endif /* CONFIG_ARCH_HIBERNATION_HEADER */

extern int hibernate_resume_nonboot_cpu_disable(void);

#define PAGES_FOR_IO	((4096 * 1024) >> PAGE_SHIFT)

#define SPARE_PAGES	((1024 * 1024) >> PAGE_SHIFT)

asmlinkage int swsusp_save(void);

extern bool freezer_test_done;

extern int hibernation_snapshot(int platform_mode);
extern int hibernation_restore(int platform_mode);
extern int hibernation_platform_enter(void);

#ifdef CONFIG_STRICT_KERNEL_RWX
extern void enable_restore_image_protection(void);
#else
static inline void enable_restore_image_protection(void) {}
#endif /* CONFIG_STRICT_KERNEL_RWX */

#else /* !CONFIG_HIBERNATION */

static inline void hibernate_reserved_size_init(void) {}
static inline void hibernate_image_size_init(void) {}
#endif /* !CONFIG_HIBERNATION */

#define power_attr(_name) \
static struct kobj_attribute _name##_attr = {	\
	.attr	= {				\
		.name = __stringify(_name),	\
		.mode = 0644,			\
	},					\
	.show	= _name##_show,			\
	.store	= _name##_store,		\
}

#define power_attr_ro(_name) \
static struct kobj_attribute _name##_attr = {	\
	.attr	= {				\
		.name = __stringify(_name),	\
		.mode = S_IRUGO,		\
	},					\
	.show	= _name##_show,			\
}

extern unsigned long image_size;
extern unsigned long reserved_size;
extern int in_suspend;
extern dev_t swsusp_resume_device;
extern sector_t swsusp_resume_block;

extern int create_basic_memory_bitmaps(void);
extern void free_basic_memory_bitmaps(void);
extern int hibernate_preallocate_memory(void);

extern void clear_or_poison_free_pages(void);


struct snapshot_handle {
	unsigned int	cur;	/* number of the block of PAGE_SIZE bytes the
				 * next operation will refer to (ie. current)
				 */
	void		*buffer;	/* address of the block to read from
					 * or write to
					 */
	int		sync_read;	/* Set to one to notify the caller of
					 * snapshot_write_next() that it may
					 * need to call wait_on_bio_chain()
					 */
};

#define data_of(handle)	((handle).buffer)

extern unsigned int snapshot_additional_pages(struct zone *zone);
extern unsigned long snapshot_get_image_size(void);
extern int snapshot_read_next(struct snapshot_handle *handle);
extern int snapshot_write_next(struct snapshot_handle *handle);
extern void snapshot_write_finalize(struct snapshot_handle *handle);
extern int snapshot_image_loaded(struct snapshot_handle *handle);

extern bool hibernate_acquire(void);
extern void hibernate_release(void);

extern sector_t alloc_swapdev_block(int swap);
extern void free_all_swap_pages(int swap);
extern int swsusp_swap_in_use(void);

#define SF_PLATFORM_MODE	1
#define SF_NOCOMPRESS_MODE	2
#define SF_CRC32_MODE	        4
#define SF_HW_SIG		8

extern int swsusp_check(void);
extern void swsusp_free(void);
extern int swsusp_read(unsigned int *flags_p);
extern int swsusp_write(unsigned int flags);
extern void swsusp_close(fmode_t);
#ifdef CONFIG_SUSPEND
extern int swsusp_unmark(void);
#endif

struct __kernel_old_timeval;
extern void swsusp_show_speed(ktime_t, ktime_t, unsigned int, char *);

#ifdef CONFIG_SUSPEND
extern const char * const pm_labels[];
extern const char *pm_states[];
extern const char *mem_sleep_states[];

extern int suspend_devices_and_enter(suspend_state_t state);
#else /* !CONFIG_SUSPEND */
#define mem_sleep_current	PM_SUSPEND_ON

static inline int suspend_devices_and_enter(suspend_state_t state)
{
	return -ENOSYS;
}
#endif /* !CONFIG_SUSPEND */

#ifdef CONFIG_PM_TEST_SUSPEND
extern void suspend_test_start(void);
extern void suspend_test_finish(const char *label);
#else /* !CONFIG_PM_TEST_SUSPEND */
static inline void suspend_test_start(void) {}
static inline void suspend_test_finish(const char *label) {}
#endif /* !CONFIG_PM_TEST_SUSPEND */

#ifdef CONFIG_PM_SLEEP
extern int pm_notifier_call_chain_robust(unsigned long val_up, unsigned long val_down);
extern int pm_notifier_call_chain(unsigned long val);
#endif

#ifdef CONFIG_HIGHMEM
int restore_highmem(void);
#else
static inline unsigned int count_highmem_pages(void) { return 0; }
static inline int restore_highmem(void) { return 0; }
#endif

enum {
	/* keep first */
	TEST_NONE,
	TEST_CORE,
	TEST_CPUS,
	TEST_PLATFORM,
	TEST_DEVICES,
	TEST_FREEZER,
	/* keep last */
	__TEST_AFTER_LAST
};

#define TEST_FIRST	TEST_NONE
#define TEST_MAX	(__TEST_AFTER_LAST - 1)

#ifdef CONFIG_PM_SLEEP_DEBUG
extern int pm_test_level;
#else
#define pm_test_level	(TEST_NONE)
#endif

#ifdef CONFIG_SUSPEND_FREEZER
static inline int suspend_freeze_processes(void)
{
	int error;

	error = freeze_processes();
	/*
	if (error)
		return error;

	error = freeze_kernel_threads();
	/*
	if (error)
		thaw_processes();

	return error;
}

static inline void suspend_thaw_processes(void)
{
	thaw_processes();
}
#else
static inline int suspend_freeze_processes(void)
{
	return 0;
}

static inline void suspend_thaw_processes(void)
{
}
#endif

#ifdef CONFIG_PM_AUTOSLEEP

extern int pm_autosleep_init(void);
extern int pm_autosleep_lock(void);
extern void pm_autosleep_unlock(void);
extern suspend_state_t pm_autosleep_state(void);
extern int pm_autosleep_set_state(suspend_state_t state);

#else /* !CONFIG_PM_AUTOSLEEP */

static inline int pm_autosleep_init(void) { return 0; }
static inline int pm_autosleep_lock(void) { return 0; }
static inline void pm_autosleep_unlock(void) {}
static inline suspend_state_t pm_autosleep_state(void) { return PM_SUSPEND_ON; }

#endif /* !CONFIG_PM_AUTOSLEEP */

#ifdef CONFIG_PM_WAKELOCKS

extern ssize_t pm_show_wakelocks(char *buf, bool show_active);
extern int pm_wake_lock(const char *buf);
extern int pm_wake_unlock(const char *buf);

#endif /* !CONFIG_PM_WAKELOCKS */

static inline int pm_sleep_disable_secondary_cpus(void)
{
	cpuidle_pause();
	return suspend_disable_secondary_cpus();
}

static inline void pm_sleep_enable_secondary_cpus(void)
{
	suspend_enable_secondary_cpus();
	cpuidle_resume();
}
