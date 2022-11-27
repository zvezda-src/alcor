
#include <linux/module.h>
#include <linux/trace_events.h>


static struct trace_event_file *gen_kprobe_test;
static struct trace_event_file *gen_kretprobe_test;

static int __init test_gen_kprobe_cmd(void)
{
	struct dynevent_cmd cmd;
	char *buf;
	int ret;

	/* Create a buffer to hold the generated command */
	buf = kzalloc(MAX_DYNEVENT_CMD_LEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Before generating the command, initialize the cmd object */
	kprobe_event_cmd_init(&cmd, buf, MAX_DYNEVENT_CMD_LEN);

	/*
	ret = kprobe_event_gen_cmd_start(&cmd, "gen_kprobe_test",
					 "do_sys_open",
					 "dfd=%ax", "filename=%dx");
	if (ret)
		goto free;

	/* Use kprobe_event_add_fields to add the rest of the fields */

	ret = kprobe_event_add_fields(&cmd, "flags=%cx", "mode=+4($stack)");
	if (ret)
		goto free;

	/*
	ret = kprobe_event_gen_cmd_end(&cmd);
	if (ret)
		goto free;

	/*
	gen_kprobe_test = trace_get_event_file(NULL, "kprobes",
					       "gen_kprobe_test");
	if (IS_ERR(gen_kprobe_test)) {
		ret = PTR_ERR(gen_kprobe_test);
		goto delete;
	}

	/* Enable the event or you won't see anything */
	ret = trace_array_set_clr_event(gen_kprobe_test->tr,
					"kprobes", "gen_kprobe_test", true);
	if (ret) {
		trace_put_event_file(gen_kprobe_test);
		goto delete;
	}
 out:
	return ret;
 delete:
	/* We got an error after creating the event, delete it */
	ret = kprobe_event_delete("gen_kprobe_test");
 free:
	kfree(buf);

	goto out;
}

static int __init test_gen_kretprobe_cmd(void)
{
	struct dynevent_cmd cmd;
	char *buf;
	int ret;

	/* Create a buffer to hold the generated command */
	buf = kzalloc(MAX_DYNEVENT_CMD_LEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Before generating the command, initialize the cmd object */
	kprobe_event_cmd_init(&cmd, buf, MAX_DYNEVENT_CMD_LEN);

	/*
	ret = kretprobe_event_gen_cmd_start(&cmd, "gen_kretprobe_test",
					    "do_sys_open",
					    "$retval");
	if (ret)
		goto free;

	/*
	ret = kretprobe_event_gen_cmd_end(&cmd);
	if (ret)
		goto free;

	/*
	gen_kretprobe_test = trace_get_event_file(NULL, "kprobes",
						  "gen_kretprobe_test");
	if (IS_ERR(gen_kretprobe_test)) {
		ret = PTR_ERR(gen_kretprobe_test);
		goto delete;
	}

	/* Enable the event or you won't see anything */
	ret = trace_array_set_clr_event(gen_kretprobe_test->tr,
					"kprobes", "gen_kretprobe_test", true);
	if (ret) {
		trace_put_event_file(gen_kretprobe_test);
		goto delete;
	}
 out:
	return ret;
 delete:
	/* We got an error after creating the event, delete it */
	ret = kprobe_event_delete("gen_kretprobe_test");
 free:
	kfree(buf);

	goto out;
}

static int __init kprobe_event_gen_test_init(void)
{
	int ret;

	ret = test_gen_kprobe_cmd();
	if (ret)
		return ret;

	ret = test_gen_kretprobe_cmd();
	if (ret) {
		WARN_ON(trace_array_set_clr_event(gen_kretprobe_test->tr,
						  "kprobes",
						  "gen_kretprobe_test", false));
		trace_put_event_file(gen_kretprobe_test);
		WARN_ON(kprobe_event_delete("gen_kretprobe_test"));
	}

	return ret;
}

static void __exit kprobe_event_gen_test_exit(void)
{
	/* Disable the event or you can't remove it */
	WARN_ON(trace_array_set_clr_event(gen_kprobe_test->tr,
					  "kprobes",
					  "gen_kprobe_test", false));

	/* Now give the file and instance back */
	trace_put_event_file(gen_kprobe_test);

	/* Now unregister and free the event */
	WARN_ON(kprobe_event_delete("gen_kprobe_test"));

	/* Disable the event or you can't remove it */
	WARN_ON(trace_array_set_clr_event(gen_kprobe_test->tr,
					  "kprobes",
					  "gen_kretprobe_test", false));

	/* Now give the file and instance back */
	trace_put_event_file(gen_kretprobe_test);

	/* Now unregister and free the event */
	WARN_ON(kprobe_event_delete("gen_kretprobe_test"));
}

module_init(kprobe_event_gen_test_init)
module_exit(kprobe_event_gen_test_exit)

MODULE_AUTHOR("Tom Zanussi");
MODULE_DESCRIPTION("kprobe event generation test");
MODULE_LICENSE("GPL v2");
