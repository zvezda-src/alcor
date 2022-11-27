
#ifndef _TRACE_DYNEVENT_H
#define _TRACE_DYNEVENT_H

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>

#include "trace.h"

struct dyn_event;

struct dyn_event_operations {
	struct list_head	list;
	int (*create)(const char *raw_command);
	int (*show)(struct seq_file *m, struct dyn_event *ev);
	bool (*is_busy)(struct dyn_event *ev);
	int (*free)(struct dyn_event *ev);
	bool (*match)(const char *system, const char *event,
		      int argc, const char **argv, struct dyn_event *ev);
};

int dyn_event_register(struct dyn_event_operations *ops);

struct dyn_event {
	struct list_head		list;
	struct dyn_event_operations	*ops;
};

extern struct list_head dyn_event_list;

static inline
int dyn_event_init(struct dyn_event *ev, struct dyn_event_operations *ops)
{
	if (!ev || !ops)
		return -EINVAL;

	INIT_LIST_HEAD(&ev->list);
	ev->ops = ops;
	return 0;
}

static inline int dyn_event_add(struct dyn_event *ev,
				struct trace_event_call *call)
{
	lockdep_assert_held(&event_mutex);

	if (!ev || !ev->ops)
		return -EINVAL;

	call->flags |= TRACE_EVENT_FL_DYNAMIC;
	list_add_tail(&ev->list, &dyn_event_list);
	return 0;
}

static inline void dyn_event_remove(struct dyn_event *ev)
{
	lockdep_assert_held(&event_mutex);
	list_del_init(&ev->list);
}

void *dyn_event_seq_start(struct seq_file *m, loff_t *pos);
void *dyn_event_seq_next(struct seq_file *m, void *v, loff_t *pos);
void dyn_event_seq_stop(struct seq_file *m, void *v);
int dyn_events_release_all(struct dyn_event_operations *type);
int dyn_event_release(const char *raw_command, struct dyn_event_operations *type);

#define for_each_dyn_event(pos)	\
	list_for_each_entry(pos, &dyn_event_list, list)

#define for_each_dyn_event_safe(pos, n)	\
	list_for_each_entry_safe(pos, n, &dyn_event_list, list)

extern void dynevent_cmd_init(struct dynevent_cmd *cmd, char *buf, int maxlen,
			      enum dynevent_type type,
			      dynevent_create_fn_t run_command);

typedef int (*dynevent_check_arg_fn_t)(void *data);

struct dynevent_arg {
	const char		*str;
	char			separator; /* e.g. ';', ',', or nothing */
};

extern void dynevent_arg_init(struct dynevent_arg *arg,
			      char separator);
extern int dynevent_arg_add(struct dynevent_cmd *cmd,
			    struct dynevent_arg *arg,
			    dynevent_check_arg_fn_t check_arg);

struct dynevent_arg_pair {
	const char		*lhs;
	const char		*rhs;
	char			operator; /* e.g. '=' or nothing */
	char			separator; /* e.g. ';', ',', or nothing */
};

extern void dynevent_arg_pair_init(struct dynevent_arg_pair *arg_pair,
				   char operator, char separator);

extern int dynevent_arg_pair_add(struct dynevent_cmd *cmd,
				 struct dynevent_arg_pair *arg_pair,
				 dynevent_check_arg_fn_t check_arg);
extern int dynevent_str_add(struct dynevent_cmd *cmd, const char *str);

#endif
