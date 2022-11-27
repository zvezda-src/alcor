
#include <kunit/test.h>
#include <linux/sysctl.h>

#define KUNIT_PROC_READ 0
#define KUNIT_PROC_WRITE 1

static int i_zero;
static int i_one_hundred = 100;

static void sysctl_test_api_dointvec_null_tbl_data(struct kunit *test)
{
	struct ctl_table null_data_table = {
		.procname = "foo",
		/*
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	/*
	void __user *buffer = (void __user *)kunit_kzalloc(test, sizeof(int),
							   GFP_USER);
	size_t len;
	loff_t pos;

	/*
	len = 1234;
	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&null_data_table,
					       KUNIT_PROC_READ, buffer, &len,
					       &pos));
	KUNIT_EXPECT_EQ(test, 0, len);

	/*
	len = 1234;
	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&null_data_table,
					       KUNIT_PROC_WRITE, buffer, &len,
					       &pos));
	KUNIT_EXPECT_EQ(test, 0, len);
}

static void sysctl_test_api_dointvec_table_maxlen_unset(struct kunit *test)
{
	int data = 0;
	struct ctl_table data_maxlen_unset_table = {
		.procname = "foo",
		.data		= &data,
		/*
		.maxlen		= 0,
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	void __user *buffer = (void __user *)kunit_kzalloc(test, sizeof(int),
							   GFP_USER);
	size_t len;
	loff_t pos;

	/*
	len = 1234;
	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&data_maxlen_unset_table,
					       KUNIT_PROC_READ, buffer, &len,
					       &pos));
	KUNIT_EXPECT_EQ(test, 0, len);

	/*
	len = 1234;
	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&data_maxlen_unset_table,
					       KUNIT_PROC_WRITE, buffer, &len,
					       &pos));
	KUNIT_EXPECT_EQ(test, 0, len);
}

static void sysctl_test_api_dointvec_table_len_is_zero(struct kunit *test)
{
	int data = 0;
	/* Good table. */
	struct ctl_table table = {
		.procname = "foo",
		.data		= &data,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	void __user *buffer = (void __user *)kunit_kzalloc(test, sizeof(int),
							   GFP_USER);
	/*
	size_t len = 0;
	loff_t pos;

	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&table, KUNIT_PROC_READ, buffer,
					       &len, &pos));
	KUNIT_EXPECT_EQ(test, 0, len);

	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&table, KUNIT_PROC_WRITE, buffer,
					       &len, &pos));
	KUNIT_EXPECT_EQ(test, 0, len);
}

static void sysctl_test_api_dointvec_table_read_but_position_set(
		struct kunit *test)
{
	int data = 0;
	/* Good table. */
	struct ctl_table table = {
		.procname = "foo",
		.data		= &data,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	void __user *buffer = (void __user *)kunit_kzalloc(test, sizeof(int),
							   GFP_USER);
	/*
	size_t len = 1234;
	/*
	loff_t pos = 1;

	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&table, KUNIT_PROC_READ, buffer,
					       &len, &pos));
	KUNIT_EXPECT_EQ(test, 0, len);
}

static void sysctl_test_dointvec_read_happy_single_positive(struct kunit *test)
{
	int data = 0;
	/* Good table. */
	struct ctl_table table = {
		.procname = "foo",
		.data		= &data,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	size_t len = 4;
	loff_t pos = 0;
	char *buffer = kunit_kzalloc(test, len, GFP_USER);
	char __user *user_buffer = (char __user *)buffer;
	/* Store 13 in the data field. */

	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&table, KUNIT_PROC_READ,
					       user_buffer, &len, &pos));
	KUNIT_ASSERT_EQ(test, 3, len);
	buffer[len] = '\0';
	/* And we read 13 back out. */
	KUNIT_EXPECT_STREQ(test, "13\n", buffer);
}

static void sysctl_test_dointvec_read_happy_single_negative(struct kunit *test)
{
	int data = 0;
	/* Good table. */
	struct ctl_table table = {
		.procname = "foo",
		.data		= &data,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	size_t len = 5;
	loff_t pos = 0;
	char *buffer = kunit_kzalloc(test, len, GFP_USER);
	char __user *user_buffer = (char __user *)buffer;

	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&table, KUNIT_PROC_READ,
					       user_buffer, &len, &pos));
	KUNIT_ASSERT_EQ(test, 4, len);
	buffer[len] = '\0';
	KUNIT_EXPECT_STREQ(test, "-16\n", buffer);
}

static void sysctl_test_dointvec_write_happy_single_positive(struct kunit *test)
{
	int data = 0;
	/* Good table. */
	struct ctl_table table = {
		.procname = "foo",
		.data		= &data,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	char input[] = "9";
	size_t len = sizeof(input) - 1;
	loff_t pos = 0;
	char *buffer = kunit_kzalloc(test, len, GFP_USER);
	char __user *user_buffer = (char __user *)buffer;

	memcpy(buffer, input, len);

	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&table, KUNIT_PROC_WRITE,
					       user_buffer, &len, &pos));
	KUNIT_EXPECT_EQ(test, sizeof(input) - 1, len);
	KUNIT_EXPECT_EQ(test, sizeof(input) - 1, pos);
	KUNIT_EXPECT_EQ(test, 9, *((int *)table.data));
}

static void sysctl_test_dointvec_write_happy_single_negative(struct kunit *test)
{
	int data = 0;
	struct ctl_table table = {
		.procname = "foo",
		.data		= &data,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	char input[] = "-9";
	size_t len = sizeof(input) - 1;
	loff_t pos = 0;
	char *buffer = kunit_kzalloc(test, len, GFP_USER);
	char __user *user_buffer = (char __user *)buffer;

	memcpy(buffer, input, len);

	KUNIT_EXPECT_EQ(test, 0, proc_dointvec(&table, KUNIT_PROC_WRITE,
					       user_buffer, &len, &pos));
	KUNIT_EXPECT_EQ(test, sizeof(input) - 1, len);
	KUNIT_EXPECT_EQ(test, sizeof(input) - 1, pos);
	KUNIT_EXPECT_EQ(test, -9, *((int *)table.data));
}

static void sysctl_test_api_dointvec_write_single_less_int_min(
		struct kunit *test)
{
	int data = 0;
	struct ctl_table table = {
		.procname = "foo",
		.data		= &data,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	size_t max_len = 32, len = max_len;
	loff_t pos = 0;
	char *buffer = kunit_kzalloc(test, max_len, GFP_USER);
	char __user *user_buffer = (char __user *)buffer;
	unsigned long abs_of_less_than_min = (unsigned long)INT_MAX
					     - (INT_MAX + INT_MIN) + 1;

	/*
	KUNIT_ASSERT_LT(test,
			(size_t)snprintf(buffer, max_len, "-%lu",
					 abs_of_less_than_min),
			max_len);

	KUNIT_EXPECT_EQ(test, -EINVAL, proc_dointvec(&table, KUNIT_PROC_WRITE,
						     user_buffer, &len, &pos));
	KUNIT_EXPECT_EQ(test, max_len, len);
	KUNIT_EXPECT_EQ(test, 0, *((int *)table.data));
}

static void sysctl_test_api_dointvec_write_single_greater_int_max(
		struct kunit *test)
{
	int data = 0;
	struct ctl_table table = {
		.procname = "foo",
		.data		= &data,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &i_zero,
		.extra2         = &i_one_hundred,
	};
	size_t max_len = 32, len = max_len;
	loff_t pos = 0;
	char *buffer = kunit_kzalloc(test, max_len, GFP_USER);
	char __user *user_buffer = (char __user *)buffer;
	unsigned long greater_than_max = (unsigned long)INT_MAX + 1;

	KUNIT_ASSERT_GT(test, greater_than_max, (unsigned long)INT_MAX);
	KUNIT_ASSERT_LT(test, (size_t)snprintf(buffer, max_len, "%lu",
					       greater_than_max),
			max_len);
	KUNIT_EXPECT_EQ(test, -EINVAL, proc_dointvec(&table, KUNIT_PROC_WRITE,
						     user_buffer, &len, &pos));
	KUNIT_ASSERT_EQ(test, max_len, len);
	KUNIT_EXPECT_EQ(test, 0, *((int *)table.data));
}

static struct kunit_case sysctl_test_cases[] = {
	KUNIT_CASE(sysctl_test_api_dointvec_null_tbl_data),
	KUNIT_CASE(sysctl_test_api_dointvec_table_maxlen_unset),
	KUNIT_CASE(sysctl_test_api_dointvec_table_len_is_zero),
	KUNIT_CASE(sysctl_test_api_dointvec_table_read_but_position_set),
	KUNIT_CASE(sysctl_test_dointvec_read_happy_single_positive),
	KUNIT_CASE(sysctl_test_dointvec_read_happy_single_negative),
	KUNIT_CASE(sysctl_test_dointvec_write_happy_single_positive),
	KUNIT_CASE(sysctl_test_dointvec_write_happy_single_negative),
	KUNIT_CASE(sysctl_test_api_dointvec_write_single_less_int_min),
	KUNIT_CASE(sysctl_test_api_dointvec_write_single_greater_int_max),
	{}
};

static struct kunit_suite sysctl_test_suite = {
	.name = "sysctl_test",
	.test_cases = sysctl_test_cases,
};

kunit_test_suites(&sysctl_test_suite);

MODULE_LICENSE("GPL v2");
