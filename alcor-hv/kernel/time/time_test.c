
#include <kunit/test.h>
#include <linux/time.h>

static bool is_leap(long year)
{
	return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int last_day_of_month(long year, int month)
{
	if (month == 2)
		return 28 + is_leap(year);
	if (month == 4 || month == 6 || month == 9 || month == 11)
		return 30;
	return 31;
}

static void advance_date(long *year, int *month, int *mday, int *yday)
{
	if (*mday != last_day_of_month(*year, *month)) {
		++*mday;
		++*yday;
		return;
	}

	if (*month != 12) {
		++*month;
		++*yday;
		return;
	}

	++*year;
}

static void time64_to_tm_test_date_range(struct kunit *test)
{
	/*
	time64_t total_secs = ((time64_t) 80000) / 400 * 146097 * 86400;
	long year = 1970 - 80000;
	int month = 1;
	int mdday = 1;
	int yday = 0;

	struct tm result;
	time64_t secs;
	s64 days;

	for (secs = -total_secs; secs <= total_secs; secs += 86400) {

		time64_to_tm(secs, 0, &result);

		days = div_s64(secs, 86400);

		#define FAIL_MSG "%05ld/%02d/%02d (%2d) : %ld", \
			year, month, mdday, yday, days

		KUNIT_ASSERT_EQ_MSG(test, year - 1900, result.tm_year, FAIL_MSG);
		KUNIT_ASSERT_EQ_MSG(test, month - 1, result.tm_mon, FAIL_MSG);
		KUNIT_ASSERT_EQ_MSG(test, mdday, result.tm_mday, FAIL_MSG);
		KUNIT_ASSERT_EQ_MSG(test, yday, result.tm_yday, FAIL_MSG);

		advance_date(&year, &month, &mdday, &yday);
	}
}

static struct kunit_case time_test_cases[] = {
	KUNIT_CASE(time64_to_tm_test_date_range),
	{}
};

static struct kunit_suite time_test_suite = {
	.name = "time_test_cases",
	.test_cases = time_test_cases,
};

kunit_test_suite(time_test_suite);
MODULE_LICENSE("GPL");
