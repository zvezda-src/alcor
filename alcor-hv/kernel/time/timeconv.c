

#include <linux/time.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define SECS_PER_HOUR	(60 * 60)
#define SECS_PER_DAY	(SECS_PER_HOUR * 24)

void time64_to_tm(time64_t totalsecs, int offset, struct tm *result)
{
	u32 u32tmp, day_of_century, year_of_century, day_of_year, month, day;
	u64 u64tmp, udays, century, year;
	bool is_Jan_or_Feb, is_leap_year;
	long days, rem;
	int remainder;

	days = div_s64_rem(totalsecs, SECS_PER_DAY, &remainder);
	rem = remainder;
	rem += offset;
	while (rem < 0) {
		rem += SECS_PER_DAY;
		--days;
	}
	while (rem >= SECS_PER_DAY) {
		rem -= SECS_PER_DAY;
		++days;
	}

	result->tm_hour = rem / SECS_PER_HOUR;
	rem %= SECS_PER_HOUR;
	result->tm_min = rem / 60;
	result->tm_sec = rem % 60;

	/* January 1, 1970 was a Thursday. */
	result->tm_wday = (4 + days) % 7;
	if (result->tm_wday < 0)
		result->tm_wday += 7;

	/*

	udays	= ((u64) days) + 2305843009213814918ULL;

	u64tmp		= 4 * udays + 3;
	century		= div64_u64_rem(u64tmp, 146097, &u64tmp);
	day_of_century	= (u32) (u64tmp / 4);

	u32tmp		= 4 * day_of_century + 3;
	u64tmp		= 2939745ULL * u32tmp;
	year_of_century	= upper_32_bits(u64tmp);
	day_of_year	= lower_32_bits(u64tmp) / 2939745 / 4;

	year		= 100 * century + year_of_century;
	is_leap_year	= year_of_century ? !(year_of_century % 4) : !(century % 4);

	u32tmp		= 2141 * day_of_year + 132377;
	month		= u32tmp >> 16;
	day		= ((u16) u32tmp) / 2141;

	/*
	is_Jan_or_Feb	= day_of_year >= 306;

	/* Convert to the Gregorian calendar and adjust to Unix time. */
	year		= year + is_Jan_or_Feb - 6313183731940000ULL;
	month		= is_Jan_or_Feb ? month - 12 : month;
	day		= day + 1;
	day_of_year	+= is_Jan_or_Feb ? -306 : 31 + 28 + is_leap_year;

	/* Convert to tm's format. */
	result->tm_year = (long) (year - 1900);
	result->tm_mon  = (int) month;
	result->tm_mday = (int) day;
	result->tm_yday = (int) day_of_year;
}
EXPORT_SYMBOL(time64_to_tm);
