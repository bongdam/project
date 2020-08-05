#include <stdio.h>
#include <string.h>
#include <libytool.h>
#include "display.h"

display d;

int displayInit(void)
{
	d.start_time = 0;
	d.total_time = 0;
	d.current_time = 0;
	d.elapsed_time = 0;
	d.percent_complete = 0.0;
	d.display_interval = 1;
	d.overtime_flag = 0;
	d.screen_width = 79;
	d.display_wait = 0;
	d.display_datacount = 1;
	d.display_throughput = 1;
	d.display_time = 1;
	d.display_elapsed_only = 1;
	d.display_percent = 1;
	d.display_bar = 1;
	d.display_summary = 1;
	d.bar_open_brace = '[';
	d.bar_close_brace = ']';
	d.bar_complete = '=';
	d.bar_incomplete = ' ';
	d.total_display_percent = 1;
	return(0);
}

int displayBegin(void)
{
	d.start_time = ygettime(NULL);
	d.current_time = ygettime(NULL);
	return(0);
}

#define sec_per_hour 3600
#define sec_per_minute 60

static int calculateTimeDisplay(uint64 *sptr, uint64 *mptr, uint64 *hptr)
{
	if (*sptr >= sec_per_hour) {
		*hptr = *sptr / sec_per_hour;
		*sptr -= *hptr * sec_per_hour;
	}
	if (*sptr >= sec_per_minute) {
		*mptr = *sptr / sec_per_minute;
		*sptr -= *mptr * sec_per_minute;
	}
	return(0);
}

static int calculatePercentComplete(void)
{
	if (d.total_size_known && (d.total_size > 0)) {
		d.percent_complete = (float)(d.total_write * 100.0 / d.total_size);
		if (d.percent_complete < 0) {
			d.percent_complete = 9999.9f;
		}
	}
	return(0);
}

static const char TRext[] = "B \0KB\0MB\0GB\0TB";

static void calculateScaled(uint64 ull,
			    uint64 *int_part,
			    unsigned int *frac_part,
			    const char **unit)
{
	int i;

	(*frac_part) = 0;
	(*int_part) = ull;
	(*unit) = TRext;
	for (i = 0; i < 4; i++) {
		if ((*int_part) >= 1024) {
			(*frac_part) = ((((unsigned int)(*int_part)) & (1024 - 1)) * 10) / 1024;
			(*int_part) /= 1024;
			(*unit) += 3;	/* K, M, G, T */
		}
	}
}

static int displayPrint(void)
{
	uint64 eta = 0;
	uint64 hours = 0;
	uint64 minutes = 0;
	uint64 seconds = 0;
	char *time_title = "eta";
	int screen_used = 0;
	int this_width = 0;

	if (d.display_wait && (d.total_write == 0))
		return (0);

	d.current_time = ygettime(NULL);
	d.elapsed_time = d.current_time - d.start_time;

	calculatePercentComplete();

	if ((d.total_size_known == 1) && (!d.display_elapsed_only)) {
		if (d.total_write > 0) {
			if (d.total_size >= d.total_write) {
				if (d.percent_complete > 0.0) {
					eta = (uint64)(100 * d.elapsed_time / d.percent_complete) - d.elapsed_time;
				} else {
					eta = (uint64)(-1);
				}
			} else {
				if (!d.overtime_flag) {
					d.overtime_flag = 1;
					d.total_time = d.elapsed_time;
				}
				eta = d.elapsed_time - d.total_time;
				time_title = "ovr";
			}
		} else {
			eta = 0;
		}
		seconds = eta;
	} else {
		seconds = d.elapsed_time;
		time_title = "elapsed";
	}

	calculateTimeDisplay(&seconds, &minutes, &hours);

	/*
	 * Display data count
	 */
	this_width = 8;
	if (screen_used > 0)
		this_width++;
	if ((d.display_datacount) && (screen_used + this_width < d.screen_width)) {
		uint64 short_count;
		unsigned int short_frac;
		const char *short_count_units;

		if (screen_used > 0)
			fprintf(stderr, " ");
		calculateScaled(d.total_write,
				&short_count, &short_frac, &short_count_units);
		if (short_count > 9999) {
			fprintf(stderr, "+999.9%2.2s", short_count_units);
		} else {
			fprintf(stderr, "%4"LLU".%u%2.2s",
				short_count, short_frac, short_count_units);
		}
		screen_used += this_width;
	}

	/*
	 * Display throughput
	 */
	this_width = 13;
	if (!d.display_datacount)
		this_width -= 3;
	if (screen_used > 0)
		this_width++;
	if ((d.display_throughput) && (screen_used + this_width < d.screen_width)) {
		uint64 short_throughput;
		unsigned int short_throughput_frac;
		const char *short_throughput_units;

		if (screen_used > 0)
			fprintf(stderr, " ");
		if (d.display_datacount)
			fprintf(stderr, "at ");

		calculateScaled((d.elapsed_time > 0) ? \
				(d.total_write / d.elapsed_time) : 0,
				&short_throughput,
				&short_throughput_frac,
				&short_throughput_units);

		fprintf(stderr, "%4"LLU".%u%2.2s/s",
			short_throughput, short_throughput_frac, short_throughput_units);
		screen_used += this_width;
	}

	/*
	 * Display time
	 */
	this_width = (int)(11 + strlen(time_title));
	if (screen_used > 0)
		this_width += 2;
	if ((d.display_time) && (screen_used + this_width < d.screen_width)) {
		if (screen_used > 0)
			fprintf(stderr, "  ");
		fprintf(stderr, "%s: ", time_title);
		if (hours > 99) {
			fprintf(stderr, "+99:99:99");
		} else
			fprintf(stderr, "%3u:%2.2u:%2.2u",
				(unsigned int)hours,
				(unsigned int)minutes,
				(unsigned int)seconds);
		screen_used += this_width;
	}

	/*
	 * Display percent
	 */
	this_width = 5;
	if (screen_used > 0)
		this_width++;
	if ((d.display_percent) && (d.total_size_known)
	    && (screen_used + this_width < d.screen_width)) {
		if (screen_used > 0)
			fprintf(stderr, " ");

		if (d.percent_complete > 999) {
			fprintf(stderr, "+999%%");
		} else {
			fprintf(stderr, "%4d%%", (int)d.percent_complete);
		}
		screen_used += this_width;
	}

	/*
	 * Display progress bar
	 */
	this_width = 5;
	if (screen_used > 0)
		this_width++;
	if ((d.display_bar) && (d.total_size_known)
	    && (screen_used + this_width < d.screen_width)) {
		int c;
		int line_length;
		int completed_length = 0;

		if (screen_used > 0) {
			fprintf(stderr, " ");
			screen_used++;
		}
		this_width = d.screen_width - screen_used + 1;
		line_length = this_width - 3;
		completed_length = (int)(line_length * d.percent_complete / 100);
		fprintf(stderr, "%c", d.bar_open_brace);
		for (c = 0; c < line_length; c++) {
			if (c <= completed_length) {
				fprintf(stderr, "%c", d.bar_complete);
			} else {
				fprintf(stderr, "%c", d.bar_incomplete);
			}
		}
		fprintf(stderr, "%c", d.bar_close_brace);
	}

	fprintf(stderr, "\r");

	return (0);
}

int displayUpdate(void)
{
	if (ygettime(NULL) < d.current_time + d.display_interval) return(0);
	if (displayPrint() != 0) return(1);
	return(0);
}

int displayEnd(void)
{
	uint64 hours = 0;
	uint64 minutes = 0;
	uint64 seconds = 0;

	displayPrint();
	d.elapsed_time = d.current_time - d.start_time;

	calculatePercentComplete();
	seconds = d.elapsed_time;
	calculateTimeDisplay(&seconds, &minutes, &hours);

	fprintf(stderr, "\n");
#ifdef SUPPORT_SUMMARY
	if (d.display_summary) {
		uint64 total_throughput;
		uint64 short_throughput;
		unsigned int short_throughput_frac;
		const char *short_throughput_units;
		uint64 short_count;
		unsigned int short_frac;
		const char *short_count_units;

		calculateScaled(d.total_write,
				&short_count, &short_frac, &short_count_units);
		fprintf(stderr, "Copied: %" LLU "B (%" LLU ".%u%s)",
			d.total_write, short_count, short_frac, short_count_units);
		if (d.total_size_known && d.total_display_percent) {
			fprintf(stderr, " (%d%% of expected input)",
				(int)d.percent_complete);
		}
		fprintf(stderr, "\nTime: ");
		if (hours > 0) {
			fprintf(stderr, "%3u:%2.2u:%2.2u",
				(unsigned int)hours,
				(unsigned int)minutes,
				(unsigned int)seconds);
		} else if (minutes > 0) {
			fprintf(stderr, "%2.2u:%2.2u",
				(unsigned int)minutes, (unsigned int)seconds);
		} else {
			fprintf(stderr, "%2u seconds", (unsigned int)seconds);
		}
		fprintf(stderr, "\nThroughput: ");
		total_throughput = (d.elapsed_time > 0) ? \
				   (d.total_write / d.elapsed_time) : 0;

		calculateScaled(total_throughput, &short_throughput,
				&short_throughput_frac, &short_throughput_units);

		if ((hours != 0) || (minutes != 0) || (seconds != 0)) {
			fprintf(stderr, "%" LLU "B (%" LLU ".%u%s/s)\n\n",
				(uint64)total_throughput,
				short_throughput, short_throughput_frac, short_throughput_units);
		} else {
			fprintf(stderr, "(infinite)\n\n");
		}
	}
#endif
	d.start_time = 0;

	return (0);
}
