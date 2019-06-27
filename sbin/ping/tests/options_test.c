/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2019 Jan Sucan <jansucan@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <atf-c.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "../options.h"

/*
 * Helper macros.
 */

#define STRINGIFY(s) #s
#define DEFINED_NUM_TO_STR(s) STRINGIFY(s)

#define GETOPT_RESET \
	optreset = optind = 1

#define ARGC_ARGV_EMPTY      				                    \
	char *test_argv[] = { "ping", NULL };        		            \
	const int test_argc = sizeof(test_argv) / sizeof(test_argv[0]) - 1; \
	GETOPT_RESET

#define ARGC_ARGV(...)           				            \
	char *test_argv[] = { "ping", __VA_ARGS__, NULL };	            \
	const int test_argc = sizeof(test_argv) / sizeof(test_argv[0]) - 1; \
	GETOPT_RESET

/*
 * Test cases.
 */

ATF_TC_WITHOUT_HEAD(options_no);
ATF_TC_BODY(options_no, tc)
{
	ARGC_ARGV_EMPTY;
	struct options options;

	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
}

ATF_TC_WITHOUT_HEAD(options_missed);
ATF_TC_BODY(options_missed, tc)
{
	ARGC_ARGV("-A", "localhost");
	struct options options;

	options.f_missed = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_missed == true);
}

ATF_TC_WITHOUT_HEAD(options_audible);
ATF_TC_BODY(options_audible, tc)
{
	ARGC_ARGV("-a", "localhost");
	struct options options;

	options.f_audible = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_audible == true);
}

ATF_TC_WITHOUT_HEAD(options_count);
ATF_TC_BODY(options_count, tc)
{
	struct options options;
	{
		ARGC_ARGV("-c");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-c", "-1000", "localhost");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-c", "0", "localhost");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-c", "1", "localhost");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.n_packets == 1);
	}
	{
		ARGC_ARGV("-c", "234567", "localhost");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.n_packets == 234567);
	}
	{
		ARGC_ARGV("-c", DEFINED_NUM_TO_STR(LONG_MAX), "localhost");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.n_packets == LONG_MAX);
	}
	{
		ARGC_ARGV("-c", "replaced_by_LONG_MAX+1", "localhost");
		const unsigned long n = ((unsigned long) LONG_MAX) + 1;
		char greater_than_long_max[64];

		sprintf(greater_than_long_max, "%lu", n);
		test_argv[2] = greater_than_long_max;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-c", "replaced_by_LONG_MAX+1000", "localhost");
		const unsigned long n = ((unsigned long) LONG_MAX) + 1000;
		char greater_than_long_max[64];

		sprintf(greater_than_long_max, "%lu", n);
		test_argv[2] = greater_than_long_max;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC_WITHOUT_HEAD(options_dont_fragment);
ATF_TC_BODY(options_dont_fragment, tc)
{
	ARGC_ARGV("-D", "localhost");
	struct options options;

	options.f_dont_fragment = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_dont_fragment == true);
}

ATF_TC_WITHOUT_HEAD(options_so_debug);
ATF_TC_BODY(options_so_debug, tc)
{
	ARGC_ARGV("-d", "localhost");
	struct options options;

	options.f_so_debug = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_so_debug == true);
}

ATF_TC_WITHOUT_HEAD(options_numeric);
ATF_TC_BODY(options_numeric, tc)
{
	ARGC_ARGV("-n", "localhost");
	struct options options;

	options.f_numeric = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_numeric == true);
}

ATF_TC_WITHOUT_HEAD(options_once);
ATF_TC_BODY(options_once, tc)
{
	ARGC_ARGV("-o", "localhost");
	struct options options;

	options.f_once = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_once == true);
}

/*
 * Main.
 */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, options_no);
	ATF_TP_ADD_TC(tp, options_missed);
	ATF_TP_ADD_TC(tp, options_audible);
	ATF_TP_ADD_TC(tp, options_count);
	ATF_TP_ADD_TC(tp, options_dont_fragment);
	ATF_TP_ADD_TC(tp, options_so_debug);
	ATF_TP_ADD_TC(tp, options_numeric);
	ATF_TP_ADD_TC(tp, options_once);

	return (atf_no_error());
}
