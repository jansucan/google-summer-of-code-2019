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

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <atf-c.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "../options.h"
#include "../defaults_limits.h"

/*
 * Max. allowed difference in microseconds used for checking the
 * result of the -i option parsing.
 */
#define DOUBLE_MAX_DELTA 100

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

#define	ARGV_BUFFER_SIZE	64

#define ARGV_SET_FROM_EXPR(argv, idx, expr)						\
	const unsigned long ul_##idx = expr;						\
	char ul_str_##idx[ARGV_BUFFER_SIZE];						\
	const int sr##idx = snprintf(ul_str_##idx, ARGV_BUFFER_SIZE, "%lu", ul_##idx);	\
	if (sr##idx < 0)								\
		atf_tc_fail("snprintf() error");					\
	else if (sr##idx >= ARGV_BUFFER_SIZE)						\
		atf_tc_fail("snprintf() buffer too small");				\
	argv[idx] = ul_str_##idx

#define ARGV_SET_LDBL_FROM_EXPR(argv, idx, expr)						\
	const long double ldbl_##idx = expr;							\
	char ldbl_str_##idx[ARGV_BUFFER_SIZE];							\
	const int sr##idx = snprintf(ldbl_str_##idx, ARGV_BUFFER_SIZE, "%Lg", ldbl_##idx);	\
	if (sr##idx < 0)									\
		atf_tc_fail("snprintf() error");						\
	else if (sr##idx >= ARGV_BUFFER_SIZE)							\
		atf_tc_fail("snprintf() buffer too small");					\
	argv[idx] = ldbl_str_##idx

/*
 * Global variables.
 */

static struct options options;

/*
 * Test cases.
 */

ATF_TC_WITHOUT_HEAD(parse_hosts);
ATF_TC_BODY(parse_hosts, tc)
{
	{
		ARGC_ARGV("127.0.0.1", "127.0.0.1");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("127.0.0.1");

		options.target = NULL;
		options.target_addrinfo = NULL;
		options.target_type = TARGET_UNKNOWN;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("127.0.0.1", options.target);
		ATF_REQUIRE(options.target_addrinfo != NULL);
		ATF_REQUIRE(options.target_addrinfo->ai_family == AF_INET);
		ATF_REQUIRE(options.target_type == TARGET_ADDRESS_IPV4);
	}
	{
		ARGC_ARGV("-4", "localhost");

		options.target = NULL;
		options.target_addrinfo = NULL;
		options.target_type = TARGET_UNKNOWN;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("localhost", options.target);
		ATF_REQUIRE(options.target_addrinfo != NULL);
		ATF_REQUIRE(options.target_addrinfo->ai_family == AF_INET);
		ATF_REQUIRE(options.target_type == TARGET_HOSTNAME_IPV4);
	}
#ifdef INET6
	{
		ARGC_ARGV("::1");

		options.target = NULL;
		options.target_addrinfo = NULL;
		options.target_type = TARGET_UNKNOWN;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("::1", options.target);
		ATF_REQUIRE(options.target_addrinfo != NULL);
		ATF_REQUIRE(options.target_addrinfo->ai_family == AF_INET6);
		ATF_REQUIRE(options.target_type == TARGET_ADDRESS_IPV6);
	}
	{
		ARGC_ARGV("-6", "localhost");

		options.target = NULL;
		options.target_addrinfo = NULL;
		options.target_type = TARGET_UNKNOWN;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("localhost", options.target);
		ATF_REQUIRE(options.target_addrinfo != NULL);
		ATF_REQUIRE(options.target_addrinfo->ai_family == AF_INET6);
		ATF_REQUIRE(options.target_type == TARGET_HOSTNAME_IPV6);
	}
	/* TODO: hops */
#endif /* INET6 */
}

#ifdef INET6
ATF_TC_WITHOUT_HEAD(compatibility_options_target);
ATF_TC_BODY(compatibility_options_target, tc)
{
	{
		ARGC_ARGV("-6", "-G", "localhost");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-4", "-e", "localhost");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	/* { */
	/* 	ARGC_ARGV("-4", "::1"); */
	/* 	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE); */
	/* } */
	/* { */
	/* 	ARGC_ARGV("-6", "127.0.0.1"); */
	/* 	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE); */
	/* } */
	/* TODO: how to test hostname resolving only to IPv4 or IPv6? */
}
#endif /* INET6 */

ATF_TC_WITHOUT_HEAD(options_no);
ATF_TC_BODY(options_no, tc)
{
	ARGC_ARGV_EMPTY;

	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
}

ATF_TC_WITHOUT_HEAD(option_missed);
ATF_TC_BODY(option_missed, tc)
{
	ARGC_ARGV("-A", "localhost");

	options.f_missed = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_missed == true);
}

ATF_TC_WITHOUT_HEAD(option_audible);
ATF_TC_BODY(option_audible, tc)
{
	ARGC_ARGV("-a", "localhost");

	options.f_audible = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_audible == true);
}

ATF_TC_WITHOUT_HEAD(option_count);
ATF_TC_BODY(option_count, tc)
{
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

		options.f_packets = false;
		options.n_packets = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packets == true);
		ATF_REQUIRE(options.n_packets == 1);
	}
	{
		ARGC_ARGV("-c", "replaced_by_LONG_MAX/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (LONG_MAX / 2));
		options.f_packets = false;
		options.n_packets = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packets == true);
		ATF_REQUIRE(options.n_packets == (LONG_MAX / 2));
	}
	{
		ARGC_ARGV("-c", DEFINED_NUM_TO_STR(LONG_MAX), "localhost");

		options.f_packets = false;
		options.n_packets = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packets == true);
		ATF_REQUIRE(options.n_packets == LONG_MAX);
	}
	{
		ARGC_ARGV("-c", "replaced_by_LONG_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) LONG_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-c", "replaced_by_LONG_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) LONG_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC_WITHOUT_HEAD(option_dont_fragment);
ATF_TC_BODY(option_dont_fragment, tc)
{
	ARGC_ARGV("-D", "localhost");

	options.f_dont_fragment = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_dont_fragment == true);
}

ATF_TC_WITHOUT_HEAD(option_so_debug);
ATF_TC_BODY(option_so_debug, tc)
{
	ARGC_ARGV("-d", "localhost");

	options.f_so_debug = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_so_debug == true);
}

ATF_TC_WITHOUT_HEAD(option_flood);
ATF_TC_BODY(option_flood, tc)
{
	ARGC_ARGV("-f", "-i", "1","localhost");

	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
}

ATF_TC(privileged_option_flood);
ATF_TC_HEAD(privileged_option_flood, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(privileged_option_flood, tc)
{
	ARGC_ARGV("-f", "localhost");

	options.f_flood = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_flood == true);
}

ATF_TC(unprivileged_option_flood);
ATF_TC_HEAD(unprivileged_option_flood, tc)
{
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(unprivileged_option_flood, tc)
{
	ARGC_ARGV("-f", "localhost");

	options.f_flood = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOPERM);
	ATF_REQUIRE(options.f_flood == true);
}

ATF_TC_WITHOUT_HEAD(option_interface);
ATF_TC_BODY(option_interface, tc)
{
	{
		ARGC_ARGV("-I");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-I", "interface1234", "localhost");
#if !defined(INET6) || !defined(USE_SIN6_SCOPE_ID)
		options.f_interface = false;
#endif
		options.s_interface = NULL;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("interface1234", options.s_interface);
#if !defined(INET6) || !defined(USE_SIN6_SCOPE_ID)
		ATF_REQUIRE(options.f_interface == true);
#endif

	}
}

ATF_TC_WITHOUT_HEAD(option_interval);
ATF_TC_BODY(option_interval, tc)
{
	{
		ARGC_ARGV("localhost");

		options.f_interval = true;
		options.n_interval.tv_sec = DEFAULT_INTERVAL_TV_SEC + 123;
		options.n_interval.tv_usec = DEFAULT_INTERVAL_TV_USEC + 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_interval == false);
		ATF_REQUIRE(options.n_interval.tv_sec == DEFAULT_INTERVAL_TV_SEC);
		ATF_REQUIRE(options.n_interval.tv_usec == DEFAULT_INTERVAL_TV_USEC);
	}
	{
		ARGC_ARGV("-i");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-i", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-i", "0", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-i", "replaced_by_DBL_MAX/2", "localhost");
		const double dbl = DBL_MAX / 2;

		ARGV_SET_LDBL_FROM_EXPR(test_argv, 2, dbl);
		options.f_interval = false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);

		double dbl_integer_part;
		const suseconds_t expected_tv_usec = (suseconds_t) (modf(dbl, &dbl_integer_part) * 1000 * 1000);
		const time_t expected_tv_sec = (time_t) dbl_integer_part;

		ATF_REQUIRE(options.n_interval.tv_sec == expected_tv_sec);
		ATF_REQUIRE(options.n_interval.tv_usec >= (expected_tv_usec - DOUBLE_MAX_DELTA) &&
		    options.n_interval.tv_usec <= (expected_tv_usec + DOUBLE_MAX_DELTA));
		ATF_REQUIRE(options.f_interval == true);
	}
	{
		ARGC_ARGV("-i", "replaced_by_DBL_MAX", "localhost");
		ARGV_SET_LDBL_FROM_EXPR(test_argv, 2, DBL_MAX);

		options.f_interval = false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);

		const double dbl = DBL_MAX;
		double dbl_integer_part;
		const suseconds_t expected_tv_usec = (suseconds_t) (modf(dbl, &dbl_integer_part) * 1000 * 1000);
		const time_t expected_tv_sec = (time_t) dbl_integer_part;

		ATF_REQUIRE(options.n_interval.tv_sec == expected_tv_sec);
		ATF_REQUIRE(options.n_interval.tv_usec >= (expected_tv_usec - DOUBLE_MAX_DELTA) &&
		    options.n_interval.tv_usec <= DBL_MAX);
		ATF_REQUIRE(options.f_interval == true);
	}
	{
		if (LDBL_MAX <= DBL_MAX)
			atf_tc_skip("This test requires 'long double' to be wider then"
			    " 'double' so it can store DBL_MAX * 2 .");

		ARGC_ARGV("-i", "replaced_by_DBL_MAX*2", "localhost");
		ARGV_SET_LDBL_FROM_EXPR(test_argv, 2, ((long double) DBL_MAX) * 2);

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC(privileged_option_interval);
ATF_TC_HEAD(privileged_option_interval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(privileged_option_interval, tc)
{
	ARGC_ARGV("-i", "replaced_by_DBL_MIN", "localhost");
	ARGV_SET_LDBL_FROM_EXPR(test_argv, 2, DBL_MIN);

	options.f_interval = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	/*
	 * Values less than 1 microsecond are raised to 1
	 * microsecond.
	 */
	ATF_REQUIRE(options.n_interval.tv_sec == 0);
	ATF_REQUIRE(options.n_interval.tv_usec == 1);
	ATF_REQUIRE(options.f_interval == true);
}

ATF_TC(unprivileged_option_interval);
ATF_TC_HEAD(unprivileged_option_interval, tc)
{
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(unprivileged_option_interval, tc)
{
	ARGC_ARGV("-i", "replaced_by_DBL_MIN", "localhost");
	ARGV_SET_LDBL_FROM_EXPR(test_argv, 2, DBL_MIN);

	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOPERM);
}

ATF_TC_WITHOUT_HEAD(option_preload);
ATF_TC_BODY(option_preload, tc)
{
	{
		ARGC_ARGV("-l");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-l", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-l", "-1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-l", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-l", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC(privileged_option_preload);
ATF_TC_HEAD(privileged_option_preload, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(privileged_option_preload, tc)
{
	{
		ARGC_ARGV("-l", "0", "localhost");

		options.f_preload = false;
		options.n_preload = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_preload == true);
		ATF_REQUIRE(options.n_preload == 0);
	}
	{
		ARGC_ARGV("-l", "replaced_by_INT_MAX/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) (INT_MAX / 2)));
		options.f_preload = false;
		options.n_preload = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_preload == true);
		ATF_REQUIRE(options.n_preload == (INT_MAX / 2));
	}
	{
		ARGC_ARGV("-l", DEFINED_NUM_TO_STR(INT_MAX), "localhost");

		options.f_preload = false;
		options.n_preload = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_preload == true);
		ATF_REQUIRE(options.n_preload == INT_MAX);
	}
}

ATF_TC(unprivileged_option_preload);
ATF_TC_HEAD(unprivileged_option_preload, tc)
{
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(unprivileged_option_preload, tc)
{
	ARGC_ARGV("-l", "1", "localhost");

	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOPERM);
}

ATF_TC_WITHOUT_HEAD(option_numeric);
ATF_TC_BODY(option_numeric, tc)
{
	ARGC_ARGV("-n", "localhost");

	options.f_numeric = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_numeric == true);
}

ATF_TC_WITHOUT_HEAD(option_once);
ATF_TC_BODY(option_once, tc)
{
	ARGC_ARGV("-o", "localhost");

	options.f_once = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_once == true);
}

ATF_TC_WITHOUT_HEAD(option_ping_filled);
ATF_TC_BODY(option_ping_filled, tc)
{
	{
		ARGC_ARGV("-p");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-p", "0123abcDEFG", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-p", "010aF", "localhost");

		options.f_ping_filled = false;
		options.ping_filled_size = 0;
		options.a_ping_filled[0] = 1;
		options.a_ping_filled[1] = 10;
		options.a_ping_filled[2] = 15;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_ping_filled == true);
		ATF_REQUIRE(options.ping_filled_size == 3);
		ATF_REQUIRE(options.a_ping_filled[0] == 1);
		ATF_REQUIRE(options.a_ping_filled[1] == 10);
		ATF_REQUIRE(options.a_ping_filled[2] == 15);
	}
	{
		ARGC_ARGV("-p", "000102030405060708090A0B0C0d0e0f", "localhost");

		options.f_ping_filled = false;
		options.ping_filled_size = 0;

		for (int i = 0; i < (sizeof(options.a_ping_filled) / sizeof(options.a_ping_filled[0])); ++i)
			options.a_ping_filled[i] = i;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_ping_filled == true);
		ATF_REQUIRE(options.ping_filled_size == 16);

		for (int i = 0; i < (sizeof(options.a_ping_filled) / sizeof(options.a_ping_filled[0])); ++i)
			ATF_REQUIRE(options.a_ping_filled[i] == i);
	}
	{
		ARGC_ARGV("-p", "707172737475767778797A7B7C7d7e7f70", "localhost");

		options.f_ping_filled = false;
		options.ping_filled_size = 0;

		for (int i = 0; i < (sizeof(options.a_ping_filled) / sizeof(options.a_ping_filled[0])); ++i)
			options.a_ping_filled[i] = 0x70 + i;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_ping_filled == true);
		ATF_REQUIRE(options.ping_filled_size == 16);

		for (int i = 0; i < (sizeof(options.a_ping_filled) / sizeof(options.a_ping_filled[0])); ++i)
			ATF_REQUIRE(options.a_ping_filled[i] == 0x70 + i);
	}
}

ATF_TC_WITHOUT_HEAD(option_quiet);
ATF_TC_BODY(option_quiet, tc)
{
	ARGC_ARGV("-q", "localhost");

	options.f_quiet = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_quiet == true);
}

ATF_TC_WITHOUT_HEAD(option_source);
ATF_TC_BODY(option_source, tc)
{
	{
		ARGC_ARGV("-S");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-S", "source1234", "localhost");

		options.s_source = NULL;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("source1234", options.s_source);
	}
}

ATF_TC_WITHOUT_HEAD(option_packet_size);
ATF_TC_BODY(option_packet_size, tc)
{
#ifdef INET6
	{
		ARGC_ARGV("-6", "localhost");

		options.f_packet_size = true;
		options.n_packet_size = DEFAULT_DATALEN_IPV6 + 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packet_size == false);
		ATF_REQUIRE(options.n_packet_size == DEFAULT_DATALEN_IPV6);
	}
#endif
	{
		ARGC_ARGV("-4", "localhost");

		options.f_packet_size = true;
		options.n_packet_size = DEFAULT_DATALEN_IPV4 + 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packet_size == false);
		ATF_REQUIRE(options.n_packet_size == DEFAULT_DATALEN_IPV4);
	}
	{
		ARGC_ARGV("-s");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-s", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-s", "0", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-s", "1", "localhost");

		options.f_packet_size = false;
		options.n_packet_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packet_size == true);
		ATF_REQUIRE(options.n_packet_size == 1);
	}
#ifdef INET6
	{
		ARGC_ARGV("-6", "-s", "replaced_by_MAXDATALEN/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, (unsigned long) (MAXDATALEN / 2));
		options.f_packet_size = false;
		options.n_packet_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packet_size == true);
		ATF_REQUIRE(options.n_packet_size == (MAXDATALEN / 2));
	}
	{
		ARGC_ARGV("-6", "-s", "replaced_by_MAXDATALEN", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, (unsigned long) MAXDATALEN);
		options.f_packet_size = false;
		options.n_packet_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packet_size == true);
		ATF_REQUIRE(options.n_packet_size == MAXDATALEN);
	}
	{
		ARGC_ARGV("-6", "-s", "replaced_by_MAXDATALEN+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, ((unsigned long) MAXDATALEN) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-6", "-s", "replaced_by_MAXDATALEN+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, ((unsigned long) MAXDATALEN) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
#endif /* !INET6 */
	{
		ARGC_ARGV("-4", "-s", "replaced_by_LONG_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, ((unsigned long) LONG_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-4", "-s", "replaced_by_LONG_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, ((unsigned long) LONG_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC(privileged_option_packet_size);
ATF_TC_HEAD(privileged_option_packet_size, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(privileged_option_packet_size, tc)
{
	{
		ARGC_ARGV("-4", "-s", "replaced_by_LONG_MAX/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, (unsigned long) (LONG_MAX / 2));
		options.f_packet_size = false;
		options.n_packet_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packet_size == true);
		ATF_REQUIRE(options.n_packet_size == (LONG_MAX / 2));
	}
	{
		ARGC_ARGV("-4", "-s", "replaced_by_LONG_MAX", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, (unsigned long) LONG_MAX);
		options.f_packet_size = false;
		options.n_packet_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packet_size == true);
		ATF_REQUIRE(options.n_packet_size == LONG_MAX);
	}
}

ATF_TC(unprivileged_option_packet_size);
ATF_TC_HEAD(unprivileged_option_packet_size, tc)
{
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(unprivileged_option_packet_size, tc)
{
	{
		ARGC_ARGV("-4", "-s", "replaced_by_DEFAULT_DATALEN_IPV4/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, (unsigned long) (DEFAULT_DATALEN_IPV4 / 2));
		options.f_packet_size = false;
		options.n_packet_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packet_size == true);
		ATF_REQUIRE(options.n_packet_size == (DEFAULT_DATALEN_IPV4 / 2));
	}
	{
		ARGC_ARGV("-4", "-s", "replaced_by_DEFAULT_DATALEN_IPV4", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, (unsigned long) DEFAULT_DATALEN_IPV4);
		options.f_packet_size = false;
		options.n_packet_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_packet_size == true);
		ATF_REQUIRE(options.n_packet_size == DEFAULT_DATALEN_IPV4);
	}
	{
		ARGC_ARGV("-4", "-s", "replaced_by_DEFAULT_DATALEN_IPV4+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, ((unsigned long) DEFAULT_DATALEN_IPV4) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOPERM);
	}
	{
		ARGC_ARGV("-4", "-s", "replaced_by_DEFAULT_DATALEN_IPV4+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 3, ((unsigned long) DEFAULT_DATALEN_IPV4) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOPERM);
	}
}

ATF_TC_WITHOUT_HEAD(option_timeout);
ATF_TC_BODY(option_timeout, tc)
{
	{
		ARGC_ARGV("-t");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-t", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-t", "0", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-t", "1", "localhost");

		options.f_timeout = false;
		options.n_timeout = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_timeout == true);
		ATF_REQUIRE(options.n_timeout == 1);
	}
	{
		ARGC_ARGV("-t", "replaced_by_MAX_TIMEOUT/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (MAX_TIMEOUT / 2));
		options.f_timeout = false;
		options.n_timeout = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_timeout == true);
		ATF_REQUIRE(options.n_timeout == (MAX_TIMEOUT / 2));
	}
	{
		ARGC_ARGV("-t", DEFINED_NUM_TO_STR(MAX_TIMEOUT), "localhost");

		options.f_timeout = false;
		options.n_timeout = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_timeout == true);
		ATF_REQUIRE(options.n_timeout == MAX_TIMEOUT);
	}
	{
		ARGC_ARGV("-t", "replaced_by_MAX_TIMEOUT+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAX_TIMEOUT) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-t", "replaced_by_MAX_TIMEOUT+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAX_TIMEOUT) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC_WITHOUT_HEAD(option_verbose);
ATF_TC_BODY(option_verbose, tc)
{
	ARGC_ARGV("-v", "localhost");

	options.f_verbose = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_verbose == true);
}

ATF_TC_WITHOUT_HEAD(option_wait_time);
ATF_TC_BODY(option_wait_time, tc)
{
	{
		ARGC_ARGV("localhost");

		options.f_wait_time = true;
		options.n_wait_time = DEFAULT_WAIT_TIME + 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_wait_time == false);
		ATF_REQUIRE(options.n_wait_time == DEFAULT_WAIT_TIME);
	}
	{
		ARGC_ARGV("-W");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-W", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-W", "-1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-W", "0", "localhost");

		options.f_wait_time = false;
		options.n_wait_time = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_wait_time == true);
		ATF_REQUIRE(options.n_wait_time == 0);
	}
	{
		ARGC_ARGV("-W", "replaced_by_INT_MAX/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (INT_MAX / 2));
		options.f_wait_time = false;
		options.n_wait_time = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_wait_time == true);
		ATF_REQUIRE(options.n_wait_time == (INT_MAX / 2));
	}
	{
		ARGC_ARGV("-W", DEFINED_NUM_TO_STR(INT_MAX), "localhost");

		options.f_wait_time = false;
		options.n_wait_time = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_wait_time == true);
		ATF_REQUIRE(options.n_wait_time == INT_MAX);
	}
	{
		ARGC_ARGV("-W", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-W", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC_WITHOUT_HEAD(option_protocol_ipv4);
ATF_TC_BODY(option_protocol_ipv4, tc)
{
	ARGC_ARGV("-4", "localhost");

	options.f_protocol_ipv4 = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_protocol_ipv4 == true);
}

ATF_TC_WITHOUT_HEAD(option_sweep_max);
ATF_TC_BODY(option_sweep_max, tc)
{
	{
		ARGC_ARGV("-G");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-G", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-G", "0", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-G", "1", "localhost");

		options.f_sweep_max = false;
		options.n_sweep_max = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_max == true);
		ATF_REQUIRE(options.n_sweep_max == 1);
	}
	{
		ARGC_ARGV("-G", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-G", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-G", "1", "-s", "1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC(privileged_option_sweep_max);
ATF_TC_HEAD(privileged_option_sweep_max, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(privileged_option_sweep_max, tc)
{
	{
		ARGC_ARGV("-G", "replaced_by_INT_MAX/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (INT_MAX / 2));
		options.f_sweep_max = false;
		options.n_sweep_max = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_max == true);
		ATF_REQUIRE(options.n_sweep_max == (INT_MAX / 2));
	}
	{
		ARGC_ARGV("-G", DEFINED_NUM_TO_STR(INT_MAX), "localhost");

		options.f_sweep_max = false;
		options.n_sweep_max = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_max == true);
		ATF_REQUIRE(options.n_sweep_max == INT_MAX);
	}
}

ATF_TC(unprivileged_option_sweep_max);
ATF_TC_HEAD(unprivileged_option_sweep_max, tc)
{
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(unprivileged_option_sweep_max, tc)
{
	{
		ARGC_ARGV("-G", DEFINED_NUM_TO_STR(DEFAULT_DATALEN_IPV4), "localhost");

		options.n_sweep_max = DEFAULT_DATALEN_IPV4 + 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		options.n_sweep_max = DEFAULT_DATALEN_IPV4;
	}
	{
		ARGC_ARGV("-G", "replaced_by_DEFAULT_DATALEN_IPV4+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) DEFAULT_DATALEN_IPV4) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOPERM);
	}
}

ATF_TC_WITHOUT_HEAD(option_sweep_min);
ATF_TC_BODY(option_sweep_min, tc)
{
	{
		ARGC_ARGV("-g");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-g", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-g", "0", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-g", "1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-g", "2", "-G", "1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-g", "1", "-G", "1", "localhost");

		options.f_sweep_min = false;
		options.n_sweep_min = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_min == true);
		ATF_REQUIRE(options.n_sweep_min == 1);
	}
	{
		ARGC_ARGV("-g", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-g", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC(privileged_option_sweep_min);
ATF_TC_HEAD(privileged_option_sweep_min, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(privileged_option_sweep_min, tc)
{
	{
		ARGC_ARGV("-g", "replaced_by_INT_MAX/2", "-G", "replaced_by_INT_MAX/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (INT_MAX / 2));
		ARGV_SET_FROM_EXPR(test_argv, 4, (unsigned long) (INT_MAX / 2));
		options.f_sweep_min = false;
		options.n_sweep_min = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_min == true);
		ATF_REQUIRE(options.n_sweep_min == (INT_MAX / 2));
	}
	{
		ARGC_ARGV("-g", DEFINED_NUM_TO_STR(INT_MAX), "-G", DEFINED_NUM_TO_STR(INT_MAX), "localhost");

		options.f_sweep_min = false;
		options.n_sweep_min = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_min == true);
		ATF_REQUIRE(options.n_sweep_min == INT_MAX);
	}
}

ATF_TC(unprivileged_option_sweep_min);
ATF_TC_HEAD(unprivileged_option_sweep_min, tc)
{
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(unprivileged_option_sweep_min, tc)
{
	{
		ARGC_ARGV("-g", DEFINED_NUM_TO_STR(DEFAULT_DATALEN_IPV4), "-G",
		    DEFINED_NUM_TO_STR(DEFAULT_DATALEN_IPV4), "localhost");

		options.n_sweep_min = DEFAULT_DATALEN_IPV4 + 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		options.n_sweep_min = DEFAULT_DATALEN_IPV4;
	}
	{
		ARGC_ARGV("-g", "replaced_by_DEFAULT_DATALEN_IPV4+1", "-G",
		    "replaced_by_DEFAULT_DATALEN_IPV4+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) DEFAULT_DATALEN_IPV4) + 1);
		ARGV_SET_FROM_EXPR(test_argv, 4, ((unsigned long) DEFAULT_DATALEN_IPV4) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOPERM);
	}
}

ATF_TC_WITHOUT_HEAD(option_sweep_incr);
ATF_TC_BODY(option_sweep_incr, tc)
{
	{
		ARGC_ARGV("localhost");

		options.f_sweep_incr = true;
		options.n_sweep_incr = DEFAULT_SWEEP_INCR + 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_incr == false);
		ATF_REQUIRE(options.n_sweep_incr == DEFAULT_SWEEP_INCR);
	}
	{
		ARGC_ARGV("-h");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-h", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-h", "0", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-h", "1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-h", "1", "-G", "1", "localhost");

		options.f_sweep_incr = false;
		options.n_sweep_incr = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_incr == true);
		ATF_REQUIRE(options.n_sweep_incr == 1);
	}
	{
		ARGC_ARGV("-h", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-h", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC(privileged_option_sweep_incr);
ATF_TC_HEAD(privileged_option_sweep_incr, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(privileged_option_sweep_incr, tc)
{
	{
		ARGC_ARGV("-h", "replaced_by_INT_MAX/2", "-G", "1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (INT_MAX / 2));
		options.f_sweep_incr = false;
		options.n_sweep_incr = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_incr == true);
		ATF_REQUIRE(options.n_sweep_incr == (INT_MAX / 2));
	}
	{
		ARGC_ARGV("-h", DEFINED_NUM_TO_STR(INT_MAX), "-G", DEFINED_NUM_TO_STR(INT_MAX), "localhost");

		options.f_sweep_incr = false;
		options.n_sweep_incr = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_incr == true);
		ATF_REQUIRE(options.n_sweep_incr == INT_MAX);
	}
}

ATF_TC(unprivileged_option_sweep_incr);
ATF_TC_HEAD(unprivileged_option_sweep_incr, tc)
{
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(unprivileged_option_sweep_incr, tc)
{
	{
		ARGC_ARGV("-h", DEFINED_NUM_TO_STR(DEFAULT_DATALEN_IPV4), "-G",
		    DEFINED_NUM_TO_STR(DEFAULT_DATALEN_IPV4), "localhost");

		options.n_sweep_incr = DEFAULT_DATALEN_IPV4 + 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		options.n_sweep_incr = DEFAULT_DATALEN_IPV4;
	}
	{
		ARGC_ARGV("-h", "replaced_by_DEFAULT_DATALEN_IPV4+1", "-G",
		    "replaced_by_DEFAULT_DATALEN_IPV4+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) DEFAULT_DATALEN_IPV4) + 1);
		ARGV_SET_FROM_EXPR(test_argv, 4, ((unsigned long) DEFAULT_DATALEN_IPV4) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOPERM);
	}
}

ATF_TC_WITHOUT_HEAD(option_no_loop);
ATF_TC_BODY(option_no_loop, tc)
{
	ARGC_ARGV("-L", "localhost");

	options.f_no_loop = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_no_loop == true);
}

ATF_TC_WITHOUT_HEAD(option_mask_time);
ATF_TC_BODY(option_mask_time, tc)
{
	{
		ARGC_ARGV("-M");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-M", "x", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-M", "M", "localhost");

		options.f_mask= false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_mask == true);
	}
	{
		ARGC_ARGV("-M", "m", "localhost");

		options.f_mask= false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_mask == true);
	}
	{
		ARGC_ARGV("-M", "T", "localhost");

		options.f_time= false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_time == true);
	}
	{
		ARGC_ARGV("-M", "t", "localhost");

		options.f_time= false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_time == true);
	}
	{
		ARGC_ARGV("-M", "mt", "localhost");

		options.f_mask = false;
		options.f_time = false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_mask == true);
		ATF_REQUIRE(options.f_time == false);
	}
	{
		ARGC_ARGV("-M", "tm", "localhost");

		options.f_mask = false;
		options.f_time = false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_mask == false);
		ATF_REQUIRE(options.f_time == true);
	}
	{
		ARGC_ARGV("-M", "m", "-M", "t", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC_WITHOUT_HEAD(option_ttl);
ATF_TC_BODY(option_ttl, tc)
{
	{
		ARGC_ARGV("-m");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-m", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-m", "-1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-m", "0", "localhost");

		options.f_ttl = false;
		options.n_ttl = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_ttl == true);
		ATF_REQUIRE(options.n_ttl == 0);
	}
	{
		ARGC_ARGV("-m", "replaced_by_MAXTTL/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (MAXTTL / 2));
		options.f_ttl = false;
		options.n_ttl = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_ttl == true);
		ATF_REQUIRE(options.n_ttl == (MAXTTL / 2));
	}
	{
		ARGC_ARGV("-m", DEFINED_NUM_TO_STR(MAXTTL), "localhost");

		options.f_ttl = false;
		options.n_ttl = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_ttl == true);
		ATF_REQUIRE(options.n_ttl == MAXTTL);
	}
	{
		ARGC_ARGV("-m", "replaced_by_MAXTTL+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAXTTL) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-m", "replaced_by_MAXTTL+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAXTTL) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC_WITHOUT_HEAD(option_somewhat_quiet);
ATF_TC_BODY(option_somewhat_quiet, tc)
{
	ARGC_ARGV("-Q", "localhost");

	options.f_somewhat_quiet = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_somewhat_quiet == true);
}

ATF_TC_WITHOUT_HEAD(option_rroute);
ATF_TC_BODY(option_rroute, tc)
{
	ARGC_ARGV("-R", "localhost");

	options.f_rroute = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_rroute == true);
}

ATF_TC_WITHOUT_HEAD(option_so_dontroute);
ATF_TC_BODY(option_so_dontroute, tc)
{
	ARGC_ARGV("-r", "localhost");

	options.f_so_dontroute = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_so_dontroute == true);
}

ATF_TC_WITHOUT_HEAD(option_multicast_ttl);
ATF_TC_BODY(option_multicast_ttl, tc)
{
	{
		ARGC_ARGV("-T");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-T", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-T", "-1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-T", "0", "localhost");

		options.f_multicast_ttl = false;
		options.n_multicast_ttl = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_multicast_ttl == true);
		ATF_REQUIRE(options.n_multicast_ttl == 0);
	}
	{
		ARGC_ARGV("-T", "replaced_by_MAXTTL/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (MAXTTL / 2));
		options.f_multicast_ttl = false;
		options.n_multicast_ttl = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_multicast_ttl == true);
		ATF_REQUIRE(options.n_multicast_ttl == (MAXTTL / 2));
	}
	{
		ARGC_ARGV("-T", DEFINED_NUM_TO_STR(MAXTTL), "localhost");

		options.f_multicast_ttl = false;
		options.n_multicast_ttl = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_multicast_ttl == true);
		ATF_REQUIRE(options.n_multicast_ttl == MAXTTL);
	}
	{
		ARGC_ARGV("-T", "replaced_by_MAXTTL+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAXTTL) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-T", "replaced_by_MAXTTL+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAXTTL) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC_WITHOUT_HEAD(option_tos);
ATF_TC_BODY(option_tos, tc)
{
	{
		ARGC_ARGV("-z");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-z", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-z", "-1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-z", "0", "localhost");

		options.f_tos = false;
		options.n_tos = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_tos == true);
		ATF_REQUIRE(options.n_tos == 0);
	}
	{
		ARGC_ARGV("-z", "replaced_by_MAX_TOS/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (MAX_TOS / 2));
		options.f_tos = false;
		options.n_tos = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_tos == true);
		ATF_REQUIRE(options.n_tos == (MAX_TOS / 2));
	}
	{
		ARGC_ARGV("-z", DEFINED_NUM_TO_STR(MAX_TOS), "localhost");

		options.f_tos = false;
		options.n_tos = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_tos == true);
		ATF_REQUIRE(options.n_tos == MAX_TOS);
	}
	{
		ARGC_ARGV("-z", "replaced_by_MAX_TOS+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAX_TOS) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-z", "replaced_by_MAX_TOS+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAX_TOS) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

#ifdef INET6
ATF_TC_WITHOUT_HEAD(option_protocol_ipv6);
ATF_TC_BODY(option_protocol_ipv6, tc)
{
	ARGC_ARGV("-6", "localhost");

	options.f_protocol_ipv6 = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_protocol_ipv6 == true);
}

ATF_TC_WITHOUT_HEAD(option_sock_buf_size);
ATF_TC_BODY(option_sock_buf_size, tc)
{
#if defined(SO_SNDBUF) && defined(SO_RCVBUF)
	{
		ARGC_ARGV("-b");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-b", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-b", "-1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-b", "0", "localhost");

		options.f_sock_buff_size = false;
		options.n_sock_buff_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sock_buff_size == true);
		ATF_REQUIRE(options.n_sock_buff_size == 0);
	}
	{
		ARGC_ARGV("-b", "replaced_by_INT_MAX/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (INT_MAX / 2));
		options.f_sock_buff_size = false;
		options.n_sock_buff_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sock_buff_size == true);
		ATF_REQUIRE(options.n_sock_buff_size == (INT_MAX / 2));
	}
	{
		ARGC_ARGV("-b", DEFINED_NUM_TO_STR(INT_MAX), "localhost");
		options.f_sock_buff_size = false;
		options.n_sock_buff_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sock_buff_size == true);
		ATF_REQUIRE(options.n_sock_buff_size == INT_MAX);
	}
	{
		ARGC_ARGV("-b", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-b", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
#else /* !SO_SNDBUF || !SO_RCVBUF */
	{
		ARGC_ARGV("-b", "0", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
#endif /* SO_SNDBUF && SO_RCVBUF */
}

ATF_TC_WITHOUT_HEAD(option_gateway);
ATF_TC_BODY(option_gateway, tc)
{
	{
		ARGC_ARGV("-e");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-e", "gateway1234", "localhost");

		options.s_gateway = NULL;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("gateway1234", options.s_gateway);
	}
}

ATF_TC_WITHOUT_HEAD(option_hoplimit);
ATF_TC_BODY(option_hoplimit, tc)
{
	{
		ARGC_ARGV("-j");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-j", "-1000", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-j", "-1", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-j", "0", "localhost");

		options.f_hoplimit = false;
		options.n_hoplimit = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_hoplimit == true);
		ATF_REQUIRE(options.n_hoplimit == 0);
	}
	{
		ARGC_ARGV("-j", "replaced_by_MAX_HOPLIMIT/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, (unsigned long) (MAX_HOPLIMIT / 2));
		options.f_hoplimit = false;
		options.n_hoplimit = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_hoplimit == true);
		ATF_REQUIRE(options.n_hoplimit == (MAX_HOPLIMIT / 2));
	}
	{
		ARGC_ARGV("-j", DEFINED_NUM_TO_STR(MAX_HOPLIMIT), "localhost");

		options.f_hoplimit = false;
		options.n_hoplimit = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_hoplimit == true);
		ATF_REQUIRE(options.n_hoplimit == MAX_HOPLIMIT);
	}
	{
		ARGC_ARGV("-j", "replaced_by_MAX_HOPLIMIT+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAX_HOPLIMIT) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-j", "replaced_by_MAX_HOPLIMIT+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv, 2, ((unsigned long) MAX_HOPLIMIT) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC_WITHOUT_HEAD(option_nodeaddr);
ATF_TC_BODY(option_nodeaddr, tc)
{
	{
		ARGC_ARGV("-k");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-k", "aclsgX", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-k", "", "localhost");

		options.f_fqdn = true;
		options.f_fqdn_old = true;
		options.f_subtypes = true;
		options.f_nodeaddr = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_fqdn == false);
		ATF_REQUIRE(options.f_fqdn_old == false);
		ATF_REQUIRE(options.f_subtypes == false);
		ATF_REQUIRE(options.f_nodeaddr == true);
	}
	{
		ARGC_ARGV("-k", "a", "localhost");

		options.f_nodeaddr_flag_all = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_all == true);
	}
	{
		ARGC_ARGV("-k", "c", "localhost");

		options.f_nodeaddr_flag_compat = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_compat == true);
	}
	{
		ARGC_ARGV("-k", "C", "localhost");

		options.f_nodeaddr_flag_compat = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_compat == true);
	}
	{
		ARGC_ARGV("-k", "l", "localhost");

		options.f_nodeaddr_flag_linklocal = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_linklocal == true);
	}
	{
		ARGC_ARGV("-k", "L", "localhost");

		options.f_nodeaddr_flag_linklocal = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_linklocal == true);
	}
	{
		ARGC_ARGV("-k", "s", "localhost");

		options.f_nodeaddr_flag_sitelocal = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_sitelocal == true);
	}
	{
		ARGC_ARGV("-k", "S", "localhost");

		options.f_nodeaddr_flag_sitelocal = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_sitelocal == true);
	}
	{
		ARGC_ARGV("-k", "g", "localhost");

		options.f_nodeaddr_flag_global = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_global == true);
	}
	{
		ARGC_ARGV("-k", "G", "localhost");

		options.f_nodeaddr_flag_global = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_global == true);
	}
	{
		ARGC_ARGV("-k", "A", "localhost");

#ifdef NI_NODEADDR_FLAG_ANYCAST
		options.f_nodeaddr_flag_anycast = false;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_anycast == true);
#else
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
#endif /* NI_NODEADDR_FLAG_ANYCAST */
	}
	{
#ifdef NI_NODEADDR_FLAG_ANYCAST
		char *const k_arg = "acClLsSgGA";
#else
		char *const k_arg = "acClLsSgG";
#endif
		ARGC_ARGV("-k", k_arg, "localhost");

		options.f_nodeaddr_flag_all = false;
		options.f_nodeaddr_flag_compat = false;
		options.f_nodeaddr_flag_linklocal = false;
		options.f_nodeaddr_flag_sitelocal = false;
		options.f_nodeaddr_flag_global = false;
#ifdef NI_NODEADDR_FLAG_ANYCAST
		options.f_nodeaddr_flag_anycast = false;
#endif
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nodeaddr_flag_all == true);
		ATF_REQUIRE(options.f_nodeaddr_flag_compat == true);
		ATF_REQUIRE(options.f_nodeaddr_flag_linklocal == true);
		ATF_REQUIRE(options.f_nodeaddr_flag_sitelocal == true);
		ATF_REQUIRE(options.f_nodeaddr_flag_global == true);
#ifdef NI_NODEADDR_FLAG_ANYCAST
		ATF_REQUIRE(options.f_nodeaddr_flag_anycast == true);
#endif
	}
}

ATF_TC_WITHOUT_HEAD(option_nigroup);
ATF_TC_BODY(option_nigroup, tc)
{
	{
		ARGC_ARGV("localhost");

		options.f_nigroup = true;
		options.c_nigroup = -123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nigroup == false);
		ATF_REQUIRE(options.c_nigroup == -1);
	}
	{
		ARGC_ARGV("-N", "localhost");

		options.f_nigroup = false;
		options.c_nigroup = 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nigroup == true);
		/* Default value of c_nigroup is -1 and every -N
		 * increments it. */
		ATF_REQUIRE(options.c_nigroup == 0);
	}
	{
		ARGC_ARGV("-N", "-N" ,"localhost");

		options.f_nigroup = false;
		options.c_nigroup = 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nigroup == true);
		ATF_REQUIRE(options.c_nigroup == 1);
	}
	{
		ARGC_ARGV("-N", "-N", "-N", "-N", "-N", "-N", "-N", "localhost");

		options.f_nigroup = false;
		options.c_nigroup = 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nigroup == true);
		ATF_REQUIRE(options.c_nigroup == 6);
	}
}

ATF_TC_WITHOUT_HEAD(option_use_min_mtu);
ATF_TC_BODY(option_use_min_mtu, tc)
{
#ifdef IPV6_USE_MIN_MTU
	{
		ARGC_ARGV("-u", "localhost");

		options.c_use_min_mtu = 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.c_use_min_mtu == 1);
	}
	{
		ARGC_ARGV("-u", "-u", "localhost");

		options.c_use_min_mtu = 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.c_use_min_mtu == 2);
	}
	{
		ARGC_ARGV("-u", "-u", "-u", "-u", "-u", "-u", "-u", "localhost");

		options.c_use_min_mtu = 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.c_use_min_mtu == 7);
	}
#else /* !IPV6_USE_MIN_MTU */
	{
		ARGC_ARGV("-u", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
#endif /* IPV6_USE_MIN_MTU */
}


ATF_TC_WITHOUT_HEAD(option_fqdn);
ATF_TC_BODY(option_fqdn, tc)
{
	ARGC_ARGV("-w", "localhost");

	options.f_nodeaddr = true;
	options.f_fqdn_old = true;
	options.f_subtypes = true;
	options.f_fqdn = false;

	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_nodeaddr == false);
	ATF_REQUIRE(options.f_fqdn_old == false);
	ATF_REQUIRE(options.f_subtypes == false);
	ATF_REQUIRE(options.f_fqdn == true);
}

ATF_TC_WITHOUT_HEAD(option_fqdn_old);
ATF_TC_BODY(option_fqdn_old, tc)
{
	ARGC_ARGV("-Y", "localhost");

	options.f_nodeaddr = true;
	options.f_fqdn_old = false;
	options.f_subtypes = true;
	options.f_fqdn = true;

	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_nodeaddr == false);
	ATF_REQUIRE(options.f_fqdn_old == true);
	ATF_REQUIRE(options.f_subtypes == false);
	ATF_REQUIRE(options.f_fqdn == false);
}

ATF_TC_WITHOUT_HEAD(option_subtypes);
ATF_TC_BODY(option_subtypes, tc)
{
	ARGC_ARGV("-y", "localhost");

	options.f_nodeaddr = true;
	options.f_fqdn_old = true;
	options.f_subtypes = false;
	options.f_fqdn = true;

	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_nodeaddr == false);
	ATF_REQUIRE(options.f_fqdn_old == false);
	ATF_REQUIRE(options.f_subtypes == true);
	ATF_REQUIRE(options.f_fqdn == false);
}
#endif /* INET6 */

#ifdef IPSEC
ATF_TC_WITHOUT_HEAD(option_policy);
ATF_TC_BODY(option_policy, tc)
{
	{
		ARGC_ARGV("-P");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-P", "unknown", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-P", "in_policy_1", "-P", "in_policy_2", "localhost");

		options.f_policy = false;
		options.s_policy_in = NULL;
		options.s_policy_out = NULL;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_policy == true);
		ATF_REQUIRE_STREQ("in_policy_2", options.s_policy_in);
		ATF_REQUIRE(options.s_policy_out == NULL);
	}
	{
		ARGC_ARGV("-P", "out_policy_1", "-P", "out_policy_2", "localhost");

		options.f_policy = false;
		options.s_policy_in = NULL;
		options.s_policy_out = NULL;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_policy == true);
		ATF_REQUIRE(options.s_policy_in == NULL);
		ATF_REQUIRE_STREQ("out_policy_2", options.s_policy_out);

	}
	{
		ARGC_ARGV("-P", "in_policy", "-P", "out_policy", "localhost");

		options.f_policy = false;
		options.s_policy_in = NULL;
		options.s_policy_out = NULL;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_policy == true);
		ATF_REQUIRE_STREQ("in_policy", options.s_policy_in);
		ATF_REQUIRE_STREQ("out_policy", options.s_policy_out);
	}
}
#if defined(INET6) && !defined(IPSEC_POLICY_IPSEC)
ATF_TC_WITHOUT_HEAD(option_authhdd);
ATF_TC_BODY(option_authhdr, tc)
{
	ARGC_ARGV("-Z", "localhost");

	options.f_authhdr = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_authhdr == true);
}

ATF_TC_WITHOUT_HEAD(option_encrypt);
ATF_TC_BODY(option_encrypt, tc)
{
	ARGC_ARGV("-E", "localhost");

	options.f_encrypt = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_encrypt == true);
}
#endif /* INET6 && IPSEC_POLICY_IPSEC */
#endif /* IPSEC */

/*
 * Main.
 */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, parse_hosts);
#ifdef INET6
	ATF_TP_ADD_TC(tp, compatibility_options_target);
#endif
	ATF_TP_ADD_TC(tp, options_no);
	ATF_TP_ADD_TC(tp, option_missed);
	ATF_TP_ADD_TC(tp, option_audible);
	ATF_TP_ADD_TC(tp, option_count);
	ATF_TP_ADD_TC(tp, option_dont_fragment);
	ATF_TP_ADD_TC(tp, option_so_debug);
	ATF_TP_ADD_TC(tp, option_flood);
	ATF_TP_ADD_TC(tp, privileged_option_flood);
	ATF_TP_ADD_TC(tp, unprivileged_option_flood);
	ATF_TP_ADD_TC(tp, option_interface);
	ATF_TP_ADD_TC(tp, option_interval);
	ATF_TP_ADD_TC(tp, privileged_option_interval);
	ATF_TP_ADD_TC(tp, unprivileged_option_interval);
	ATF_TP_ADD_TC(tp, option_preload);
	ATF_TP_ADD_TC(tp, privileged_option_preload);
	ATF_TP_ADD_TC(tp, unprivileged_option_preload);
	ATF_TP_ADD_TC(tp, option_numeric);
	ATF_TP_ADD_TC(tp, option_once);
	ATF_TP_ADD_TC(tp, option_ping_filled);
	ATF_TP_ADD_TC(tp, option_quiet);
	ATF_TP_ADD_TC(tp, option_source);
	ATF_TP_ADD_TC(tp, option_packet_size);
	ATF_TP_ADD_TC(tp, privileged_option_packet_size);
	ATF_TP_ADD_TC(tp, unprivileged_option_packet_size);
	ATF_TP_ADD_TC(tp, option_timeout);
	ATF_TP_ADD_TC(tp, option_verbose);
	ATF_TP_ADD_TC(tp, option_wait_time);
	ATF_TP_ADD_TC(tp, option_protocol_ipv4);
	ATF_TP_ADD_TC(tp, option_sweep_max);
	ATF_TP_ADD_TC(tp, privileged_option_sweep_max);
	ATF_TP_ADD_TC(tp, unprivileged_option_sweep_max);
	ATF_TP_ADD_TC(tp, option_sweep_min);
	ATF_TP_ADD_TC(tp, privileged_option_sweep_min);
	ATF_TP_ADD_TC(tp, unprivileged_option_sweep_min);
	ATF_TP_ADD_TC(tp, option_sweep_incr);
	ATF_TP_ADD_TC(tp, privileged_option_sweep_incr);
	ATF_TP_ADD_TC(tp, unprivileged_option_sweep_incr);
	ATF_TP_ADD_TC(tp, option_no_loop);
	ATF_TP_ADD_TC(tp, option_mask_time);
	ATF_TP_ADD_TC(tp, option_ttl);
	ATF_TP_ADD_TC(tp, option_somewhat_quiet);
	ATF_TP_ADD_TC(tp, option_rroute);
	ATF_TP_ADD_TC(tp, option_so_dontroute);
	ATF_TP_ADD_TC(tp, option_multicast_ttl);
	ATF_TP_ADD_TC(tp, option_tos);

#ifdef INET6
	ATF_TP_ADD_TC(tp, option_protocol_ipv6);
	ATF_TP_ADD_TC(tp, option_sock_buf_size);
	ATF_TP_ADD_TC(tp, option_gateway);
	ATF_TP_ADD_TC(tp, option_hoplimit);
	ATF_TP_ADD_TC(tp, option_nodeaddr);
	ATF_TP_ADD_TC(tp, option_nigroup);
	ATF_TP_ADD_TC(tp, option_use_min_mtu);
	ATF_TP_ADD_TC(tp, option_fqdn);
	ATF_TP_ADD_TC(tp, option_fqdn_old);
	ATF_TP_ADD_TC(tp, option_subtypes);
#endif /* INET6 */

#ifdef IPSEC
	ATF_TP_ADD_TC(tp, option_policy);
#if defined(INET6) && !defined(IPSEC_POLICY_IPSEC)
	ATF_TP_ADD_TC(tp, option_authhdr);
	ATF_TP_ADD_TC(tp, option_encrypt);
#endif /* INET6 && IPSEC_POLICY_IPSEC */
#endif /* IPSEC */

	return (atf_no_error());
}
