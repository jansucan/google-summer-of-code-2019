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
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "../options.h"

/* TODO: this is duplicated from options.c */
#define MAX_ALARM      3600
#define	MAX_TOS		255

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

#define ARGV_SET_FROM_EXPR(argv, expr)		\
	const unsigned long ul = expr;		\
	char ul_str[64];			\
	sprintf(ul_str, "%lu", ul);		\
	argv = ul_str

/*
 * Global variables.
 */

static struct options options;

/*
 * Test cases.
 */

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

		options.n_packets = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.n_packets == 1);
	}
	{
		ARGC_ARGV("-c", "234567", "localhost");

		options.n_packets = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.n_packets == 234567);
	}
	{
		ARGC_ARGV("-c", DEFINED_NUM_TO_STR(LONG_MAX), "localhost");

		options.n_packets = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.n_packets == LONG_MAX);
	}
	{
		ARGC_ARGV("-c", "replaced_by_LONG_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) LONG_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-c", "replaced_by_LONG_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) LONG_MAX) + 1000);
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

ATF_TC_WITHOUT_HEAD(option_quiet);
ATF_TC_BODY(option_quiet, tc)
{
	ARGC_ARGV("-q", "localhost");

	options.f_quiet = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_quiet == true);
}

ATF_TC_WITHOUT_HEAD(option_alarm_timeout);
ATF_TC_BODY(option_alarm_timeout, tc)
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

		options.f_alarm_timeout = false;
		options.n_alarm_timeout = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_alarm_timeout == true);
		ATF_REQUIRE(options.n_alarm_timeout == 1);
	}
	{
		ARGC_ARGV("-t", "replaced_by_MAX_ALARM/2", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], (unsigned long) (MAX_ALARM / 2));
		options.f_alarm_timeout = false;
		options.n_alarm_timeout = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_alarm_timeout == true);
		ATF_REQUIRE(options.n_alarm_timeout == (MAX_ALARM / 2));
	}
	{
		ARGC_ARGV("-t", DEFINED_NUM_TO_STR(MAX_ALARM), "localhost");

		options.f_alarm_timeout = false;
		options.n_alarm_timeout = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_alarm_timeout == true);
		ATF_REQUIRE(options.n_alarm_timeout == MAX_ALARM);
	}
	{
		ARGC_ARGV("-t", "replaced_by_MAX_ALARM+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) MAX_ALARM) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-t", "replaced_by_MAX_ALARM+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) MAX_ALARM) + 1000);
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
		ARGC_ARGV("-G", "123456", "localhost");

		options.f_sweep_max = false;
		options.n_sweep_max = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_max == true);
		ATF_REQUIRE(options.n_sweep_max == 123456);
	}
	{
		ARGC_ARGV("-G", DEFINED_NUM_TO_STR(INT_MAX), "localhost");

		options.f_sweep_max = false;
		options.n_sweep_max = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_max == true);
		ATF_REQUIRE(options.n_sweep_max == INT_MAX);
	}
	{
		ARGC_ARGV("-G", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-G", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
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
		ARGC_ARGV("-g", "1", "-G", "1", "localhost");

		options.f_sweep_min = false;
		options.n_sweep_min = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_min == true);
		ATF_REQUIRE(options.n_sweep_min == 1);
	}
	{
		ARGC_ARGV("-g", "123456", "-G", "123456", "localhost");

		options.f_sweep_min = false;
		options.n_sweep_min = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_min == true);
		ATF_REQUIRE(options.n_sweep_min == 123456);
	}
	{
		ARGC_ARGV("-g", DEFINED_NUM_TO_STR(INT_MAX), "-G", DEFINED_NUM_TO_STR(INT_MAX), "localhost");

		options.f_sweep_min = false;
		options.n_sweep_min = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_min == true);
		ATF_REQUIRE(options.n_sweep_min == INT_MAX);
	}
	{
		ARGC_ARGV("-g", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-g", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
}

ATF_TC_WITHOUT_HEAD(option_sweep_incr);
ATF_TC_BODY(option_sweep_incr, tc)
{
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
		ARGC_ARGV("-h", "123456", "-G", "123456", "localhost");

		options.f_sweep_incr = false;
		options.n_sweep_incr = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_incr == true);
		ATF_REQUIRE(options.n_sweep_incr == 123456);
	}
	{
		ARGC_ARGV("-h", DEFINED_NUM_TO_STR(INT_MAX), "-G", DEFINED_NUM_TO_STR(INT_MAX), "localhost");

		options.f_sweep_incr = false;
		options.n_sweep_incr = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_sweep_incr == true);
		ATF_REQUIRE(options.n_sweep_incr == INT_MAX);
	}
	{
		ARGC_ARGV("-h", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-h", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
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

		ARGV_SET_FROM_EXPR(test_argv[2], (unsigned long) (MAXTTL / 2));
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

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) MAXTTL) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-m", "replaced_by_MAXTTL+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) MAXTTL) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
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

		ARGV_SET_FROM_EXPR(test_argv[2], (unsigned long) (MAXTTL / 2));
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

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) MAXTTL) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-T", "replaced_by_MAXTTL+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) MAXTTL) + 1000);
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

		ARGV_SET_FROM_EXPR(test_argv[2], (unsigned long) (MAX_TOS / 2));
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

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) MAX_TOS) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-z", "replaced_by_MAX_TOS+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) MAX_TOS) + 1000);
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

		options.n_sock_buff_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.n_sock_buff_size == 0);
	}
	{
		ARGC_ARGV("-b", "123456", "localhost");

		options.n_sock_buff_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.n_sock_buff_size == 123456);
	}
	{
		ARGC_ARGV("-b", DEFINED_NUM_TO_STR(INT_MAX), "localhost");

		options.n_sock_buff_size = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.n_sock_buff_size == INT_MAX);
	}
	{
		ARGC_ARGV("-b", "replaced_by_INT_MAX+1", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) INT_MAX) + 1);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-b", "replaced_by_INT_MAX+1000", "localhost");

		ARGV_SET_FROM_EXPR(test_argv[2], ((unsigned long) INT_MAX) + 1000);
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
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
		ARGC_ARGV("-j", "123", "localhost");

		options.f_hoplimit = false;
		options.n_hoplimit = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_hoplimit == true);
		ATF_REQUIRE(options.n_hoplimit == 123);
	}
	{
		ARGC_ARGV("-j", "255", "localhost");

		options.f_hoplimit = false;
		options.n_hoplimit = -1;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_hoplimit == true);
		ATF_REQUIRE(options.n_hoplimit == 255);
	}
	{
		ARGC_ARGV("-j", "256", "localhost");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-j", "1255", "localhost");

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

}

ATF_TC_WITHOUT_HEAD(option_nigroup);
ATF_TC_BODY(option_nigroup, tc)
{
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

#ifdef IPV6_USE_MIN_MTU
ATF_TC_WITHOUT_HEAD(option_use_min_mtu);
ATF_TC_BODY(option_use_min_mtu, tc)
{
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
}
#endif /* IPV6_USE_MIN_MTU */

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
	ATF_TP_ADD_TC(tp, options_no);
	ATF_TP_ADD_TC(tp, option_missed);
	ATF_TP_ADD_TC(tp, option_audible);
	ATF_TP_ADD_TC(tp, option_count);
	ATF_TP_ADD_TC(tp, option_dont_fragment);
	ATF_TP_ADD_TC(tp, option_so_debug);
	ATF_TP_ADD_TC(tp, option_interface);
	ATF_TP_ADD_TC(tp, option_numeric);
	ATF_TP_ADD_TC(tp, option_once);
	ATF_TP_ADD_TC(tp, option_quiet);
	ATF_TP_ADD_TC(tp, option_alarm_timeout);
	ATF_TP_ADD_TC(tp, option_verbose);
	ATF_TP_ADD_TC(tp, option_protocol_ipv4);
	ATF_TP_ADD_TC(tp, option_sweep_max);
	ATF_TP_ADD_TC(tp, option_sweep_min);
	ATF_TP_ADD_TC(tp, option_sweep_incr);
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
#ifdef IPV6_USE_MIN_MTU
	ATF_TP_ADD_TC(tp, option_use_min_mtu);
#endif /* IPV6_USE_MIN_MTU */
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
