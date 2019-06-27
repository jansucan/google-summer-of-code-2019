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

ATF_TC_WITHOUT_HEAD(option_missed);
ATF_TC_BODY(option_missed, tc)
{
	ARGC_ARGV("-A", "localhost");
	struct options options;

	options.f_missed = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_missed == true);
}

ATF_TC_WITHOUT_HEAD(option_audible);
ATF_TC_BODY(option_audible, tc)
{
	ARGC_ARGV("-a", "localhost");
	struct options options;

	options.f_audible = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_audible == true);
}

ATF_TC_WITHOUT_HEAD(option_count);
ATF_TC_BODY(option_count, tc)
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

ATF_TC_WITHOUT_HEAD(option_dont_fragment);
ATF_TC_BODY(option_dont_fragment, tc)
{
	ARGC_ARGV("-D", "localhost");
	struct options options;

	options.f_dont_fragment = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_dont_fragment == true);
}

ATF_TC_WITHOUT_HEAD(option_so_debug);
ATF_TC_BODY(option_so_debug, tc)
{
	ARGC_ARGV("-d", "localhost");
	struct options options;

	options.f_so_debug = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_so_debug == true);
}

ATF_TC_WITHOUT_HEAD(option_numeric);
ATF_TC_BODY(option_numeric, tc)
{
	ARGC_ARGV("-n", "localhost");
	struct options options;

	options.f_numeric = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_numeric == true);
}

ATF_TC_WITHOUT_HEAD(option_once);
ATF_TC_BODY(option_once, tc)
{
	ARGC_ARGV("-o", "localhost");
	struct options options;

	options.f_once = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_once == true);
}

ATF_TC_WITHOUT_HEAD(option_quiet);
ATF_TC_BODY(option_quiet, tc)
{
	ARGC_ARGV("-q", "localhost");
	struct options options;

	options.f_quiet = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_quiet == true);
}

ATF_TC_WITHOUT_HEAD(option_verbose);
ATF_TC_BODY(option_verbose, tc)
{
	ARGC_ARGV("-v", "localhost");
	struct options options;

	options.f_verbose = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_verbose == true);
}

ATF_TC_WITHOUT_HEAD(option_protocol_ipv4);
ATF_TC_BODY(option_protocol_ipv4, tc)
{
	ARGC_ARGV("-4", "localhost");
	struct options options;

	options.f_protocol_ipv4 = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_protocol_ipv4 == true);
}

ATF_TC_WITHOUT_HEAD(option_no_loop);
ATF_TC_BODY(option_no_loop, tc)
{
	ARGC_ARGV("-L", "localhost");
	struct options options;

	options.f_no_loop = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_no_loop == true);
}

ATF_TC_WITHOUT_HEAD(option_somewhat_quiet);
ATF_TC_BODY(option_somewhat_quiet, tc)
{
	ARGC_ARGV("-Q", "localhost");
	struct options options;

	options.f_somewhat_quiet = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_somewhat_quiet == true);
}

ATF_TC_WITHOUT_HEAD(option_rroute);
ATF_TC_BODY(option_rroute, tc)
{
	ARGC_ARGV("-R", "localhost");
	struct options options;

	options.f_rroute = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_rroute == true);
}

ATF_TC_WITHOUT_HEAD(option_so_dontroute);
ATF_TC_BODY(option_so_dontroute, tc)
{
	ARGC_ARGV("-r", "localhost");
	struct options options;

	options.f_so_dontroute = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_so_dontroute == true);
}

#ifdef INET6
ATF_TC_WITHOUT_HEAD(option_protocol_ipv6);
ATF_TC_BODY(option_protocol_ipv6, tc)
{
	ARGC_ARGV("-6", "localhost");
	struct options options;

	options.f_protocol_ipv6 = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_protocol_ipv6 == true);
}

ATF_TC_WITHOUT_HEAD(option_gateway);
ATF_TC_BODY(option_gateway, tc)
{
	ARGC_ARGV("-e", "gateway1234", "localhost");
	struct options options;

	options.s_gateway = NULL;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE_STREQ("gateway1234", options.s_gateway);
}

ATF_TC_WITHOUT_HEAD(option_nigroup);
ATF_TC_BODY(option_nigroup, tc)
{
	{
		ARGC_ARGV("-N", "localhost");
		struct options options;

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
		struct options options;

		options.f_nigroup = false;
		options.c_nigroup = 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.f_nigroup == true);
		ATF_REQUIRE(options.c_nigroup == 1);
	}
	{
		ARGC_ARGV("-N", "-N", "-N", "-N", "-N", "-N", "-N", "localhost");
		struct options options;

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
		struct options options;

		options.c_use_min_mtu = 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.c_use_min_mtu == 1);
	}
	{
		ARGC_ARGV("-u", "-u", "localhost");
		struct options options;

		options.c_use_min_mtu = 123;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE(options.c_use_min_mtu == 2);
	}
	{
		ARGC_ARGV("-u", "-u", "-u", "-u", "-u", "-u", "-u", "localhost");
		struct options options;

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
	struct options options;

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
	struct options options;

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
	struct options options;

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
		ARGC_ARGV("-P", "unknown", "localhost");
		struct options options;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-P", "in_policy_1", "-P", "in_policy_2", "localhost");
		struct options options;

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
		struct options options;

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
		struct options options;

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
	struct options options;

	options.f_authhdr = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
	ATF_REQUIRE(options.f_authhdr == true);
}

ATF_TC_WITHOUT_HEAD(option_encrypt);
ATF_TC_BODY(option_encrypt, tc)
{
	ARGC_ARGV("-E", "localhost");
	struct options options;

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
	ATF_TP_ADD_TC(tp, option_numeric);
	ATF_TP_ADD_TC(tp, option_once);
	ATF_TP_ADD_TC(tp, option_quiet);
	ATF_TP_ADD_TC(tp, option_verbose);
	ATF_TP_ADD_TC(tp, option_protocol_ipv4);
	ATF_TP_ADD_TC(tp, option_no_loop);
	ATF_TP_ADD_TC(tp, option_somewhat_quiet);
	ATF_TP_ADD_TC(tp, option_rroute);
	ATF_TP_ADD_TC(tp, option_so_dontroute);

#ifdef INET6
	ATF_TP_ADD_TC(tp, option_protocol_ipv6);
	ATF_TP_ADD_TC(tp, option_gateway);
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
