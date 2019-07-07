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
#include <sysexits.h>

#include "getaddrinfo.h"
#include "test_argc_argv.h"

#include "../options.h"

/*
 * Global variables.
 */

static struct options options;

/*
 * Test cases.
 */

ATF_TC_WITHOUT_HEAD(target);
ATF_TC_BODY(target, tc)
{
	{
		ARGC_ARGV("target_unknown");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOHOST);
	}
	{
		ARGC_ARGV("target_ipv4");
		options.target = NULL;
		options.target_addrinfo = NULL;
		options.target_type = TARGET_UNKNOWN;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("target_ipv4", options.target);
		ATF_REQUIRE(options.target_addrinfo != NULL);
		ATF_REQUIRE(options.target_addrinfo->ai_family == AF_INET);
		ATF_REQUIRE(options.target_type == TARGET_HOSTNAME_IPV4);
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
		ATF_REQUIRE(options.target_type == TARGET_HOSTNAME_IPV4);
	}
	{
		ARGC_ARGV("-4", "target_ipv4");
		options.target = NULL;
		options.target_addrinfo = NULL;
		options.target_type = TARGET_UNKNOWN;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("target_ipv4", options.target);
		ATF_REQUIRE(options.target_addrinfo != NULL);
		ATF_REQUIRE(options.target_addrinfo->ai_family == AF_INET);
		ATF_REQUIRE(options.target_type == TARGET_HOSTNAME_IPV4);
	}
#ifdef INET6
	{
		ARGC_ARGV("-6", "-G", "localhost");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-4", "-e", "localhost");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("target_ipv6");
		options.target = NULL;
		options.target_addrinfo = NULL;
		options.target_type = TARGET_UNKNOWN;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("target_ipv6", options.target);
		ATF_REQUIRE(options.target_addrinfo != NULL);
		ATF_REQUIRE(options.target_addrinfo->ai_family == AF_INET6);
		ATF_REQUIRE(options.target_type == TARGET_HOSTNAME_IPV6);
	}
	{
		ARGC_ARGV("::1");
		options.target = NULL;
		options.target_addrinfo = NULL;
		options.target_type = TARGET_UNKNOWN;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("::1", options.target);
		ATF_REQUIRE(options.target_addrinfo != NULL);
		ATF_REQUIRE(options.target_addrinfo->ai_family == AF_INET6);
		ATF_REQUIRE(options.target_type == TARGET_HOSTNAME_IPV6);
	}
	{
		ARGC_ARGV("-6", "target_ipv6");
		options.target = NULL;
		options.target_addrinfo = NULL;
		options.target_type = TARGET_UNKNOWN;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);
		ATF_REQUIRE_STREQ("target_ipv6", options.target);
		ATF_REQUIRE(options.target_addrinfo != NULL);
		ATF_REQUIRE(options.target_addrinfo->ai_family == AF_INET6);
		ATF_REQUIRE(options.target_type == TARGET_HOSTNAME_IPV6);
	}
	{
		ARGC_ARGV("-4", "target_ipv6");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
	{
		ARGC_ARGV("-6", "target_ipv4");
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
#endif	/* IENT6 */
}

ATF_TC_WITHOUT_HEAD(hops);
ATF_TC_BODY(hops, tc)
{
 	{
		ARGC_ARGV("target_ipv4", "target_ipv4");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
#ifdef INET6
	{
		ARGC_ARGV("target_ipv6", "target_unknown", "target_ipv6");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_NOHOST);
	}
	{
		ARGC_ARGV("target_ipv6", "target_ipv4", "target_ipv6");

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_USAGE);
	}
 	{
		ARGC_ARGV("target_ipv6", "::1", "target_ipv6");
		options.hops = NULL;
		options.hops_addrinfo = NULL;
		options.hop_count = 0;

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options) == EX_OK);

		ATF_REQUIRE(options.hops != NULL);
		ATF_REQUIRE(options.hops_addrinfo != NULL);
		ATF_REQUIRE(options.hop_count == 2);

		ATF_REQUIRE_STREQ("target_ipv6", options.hops[0]);
		ATF_REQUIRE(options.hops_addrinfo[0] != NULL);
		ATF_REQUIRE(options.hops_addrinfo[0]->ai_family == AF_INET6);

		ATF_REQUIRE_STREQ("::1", options.hops[1]);
		ATF_REQUIRE(options.hops_addrinfo[1] != NULL);
		ATF_REQUIRE(options.hops_addrinfo[1]->ai_family == AF_INET6);
	}
#endif	/* INET6 */
}

/*
 * Main.
 */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, target);
	ATF_TP_ADD_TC(tp, hops);

	return (atf_no_error());
}
