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

#include "cap_getaddrinfo.h"
#include "test_argc_argv.h"

#include "../options.h"

/*
 * Global variables.
 */

static cap_channel_t *capdns;
static struct options options;

/*
 * Test cases.
 */

ATF_TC_WITHOUT_HEAD(option_source);
ATF_TC_BODY(option_source, tc)
{
	{
		ARGC_ARGV("-S", "host_unknown", "host_ipv4");
		capdns = capdns_setup();

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options, capdns) == EX_NOHOST);
		cap_close(capdns);
	}
	{
		ARGC_ARGV("-S", "host_ipv4", "host_ipv4");
		options.s_source[0] = '\0';
		options.source_sockaddr.in.sin_family = 0;
		options.source_sockaddr.in6.sin6_len = 0;
		capdns = capdns_setup();

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options, capdns) == EX_OK);
		ATF_REQUIRE_STREQ("host_ipv4", options.s_source);
		ATF_REQUIRE(options.source_sockaddr.in.sin_family == AF_INET);
		ATF_REQUIRE(options.source_sockaddr.in.sin_len == sizeof(struct sockaddr_in));
		cap_close(capdns);
	}
#ifdef INET6
	{
		ARGC_ARGV("-S", "host_ipv6", "host_ipv6");
		options.s_source[0] = '\0';
		options.source_sockaddr.in6.sin6_family = 0;
		options.source_sockaddr.in6.sin6_len = 0;
		capdns = capdns_setup();

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options, capdns) == EX_OK);
		ATF_REQUIRE_STREQ("host_ipv6", options.s_source);
		ATF_REQUIRE(options.source_sockaddr.in6.sin6_family == AF_INET6);
		ATF_REQUIRE(options.source_sockaddr.in6.sin6_len == sizeof(struct sockaddr_in6));
		cap_close(capdns);
	}
#endif	/* INET6 */
}

/*
 * Main.
 */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, option_source);

	return (atf_no_error());
}
