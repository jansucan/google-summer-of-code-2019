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

#include "cap_getaddrinfo.h"
#include "test_argc_argv.h"

#include "../../options.h"

/*
 * Global variables.
 */

static cap_channel_t *capdns;
static struct options options;

/*
 * Test cases.
 */

ATF_TC_WITHOUT_HEAD(option_flood);
ATF_TC_BODY(option_flood, tc)
{
	ARGC_ARGV("-f", "-i", "1", "host_ipv4");
	capdns = capdns_setup();

	ATF_REQUIRE(options_parse(test_argc, test_argv, &options,
		capdns) == false);
	cap_close(capdns);
	options_free(&options);
}

ATF_TC(privileged_option_flood);
ATF_TC_HEAD(privileged_option_flood, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(privileged_option_flood, tc)
{
	{
		ARGC_ARGV("-f", "host_ipv4_ipv6");

		capdns = capdns_setup();

		options.f_flood = false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options,
			capdns) == true);
		ATF_REQUIRE(options.f_flood == true);
		cap_close(capdns);
		options_free(&options);
	}
#ifdef INET
	{
		ARGC_ARGV("-f", "multicast_ipv4");
		capdns = capdns_setup();

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options,
			capdns) == false);
		cap_close(capdns);
		options_free(&options);
	}
#endif
}

ATF_TC(unprivileged_option_flood);
ATF_TC_HEAD(unprivileged_option_flood, tc)
{
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(unprivileged_option_flood, tc)
{
	ARGC_ARGV("-f", "host_ipv4");
	capdns = capdns_setup();

	options.f_flood = false;
	ATF_REQUIRE(options_parse(test_argc, test_argv, &options,
		capdns) == false);
	ATF_REQUIRE(options.f_flood == true);
	cap_close(capdns);
	options_free(&options);
}

/*
 * Main.
 */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, option_flood);
	ATF_TP_ADD_TC(tp, privileged_option_flood);
	ATF_TP_ADD_TC(tp, unprivileged_option_flood);

	return (atf_no_error());
}
