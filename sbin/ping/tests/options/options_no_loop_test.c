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

#include "../../options.h"

/*
 * Global variables.
 */

static cap_channel_t *capdns;
static struct options options;

/*
 * Test cases.
 */

ATF_TC_WITHOUT_HEAD(option_no_loop);
ATF_TC_BODY(option_no_loop, tc)
{
	{
		ARGC_ARGV("-L", "host_ipv4");
		capdns = capdns_setup();

		ATF_REQUIRE(options_parse(test_argc, test_argv, &options, capdns) == EX_USAGE);
		cap_close(capdns);
	}
	{
		ARGC_ARGV("-L", "multicast_ipv4");
		capdns = capdns_setup();

		options.f_no_loop = false;
		ATF_REQUIRE(options_parse(test_argc, test_argv, &options, capdns) == EX_OK);
		ATF_REQUIRE(options.f_no_loop == true);
		cap_close(capdns);
	}
}

/*
 * Main.
 */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, option_no_loop);

	return (atf_no_error());
}
