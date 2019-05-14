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

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "options.h"

#define OPSTR_COMMON        "Aac:DdfI:i:l:nop:qS:s:v"
#define OPSTR_IPV4          "4G:g:h:LM:m:QRrT:t:W:z:"
#define OPSTR_IPV6          "6b:e:Hj:k:Nuwx:X:Yy"
#define OPSTR_IPSEC_COMMON  "P:"

#ifdef IPSEC
#if defined(INET6) && !defined(IPSEC_POLICY_IPSEC)
#define OPSTR_IPSEC   OPSTR_IPSEC_COMMON "ZE"
#else  /* !INET6 || IPSEC_POLICY_IPSEC */
#define OPSTR_IPSEC   OPSTR_IPSEC_COMMON
#endif /* INET6 && IPSEC_POLICY_IPSEC */
#else  /* !IPSEC  */
#define OPSTR_IPSEC   ""
#endif  /* IPSEC */

#ifdef INET6
#define OPSTR  OPSTR_COMMON OPSTR_IPV4 OPSTR_IPV6 OPSTR_IPSEC
#else  /* !INET6 */
#define OPSTR  OPSTR_COMMON OPSTR_IPV4 OPSTR_IPSEC
#endif	/* INET6 */

static bool options_process_common(int opt, struct options *const options);
static bool options_process_ipv4(int opt, struct options *const options);
static bool options_process_ipv6(int opt, struct options *const options);
static bool options_process_ipsec(int opt, struct options *const options);

void
options_parse(int *const argc, char **argv, struct options *const options)
{
	int ch;

	memset(options, 0, sizeof(*options));
	
	while ((ch = getopt(*argc, argv, OPSTR)) != -1) {
		const bool opt_ipv4 = options_process_ipv4(ch, options);
#ifdef INET6	
		const bool opt_ipv6 = options_process_ipv6(ch, options);
#endif

		if (!options_process_common(ch, options) &&
#ifdef INET6
		    !opt_ipv6 &&
#endif
#ifdef IPSEC
		    !options_process_ipsec(ch, options) &&
#endif
		    !opt_ipv4) {
			usage();
			/* NOTREACHED */
		}
#ifdef INET6
		if (options->f_protocol_ipv6 && opt_ipv4)
			errx(EX_USAGE, "IPv6 requested but IPv4 option provided");
		else if (options->f_protocol_ipv4 && opt_ipv6)
			errx(EX_USAGE, "IPv4 requested but IPv6 option provided");
#endif /* INET6 */
	}

#ifdef INET6
	if (options->f_protocol_ipv4 && options->f_protocol_ipv6)
		errx(EX_USAGE, "-4 and -6 cannot be used together");
#endif

	*argc -= optind;
	argv += optind;
}

static bool
options_process_common(int opt, struct options *const options)
{
	switch (opt) {
	case 'A':
		options->f_missed = true;
		break;
	case 'a':
		options->f_audible = true;
		break;
	case 'c':
		break;
	case 'D':
		options->f_dont_fragment = true;
		break;
	case 'd':
		options->f_so_debug = true;
		break;
	case 'f':
		break;
	case 'I':
		break;
	case 'i':
		break;
	case 'l':
		break;
	case 'n':
		options->f_numeric = true;
		break;
	case 'o':
		options->f_once = true;
		break;
	case 'p':
		break;
	case 'q':
		options->f_somewhat_quiet = true;
		break;
	case 'S':
		options->s_source = optarg;
		break;
	case 's':
		options->f_ping_filled = true;
		options->s_ping_filled = optarg;
		break;
	case 'v':
		options->f_verbose = true;
		break;
	default:
		return false;
	}

	return true;
}

static bool
options_process_ipv4(int opt, struct options *const options)
{
	switch (opt) {
	case '4':
		options->f_protocol_ipv4 = true;
		break;
	case 'G':
		break;
	case 'g':
		break;
	case 'h':
		break;
	case 'L':
		options->f_no_loop = true;
		break;
	case 'M':
		switch(optarg[0]) {
		case 'M':
		case 'm':
			options->f_mask;
			break;
		case 'T':
		case 't':
			options->f_mask;
			break;
		default:
			errx(EX_USAGE, "invalid message: `%c'", optarg[0]);
			break;
		}
		break;
	case 'm':
		break;
	case 'Q':
		options->f_quiet = true;
		break;
	case 'R':
		options->f_rroute = true;
		break;
	case 'r':
		options->f_so_dontroute = true;
		break;
	case 'T':
		break;
	case 't':
		break;
	case 'W':
		break;
	case 'z':
		break;
	default:
		return false;
	}

	return true;
}

#ifdef INET6
static bool
options_process_ipv6(int opt, struct options *const options)
{
	switch (opt) {
	case '6':
		options->f_protocol_ipv6 = true;
		break;
	case 'b':
		break;
	case 'e':
		break;
	case 'H':
		break;
	case 'j':
		break;
	case 'k':
		break;
	case 'N':
		break;
	case 'u':
		break;
	case 'w':
		break;
	case 'x':
		break;
	case 'X':
		break;
	case 'Y':
		break;
	case 'y':
		break;
	default:
		return false;
	}

	return true;
}
#endif /* INET6 */

#ifdef IPSEC
static bool
options_process_ipsec(int opt, struct options *const options)
{
	switch (opt) {
	case 'P':
		break;
#if defined(INET6) && !defined(IPSEC_POLICY_IPSEC)
	case 'Z':
		break;
	case 'E':
		break;
#endif /* INET6 && IPSEC_POLICY_IPSEC */
	default:
		return false;
	}

	return true;
}
#endif /* IPSEC */

void
usage(void)
{
	/* TODO */
	exit(EX_USAGE);
}
