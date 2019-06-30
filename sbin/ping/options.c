
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
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "options.h"
#include "defaults_limits.h"

#define OPTIONS_STRTONUM_ERRBUF_SIZE 72

#define OPSTR_COMMON        "Aac:DdfI:i:l:nop:qS:s:t:vW:"
#define OPSTR_IPV4          "4G:g:h:LM:m:QRrT:z:"
#define OPSTR_IPV6          "6b:e:j:k:NuwYy"
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

static int  options_check(struct options *const options);
static int  options_check_packet_size(long, long);
static int  options_get_target_type(struct options *const options);
static int  options_getaddrinfo(const char *const hostname,
    const struct addrinfo *const hints, struct addrinfo **const res);
static bool options_has_ipv4_only(const struct options *const options);
#ifdef INET6
static bool options_has_ipv6_only(const struct options *const options);
#endif
static int  options_parse_hosts(int argc, char **argv, struct options *const options);
static void options_print_error(const char *const fmt, ...);
static void options_set_defaults(struct options *const options);
static bool options_strtod(const char *const str, double *const val);
static long long options_strtonum(const char *const str, long long minval,
    long long maxval, char *const errbuf);

void
options_free(struct options *const options)
{
	if (options->target_addrinfo != NULL) {
		freeaddrinfo(options->target_addrinfo);
		options->target_addrinfo = NULL;
	}

	if (options->hops_addrinfo != NULL) {
		for (unsigned i = 0; i < options->hop_count; ++i) {
			if (options->hops_addrinfo[i] != NULL)
				freeaddrinfo(options->hops_addrinfo[i]);
		}
		options->hop_count = 0;
		free(options->hops_addrinfo);
		options->hops_addrinfo = NULL;
	}
}

int
options_parse(int argc, char **argv, struct options *const options)
{
	int ch;
	double dbl, dbl_integer_part;
	char errbuf[OPTIONS_STRTONUM_ERRBUF_SIZE];

	memset(options, 0, sizeof(*options));

	while ((ch = getopt(argc, argv, OPSTR)) != -1) {
		switch (ch) {
		case 'A':
			options->f_missed = true;
			break;
		case 'a':
			options->f_audible = true;
			break;
		case 'c':
			options->n_packets = options_strtonum(optarg, 1, LONG_MAX, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid count of packets to transmit: `%s': %s",
				    optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_packets = true;
			break;
		case 'D':
			options->f_dont_fragment = true;
			break;
		case 'd':
			options->f_so_debug = true;
			break;
		case 'f':
			options->f_flood = true;
			break;
		case 'I':
			options->s_interface = optarg;
#if !defined(INET6) || !defined(USE_SIN6_SCOPE_ID)
			options->f_interface = true;
#endif
			break;
		case 'i':
			/*
			 * The interval is in seconds and may be
			 * fractional.
			 */
			if (!options_strtod(optarg, &dbl) || (dbl <= 0)) {
				options_print_error("invalid timing interval: `%s'", optarg);
				return (EX_USAGE);
			}
			/* 1 second = 1000 ms = 1000 * 1000 microseconds */
			options->n_interval.tv_usec = (suseconds_t) (modf(dbl, &dbl_integer_part) * 1000 * 1000);
			options->n_interval.tv_sec = (time_t) dbl_integer_part;
			options->f_interval = true;
			break;
		case 'l':
			options->n_preload = options_strtonum(optarg, 0, INT_MAX, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid preload value: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_preload = true;
			break;
		case 'n':
			options->f_numeric = true;
			break;
		case 'o':
			options->f_once = true;
			break;
		case 'p':
			options->f_ping_filled = true;
			for (const char *cp = optarg; *cp; cp++) {
				if (!isxdigit(*cp)) {
					options_print_error("patterns must be specified as hex digits");
					return (EX_USAGE);
				}
			}
			options->ping_filled_size = sscanf(optarg,
			    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
			    &options->a_ping_filled[0], &options->a_ping_filled[1],
			    &options->a_ping_filled[2], &options->a_ping_filled[3],
			    &options->a_ping_filled[4], &options->a_ping_filled[5],
			    &options->a_ping_filled[6], &options->a_ping_filled[7],
			    &options->a_ping_filled[8], &options->a_ping_filled[9],
			    &options->a_ping_filled[10], &options->a_ping_filled[11],
			    &options->a_ping_filled[12], &options->a_ping_filled[13],
			    &options->a_ping_filled[14], &options->a_ping_filled[15]);
			break;
		case 'q':
			options->f_quiet = true;
			break;
		case 'S':
			options->s_source = optarg;
			break;
		case 's':
			options->n_packet_size = options_strtonum(optarg, 1, LONG_MAX, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid packet size: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_packet_size = true;
			break;
		case 't':
			options->n_timeout = options_strtonum(optarg, 1, MAX_TIMEOUT, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid timeout: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_timeout = true;
			break;
		case 'v':
			options->f_verbose = true;
			break;
		case 'W':
			/* TODO: with 0 no packet will be printed */
			options->n_wait_time = options_strtonum(optarg, 0, INT_MAX, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid timing interval: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_wait_time = true;
			break;
			/* IPV4 options */
		case '4':
			options->f_protocol_ipv4 = true;
			break;
		case 'G':
			options->n_sweep_max = options_strtonum(optarg, 1, INT_MAX, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid packet size: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_sweep_max = true;
			break;
		case 'g':
			options->n_sweep_min = options_strtonum(optarg, 1, INT_MAX, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid packet size: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_sweep_min = true;
			break;
		case 'h':
			options->n_sweep_incr = options_strtonum(optarg, 1, INT_MAX, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid increment size: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_sweep_incr = true;
			break;
		case 'L':
			options->f_no_loop = true;
			break;
		case 'M':
			switch(optarg[0]) {
			case 'M':
			case 'm':
				options->f_mask = true;
				break;
			case 'T':
			case 't':
				options->f_time = true;
				break;
			default:
				options_print_error("invalid message: `%c'", optarg[0]);
				return (EX_USAGE);
			}
			break;
		case 'm':
			options->n_ttl = options_strtonum(optarg, 0, MAXTTL, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid TTL: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_ttl = true;
			break;
		case 'Q':
			options->f_somewhat_quiet = true;
			break;
		case 'R':
			options->f_rroute = true;
			break;
		case 'r':
			options->f_so_dontroute = true;
			break;
		case 'T':
			options->n_multicast_ttl = options_strtonum(optarg, 0, MAXTTL, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid multicast TTL: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_multicast_ttl = true;
			break;
		case 'z':
			options->n_tos = options_strtonum(optarg, 0, MAX_TOS, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid TOS: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_tos = true;
			break;
			/* IPv6 options */
#ifdef INET6
		case '6':
			options->f_protocol_ipv6 = true;
			break;
		case 'b':
#if defined(SO_SNDBUF) && defined(SO_RCVBUF)
			options->n_sock_buff_size = options_strtonum(optarg, 0, INT_MAX, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("invalid socket buffer size: `%s': %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_sock_buff_size = true;
#else
			options_print_error("-b option ignored: SO_SNDBUF/SO_RCVBUF socket options not supported");
			return (EX_USAGE);
#endif
			break;
		case 'e':
			options->s_gateway = optarg;
			break;
		case 'j':
			options->n_hoplimit = options_strtonum(optarg, 0, MAX_HOPLIMIT, errbuf);
			if (errbuf[0] != '\0') {
				options_print_error("illegal hoplimit %s: %s", optarg, errbuf);
				return (EX_USAGE);
			}
			options->f_hoplimit = true;
			break;
		case 'k':
			for (const char *cp = optarg; *cp != '\0'; cp++) {
				switch (*cp) {
				case 'a':
					options->f_nodeaddr_flag_all = true;
					break;
				case 'c':
				case 'C':
					options->f_nodeaddr_flag_compat = true;
					break;
				case 'l':
				case 'L':
					options->f_nodeaddr_flag_linklocal = true;
					break;
				case 's':
				case 'S':
					options->f_nodeaddr_flag_sitelocal = true;
					break;
				case 'g':
				case 'G':
					options->f_nodeaddr_flag_global = true;
					break;
				case 'A': /* experimental. not in the spec */
#ifdef NI_NODEADDR_FLAG_ANYCAST
					options->f_nodeaddr_flag_anycast = true;
					break;
#else
					options_print_error("-k A is not supported on the platform");
					return (EX_USAGE);
#endif
				default:
					usage();
					return (EX_USAGE);
				}
			}
			options->f_fqdn = false;
			options->f_fqdn_old = false;
			options->f_subtypes = false;
			options->f_nodeaddr = true;
			break;
		case 'N':
			options->f_nigroup = true;
			options->c_nigroup++;
			break;
		case 'u':
			/* TODO: should -u be recognized when it is not supported? */
#ifdef IPV6_USE_MIN_MTU
			options->c_use_min_mtu++;
#else
			options_print_error("-u is not supported on this platform");
			return (EX_USAGE);
#endif
			break;
		case 'w':
			options->f_nodeaddr = false;
			options->f_fqdn_old = false;
			options->f_subtypes = false;
			options->f_fqdn = true;
			break;
		case 'Y':
			options->f_nodeaddr = false;
			options->f_fqdn = false;
			options->f_subtypes = false;
			options->f_fqdn_old = true;
			break;
		case 'y':
			options->f_nodeaddr = false;
			options->f_fqdn = false;
			options->f_fqdn_old = false;
			options->f_subtypes = true;
			break;
#endif /* INET6 */
#ifdef IPSEC
		case 'P':
			/* TODO: Free strdup() allocated memory. */
			if (!strncmp("in", optarg, 2)) {
				if (options->s_policy_in != NULL)
					/*
					 * Setting another policy. Free the
					 * memory allocated by the previous
					 * strdup().
					 */
					free(options->s_policy_in);
				if ((options->s_policy_in = strdup(optarg)) == NULL) {
					options_print_error("strdup");
					return (EX_OSERR);
				}
			} else if (!strncmp("out", optarg, 3)) {
				if (options->s_policy_out != NULL)
					/*
					 * Setting another policy. Free the
					 * memory allocated by the previous
					 * strdup().
					 */
					free(options->s_policy_out);
				if ((options->s_policy_out = strdup(optarg)) == NULL) {
					options_print_error("strdup");
					return (EX_OSERR);
				}
			} else {
				options_print_error("invalid security policy");
				return (EX_USAGE);
			}
			options->f_policy = true;
			break;
#if defined(INET6) && !defined(IPSEC_POLICY_IPSEC)
		case 'Z':
			options->f_authhdr = true;
			break;
		case 'E':
			options->f_encrypt = true;
			break;
#endif /* INET6 && IPSEC_POLICY_IPSEC */
#endif /* IPSEC */
		default:
			usage();
			return (EX_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	const int r = options_parse_hosts(argc, argv, options);
	if (r != EX_OK)
		return (r);

	options_set_defaults(options);
	return (options_check(options));
}

static int
options_check(struct options *const options)
{
#ifdef INET6
	if (options->f_protocol_ipv6 && options_has_ipv4_only(options)) {
		options_print_error("IPv6 requested but IPv4 option provided");
		return (EX_USAGE);
	} else if (options->f_protocol_ipv4 && options_has_ipv6_only(options)) {
		options_print_error("IPv4 requested but IPv6 option provided");
		return (EX_USAGE);
	} else if (options->f_protocol_ipv4 && (options->target_type == TARGET_ADDRESS_IPV6)) {
		options_print_error("IPv4 requested but IPv6 target address provided");
		return (EX_USAGE);
	} else if (options->f_protocol_ipv6 && (options->target_type == TARGET_ADDRESS_IPV4)) {
		options_print_error("IPv6 requested but IPv4 target address provided");
		return (EX_USAGE);
	} else if (options->f_protocol_ipv4 && (options->target_type == TARGET_HOSTNAME_IPV6)) {
		options_print_error("IPv4 requested but the hostname has been resolved to IPv6");
		return (EX_USAGE);
	} else if (options->f_protocol_ipv6 && (options->target_type == TARGET_HOSTNAME_IPV4)) {
		options_print_error("IPv6 requested but the hostname has been resolved to IPv4");
		return (EX_USAGE);
	}
#endif
	/*
	 * Check options common to both IPv4 and IPv6 targets.
	 */
	if (options->f_flood && options->f_interval) {
		options_print_error("-f and -i are incompatible options");
		return (EX_USAGE);
	}
	if (options->f_flood && (getuid() != 0)) {
		options_print_error("Must be superuser to flood ping");
		return (EX_NOPERM);
	}
	/* Check interval between sending each packet. */
	if ((getuid() != 0) && (options->n_interval.tv_sec < 1)) {
		options_print_error("only root may use interval < 1s");
		return (EX_NOPERM);
	}
	/* The interval less than 1 microsecond does not make sense. */
	if (options->n_interval.tv_sec == 0 && options->n_interval.tv_usec < 1) {
		options->n_interval.tv_usec = 1;
		warnx("too small interval, raised to .000001");
	}

	if (options->f_packet_size) {
		if ((options->target_type == TARGET_ADDRESS_IPV4) ||
		    (options->target_type == TARGET_HOSTNAME_IPV4)) {
			const int r = options_check_packet_size(options->n_packet_size, DEFAULT_DATALEN_IPV4);
			if (r != EX_OK)
				return (r);
		} else if (options->n_packet_size > MAXDATALEN) {
			options_print_error("datalen value too large, maximum is %d", MAXDATALEN);
			return (EX_USAGE);
		}
	}

	/*
	 * Check options only for IPv4 target.
	 */
	if (options->f_mask && options->f_time) {
		options_print_error("ICMP_TSTAMP and ICMP_MASKREQ are exclusive");
		return (EX_USAGE);
	}
	if ((options->f_sweep_max || options->f_sweep_min || options->f_sweep_incr) &&
	    (options->n_sweep_max == 0)) {
		options_print_error("Maximum sweep size must be specified");
		return (EX_USAGE);
	}
	if (options->f_sweep_max) {
		if (options->n_sweep_min > options->n_sweep_max) {
			options_print_error("Maximum packet size must be no less than the minimum packet size");
			return (EX_USAGE);
		}
		if (options->f_packet_size) {
			options_print_error("Packet size and ping sweep are mutually exclusive");
			return (EX_USAGE);
		}
		const int r = options_check_packet_size(options->n_sweep_max, DEFAULT_DATALEN_IPV4);
		if (r != EX_OK)
			return (r);
	}
	if (options->f_sweep_min) {
		const int r = options_check_packet_size(options->n_sweep_min, DEFAULT_DATALEN_IPV4);
		if (r != EX_OK)
			return (r);
	}
	if (options->f_sweep_incr) {
		const int r = options_check_packet_size(options->n_sweep_incr, DEFAULT_DATALEN_IPV4);
		if (r != EX_OK)
			return (r);
	}

	if (options->f_preload) {
		if (getuid() != 0) {
			options_print_error("Must be superuser to preload");
			return (EX_NOPERM);
		}
	}

	return (EX_OK);
}

static int
options_check_packet_size(long size, long max_size)
{
	if ((getuid() != 0) && (size > max_size)) {
		options_print_error("packet size too large: %d > %u", size, max_size);
		return (EX_NOPERM);
	}
	return (EX_OK);
}

static int
options_get_target_type(struct options *const options)
{
	struct in_addr a;
#ifdef INET6
	struct in6_addr a6;
#endif
	struct addrinfo hints;
	bool is_address;

	options->target_type = TARGET_UNKNOWN;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	is_address = false;
	/* TODO: check for inet_pton() errors (retval -1) */
	if ((is_address = (inet_pton(AF_INET, options->target, &a) == 1)) ||
	    options->f_protocol_ipv4) {
		if (is_address)
			options->target_type = TARGET_ADDRESS_IPV4;
		hints.ai_family = AF_INET;
	}
#ifdef INET6
	else if ((is_address = (inet_pton(AF_INET6, options->target, &a6) == 1)) ||
	    options->f_protocol_ipv6) {
		if (is_address)
			options->target_type = TARGET_ADDRESS_IPV6;
		hints.ai_flags = AI_CANONNAME;
		hints.ai_family = AF_INET6;
		hints.ai_protocol = IPPROTO_ICMPV6;
	}
#endif
	const int r = options_getaddrinfo(options->target, &hints, &options->target_addrinfo);
	if (r != EX_OK)
		return (r);

	if (!is_address) {
		if (options->target_addrinfo->ai_family == AF_INET)
			options->target_type = TARGET_HOSTNAME_IPV4;
#ifdef INET6
		else if (options->target_addrinfo->ai_family == AF_INET6)
			options->target_type = TARGET_HOSTNAME_IPV6;
#endif
	}

	return (EX_OK);
}

static int
options_getaddrinfo(const char *const hostname, const struct addrinfo *const hints,
    struct addrinfo **const res)
{
	const int r = getaddrinfo(hostname, NULL, hints, res);
	if (r != 0) {
		options_print_error("getaddrinfo for `%s': %s", hostname, gai_strerror(r));
		/* TODO: Which sysexits(3) code to use? */
		return (1);
	} else if (res == NULL) {
		options_print_error("getaddrinfo for `%s'", hostname);
		return (1);
	}
	return (EX_OK);
}

static int
options_parse_hosts(int argc, char **argv, struct options *const options)
{
	/* The last argument is a target. */
	if (argc == 0) {
		usage();
		return (EX_USAGE);
	}

	options->target = argv[argc - 1];
	const int r = options_get_target_type(options);
	if (r != EX_OK)
		return (r);

	if (options->target_type == TARGET_UNKNOWN) {
		options_print_error("invalid ping target: `%s'", options->target);
		return (EX_USAGE);
	}

	--argc;
	++argv;

	/* Everything else are IPv6 hops. */
	if (argc != 0) {
		/* Ping to IPv4 host cannot have any hops specified. */
		if ((options->target_type == TARGET_ADDRESS_IPV4) ||
		    (options->target_type == TARGET_HOSTNAME_IPV4)) {
			usage();
			return (EX_USAGE);
		}

		options->hop_count = argc;
		options->hops = malloc(argc * sizeof(char *));
		options->hops_addrinfo = malloc(argc * sizeof(struct addrinfo *));

		for (int i = 0; i < argc; ++i) {
			struct addrinfo hints;

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET6;

			const int r = options_getaddrinfo(argv[i], &hints, &(options->hops_addrinfo[i]));
			if (r != EX_OK)
				return (r);

			if (options->hops_addrinfo[i]->ai_addr->sa_family != AF_INET6) {
				options_print_error("bad addr family of an intermediate addr");
				return (1);
			}
		}
	}

	return (EX_OK);
}

static void
options_print_error(const char *const fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ping: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	fflush(stderr);
}

static void
options_set_defaults(struct options *const options)
{
	if (!options->f_sweep_incr)
		options->n_sweep_incr = DEFAULT_SWEEP_INCR;
	if (!options->f_interval) {
		options->n_interval.tv_sec = DEFAULT_INTERVAL_TV_SEC;
		options->n_interval.tv_usec = DEFAULT_INTERVAL_TV_USEC;
	}
	if (!options->f_wait_time)
		options->n_wait_time = DEFAULT_WAIT_TIME;
	if (!options->f_packet_size) {
		if ((options->target_type == TARGET_ADDRESS_IPV4) ||
		    (options->target_type == TARGET_HOSTNAME_IPV4))
			options->n_packet_size = DEFAULT_DATALEN_IPV4;
		else
			options->n_packet_size = DEFAULT_DATALEN_IPV6;
	}
	/*
	 * Default value is -1. By the memset(options, ...) it is
	 * initialized to 0 and every -N option increments it. Thus,
	 * by subtracting -1 we get the correct value for both cases
	 * (default and non-default).
	 */
	options->c_nigroup -= 1;
}

static bool
options_strtod(const char *const str, double *const val)
{
	char *ep;

	*val = strtod(str, &ep);

	return (!((*val == 0) && (errno == EINVAL)) &&
	    !(((*val == HUGE_VAL) || (*val == -HUGE_VAL)) && (errno == ERANGE)) &&
	    (*ep == '\0' && *str != '\0'));
}

static long long
options_strtonum(const char *const str, long long minval,
    long long maxval, char *const errbuf)
{
	assert(minval <= maxval);

	char *ep;
	const long long val = strtoll(str, &ep, 0);

	errbuf[0] = '\0';

	if (!(*str != '\0' && *ep == '\0'))
		sprintf(errbuf, "invalid character `%c'", *ep);
	else if	(val == 0 && errno == EINVAL)
		sprintf(errbuf, "invalid");
	else if	((val == LLONG_MIN && errno == ERANGE) || val < minval)
		sprintf(errbuf, "too small, outside range [%lld, %lld]",
		    minval, maxval);
	else if	((val == LLONG_MAX && errno == ERANGE) || val > maxval)
		sprintf(errbuf, "too large, outside range [%lld, %lld]",
		    minval, maxval);

	return (val);
}

#ifdef INET6
static bool
options_has_ipv4_only(const struct options *const options)
{
	return (options->f_protocol_ipv4 ||
	    options->f_sweep_max ||
	    options->f_sweep_min ||
	    options->f_sweep_incr ||
	    options->f_no_loop ||
	    options->f_mask ||
	    options->f_time ||
	    options->f_ttl ||
	    options->f_quiet ||
	    options->f_rroute ||
	    options->f_so_dontroute ||
	    options->f_multicast_ttl ||
#if defined(IPSEC) && !defined(IPSEC_POLICY_IPSEC)
	    options->f_policy ||
#endif
	    options->f_tos);
}

static bool
options_has_ipv6_only(const struct options *const options)
{
	return (options->f_protocol_ipv6 ||
#if defined(SO_SNDBUF) && defined(SO_RCVBUF)
	    options->f_sock_buff_size ||
#endif
	    options->s_gateway != NULL ||
	    options->f_hoplimit ||
	    options->f_nodeaddr ||
	    options->f_nigroup ||
#ifdef IPV6_USE_MIN_MTU
	    options->c_use_min_mtu > 0 ||
#endif
	    options->f_fqdn ||
	    options->f_fqdn_old ||
#if defined(IPSEC) && !defined(IPSEC_POLICY_IPSEC)
	    options->f_authhdr ||
	    options->f_encrypt ||
#endif /* IPSEC && !IPSEC_POLICY_IPSEC */
	    options->f_subtypes);
}
#endif /* INET6 */

/* TODO: rename to options_usage()? */
void
usage(void)
{
	(void)fprintf(stderr,
	    "usage: ping [-4AaDdfnoQqRrv] [-c count] [-G sweepmaxsize] [-g sweepminsize]\n"
	    "            [-h sweepincrsize] [-i wait] [-l preload] [-M mask | time] [-m ttl]\n"
	    "            "
#ifdef IPSEC
	    "[-P policy] "
#endif
	    "[-p pattern] [-S src_addr] [-s packetsize] [-t timeout]\n"
	    "            [-W waittime] [-z tos] IPv4-host\n"
	    "       ping [-4AaDdfLnoQqRrv] [-c count] [-I iface] [-i wait] [-l preload]\n"
	    "            [-M mask | time] [-m ttl] "
#ifdef IPSEC
	    "[-P policy] "
#endif
	    "[-p pattern] [-S src_addr]\n"
	    "            [-s packetsize] [-T ttl] [-t timeout] [-W waittime]\n"
	    "            [-z tos] IPv4-mcast-group\n"
#ifdef INET6
	    "       ping [-6AaDd"
#if defined(IPSEC) && !defined(IPSEC_POLICY_IPSEC)
	    "E"
#endif
	    "fHNnoq"
#ifdef IPV6_USE_MIN_MTU
	    "u"
#endif
	    "vwYy"
#if defined(IPSEC) && !defined(IPSEC_POLICY_IPSEC)
	    "Z"
#endif
	    "] [-b bufsiz ] [-c count] [-e gateway]\n"
	    "            [-I iface] [-i wait] [-j hoplimit] [-k addrtype]\n"
	    "            [-l preload] "
#if defined(IPSEC) && defined(IPSEC_POLICY_IPSEC)
	    "[-P policy] "
#endif
	    "[-p pattern] [-S src_addr] [-s packetsize]\n"
	    "            [-t timeout] [-W waittime] [IPv6 hops ...] IPv6-host\n");
#endif	/* INET6 */
}
