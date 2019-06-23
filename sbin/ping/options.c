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
#include <netdb.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "options.h"

/* TODO: This is duplicated from ping6.c */
struct tv32 {
	int32_t tv32_sec;
	int32_t tv32_usec;
};
#define MAXPACKETLEN	131072
#define	IP6LEN		40
#define ICMP6ECHOLEN	8	/* icmp echo header len excluding time */
#define ICMP6ECHOTMLEN  sizeof(struct tv32)
#define MAXDATALEN	MAXPACKETLEN - IP6LEN - ICMP6ECHOLEN

#define DEFAULT_DATALEN_IPV6   ICMP6ECHOTMLEN
#define	DEFAULT_DATALEN_IPV4   56

#define MAX_ALARM (60 * 60)
#define	MAX_TOS		255

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

static void options_check(int argc, char **argv, struct options *const options);
static void options_check_packet_size(int, int);
static void options_get_target_type(struct options *const options);
static void options_getaddrinfo(const char *const hostname,
    const struct addrinfo *const hints, struct addrinfo **const res);
static bool options_has_ipv4_only(const struct options *const options);
#ifdef INET6
static bool options_has_ipv6_only(const struct options *const options);
#endif
static void options_parse_hosts(int argc, char **argv, struct options *const options);
static void options_set_defaults(struct options *const options);
static bool options_strtol(const char *const str, long *const val);
static bool options_strtoi(const char *const str, int *const val);
static bool options_strtoul(const char *const str, unsigned long *const val);
static bool options_strtod(const char *const str, double *const val);

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

void
options_parse(int *const argc, char ***argv, struct options *const options)
{
	int ch;
	double dbl, dbl_integer_part;

	memset(options, 0, sizeof(*options));

	while ((ch = getopt(*argc, *argv, OPSTR)) != -1) {
		switch (ch) {
		case 'A':
			options->f_missed = true;
			break;
		case 'a':
			options->f_audible = true;
			break;
		case 'c':
			if (!options_strtol(optarg, &options->n_packets))
				errx(EX_USAGE, "invalid count of packets to transmit: `%s'", optarg);
			options->f_packets = true;
			break;
		case 'D':
			options->f_dont_fragment = true;
			break;
		case 'd':
			options->f_so_debug = true;
			break;
		case 'f':
			if (getuid() != 0) {
				errno = EPERM;
				errx(EX_NOPERM, "Must be superuser to flood ping");
			}
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
			if (options_strtod(optarg, &dbl) || (dbl <= 0))
				errx(EX_USAGE, "invalid timing interval: `%s'", optarg);
			/* 1 second = 1000 ms = 1000 * 1000 microseconds */
			options->n_interval.tv_usec = (suseconds_t) (modf(dbl, &dbl_integer_part) * 1000 * 1000);
			options->n_interval.tv_sec = (time_t) dbl_integer_part;
			options->f_interval = true;
			break;
		case 'l':
			if (!options_strtoi(optarg, &options->n_preload))
				errx(EX_USAGE, "invalid preload value: `%s'", optarg);
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
				if (!isxdigit(*cp))
					errx(EX_USAGE, "patterns must be specified as hex digits");
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
			if (options_strtol(optarg, &options->n_packet_size))
				errx(EX_USAGE, "invalid packet size: `%s'", optarg);
			options->f_packet_size = true;
			break;
		case 't':
			if (options_strtoul(optarg, &options->n_alarm_timeout))
				errx(EX_USAGE, "invalid timeout: `%s'", optarg);
			options->f_alarm_timeout = true;
			break;
		case 'v':
			options->f_verbose = true;
			break;
		case 'W':
			if (options_strtoi(optarg, &options->n_wait_time))
				errx(EX_USAGE, "invalid timing interval: `%s'", optarg);
			options->f_wait_time = true;
			break;
			/* IPV4 options */
		case '4':
			options->f_protocol_ipv4 = true;
			break;
		case 'G':
			if (options_strtoi(optarg, &options->n_sweep_max))
				errx(EX_USAGE, "invalid packet size: `%s'", optarg);
			options->f_sweep_max = true;
			break;
		case 'g':
			if (options_strtoi(optarg, &options->n_sweep_min))
				errx(EX_USAGE, "invalid packet size: `%s'", optarg);
			options->f_sweep_min = true;
			break;
		case 'h':
			if (options_strtoi(optarg, &options->n_sweep_incr))
				errx(EX_USAGE, "invalid increment size: `%s'", optarg);
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
				errx(EX_USAGE, "invalid message: `%c'", optarg[0]);
				break;
			}
			break;
		case 'm':
			if (options_strtoi(optarg, &options->n_ttl))
				errx(EX_USAGE, "invalid TTL: `%s'", optarg);
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
			if (options_strtoi(optarg, &options->n_multicast_ttl))
				errx(EX_USAGE, "invalid multicast TTL: `%s'", optarg);
			options->f_multicast_ttl = true;
			break;
		case 'z':
			if (options_strtoi(optarg, &options->n_tos))
				errx(EX_USAGE, "invalid TOS: `%s'", optarg);
			options->f_tos = true;
			break;
			/* IPv6 options */
#ifdef INET6
		case '6':
			options->f_protocol_ipv6 = true;
			break;
		case 'b':
#if defined(SO_SNDBUF) && defined(SO_RCVBUF)
			if (options_strtoul(optarg, &options->n_sock_buff_size))
				errx(EX_USAGE, "invalid socket buffer size: `%s'", optarg);
			options->f_sock_buff_size = true;
#else
			errx(EX_USAGE, "-b option ignored: SO_SNDBUF/SO_RCVBUF socket options not supported");
#endif
			break;
		case 'e':
			options->s_gateway = optarg;
			break;
		case 'j':
			if (options_strtoi(optarg, &options->n_hoplimit))
				errx(EX_USAGE, "illegal hoplimit %s", optarg);
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
					errx(EX_USAGE, "-a A is not supported on the platform");
					/*NOTREACHED*/
#endif
				default:
					usage();
					/*NOTREACHED*/
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
			errx(EX_USAGE, "-u is not supported on this platform");
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
			if (!strncmp("in", optarg, 2)) {
				if ((options->s_policy_in = strdup(optarg)) == NULL)
					errx(EX_OSERR, "strdup");
			} else if (!strncmp("out", optarg, 3)) {
				if ((options->s_policy_out = strdup(optarg)) == NULL)
					errx(EX_OSERR, "strdup");
			} else
				errx(EX_USAGE, "invalid security policy");
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
		}
	}

	*argc -= optind;
	*argv += optind;

	options_parse_hosts(*argc, *argv, options);
	options_set_defaults(options);
	options_check(*argc, *argv, options);
}

static void
options_check(int argc, char **argv, struct options *const options)
{
#ifdef INET6
	if (options->f_protocol_ipv6 && options_has_ipv4_only(options))
		errx(EX_USAGE, "IPv6 requested but IPv4 option provided");
	else if (options->f_protocol_ipv4 && options_has_ipv6_only(options))
		errx(EX_USAGE, "IPv4 requested but IPv6 option provided");
	else if (options->f_protocol_ipv4 && (options->target_type == TARGET_ADDRESS_IPV6))
		errx(EX_USAGE, "IPv4 requested but IPv6 target address provided");
	else if (options->f_protocol_ipv6 && (options->target_type == TARGET_ADDRESS_IPV4))
		errx(EX_USAGE, "IPv6 requested but IPv4 target address provided");
	else if (options->f_protocol_ipv4 && (options->target_type == TARGET_HOSTNAME_IPV6))
		errx(EX_USAGE, "IPv4 requested but the hostname has been resolved to IPv6");
	else if (options->f_protocol_ipv6 && (options->target_type == TARGET_HOSTNAME_IPV4))
		errx(EX_USAGE, "IPv6 requested but the hostname has been resolved to IPv4");
#endif
	/*
	 * Check options common to both IPv4 and IPv6 targets.
	 */
	if (options->f_flood && options->f_interval)
		errx(EX_USAGE, "-f and -i are incompatible options");
	if (options->f_flood && (getuid() != 0))
		errx(EX_NOPERM, "Must be superuser to flood ping");
	/* Check interval between sending each packet. */
	if ((getuid() != 0) && (options->n_interval.tv_sec < 1)) {
		errno = EPERM;
		err(EX_NOPERM, "only root may use interval < 1s");
	}
	/* The interval less than 1 microsecond does not make sense. */
	if (options->n_interval.tv_sec == 0 && options->n_interval.tv_usec < 1) {
		options->n_interval.tv_usec = 1;
		warnx("too small interval, raised to .000001");
	}
	if ((options->f_alarm_timeout) && (options->n_alarm_timeout > MAX_ALARM))
		errx(EX_USAGE, "invalid timeout: `%lu' > %d", options->n_alarm_timeout, MAX_ALARM);

	if (options->f_packet_size) {
		if (options->n_packet_size <= 0)
			errx(1, "illegal datalen value -- %ld", options->n_packet_size);
		if ((options->target_type == TARGET_ADDRESS_IPV4) ||
		    (options->target_type == TARGET_HOSTNAME_IPV4))
			options_check_packet_size(options->n_packet_size, DEFAULT_DATALEN_IPV4);
		else if (options->n_packet_size > MAXDATALEN)
			errx(1, "datalen value too large, maximum is %d", MAXDATALEN);
	} else if ((options->target_type == TARGET_ADDRESS_IPV4) ||
	    (options->target_type == TARGET_HOSTNAME_IPV4))
		options->n_packet_size = DEFAULT_DATALEN_IPV4;
	else
		options->n_packet_size = DEFAULT_DATALEN_IPV6;

	/*
	 * Check options only for IPv4 target.
	 */
	if (options->f_mask && options->f_time)
		errx(EX_USAGE, "ICMP_TSTAMP and ICMP_MASKREQ are exclusive");
	if ((options->f_sweep_max || options->f_sweep_min || options->f_sweep_incr) &&
	    (options->n_sweep_max == 0))
		errx(EX_USAGE, "Maximum sweep size must be specified");
	if (options->f_sweep_max) {
		if (options->n_sweep_min > options->n_sweep_max)
			errx(EX_USAGE, "Maximum packet size must be no less than the minimum packet size");
		if (options->f_packet_size)
			errx(EX_USAGE, "Packet size and ping sweep are mutually exclusive");
		options_check_packet_size(options->f_sweep_max, DEFAULT_DATALEN_IPV4);
	}
	if (options->f_sweep_min)
		options_check_packet_size(options->f_sweep_min, DEFAULT_DATALEN_IPV4);
	if (options->f_sweep_incr)
		options_check_packet_size(options->f_sweep_incr, DEFAULT_DATALEN_IPV4);

	if (options->f_preload) {
		if (getuid() != 0)
			errx(EX_NOPERM, "Must be superuser to preload");
		else if (options->n_preload < 0)
			errx(EX_USAGE, "invalid preload value: `%d'", options->n_preload);
	}

	if ((options->f_ttl) && (options->n_ttl > MAXTTL || options->n_ttl < 0))
		errx(EX_USAGE, "invalid TTL: `%d'", options->n_ttl);
	if ((options->f_multicast_ttl) && (options->n_multicast_ttl > MAXTTL || options->n_multicast_ttl < 0))
		errx(EX_USAGE, "invalid multicast TTL: `%d'", options->n_multicast_ttl);
	if ((options->f_tos) && (options->n_tos > MAX_TOS || options->n_tos < 0))
		errx(EX_USAGE, "invalid TOS: `%d'", options->n_tos);

	/*
	 * Check options only for IPv6 target.
	 */
	if (options->f_sock_buff_size && (options->n_sock_buff_size > INT_MAX))
		errx(1, "invalid socket buffer size");
	if ((options->f_hoplimit) && ((options->n_hoplimit < 0) || (options->n_hoplimit > 255)))
		errx(1, "illegal hoplimit -- %d", options->n_hoplimit);


}

static void
options_check_packet_size(int size, int max_size)
{
	if (size <= 0)
		errx(EX_USAGE, "invalid packet size: `%d'", size);
	if ((getuid() != 0) && (size > max_size)) {
		err(EX_NOPERM,
		    "packet size too large: %d > %u", size, max_size);
	}
}

static void
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
	options_getaddrinfo(options->target, &hints, &options->target_addrinfo);

	if (!is_address) {
		if (options->target_addrinfo->ai_family == AF_INET)
			options->target_type = TARGET_HOSTNAME_IPV4;
#ifdef INET6
		else if (options->target_addrinfo->ai_family == AF_INET6)
			options->target_type = TARGET_HOSTNAME_IPV6;
#endif
	}
}

static void
options_getaddrinfo(const char *const hostname, const struct addrinfo *const hints,
    struct addrinfo **const res)
{
	const int r = getaddrinfo(hostname, NULL, hints, res);
	if (r != 0)
		/* TODO: Which sysexits(3) code to use? */
		errx(1, "getaddrinfo for `%s': %s", hostname, gai_strerror(r));
	else if (res == NULL)
		errx(1, "getaddrinfo for `%s'", hostname);
}

static void
options_parse_hosts(int argc, char **argv, struct options *const options)
{
	/* The last argument is a target. */
	if (argc == 0)
		usage();

	options->target = argv[argc - 1];
	options_get_target_type(options);

	if (options->target_type == TARGET_UNKNOWN)
		errx(EX_USAGE, "invalid ping target: `%s'", options->target);

	--argc;
	++argv;

	/* Everything else are IPv6 hops. */
	if (argc != 0) {
		/* Ping to IPv4 host cannot have any hops specified. */
		if ((options->target_type == TARGET_ADDRESS_IPV4) ||
		    (options->target_type == TARGET_HOSTNAME_IPV4))
			usage();

		options->hop_count = argc;
		options->hops = malloc(argc * sizeof(char *));
		options->hops_addrinfo = malloc(argc * sizeof(struct addrinfo *));

		for (int i = 0; i < argc; ++i) {
			struct addrinfo hints;

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET6;

			options_getaddrinfo(argv[i], &hints, &(options->hops_addrinfo[i]));

			if (options->hops_addrinfo[i]->ai_addr->sa_family != AF_INET6)
				errx(1, "bad addr family of an intermediate addr");
		}
	}
}

static void
options_set_defaults(struct options *const options)
{
	if (!options->f_sweep_incr)
		options->n_sweep_incr = 1;
	if (!options->f_interval) {
		options->n_interval.tv_sec = 1;
		options->n_interval.tv_usec = 0;
	}
	if (!options->f_wait_time)
		options->n_wait_time = 10000;
	if (!options->f_packet_size) {
		if ((options->target_type == TARGET_ADDRESS_IPV4) ||
		    (options->target_type == TARGET_ADDRESS_IPV4))
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
options_strtol(const char *const str, long *const val)
{
	/* TODO: check errno */
	char *ep;

	*val = strtol(str, &ep, 0);

	return (*ep == '\0' && optarg != '\0');
}

static bool
options_strtoi(const char *const str, int *const val)
{
	/* TODO: check errno */
	long ltmp;
	if (!options_strtol(str, &ltmp) || ltmp > INT_MAX || ltmp < INT_MIN)
		return false;
	else {
		*val = (int) ltmp;
		return true;
	}
}

static bool
options_strtoul(const char *const str, unsigned long *const val)
{
	/* TODO: check errno */
	char *ep;

	*val = strtoul(optarg, &ep, 0);

	return ((*ep == '\0' && optarg != '\0') && (*val != ULONG_MAX));
}

static bool
options_strtod(const char *const str, double *const val)
{
	/* TODO: check errno */
	char *ep;

	*val = strtod(str, &ep);

	return (*ep == '\0' && optarg != '\0');
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

       exit(EX_USAGE);
}
