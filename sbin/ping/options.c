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

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "options.h"

#define OPSTR_COMMON        "Aac:DdfI:i:l:nop:qS:s:t:vW:"
#define OPSTR_IPV4          "4G:g:h:LM:m:QRrT:z:"
#define OPSTR_IPV6          "6b:e:Hj:k:NuwYy"
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

static bool options_has_ipv4_only(const struct options *const options);
#ifdef INET6
static bool options_has_ipv6_only(const struct options *const options);
#endif
static bool options_strtol(const char *const str, long *const val);
static bool options_strtoi(const char *const str, int *const val);
static bool options_strtoul(const char *const str, unsigned long *const val);
static bool options_strtod(const char *const str, double *const val);

void
options_parse(int *const argc, char **argv, struct options *const options)
{
	int ch;
#ifdef INET6
	char *cp;
#endif
	memset(options, 0, sizeof(*options));
	
	while ((ch = getopt(*argc, argv, OPSTR)) != -1) {
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
			if (options_strtod(optarg, &options->n_interval))
				errx(EX_USAGE, "invalid timing interval: `%s'", optarg);
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
			options->s_ping_filled = optarg;
			break;
		case 'q':
			options->f_somewhat_quiet = true;
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
			options->f_quiet = true;
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
			errx(1, "-b option ignored: SO_SNDBUF/SO_RCVBUF socket options not supported");
#endif
			break;
		case 'e':
			options->s_gateway = optarg;
			break;
		case 'H':
			options->f_hostname = true;
			break;
		case 'j':
			if (options_strtoi(optarg, &options->n_hoplimit))
				errx(EX_USAGE, "illegal hoplimit %s", optarg);
			options->f_hoplimit = true;
			break;
		case 'k':
			for (cp = optarg; *cp != '\0'; cp++) {
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
					errx(1, "-a A is not supported on the platform");
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
#ifdef IPV6_USE_MIN_MTU
			options->c_use_min_mtu++;
#else
			errx(1, "-u is not supported on this platform");
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
			/* TODO: use EX_ code in errx() */
			if (!strncmp("in", optarg, 2)) {
				if ((options->s_policy_in = strdup(optarg)) == NULL)
					errx(1, "strdup");
			} else if (!strncmp("out", optarg, 3)) {
				if ((options->s_policy_out = strdup(optarg)) == NULL)
					errx(1, "strdup");
			} else
				errx(1, "invalid security policy");
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

/* 		const bool opt_ipv4 = options_process_ipv4(ch, options); */
/* #ifdef INET6	 */
/* 		const bool opt_ipv6 = options_process_ipv6(ch, options); */
/* #endif */

/* 		if (!options_process_common(ch, options) && */
/* #ifdef INET6 */
/* 		    !opt_ipv6 && */
/* #endif */
/* #ifdef IPSEC */
/* 		    !options_process_ipsec(ch, options) && */
/* #endif */
/* 		    !opt_ipv4) { */
/* 			usage(); */
/* 			/\* NOTREACHED *\/ */
/* 		} */
/* #ifdef INET6 */
/* 		if (options->f_protocol_ipv6 && opt_ipv4) */
/* 			errx(EX_USAGE, "IPv6 requested but IPv4 option provided"); */
/* 		else if (options->f_protocol_ipv4 && opt_ipv6) */
/* 			errx(EX_USAGE, "IPv4 requested but IPv6 option provided"); */
/* #endif /\* INET6 *\/ */
/* 	} */

#ifdef INET6
	if (options->f_protocol_ipv4 && options->f_protocol_ipv6)
		errx(EX_USAGE, "-4 and -6 cannot be used together");
#endif
	/* TODO: check for invalid combinations of the options */

	*argc -= optind;
	argv += optind;
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
	    options->f_tos);
}

#ifdef INET6
static bool
options_has_ipv6_only(const struct options *const options)
{
	return (options->f_protocol_ipv6 ||
#if defined(SO_SNDBUF) && defined(SO_RCVBUF)
	    options->f_sock_buff_size ||
#endif
	    options->s_gateway != NULL ||
	    options->f_hostname ||
	    options->f_hoplimit ||
	    options->f_nodeaddr ||
	    options->f_nigroup ||
#ifdef IPV6_USE_MIN_MTU
	    options->c_use_min_mtu > 0 ||
#endif
	    options->f_fqdn ||
	    options->f_fqdn_old ||
#ifndef IPSEC_POLICY_IPSEC
	    options->f_authhdr ||
	    options->f_encrypt ||
#endif /* !IPSEC_POLICY_IPSEC */
	    options->f_subtypes);
}
#endif /* INET6 */

void
usage(void)
{
	/* TODO */

	/* PING USAGE */
/* #if defined(IPSEC) && defined(IPSEC_POLICY_IPSEC) */
/* #define	SECOPT		" [-P policy]" */
/* #else */
/* #define	SECOPT		"" */
/* #endif */
/* static void */
/* usage(void) */
/* { */

/* 	(void)fprintf(stderr, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", */
/* "usage: ping [-AaDdfnoQqRrv] [-c count] [-G sweepmaxsize] [-g sweepminsize]", */
/* "            [-h sweepincrsize] [-i wait] [-l preload] [-M mask | time] [-m ttl]", */
/* "           " SECOPT " [-p pattern] [-S src_addr] [-s packetsize] [-t timeout]", */
/* "            [-W waittime] [-z tos] host", */
/* "       ping [-AaDdfLnoQqRrv] [-c count] [-I iface] [-i wait] [-l preload]", */
/* "            [-M mask | time] [-m ttl]" SECOPT " [-p pattern] [-S src_addr]", */
/* "            [-s packetsize] [-T ttl] [-t timeout] [-W waittime]", */
/* "            [-z tos] mcast-group"); */
/* 	exit(EX_USAGE); */
/* } */

	/* PING6 USAGE */
/* static void */
/* usage(void) */
/* { */
/* 	(void)fprintf(stderr, */
/* 	    "usage: ping6 [-" */
/* 	    "AaDd" */
/* #if defined(IPSEC) && !defined(IPSEC_POLICY_IPSEC) */
/* 	    "E" */
/* #endif */
/* 	    "fHnNoq" */
/* #ifdef IPV6_USE_MIN_MTU */
/* 	    "u" */
/* #endif */
/* 	    "vwYy" */
/* #if defined(IPSEC) && !defined(IPSEC_POLICY_IPSEC) */
/* 	    "Z" */
/* #endif */
/* 	    "] " */
/* 	    "[-b bufsiz] [-c count] [-e gateway]\n" */
/* 	    "             [-I interface] [-i wait] [-j hoplimit] [-k addrtype] [-l preload]" */
/* #if defined(IPSEC) && defined(IPSEC_POLICY_IPSEC) */
/* 	    " [-P policy]" */
/* #endif */
/* 	    "\n" */
/* 	    "             [-p pattern] [-S sourceaddr] [-s packetsize]\n" */
/* 	    "[-x waittime] [-X timeout] [hops ...] host\n"); */
/* 	exit(1); */
/* } */

	exit(EX_USAGE);
}
