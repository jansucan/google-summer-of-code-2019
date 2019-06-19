/*	$KAME: ping6.c,v 1.169 2003/07/25 06:01:47 itojun Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*	BSDI	ping.c,v 2.3 1996/01/21 17:56:50 jch Exp	*/

/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char copyright[] =
"@(#) Copyright (c) 1989, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)ping.c	8.1 (Berkeley) 6/5/93";
#endif
#endif /* not lint */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 * Bugs -
 *	More statistics could always be gathered.
 *	This program has to run SUID to ROOT to access the ICMP socket.
 */
/*
 * NOTE:
 * USE_SIN6_SCOPE_ID assumes that sin6_scope_id has the same semantics
 * as IPV6_PKTINFO.  Some people object it (sin6_scope_id specifies *link*
 * while IPV6_PKTINFO specifies *interface*.  Link is defined as collection of
 * network attached to 1 or more interfaces)
 */

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#ifdef IPSEC
#include <netipsec/ah.h>
#include <netipsec/ipsec.h>
#endif

#include <md5.h>

#include "ping6.h"
#include "utils.h"

struct tv32 {
	u_int32_t tv32_sec;
	u_int32_t tv32_usec;
};

#define MAXPACKETLEN	131072
#define	IP6LEN		40
#define ICMP6ECHOLEN	8	/* icmp echo header len excluding time */
#define ICMP6ECHOTMLEN sizeof(struct tv32)
#define ICMP6_NIQLEN	(ICMP6ECHOLEN + 8)
# define CONTROLLEN	10240	/* ancillary data buffer size RFC3542 20.1 */
/* FQDN case, 64 bits of nonce + 32 bits ttl */
#define ICMP6_NIRLEN	(ICMP6ECHOLEN + 12)
#define	EXTRA		256	/* for AH and various other headers. weird. */
#define	DEFDATALEN	ICMP6ECHOTMLEN
#define MAXDATALEN	MAXPACKETLEN - IP6LEN - ICMP6ECHOLEN
#define	NROUTES		9		/* number of record route slots */
#define	MAXWAIT		10000		/* max ms to wait for response */
#define	MAXALARM	(60 * 60)	/* max seconds for alarm timeout */

#define BBELL   '\a'  /* characters written for MISSED and AUDIBLE */
#define BSPACE  '\b'  /* characters written for flood */
#define DOT     '.'

#define IN6LEN		sizeof(struct in6_addr)
#define SA6LEN		sizeof(struct sockaddr_in6)
#define DUMMY_PORT	10101

#define SIN6(s)	((struct sockaddr_in6 *)(s))

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.  Change 128
 * to 8192 for complete accuracy...
 */
#define	MAX_DUP_CHK	(8 * 8192)

struct shared_variables {
	char rcvd_tbl[MAX_DUP_CHK / 8];
	struct sockaddr_in6 dst;	/* who to ping6 */
	int s;			/* socket file descriptor */
	u_char outpack[MAXPACKETLEN];
	char *hostname;
	int ident;		/* process id to identify our packets */
	u_int8_t nonce[8];	/* nonce field for node information */
	u_char *packet;
	/* for ancillary data(advanced API) */
	struct msghdr smsghdr;
};

struct counters {
	long nmissedmax;	/* max value of ntransmitted - nreceived - 1 */
	long nreceived;		/* # of packets we got back */
	long nrepeats;		/* number of duplicates */
	long ntransmitted;	/* sequence # for outbound packets = #sent */
	long nrcvtimeout;	/* # of packets we got back after waittime */
};

struct timing {
	bool   enabled;	/* flag to do timing */
	double min;	/* minimum round trip time */
	double max;	/* maximum round trip time */
	double sum;	/* sum of all times, for doing average */
	double sumsq;	/* sum of all times squared, for std. dev. */
};

static bool sig_option_f_hostname;
static volatile sig_atomic_t seenint;
#ifdef SIGINFO
static volatile sig_atomic_t seeninfo;
#endif
/* 
 * This pointer is used in the signal handler for accessing nreceived
 * member variable of the local 'struct counters' variable. Thus, the
 * nreceived variable does not have to be global.
 */
static const long *sig_counters_nreceived;

static int	 get_hoplim(struct msghdr *);
static int	 get_pathmtu(struct msghdr *, const struct options *const, const struct sockaddr_in6 *const);
static struct in6_pktinfo *get_rcvpktinfo(struct msghdr *);
static void	 onsignal(int);
static void	 onint(int);
static size_t	 pingerlen(const struct options *const, size_t);
static int	 pinger(struct options *const, struct shared_variables *const,
    struct counters *const, struct timing *const);
static const char *pr_addr(struct sockaddr *, int, bool);
static void	 pr_icmph(struct icmp6_hdr *, u_char *, bool);
static void	 pr_iph(struct ip6_hdr *);
static void	 pr_suptypes(struct icmp6_nodeinfo *, size_t, bool verbose);
static void	 pr_nodeaddr(struct icmp6_nodeinfo *, int, bool verbose);
static int	 myechoreply(const struct icmp6_hdr *, int);
static int	 mynireply(const struct icmp6_nodeinfo *, const struct shared_variables *const);
static char *dnsdecode(const u_char **, const u_char *, const u_char *,
    char *, size_t);
static void	 pr_pack(u_char *, int, struct msghdr *, const struct options *const,
    struct shared_variables *const, struct counters *const, struct timing *const);
static void	 pr_exthdrs(struct msghdr *);
static void	 pr_ip6opt(void *, size_t);
static void	 pr_rthdr(void *, size_t);
static int	 pr_bitrange(u_int32_t, int, int);
static void	 pr_retip(struct ip6_hdr *, u_char *);
static void	 summary(const struct counters *const, const struct timing *const, const char *const);
static void	 tvsub(struct timeval *, struct timeval *);
static int	 setpolicy(int, char *);
static char	*nigroup(char *, int);
static void      check_options(struct options *const, struct timeval *const);
static u_short   get_node_address_flags(const struct options *const);

void
ping6(struct options *const options)
{
	struct timeval last, intvl;
	struct sockaddr_in6 from, *sin6, src;
	struct addrinfo hints, *res;
	struct sigaction si_sa;
	struct shared_variables vars;
	struct counters counters;
	struct timing timing;
	int cc, i;
	int almost_done, hold, packlen, optval, error;
	u_char *datap;
	char *scmsg = 0;
	int ip6optlen = 0;
	struct cmsghdr *scmsgp = NULL;
	/* For control (ancillary) data received from recvmsg() */
	struct cmsghdr cm[CONTROLLEN];
	struct in6_pktinfo *pktinfo = NULL;
#ifdef USE_RFC2292BIS
	struct ip6_rthdr *rthdr = NULL;
#endif
	socklen_t srclen;
	size_t rthlen;

	memset(&vars, 0, sizeof(vars));

	memset(&counters, 0, sizeof(counters));
	sig_counters_nreceived = &counters.nreceived;

	timing.enabled = false;
	timing.min = 999999999.0;
	timing.max = 0.0;
	timing.sum = 0.0;
	timing.sumsq = 0.0;

	/* just to be sure */
	memset(&vars.smsghdr, 0, sizeof(vars.smsghdr));

	datap = &vars.outpack[ICMP6ECHOLEN + ICMP6ECHOTMLEN];

	check_options(options, &intvl);

	if (options->f_ping_filled)
		fill((char *)datap, MAXDATALEN - 8 + sizeof(struct tv32) + options->ping_filled_size,
		    options);

	/* TODO: Move gettaddrinfo() of the source to options.c? */
	if (options->s_source != NULL) {
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_flags = AI_NUMERICHOST; /* allow hostname? */
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_RAW;
		hints.ai_protocol = IPPROTO_ICMPV6;

		error = getaddrinfo(options->s_source, NULL, &hints, &res);
		if (error) {
			errx(1, "invalid source address: %s",
			    gai_strerror(error));
		}
		/*
		 * res->ai_family must be AF_INET6 and res->ai_addrlen
		 * must be sizeof(src).
		 */
		memcpy(&src, res->ai_addr, res->ai_addrlen);
		srclen = res->ai_addrlen;
		freeaddrinfo(res);
	}

	if (options->hop_count != 0) {
#ifdef IPV6_RECVRTHDR	/* 2292bis */
		rthlen = CMSG_SPACE(inet6_rth_space(IPV6_RTHDR_TYPE_0,
		    options->hop_count));
#else  /* RFC2292 */
		rthlen = inet6_rthdr_space(IPV6_RTHDR_TYPE_0, options->hop_count);
#endif
		if (rthlen == 0) {
			errx(1, "too many intermediate hops");
			/*NOTREACHED*/
		}
		ip6optlen += rthlen;
	}

	if (options->f_nigroup) {
		options->target = nigroup(options->target, options->c_nigroup);
		if (options->target == NULL) {
			usage();
			/*NOTREACHED*/
		}
	}

	/* Create socket for the ping target. */
	if (options->target_addrinfo->ai_canonname)
		vars.hostname = strdup(options->target_addrinfo->ai_canonname);
	else
		vars.hostname = options->target;

	if (!options->target_addrinfo->ai_addr)
		errx(1, "getaddrinfo failed");

	(void)memcpy(&vars.dst, options->target_addrinfo->ai_addr,
	    options->target_addrinfo->ai_addrlen);

	if ((vars.s = socket(options->target_addrinfo->ai_family,
		    options->target_addrinfo->ai_socktype,
		    options->target_addrinfo->ai_protocol)) < 0)
		err(1, "socket");
	freeaddrinfo(options->target_addrinfo);
	options->target_addrinfo = NULL;

	/* set the source address if specified. */
	if (options->s_source != NULL) {
		/* properly fill sin6_scope_id */
		if (IN6_IS_ADDR_LINKLOCAL(&src.sin6_addr) && (
		    IN6_IS_ADDR_LINKLOCAL(&vars.dst.sin6_addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&vars.dst.sin6_addr) ||
		    IN6_IS_ADDR_MC_NODELOCAL(&vars.dst.sin6_addr))) {
			if (src.sin6_scope_id == 0)
				src.sin6_scope_id = vars.dst.sin6_scope_id;
			if (vars.dst.sin6_scope_id == 0)
				vars.dst.sin6_scope_id = src.sin6_scope_id;
		}
		if (bind(vars.s, (struct sockaddr *)&src, srclen) != 0)
			err(1, "bind");
	}
	/* TODO: Move gettaddrinfo() of the source to options.c? */
	/* set the gateway (next hop) if specified */
	if (options->s_gateway) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_RAW;
		hints.ai_protocol = IPPROTO_ICMPV6;

		error = getaddrinfo(options->s_gateway, NULL, &hints, &res);
		if (error) {
			errx(1, "getaddrinfo for the gateway %s: %s",
			     options->s_gateway, gai_strerror(error));
		}
		if (res->ai_next && options->f_verbose)
			warnx("gateway resolves to multiple addresses");

		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_NEXTHOP,
		    res->ai_addr, res->ai_addrlen)) {
			err(1, "setsockopt(IPV6_NEXTHOP)");
		}

		freeaddrinfo(res);
	}

	/*
	 * let the kerel pass extension headers of incoming packets,
	 * for privileged socket options
	 */
	if (options->f_verbose) {
		const int opton = 1;

#ifdef IPV6_RECVHOPOPTS
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &opton,
		    sizeof(opton)))
			err(1, "setsockopt(IPV6_RECVHOPOPTS)");
#else  /* old adv. API */
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_HOPOPTS, &opton,
		    sizeof(opton)))
			err(1, "setsockopt(IPV6_HOPOPTS)");
#endif
#ifdef IPV6_RECVDSTOPTS
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_RECVDSTOPTS, &opton,
		    sizeof(opton)))
			err(1, "setsockopt(IPV6_RECVDSTOPTS)");
#else  /* old adv. API */
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_DSTOPTS, &opton,
		    sizeof(opton)))
			err(1, "setsockopt(IPV6_DSTOPTS)");
#endif
#ifdef IPV6_RECVRTHDRDSTOPTS
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_RECVRTHDRDSTOPTS, &opton,
		    sizeof(opton)))
			err(1, "setsockopt(IPV6_RECVRTHDRDSTOPTS)");
#endif
	}

	/* revoke root privilege */
	if (seteuid(getuid()) != 0)
		err(1, "seteuid() failed");
	if (setuid(getuid()) != 0)
		err(1, "setuid() failed");

	if (!options->f_nodeaddr && !options->f_fqdn && !options->f_fqdn_old && !options->f_subtypes) {
		if (options->n_packet_size >= (long)sizeof(struct tv32)) {
			/* we can time transfer */
			timing.enabled = true;
		} else
			timing.enabled = false;
		/* in F_VERBOSE case, we may get non-echoreply packets*/
		if (options->f_verbose)
			packlen = 2048 + IP6LEN + ICMP6ECHOLEN + EXTRA;
		else
			packlen = options->n_packet_size + IP6LEN + ICMP6ECHOLEN + EXTRA;
	} else {
		/* suppress timing for node information query */
		timing.enabled = false;
		options->n_packet_size = 2048;
		packlen = 2048 + IP6LEN + ICMP6ECHOLEN + EXTRA;
	}

	if (!(vars.packet = (u_char *)malloc((u_int)packlen)))
		err(1, "Unable to allocate packet");
	if (!options->f_ping_filled)
		for (i = ICMP6ECHOLEN; i < packlen; ++i)
			*datap++ = i;

	vars.ident = getpid() & 0xFFFF;
	arc4random_buf(vars.nonce, sizeof(vars.nonce));
	optval = 1;
	if (options->f_dont_fragment)
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_DONTFRAG,
		    &optval, sizeof(optval)) == -1)
			err(1, "IPV6_DONTFRAG");
	hold = 1;

	if (options->f_so_debug)
		(void)setsockopt(vars.s, SOL_SOCKET, SO_DEBUG, (char *)&hold,
		    sizeof(hold));
	optval = IPV6_DEFHLIM;
	if (IN6_IS_ADDR_MULTICAST(&vars.dst.sin6_addr))
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		    &optval, sizeof(optval)) == -1)
			err(1, "IPV6_MULTICAST_HOPS");
#ifdef IPV6_USE_MIN_MTU
	if (options->c_use_min_mtu != 1) {
		optval = (options->c_use_min_mtu > 1) ? 0 : 1;

		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_USE_MIN_MTU,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt(IPV6_USE_MIN_MTU)");
	}
#ifdef IPV6_RECVPATHMTU
	else {
		optval = 1;
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_RECVPATHMTU,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt(IPV6_RECVPATHMTU)");
	}
#endif /* IPV6_RECVPATHMTU */
#endif /* IPV6_USE_MIN_MTU */

#ifdef IPSEC
#ifdef IPSEC_POLICY_IPSEC
	if (options->f_policy) {
		if (setpolicy(vars.s, options->s_policy_in) < 0)
			errx(1, "%s", ipsec_strerror());
		if (setpolicy(vars.s, options->s_policy_out) < 0)
			errx(1, "%s", ipsec_strerror());
	}
#else
	if (options->f_authhdr) {
		optval = IPSEC_LEVEL_REQUIRE;
#ifdef IPV6_AUTH_TRANS_LEVEL
		if (setsockopt(s, IPPROTO_IPV6, IPV6_AUTH_TRANS_LEVEL,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt(IPV6_AUTH_TRANS_LEVEL)");
#else /* old def */
		if (setsockopt(s, IPPROTO_IPV6, IPV6_AUTH_LEVEL,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt(IPV6_AUTH_LEVEL)");
#endif
	}
	if (options->f_encrypt) {
		optval = IPSEC_LEVEL_REQUIRE;
		if (setsockopt(s, IPPROTO_IPV6, IPV6_ESP_TRANS_LEVEL,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt(IPV6_ESP_TRANS_LEVEL)");
	}
#endif /*IPSEC_POLICY_IPSEC*/
#endif

#ifdef ICMP6_FILTER
    {
	struct icmp6_filter filt;
	if (!options->f_verbose) {
		ICMP6_FILTER_SETBLOCKALL(&filt);
		if (options->f_fqdn || options->f_fqdn_old ||
		    options->f_nodeaddr || options->f_subtypes)
			ICMP6_FILTER_SETPASS(ICMP6_NI_REPLY, &filt);
		else
			ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
	} else {
		ICMP6_FILTER_SETPASSALL(&filt);
	}
	if (setsockopt(vars.s, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
	    sizeof(filt)) < 0)
		err(1, "setsockopt(ICMP6_FILTER)");
    }
#endif /*ICMP6_FILTER*/

	/* let the kerel pass extension headers of incoming packets */
	if (options->f_verbose) {
		int opton = 1;

#ifdef IPV6_RECVRTHDR
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_RECVRTHDR, &opton,
		    sizeof(opton)))
			err(1, "setsockopt(IPV6_RECVRTHDR)");
#else  /* old adv. API */
		if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_RTHDR, &opton,
		    sizeof(opton)))
			err(1, "setsockopt(IPV6_RTHDR)");
#endif
	}

/*
	optval = 1;
	if (IN6_IS_ADDR_MULTICAST(&dst.sin6_addr))
		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		    &optval, sizeof(optval)) == -1)
			err(1, "IPV6_MULTICAST_LOOP");
*/

	/* Specify the outgoing interface and/or the source address */
	if (options->f_interface)
		ip6optlen += CMSG_SPACE(sizeof(struct in6_pktinfo));

	if (options->f_hoplimit)
		ip6optlen += CMSG_SPACE(sizeof(int));

	/* set IP6 packet options */
	if (ip6optlen) {
		if ((scmsg = (char *)malloc(ip6optlen)) == NULL)
			errx(1, "can't allocate enough memory");
		vars.smsghdr.msg_control = (caddr_t)scmsg;
		vars.smsghdr.msg_controllen = ip6optlen;
		scmsgp = (struct cmsghdr *)scmsg;
	}
	if (options->f_interface) {
		pktinfo = (struct in6_pktinfo *)(CMSG_DATA(scmsgp));
		memset(pktinfo, 0, sizeof(*pktinfo));
		scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		scmsgp->cmsg_level = IPPROTO_IPV6;
		scmsgp->cmsg_type = IPV6_PKTINFO;
		scmsgp = CMSG_NXTHDR(&vars.smsghdr, scmsgp);
	}

	/* set the outgoing interface */
	if (options->s_interface) {
#ifndef USE_SIN6_SCOPE_ID
		/* pktinfo must have already been allocated */
		if ((pktinfo->ipi6_ifindex = if_nametoindex(options->s_interface)) == 0)
			errx(1, "%s: invalid interface name", options->s_interface);
#else
		if ((dst.sin6_scope_id = if_nametoindex(options->s_interface)) == 0)
			errx(1, "%s: invalid interface name", options->s_interface);
#endif
	}
	if (options->f_hoplimit) {
		scmsgp->cmsg_len = CMSG_LEN(sizeof(int));
		scmsgp->cmsg_level = IPPROTO_IPV6;
		scmsgp->cmsg_type = IPV6_HOPLIMIT;
		*(int *)(CMSG_DATA(scmsgp)) = options->n_hoplimit;

		scmsgp = CMSG_NXTHDR(&vars.smsghdr, scmsgp);
	}

	if (options->hop_count != 0) {	/* some intermediate addrs are specified */
		unsigned hops;
#ifdef USE_RFC2292BIS
		int rthdrlen;
#endif

#ifdef USE_RFC2292BIS
		rthdrlen = inet6_rth_space(IPV6_RTHDR_TYPE_0, options->hop_count);
		scmsgp->cmsg_len = CMSG_LEN(rthdrlen);
		scmsgp->cmsg_level = IPPROTO_IPV6;
		scmsgp->cmsg_type = IPV6_RTHDR;
		rthdr = (struct ip6_rthdr *)CMSG_DATA(scmsgp);
		rthdr = inet6_rth_init((void *)rthdr, rthdrlen,
		    IPV6_RTHDR_TYPE_0, options->hop_count);
		if (rthdr == NULL)
			errx(1, "can't initialize rthdr");
#else  /* old advanced API */
		if ((scmsgp = (struct cmsghdr *)inet6_rthdr_init(scmsgp,
		    IPV6_RTHDR_TYPE_0)) == NULL)
			errx(1, "can't initialize rthdr");
#endif /* USE_RFC2292BIS */

		for (hops = 0; hops < options->hop_count; hops++) {
			sin6 = (struct sockaddr_in6 *)(void *)options->hops_addrinfo[hops]->ai_addr;
#ifdef USE_RFC2292BIS
			if (inet6_rth_add(rthdr, &sin6->sin6_addr))
				errx(1, "can't add an intermediate node");
#else  /* old advanced API */
			if (inet6_rthdr_add(scmsg, &sin6->sin6_addr,
			    IPV6_RTHDR_LOOSE))
				errx(1, "can't add an intermediate node");
#endif /* USE_RFC2292BIS */
			freeaddrinfo(options->hops_addrinfo[hops]);
			options->hops_addrinfo[hops] = NULL;
		}

#ifndef USE_RFC2292BIS
		if (inet6_rthdr_lasthop(scmsgp, IPV6_RTHDR_LOOSE))
			errx(1, "can't set the last flag");
#endif

		scmsgp = CMSG_NXTHDR(&vars.smsghdr, scmsgp);
	}

	if (options->s_source == NULL) {
		/*
		 * get the source address. XXX since we revoked the root
		 * privilege, we cannot use a raw socket for this.
		 */
		int dummy;
		socklen_t len = sizeof(src);

		if ((dummy = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
			err(1, "UDP socket");

		src.sin6_family = AF_INET6;
		src.sin6_addr = vars.dst.sin6_addr;
		src.sin6_port = ntohs(DUMMY_PORT);
		src.sin6_scope_id = vars.dst.sin6_scope_id;

#ifdef USE_RFC2292BIS
		if (pktinfo &&
		    setsockopt(dummy, IPPROTO_IPV6, IPV6_PKTINFO,
		    (void *)pktinfo, sizeof(*pktinfo)))
			err(1, "UDP setsockopt(IPV6_PKTINFO)");

		if (options->f_hoplimit &&
		    setsockopt(dummy, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			(void *)&(options->n_hoplimit), sizeof(options->n_hoplimit)))
			err(1, "UDP setsockopt(IPV6_UNICAST_HOPS)");

		if (options->f_hoplimit &&
		    setsockopt(dummy, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			(void *)&(options->n_hoplimit), sizeof(options->n_hoplimit)))
			err(1, "UDP setsockopt(IPV6_MULTICAST_HOPS)");

		if (rthdr &&
		    setsockopt(dummy, IPPROTO_IPV6, IPV6_RTHDR,
		    (void *)rthdr, (rthdr->ip6r_len + 1) << 3))
			err(1, "UDP setsockopt(IPV6_RTHDR)");
#else  /* old advanced API */
		if (smsghdr.msg_control &&
		    setsockopt(dummy, IPPROTO_IPV6, IPV6_PKTOPTIONS,
		    (void *)smsghdr.msg_control, smsghdr.msg_controllen))
			err(1, "UDP setsockopt(IPV6_PKTOPTIONS)");
#endif

		if (connect(dummy, (struct sockaddr *)&src, len) < 0)
			err(1, "UDP connect");

		if (getsockname(dummy, (struct sockaddr *)&src, &len) < 0)
			err(1, "getsockname");

		close(dummy);
	}

#if defined(SO_SNDBUF) && defined(SO_RCVBUF)
	if (options->f_sock_buff_size) {
		if (options->n_packet_size > (long)options->n_sock_buff_size)
			warnx("you need -b to increase socket buffer size");
		if (setsockopt(vars.s, SOL_SOCKET, SO_SNDBUF, &(options->n_sock_buff_size),
		    sizeof(options->n_sock_buff_size)) < 0)
			err(1, "setsockopt(SO_SNDBUF)");
		if (setsockopt(vars.s, SOL_SOCKET, SO_RCVBUF, &(options->n_sock_buff_size),
		    sizeof(options->n_sock_buff_size)) < 0)
			err(1, "setsockopt(SO_RCVBUF)");
	}
	else {
		if (options->n_packet_size > 8 * 1024)	/*XXX*/
			warnx("you need -b to increase socket buffer size");
		/*
		 * When pinging the broadcast address, you can get a lot of
		 * answers. Doing something so evil is useful if you are trying
		 * to stress the ethernet, or just want to fill the arp cache
		 * to get some stuff for /etc/ethers.
		 */
		hold = 48 * 1024;
		setsockopt(vars.s, SOL_SOCKET, SO_RCVBUF, (char *)&hold,
		    sizeof(hold));
	}
#endif

	optval = 1;
#ifndef USE_SIN6_SCOPE_ID
#ifdef IPV6_RECVPKTINFO
	if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval,
	    sizeof(optval)) < 0)
		warn("setsockopt(IPV6_RECVPKTINFO)"); /* XXX err? */
#else  /* old adv. API */
	if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_PKTINFO, &optval,
	    sizeof(optval)) < 0)
		warn("setsockopt(IPV6_PKTINFO)"); /* XXX err? */
#endif
#endif /* USE_SIN6_SCOPE_ID */
#ifdef IPV6_RECVHOPLIMIT
	if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &optval,
	    sizeof(optval)) < 0)
		warn("setsockopt(IPV6_RECVHOPLIMIT)"); /* XXX err? */
#else  /* old adv. API */
	if (setsockopt(vars.s, IPPROTO_IPV6, IPV6_HOPLIMIT, &optval,
	    sizeof(optval)) < 0)
		warn("setsockopt(IPV6_HOPLIMIT)"); /* XXX err? */
#endif

	printf("PING6(%lu=40+8+%lu bytes) ", (unsigned long)(40 + pingerlen(options, sizeof(vars.dst.sin6_addr))),
	    (unsigned long)(pingerlen(options, sizeof(vars.dst.sin6_addr)) - 8));
	printf("%s --> ", pr_addr((struct sockaddr *)&src, sizeof(src), options->f_hostname));
	printf("%s\n", pr_addr((struct sockaddr *)&vars.dst, sizeof(vars.dst), options->f_hostname));

	if (options->n_preload == 0)
		pinger(options, &vars, &counters, &timing);
	else {
		if (options->n_packets != 0 && options->n_preload > options->n_packets)
			options->n_preload = options->n_packets;
		while (options->n_preload--)
			pinger(options, &vars, &counters, &timing);
	}
	gettimeofday(&last, NULL);

	sigemptyset(&si_sa.sa_mask);
	si_sa.sa_flags = 0;
	si_sa.sa_handler = onsignal;
	if (sigaction(SIGINT, &si_sa, 0) == -1)
		err(EX_OSERR, "sigaction SIGINT");
	seenint = 0;
#ifdef SIGINFO
	if (sigaction(SIGINFO, &si_sa, 0) == -1)
		err(EX_OSERR, "sigaction SIGINFO");
	seeninfo = 0;
#endif
	if (options->n_alarm_timeout > 0) {
		if (sigaction(SIGALRM, &si_sa, 0) == -1)
			err(EX_OSERR, "sigaction SIGALRM");
	}
	if (options->f_flood) {
		intvl.tv_sec = 0;
		intvl.tv_usec = 10000;
	} else if (!options->f_interval) {
		intvl.tv_sec = options->n_interval / 1000;
		intvl.tv_usec = (int)options->n_interval % 1000 * 1000;
	}

	almost_done = 0;
	while (seenint == 0) {
		struct timeval now, timeout;
		struct msghdr m;
		struct iovec iov[2];
		fd_set rfds;
		int n;

		/* signal handling */
		if (seenint)
			onint(SIGINT);
#ifdef SIGINFO
		if (seeninfo) {
			summary(&counters, &timing, vars.hostname);
			seeninfo = 0;
			continue;
		}
#endif
		FD_ZERO(&rfds);
		FD_SET(vars.s, &rfds);
		gettimeofday(&now, NULL);
		timeout.tv_sec = last.tv_sec + intvl.tv_sec - now.tv_sec;
		timeout.tv_usec = last.tv_usec + intvl.tv_usec - now.tv_usec;
		while (timeout.tv_usec < 0) {
			timeout.tv_usec += 1000000;
			timeout.tv_sec--;
		}
		while (timeout.tv_usec > 1000000) {
			timeout.tv_usec -= 1000000;
			timeout.tv_sec++;
		}
		if (timeout.tv_sec < 0)
			timeout.tv_sec = timeout.tv_usec = 0;

		n = select(vars.s + 1, &rfds, NULL, NULL, &timeout);
		if (n < 0)
			continue;	/* EINTR */
		if (n == 1) {
			m.msg_name = (caddr_t)&from;
			m.msg_namelen = sizeof(from);
			memset(&iov, 0, sizeof(iov));
			iov[0].iov_base = (caddr_t)vars.packet;
			iov[0].iov_len = packlen;
			m.msg_iov = iov;
			m.msg_iovlen = 1;
			memset(cm, 0, CONTROLLEN);
			m.msg_control = (void *)cm;
			m.msg_controllen = CONTROLLEN;

			cc = recvmsg(vars.s, &m, 0);
			if (cc < 0) {
				if (errno != EINTR) {
					warn("recvmsg");
					sleep(1);
				}
				continue;
			} else if (cc == 0) {
				int mtu;

				/*
				 * receive control messages only. Process the
				 * exceptions (currently the only possibility is
				 * a path MTU notification.)
				 */
				if ((mtu = get_pathmtu(&m, options, &vars.dst)) > 0) {
					if (options->f_verbose) {
						printf("new path MTU (%d) is "
						    "notified\n", mtu);
					}
				}
				continue;
			} else {
				/*
				 * an ICMPv6 message (probably an echoreply)
				 * arrived.
				 */
				pr_pack(vars.packet, cc, &m, options, &vars, &counters, &timing);
			}
			if ((options->f_once != 0 && counters.nreceived > 0) ||
			    (options->n_packets > 0 && counters.nreceived >= options->n_packets))
				break;
		}
		if (n == 0 || options->f_flood) {
			if (options->n_packets == 0 || counters.ntransmitted < options->n_packets)
				pinger(options, &vars, &counters, &timing);
			else {
				if (almost_done)
					break;
				almost_done = 1;
			/*
			 * If we're not transmitting any more packets,
			 * change the timer to wait two round-trip times
			 * if we've received any packets or (options->n_wait_time)
			 * milliseconds if we haven't.
			 */
				intvl.tv_usec = 0;
				if (counters.nreceived) {
					intvl.tv_sec = 2 * timing.max / 1000;
					if (intvl.tv_sec == 0)
						intvl.tv_sec = 1;
				} else {
					intvl.tv_sec = options->n_wait_time / 1000;
					intvl.tv_usec = options->n_wait_time % 1000 * 1000;
				}
			}
			gettimeofday(&last, NULL);
			if (counters.ntransmitted - counters.nreceived - 1 > counters.nmissedmax) {
				counters.nmissedmax = counters.ntransmitted - counters.nreceived - 1;
				if (options->f_missed)
					write_char(STDOUT_FILENO, BBELL);
			}
		}
	}
	sigemptyset(&si_sa.sa_mask);
	si_sa.sa_flags = 0;
	si_sa.sa_handler = SIG_IGN;
	sigaction(SIGINT, &si_sa, 0);
	sigaction(SIGALRM, &si_sa, 0);
	summary(&counters, &timing, vars.hostname);

        if(vars.packet != NULL)
                free(vars.packet);

	exit(counters.nreceived == 0 ? 2 : 0);
}

static void
onsignal(int sig)
{

	switch (sig) {
	case SIGINT:
	case SIGALRM:
		seenint++;
		break;
#ifdef SIGINFO
	case SIGINFO:
		seeninfo++;
		break;
#endif
	}
}

/*
 * pinger --
 *	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
static size_t
pingerlen(const struct options *const options, size_t sin6_addr_size)
{
	size_t l;

	if (options->f_fqdn)
		l = ICMP6_NIQLEN + sin6_addr_size;
	else if (options->f_fqdn_old)
		l = ICMP6_NIQLEN;
	else if (options->f_nodeaddr)
		l = ICMP6_NIQLEN + sin6_addr_size;
	else if (options->f_subtypes)
		l = ICMP6_NIQLEN;
	else
		l = ICMP6ECHOLEN + options->n_packet_size;

	return l;
}

static int
pinger(struct options *const options, struct shared_variables *const vars,
    struct counters *const counters ,struct timing *const timing)
{
	struct icmp6_hdr *icp;
	struct iovec iov[2];
	int i, cc;
	struct icmp6_nodeinfo *nip;
	int seq;

	if (options->n_packets && counters->ntransmitted >= options->n_packets)
		return(-1);	/* no more transmission */

	icp = (struct icmp6_hdr *)vars->outpack;
	nip = (struct icmp6_nodeinfo *)vars->outpack;
	memset(icp, 0, sizeof(*icp));
	icp->icmp6_cksum = 0;
	seq = counters->ntransmitted++;
	BIT_ARRAY_CLR(vars->rcvd_tbl, seq % MAX_DUP_CHK);

	if (options->f_fqdn) {
		icp->icmp6_type = ICMP6_NI_QUERY;
		icp->icmp6_code = ICMP6_NI_SUBJ_IPV6;
		nip->ni_qtype = htons(NI_QTYPE_FQDN);
		nip->ni_flags = htons(0);

		memcpy(nip->icmp6_ni_nonce, vars->nonce,
		    sizeof(nip->icmp6_ni_nonce));
		*(u_int16_t *)nip->icmp6_ni_nonce = ntohs(seq);

		memcpy(&vars->outpack[ICMP6_NIQLEN], &vars->dst.sin6_addr,
		    sizeof(vars->dst.sin6_addr));
		cc = ICMP6_NIQLEN + sizeof(vars->dst.sin6_addr);
		options->n_packet_size = 0;
	} else if (options->f_fqdn_old) {
		/* packet format in 03 draft - no Subject data on queries */
		icp->icmp6_type = ICMP6_NI_QUERY;
		icp->icmp6_code = 0;	/* code field is always 0 */
		nip->ni_qtype = htons(NI_QTYPE_FQDN);
		nip->ni_flags = htons(0);

		memcpy(nip->icmp6_ni_nonce, vars->nonce,
		    sizeof(nip->icmp6_ni_nonce));
		*(u_int16_t *)nip->icmp6_ni_nonce = ntohs(seq);

		cc = ICMP6_NIQLEN;
		options->n_packet_size = 0;
	} else if (options->f_nodeaddr) {
		icp->icmp6_type = ICMP6_NI_QUERY;
		icp->icmp6_code = ICMP6_NI_SUBJ_IPV6;
		nip->ni_qtype = htons(NI_QTYPE_NODEADDR);
		nip->ni_flags = get_node_address_flags(options);

		memcpy(nip->icmp6_ni_nonce, vars->nonce,
		    sizeof(nip->icmp6_ni_nonce));
		*(u_int16_t *)nip->icmp6_ni_nonce = ntohs(seq);

		memcpy(&vars->outpack[ICMP6_NIQLEN], &vars->dst.sin6_addr,
		    sizeof(vars->dst.sin6_addr));
		cc = ICMP6_NIQLEN + sizeof(vars->dst.sin6_addr);
		options->n_packet_size = 0;
	} else if (options->f_subtypes) {
		icp->icmp6_type = ICMP6_NI_QUERY;
		icp->icmp6_code = ICMP6_NI_SUBJ_FQDN;	/*empty*/
		nip->ni_qtype = htons(NI_QTYPE_SUPTYPES);
		/* we support compressed bitmap */
		nip->ni_flags = NI_SUPTYPE_FLAG_COMPRESS;

		memcpy(nip->icmp6_ni_nonce, vars->nonce,
		    sizeof(nip->icmp6_ni_nonce));
		*(u_int16_t *)nip->icmp6_ni_nonce = ntohs(seq);
		cc = ICMP6_NIQLEN;
		options->n_packet_size = 0;
	} else {
		icp->icmp6_type = ICMP6_ECHO_REQUEST;
		icp->icmp6_code = 0;
		icp->icmp6_id = htons(vars->ident);
		icp->icmp6_seq = ntohs(seq);
		if (timing->enabled) {
			struct timeval tv;
			struct tv32 *tv32;
			(void)gettimeofday(&tv, NULL);
			tv32 = (struct tv32 *)&vars->outpack[ICMP6ECHOLEN];
			tv32->tv32_sec = htonl(tv.tv_sec);
			tv32->tv32_usec = htonl(tv.tv_usec);
		}
		cc = ICMP6ECHOLEN + options->n_packet_size;
	}

#ifdef DIAGNOSTIC
	if (pingerlen() != cc)
		errx(1, "internal error; length mismatch");
#endif

	vars->smsghdr.msg_name = (caddr_t)&vars->dst;
	vars->smsghdr.msg_namelen = sizeof(vars->dst);
	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = (caddr_t)vars->outpack;
	iov[0].iov_len = cc;
	vars->smsghdr.msg_iov = iov;
	vars->smsghdr.msg_iovlen = 1;

	i = sendmsg(vars->s, &vars->smsghdr, 0);

	if (i < 0 || i != cc)  {
		if (i < 0)
			warn("sendmsg");
		(void)printf("ping6: wrote %s %d chars, ret=%d\n",
		    vars->hostname, cc, i);
	}
	if (!options->f_quiet && options->f_flood)
		write_char(STDOUT_FILENO, DOT);

	return(0);
}

static int
myechoreply(const struct icmp6_hdr *icp, int ident)
{
	if (ntohs(icp->icmp6_id) == ident)
		return 1;
	else
		return 0;
}

static int
mynireply(const struct icmp6_nodeinfo *nip, const struct shared_variables *const vars)
{
	if (memcmp(nip->icmp6_ni_nonce + sizeof(u_int16_t),
	    vars->nonce + sizeof(u_int16_t),
	    sizeof(vars->nonce) - sizeof(u_int16_t)) == 0)
		return 1;
	else
		return 0;
}

static char *
dnsdecode(const u_char **sp, const u_char *ep, const u_char *base, char *buf,
	size_t bufsiz)
	/*base for compressed name*/
{
	int i;
	const u_char *cp;
	char cresult[MAXDNAME + 1];
	const u_char *comp;
	int l;

	cp = *sp;
	*buf = '\0';

	if (cp >= ep)
		return NULL;
	while (cp < ep) {
		i = *cp;
		if (i == 0 || cp != *sp) {
			if (strlcat((char *)buf, ".", bufsiz) >= bufsiz)
				return NULL;	/*result overrun*/
		}
		if (i == 0)
			break;
		cp++;

		if ((i & 0xc0) == 0xc0 && cp - base > (i & 0x3f)) {
			/* DNS compression */
			if (!base)
				return NULL;

			comp = base + (i & 0x3f);
			if (dnsdecode(&comp, cp, base, cresult,
			    sizeof(cresult)) == NULL)
				return NULL;
			if (strlcat(buf, cresult, bufsiz) >= bufsiz)
				return NULL;	/*result overrun*/
			break;
		} else if ((i & 0x3f) == i) {
			if (i > ep - cp)
				return NULL;	/*source overrun*/
			while (i-- > 0 && cp < ep) {
				l = snprintf(cresult, sizeof(cresult),
				    isprint(*cp) ? "%c" : "\\%03o", *cp & 0xff);
				if ((size_t)l >= sizeof(cresult) || l < 0)
					return NULL;
				if (strlcat(buf, cresult, bufsiz) >= bufsiz)
					return NULL;	/*result overrun*/
				cp++;
			}
		} else
			return NULL;	/*invalid label*/
	}
	if (i != 0)
		return NULL;	/*not terminated*/
	cp++;
	*sp = cp;
	return buf;
}

/*
 * pr_pack --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
static void
pr_pack(u_char *buf, int cc, struct msghdr *mhdr, const struct options *const options,
    struct shared_variables *const vars, struct counters *const counters,
    struct timing *const timing)
{
#define safeputc(c)	printf((isprint((c)) ? "%c" : "\\%03o"), c)
	struct icmp6_hdr *icp;
	struct icmp6_nodeinfo *ni;
	int i;
	int hoplim;
	struct sockaddr *from;
	int fromlen;
	u_char *cp = NULL, *dp, *end = buf + cc;
	struct in6_pktinfo *pktinfo = NULL;
	struct timeval tv, tp;
	struct tv32 *tpp;
	double triptime = 0;
	int dupflag;
	size_t off;
	int oldfqdn;
	u_int16_t seq;
	char dnsname[MAXDNAME + 1];

	(void)gettimeofday(&tv, NULL);

	if (!mhdr || !mhdr->msg_name ||
	    mhdr->msg_namelen != sizeof(struct sockaddr_in6) ||
	    ((struct sockaddr *)mhdr->msg_name)->sa_family != AF_INET6) {
		if (options->f_verbose)
			warnx("invalid peername");
		return;
	}
	from = (struct sockaddr *)mhdr->msg_name;
	fromlen = mhdr->msg_namelen;
	if (cc < (int)sizeof(struct icmp6_hdr)) {
		if (options->f_verbose)
			warnx("packet too short (%d bytes) from %s", cc,
			    pr_addr(from, fromlen, options->f_hostname));
		return;
	}
	if (((mhdr->msg_flags & MSG_CTRUNC) != 0) &&
	    options->f_verbose)
		warnx("some control data discarded, insufficient buffer size");
	icp = (struct icmp6_hdr *)buf;
	ni = (struct icmp6_nodeinfo *)buf;
	off = 0;

	if ((hoplim = get_hoplim(mhdr)) == -1) {
		warnx("failed to get receiving hop limit");
		return;
	}
	if ((pktinfo = get_rcvpktinfo(mhdr)) == NULL) {
		warnx("failed to get receiving packet information");
		return;
	}

	if (icp->icmp6_type == ICMP6_ECHO_REPLY && myechoreply(icp, vars->ident)) {
		seq = ntohs(icp->icmp6_seq);
		++(counters->nreceived);
		if (timing->enabled) {
			tpp = (struct tv32 *)(icp + 1);
			tp.tv_sec = ntohl(tpp->tv32_sec);
			tp.tv_usec = ntohl(tpp->tv32_usec);
			tvsub(&tv, &tp);
			triptime = ((double)tv.tv_sec) * 1000.0 +
			    ((double)tv.tv_usec) / 1000.0;
			timing->sum += triptime;
			timing->sumsq += triptime * triptime;
			if (triptime < timing->min)
				timing->min = triptime;
			if (triptime > timing->max)
				timing->max = triptime;
		}

		if (BIT_ARRAY_IS_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK)) {
			++(counters->nrepeats);
			--(counters->nreceived);
			dupflag = 1;
		} else {
			BIT_ARRAY_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK);
			dupflag = 0;
		}

		if (options->f_quiet)
			return;

		if (options->f_wait_time && triptime > options->n_wait_time) {
			++(counters->nrcvtimeout);
			return;
		}

		if (options->f_flood)
			write_char(STDOUT_FILENO, BSPACE);
		else {
			if (options->f_audible)
				write_char(STDOUT_FILENO, BBELL);
			(void)printf("%d bytes from %s, icmp_seq=%u", cc,
			    pr_addr(from, fromlen, options->f_hostname), seq);
			(void)printf(" hlim=%d", hoplim);
			if (options->f_verbose) {
				struct sockaddr_in6 dstsa;

				memset(&dstsa, 0, sizeof(dstsa));
				dstsa.sin6_family = AF_INET6;
				dstsa.sin6_len = sizeof(dstsa);
				dstsa.sin6_scope_id = pktinfo->ipi6_ifindex;
				dstsa.sin6_addr = pktinfo->ipi6_addr;
				(void)printf(" dst=%s",
				    pr_addr((struct sockaddr *)&dstsa,
					sizeof(dstsa), options->f_hostname));
			}
			if (timing->enabled)
				(void)printf(" time=%.3f ms", triptime);
			if (dupflag)
				(void)printf("(DUP!)");
			/* check the data */
			cp = buf + off + ICMP6ECHOLEN + ICMP6ECHOTMLEN;
			dp = vars->outpack + ICMP6ECHOLEN + ICMP6ECHOTMLEN;
			for (i = 8; cp < end; ++i, ++cp, ++dp) {
				if (*cp != *dp) {
					(void)printf("\nwrong data byte #%d should be 0x%x but was 0x%x", i, *dp, *cp);
					break;
				}
			}
		}
	} else if (icp->icmp6_type == ICMP6_NI_REPLY && mynireply(ni, vars)) {
		seq = ntohs(*(u_int16_t *)ni->icmp6_ni_nonce);
		++(counters->nreceived);
		if (BIT_ARRAY_IS_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK)) {
			++(counters->nrepeats);
			--(counters->nreceived);
			dupflag = 1;
		} else {
			BIT_ARRAY_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK);
			dupflag = 0;
		}

		if (options->f_quiet)
			return;

		(void)printf("%d bytes from %s: ", cc, pr_addr(from, fromlen, options->f_hostname));

		switch (ntohs(ni->ni_code)) {
		case ICMP6_NI_SUCCESS:
			break;
		case ICMP6_NI_REFUSED:
			printf("refused, type 0x%x", ntohs(ni->ni_type));
			goto fqdnend;
		case ICMP6_NI_UNKNOWN:
			printf("unknown, type 0x%x", ntohs(ni->ni_type));
			goto fqdnend;
		default:
			printf("unknown code 0x%x, type 0x%x",
			    ntohs(ni->ni_code), ntohs(ni->ni_type));
			goto fqdnend;
		}

		switch (ntohs(ni->ni_qtype)) {
		case NI_QTYPE_NOOP:
			printf("NodeInfo NOOP");
			break;
		case NI_QTYPE_SUPTYPES:
			pr_suptypes(ni, end - (u_char *)ni, options->f_verbose);
			break;
		case NI_QTYPE_NODEADDR:
			pr_nodeaddr(ni, end - (u_char *)ni, options->f_verbose);
			break;
		case NI_QTYPE_FQDN:
		default:	/* XXX: for backward compatibility */
			cp = (u_char *)ni + ICMP6_NIRLEN;
			if (buf[off + ICMP6_NIRLEN] ==
			    cc - off - ICMP6_NIRLEN - 1)
				oldfqdn = 1;
			else
				oldfqdn = 0;
			if (oldfqdn) {
				cp++;	/* skip length */
				while (cp < end) {
					safeputc(*cp & 0xff);
					cp++;
				}
			} else {
				i = 0;
				while (cp < end) {
					if (dnsdecode((const u_char **)&cp, end,
					    (const u_char *)(ni + 1), dnsname,
					    sizeof(dnsname)) == NULL) {
						printf("???");
						break;
					}
					/*
					 * name-lookup special handling for
					 * truncated name
					 */
					if (cp + 1 <= end && !*cp &&
					    strlen(dnsname) > 0) {
						dnsname[strlen(dnsname) - 1] = '\0';
						cp++;
					}
					printf("%s%s", i > 0 ? "," : "",
					    dnsname);
				}
			}
			if (options->f_verbose) {
				int32_t ttl;
				int comma = 0;

				(void)printf(" (");	/*)*/

				switch (ni->ni_code) {
				case ICMP6_NI_REFUSED:
					(void)printf("refused");
					comma++;
					break;
				case ICMP6_NI_UNKNOWN:
					(void)printf("unknown qtype");
					comma++;
					break;
				}

				if ((end - (u_char *)ni) < ICMP6_NIRLEN) {
					/* case of refusion, unknown */
					/*(*/
					printf(")");
					goto fqdnend;
				}
				ttl = (int32_t)ntohl(*(u_long *)&buf[off+ICMP6ECHOLEN+8]);
				if (comma)
					printf(",");
				if (!(ni->ni_flags & NI_FQDN_FLAG_VALIDTTL)) {
					(void)printf("TTL=%d:meaningless",
					    (int)ttl);
				} else {
					if (ttl < 0) {
						(void)printf("TTL=%d:invalid",
						   ttl);
					} else
						(void)printf("TTL=%d", ttl);
				}
				comma++;

				if (oldfqdn) {
					if (comma)
						printf(",");
					printf("03 draft");
					comma++;
				} else {
					cp = (u_char *)ni + ICMP6_NIRLEN;
					if (cp == end) {
						if (comma)
							printf(",");
						printf("no name");
						comma++;
					}
				}

				if (buf[off + ICMP6_NIRLEN] !=
				    cc - off - ICMP6_NIRLEN - 1 && oldfqdn) {
					if (comma)
						printf(",");
					(void)printf("invalid namelen:%d/%lu",
					    buf[off + ICMP6_NIRLEN],
					    (u_long)cc - off - ICMP6_NIRLEN - 1);
					comma++;
				}
				/*(*/
				printf("\n");
			}
		fqdnend:
			;
		}
	} else {
		/* We've got something other than an ECHOREPLY */
		if (!options->f_verbose)
			return;
		(void)printf("%d bytes from %s: ", cc, pr_addr(from, fromlen, options->f_hostname));
		pr_icmph(icp, end, options->f_verbose);
	}

	if (!options->f_flood) {
		(void)printf("\n");
		if (options->f_verbose)
			pr_exthdrs(mhdr);
		(void)fflush(stdout);
	}
#undef safeputc
}

static void
pr_exthdrs(struct msghdr *mhdr)
{
	ssize_t	bufsize;
	void	*bufp;
	struct cmsghdr *cm;

	bufsize = 0;
	bufp = mhdr->msg_control;
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(mhdr); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(mhdr, cm)) {
		if (cm->cmsg_level != IPPROTO_IPV6)
			continue;

		bufsize = CONTROLLEN - ((caddr_t)CMSG_DATA(cm) - (caddr_t)bufp);
		if (bufsize <= 0)
			continue; 
		switch (cm->cmsg_type) {
		case IPV6_HOPOPTS:
			printf("  HbH Options: ");
			pr_ip6opt(CMSG_DATA(cm), (size_t)bufsize);
			break;
		case IPV6_DSTOPTS:
#ifdef IPV6_RTHDRDSTOPTS
		case IPV6_RTHDRDSTOPTS:
#endif
			printf("  Dst Options: ");
			pr_ip6opt(CMSG_DATA(cm), (size_t)bufsize);
			break;
		case IPV6_RTHDR:
			printf("  Routing: ");
			pr_rthdr(CMSG_DATA(cm), (size_t)bufsize);
			break;
		}
	}
}

#ifdef USE_RFC2292BIS
static void
pr_ip6opt(void *extbuf, size_t bufsize)
{
	struct ip6_hbh *ext;
	int currentlen;
	u_int8_t type;
	socklen_t extlen, len;
	void *databuf;
	size_t offset;
	u_int16_t value2;
	u_int32_t value4;

	ext = (struct ip6_hbh *)extbuf;
	extlen = (ext->ip6h_len + 1) * 8;
	printf("nxt %u, len %u (%lu bytes)\n", ext->ip6h_nxt,
	    (unsigned int)ext->ip6h_len, (unsigned long)extlen);

	/*
	 * Bounds checking on the ancillary data buffer:
	 *     subtract the size of a cmsg structure from the buffer size.
	 */
	if (bufsize < (extlen  + CMSG_SPACE(0))) {
		extlen = bufsize - CMSG_SPACE(0);
		warnx("options truncated, showing only %u (total=%u)",
		    (unsigned int)(extlen / 8 - 1),
		    (unsigned int)(ext->ip6h_len));
	}

	currentlen = 0;
	while (1) {
		currentlen = inet6_opt_next(extbuf, extlen, currentlen,
		    &type, &len, &databuf);
		if (currentlen == -1)
			break;
		switch (type) {
		/*
		 * Note that inet6_opt_next automatically skips any padding
		 * optins.
		 */
		case IP6OPT_JUMBO:
			offset = 0;
			offset = inet6_opt_get_val(databuf, offset,
			    &value4, sizeof(value4));
			printf("    Jumbo Payload Opt: Length %u\n",
			    (u_int32_t)ntohl(value4));
			break;
		case IP6OPT_ROUTER_ALERT:
			offset = 0;
			offset = inet6_opt_get_val(databuf, offset,
						   &value2, sizeof(value2));
			printf("    Router Alert Opt: Type %u\n",
			    ntohs(value2));
			break;
		default:
			printf("    Received Opt %u len %lu\n",
			    type, (unsigned long)len);
			break;
		}
	}
	return;
}
#else  /* !USE_RFC2292BIS */
/* ARGSUSED */
static void
pr_ip6opt(void *extbuf, size_t bufsize __unused)
{
	printf("\n");
	return;
}
#endif /* USE_RFC2292BIS */

#ifdef USE_RFC2292BIS
static void
pr_rthdr(void *extbuf, size_t bufsize)
{
	struct in6_addr *in6;
	char ntopbuf[INET6_ADDRSTRLEN];
	struct ip6_rthdr *rh = (struct ip6_rthdr *)extbuf;
	int i, segments, origsegs, rthsize, size0, size1;

	/* print fixed part of the header */
	printf("nxt %u, len %u (%d bytes), type %u, ", rh->ip6r_nxt,
	    rh->ip6r_len, (rh->ip6r_len + 1) << 3, rh->ip6r_type);
	if ((segments = inet6_rth_segments(extbuf)) >= 0) {
		printf("%d segments, ", segments);
		printf("%d left\n", rh->ip6r_segleft);
	} else {
		printf("segments unknown, ");
		printf("%d left\n", rh->ip6r_segleft);
		return;
	}

	/*
	 * Bounds checking on the ancillary data buffer. When calculating
	 * the number of items to show keep in mind:
	 *	- The size of the cmsg structure
	 *	- The size of one segment (the size of a Type 0 routing header)
	 *	- When dividing add a fudge factor of one in case the
	 *	  dividend is not evenly divisible by the divisor
	 */
	rthsize = (rh->ip6r_len + 1) * 8;
	if (bufsize < (rthsize + CMSG_SPACE(0))) {
		origsegs = segments;
		size0 = inet6_rth_space(IPV6_RTHDR_TYPE_0, 0);
		size1 = inet6_rth_space(IPV6_RTHDR_TYPE_0, 1);
		segments -= (rthsize - (bufsize - CMSG_SPACE(0))) /
		    (size1 - size0) + 1;
		warnx("segments truncated, showing only %d (total=%d)",
		    segments, origsegs);
	}

	for (i = 0; i < segments; i++) {
		in6 = inet6_rth_getaddr(extbuf, i);
		if (in6 == NULL)
			printf("   [%d]<NULL>\n", i);
		else {
			if (!inet_ntop(AF_INET6, in6, ntopbuf,
			    sizeof(ntopbuf)))
				strlcpy(ntopbuf, "?", sizeof(ntopbuf));
			printf("   [%d]%s\n", i, ntopbuf);
		}
	}

	return;

}

#else  /* !USE_RFC2292BIS */
/* ARGSUSED */
static void
pr_rthdr(void *extbuf, size_t bufsize __unused)
{
	printf("\n");
	return;
}
#endif /* USE_RFC2292BIS */

static int
pr_bitrange(u_int32_t v, int soff, int ii)
{
	int off;
	int i;

	off = 0;
	while (off < 32) {
		/* shift till we have 0x01 */
		if ((v & 0x01) == 0) {
			if (ii > 1)
				printf("-%u", soff + off - 1);
			ii = 0;
			switch (v & 0x0f) {
			case 0x00:
				v >>= 4;
				off += 4;
				continue;
			case 0x08:
				v >>= 3;
				off += 3;
				continue;
			case 0x04: case 0x0c:
				v >>= 2;
				off += 2;
				continue;
			default:
				v >>= 1;
				off += 1;
				continue;
			}
		}

		/* we have 0x01 with us */
		for (i = 0; i < 32 - off; i++) {
			if ((v & (0x01 << i)) == 0)
				break;
		}
		if (!ii)
			printf(" %u", soff + off);
		ii += i;
		v >>= i; off += i;
	}
	return ii;
}

static void
pr_suptypes(struct icmp6_nodeinfo *ni, size_t nilen, bool verbose)
	/* ni->qtype must be SUPTYPES */
{
	size_t clen;
	u_int32_t v;
	const u_char *cp, *end;
	u_int16_t cur;
	struct cbit {
		u_int16_t words;	/*32bit count*/
		u_int16_t skip;
	} cbit;
#define MAXQTYPES	(1 << 16)
	size_t off;
	int b;

	cp = (u_char *)(ni + 1);
	end = ((u_char *)ni) + nilen;
	cur = 0;
	b = 0;

	printf("NodeInfo Supported Qtypes");
	if (verbose) {
		if (ni->ni_flags & NI_SUPTYPE_FLAG_COMPRESS)
			printf(", compressed bitmap");
		else
			printf(", raw bitmap");
	}

	while (cp < end) {
		clen = (size_t)(end - cp);
		if ((ni->ni_flags & NI_SUPTYPE_FLAG_COMPRESS) == 0) {
			if (clen == 0 || clen > MAXQTYPES / 8 ||
			    clen % sizeof(v)) {
				printf("???");
				return;
			}
		} else {
			if (clen < sizeof(cbit) || clen % sizeof(v))
				return;
			memcpy(&cbit, cp, sizeof(cbit));
			if (sizeof(cbit) + ntohs(cbit.words) * sizeof(v) >
			    clen)
				return;
			cp += sizeof(cbit);
			clen = ntohs(cbit.words) * sizeof(v);
			if (cur + clen * 8 + (u_long)ntohs(cbit.skip) * 32 >
			    MAXQTYPES)
				return;
		}

		for (off = 0; off < clen; off += sizeof(v)) {
			memcpy(&v, cp + off, sizeof(v));
			v = (u_int32_t)ntohl(v);
			b = pr_bitrange(v, (int)(cur + off * 8), b);
		}
		/* flush the remaining bits */
		b = pr_bitrange(0, (int)(cur + off * 8), b);

		cp += clen;
		cur += clen * 8;
		if ((ni->ni_flags & NI_SUPTYPE_FLAG_COMPRESS) != 0)
			cur += ntohs(cbit.skip) * 32;
	}
}

static void
pr_nodeaddr(struct icmp6_nodeinfo *ni, int nilen, bool verbose)
	/* ni->qtype must be NODEADDR */
{
	u_char *cp = (u_char *)(ni + 1);
	char ntop_buf[INET6_ADDRSTRLEN];
	int withttl = 0;

	nilen -= sizeof(struct icmp6_nodeinfo);

	if (verbose) {
		switch (ni->ni_code) {
		case ICMP6_NI_REFUSED:
			(void)printf("refused");
			break;
		case ICMP6_NI_UNKNOWN:
			(void)printf("unknown qtype");
			break;
		}
		if (ni->ni_flags & NI_NODEADDR_FLAG_TRUNCATE)
			(void)printf(" truncated");
	}
	printf("\n");
	if (nilen <= 0)
		printf("  no address\n");

	/*
	 * In icmp-name-lookups 05 and later, TTL of each returned address
	 * is contained in the resposne. We try to detect the version
	 * by the length of the data, but note that the detection algorithm
	 * is incomplete. We assume the latest draft by default.
	 */
	if (nilen % (sizeof(u_int32_t) + sizeof(struct in6_addr)) == 0)
		withttl = 1;
	while (nilen > 0) {
		u_int32_t ttl;

		if (withttl) {
			/* XXX: alignment? */
			ttl = (u_int32_t)ntohl(*(u_int32_t *)cp);
			cp += sizeof(u_int32_t);
			nilen -= sizeof(u_int32_t);
		}

		if (inet_ntop(AF_INET6, cp, ntop_buf, sizeof(ntop_buf)) ==
		    NULL)
			strlcpy(ntop_buf, "?", sizeof(ntop_buf));
		printf("  %s", ntop_buf);
		if (withttl) {
			if (ttl == 0xffffffff) {
				/*
				 * XXX: can this convention be applied to all
				 * type of TTL (i.e. non-ND TTL)?
				 */
				printf("(TTL=infty)");
			}
			else
				printf("(TTL=%u)", ttl);
		}
		printf("\n");

		nilen -= sizeof(struct in6_addr);
		cp += sizeof(struct in6_addr);
	}
}

static int
get_hoplim(struct msghdr *mhdr)
{
	struct cmsghdr *cm;

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(mhdr); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(mhdr, cm)) {
		if (cm->cmsg_len == 0)
			return(-1);

		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_HOPLIMIT &&
		    cm->cmsg_len == CMSG_LEN(sizeof(int)))
			return(*(int *)CMSG_DATA(cm));
	}

	return(-1);
}

static struct in6_pktinfo *
get_rcvpktinfo(struct msghdr *mhdr)
{
	struct cmsghdr *cm;

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(mhdr); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(mhdr, cm)) {
		if (cm->cmsg_len == 0)
			return(NULL);

		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))
			return((struct in6_pktinfo *)CMSG_DATA(cm));
	}

	return(NULL);
}

static int
get_pathmtu(struct msghdr *mhdr, const struct options *const options, const struct sockaddr_in6 *const dst)
{
#ifdef IPV6_RECVPATHMTU
	struct cmsghdr *cm;
	struct ip6_mtuinfo *mtuctl = NULL;

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(mhdr); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(mhdr, cm)) {
		if (cm->cmsg_len == 0)
			return(0);

		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PATHMTU &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct ip6_mtuinfo))) {
			mtuctl = (struct ip6_mtuinfo *)CMSG_DATA(cm);

			/*
			 * If the notified destination is different from
			 * the one we are pinging, just ignore the info.
			 * We check the scope ID only when both notified value
			 * and our own value have non-0 values, because we may
			 * have used the default scope zone ID for sending,
			 * in which case the scope ID value is 0.
			 */
			if (!IN6_ARE_ADDR_EQUAL(&mtuctl->ip6m_addr.sin6_addr,
						&dst->sin6_addr) ||
			    (mtuctl->ip6m_addr.sin6_scope_id &&
			     dst->sin6_scope_id &&
			     mtuctl->ip6m_addr.sin6_scope_id !=
			     dst->sin6_scope_id)) {
				if (options->f_verbose) {
					printf("path MTU for %s is notified. "
					       "(ignored)\n",
					   pr_addr((struct sockaddr *)&mtuctl->ip6m_addr,
					       sizeof(mtuctl->ip6m_addr), options->f_hostname));
				}
				return(0);
			}

			/*
			 * Ignore an invalid MTU. XXX: can we just believe
			 * the kernel check?
			 */
			if (mtuctl->ip6m_mtu < IPV6_MMTU)
				return(0);

			/* notification for our destination. return the MTU. */
			return((int)mtuctl->ip6m_mtu);
		}
	}
#endif
	return(0);
}

/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static void
tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

/*
 * onint --
 *	SIGINT handler.
 */
/* ARGSUSED */
static void
onint(int notused __unused)
{
	/*
	 * When doing reverse DNS lookups, the seenint flag might not
	 * be noticed for a while.  Just exit if we get a second SIGINT.
	 */
	if (sig_option_f_hostname && seenint != 0)
		_exit(((sig_counters_nreceived != NULL) && (*sig_counters_nreceived != 0)) ? 0 : 2);
}

/*
 * summary --
 *	Print out statistics.
 */
static void
summary(const struct counters *const counters, const struct timing *const timing, const char *const hostname)
{

	(void)printf("\n--- %s ping6 statistics ---\n", hostname);
	(void)printf("%ld packets transmitted, ", counters->ntransmitted);
	(void)printf("%ld packets received, ",  counters->nreceived);
	if (counters->nrepeats)
		(void)printf("+%ld duplicates, ", counters->nrepeats);
	if (counters->ntransmitted) {
		if (counters->nreceived > counters->ntransmitted)
			(void)printf("-- somebody's duplicating packets!");
		else
			(void)printf("%.1f%% packet loss",
			    ((((double)counters->ntransmitted - counters->nreceived) * 100.0) /
			    counters->ntransmitted));
	}
	if (counters->nrcvtimeout)
		printf(", %ld packets out of wait time", counters->nrcvtimeout);
	(void)printf("\n");
	if (counters->nreceived && timing->enabled) {
		/* Only display average to microseconds */
		double num = counters->nreceived + counters->nrepeats;
		double avg = timing->sum / num;
		double dev = sqrt(timing->sumsq / num - avg * avg);
		(void)printf(
		    "round-trip min/avg/max/std-dev = %.3f/%.3f/%.3f/%.3f ms\n",
		    timing->min, avg, timing->max, dev);
		(void)fflush(stdout);
	}
	(void)fflush(stdout);
}

/*
 * pr_icmph --
 *	Print a descriptive string about an ICMP header.
 */
static void
pr_icmph(struct icmp6_hdr *icp, u_char *end, bool verbose)
{
	/* subject type */
	const char *niqcode[] = {
		"IPv6 address",
		"DNS label",	/*or empty*/
		"IPv4 address",
	};

	/* result code */
	const char *nircode[] = {
		"Success", "Refused", "Unknown",
	};

	char ntop_buf[INET6_ADDRSTRLEN];
	struct nd_redirect *red;
	struct icmp6_nodeinfo *ni;
	char dnsname[MAXDNAME + 1];
	const u_char *cp;
	size_t l;

	switch (icp->icmp6_type) {
	case ICMP6_DST_UNREACH:
		switch (icp->icmp6_code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			(void)printf("No Route to Destination\n");
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			(void)printf("Destination Administratively "
			    "Unreachable\n");
			break;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			(void)printf("Destination Unreachable Beyond Scope\n");
			break;
		case ICMP6_DST_UNREACH_ADDR:
			(void)printf("Destination Host Unreachable\n");
			break;
		case ICMP6_DST_UNREACH_NOPORT:
			(void)printf("Destination Port Unreachable\n");
			break;
		default:
			(void)printf("Destination Unreachable, Bad Code: %d\n",
			    icp->icmp6_code);
			break;
		}
		/* Print returned IP header information */
		pr_retip((struct ip6_hdr *)(icp + 1), end);
		break;
	case ICMP6_PACKET_TOO_BIG:
		(void)printf("Packet too big mtu = %d\n",
		    (int)ntohl(icp->icmp6_mtu));
		pr_retip((struct ip6_hdr *)(icp + 1), end);
		break;
	case ICMP6_TIME_EXCEEDED:
		switch (icp->icmp6_code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			(void)printf("Time to live exceeded\n");
			break;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			(void)printf("Frag reassembly time exceeded\n");
			break;
		default:
			(void)printf("Time exceeded, Bad Code: %d\n",
			    icp->icmp6_code);
			break;
		}
		pr_retip((struct ip6_hdr *)(icp + 1), end);
		break;
	case ICMP6_PARAM_PROB:
		(void)printf("Parameter problem: ");
		switch (icp->icmp6_code) {
		case ICMP6_PARAMPROB_HEADER:
			(void)printf("Erroneous Header ");
			break;
		case ICMP6_PARAMPROB_NEXTHEADER:
			(void)printf("Unknown Nextheader ");
			break;
		case ICMP6_PARAMPROB_OPTION:
			(void)printf("Unrecognized Option ");
			break;
		default:
			(void)printf("Bad code(%d) ", icp->icmp6_code);
			break;
		}
		(void)printf("pointer = 0x%02x\n",
		    (u_int32_t)ntohl(icp->icmp6_pptr));
		pr_retip((struct ip6_hdr *)(icp + 1), end);
		break;
	case ICMP6_ECHO_REQUEST:
		(void)printf("Echo Request");
		/* XXX ID + Seq + Data */
		break;
	case ICMP6_ECHO_REPLY:
		(void)printf("Echo Reply");
		/* XXX ID + Seq + Data */
		break;
	case ICMP6_MEMBERSHIP_QUERY:
		(void)printf("Listener Query");
		break;
	case ICMP6_MEMBERSHIP_REPORT:
		(void)printf("Listener Report");
		break;
	case ICMP6_MEMBERSHIP_REDUCTION:
		(void)printf("Listener Done");
		break;
	case ND_ROUTER_SOLICIT:
		(void)printf("Router Solicitation");
		break;
	case ND_ROUTER_ADVERT:
		(void)printf("Router Advertisement");
		break;
	case ND_NEIGHBOR_SOLICIT:
		(void)printf("Neighbor Solicitation");
		break;
	case ND_NEIGHBOR_ADVERT:
		(void)printf("Neighbor Advertisement");
		break;
	case ND_REDIRECT:
		red = (struct nd_redirect *)icp;
		(void)printf("Redirect\n");
		if (!inet_ntop(AF_INET6, &red->nd_rd_dst, ntop_buf,
		    sizeof(ntop_buf)))
			strlcpy(ntop_buf, "?", sizeof(ntop_buf));
		(void)printf("Destination: %s", ntop_buf);
		if (!inet_ntop(AF_INET6, &red->nd_rd_target, ntop_buf,
		    sizeof(ntop_buf)))
			strlcpy(ntop_buf, "?", sizeof(ntop_buf));
		(void)printf(" New Target: %s", ntop_buf);
		break;
	case ICMP6_NI_QUERY:
		(void)printf("Node Information Query");
		/* XXX ID + Seq + Data */
		ni = (struct icmp6_nodeinfo *)icp;
		l = end - (u_char *)(ni + 1);
		printf(", ");
		switch (ntohs(ni->ni_qtype)) {
		case NI_QTYPE_NOOP:
			(void)printf("NOOP");
			break;
		case NI_QTYPE_SUPTYPES:
			(void)printf("Supported qtypes");
			break;
		case NI_QTYPE_FQDN:
			(void)printf("DNS name");
			break;
		case NI_QTYPE_NODEADDR:
			(void)printf("nodeaddr");
			break;
		case NI_QTYPE_IPV4ADDR:
			(void)printf("IPv4 nodeaddr");
			break;
		default:
			(void)printf("unknown qtype");
			break;
		}
		if (verbose) {
			switch (ni->ni_code) {
			case ICMP6_NI_SUBJ_IPV6:
				if (l == sizeof(struct in6_addr) &&
				    inet_ntop(AF_INET6, ni + 1, ntop_buf,
				    sizeof(ntop_buf)) != NULL) {
					(void)printf(", subject=%s(%s)",
					    niqcode[ni->ni_code], ntop_buf);
				} else {
#if 1
					/* backward compat to -W */
					(void)printf(", oldfqdn");
#else
					(void)printf(", invalid");
#endif
				}
				break;
			case ICMP6_NI_SUBJ_FQDN:
				if (end == (u_char *)(ni + 1)) {
					(void)printf(", no subject");
					break;
				}
				printf(", subject=%s", niqcode[ni->ni_code]);
				cp = (const u_char *)(ni + 1);
				if (dnsdecode(&cp, end, NULL, dnsname,
				    sizeof(dnsname)) != NULL)
					printf("(%s)", dnsname);
				else
					printf("(invalid)");
				break;
			case ICMP6_NI_SUBJ_IPV4:
				if (l == sizeof(struct in_addr) &&
				    inet_ntop(AF_INET, ni + 1, ntop_buf,
				    sizeof(ntop_buf)) != NULL) {
					(void)printf(", subject=%s(%s)",
					    niqcode[ni->ni_code], ntop_buf);
				} else
					(void)printf(", invalid");
				break;
			default:
				(void)printf(", invalid");
				break;
			}
		}
		break;
	case ICMP6_NI_REPLY:
		(void)printf("Node Information Reply");
		/* XXX ID + Seq + Data */
		ni = (struct icmp6_nodeinfo *)icp;
		printf(", ");
		switch (ntohs(ni->ni_qtype)) {
		case NI_QTYPE_NOOP:
			(void)printf("NOOP");
			break;
		case NI_QTYPE_SUPTYPES:
			(void)printf("Supported qtypes");
			break;
		case NI_QTYPE_FQDN:
			(void)printf("DNS name");
			break;
		case NI_QTYPE_NODEADDR:
			(void)printf("nodeaddr");
			break;
		case NI_QTYPE_IPV4ADDR:
			(void)printf("IPv4 nodeaddr");
			break;
		default:
			(void)printf("unknown qtype");
			break;
		}
		if (verbose) {
			if (ni->ni_code > nitems(nircode))
				printf(", invalid");
			else
				printf(", %s", nircode[ni->ni_code]);
		}
		break;
	default:
		(void)printf("Bad ICMP type: %d", icp->icmp6_type);
	}
}

/*
 * pr_iph --
 *	Print an IP6 header.
 */
static void
pr_iph(struct ip6_hdr *ip6)
{
	u_int32_t flow = ip6->ip6_flow & IPV6_FLOWLABEL_MASK;
	u_int8_t tc;
	char ntop_buf[INET6_ADDRSTRLEN];

	tc = *(&ip6->ip6_vfc + 1); /* XXX */
	tc = (tc >> 4) & 0x0f;
	tc |= (ip6->ip6_vfc << 4);

	printf("Vr TC  Flow Plen Nxt Hlim\n");
	printf(" %1x %02x %05x %04x  %02x   %02x\n",
	    (ip6->ip6_vfc & IPV6_VERSION_MASK) >> 4, tc, (u_int32_t)ntohl(flow),
	    ntohs(ip6->ip6_plen), ip6->ip6_nxt, ip6->ip6_hlim);
	if (!inet_ntop(AF_INET6, &ip6->ip6_src, ntop_buf, sizeof(ntop_buf)))
		strlcpy(ntop_buf, "?", sizeof(ntop_buf));
	printf("%s->", ntop_buf);
	if (!inet_ntop(AF_INET6, &ip6->ip6_dst, ntop_buf, sizeof(ntop_buf)))
		strlcpy(ntop_buf, "?", sizeof(ntop_buf));
	printf("%s\n", ntop_buf);
}

/*
 * pr_addr --
 *	Return an ascii host address as a dotted quad and optionally with
 * a hostname.
 */
static const char *
pr_addr(struct sockaddr *addr, int addrlen, bool hostname)
{
	static char buf[NI_MAXHOST];
	int flag = 0;

	if (!hostname)
		flag |= NI_NUMERICHOST;

	if (getnameinfo(addr, addrlen, buf, sizeof(buf), NULL, 0, flag) == 0)
		return (buf);
	else
		return "?";
}

/*
 * pr_retip --
 *	Dump some info on a returned (via ICMPv6) IPv6 packet.
 */
static void
pr_retip(struct ip6_hdr *ip6, u_char *end)
{
	u_char *cp = (u_char *)ip6, nh;
	int hlen;

	if ((size_t)(end - (u_char *)ip6) < sizeof(*ip6)) {
		printf("IP6");
		goto trunc;
	}
	pr_iph(ip6);
	hlen = sizeof(*ip6);

	nh = ip6->ip6_nxt;
	cp += hlen;
	while (end - cp >= 8) {
		switch (nh) {
		case IPPROTO_HOPOPTS:
			printf("HBH ");
			hlen = (((struct ip6_hbh *)cp)->ip6h_len+1) << 3;
			nh = ((struct ip6_hbh *)cp)->ip6h_nxt;
			break;
		case IPPROTO_DSTOPTS:
			printf("DSTOPT ");
			hlen = (((struct ip6_dest *)cp)->ip6d_len+1) << 3;
			nh = ((struct ip6_dest *)cp)->ip6d_nxt;
			break;
		case IPPROTO_FRAGMENT:
			printf("FRAG ");
			hlen = sizeof(struct ip6_frag);
			nh = ((struct ip6_frag *)cp)->ip6f_nxt;
			break;
		case IPPROTO_ROUTING:
			printf("RTHDR ");
			hlen = (((struct ip6_rthdr *)cp)->ip6r_len+1) << 3;
			nh = ((struct ip6_rthdr *)cp)->ip6r_nxt;
			break;
#ifdef IPSEC
		case IPPROTO_AH:
			printf("AH ");
			hlen = (((struct ah *)cp)->ah_len+2) << 2;
			nh = ((struct ah *)cp)->ah_nxt;
			break;
#endif
		case IPPROTO_ICMPV6:
			printf("ICMP6: type = %d, code = %d\n",
			    *cp, *(cp + 1));
			return;
		case IPPROTO_ESP:
			printf("ESP\n");
			return;
		case IPPROTO_TCP:
			printf("TCP: from port %u, to port %u (decimal)\n",
			    (*cp * 256 + *(cp + 1)),
			    (*(cp + 2) * 256 + *(cp + 3)));
			return;
		case IPPROTO_UDP:
			printf("UDP: from port %u, to port %u (decimal)\n",
			    (*cp * 256 + *(cp + 1)),
			    (*(cp + 2) * 256 + *(cp + 3)));
			return;
		default:
			printf("Unknown Header(%d)\n", nh);
			return;
		}

		if ((cp += hlen) >= end)
			goto trunc;
	}
	if (end - cp < 8)
		goto trunc;

	printf("\n");
	return;

  trunc:
	printf("...\n");
	return;
}

#ifdef IPSEC
#ifdef IPSEC_POLICY_IPSEC
static int
setpolicy(int socket, char *policy)
{
	char *buf;

	if (policy == NULL)
		return 0;	/* ignore */

	buf = ipsec_set_policy(policy, strlen(policy));
	if (buf == NULL)
		errx(1, "%s", ipsec_strerror());
	if (setsockopt(socket, IPPROTO_IPV6, IPV6_IPSEC_POLICY, buf,
	    ipsec_get_policylen(buf)) < 0)
		warnx("Unable to set IPsec policy");
	free(buf);

	return 0;
}
#endif
#endif

static char *
nigroup(char *name, int nig_oldmcprefix)
{
	char *p;
	char *q;
	MD5_CTX ctxt;
	u_int8_t digest[16];
	u_int8_t c;
	size_t l;
	char hbuf[NI_MAXHOST];
	struct in6_addr in6;
	int valid;

	p = strchr(name, '.');
	if (!p)
		p = name + strlen(name);
	l = p - name;
	if (l > 63 || l > sizeof(hbuf) - 1)
		return NULL;	/*label too long*/
	strncpy(hbuf, name, l);
	hbuf[(int)l] = '\0';

	for (q = name; *q; q++) {
		if (isupper(*(unsigned char *)q))
			*q = tolower(*(unsigned char *)q);
	}

	/* generate 16 bytes of pseudo-random value. */
	memset(&ctxt, 0, sizeof(ctxt));
	MD5Init(&ctxt);
	c = l & 0xff;
	MD5Update(&ctxt, &c, sizeof(c));
	MD5Update(&ctxt, (unsigned char *)name, l);
	MD5Final(digest, &ctxt);

	if (nig_oldmcprefix) {
		/* draft-ietf-ipngwg-icmp-name-lookup */
		valid = inet_pton(AF_INET6, "ff02::2:0000:0000", &in6);
	} else {
		/* RFC 4620 */
		valid = inet_pton(AF_INET6, "ff02::2:ff00:0000", &in6);
	}
	if (valid != 1)
		return NULL;	/*XXX*/
	
	if (nig_oldmcprefix) {
		/* draft-ietf-ipngwg-icmp-name-lookup */
		bcopy(digest, &in6.s6_addr[12], 4);
	} else {
		/* RFC 4620 */
		bcopy(digest, &in6.s6_addr[13], 3);
	}

	if (inet_ntop(AF_INET6, &in6, hbuf, sizeof(hbuf)) == NULL)
		return NULL;

	return strdup(hbuf);
}

static void
check_options(struct options *const options, struct timeval *const intvl)
{
	/* Globalize information needed by the signal handler */
	sig_option_f_hostname = options->f_hostname;
	
	if (options->f_flood) {
		if (getuid() != 0) {
			errno = EPERM;
			errx(EX_NOPERM, "Must be superuser to flood ping");
		}
		setbuf(stdout, (char *)NULL);
	}

	if (options->f_sock_buff_size && (options->n_sock_buff_size > INT_MAX))
		errx(1, "invalid socket buffer size");

	if ((options->f_hoplimit) && ((options->n_hoplimit < 0) || (options->n_hoplimit > 255)))
		errx(1, "illegal hoplimit -- %d", options->n_hoplimit);

	if (!options->f_interval)
		options->n_interval = 1000;
	else {
		if (options->n_interval > (double)INT_MAX)
			errx(EX_USAGE, "invalid timing interval: `%f'", options->n_interval);
		else if ((getuid() != 0) && (options->n_interval < 1)) {
			errno = EPERM;
			err(EX_NOPERM, "only root may use interval < 1s");
		}
		intvl->tv_sec = (long)options->n_interval;
		intvl->tv_usec =
			(long)((options->n_interval - intvl->tv_sec) * 1000000);
		if (intvl->tv_sec < 0)
			errx(1, "illegal timing interval %f", options->n_interval);
		/* less than 1/hz does not make sense */
		if (intvl->tv_sec == 0 && intvl->tv_usec < 1) {
			warnx("too small interval, raised to .000001");
			intvl->tv_usec = 1;
		}
	}
	
	if (options->f_preload) {
		if (getuid() != 0) {
			errno = EPERM;
			errx(EX_NOPERM, "Must be superuser to preload");
		} else if (options->n_preload < 0)
			errx(EX_USAGE, "invalid preload value: `%d'", options->n_preload);
			
	}

	if (options->f_numeric)
		options->f_hostname = false;

	options->c_nigroup -= 1;
		
	
	if (options->f_packet_size) {
		if (options->n_packet_size <= 0)
			errx(1, "illegal datalen value -- %ld", options->n_packet_size);
		else if (options->n_packet_size > MAXDATALEN)
			errx(1,
			    "datalen value too large, maximum is %d",
			    MAXDATALEN);
		
	} else
		options->n_packet_size = DEFDATALEN;
	
	if (!options->f_wait_time)
		options->n_wait_time = MAXWAIT;
	
	/* TODO: alarm is obsoletet by setitimer(2) */
	if (options->f_alarm_timeout) {
		if (options->n_alarm_timeout > MAXALARM)
			errx(EX_USAGE, "invalid timeout: `%lu' > %d", options->n_alarm_timeout, MAXALARM);
		alarm((unsigned int) options->n_alarm_timeout);
	}
}

static u_short
get_node_address_flags(const struct options *const options)
{
	u_short naflags = 0;

	if (options->f_nodeaddr_flag_all)
		naflags |= NI_NODEADDR_FLAG_ALL;
	if (options->f_nodeaddr_flag_compat)
		naflags |= NI_NODEADDR_FLAG_COMPAT;
	if (options->f_nodeaddr_flag_linklocal)
		naflags |= NI_NODEADDR_FLAG_LINKLOCAL;
	if (options->f_nodeaddr_flag_sitelocal)
		naflags |= NI_NODEADDR_FLAG_SITELOCAL;
	if (options->f_nodeaddr_flag_global)
		naflags |= NI_NODEADDR_FLAG_GLOBAL;
#ifdef NI_NODEADDR_FLAG_ANYCAST
	if (options->f_nodeaddr_flag_anycast)
		naflags |= NI_NODEADDR_FLAG_ANYCAST;
#endif

	return naflags;
}
