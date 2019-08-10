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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cap.h"
#include "defaults_limits.h"
#include "ipsec.h"
#include "ping6.h"
#include "ping6_print.h"
#include "timing.h"
#include "utils.h"

#define	EXTRA		256	/* for AH and various other headers. weird. */

#define DUMMY_PORT	10101

static int       get_pathmtu(const struct msghdr *const ,
    const struct options *const, const struct sockaddr_in6 *const,
    cap_channel_t *const);
static bool	 is_packet_valid(int, const struct msghdr *const,
    const struct options *const,
    cap_channel_t *const);
static void	 mark_packet_as_received(struct shared_variables *const);
static u_short   get_node_address_flags(const struct options *const);
static void	 update_counters(const struct options *const,
    const struct shared_variables *const,
    struct counters *const, double);
static bool      update_timing(const struct shared_variables *const,
    struct timing *const, double *const);

bool
ping6_init(struct options *const options, struct shared_variables *const vars,
    struct timing *const timing)
{
	int hold, optval;
	u_char *datap;
	char *scmsg = NULL;
	size_t ip6optlen = 0;
	struct cmsghdr *scmsgp = NULL;
	struct in6_pktinfo pktinfo;
	unsigned char *cmsg_pktinfo = NULL;
	struct ip6_rthdr *rthdr = NULL;

	memset(&vars->smsghdr, 0, sizeof(vars->smsghdr));
	memset(&pktinfo, 0, sizeof(pktinfo));

	datap = &vars->outpack6[ICMP6ECHOLEN + ICMP6ECHOTMLEN];

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#endif
	vars->target_sockaddr_in6 =
		(struct sockaddr_in6 *)options->target_addrinfo->ai_addr;
#ifdef __clang__
#pragma clang diagnostic pop
#endif

	if (options->f_ping_filled) {
		fill((char *)datap, MAXDATALEN - 8 + sizeof(struct tv32) +
		    options->ping_filled_size, options);
		if (!options->f_quiet)
			print_fill_pattern((char *)datap,
			    options->ping_filled_size);
	}

	if (options->hop_count != 0) {
		size_t rthlen;
#ifdef IPV6_RECVRTHDR	/* 2292bis */
		socklen_t rth_space;

		rth_space = inet6_rth_space(IPV6_RTHDR_TYPE_0,
		    options->hop_count);
		if (rth_space == 0) {
			print_error("inet6_rth_space() hop_count");
			return (false);
		}
		rthlen = CMSG_SPACE(rth_space);
#else  /* RFC2292 */
		rthlen = inet6_rthdr_space(IPV6_RTHDR_TYPE_0,
		    options->hop_count);
#endif
		if (rthlen == 0) {
			print_error("too many intermediate hops");
			return (false);
		}
		ip6optlen += rthlen;
	}

	/* set the source address if specified. */
	if (options->f_source) {
		/* properly fill sin6_scope_id */
		if (IN6_IS_ADDR_LINKLOCAL(
			    &options->source_sockaddr.in6.sin6_addr) && (
		    IN6_IS_ADDR_LINKLOCAL(
			    &vars->target_sockaddr_in6->sin6_addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(
			    &vars->target_sockaddr_in6->sin6_addr) ||
		    IN6_IS_ADDR_MC_NODELOCAL(
			    &vars->target_sockaddr_in6->sin6_addr))) {
			if (options->source_sockaddr.in6.sin6_scope_id == 0)
				options->source_sockaddr.in6.sin6_scope_id =
					vars->target_sockaddr_in6->sin6_scope_id;
			if (vars->target_sockaddr_in6->sin6_scope_id == 0)
				vars->target_sockaddr_in6->sin6_scope_id =
					options->source_sockaddr.in6.sin6_scope_id;
		}
		if (bind(vars->socket_send,
			(struct sockaddr *)&options->source_sockaddr.in6,
			sizeof(options->source_sockaddr.in6)) != 0) {
			print_error_strerr("bind");
			return (false);
		}
	}

	if (connect(vars->socket_send,
		(struct sockaddr *)vars->target_sockaddr_in6,
		sizeof(*vars->target_sockaddr_in6)) != 0) {
		print_error_strerr("connect");
		return (false);
	}

	/* set the gateway (next hop) if specified */
	if (options->s_gateway != NULL) {
		if (setsockopt(vars->socket_send, IPPROTO_IPV6, IPV6_NEXTHOP,
			&options->gateway_sockaddr_in6,
			options->gateway_sockaddr_in6.sin6_len) != 0) {
			print_error_strerr("setsockopt(IPV6_NEXTHOP)");
			return (false);
		}
	}

	/*
	 * let the kerel pass extension headers of incoming packets,
	 * for privileged socket options
	 */
	if (options->f_verbose) {
		const int opton = 1;

#ifdef IPV6_RECVHOPOPTS
		if (setsockopt(vars->socket_recv, IPPROTO_IPV6, IPV6_RECVHOPOPTS,
			&opton, sizeof(opton)) != 0) {
			print_error_strerr("setsockopt(IPV6_RECVHOPOPTS)");
			return (false);
		}
#else  /* old adv. API */
		if (setsockopt(vars->socket_recv, IPPROTO_IPV6, IPV6_HOPOPTS,
			&opton, sizeof(opton)) != 0) {
			print_error_strerr("setsockopt(IPV6_HOPOPTS)");
			return (false);
		}
#endif
#ifdef IPV6_RECVDSTOPTS
		if (setsockopt(vars->socket_recv, IPPROTO_IPV6,
			IPV6_RECVDSTOPTS, &opton, sizeof(opton)) != 0) {
			print_error_strerr("setsockopt(IPV6_RECVDSTOPTS)");
			return (false);
		}
#else  /* old adv. API */
		if (setsockopt(vars->srec, IPPROTO_IPV6, IPV6_DSTOPTS, &opton,
			sizeof(opton)) != 0) {
			print_error_strerr("setsockopt(IPV6_DSTOPTS)");
			return (false);
		}
#endif
#ifdef IPV6_RECVRTHDRDSTOPTS
		if (setsockopt(vars->srec, IPPROTO_IPV6, IPV6_RECVRTHDRDSTOPTS,
			&opton, sizeof(opton)) != 0) {
			print_error_strerr("setsockopt(IPV6_RECVRTHDRDSTOPTS)");
			return (false);
		}
#endif
	}

	if (!options->f_nodeaddr && !options->f_fqdn && !options->f_fqdn_old &&
	    !options->f_subtypes) {
		if (options->n_packet_size >= (long)sizeof(struct tv32)) {
			/* we can time transfer */
			timing->enabled = true;
		} else
			timing->enabled = false;
		/* in F_VERBOSE case, we may get non-echoreply packets*/
		if (options->f_verbose)
			vars->packlen = 2048 + IP6LEN + ICMP6ECHOLEN + EXTRA;
		else
			vars->packlen = options->n_packet_size + IP6LEN +
				ICMP6ECHOLEN + EXTRA;
	} else {
		/* suppress timing for node information query */
		timing->enabled = false;
		options->n_packet_size = 2048;
		vars->packlen = 2048 + IP6LEN + ICMP6ECHOLEN + EXTRA;
	}

	if (!(vars->packet6 = (u_char *)malloc((u_int)vars->packlen))) {
		print_error("Unable to allocate packet");
		return (false);
	}
	if (!options->f_ping_filled)
		for (int i = ICMP6ECHOLEN; i < vars->packlen; ++i)
			*datap++ = i;

	arc4random_buf(vars->nonce, sizeof(vars->nonce));
	optval = 1;
	if (options->f_dont_fragment)
		if (setsockopt(vars->socket_send, IPPROTO_IPV6, IPV6_DONTFRAG,
			&optval, sizeof(optval)) != 0) {
			print_error_strerr("IPV6_DONTFRAG");
			return (false);
		}

	optval = IPV6_DEFHLIM;
	if (IN6_IS_ADDR_MULTICAST(&vars->target_sockaddr_in6->sin6_addr))
		if (setsockopt(vars->socket_send, IPPROTO_IPV6,
			IPV6_MULTICAST_HOPS, &optval, sizeof(optval)) != 0) {
			print_error_strerr("IPV6_MULTICAST_HOPS");
			return (false);
		}
#ifdef IPV6_USE_MIN_MTU
	if (options->c_use_min_mtu != 1) {
		optval = (options->c_use_min_mtu > 1) ? 0 : 1;

		if (setsockopt(vars->socket_send, IPPROTO_IPV6,
			IPV6_USE_MIN_MTU, &optval, sizeof(optval)) != 0) {
			print_error_strerr("setsockopt(IPV6_USE_MIN_MTU)");
			return (false);
		}
	}
#ifdef IPV6_RECVPATHMTU
	else {
		optval = 1;
		if (setsockopt(vars->socket_recv, IPPROTO_IPV6,
			IPV6_RECVPATHMTU, &optval, sizeof(optval)) != 0) {
			print_error_strerr("setsockopt(IPV6_RECVPATHMTU)");
			return (false);
		}
	}
#endif /* IPV6_RECVPATHMTU */
#endif /* IPV6_USE_MIN_MTU */

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
	if (setsockopt(vars->socket_recv, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
		sizeof(filt)) != 0) {
		print_error_strerr("setsockopt(ICMP6_FILTER)");
		return (false);
	}
    }
#endif /*ICMP6_FILTER*/

	/* let the kerel pass extension headers of incoming packets */
	if (options->f_verbose) {
		int opton = 1;

#ifdef IPV6_RECVRTHDR
		if (setsockopt(vars->socket_recv, IPPROTO_IPV6, IPV6_RECVRTHDR,
			&opton, sizeof(opton)) != 0) {
			print_error_strerr("setsockopt(IPV6_RECVRTHDR)");
			return (false);
		}
#else  /* old adv. API */
		if (setsockopt(vars->socket_recv, IPPROTO_IPV6, IPV6_RTHDR,
			&opton, sizeof(opton)) != 0) {
			print_error_strerr("setsockopt(IPV6_RTHDR)");
			return (false);
		}
#endif
	}

	/* Specify the outgoing interface and/or the source address */
	if (options->f_interface_use_pktinfo)
		ip6optlen += CMSG_SPACE(sizeof(struct in6_pktinfo));

	if (options->f_hoplimit)
		ip6optlen += CMSG_SPACE(sizeof(int));

	/* set IP6 packet options */
	if (ip6optlen > 0) {
		if ((scmsg = (char *)malloc(ip6optlen)) == NULL) {
			print_error("can't allocate enough memory");
			return (false);
		}
		vars->smsghdr.msg_control = (caddr_t)scmsg;
		vars->smsghdr.msg_controllen = ip6optlen;
		scmsgp = CMSG_FIRSTHDR(&vars->smsghdr);
	}
	if (options->f_interface_use_pktinfo) {
		cmsg_pktinfo = CMSG_DATA(scmsgp);
		scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		scmsgp->cmsg_level = IPPROTO_IPV6;
		scmsgp->cmsg_type = IPV6_PKTINFO;
		scmsgp = CMSG_NXTHDR(&vars->smsghdr, scmsgp);
	}

	/* set the outgoing interface */
	if (options->f_interface) {
#ifndef USE_SIN6_SCOPE_ID
		/* pktinfo must have already been allocated */
		pktinfo.ipi6_ifindex = options->interface.index;
#else
		dst.sin6_scope_id = options->interface.index;
#endif
	}
	if (options->f_hoplimit) {
		scmsgp->cmsg_len = CMSG_LEN(sizeof(int));
		scmsgp->cmsg_level = IPPROTO_IPV6;
		scmsgp->cmsg_type = IPV6_HOPLIMIT;
		memcpy(CMSG_DATA(scmsgp), &options->n_hoplimit,
		    sizeof(options->n_hoplimit));

		scmsgp = CMSG_NXTHDR(&vars->smsghdr, scmsgp);
	}

	if (options->hop_count != 0) {
		/* some intermediate addrs are specified */
		unsigned hops;
		int rthdrlen;

		rthdrlen = inet6_rth_space(IPV6_RTHDR_TYPE_0,
		    options->hop_count);
		if (rthdrlen == 0) {
			print_error("inet6_rth_space() hop_count");
			return (false);
		}
		scmsgp->cmsg_len = CMSG_LEN(rthdrlen);
		scmsgp->cmsg_level = IPPROTO_IPV6;
		scmsgp->cmsg_type = IPV6_RTHDR;
		rthdr = (struct ip6_rthdr *)CMSG_DATA(scmsgp);
		rthdr = inet6_rth_init((void *)rthdr, rthdrlen,
		    IPV6_RTHDR_TYPE_0, options->hop_count);
		if (rthdr == NULL) {
			print_error("can't initialize rthdr");
			return (false);
		}

		for (hops = 0; hops < options->hop_count; hops++) {
			struct sockaddr_in6 *sin6;
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#endif
			sin6 = (struct sockaddr_in6 *)
				options->hops_addrinfo[hops]->ai_addr;
#ifdef __clang__
#pragma clang diagnostic pop
#endif
			if (inet6_rth_add(rthdr, &sin6->sin6_addr)) {
				print_error("can't add an intermediate node");
				return (false);
			}
			freeaddrinfo(options->hops_addrinfo[hops]);
			options->hops_addrinfo[hops] = NULL;
		}

		scmsgp = CMSG_NXTHDR(&vars->smsghdr, scmsgp);
	}

	if (!options->f_source) {
		/*
		 * get the source address. XXX since we revoked the root
		 * privilege, we cannot use a raw socket for this.
		 */
		int dummy;
		socklen_t len = sizeof(options->source_sockaddr.in6);

		if ((dummy = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
			print_error_strerr("UDP socket");
			return (false);
		}

		options->source_sockaddr.in6.sin6_family = AF_INET6;
		options->source_sockaddr.in6.sin6_addr =
			vars->target_sockaddr_in6->sin6_addr;
		options->source_sockaddr.in6.sin6_port = ntohs(DUMMY_PORT);
		options->source_sockaddr.in6.sin6_scope_id =
			vars->target_sockaddr_in6->sin6_scope_id;

		if (options->f_interface_use_pktinfo &&
		    (setsockopt(dummy, IPPROTO_IPV6, IPV6_PKTINFO,
			(void *)&pktinfo, sizeof(pktinfo)) != 0)) {
			print_error_strerr("UDP setsockopt(IPV6_PKTINFO)");
			return (false);
		}

		if (options->f_hoplimit &&
		    (setsockopt(dummy, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			(void *)&(options->n_hoplimit),
			sizeof(options->n_hoplimit)) != 0)) {
			print_error_strerr("UDP setsockopt(IPV6_UNICAST_HOPS)");
			return (false);
		}

		if (options->f_hoplimit &&
		    (setsockopt(dummy, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			(void *)&(options->n_hoplimit),
			sizeof(options->n_hoplimit)) != 0)) {
			print_error_strerr("UDP "
			    "setsockopt(IPV6_MULTICAST_HOPS)");
			return (false);
		}

		if (rthdr &&
		    (setsockopt(dummy, IPPROTO_IPV6, IPV6_RTHDR,
			(void *)rthdr, (rthdr->ip6r_len + 1) << 3) != 0)) {
			print_error_strerr("UDP setsockopt(IPV6_RTHDR)");
			return (false);
		}

		if (connect(dummy,
			(struct sockaddr *)&options->source_sockaddr.in6,
			len) < 0) {
			print_error_strerr("UDP connect");
			return (false);
		}

		if (getsockname(dummy,
			(struct sockaddr *)&options->source_sockaddr.in6,
			&len) < 0) {
			print_error_strerr("getsockname");
			return (false);
		}

		close(dummy);
	}

	/*
	 * Here we enter capability mode. Further down access to global
	 * namespaces (e.g filesystem) is restricted (see capsicum(4)).
	 * We must connect(2) our socket before this point.
	 */
	if (!cap_enter_capability_mode() ||
	    !cap_limit_socket(vars->socket_recv,
		RIGHTS_RECV_EVENT_SETSOCKOPT) ||
	    !cap_limit_socket(vars->socket_send, RIGHTS_SEND_SETSOCKOPT) ||
	    !cap_limit_stdio())
		return (false);

#if defined(SO_SNDBUF) && defined(SO_RCVBUF)
	if (options->f_sock_buff_size) {
		if (options->n_packet_size > (long)options->n_sock_buff_size)
			warnx("you need -b to increase socket buffer size");
		if (setsockopt(vars->socket_send, SOL_SOCKET, SO_SNDBUF,
			&(options->n_sock_buff_size),
			sizeof(options->n_sock_buff_size)) != 0) {
			print_error_strerr("setsockopt(SO_SNDBUF)");
			return (false);
		}
		if (setsockopt(vars->socket_recv, SOL_SOCKET, SO_RCVBUF,
			&(options->n_sock_buff_size),
			sizeof(options->n_sock_buff_size)) != 0) {
			print_error_strerr("setsockopt(SO_RCVBUF)");
			return (false);
		}
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
		if (setsockopt(vars->socket_recv, SOL_SOCKET, SO_RCVBUF,
			(char *)&hold, sizeof(hold)) != 0) {
			print_error_strerr("setsockopt() SO_RCVBUF");
			return (false);
		}
	}
#endif

	optval = 1;
#ifndef USE_SIN6_SCOPE_ID
#ifdef IPV6_RECVPKTINFO
	if (setsockopt(vars->socket_recv, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		&optval, sizeof(optval)) != 0)
		warn("setsockopt(IPV6_RECVPKTINFO)"); /* XXX err? */
#else  /* old adv. API */
	if (setsockopt(vars->socket_recv, IPPROTO_IPV6, IPV6_PKTINFO, &optval,
	    sizeof(optval)) != 0)
		warn("setsockopt(IPV6_PKTINFO)"); /* XXX err? */
#endif
#endif /* USE_SIN6_SCOPE_ID */
#ifdef IPV6_RECVHOPLIMIT
	if (setsockopt(vars->socket_recv, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
		&optval, sizeof(optval)) != 0)
		warn("setsockopt(IPV6_RECVHOPLIMIT)"); /* XXX err? */
#else  /* old adv. API */
	if (setsockopt(vars->socket_recv, IPPROTO_IPV6, IPV6_HOPLIMIT, &optval,
	    sizeof(optval)) != 0)
		warn("setsockopt(IPV6_HOPLIMIT)"); /* XXX err? */
#endif

	/* CAP_SETSOCKOPT removed */
	if (!cap_limit_socket(vars->socket_recv, RIGHTS_RECV_EVENT) ||
	    !cap_limit_socket(vars->socket_send, RIGHTS_SEND))
		return (false);

	/* Save pktinfo in the ancillary data. */
	if (options->f_interface_use_pktinfo)
		memcpy(cmsg_pktinfo, &pktinfo, sizeof(pktinfo));

	return (true);
}

int
ping6_process_received_packet(const struct options *const options,
    struct shared_variables *const vars, struct counters *const counters,
    struct timing *const timing)
{
	struct sockaddr_in6 from;
	/* For control (ancillary) data received from recvmsg() */
	struct cmsghdr cm[CONTROLLEN];

	struct msghdr m;
	struct iovec iov[2];

	m.msg_name = (caddr_t)&from;
	m.msg_namelen = sizeof(from);
	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = (caddr_t)vars->packet6;
	iov[0].iov_len = vars->packlen;
	m.msg_iov = iov;
	m.msg_iovlen = 1;
	memset(cm, 0, CONTROLLEN);
	m.msg_control = (void *)cm;
	m.msg_controllen = CONTROLLEN;

	const int cc = recvmsg(vars->socket_recv, &m, 0);
	if (cc < 0) {
		if (errno != EINTR) {
			warn("recvmsg");
			sleep(1);
		}
		return (0);
	} else if (cc == 0) {
		int mtu;

		/*
		 * receive control messages only. Process the
		 * exceptions (currently the only possibility is
		 * a path MTU notification.)
		 */
		if ((mtu = get_pathmtu(&m, options, vars->target_sockaddr_in6,
			    vars->capdns)) > 0) {
			if (options->f_verbose) {
				printf("new path MTU (%d) is "
				    "notified\n", mtu);
			}
		}
		return (0);
	} else if (is_packet_valid(cc, &m, options, vars->capdns)) {
		/*
		 * an ICMPv6 message (probably an echoreply)
		 * arrived.
		 */
		double triptime;

		if (!update_timing(vars, timing, &triptime))
			return (-1);
		update_counters(options, vars, counters, triptime);
		pr6_pack(cc, &m, options, vars, timing, triptime);
		mark_packet_as_received(vars);
	}

	return (1);
}

/*
 * pinger6 --
 *	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
bool
pinger6(struct options *const options, struct shared_variables *const vars,
    struct counters *const counters, struct timing *const timing)
{
	struct icmp6_hdr *icp;
	struct iovec iov[2];
	int i, cc;
	struct icmp6_nodeinfo *nip;
	int seq;

	if (options->n_packets && counters->transmitted >= options->n_packets)
		return (true);	/* no more transmission */

	icp = (struct icmp6_hdr *)vars->outpack6;
	nip = (struct icmp6_nodeinfo *)vars->outpack6;
	memset(icp, 0, sizeof(*icp));
	icp->icmp6_cksum = 0;
	seq = counters->transmitted++;
	BIT_ARRAY_CLR(vars->rcvd_tbl, seq % MAX_DUP_CHK);

	if (options->f_fqdn) {
		uint16_t s;

		icp->icmp6_type = ICMP6_NI_QUERY;
		icp->icmp6_code = ICMP6_NI_SUBJ_IPV6;
		nip->ni_qtype = htons(NI_QTYPE_FQDN);
		nip->ni_flags = htons(0);

		memcpy(nip->icmp6_ni_nonce, vars->nonce,
		    sizeof(nip->icmp6_ni_nonce));
		/* XXX: Shouldn't this be htons? */
		s = ntohs(seq);
		memcpy(nip->icmp6_ni_nonce, &s, sizeof(s));

		memcpy(&vars->outpack6[ICMP6_NIQLEN],
		    &vars->target_sockaddr_in6->sin6_addr,
		    sizeof(vars->target_sockaddr_in6->sin6_addr));
		cc = ICMP6_NIQLEN +
			sizeof(vars->target_sockaddr_in6->sin6_addr);
		options->n_packet_size = 0;
	} else if (options->f_fqdn_old) {
		uint16_t s;

		/* packet format in 03 draft - no Subject data on queries */
		icp->icmp6_type = ICMP6_NI_QUERY;
		icp->icmp6_code = 0;	/* code field is always 0 */
		nip->ni_qtype = htons(NI_QTYPE_FQDN);
		nip->ni_flags = htons(0);

		memcpy(nip->icmp6_ni_nonce, vars->nonce,
		    sizeof(nip->icmp6_ni_nonce));
		/* XXX: Shouldn't this be htons? */
		s = ntohs(seq);
		memcpy(nip->icmp6_ni_nonce, &s, sizeof(s));

		cc = ICMP6_NIQLEN;
		options->n_packet_size = 0;
	} else if (options->f_nodeaddr) {
		uint16_t s;

		icp->icmp6_type = ICMP6_NI_QUERY;
		icp->icmp6_code = ICMP6_NI_SUBJ_IPV6;
		nip->ni_qtype = htons(NI_QTYPE_NODEADDR);
		nip->ni_flags = get_node_address_flags(options);

		memcpy(nip->icmp6_ni_nonce, vars->nonce,
		    sizeof(nip->icmp6_ni_nonce));
		/* XXX: Shouldn't this be htons? */
		s = ntohs(seq);
		memcpy(nip->icmp6_ni_nonce, &s, sizeof(s));

		memcpy(&vars->outpack6[ICMP6_NIQLEN],
		    &vars->target_sockaddr_in6->sin6_addr,
		    sizeof(vars->target_sockaddr_in6->sin6_addr));
		cc = ICMP6_NIQLEN +
			sizeof(vars->target_sockaddr_in6->sin6_addr);
		options->n_packet_size = 0;
	} else if (options->f_subtypes) {
		uint16_t s;

		icp->icmp6_type = ICMP6_NI_QUERY;
		icp->icmp6_code = ICMP6_NI_SUBJ_FQDN;	/*empty*/
		nip->ni_qtype = htons(NI_QTYPE_SUPTYPES);
		/* we support compressed bitmap */
		nip->ni_flags = NI_SUPTYPE_FLAG_COMPRESS;

		memcpy(nip->icmp6_ni_nonce, vars->nonce,
		    sizeof(nip->icmp6_ni_nonce));
		/* XXX: Shouldn't this be htons? */
		s = ntohs(seq);
		memcpy(nip->icmp6_ni_nonce, &s, sizeof(s));
		cc = ICMP6_NIQLEN;
		options->n_packet_size = 0;
	} else {
		icp->icmp6_type = ICMP6_ECHO_REQUEST;
		icp->icmp6_code = 0;
		icp->icmp6_id = htons(vars->ident);
		icp->icmp6_seq = ntohs(seq);
		if (timing->enabled) {
			struct timeval tv;
			struct tv32 tv32;
			if (gettimeofday(&tv, NULL) != 0) {
				print_error_strerr("gettimeofday()");
				return (false);
			}
			tv32.tv32_sec = htonl(tv.tv_sec);
			tv32.tv32_usec = htonl(tv.tv_usec);
			memcpy(&vars->outpack6[ICMP6ECHOLEN], &tv32,
			    sizeof(tv32));
		}
		cc = ICMP6ECHOLEN + options->n_packet_size;
	}

#ifdef DIAGNOSTIC
	if (pingerlen() != cc) {
		print_error("internal error; length mismatch");
		return (false);
	}
#endif

	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = (caddr_t)vars->outpack6;
	iov[0].iov_len = cc;
	vars->smsghdr.msg_iov = iov;
	vars->smsghdr.msg_iovlen = 1;

	i = sendmsg(vars->socket_send, &vars->smsghdr, 0);

	if (i < 0 || i != cc)  {
		if (i < 0)
			warn("sendmsg");
		(void)printf("ping6: wrote %s %d chars, ret=%d\n",
		    options->target, cc, i);
	}
	if (!options->f_quiet && options->f_flood)
		write_char(STDOUT_FILENO, CHAR_DOT);

	return (true);
}

static bool
is_packet_valid(int cc, const struct msghdr *const mhdr,
    const struct options *const options, cap_channel_t *const capdns)
{
	struct sockaddr *from;
	struct in6_pktinfo *pktinfo = NULL;
	int fromlen, hoplim;

	if (!mhdr || !mhdr->msg_name ||
	    mhdr->msg_namelen != sizeof(struct sockaddr_in6) ||
	    ((struct sockaddr *)mhdr->msg_name)->sa_family != AF_INET6) {
		if (options->f_verbose)
			warnx("invalid peername");
		return (false);
	}

	from = (struct sockaddr *)mhdr->msg_name;
	fromlen = mhdr->msg_namelen;

	if (cc < (int)sizeof(struct icmp6_hdr)) {
		if (options->f_verbose)
			warnx("packet too short (%d bytes) from %s", cc,
			    pr6_addr(from, fromlen, options->f_numeric,
				capdns));
		return (false);
	}

	if ((hoplim = get_hoplim(mhdr)) == -1) {
		warnx("failed to get receiving hop limit");
		return (false);
	}

	if ((pktinfo = get_rcvpktinfo(mhdr)) == NULL) {
		warnx("failed to get receiving packet information");
		return (false);
	}

	return (true);
}

static void
mark_packet_as_received(struct shared_variables *const vars)
{
	struct icmp6_hdr *icp;
	struct icmp6_nodeinfo *ni;
	uint16_t seq;

	icp = (struct icmp6_hdr *)vars->packet6;
	ni = (struct icmp6_nodeinfo *)vars->packet6;

	if (icp->icmp6_type == ICMP6_ECHO_REPLY &&
	    myechoreply(icp, vars->ident)) {
		seq = ntohs(icp->icmp6_seq);
		BIT_ARRAY_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK);
	} else if (icp->icmp6_type == ICMP6_NI_REPLY &&
	    mynireply(ni, vars->nonce)) {
		memcpy(&seq, ni->icmp6_ni_nonce, sizeof(seq));
		BIT_ARRAY_SET(vars->rcvd_tbl, ntohs(seq) % MAX_DUP_CHK);
	}
}

static void
update_counters(const struct options *const options,
    const struct shared_variables *const vars,
    struct counters *const counters, double triptime)
{
	struct icmp6_hdr *icp;
	struct icmp6_nodeinfo *ni;
	uint16_t seq;

	icp = (struct icmp6_hdr *)vars->packet6;
	ni = (struct icmp6_nodeinfo *)vars->packet6;

	if (icp->icmp6_type == ICMP6_ECHO_REPLY &&
	    myechoreply(icp, vars->ident)) {
		seq = ntohs(icp->icmp6_seq);

		if (BIT_ARRAY_IS_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK))
			++(counters->repeats);
		else
			++(counters->received);

		if (options->f_quiet)
			return;

		if (options->f_wait_time && triptime > options->n_wait_time)
			++(counters->rcvtimeout);
	} else if (icp->icmp6_type == ICMP6_NI_REPLY &&
	    mynireply(ni, vars->nonce)) {
		memcpy(&seq, ni->icmp6_ni_nonce, sizeof(seq));

		if (BIT_ARRAY_IS_SET(vars->rcvd_tbl, ntohs(seq) % MAX_DUP_CHK))
			++(counters->repeats);
		else
			++(counters->received);
	}
}

static bool
update_timing(const struct shared_variables *const vars,
    struct timing *const timing, double *const triptime)
{
	struct icmp6_hdr *icp;
	struct timeval tv, tp;
	struct tv32 tpp;

	*triptime = 0;

	if (gettimeofday(&tv, NULL) != 0) {
		print_error_strerr("gettimeofday()");
		return (false);
	}

	icp = (struct icmp6_hdr *)vars->packet6;

	if (icp->icmp6_type == ICMP6_ECHO_REPLY &&
	    myechoreply(icp, vars->ident)) {
		if (timing->enabled) {
			memcpy(&tpp, icp + 1, sizeof(tpp));
			tp.tv_sec = ntohl(tpp.tv32_sec);
			tp.tv_usec = ntohl(tpp.tv32_usec);
			tvsub(&tv, &tp);
			*triptime = ((double)tv.tv_sec) * 1000.0 +
			    ((double)tv.tv_usec) / 1000.0;
			timing->sum += *triptime;
			timing->sumsq += *triptime * *triptime;
			if (*triptime < timing->min)
				timing->min = *triptime;
			if (*triptime > timing->max)
				timing->max = *triptime;
		}
	}

	return (true);
}

static int
get_pathmtu(const struct msghdr *const mhdr,
    const struct options *const options, const struct sockaddr_in6 *const dst,
    cap_channel_t *const capdns)
{
#ifdef IPV6_RECVPATHMTU
	struct cmsghdr *cm;
	struct ip6_mtuinfo mtuctl;

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(mhdr); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(mhdr, cm)) {
		if (cm->cmsg_len == 0)
			return (0);

		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PATHMTU &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct ip6_mtuinfo))) {
			memcpy(&mtuctl, CMSG_DATA(cm), sizeof(mtuctl));

			/*
			 * If the notified destination is different from
			 * the one we are pinging, just ignore the info.
			 * We check the scope ID only when both notified value
			 * and our own value have non-0 values, because we may
			 * have used the default scope zone ID for sending,
			 * in which case the scope ID value is 0.
			 */
			if (!IN6_ARE_ADDR_EQUAL(&mtuctl.ip6m_addr.sin6_addr,
						&dst->sin6_addr) ||
			    (mtuctl.ip6m_addr.sin6_scope_id &&
			     dst->sin6_scope_id &&
			     mtuctl.ip6m_addr.sin6_scope_id !=
			     dst->sin6_scope_id)) {
				if (options->f_verbose) {
					printf("path MTU for %s is notified. "
					       "(ignored)\n",
					   pr6_addr((struct sockaddr *)
					       &mtuctl.ip6m_addr,
					       sizeof(mtuctl.ip6m_addr),
					       options->f_numeric, capdns));
				}
				return (0);
			}

			/*
			 * Ignore an invalid MTU. XXX: can we just believe
			 * the kernel check?
			 */
			if (mtuctl.ip6m_mtu < IPV6_MMTU)
				return (0);

			/* notification for our destination. return the MTU. */
			return ((int)mtuctl.ip6m_mtu);
		}
	}
#endif
	return (0);
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

	return (naflags);
}
