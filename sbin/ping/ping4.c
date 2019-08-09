/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
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

#if 0
#ifndef lint
static const char copyright[] =
"@(#) Copyright (c) 1989, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)ping.c	8.1 (Berkeley) 6/5/93";
#endif /* not lint */
#endif
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 *			P I N G . C
 *
 * Using the Internet Control Message Protocol (ICMP) "ECHO" facility,
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

#include <sys/param.h>		/* NB: we rely on this for <sys/types.h> */
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cap.h"
#include "defaults_limits.h"
#include "ping4.h"
#include "ping4_print.h"
#include "timing.h"
#include "utils.h"

#define	MASK_LEN	(ICMP_MASKLEN - ICMP_MINLEN)
#define	TS_LEN		(ICMP_TSLEN - ICMP_MINLEN)
#define	FLOOD_BACKOFF	20000		/* usecs to back off if F_FLOOD mode */

static void get_triptime(size_t, struct timeval *const,
    const struct shared_variables *const, bool);
static bool is_packet_too_short(u_char, size_t,
    const struct sockaddr_in *const, bool);
static void mark_packet_as_received(const struct icmp *const,
    struct shared_variables *const);
static void update_counters(const struct timeval *const,
    const struct options *const, const struct shared_variables *const,
    struct counters *const);
static void update_timing(size_t, const struct timeval *const,
    const struct shared_variables *const, struct timing *const);

bool
ping4_init(struct options *const options, struct shared_variables *const vars,
    struct counters *const counters, struct timing *const timing)
{
	int hold;

	if (options->f_mask) {
		vars->send_packet.icmp_type = ICMP_MASKREQ;
		vars->recv_packet.expected_icmp_type = ICMP_MASKREPLY;
		vars->send_packet.phdr_len = MASK_LEN;
		if (!options->f_quiet)
			(void)printf("ICMP_MASKREQ\n");
	} else if (options->f_time) {
		vars->send_packet.icmp_type = ICMP_TSTAMP;
		vars->recv_packet.expected_icmp_type = ICMP_TSTAMPREPLY;
		vars->send_packet.phdr_len = TS_LEN;
		if (!options->f_quiet)
			(void)printf("ICMP_TSTAMP\n");
	} else {
		vars->send_packet.icmp_type = ICMP_ECHO;
		vars->recv_packet.expected_icmp_type = ICMP_ECHOREPLY;
	}

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#endif
	vars->target_sockaddr =
		(struct sockaddr_in *)options->target_addrinfo->ai_addr;
#ifdef __clang__
#pragma clang diagnostic pop
#endif

	vars->send_packet.icmp_len = sizeof(struct ip) + ICMP_MINLEN + vars->send_packet.phdr_len;
	if (options->f_rroute)
		vars->send_packet.icmp_len += MAX_IPOPTLEN;

	const int maxpayload = IP_MAXPACKET - vars->send_packet.icmp_len;

	if (options->n_packet_size > maxpayload) {
		print_error("packet size too large: %ld > %d",
		    options->n_packet_size, maxpayload);
		return (false);
	}
	vars->send_packet.send_len = vars->send_packet.icmp_len + options->n_packet_size;
	vars->send_packet.data = vars->send_packet.raw + sizeof(struct ip) +
		ICMP_MINLEN + vars->send_packet.phdr_len + TIMEVAL_LEN;
	if (options->f_ping_filled) {
		fill((char *)vars->send_packet.data, maxpayload -
		    (TIMEVAL_LEN + options->ping_filled_size), options);
		if (!options->f_quiet)
			print_fill_pattern((char *)vars->send_packet.data,
			    options->ping_filled_size);
	}

	if ((options->f_source) &&
	    (bind(vars->socket_send,
		(struct sockaddr *)&options->source_sockaddr.in,
		sizeof(options->source_sockaddr.in)) == -1)) {
		print_error_strerr("bind");
		return (false);
	}

	if (connect(vars->socket_send,
		(const struct sockaddr *)vars->target_sockaddr,
		sizeof(*vars->target_sockaddr)) != 0) {
		print_error_strerr("connect");
		return (false);
	}

	if (options->n_packet_size >= TIMEVAL_LEN)
		/* can we time transfer */
		timing->enabled = true;

	if (!options->f_ping_filled)
		for (int i = TIMEVAL_LEN; i < options->n_packet_size; ++i)
			*vars->send_packet.data++ = i;

	hold = 1;
	if (options->f_so_dontroute) {
		if (setsockopt(vars->socket_send, SOL_SOCKET, SO_DONTROUTE,
			(char *)&hold, sizeof(hold)) != 0) {
			print_error_strerr("setsockopt() SO_DONTROUTE");
			return (false);
		}
	}

	if (options->f_dont_fragment || options->f_tos) {
		if (!options->f_ttl && !options->f_multicast_ttl) {
			int mib[4];
			size_t sz;

			mib[0] = CTL_NET;
			mib[1] = PF_INET;
			mib[2] = IPPROTO_IP;
			mib[3] = IPCTL_DEFTTL;
			sz = sizeof(options->n_ttl);
			if (sysctl(mib, 4, &options->n_ttl, &sz, NULL,
				0) == -1) {
				print_error_strerr("sysctl(net.inet.ip.ttl)");
				return (false);
			}
		}
		if (setsockopt(vars->socket_send, IPPROTO_IP, IP_HDRINCL, &hold,
			sizeof(hold)) != 0) {
			print_error_strerr("setsockopt() IP_HDRINCL");
			return (false);
		}
		vars->send_packet.ip.ip_v = IPVERSION;
		vars->send_packet.ip.ip_hl = sizeof(struct ip) >> 2;
		vars->send_packet.ip.ip_tos = options->n_tos;
		vars->send_packet.ip.ip_id = 0;
		vars->send_packet.ip.ip_off =
			htons(options->f_dont_fragment ? IP_DF : 0);
		vars->send_packet.ip.ip_ttl = options->n_ttl;
		vars->send_packet.ip.ip_p = IPPROTO_ICMP;
		vars->send_packet.ip.ip_src.s_addr = options->f_source ?
			options->source_sockaddr.in.sin_addr.s_addr :
			INADDR_ANY;
		vars->send_packet.ip.ip_dst = vars->target_sockaddr->sin_addr;
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

#ifdef IP_OPTIONS
	/* record route option */
	if (options->f_rroute) {
		char rspace[MAX_IPOPTLEN];	/* record route space */

		memset(rspace, 0, sizeof(rspace));
		rspace[IPOPT_OPTVAL] = IPOPT_RR;
		rspace[IPOPT_OLEN] = sizeof(rspace) - 1;
		rspace[IPOPT_OFFSET] = IPOPT_MINOFF;
		rspace[sizeof(rspace) - 1] = IPOPT_EOL;
		if (setsockopt(vars->socket_send, IPPROTO_IP, IP_OPTIONS,
			rspace, sizeof(rspace)) != 0) {
			print_error_strerr("setsockopt IP_OPTIONS");
			return (false);
		}
	}
#endif /* IP_OPTIONS */

	if (options->f_ttl) {
		if (setsockopt(vars->socket_send, IPPROTO_IP, IP_TTL,
			&options->n_ttl, sizeof(options->n_ttl)) != 0) {
			print_error_strerr("setsockopt IP_TTL");
			return (false);
		}
	}
	if (options->f_no_loop) {
		const unsigned char loop = 0;

		if (setsockopt(vars->socket_send, IPPROTO_IP, IP_MULTICAST_LOOP,
			&loop, sizeof(loop)) != 0) {
			print_error_strerr("setsockopt IP_MULTICAST_LOOP");
			return (false);
		}
	}
	if (options->f_multicast_ttl) {
		if (setsockopt(vars->socket_send, IPPROTO_IP, IP_MULTICAST_TTL,
			&options->n_multicast_ttl,
			sizeof(options->n_multicast_ttl)) != 0) {
			print_error_strerr("setsockopt IP_MULTICAST_TTL");
			return (false);
		}
	}
	if (options->f_interface) {
		if (setsockopt(vars->socket_send, IPPROTO_IP, IP_MULTICAST_IF,
			&options->interface.ifaddr,
		    sizeof(options->interface.ifaddr)) != 0) {
			print_error_strerr("setsockopt IP_MULTICAST_IF");
			return (false);
		}
	}
#ifdef SO_TIMESTAMP
	{ int on = 1;
		if (setsockopt(vars->socket_recv, SOL_SOCKET, SO_TIMESTAMP, &on,
			sizeof(on)) != 0) {
			print_error_strerr("setsockopt SO_TIMESTAMP");
			return (false);
		}
	}
#endif
	if (options->f_sweep_max) {
		if (options->n_packets > 0) {
			counters->sweep_max_packets = options->n_packets;
			options->n_packets = 0;
		} else
			counters->sweep_max_packets = 1;
		options->n_packet_size = options->n_sweep_min;
		vars->send_packet.send_len = vars->send_packet.icmp_len + options->n_sweep_min;
	}

	/*
	 * When pinging the broadcast address, you can get a lot of answers.
	 * Doing something so evil is useful if you are trying to stress the
	 * ethernet, or just want to fill the arp cache to get some stuff for
	 * /etc/ethers.  But beware: RFC 1122 allows hosts to ignore broadcast
	 * or multicast pings if they wish.
	 */

	/*
	 * XXX receive buffer needs undetermined space for mbuf overhead
	 * as well.
	 */
	hold = IP_MAXPACKET + 128;
	if (setsockopt(vars->socket_recv, SOL_SOCKET, SO_RCVBUF, (char *)&hold,
		sizeof(hold)) != 0) {
		print_error_strerr("setsockopt() SO_RCVBUF");
		return (false);
	}
	/* CAP_SETSOCKOPT removed */
	if (!cap_limit_socket(vars->socket_recv, RIGHTS_RECV_EVENT))
		return (false);
	if (getuid() == 0) {
		if (setsockopt(vars->socket_send, SOL_SOCKET, SO_SNDBUF,
			(char *)&hold, sizeof(hold)) != 0) {
			print_error_strerr("setsockopt() SO_SNDBUF");
			return (false);
		}
	}
	/* CAP_SETSOCKOPT removed */
	if (!cap_limit_socket(vars->socket_send, RIGHTS_SEND))
		return (false);

	return (true);
}

bool
ping4_process_received_packet(const struct options *const options,
    struct shared_variables *const vars, struct counters *const counters,
    struct timing *const timing)
{
	int cc;
	char ctrl[CMSG_SPACE(sizeof(struct timeval))];
	struct iovec iov;
	struct msghdr msg;
	struct timeval now;
	struct timeval *tv = NULL;
#ifdef SO_TIMESTAMP
	struct cmsghdr *cmsg = (struct cmsghdr *)&ctrl;
#endif

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (caddr_t)&vars->recv_packet.from;
	msg.msg_namelen = sizeof(vars->recv_packet.from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
#ifdef SO_TIMESTAMP
	msg.msg_control = (caddr_t)ctrl;
	msg.msg_controllen = sizeof(ctrl);
#endif
	iov.iov_base = vars->recv_packet.raw;
	iov.iov_len = IP_MAXPACKET;

	if ((cc = recvmsg(vars->socket_recv, &msg, 0)) < 0) {
		if (errno == EINTR)
			return (false);
		warn("recvmsg");
		return (false);
	}
#ifdef SO_TIMESTAMP
	if (cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_TIMESTAMP &&
	    cmsg->cmsg_len == CMSG_LEN(sizeof(*tv))) {
		/* Copy to avoid alignment problems: */
		memcpy(&now, CMSG_DATA(cmsg), sizeof(now));
		tv = &now;
	}
#endif
	if (tv == NULL) {
		if (gettimeofday(&now, NULL) != 0) {
			print_error_strerr("gettimeofday()");
			return (false);
		}
		tv = &now;
	}

	/*
	 * Get size of IP header of the received packet. The
	 * information is contained in the lower four bits of the
	 * first byte.
	 */
	memcpy(&vars->recv_packet.ip_header_len, vars->recv_packet.raw, 1);
	vars->recv_packet.ip_header_len =
		(vars->recv_packet.ip_header_len & 0x0f) << 2;

	/* Copy 'struct ip' out of the raw packet byte array. */
	memcpy(&vars->recv_packet.ip, vars->recv_packet.raw,
	    vars->recv_packet.ip_header_len);
	/*
	 * Copy used part of 'struct icmp' out of the raw packet byte
	 * array.
	 */
	memcpy(&vars->recv_packet.icmp, vars->recv_packet.raw +
	    vars->recv_packet.ip_header_len, ICMP_MINLEN +
	    vars->send_packet.phdr_len);
	/* Get address of ICMP data in the raw buffer. */
	vars->recv_packet.icmp_payload = vars->recv_packet.raw +
		vars->recv_packet.ip_header_len;
#ifndef icmp_data
	vars->recv_packet.icmp_payload += offsetof(struct icmp, icmp_ip);
#else
	vars->recv_packet.icmp_payload += offsetof(struct icmp, icmp_data);
#endif

	if (!is_packet_too_short(vars->recv_packet.ip_header_len, cc,
		&vars->recv_packet.from, options->f_verbose)) {
		get_triptime(cc, tv, vars, timing->enabled);
		update_timing(cc, tv, vars, timing);
		update_counters(tv, options, vars, counters);
		pr_pack(cc, tv, options, vars, timing->enabled);
		mark_packet_as_received(&vars->recv_packet.icmp, vars);
	}

	return (true);
}

bool
update_sweep(struct options *const options, struct shared_variables *const vars,
    struct counters *const counters)
{
	if ((options->n_sweep_max > 0) &&
	    (counters->sweep_transmitted == counters->sweep_max_packets)) {
		for (int i = 0; i < options->n_sweep_incr ; ++i)
			*vars->send_packet.data++ = i;
		options->n_packet_size += options->n_sweep_incr;
		if (options->n_packet_size > options->n_sweep_max)
			return (false);
		vars->send_packet.send_len = vars->send_packet.icmp_len + options->n_packet_size;
		counters->sweep_transmitted = 0;
	}
	return (true);
}

/*
 * pinger --
 *	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first TIMEVAL_LEN
 * bytes of the data portion are used to hold a UNIX "timeval" struct in
 * host byte-order, to compute the round-trip time.
 */
bool
pinger(const struct options *const options, struct shared_variables *const vars,
    struct counters *const counters, const struct timing *const timing)
{
	struct timeval now;
	struct tv32 tv32;
	int cc, i;
	u_char *packet;

	packet = vars->send_packet.raw + sizeof(struct ip);
	vars->send_packet.icmp.icmp_type = vars->send_packet.icmp_type;
	vars->send_packet.icmp.icmp_code = 0;
	vars->send_packet.icmp.icmp_cksum = 0;
	vars->send_packet.icmp.icmp_seq = htons(counters->transmitted);
	vars->send_packet.icmp.icmp_id = vars->ident;

	BIT_ARRAY_CLR(vars->rcvd_tbl, counters->transmitted % MAX_DUP_CHK);

	if (options->f_time || timing->enabled) {
		if (gettimeofday(&now, NULL) != 0) {
			print_error_strerr("gettimeofday()");
			return (false);
		}

		tv32.tv32_sec = htonl(now.tv_sec);
		tv32.tv32_usec = htonl(now.tv_usec);
		if (options->f_time)
			vars->send_packet.icmp.icmp_otime =
				htonl((now.tv_sec % (24 * 60 * 60)) * 1000 +
				    now.tv_usec / 1000);
		if (timing->enabled)
			memcpy((void *)(vars->send_packet.raw +
				sizeof(struct ip) + ICMP_MINLEN +
				vars->send_packet.phdr_len), (void *)&tv32,
			    sizeof(tv32));
	}

	cc = ICMP_MINLEN + vars->send_packet.phdr_len + options->n_packet_size;

	/*
	 * Copy the used part of 'struct icmp' to raw data buffer so
	 * the checksum can be computed.
	 */
	memcpy(vars->send_packet.raw + sizeof(struct ip),
	    &vars->send_packet.icmp, ICMP_MINLEN + vars->send_packet.phdr_len);
	vars->send_packet.icmp.icmp_cksum = in_cksum(
	    (vars->send_packet.raw + sizeof(struct ip)), cc);
	/* Update only icmp_cksum in the raw data. */
	memcpy(vars->send_packet.raw + sizeof(struct ip) +
	    offsetof(struct icmp, icmp_cksum),
	    &vars->send_packet.icmp.icmp_cksum,
	    sizeof(vars->send_packet.icmp.icmp_cksum));

	if (options->f_dont_fragment || options->f_tos) {
		cc += sizeof(struct ip);
		vars->send_packet.ip.ip_len = htons(cc);
		/*
		 * Copy the 'struct ip' to raw data buffer so the
		 * checksum can be computed.
		 */
		memcpy(vars->send_packet.raw, &vars->send_packet.ip,
		    sizeof(struct ip));
		vars->send_packet.ip.ip_sum =
			in_cksum(vars->send_packet.raw, cc);
		/* Update only ip_sum in the raw data. */
		memcpy(vars->send_packet.raw + offsetof(struct ip, ip_sum),
		    &vars->send_packet.ip.ip_sum,
		    sizeof(vars->send_packet.ip.ip_sum));
		packet = vars->send_packet.raw;
	}
	i = send(vars->socket_send, (char *)packet, cc, 0);
	if (i < 0 || i != cc)  {
		if (i < 0) {
			if (options->f_flood && errno == ENOBUFS) {
				usleep(FLOOD_BACKOFF);
				return (true);
			}
			warn("sendto");
		} else {
			warn("%s: partial write: %d of %d bytes",
			     options->target, i, cc);
		}
	}
	counters->transmitted++;
	counters->sweep_transmitted++;
	if (!options->f_quiet && options->f_flood)
		write_char(STDOUT_FILENO, CHAR_DOT);

	return (true);
}

static bool
is_packet_too_short(u_char ip_header_len, size_t bufsize,
    const struct sockaddr_in *const from, bool verbose)
{
	if (bufsize < (ip_header_len + ICMP_MINLEN))  {
		if (verbose)
			warn("packet too short (%zu bytes) from %s", bufsize,
			    inet_ntoa(from->sin_addr));
		return (true);
	}
	return (false);
}

static void
get_triptime(size_t bufsize, struct timeval *const triptime,
    const struct shared_variables *const vars, bool timing_enabled)
{
	bufsize -= vars->recv_packet.ip_header_len;

	if ((vars->recv_packet.icmp.icmp_type ==
		vars->recv_packet.expected_icmp_type) &&
	    ((vars->recv_packet.icmp.icmp_id == vars->ident)
		&& timing_enabled)) {
		struct timeval tv1;
		struct tv32 tv32;
		const void *tp;

		tp = (const char *)vars->recv_packet.icmp_payload +
			vars->send_packet.phdr_len;

		if ((size_t)(bufsize - ICMP_MINLEN - vars->send_packet.phdr_len) >=
		    sizeof(tv1)) {
			/* Copy to avoid alignment problems: */
			memcpy(&tv32, tp, sizeof(tv32));
			tv1.tv_sec = ntohl(tv32.tv32_sec);
			tv1.tv_usec = ntohl(tv32.tv32_usec);
			tvsub(triptime, &tv1);
		}
	}
}

static void
update_timing(size_t bufsize, const struct timeval *const triptime,
    const struct shared_variables *const vars, struct timing *const timing)
{
	bufsize -= vars->recv_packet.ip_header_len;

	if ((vars->recv_packet.icmp.icmp_type ==
		vars->recv_packet.expected_icmp_type) &&
	    ((vars->recv_packet.icmp.icmp_id == vars->ident)
		&& timing->enabled)) {
		const void *tp;
		double triptime_sec;

		tp = (const char *)vars->recv_packet.icmp_payload +
			vars->send_packet.phdr_len;

		if ((size_t)(bufsize - ICMP_MINLEN - vars->send_packet.phdr_len) >=
		    sizeof(struct timeval)) {
			/* Copy to avoid alignment problems: */
			triptime_sec = ((double)triptime->tv_sec) * 1000.0 +
				((double)triptime->tv_usec) / 1000.0;
			timing->sum += triptime_sec;
			timing->sumsq += triptime_sec * triptime_sec;
			if (triptime_sec < timing->min)
				timing->min = triptime_sec;
			if (triptime_sec > timing->max)
				timing->max = triptime_sec;
		} else
			timing->enabled = false;
	}
}

static void
update_counters(const struct timeval *const triptime,
    const struct options *const options,
    const struct shared_variables *const vars, struct counters *const counters)
{
	if ((vars->recv_packet.icmp.icmp_type ==
		vars->recv_packet.expected_icmp_type) &&
	    (vars->recv_packet.icmp.icmp_id == vars->ident)) {
		size_t seq;
		double triptime_sec;

		seq = ntohs(vars->recv_packet.icmp.icmp_seq);
		if (BIT_ARRAY_IS_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK))
			++(counters->repeats);
		else
			++(counters->received);

		triptime_sec = ((double)triptime->tv_sec) * 1000.0 +
			((double)triptime->tv_usec) / 1000.0;

		if (!options->f_quiet &&
		    (options->f_wait_time &&
			triptime_sec > options->n_wait_time))
			++(counters->rcvtimeout);
	}
}

static void
mark_packet_as_received(const struct icmp *const icmp,
    struct shared_variables *const vars)
{
	if ((icmp->icmp_type ==
		vars->recv_packet.expected_icmp_type) &&
	    (icmp->icmp_id == vars->ident)) {
		size_t seq;

		seq = ntohs(icmp->icmp_seq);
		BIT_ARRAY_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK);
	}
}
