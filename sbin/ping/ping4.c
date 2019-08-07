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

static u_short in_cksum(const u_short *const, int);
static void get_triptime(const char *const, size_t, struct timeval *const,
    const struct shared_variables *const, bool);
static bool is_packet_too_short(const char *const, size_t,
    const struct sockaddr_in *const, bool);
static void mark_packet_as_received(const char *const,
    struct shared_variables *const);
static void update_counters(const char *const, const struct timeval *const,
    const struct options *const, const struct shared_variables *const,
    struct counters *const);
static void update_timing(const char *const, size_t,
    const struct timeval *const, const struct shared_variables *const,
    struct timing *const);

bool
ping4_init(struct options *const options, struct shared_variables *const vars,
    struct counters *const counters, struct timing *const timing)
{
	struct ip *ip;
	int hold;

	vars->icmp_type = ICMP_ECHO;
	vars->icmp_type_rsp = ICMP_ECHOREPLY;

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#endif
	vars->target_sockaddr =
		(struct sockaddr_in *)options->target_addrinfo->ai_addr;
#ifdef __clang__
#pragma clang diagnostic pop
#endif
	vars->outpack = vars->outpackhdr + sizeof(struct ip);

	if (options->f_mask) {
		vars->icmp_type = ICMP_MASKREQ;
		vars->icmp_type_rsp = ICMP_MASKREPLY;
		vars->phdr_len = MASK_LEN;
		if (!options->f_quiet)
			(void)printf("ICMP_MASKREQ\n");
	} else if (options->f_time) {
		vars->icmp_type = ICMP_TSTAMP;
		vars->icmp_type_rsp = ICMP_TSTAMPREPLY;
		vars->phdr_len = TS_LEN;
		if (!options->f_quiet)
			(void)printf("ICMP_TSTAMP\n");

	}

	vars->icmp_len = sizeof(struct ip) + ICMP_MINLEN + vars->phdr_len;
	if (options->f_rroute)
		vars->icmp_len += MAX_IPOPTLEN;

	const int maxpayload = IP_MAXPACKET - vars->icmp_len;

	if (options->n_packet_size > maxpayload) {
		print_error("packet size too large: %ld > %d",
		    options->n_packet_size, maxpayload);
		return (false);
	}
	vars->send_len = vars->icmp_len + options->n_packet_size;
	vars->datap = &vars->outpack[ICMP_MINLEN + vars->phdr_len +
	    TIMEVAL_LEN];
	if (options->f_ping_filled) {
		fill((char *)vars->datap, maxpayload -
		    (TIMEVAL_LEN + options->ping_filled_size), options);
		if (!options->f_quiet)
			print_fill_pattern((char *)vars->datap,
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
			*vars->datap++ = i;

	hold = 1;
	if (options->f_so_dontroute) {
		if (setsockopt(vars->socket_send, SOL_SOCKET, SO_DONTROUTE,
			(char *)&hold, sizeof(hold)) != 0) {
			print_error_strerr("setsockopt() SO_DONTROUTE");
			return (false);
		}
	}

	if (options->f_dont_fragment || options->f_tos) {
		ip = (struct ip *)vars->outpackhdr;
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
		ip->ip_v = IPVERSION;
		ip->ip_hl = sizeof(struct ip) >> 2;
		ip->ip_tos = options->n_tos;
		ip->ip_id = 0;
		ip->ip_off = htons(options->f_dont_fragment ? IP_DF : 0);
		ip->ip_ttl = options->n_ttl;
		ip->ip_p = IPPROTO_ICMP;
		ip->ip_src.s_addr = options->f_source ?
			options->source_sockaddr.in.sin_addr.s_addr :
			INADDR_ANY;
		ip->ip_dst = vars->target_sockaddr->sin_addr;
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
		vars->send_len = vars->icmp_len + options->n_sweep_min;
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
	msg.msg_name = (caddr_t)&vars->from;
	msg.msg_namelen = sizeof(vars->from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
#ifdef SO_TIMESTAMP
	msg.msg_control = (caddr_t)ctrl;
	msg.msg_controllen = sizeof(ctrl);
#endif
	iov.iov_base = vars->rcvd_packet;
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
	if (!is_packet_too_short((char *)vars->rcvd_packet, cc, &vars->from,
		options->f_verbose)) {
		get_triptime((char *)vars->rcvd_packet, cc, tv, vars,
		    timing->enabled);
		update_timing((char *)vars->rcvd_packet, cc, tv, vars, timing);
		update_counters((char *)vars->rcvd_packet, tv, options, vars,
		    counters);
		pr_pack((char *)vars->rcvd_packet, cc, &vars->from, tv, options,
		    vars, timing->enabled);
		mark_packet_as_received((char *)vars->rcvd_packet, vars);
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
			*vars->datap++ = i;
		options->n_packet_size += options->n_sweep_incr;
		if (options->n_packet_size > options->n_sweep_max)
			return (false);
		vars->send_len = vars->icmp_len + options->n_packet_size;
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
	struct ip *ip;
	struct icmp *icp;
	int cc, i;
	u_char *packet;

	packet = vars->outpack;
	icp = (struct icmp *)vars->outpack;
	icp->icmp_type = vars->icmp_type;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = htons(counters->transmitted);
	icp->icmp_id = vars->ident;			/* ID */

	BIT_ARRAY_CLR(vars->rcvd_tbl, counters->transmitted % MAX_DUP_CHK);

	if (options->f_time || timing->enabled) {
		if (gettimeofday(&now, NULL) != 0) {
			print_error_strerr("gettimeofday()");
			return (false);
		}

		tv32.tv32_sec = htonl(now.tv_sec);
		tv32.tv32_usec = htonl(now.tv_usec);
		if (options->f_time)
			icp->icmp_otime = htonl((now.tv_sec % (24 * 60 * 60))
				* 1000 + now.tv_usec / 1000);
		if (timing->enabled)
			memcpy((void *)&vars->outpack[ICMP_MINLEN +
				vars->phdr_len], (void *)&tv32, sizeof(tv32));
	}

	cc = ICMP_MINLEN + vars->phdr_len + options->n_packet_size;

	/* compute ICMP checksum here */
	icp->icmp_cksum = in_cksum((u_short *)icp, cc);

	if (options->f_dont_fragment || options->f_tos) {
		cc += sizeof(struct ip);
		ip = (struct ip *)vars->outpackhdr;
		ip->ip_len = htons(cc);
		ip->ip_sum = in_cksum((u_short *)vars->outpackhdr, cc);
		packet = vars->outpackhdr;
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
is_packet_too_short(const char *const buf, size_t bufsize,
    const struct sockaddr_in *const from, bool verbose)
{
	const struct ip *ip;
	size_t hlen;

	ip = (const struct ip *)buf;
	hlen = ip->ip_hl << 2;

	if (bufsize < (hlen + ICMP_MINLEN))  {
		if (verbose)
			warn("packet too short (%zu bytes) from %s", bufsize,
			    inet_ntoa(from->sin_addr));
		return (true);
	}
	return (false);
}

static void
get_triptime(const char *const buf, size_t bufsize,
    struct timeval *const triptime, const struct shared_variables *const vars,
    bool timing_enabled)
{
	const struct icmp *icp;
	const struct ip *ip;
	const void *tp;
	size_t hlen;

	ip = (const struct ip *)buf;
	hlen = ip->ip_hl << 2;

	/* Now the ICMP part */
	bufsize -= hlen;
	icp = (const struct icmp *)(buf + hlen);
	if ((icp->icmp_type == vars->icmp_type_rsp) &&
	    ((icp->icmp_id == vars->ident) && (timing_enabled))) {
		struct timeval tv1;
		struct tv32 tv32;
#ifndef icmp_data
		tp = &icp->icmp_ip;
#else
		tp = icp->icmp_data;
#endif
		tp = (const char *)tp + vars->phdr_len;

		if ((size_t)(bufsize - ICMP_MINLEN - vars->phdr_len) >=
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
update_timing(const char *const buf, size_t bufsize,
    const struct timeval *const triptime,
    const struct shared_variables *const vars, struct timing *const timing)
{
	const struct icmp *icp;
	const struct ip *ip;
	const void *tp;
	double triptime_sec;
	size_t hlen;

	ip = (const struct ip *)buf;
	hlen = ip->ip_hl << 2;

	/* Now the ICMP part */
	bufsize -= hlen;
	icp = (const struct icmp *)(buf + hlen);

	if ((icp->icmp_type == vars->icmp_type_rsp) &&
	    (icp->icmp_id == vars->ident) && (timing->enabled)) {
#ifndef icmp_data
		tp = &icp->icmp_ip;
#else
		tp = icp->icmp_data;
#endif
		tp = (const char *)tp + vars->phdr_len;

		if ((size_t)(bufsize - ICMP_MINLEN - vars->phdr_len) >=
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
update_counters(const char *const buf, const struct timeval *const triptime,
    const struct options *const options,
    const struct shared_variables *const vars, struct counters *const counters)
{
	const struct icmp *icp;
	const struct ip *ip;
	size_t hlen, seq;
	double triptime_sec;

	ip = (const struct ip *)buf;
	hlen = ip->ip_hl << 2;

	icp = (const struct icmp *)(buf + hlen);
	if ((icp->icmp_type == vars->icmp_type_rsp) &&
	    (icp->icmp_id == vars->ident)) {
		seq = ntohs(icp->icmp_seq);
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
mark_packet_as_received(const char *const buf,
    struct shared_variables *const vars)
{
	const struct icmp *icp;
	const struct ip *ip;
	size_t hlen, seq;

	ip = (const struct ip *)buf;
	hlen = ip->ip_hl << 2;

	/* Now the ICMP part */
	icp = (const struct icmp *)(buf + hlen);
	if ((icp->icmp_type == vars->icmp_type_rsp) &&
	    (icp->icmp_id == vars->ident)) {
		seq = ntohs(icp->icmp_seq);
		BIT_ARRAY_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK);
	}
}

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(const u_short *const addr, int len)
{
	int nleft, sum;
	const u_short *w;
	union {
		u_short	us;
		u_char	uc[2];
	} last;
	u_short answer;

	nleft = len;
	sum = 0;
	w = addr;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		last.uc[0] = *(const u_char *)w;
		last.uc[1] = 0;
		sum += last.us;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}
