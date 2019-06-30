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
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <arpa/inet.h>

#include <libcasper.h>
#include <casper/cap_dns.h>

#ifdef IPSEC
#include <netipsec/ipsec.h>
#endif /*IPSEC*/

#include <capsicum_helpers.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "ping.h"
#include "timing.h"
#include "utils.h"

#define	INADDR_LEN	((int)sizeof(in_addr_t))
#define	TIMEVAL_LEN	((int)sizeof(struct tv32))
#define	MASK_LEN	(ICMP_MASKLEN - ICMP_MINLEN)
#define	TS_LEN		(ICMP_TSLEN - ICMP_MINLEN)
#define	FLOOD_BACKOFF	20000		/* usecs to back off if F_FLOOD mode */
					/* runs out of buffer space */
#define	MAXIPLEN	(sizeof(struct ip) + MAX_IPOPTLEN)
#define	MAXICMPLEN	(ICMP_ADVLENMIN + MAX_IPOPTLEN)

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.  Change 128
 * to 8192 for complete accuracy...
 */
#define	MAX_DUP_CHK	(8 * 128)

struct shared_variables {
	char rcvd_tbl[MAX_DUP_CHK / 8];
	struct sockaddr_in whereto;	/* who to ping */
	int ssend;		/* send socket file descriptor */
	u_char outpackhdr[IP_MAXPACKET], *outpack;
	char hostname[MAXHOSTNAMELEN];
	int ident;		/* process id to identify our packets */
	u_char icmp_type;
	u_char icmp_type_rsp;
	int phdr_len;
	int send_len;
	cap_channel_t *capdns;
};

struct counters {
	long nmissedmax;	/* max value of ntransmitted - nreceived - 1 */
	long nreceived;		/* # of packets we got back */
	long nrepeats;		/* number of duplicates */
	long ntransmitted;	/* sequence # for outbound packets = #sent */
	long snpackets;		/* max packets to transmit in one sweep */
	long sntransmitted;	/* # of packets we sent in this sweep */
	long nrcvtimeout;	/* # of packets we got back after waittime */
};

/* nonzero if we've been told to finish up */
static bool sig_option_f_numeric;
static volatile sig_atomic_t finish_up;
static volatile sig_atomic_t siginfo_p;
/* 
 * This pointer is used in the signal handler for accessing nreceived
 * member variable of the local 'struct counters' variable. Thus, the
 * nreceived variable does not have to be global.
 */
static const long *sig_counters_nreceived;

static u_short in_cksum(u_short *, int);
static cap_channel_t *capdns_setup(void);
static void check_status(const struct counters *const, const struct timing *const);
static void finish(const struct shared_variables *const, const struct counters *const,
    const struct timing *const) __dead2;
static void pinger(const struct options *const, struct shared_variables *const,
    struct counters *const, struct timing *const);
static char *pr_addr(struct in_addr, cap_channel_t *const, bool);
static char *pr_ntime(n_time);
static void pr_icmph(struct icmp *);
static void pr_iph(struct ip *);
static void pr_pack(char *, int, struct sockaddr_in *, struct timeval *,
    const struct options *const, struct shared_variables *const,
    struct counters *const, struct timing *const);
static void pr_retip(struct ip *);
static void status(int);
static void stopit(int);

void
ping(struct options *const options)
{
	struct sockaddr_in from, sock_in;
	struct in_addr ifaddr;
	struct timeval last;
	struct iovec iov;
	struct ip *ip;
	struct msghdr msg;
	struct sigaction si_sa;
	struct shared_variables vars;
	struct counters counters;
	struct timing timing;
	u_char *datap, packet[IP_MAXPACKET] __aligned(4);
	const char *shostname;
	struct sockaddr_in *to;
	int hold, icmp_len;
	int ssend_errno, srecv_errno;
	int srecv; /* receive socket file descriptor */
	char ctrl[CMSG_SPACE(sizeof(struct timeval))];
	cap_rights_t rights;

	/*
	 * Ping to IPv6 does use target_addrinfo but this ping to IPv4
	 * host does not use it.
	 */
	freeaddrinfo(options->target_addrinfo);
	options->target_addrinfo = NULL;

	memset(&vars, 0, sizeof(vars));
	vars.icmp_type = ICMP_ECHO;
	vars.icmp_type_rsp = ICMP_ECHOREPLY;

	memset(&counters, 0, sizeof(counters));
	sig_counters_nreceived = &counters.nreceived;

	timing_init(&timing);

	/*
	 * Do the stuff that we need root priv's for *first*, and
	 * then drop our setuid bit.  Save error reporting for
	 * after arg parsing.
	 *
	 * Historicaly ping was using one socket 's' for sending and for
	 * receiving. After capsicum(4) related changes we use two
	 * sockets. It was done for special ping use case - when user
	 * issue ping on multicast or broadcast address replies come
	 * from different addresses, not from the address we
	 * connect(2)'ed to, and send socket do not receive those
	 * packets.
	 */
	vars.ssend = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	ssend_errno = errno;
	srecv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	srecv_errno = errno;

	if (setuid(getuid()) != 0)
		err(EX_NOPERM, "setuid() failed");

	if (vars.ssend < 0) {
		errno = ssend_errno;
		err(EX_OSERR, "ssend socket");
	}

	if (srecv < 0) {
		errno = srecv_errno;
		err(EX_OSERR, "srecv socket");
	}

	vars.outpack = vars.outpackhdr + sizeof(struct ip);

	/* Globalize information needed by the signal handler */
	sig_option_f_numeric = options->f_numeric;

	if (options->f_flood)
		setbuf(stdout, (char *)NULL);

	/* TODO: alarm is obsoletet by setitimer(2) */
	if (options->f_timeout)
		alarm((unsigned int) options->n_timeout);

	if ((options->f_interface) && (inet_aton(options->s_interface, &ifaddr) == 0))
		errx(EX_USAGE, "invalid multicast interface: `%s'", options->s_interface);
	
	if (options->f_mask) {
		vars.icmp_type = ICMP_MASKREQ;
		vars.icmp_type_rsp = ICMP_MASKREPLY;
		vars.phdr_len = MASK_LEN;
		if (!options->f_quiet)
			(void)printf("ICMP_MASKREQ\n");
	} else if (options->f_time) {
		vars.icmp_type = ICMP_TSTAMP;
		vars.icmp_type_rsp = ICMP_TSTAMPREPLY;
		vars.phdr_len = TS_LEN;
		if (!options->f_quiet)
			(void)printf("ICMP_TSTAMP\n");

	}
	
	icmp_len = sizeof(struct ip) + ICMP_MINLEN + vars.phdr_len;
	if (options->f_rroute)
		icmp_len += MAX_IPOPTLEN;

	const int maxpayload = IP_MAXPACKET - icmp_len;

	if (options->n_packet_size > maxpayload)
		errx(EX_USAGE, "packet size too large: %ld > %d", options->n_packet_size,
		    maxpayload);
	vars.send_len = icmp_len + options->n_packet_size;
	datap = &vars.outpack[ICMP_MINLEN + vars.phdr_len + TIMEVAL_LEN];
	if (options->f_ping_filled) {
		fill((char *)datap, maxpayload - (TIMEVAL_LEN + options->ping_filled_size),
		    options);
		if (!options->f_quiet)
			print_fill_pattern((char *)datap, options->ping_filled_size);
	}
	vars.capdns = capdns_setup();
	if (options->s_source) {
		bzero((char *)&sock_in, sizeof(sock_in));
		sock_in.sin_family = AF_INET;
		if (inet_aton(options->s_source, &sock_in.sin_addr) != 0) {
			shostname = options->s_source;
		} else {
			char snamebuf[MAXHOSTNAMELEN];

			const struct hostent *const hp =
				cap_gethostbyname2(vars.capdns, options->s_source, AF_INET);

			if (!hp)
				errx(EX_NOHOST, "cannot resolve %s: %s",
				    options->s_source, hstrerror(h_errno));

			sock_in.sin_len = sizeof sock_in;
			if ((unsigned)hp->h_length > sizeof(sock_in.sin_addr) ||
			    hp->h_length < 0)
				errx(1, "gethostbyname2: illegal address");
			memcpy(&sock_in.sin_addr, hp->h_addr_list[0],
			    sizeof(sock_in.sin_addr));
			(void)strncpy(snamebuf, hp->h_name,
			    sizeof(snamebuf) - 1);
			snamebuf[sizeof(snamebuf) - 1] = '\0';
			shostname = snamebuf;
		}
		if (bind(vars.ssend, (struct sockaddr *)&sock_in, sizeof sock_in) ==
		    -1)
			err(1, "bind");
	}

	bzero(&vars.whereto, sizeof(vars.whereto));
	to = &vars.whereto;
	to->sin_family = AF_INET;
	to->sin_len = sizeof *to;
	if (inet_aton(options->target, &to->sin_addr) != 0) {
		/* TODO: check the return value of strncpy() */
		(void)strncpy(vars.hostname, options->target, sizeof(vars.hostname) - 1);
		vars.hostname[sizeof(vars.hostname) - 1] = '\0';
	} else {
		const struct hostent *const hp =
			cap_gethostbyname2(vars.capdns, options->target, AF_INET);

		if (!hp)
			errx(EX_NOHOST, "cannot resolve %s: %s",
			    options->target, hstrerror(h_errno));

		if ((unsigned)hp->h_length > sizeof(to->sin_addr))
			errx(1, "gethostbyname2 returned an illegal address");
		memcpy(&to->sin_addr, hp->h_addr_list[0], sizeof to->sin_addr);
		(void)strncpy(vars.hostname, hp->h_name, sizeof(vars.hostname) - 1);
		vars.hostname[sizeof(vars.hostname) - 1] = '\0';
	}

	/* From now on we will use only reverse DNS lookups. */
	if (vars.capdns != NULL) {
		const char *const types[1] = { "ADDR2NAME" };

		if (cap_dns_type_limit(vars.capdns, types, 1) < 0)
			err(1, "unable to limit access to system.dns service");
	}

	if (connect(vars.ssend, (struct sockaddr *)&vars.whereto, sizeof(vars.whereto)) != 0)
		err(1, "connect");

	if (options->f_flood && IN_MULTICAST(ntohl(to->sin_addr.s_addr)))
		errx(EX_USAGE,
		    "-f flag cannot be used with multicast destination");
	if ((options->f_interface || options->f_no_loop || options->f_multicast_ttl)
	    && !IN_MULTICAST(ntohl(to->sin_addr.s_addr)))
		errx(EX_USAGE,
		    "-I, -L, -T flags cannot be used with unicast destination");

	if (options->n_packet_size >= TIMEVAL_LEN)	/* can we time transfer */
		timing.enabled = true;

	if (!options->f_ping_filled)
		for (int i = TIMEVAL_LEN; i < options->n_packet_size; ++i)
			*datap++ = i;

	vars.ident = getpid() & 0xFFFF;

	hold = 1;
	if (options->f_so_debug) {
		(void)setsockopt(vars.ssend, SOL_SOCKET, SO_DEBUG, (char *)&hold,
		    sizeof(hold));
		(void)setsockopt(srecv, SOL_SOCKET, SO_DEBUG, (char *)&hold,
		    sizeof(hold));
	}
	if (options->f_so_dontroute)
		(void)setsockopt(vars.ssend, SOL_SOCKET, SO_DONTROUTE, (char *)&hold,
		    sizeof(hold));
#ifdef IPSEC
#ifdef IPSEC_POLICY_IPSEC
	if (options->f_policy) {
		char *buf;
		if (options->s_policy_in != NULL) {
			buf = ipsec_set_policy(options->s_policy_in, strlen(options->s_policy_in));
			if (buf == NULL)
				errx(EX_CONFIG, "%s", ipsec_strerror());
			if (setsockopt(srecv, IPPROTO_IP, IP_IPSEC_POLICY,
					buf, ipsec_get_policylen(buf)) < 0)
				err(EX_CONFIG,
				    "ipsec policy cannot be configured");
			free(buf);
		}

		if (options->s_policy_out != NULL) {
			buf = ipsec_set_policy(options->s_policy_out, strlen(options->s_policy_out));
			if (buf == NULL)
				errx(EX_CONFIG, "%s", ipsec_strerror());
			if (setsockopt(vars.ssend, IPPROTO_IP, IP_IPSEC_POLICY,
					buf, ipsec_get_policylen(buf)) < 0)
				err(EX_CONFIG,
				    "ipsec policy cannot be configured");
			free(buf);
		}
	}
#endif /*IPSEC_POLICY_IPSEC*/
#endif /*IPSEC*/

	if (options->f_dont_fragment || options->f_tos) {
		ip = (struct ip*)vars.outpackhdr;
		if (!options->f_ttl && !options->f_multicast_ttl) {
			int mib[4];
			size_t sz;

			mib[0] = CTL_NET;
			mib[1] = PF_INET;
			mib[2] = IPPROTO_IP;
			mib[3] = IPCTL_DEFTTL;
			sz = sizeof(options->n_ttl);
			if (sysctl(mib, 4, &options->n_ttl, &sz, NULL, 0) == -1)
				err(1, "sysctl(net.inet.ip.ttl)");
		}
		setsockopt(vars.ssend, IPPROTO_IP, IP_HDRINCL, &hold, sizeof(hold));
		ip->ip_v = IPVERSION;
		ip->ip_hl = sizeof(struct ip) >> 2;
		ip->ip_tos = options->n_tos;
		ip->ip_id = 0;
		ip->ip_off = htons(options->f_dont_fragment ? IP_DF : 0);
		ip->ip_ttl = options->n_ttl;
		ip->ip_p = IPPROTO_ICMP;
		ip->ip_src.s_addr = options->s_source ? sock_in.sin_addr.s_addr : INADDR_ANY;
		ip->ip_dst = to->sin_addr;
        }

	/*
	 * Here we enter capability mode. Further down access to global
	 * namespaces (e.g filesystem) is restricted (see capsicum(4)).
	 * We must connect(2) our socket before this point.
	 */
	caph_cache_catpages();
	if (caph_enter_casper() < 0)
		err(1, "cap_enter");

	cap_rights_init(&rights, CAP_RECV, CAP_EVENT, CAP_SETSOCKOPT);
	if (caph_rights_limit(srecv, &rights) < 0)
		err(1, "cap_rights_limit srecv");
	cap_rights_init(&rights, CAP_SEND, CAP_SETSOCKOPT);
	if (caph_rights_limit(vars.ssend, &rights) < 0)
		err(1, "cap_rights_limit ssend");

	/* record route option */
	if (options->f_rroute) {
#ifdef IP_OPTIONS
		char rspace[MAX_IPOPTLEN];	/* record route space */

		bzero(rspace, sizeof(rspace));
		rspace[IPOPT_OPTVAL] = IPOPT_RR;
		rspace[IPOPT_OLEN] = sizeof(rspace) - 1;
		rspace[IPOPT_OFFSET] = IPOPT_MINOFF;
		rspace[sizeof(rspace) - 1] = IPOPT_EOL;
		if (setsockopt(vars.ssend, IPPROTO_IP, IP_OPTIONS, rspace,
		    sizeof(rspace)) < 0)
			err(EX_OSERR, "setsockopt IP_OPTIONS");
#else
		errx(EX_UNAVAILABLE,
		    "record route not available in this implementation");
#endif /* IP_OPTIONS */
	}

	if (options->f_ttl) {
		if (setsockopt(vars.ssend, IPPROTO_IP, IP_TTL, &options->n_ttl,
		    sizeof(options->n_ttl)) < 0) {
			err(EX_OSERR, "setsockopt IP_TTL");
		}
	}
	if (options->f_no_loop) {
		const unsigned char loop = 0;

		if (setsockopt(vars.ssend, IPPROTO_IP, IP_MULTICAST_LOOP, &loop,
		    sizeof(loop)) < 0) {
			err(EX_OSERR, "setsockopt IP_MULTICAST_LOOP");
		}
	}
	if (options->f_multicast_ttl) {
		if (setsockopt(vars.ssend, IPPROTO_IP, IP_MULTICAST_TTL, &options->n_multicast_ttl,
		    sizeof(options->n_multicast_ttl)) < 0) {
			err(EX_OSERR, "setsockopt IP_MULTICAST_TTL");
		}
	}
	if (options->f_interface) {
		if (setsockopt(vars.ssend, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr,
		    sizeof(ifaddr)) < 0) {
			err(EX_OSERR, "setsockopt IP_MULTICAST_IF");
		}
	}
#ifdef SO_TIMESTAMP
	{ int on = 1;
	if (setsockopt(srecv, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) < 0)
		err(EX_OSERR, "setsockopt SO_TIMESTAMP");
	}
#endif
	if (options->f_sweep_max) {
		if (options->n_packets > 0) {
			counters.snpackets = options->n_packets;
			options->n_packets = 0;
		} else
			counters.snpackets = 1;
		options->n_packet_size = options->n_sweep_min;
		vars.send_len = icmp_len + options->n_sweep_min;
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
	(void)setsockopt(srecv, SOL_SOCKET, SO_RCVBUF, (char *)&hold,
	    sizeof(hold));
	/* CAP_SETSOCKOPT removed */
	cap_rights_init(&rights, CAP_RECV, CAP_EVENT);
	if (caph_rights_limit(srecv, &rights) < 0)
		err(1, "cap_rights_limit srecv setsockopt");
	if (getuid() == 0)
		(void)setsockopt(vars.ssend, SOL_SOCKET, SO_SNDBUF, (char *)&hold,
		    sizeof(hold));
	/* CAP_SETSOCKOPT removed */
	cap_rights_init(&rights, CAP_SEND);
	if (caph_rights_limit(vars.ssend, &rights) < 0)
		err(1, "cap_rights_limit ssend setsockopt");

	if (to->sin_family == AF_INET) {
		(void)printf("PING %s (%s)", vars.hostname,
		    inet_ntoa(to->sin_addr));
		if (options->s_source)
			(void)printf(" from %s", shostname);
		if (options->n_sweep_max)
			(void)printf(": (%d ... %d) data bytes\n",
			    options->n_sweep_min, options->n_sweep_max);
		else
			(void)printf(": %ld data bytes\n", options->n_packet_size);

	} else {
		if (options->n_sweep_max)
			(void)printf("PING %s: (%d ... %d) data bytes\n",
			    vars.hostname, options->n_sweep_min, options->n_sweep_max);
		else
			(void)printf("PING %s: %ld data bytes\n", vars.hostname, options->n_packet_size);
	}

	/*
	 * Use sigaction() instead of signal() to get unambiguous semantics,
	 * in particular with SA_RESTART not set.
	 */

	sigemptyset(&si_sa.sa_mask);
	si_sa.sa_flags = 0;

	si_sa.sa_handler = stopit;
	if (sigaction(SIGINT, &si_sa, 0) == -1) {
		err(EX_OSERR, "sigaction SIGINT");
	}

	si_sa.sa_handler = status;
	if (sigaction(SIGINFO, &si_sa, 0) == -1) {
		err(EX_OSERR, "sigaction");
	}

        if (options->n_timeout > 0) {
		si_sa.sa_handler = stopit;
		if (sigaction(SIGALRM, &si_sa, 0) == -1)
			err(EX_OSERR, "sigaction SIGALRM");
        }

	bzero(&msg, sizeof(msg));
	msg.msg_name = (caddr_t)&from;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
#ifdef SO_TIMESTAMP
	msg.msg_control = (caddr_t)ctrl;
#endif
	iov.iov_base = packet;
	iov.iov_len = IP_MAXPACKET;

	if (options->n_preload == 0)
		pinger(options, &vars, &counters, &timing);	/* send the first ping */
	else {
		if (options->n_packets != 0 && options->n_preload > options->n_packets)
			options->n_preload = options->n_packets;
		while (options->n_preload--)	/* fire off them quickies */
			pinger(options, &vars, &counters, &timing);
	}
	(void)gettimeofday(&last, NULL);

	if (options->f_flood) {
		options->n_interval.tv_sec = 0;
		options->n_interval.tv_usec = 10000;
	}

	bool almost_done = false;
	while (!finish_up) {
		struct timeval now, timeout;
		fd_set rfds;
		int cc, n;

		check_status(&counters, &timing);
		if ((unsigned)srecv >= FD_SETSIZE)
			errx(EX_OSERR, "descriptor too large");
		FD_ZERO(&rfds);
		FD_SET(srecv, &rfds);
		(void)gettimeofday(&now, NULL);
		timeout.tv_sec = last.tv_sec + options->n_interval.tv_sec - now.tv_sec;
		timeout.tv_usec = last.tv_usec + options->n_interval.tv_usec - now.tv_usec;
		while (timeout.tv_usec < 0) {
			timeout.tv_usec += 1000000;
			timeout.tv_sec--;
		}
		while (timeout.tv_usec >= 1000000) {
			timeout.tv_usec -= 1000000;
			timeout.tv_sec++;
		}
		if (timeout.tv_sec < 0)
			timerclear(&timeout);
		n = select(srecv + 1, &rfds, NULL, NULL, &timeout);
		if (n < 0)
			continue;	/* Must be EINTR. */
		if (n == 1) {
			struct timeval *tv = NULL;
#ifdef SO_TIMESTAMP
			struct cmsghdr *cmsg = (struct cmsghdr *)&ctrl;

			msg.msg_controllen = sizeof(ctrl);
#endif
			msg.msg_namelen = sizeof(from);
			if ((cc = recvmsg(srecv, &msg, 0)) < 0) {
				if (errno == EINTR)
					continue;
				warn("recvmsg");
				continue;
			}
#ifdef SO_TIMESTAMP
			if (cmsg->cmsg_level == SOL_SOCKET &&
			    cmsg->cmsg_type == SCM_TIMESTAMP &&
			    cmsg->cmsg_len == CMSG_LEN(sizeof *tv)) {
				/* Copy to avoid alignment problems: */
				memcpy(&now, CMSG_DATA(cmsg), sizeof(now));
				tv = &now;
			}
#endif
			if (tv == NULL) {
				(void)gettimeofday(&now, NULL);
				tv = &now;
			}
			pr_pack((char *)packet, cc, &from, tv, options, &vars, &counters, &timing);
			if ((options->f_once && counters.nreceived) ||
			    (options->n_packets && counters.nreceived >= options->n_packets))
				break;
		}
		if (n == 0 || options->f_flood) {
			if (options->n_sweep_max && counters.sntransmitted == counters.snpackets) {
				for (int i = 0; i < options->n_sweep_incr ; ++i)
					*datap++ = i;
				options->n_packet_size += options->n_sweep_incr;
				if (options->n_packet_size > options->n_sweep_max)
					break;
				vars.send_len = icmp_len + options->n_packet_size;
				counters.sntransmitted = 0;
			}
			if (!options->n_packets || counters.ntransmitted < options->n_packets)
				pinger(options, &vars, &counters, &timing);
			else {
				if (almost_done)
					break;
				almost_done = true;
				options->n_interval.tv_usec = 0;
				if (counters.nreceived) {
					options->n_interval.tv_sec = 2 * timing.max / 1000;
					if (!options->n_interval.tv_sec)
						options->n_interval.tv_sec = 1;
				} else {
					options->n_interval.tv_sec = options->n_wait_time / 1000;
					options->n_interval.tv_usec = options->n_wait_time % 1000 * 1000;
				}
			}
			(void)gettimeofday(&last, NULL);
			if (counters.ntransmitted - counters.nreceived - 1 > counters.nmissedmax) {
				counters.nmissedmax = counters.ntransmitted - counters.nreceived - 1;
				if (options->f_missed)
					write_char(STDOUT_FILENO, CHAR_BBELL);
			}
		}
	}
	finish(&vars, &counters, &timing);
	/* NOTREACHED */
	exit(0);	/* Make the compiler happy */
}

/*
 * stopit --
 *	Set the global bit that causes the main loop to quit.
 * Do NOT call finish() from here, since finish() does far too much
 * to be called from a signal handler.
 */
void
stopit(int sig __unused)
{

	/*
	 * When doing reverse DNS lookups, the finish_up flag might not
	 * be noticed for a while.  Just exit if we get a second SIGINT.
	 */
	if (!sig_option_f_numeric && finish_up)
		_exit(((sig_counters_nreceived != NULL) && (*sig_counters_nreceived != 0)) ? 0 : 2);
	finish_up = 1;
}

/*
 * pinger --
 *	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first TIMEVAL_LEN
 * bytes of the data portion are used to hold a UNIX "timeval" struct in
 * host byte-order, to compute the round-trip time.
 */
static void
pinger(const struct options *const options, struct shared_variables *const vars,
    struct counters *const counters, struct timing *const timing)
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
	icp->icmp_seq = htons(counters->ntransmitted);
	icp->icmp_id = vars->ident;			/* ID */

	BIT_ARRAY_CLR(vars->rcvd_tbl, counters->ntransmitted % MAX_DUP_CHK);

	if (options->f_time || timing->enabled) {
		(void)gettimeofday(&now, NULL);

		tv32.tv32_sec = htonl(now.tv_sec);
		tv32.tv32_usec = htonl(now.tv_usec);
		if (options->f_time)
			icp->icmp_otime = htonl((now.tv_sec % (24*60*60))
				* 1000 + now.tv_usec / 1000);
		if (timing->enabled)
			bcopy((void *)&tv32,
			    (void *)&vars->outpack[ICMP_MINLEN + vars->phdr_len],
			    sizeof(tv32));
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
	i = send(vars->ssend, (char *)packet, cc, 0);
	if (i < 0 || i != cc)  {
		if (i < 0) {
			if (options->f_flood && errno == ENOBUFS) {
				usleep(FLOOD_BACKOFF);
				return;
			}
			warn("sendto");
		} else {
			warn("%s: partial write: %d of %d bytes",
			     vars->hostname, i, cc);
		}
	}
	counters->ntransmitted++;
	counters->sntransmitted++;
	if (!options->f_quiet && options->f_flood)
		write_char(STDOUT_FILENO, CHAR_DOT);
}

/*
 * pr_pack --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
static void
pr_pack(char *buf, int cc, struct sockaddr_in *from, struct timeval *tv,
    const struct options *const options, struct shared_variables *const vars, 
    struct counters *const counters, struct timing *const timing)
{
	struct in_addr ina;
	u_char *cp, *dp;
	struct icmp *icp;
	struct ip *ip;
	const void *tp;
	double triptime;
	int dupflag, hlen, i, j, recv_len, seq;
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];

	/* Check the IP header */
	ip = (struct ip *)buf;
	hlen = ip->ip_hl << 2;
	recv_len = cc;
	if (cc < hlen + ICMP_MINLEN) {
		if (options->f_verbose)
			warn("packet too short (%d bytes) from %s", cc,
			     inet_ntoa(from->sin_addr));
		return;
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmp *)(buf + hlen);
	if (icp->icmp_type == vars->icmp_type_rsp) {
		if (icp->icmp_id != vars->ident)
			return;			/* 'Twas not our ECHO */
		++(counters->nreceived);
		triptime = 0.0;
		if (timing->enabled) {
			struct timeval tv1;
			struct tv32 tv32;
#ifndef icmp_data
			tp = &icp->icmp_ip;
#else
			tp = icp->icmp_data;
#endif
			tp = (const char *)tp + vars->phdr_len;

			if ((size_t)(cc - ICMP_MINLEN - vars->phdr_len) >=
			    sizeof(tv1)) {
				/* Copy to avoid alignment problems: */
				memcpy(&tv32, tp, sizeof(tv32));
				tv1.tv_sec = ntohl(tv32.tv32_sec);
				tv1.tv_usec = ntohl(tv32.tv32_usec);
				tvsub(tv, &tv1);
 				triptime = ((double)tv->tv_sec) * 1000.0 +
 				    ((double)tv->tv_usec) / 1000.0;
				timing->sum += triptime;
				timing->sumsq += triptime * triptime;
				if (triptime < timing->min)
					timing->min = triptime;
				if (triptime > timing->max)
					timing->max = triptime;
			} else
				timing->enabled = false;
		}

		seq = ntohs(icp->icmp_seq);

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
			write_char(STDOUT_FILENO, CHAR_BSPACE);
		else {
			(void)printf("%d bytes from %s: icmp_seq=%u", cc,
			   inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr),
			   seq);
			(void)printf(" ttl=%d", ip->ip_ttl);
			if (timing->enabled)
				(void)printf(" time=%.3f ms", triptime);
			if (dupflag)
				(void)printf(" (DUP!)");
			if (options->f_audible)
				write_char(STDOUT_FILENO, CHAR_BBELL);
			if (options->f_mask) {
				/* Just prentend this cast isn't ugly */
				(void)printf(" mask=%s",
					inet_ntoa(*(struct in_addr *)&(icp->icmp_mask)));
			}
			if (options->f_time) {
				(void)printf(" tso=%s", pr_ntime(icp->icmp_otime));
				(void)printf(" tsr=%s", pr_ntime(icp->icmp_rtime));
				(void)printf(" tst=%s", pr_ntime(icp->icmp_ttime));
			}
			if (recv_len != vars->send_len) {
                        	(void)printf(
				     "\nwrong total length %d instead of %d",
				     recv_len, vars->send_len);
			}
			/* check the data */
			cp = (u_char*)&icp->icmp_data[vars->phdr_len];
			dp = &vars->outpack[ICMP_MINLEN + vars->phdr_len];
			cc -= ICMP_MINLEN + vars->phdr_len;
			i = 0;
			if (timing->enabled) {   /* don't check variable timestamp */
				cp += TIMEVAL_LEN;
				dp += TIMEVAL_LEN;
				cc -= TIMEVAL_LEN;
				i += TIMEVAL_LEN;
			}
			for (; i < options->n_packet_size && cc > 0; ++i, ++cp, ++dp, --cc) {
				if (*cp != *dp) {
	(void)printf("\nwrong data byte #%d should be 0x%x but was 0x%x",
	    i, *dp, *cp);
					(void)printf("\ncp:");
					cp = (u_char*)&icp->icmp_data[0];
					for (i = 0; i < options->n_packet_size; ++i, ++cp) {
						if ((i % 16) == 8)
							(void)printf("\n\t");
						(void)printf("%2x ", *cp);
					}
					(void)printf("\ndp:");
					cp = &vars->outpack[ICMP_MINLEN];
					for (i = 0; i < options->n_packet_size; ++i, ++cp) {
						if ((i % 16) == 8)
							(void)printf("\n\t");
						(void)printf("%2x ", *cp);
					}
					break;
				}
			}
		}
	} else {
		/*
		 * We've got something other than an ECHOREPLY.
		 * See if it's a reply to something that we sent.
		 * We can compare IP destination, protocol,
		 * and ICMP type and ID.
		 *
		 * Only print all the error messages if we are running
		 * as root to avoid leaking information not normally
		 * available to those not running as root.
		 */
#ifndef icmp_data
		struct ip *oip = &icp->icmp_ip;
#else
		struct ip *oip = (struct ip *)icp->icmp_data;
#endif
		struct icmp *oicmp = (struct icmp *)(oip + 1);

		if (((options->f_verbose) && getuid() == 0) ||
		    (!(options->f_somewhat_quiet) &&
		     (oip->ip_dst.s_addr == vars->whereto.sin_addr.s_addr) &&
		     (oip->ip_p == IPPROTO_ICMP) &&
		     (oicmp->icmp_type == ICMP_ECHO) &&
		     (oicmp->icmp_id == vars->ident))) {
		    (void)printf("%d bytes from %s: ", cc,
			pr_addr(from->sin_addr, vars->capdns, options->f_numeric));
		    pr_icmph(icp);
		} else
		    return;
	}

	/* Display any IP options */
	cp = (u_char *)buf + sizeof(struct ip);

	for (; hlen > (int)sizeof(struct ip); --hlen, ++cp)
		switch (*cp) {
		case IPOPT_EOL:
			hlen = 0;
			break;
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			(void)printf(*cp == IPOPT_LSRR ?
			    "\nLSRR: " : "\nSSRR: ");
			j = cp[IPOPT_OLEN] - IPOPT_MINOFF + 1;
			hlen -= 2;
			cp += 2;
			if (j >= INADDR_LEN &&
			    j <= hlen - (int)sizeof(struct ip)) {
				for (;;) {
					bcopy(++cp, &ina.s_addr, INADDR_LEN);
					if (ina.s_addr == 0)
						(void)printf("\t0.0.0.0");
					else
						(void)printf("\t%s",
						     pr_addr(ina, vars->capdns, options->f_numeric));
					hlen -= INADDR_LEN;
					cp += INADDR_LEN - 1;
					j -= INADDR_LEN;
					if (j < INADDR_LEN)
						break;
					(void)printf("\n");
				}
			} else
				(void)printf("\t(truncated route)\n");
			break;
		case IPOPT_RR:
			j = cp[IPOPT_OLEN];		/* get length */
			i = cp[IPOPT_OFFSET];		/* and pointer */
			hlen -= 2;
			cp += 2;
			if (i > j)
				i = j;
			i = i - IPOPT_MINOFF + 1;
			if (i < 0 || i > (hlen - (int)sizeof(struct ip))) {
				old_rrlen = 0;
				continue;
			}
			if (i == old_rrlen
			    && !bcmp((char *)cp, old_rr, i)
			    && !(options->f_flood)) {
				(void)printf("\t(same route)");
				hlen -= i;
				cp += i;
				break;
			}
			old_rrlen = i;
			bcopy((char *)cp, old_rr, i);
			(void)printf("\nRR: ");
			if (i >= INADDR_LEN &&
			    i <= hlen - (int)sizeof(struct ip)) {
				for (;;) {
					bcopy(++cp, &ina.s_addr, INADDR_LEN);
					if (ina.s_addr == 0)
						(void)printf("\t0.0.0.0");
					else
						(void)printf("\t%s",
						     pr_addr(ina, vars->capdns, options->f_numeric));
					hlen -= INADDR_LEN;
					cp += INADDR_LEN - 1;
					i -= INADDR_LEN;
					if (i < INADDR_LEN)
						break;
					(void)printf("\n");
				}
			} else
				(void)printf("\t(truncated route)");
			break;
		case IPOPT_NOP:
			(void)printf("\nNOP");
			break;
		default:
			(void)printf("\nunknown option %x", *cp);
			break;
		}
	if (!options->f_flood) {
		(void)printf("\n");
		(void)fflush(stdout);
	}
}

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(u_short *addr, int len)
{
	int nleft, sum;
	u_short *w;
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
		last.uc[0] = *(u_char *)w;
		last.uc[1] = 0;
		sum += last.us;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

/*
 * status --
 *	Print out statistics when SIGINFO is received.
 */

static void
status(int sig __unused)
{

	siginfo_p = 1;
}

static void
check_status(const struct counters *const counters, const struct timing *const timing)
{

	if (siginfo_p) {
		siginfo_p = 0;
		(void)printf("\r%ld/%ld packets received (%.1f%%)",
		    counters->nreceived, counters->ntransmitted,
		    counters->ntransmitted ? counters->nreceived * 100.0 / counters->ntransmitted : 0.0);
		if (counters->nreceived && timing->enabled)
			(void)printf(" %.3f min / %.3f avg / %.3f max",
			    timing->min, timing->sum / (counters->nreceived + counters->nrepeats),
			    timing->max);
		(void)printf("\n");
	}
}

/*
 * finish --
 *	Print out statistics, and give up.
 */
static void
finish(const struct shared_variables *const vars, const struct counters *const counters,
    const struct timing *const timing)
{

	(void)signal(SIGINT, SIG_IGN);
	(void)signal(SIGALRM, SIG_IGN);
	(void)printf("\n");
	(void)fflush(stdout);
	(void)printf("--- %s ping statistics ---\n", vars->hostname);
	(void)printf("%ld packets transmitted, ", counters->ntransmitted);
	(void)printf("%ld packets received, ", counters->nreceived);
	if (counters->nrepeats)
		(void)printf("+%ld duplicates, ", counters->nrepeats);
	if (counters->ntransmitted) {
		if (counters->nreceived > counters->ntransmitted)
			(void)printf("-- somebody's printing up packets!");
		else
			(void)printf("%.1f%% packet loss",
			    ((counters->ntransmitted - counters->nreceived) * 100.0) /
			    counters->ntransmitted);
	}
	if (counters->nrcvtimeout)
		(void)printf(", %ld packets out of wait time", counters->nrcvtimeout);
	(void)printf("\n");
	if (counters->nreceived && timing->enabled) {
		double n = counters->nreceived + counters->nrepeats;
		double avg = timing->sum / n;
		double vari = timing->sumsq / n - avg * avg;
		(void)printf(
		    "round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
		    timing->min, avg, timing->max, sqrt(vari));
	}

	if (counters->nreceived)
		exit(0);
	else
		exit(2);
}

#ifdef notdef
static char *ttab[] = {
	"Echo Reply",		/* ip + seq + udata */
	"Dest Unreachable",	/* net, host, proto, port, frag, sr + IP */
	"Source Quench",	/* IP */
	"Redirect",		/* redirect type, gateway, + IP  */
	"Echo",
	"Time Exceeded",	/* transit, frag reassem + IP */
	"Parameter Problem",	/* pointer + IP */
	"Timestamp",		/* id + seq + three timestamps */
	"Timestamp Reply",	/* " */
	"Info Request",		/* id + sq */
	"Info Reply"		/* " */
};
#endif

/*
 * pr_icmph --
 *	Print a descriptive string about an ICMP header.
 */
static void
pr_icmph(struct icmp *icp)
{

	switch(icp->icmp_type) {
	case ICMP_ECHOREPLY:
		(void)printf("Echo Reply\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_UNREACH:
		switch(icp->icmp_code) {
		case ICMP_UNREACH_NET:
			(void)printf("Destination Net Unreachable\n");
			break;
		case ICMP_UNREACH_HOST:
			(void)printf("Destination Host Unreachable\n");
			break;
		case ICMP_UNREACH_PROTOCOL:
			(void)printf("Destination Protocol Unreachable\n");
			break;
		case ICMP_UNREACH_PORT:
			(void)printf("Destination Port Unreachable\n");
			break;
		case ICMP_UNREACH_NEEDFRAG:
			(void)printf("frag needed and DF set (MTU %d)\n",
					ntohs(icp->icmp_nextmtu));
			break;
		case ICMP_UNREACH_SRCFAIL:
			(void)printf("Source Route Failed\n");
			break;
		case ICMP_UNREACH_FILTER_PROHIB:
			(void)printf("Communication prohibited by filter\n");
			break;
		default:
			(void)printf("Dest Unreachable, Bad Code: %d\n",
			    icp->icmp_code);
			break;
		}
		/* Print returned IP header information */
#ifndef icmp_data
		pr_retip(&icp->icmp_ip);
#else
		pr_retip((struct ip *)icp->icmp_data);
#endif
		break;
	case ICMP_SOURCEQUENCH:
		(void)printf("Source Quench\n");
#ifndef icmp_data
		pr_retip(&icp->icmp_ip);
#else
		pr_retip((struct ip *)icp->icmp_data);
#endif
		break;
	case ICMP_REDIRECT:
		switch(icp->icmp_code) {
		case ICMP_REDIRECT_NET:
			(void)printf("Redirect Network");
			break;
		case ICMP_REDIRECT_HOST:
			(void)printf("Redirect Host");
			break;
		case ICMP_REDIRECT_TOSNET:
			(void)printf("Redirect Type of Service and Network");
			break;
		case ICMP_REDIRECT_TOSHOST:
			(void)printf("Redirect Type of Service and Host");
			break;
		default:
			(void)printf("Redirect, Bad Code: %d", icp->icmp_code);
			break;
		}
		(void)printf("(New addr: %s)\n", inet_ntoa(icp->icmp_gwaddr));
#ifndef icmp_data
		pr_retip(&icp->icmp_ip);
#else
		pr_retip((struct ip *)icp->icmp_data);
#endif
		break;
	case ICMP_ECHO:
		(void)printf("Echo Request\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIMXCEED:
		switch(icp->icmp_code) {
		case ICMP_TIMXCEED_INTRANS:
			(void)printf("Time to live exceeded\n");
			break;
		case ICMP_TIMXCEED_REASS:
			(void)printf("Frag reassembly time exceeded\n");
			break;
		default:
			(void)printf("Time exceeded, Bad Code: %d\n",
			    icp->icmp_code);
			break;
		}
#ifndef icmp_data
		pr_retip(&icp->icmp_ip);
#else
		pr_retip((struct ip *)icp->icmp_data);
#endif
		break;
	case ICMP_PARAMPROB:
		(void)printf("Parameter problem: pointer = 0x%02x\n",
		    icp->icmp_hun.ih_pptr);
#ifndef icmp_data
		pr_retip(&icp->icmp_ip);
#else
		pr_retip((struct ip *)icp->icmp_data);
#endif
		break;
	case ICMP_TSTAMP:
		(void)printf("Timestamp\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TSTAMPREPLY:
		(void)printf("Timestamp Reply\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_IREQ:
		(void)printf("Information Request\n");
		/* XXX ID + Seq */
		break;
	case ICMP_IREQREPLY:
		(void)printf("Information Reply\n");
		/* XXX ID + Seq */
		break;
	case ICMP_MASKREQ:
		(void)printf("Address Mask Request\n");
		break;
	case ICMP_MASKREPLY:
		(void)printf("Address Mask Reply\n");
		break;
	case ICMP_ROUTERADVERT:
		(void)printf("Router Advertisement\n");
		break;
	case ICMP_ROUTERSOLICIT:
		(void)printf("Router Solicitation\n");
		break;
	default:
		(void)printf("Bad ICMP type: %d\n", icp->icmp_type);
	}
}

/*
 * pr_iph --
 *	Print an IP header with options.
 */
static void
pr_iph(struct ip *ip)
{
	struct in_addr ina;
	u_char *cp;
	int hlen;

	hlen = ip->ip_hl << 2;
	cp = (u_char *)ip + 20;		/* point to options */

	(void)printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst\n");
	(void)printf(" %1x  %1x  %02x %04x %04x",
	    ip->ip_v, ip->ip_hl, ip->ip_tos, ntohs(ip->ip_len),
	    ntohs(ip->ip_id));
	(void)printf("   %1lx %04lx",
	    (u_long) (ntohl(ip->ip_off) & 0xe000) >> 13,
	    (u_long) ntohl(ip->ip_off) & 0x1fff);
	(void)printf("  %02x  %02x %04x", ip->ip_ttl, ip->ip_p,
							    ntohs(ip->ip_sum));
	memcpy(&ina, &ip->ip_src.s_addr, sizeof ina);
	(void)printf(" %s ", inet_ntoa(ina));
	memcpy(&ina, &ip->ip_dst.s_addr, sizeof ina);
	(void)printf(" %s ", inet_ntoa(ina));
	/* dump any option bytes */
	while (hlen-- > 20) {
		(void)printf("%02x", *cp++);
	}
	(void)printf("\n");
}

/*
 * pr_addr --
 *	Return an ascii host address as a dotted quad and optionally with
 * a hostname.
 */
static char *
pr_addr(struct in_addr ina, cap_channel_t *const capdns, bool numeric)
{
	struct hostent *hp;
	static char buf[16 + 3 + MAXHOSTNAMELEN];

	if (numeric)
		return inet_ntoa(ina);

	hp = cap_gethostbyaddr(capdns, (char *)&ina, 4, AF_INET);

	if (hp == NULL)
		return inet_ntoa(ina);

	(void)snprintf(buf, sizeof(buf), "%s (%s)", hp->h_name,
	    inet_ntoa(ina));
	return(buf);
}

/*
 * pr_retip --
 *	Dump some info on a returned (via ICMP) IP packet.
 */
static void
pr_retip(struct ip *ip)
{
	u_char *cp;
	int hlen;

	pr_iph(ip);
	hlen = ip->ip_hl << 2;
	cp = (u_char *)ip + hlen;

	if (ip->ip_p == 6)
		(void)printf("TCP: from port %u, to port %u (decimal)\n",
		    (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
	else if (ip->ip_p == 17)
		(void)printf("UDP: from port %u, to port %u (decimal)\n",
			(*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
}

static char *
pr_ntime(n_time timestamp)
{
	static char buf[10];
	int hour, min, sec;

	sec = ntohl(timestamp) / 1000;
	hour = sec / 60 / 60;
	min = (sec % (60 * 60)) / 60;
	sec = (sec % (60 * 60)) % 60;

	(void)snprintf(buf, sizeof(buf), "%02d:%02d:%02d", hour, min, sec);

	return (buf);
}

static cap_channel_t *
capdns_setup(void)
{
	cap_channel_t *capcas, *capdnsloc;
	const char *types[2];
	int families[1];

	capcas = cap_init();
	if (capcas == NULL)
		err(1, "unable to create casper process");
	capdnsloc = cap_service_open(capcas, "system.dns");
	/* Casper capability no longer needed. */
	cap_close(capcas);
	if (capdnsloc == NULL)
		err(1, "unable to open system.dns service");
	types[0] = "NAME2ADDR";
	types[1] = "ADDR2NAME";
	if (cap_dns_type_limit(capdnsloc, types, 2) < 0)
		err(1, "unable to limit access to system.dns service");
	families[0] = AF_INET;
	if (cap_dns_family_limit(capdnsloc, families, 1) < 0)
		err(1, "unable to limit access to system.dns service");

	return (capdnsloc);
}
