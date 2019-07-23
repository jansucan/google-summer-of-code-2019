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

#include <math.h>
#include <string.h>
#include <strings.h>

#include "ping4_print.h"
#include "utils.h"

#define	INADDR_LEN	((int)sizeof(in_addr_t))

static char *pr_addr(struct in_addr, cap_channel_t *const, bool);
static char *pr_ntime(n_time);
static void pr_icmph(const struct icmp *);
static void pr_iph(const struct ip *);
static void pr_retip(const struct ip *);

/*
 * pr_pack --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
void
pr_pack(const char *const buf, int cc, const struct sockaddr_in *const from,
    const struct timeval *const triptime, const struct options *const options,
    const struct shared_variables *const vars, bool timing_enabled)
{
	struct in_addr ina;
	const u_char *cp;
	u_char *dp;
	const struct icmp *icp;
	const struct ip *ip;
	int hlen, i, j, recv_len, seq;
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];

	ip = (const struct ip *)buf;
	hlen = ip->ip_hl << 2;
	recv_len = cc;

	/* Now the ICMP part */
	cc -= hlen;
	icp = (const struct icmp *)(buf + hlen);
	if (icp->icmp_type == vars->icmp_type_rsp) {
		double triptime_sec;

		if (icp->icmp_id != vars->ident)
			return;			/* 'Twas not our ECHO */

		if (options->f_quiet)
			return;

		triptime_sec = ((double)triptime->tv_sec) * 1000.0 +
			((double)triptime->tv_usec) / 1000.0;

		if (options->f_wait_time && triptime_sec > options->n_wait_time)
			return;

		seq = ntohs(icp->icmp_seq);

		if (options->f_flood)
			write_char(STDOUT_FILENO, CHAR_BSPACE);
		else {
			(void)printf("%d bytes from %s: icmp_seq=%u", cc,
			   inet_ntoa(*(const struct in_addr *)&from->sin_addr.s_addr),
			   seq);
			(void)printf(" ttl=%d", ip->ip_ttl);
			if (timing_enabled)
				(void)printf(" time=%.3f ms", triptime_sec);
			if (BIT_ARRAY_IS_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK))
				(void)printf(" (DUP!)");
			if (options->f_audible)
				write_char(STDOUT_FILENO, CHAR_BBELL);
			if (options->f_mask) {
				/* Just prentend this cast isn't ugly */
				(void)printf(" mask=%s",
					inet_ntoa(*(const struct in_addr *)&(icp->icmp_mask)));
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
			cp = (const u_char*)&icp->icmp_data[vars->phdr_len];
			dp = &vars->outpack[ICMP_MINLEN + vars->phdr_len];
			cc -= ICMP_MINLEN + vars->phdr_len;
			i = 0;
			if (timing_enabled) {   /* don't check variable timestamp */
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
					cp = (const u_char*)&icp->icmp_data[0];
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
		const struct ip *oip = (const struct ip *)icp->icmp_data;
#endif
		const struct icmp *oicmp = (const struct icmp *)(oip + 1);

		if (((options->f_verbose) && getuid() == 0) ||
		    (!(options->f_somewhat_quiet) &&
		     (oip->ip_dst.s_addr == vars->target_sockaddr->sin_addr.s_addr) &&
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
	cp = (const u_char *)buf + sizeof(struct ip);

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
			    && !bcmp((const char *)cp, old_rr, i)
			    && !(options->f_flood)) {
				(void)printf("\t(same route)");
				hlen -= i;
				cp += i;
				break;
			}
			old_rrlen = i;
			bcopy((const char *)cp, old_rr, i);
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

void
pr_heading(const struct sockaddr_in *const target_sockaddr,
    const struct options *const options)
{
	if (target_sockaddr->sin_family == AF_INET) {
		(void)printf("PING %s (%s)", options->target,
		    inet_ntoa(target_sockaddr->sin_addr));
		if (options->f_source)
			(void)printf(" from %s", options->s_source);
		if (options->n_sweep_max)
			(void)printf(": (%d ... %d) data bytes\n",
			    options->n_sweep_min, options->n_sweep_max);
		else
			(void)printf(": %ld data bytes\n", options->n_packet_size);

	} else {
		if (options->n_sweep_max)
			(void)printf("PING %s: (%d ... %d) data bytes\n",
			    options->target, options->n_sweep_min, options->n_sweep_max);
		else
			(void)printf("PING %s: %ld data bytes\n", options->target, options->n_packet_size);
	}
}


/*
 * pr_icmph --
 *	Print a descriptive string about an ICMP header.
 */
static void
pr_icmph(const struct icmp *icp)
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
		pr_retip((const struct ip *)icp->icmp_data);
#endif
		break;
	case ICMP_SOURCEQUENCH:
		(void)printf("Source Quench\n");
#ifndef icmp_data
		pr_retip(&icp->icmp_ip);
#else
		pr_retip((const struct ip *)icp->icmp_data);
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
		pr_retip((const struct ip *)icp->icmp_data);
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
		pr_retip((const struct ip *)icp->icmp_data);
#endif
		break;
	case ICMP_PARAMPROB:
		(void)printf("Parameter problem: pointer = 0x%02x\n",
		    icp->icmp_hun.ih_pptr);
#ifndef icmp_data
		pr_retip(&icp->icmp_ip);
#else
		pr_retip((const struct ip *)icp->icmp_data);
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
pr_iph(const struct ip *ip)
{
	struct in_addr ina;
	const u_char *cp;
	int hlen;

	hlen = ip->ip_hl << 2;
	cp = (const u_char *)ip + 20;		/* point to options */

	(void)printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst\n");
	(void)printf(" %1x  %1x  %02x %04x %04x",
	    ip->ip_v, ip->ip_hl, ip->ip_tos, ntohs(ip->ip_len),
	    ntohs(ip->ip_id));
	(void)printf("   %1lx %04lx",
	    (u_long) (ntohl(ip->ip_off) & 0xe000) >> 13,
	    (u_long) ntohl(ip->ip_off) & 0x1fff);
	(void)printf("  %02x  %02x %04x", ip->ip_ttl, ip->ip_p,
							    ntohs(ip->ip_sum));
	memcpy(&ina, &ip->ip_src.s_addr, sizeof(ina));
	(void)printf(" %s ", inet_ntoa(ina));
	memcpy(&ina, &ip->ip_dst.s_addr, sizeof(ina));
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
		return (inet_ntoa(ina));

	hp = cap_gethostbyaddr(capdns, (char *)&ina, 4, AF_INET);

	if (hp == NULL)
		return (inet_ntoa(ina));

	(void)snprintf(buf, sizeof(buf), "%s (%s)", hp->h_name,
	    inet_ntoa(ina));
	return (buf);
}

/*
 * pr_retip --
 *	Dump some info on a returned (via ICMP) IP packet.
 */
static void
pr_retip(const struct ip *ip)
{
	const u_char *cp;
	int hlen;

	pr_iph(ip);
	hlen = ip->ip_hl << 2;
	cp = (const u_char *)ip + hlen;

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

/*
 * pr_summary --
 *	Print out statistics.
 */
void
pr_summary(const struct counters *const counters,
    const struct timing *const timing, const char *const target)
{
	(void)printf("\n");
	(void)fflush(stdout);
	(void)printf("--- %s ping statistics ---\n", target);
	(void)printf("%ld packets transmitted, ", counters->transmitted);
	(void)printf("%ld packets received, ", counters->received);
	if (counters->repeats)
		(void)printf("+%ld duplicates, ", counters->repeats);
	if (counters->transmitted) {
		if (counters->received > counters->transmitted)
			(void)printf("-- somebody's printing up packets!");
		else
			(void)printf("%.1f%% packet loss",
			    ((counters->transmitted - counters->received) * 100.0) /
			    counters->transmitted);
	}
	if (counters->rcvtimeout)
		(void)printf(", %ld packets out of wait time", counters->rcvtimeout);
	(void)printf("\n");
	if (counters->received && timing->enabled) {
		double n = counters->received + counters->repeats;
		double avg = timing->sum / n;
		double vari = timing->sumsq / n - avg * avg;
		(void)printf(
		    "round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
		    timing->min, avg, timing->max, sqrt(vari));
	}
}

void
pr_status(const struct counters *const counters, const struct timing *const timing)
{
	(void)printf("\r%ld/%ld packets received (%.1f%%)",
	    counters->received, counters->transmitted,
	    counters->transmitted ? counters->received * 100.0 / counters->transmitted : 0.0);
	if (counters->received && timing->enabled)
		(void)printf(" %.3f min / %.3f avg / %.3f max",
		    timing->min, timing->sum / (counters->received + counters->repeats),
		    timing->max);
	(void)printf("\n");
}
