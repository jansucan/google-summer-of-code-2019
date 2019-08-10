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

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <string.h>
#include <math.h>

#include "ipsec.h"
#include "ping6_print.h"
#include "utils.h"

/* FQDN case, 64 bits of nonce + 32 bits ttl */
#define ICMP6_NIRLEN	(ICMP6ECHOLEN + 12)

static char	*dnsdecode(const u_char *, const u_char *const,
    const u_char *const, char *const, size_t);
static void	 pr6_icmph(const struct icmp6_hdr *const, const u_char *const,
    bool);
static void	 pr6_iph(const struct ip6_hdr *const);
static void	 pr6_suptypes(const struct icmp6_nodeinfo *const, size_t,
    bool verbose);
static void	 pr6_nodeaddr(const struct icmp6_nodeinfo *const, int,
    bool verbose);
static void	 pr6_exthdrs(const struct msghdr *const);
static void	 pr6_ip6opt(void *const, size_t);
static void	 pr6_rthdr(const void *const, size_t);
static int	 pr6_bitrange(uint32_t, int, int);
static void	 pr6_retip(const struct ip6_hdr *const, const u_char *const);

static char *
dnsdecode(const u_char *sp, const u_char *const ep, const u_char *const base,
    char *const buf, size_t bufsiz)
	/*base for compressed name*/
{
	int i;
	const u_char *cp;
	char cresult[MAXDNAME + 1];
	const u_char *comp;
	int l;

	cp = sp;
	*buf = '\0';

	if (cp >= ep)
		return (NULL);
	while (cp < ep) {
		i = *cp;
		if (i == 0 || cp != sp) {
			if (strlcat((char *)buf, ".", bufsiz) >= bufsiz)
				return (NULL);	/*result overrun*/
		}
		if (i == 0)
			break;
		cp++;

		if ((i & 0xc0) == 0xc0 && cp - base > (i & 0x3f)) {
			/* DNS compression */
			if (!base)
				return (NULL);

			comp = base + (i & 0x3f);
			if (dnsdecode(comp, cp, base, cresult,
			    sizeof(cresult)) == NULL)
				return (NULL);
			if (strlcat(buf, cresult, bufsiz) >= bufsiz)
				return (NULL);	/*result overrun*/
			break;
		} else if ((i & 0x3f) == i) {
			if (i > ep - cp)
				return (NULL);	/*source overrun*/
			while (i-- > 0 && cp < ep) {
				l = snprintf(cresult, sizeof(cresult),
				    isprint(*cp) ? "%c" : "\\%03o", *cp & 0xff);
				if ((size_t)l >= sizeof(cresult) || l < 0)
					return (NULL);
				if (strlcat(buf, cresult, bufsiz) >= bufsiz)
					return (NULL);	/*result overrun*/
				cp++;
			}
		} else
			return (NULL);	/*invalid label*/
	}
	if (i != 0)
		return (NULL);	/*not terminated*/
	cp++;
	sp = cp;
	return (buf);
}

int
get_hoplim(const struct msghdr *const mhdr)
{
	struct cmsghdr *cm;

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(mhdr); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(mhdr, cm)) {
		if (cm->cmsg_len == 0)
			return (-1);

		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_HOPLIMIT &&
		    cm->cmsg_len == CMSG_LEN(sizeof(int))) {
			int r;

			memcpy(&r, CMSG_DATA(cm), sizeof(r));
			return (r);
		}
	}

	return (-1);
}

struct in6_pktinfo *
get_rcvpktinfo(const struct msghdr *const mhdr)
{
	static struct in6_pktinfo pi;
	struct cmsghdr *cm;

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(mhdr); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(mhdr, cm)) {
		if (cm->cmsg_len == 0)
			return (NULL);

		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			memcpy(&pi, CMSG_DATA(cm), sizeof(pi));
			return (&pi);
		}
	}

	return (NULL);
}

bool
myechoreply(const struct icmp6_hdr *const icp, int ident)
{
	return (ntohs(icp->icmp6_id) == ident);
}

bool
mynireply(const struct icmp6_nodeinfo *const nip, const uint8_t *const nonce)
{
	return (memcmp(nip->icmp6_ni_nonce + sizeof(uint16_t),
		nonce + sizeof(uint16_t),
		sizeof(nonce) - sizeof(uint16_t)) == 0);
}

size_t
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

	return (l);
}

/*
 * pr6_pack --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
void
pr6_pack(int cc, const struct msghdr *const mhdr,
    const struct options *const options,
    const struct shared_variables *const vars,
    const struct timing *const timing,
    double triptime)
{
	struct icmp6_hdr *icp;
	struct icmp6_nodeinfo *ni;
	int i;
	int hoplim;
	struct sockaddr *from;
	int fromlen;
	u_char *cp = NULL, *end = vars->recv_packet.packet6 + cc;
	const u_char *dp;
	struct in6_pktinfo *pktinfo = NULL;
	size_t off;
	int oldfqdn;
	uint16_t seq;
	char dnsname[MAXDNAME + 1];

	from = (struct sockaddr *)mhdr->msg_name;
	fromlen = mhdr->msg_namelen;

	if (((mhdr->msg_flags & MSG_CTRUNC) != 0) &&
	    options->f_verbose)
		warnx("some control data discarded, insufficient buffer size");
	icp = (struct icmp6_hdr *)vars->recv_packet.packet6;
	ni = (struct icmp6_nodeinfo *)vars->recv_packet.packet6;
	off = 0;
	/*
	 * The next two calls cannot fail. They were tried and checked
	 * in is_packet_valid().
	 */
	hoplim = get_hoplim(mhdr);
	pktinfo = get_rcvpktinfo(mhdr);

	if (icp->icmp6_type == ICMP6_ECHO_REPLY &&
	    myechoreply(icp, vars->ident)) {
		seq = ntohs(icp->icmp6_seq);

		if (options->f_quiet)
			return;

		if (options->f_wait_time && triptime > options->n_wait_time)
			return;

		if (options->f_flood)
			write_char(STDOUT_FILENO, CHAR_BSPACE);
		else {
			if (options->f_audible)
				write_char(STDOUT_FILENO, CHAR_BBELL);
			(void)printf("%d bytes from %s, icmp_seq=%u", cc,
			    pr6_addr(from, fromlen, options->f_numeric,
				vars->capdns), seq);
			(void)printf(" hlim=%d", hoplim);
			if (options->f_verbose) {
				struct sockaddr_in6 dstsa;

				memset(&dstsa, 0, sizeof(dstsa));
				dstsa.sin6_family = AF_INET6;
				dstsa.sin6_len = sizeof(dstsa);
				dstsa.sin6_scope_id = pktinfo->ipi6_ifindex;
				dstsa.sin6_addr = pktinfo->ipi6_addr;
				(void)printf(" dst=%s",
				    pr6_addr((struct sockaddr *)&dstsa,
					sizeof(dstsa), options->f_numeric,
					vars->capdns));
			}
			if (timing->enabled)
				(void)printf(" time=%.3f ms", triptime);
			if (BIT_ARRAY_IS_SET(vars->rcvd_tbl, seq % MAX_DUP_CHK))
				(void)printf("(DUP!)");
			/* check the data */
			cp = vars->recv_packet.packet6 + off + ICMP6ECHOLEN +
				ICMP6ECHOTMLEN;
			dp = vars->send_packet.outpack6 + ICMP6ECHOLEN + ICMP6ECHOTMLEN;
			for (i = 8; cp < end; ++i, ++cp, ++dp) {
				if (*cp != *dp) {
					(void)printf("\nwrong data byte #%d "
					    "should be 0x%x but was 0x%x", i,
					    *dp, *cp);
					break;
				}
			}
		}
	} else if (icp->icmp6_type == ICMP6_NI_REPLY &&
	    mynireply(ni, vars->send_packet.nonce)) {
		uint16_t s;

		memcpy(&s, ni->icmp6_ni_nonce, sizeof(s));
		seq = ntohs(s);

		if (options->f_quiet)
			return;

		(void)printf("%d bytes from %s: ", cc, pr6_addr(from, fromlen,
			options->f_numeric, vars->capdns));

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
			pr6_suptypes(ni, end - (u_char *)ni,
			    options->f_verbose);
			break;
		case NI_QTYPE_NODEADDR:
			pr6_nodeaddr(ni, end - (u_char *)ni,
			    options->f_verbose);
			break;
		case NI_QTYPE_FQDN:
		default:	/* XXX: for backward compatibility */
			cp = (u_char *)ni + ICMP6_NIRLEN;
			if (vars->recv_packet.packet6[off + ICMP6_NIRLEN] ==
			    cc - off - ICMP6_NIRLEN - 1)
				oldfqdn = 1;
			else
				oldfqdn = 0;
			if (oldfqdn) {
				cp++;	/* skip length */
				while (cp < end) {
					const int c = *cp & 0xff;
					printf((isprint(c) ? "%c" : "\\%03o"),
					    c);
					cp++;
				}
			} else {
				i = 0;
				while (cp < end) {
					if (dnsdecode((const u_char *)cp, end,
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
						dnsname[strlen(dnsname) - 1] =
							'\0';
						cp++;
					}
					printf("%s%s", i > 0 ? "," : "",
					    dnsname);
				}
			}
			if (options->f_verbose) {
				u_long t;
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
				memcpy(&t, &vars->recv_packet.packet6[off+ICMP6ECHOLEN+8],
				    sizeof(t));
				ttl = (int32_t)ntohl(t);
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

				if (vars->recv_packet.packet6[off + ICMP6_NIRLEN] !=
				    cc - off - ICMP6_NIRLEN - 1 && oldfqdn) {
					if (comma)
						printf(",");
					(void)printf("invalid namelen:%d/%lu",
					    vars->recv_packet.packet6[off + ICMP6_NIRLEN],
					    (u_long)cc - off -
					    ICMP6_NIRLEN - 1);
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
		(void)printf("%d bytes from %s: ", cc, pr6_addr(from, fromlen,
			options->f_numeric, vars->capdns));
		pr6_icmph(icp, end, options->f_verbose);
	}

	if (!options->f_flood) {
		(void)printf("\n");
		if (options->f_verbose)
			pr6_exthdrs(mhdr);
		(void)fflush(stdout);
	}
}

static void
pr6_exthdrs(const struct msghdr *const mhdr)
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
			pr6_ip6opt(CMSG_DATA(cm), (size_t)bufsize);
			break;
		case IPV6_DSTOPTS:
#ifdef IPV6_RTHDRDSTOPTS
		case IPV6_RTHDRDSTOPTS:
#endif
			printf("  Dst Options: ");
			pr6_ip6opt(CMSG_DATA(cm), (size_t)bufsize);
			break;
		case IPV6_RTHDR:
			printf("  Routing: ");
			pr6_rthdr(CMSG_DATA(cm), (size_t)bufsize);
			break;
		}
	}
}

void
pr6_heading(const struct options *const options,
    const struct sockaddr_in6 *const dst, cap_channel_t *const capdns)
{
	const struct sockaddr_in6 *const src = &options->source_sockaddr.in6;

	printf("PING6(%lu=40+8+%lu bytes) ", (unsigned long)
	    (40 + pingerlen(options, sizeof(dst->sin6_addr))),
	    (unsigned long)(pingerlen(options, sizeof(dst->sin6_addr)) - 8));
	printf("%s --> ", pr6_addr((const struct sockaddr *)src, sizeof(*src),
		options->f_numeric, capdns));
	printf("%s\n", pr6_addr((const struct sockaddr *)dst, sizeof(*dst),
		options->f_numeric, capdns));
}

static void
pr6_ip6opt(void *const extbuf, size_t bufsize)
{
	struct ip6_hbh *ext;
	int currentlen;
	uint8_t type;
	socklen_t extlen, len;
	void *databuf;
	size_t offset;
	uint16_t value2;
	uint32_t value4;

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
			    (uint32_t)ntohl(value4));
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

static void
pr6_rthdr(const void *const extbuf, size_t bufsize)
{
	struct in6_addr *in6;
	char ntopbuf[INET6_ADDRSTRLEN];
	const struct ip6_rthdr *rh = (const struct ip6_rthdr *)extbuf;
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

static int
pr6_bitrange(uint32_t v, int soff, int ii)
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
	return (ii);
}

static void
pr6_suptypes(const struct icmp6_nodeinfo *const ni, size_t nilen, bool verbose)
{
	size_t clen;
	uint32_t v;
	const u_char *cp, *end;
	uint16_t cur;
	struct cbit {
		uint16_t words;	/*32bit count*/
		uint16_t skip;
	} cbit;
	const size_t maxqtypes = (1 << 16);
	size_t off;
	int b;

	assert(ni->ni_qtype == NI_QTYPE_SUPTYPES);

	cp = (const u_char *)(ni + 1);
	end = ((const u_char *)ni) + nilen;
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
			if (clen == 0 || clen > maxqtypes / 8 ||
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
			    maxqtypes)
				return;
		}

		for (off = 0; off < clen; off += sizeof(v)) {
			memcpy(&v, cp + off, sizeof(v));
			v = (uint32_t)ntohl(v);
			b = pr6_bitrange(v, (int)(cur + off * 8), b);
		}
		/* flush the remaining bits */
		b = pr6_bitrange(0, (int)(cur + off * 8), b);

		cp += clen;
		cur += clen * 8;
		if ((ni->ni_flags & NI_SUPTYPE_FLAG_COMPRESS) != 0)
			cur += ntohs(cbit.skip) * 32;
	}
}

static void
pr6_nodeaddr(const struct icmp6_nodeinfo *const ni, int nilen, bool verbose)
{
	const u_char *cp = (const u_char *)(ni + 1);
	char ntop_buf[INET6_ADDRSTRLEN];
	int withttl = 0;

	assert(ni->ni_qtype == NI_QTYPE_NODEADDR);

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
	if (nilen % (sizeof(uint32_t) + sizeof(struct in6_addr)) == 0)
		withttl = 1;
	while (nilen > 0) {
		uint32_t ttl;

		if (withttl) {
			uint32_t t;

			memcpy(&t, cp, sizeof(t));
			ttl = (uint32_t)ntohl(t);
			cp += sizeof(uint32_t);
			nilen -= sizeof(uint32_t);
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

/*
 * summary --
 *	Print out statistics.
 */
void
pr6_summary(const struct counters *const counters,
    const struct timing *const timing, const char *const hostname)
{

	(void)printf("\n--- %s ping6 statistics ---\n", hostname);
	(void)printf("%ld packets transmitted, ", counters->transmitted);
	(void)printf("%ld packets received, ",  counters->received);
	if (counters->repeats)
		(void)printf("+%ld duplicates, ", counters->repeats);
	if (counters->transmitted) {
		if (counters->received > counters->transmitted)
			(void)printf("-- somebody's duplicating packets!");
		else
			(void)printf("%.1f%% packet loss",
			    ((((double)counters->transmitted -
				    counters->received) * 100.0) /
			    counters->transmitted));
	}
	if (counters->rcvtimeout)
		printf(", %ld packets out of wait time", counters->rcvtimeout);
	(void)printf("\n");
	if (counters->received && timing->enabled) {
		/* Only display average to microseconds */
		double num = counters->received + counters->repeats;
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
 * pr6_icmph --
 *	Print a descriptive string about an ICMP header.
 */
static void
pr6_icmph(const struct icmp6_hdr *const icp, const u_char *const end,
    bool verbose)
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
	const struct nd_redirect *red;
	const struct icmp6_nodeinfo *ni;
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
		pr6_retip((const struct ip6_hdr *)(icp + 1), end);
		break;
	case ICMP6_PACKET_TOO_BIG:
		(void)printf("Packet too big mtu = %d\n",
		    (int)ntohl(icp->icmp6_mtu));
		pr6_retip((const struct ip6_hdr *)(icp + 1), end);
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
		pr6_retip((const struct ip6_hdr *)(icp + 1), end);
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
		    (uint32_t)ntohl(icp->icmp6_pptr));
		pr6_retip((const struct ip6_hdr *)(icp + 1), end);
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
		red = (const struct nd_redirect *)icp;
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
		ni = (const struct icmp6_nodeinfo *)icp;
		l = end - (const u_char *)(ni + 1);
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
				if (end == (const u_char *)(ni + 1)) {
					(void)printf(", no subject");
					break;
				}
				printf(", subject=%s", niqcode[ni->ni_code]);
				cp = (const u_char *)(ni + 1);
				if (dnsdecode(cp, end, NULL, dnsname,
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
		ni = (const struct icmp6_nodeinfo *)icp;
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
 * pr6_iph --
 *	Print an IP6 header.
 */
static void
pr6_iph(const struct ip6_hdr *const ip6)
{
	uint32_t flow = ip6->ip6_flow & IPV6_FLOWLABEL_MASK;
	uint8_t tc;
	char ntop_buf[INET6_ADDRSTRLEN];

	tc = *(&ip6->ip6_vfc + 1); /* XXX */
	tc = (tc >> 4) & 0x0f;
	tc |= (ip6->ip6_vfc << 4);

	printf("Vr TC  Flow Plen Nxt Hlim\n");
	printf(" %1x %02x %05x %04x  %02x   %02x\n",
	    (ip6->ip6_vfc & IPV6_VERSION_MASK) >> 4, tc, (uint32_t)ntohl(flow),
	    ntohs(ip6->ip6_plen), ip6->ip6_nxt, ip6->ip6_hlim);
	if (!inet_ntop(AF_INET6, &ip6->ip6_src, ntop_buf, sizeof(ntop_buf)))
		strlcpy(ntop_buf, "?", sizeof(ntop_buf));
	printf("%s->", ntop_buf);
	if (!inet_ntop(AF_INET6, &ip6->ip6_dst, ntop_buf, sizeof(ntop_buf)))
		strlcpy(ntop_buf, "?", sizeof(ntop_buf));
	printf("%s\n", ntop_buf);
}

/*
 * pr6_addr --
 *	Return an ascii host address as a dotted quad and optionally with
 * a hostname.
 */
const char *
pr6_addr(const struct sockaddr *const addr, int addrlen, bool numeric,
    cap_channel_t *const capdns)
{
	static char buf[NI_MAXHOST];
	int flag = 0;

	if (numeric)
		flag |= NI_NUMERICHOST;

	if (cap_getnameinfo(capdns, addr, addrlen, buf, sizeof(buf), NULL, 0,
		flag) == 0)
		return (buf);
	else
		return ("?");
}

/*
 * pr6_retip --
 *	Dump some info on a returned (via ICMPv6) IPv6 packet.
 */
static void
pr6_retip(const struct ip6_hdr *const ip6, const u_char *const end)
{
	const u_char *cp = (const u_char *)ip6;
	u_char nh;
	int hlen;

	if ((size_t)(end - (const u_char *)ip6) < sizeof(*ip6)) {
		printf("IP6");
		goto trunc;
	}
	pr6_iph(ip6);
	hlen = sizeof(*ip6);

	nh = ip6->ip6_nxt;
	cp += hlen;
	while (end - cp >= 8) {
		struct ah ah;

		switch (nh) {
		case IPPROTO_HOPOPTS:
			printf("HBH ");
			hlen = (((const struct ip6_hbh *)cp)->ip6h_len+1) << 3;
			nh = ((const struct ip6_hbh *)cp)->ip6h_nxt;
			break;
		case IPPROTO_DSTOPTS:
			printf("DSTOPT ");
			hlen = (((const struct ip6_dest *)cp)->ip6d_len+1) << 3;
			nh = ((const struct ip6_dest *)cp)->ip6d_nxt;
			break;
		case IPPROTO_FRAGMENT:
			printf("FRAG ");
			hlen = sizeof(struct ip6_frag);
			nh = ((const struct ip6_frag *)cp)->ip6f_nxt;
			break;
		case IPPROTO_ROUTING:
			printf("RTHDR ");
			hlen = (((const struct ip6_rthdr *)cp)->ip6r_len+1) << 3;
			nh = ((const struct ip6_rthdr *)cp)->ip6r_nxt;
			break;
#ifdef IPSEC
		case IPPROTO_AH:
			printf("AH ");
			memcpy(&ah, cp, sizeof(ah));
			hlen = (ah.ah_len+2) << 2;
			nh = ah.ah_nxt;
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
