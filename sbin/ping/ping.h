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
 *
 * $FreeBSD$
 */

#ifndef PING_H
#define PING_H 1

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "cap.h"
#include "defaults_limits.h"
#include "options.h"

struct send_packet {
#ifdef INET
	int icmp_len;
	int phdr_len;
	int send_len;
	u_char raw[IP_MAXPACKET];
	struct ip ip;
	struct icmp icmp;
	u_char icmp_type;
	u_char *data;
#endif
};

struct receive_packet {
#ifdef INET
	u_char expected_icmp_type;
	struct sockaddr_in from;
	u_char raw[IP_MAXPACKET];
	struct ip ip;
	struct icmp icmp;
	u_char ip_header_len;
	const u_char *icmp_payload;
#endif
};

struct shared_variables {
	char rcvd_tbl[MAX_DUP_CHK / 8];
	int socket_send;
	int socket_recv;
	/* Process id to identify our packets. */
	int ident;
	cap_channel_t *capdns;
	struct send_packet send_packet;
	struct receive_packet recv_packet;
#ifdef INET
	const struct sockaddr_in *target_sockaddr;
#endif	/* INET */
#ifdef INET6
	struct sockaddr_in6 *target_sockaddr_in6;	/* who to ping6 */
	u_char outpack6[MAXPACKETLEN];			/* V6: outpack */
	uint8_t nonce[8];	/* nonce field for node information */
	int packlen;
	struct msghdr smsghdr;
	u_char *packet6;
#endif	/* INET6 */
};

struct counters {
	long missedmax;		/* max value of ntransmitted - received - 1 */
	long received;		/* # of packets we got back */
	long repeats;		/* number of duplicates */
	long transmitted;	/* sequence # for outbound packets = #sent */
	long rcvtimeout;	/* # of packets we got back after waittime */
#ifdef INET
	long sweep_max_packets;	/* max packets to transmit in one sweep */
	long sweep_transmitted;	/* # of packets we sent in this sweep */
#endif
};

struct signal_variables {
	volatile sig_atomic_t siginfo;
	volatile sig_atomic_t sigint_sigalrm;

	struct options *options;
	struct shared_variables *vars;
	const long *counters_received;
};

bool	ping_init(struct options *const options,
    struct shared_variables *const vars, struct counters *const counters,
    struct timing *const timing);
void	ping_free(struct options *const options,
    struct shared_variables *const vars);
bool	ping_send_initial_packets(struct options *const options,
    struct shared_variables *const vars,
    struct counters *const counters, struct timing *const timing);
bool	ping_loop(struct options *const options,
    struct shared_variables *const vars,
    struct counters *const counters, struct timing *const timing,
    struct signal_variables *const signal_vars);
void	ping_print_summary(struct options *const options,
    const struct counters *const counters, const struct timing *const timing);
void	ping_print_heading(const struct options *const options,
	const struct shared_variables *const vars);

#endif
