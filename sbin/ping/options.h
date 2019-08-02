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

#ifndef OPTIONS_H
#define OPTIONS_H 1

#include <sys/param.h>
#include <sys/time.h>

/*
 * This block of includes is needed here. It contains preprocessor
 * symbols for configuration of 'struct options' during build-time.
 */
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netipsec/ipsec.h>

#include <stdbool.h>

#include "cap.h"

enum target_type {
	TARGET_UNKNOWN,
#ifdef INET
	TARGET_IPV4,
#endif
#ifdef INET6
	TARGET_IPV6
#endif
};

struct options {
	/*
	 * Prefixes of the member variables:
	 *   f_ - flag
	 *   n_ - number argument
	 *   s_ - string argument
	 *   c_ - occurence count of the option
	 *   a_ - array argument
	 */

	/* TODO: ordering of the variables */
	/* TODO: rationalize the data types */

	bool f_missed;
	bool f_audible;
	/* Max packets to transmit */
	bool f_packets;
	long n_packets;
	bool f_dont_fragment;
	bool f_so_debug;
	bool f_flood;
	bool        f_interface;
	const char *s_interface;
	union {
#ifdef INET
		struct in_addr ifaddr;
#endif
#ifdef INET6
		unsigned int index;
#endif
	} interface;
	/* Wait between sending packets */
	bool    f_interval;
	struct timeval n_interval;
	bool f_preload;
	int  n_preload;
	bool f_numeric;
	bool f_once;
	/* Fill buffer with user pattern  */
	bool f_ping_filled;
	int  a_ping_filled[16];
	/* Number of bytes of the pattern */
	size_t ping_filled_size;
	bool f_quiet;
	bool f_source;
	char s_source[MAXHOSTNAMELEN];
	union {
#ifdef INET
		struct sockaddr_in	in;
#endif
#ifdef INET6
		struct sockaddr_in6	in6;
#endif
	} source_sockaddr;
	/* Size of packet to send */
	bool f_packet_size;
	long n_packet_size;
	bool             f_timeout;
	struct itimerval n_timeout;
	bool f_verbose;
	/* Timeout for each packet */
	bool f_wait_time;
	int  n_wait_time;
#ifdef IPSEC
	bool f_policy;
	char *s_policy_in;
	char *s_policy_out;
#endif /* IPSEC */
	char target[MAXHOSTNAMELEN];
	/*
	 * The target can be resolved to multiple protocols by
	 * cap_getaddrinfo(). Pointer to the head of the linked list
	 * of the addrinfo structures is saved in target_addrinfo_root
	 * variable so it can be used as an argument to
	 * freeaddrinfo().
	 */
	struct addrinfo *target_addrinfo_root;
	/*
	 * This is a pointer to a chosen protocol version addrinfo
	 * structure in the linked list of the addrinfo structures
	 * from cap_getaddrinfo().
	 */
	struct addrinfo *target_addrinfo;
	enum target_type target_type;

#ifdef INET
	bool f_protocol_ipv4;
	/* Max value of payload in sweep */
	bool f_sweep_max;
	int  n_sweep_max;
        /* Start value of payload in sweep */
	bool f_sweep_min;
	int  n_sweep_min;
        /* Payload increment in sweep */
	bool f_sweep_incr;
	int  n_sweep_incr;
	bool f_no_loop;
	bool f_mask;
	bool f_time;
	bool f_ttl;
	int  n_ttl;
	bool f_somewhat_quiet;
	bool f_rroute;
	bool f_so_dontroute;
   	bool f_multicast_ttl;
	int  n_multicast_ttl;
	bool f_tos;
	int  n_tos;
#endif	/* INET */

#ifdef INET6
#ifndef USE_SIN6_SCOPE_ID
	bool f_interface_use_pktinfo;
#endif
	bool f_protocol_ipv6;
#if defined(SO_SNDBUF) && defined(SO_RCVBUF)
	bool          f_sock_buff_size;
	unsigned long n_sock_buff_size;
#endif
	const char *s_gateway;
	struct  sockaddr_in6 gateway_sockaddr_in6;
	bool f_hoplimit;
	int  n_hoplimit;
	bool f_nodeaddr;
	bool f_fqdn;
	bool f_fqdn_old;
	bool f_subtypes;
	bool f_nodeaddr_flag_all;
	bool f_nodeaddr_flag_compat;
	bool f_nodeaddr_flag_linklocal;
	bool f_nodeaddr_flag_sitelocal;
	bool f_nodeaddr_flag_global;
#ifdef NI_NODEADDR_FLAG_ANYCAST
	bool f_nodeaddr_flag_anycast;
#endif
	bool f_nigroup;
	int  c_nigroup;
#ifdef IPV6_USE_MIN_MTU
	int  c_use_min_mtu;
#endif
#if defined(IPSEC) && !defined(IPSEC_POLICY_IPSEC)
	bool f_authhdr;
	bool f_encrypt;
#endif
	/* TODO: restrict numbre of IPv6 hops? */
	const char **hops;
	struct addrinfo **hops_addrinfo;
	unsigned hop_count;
#endif	/* INET6 */
};

void options_free(struct options *const options);
bool options_parse(int argc, char **argv, struct options *const options,
    cap_channel_t *const capdns);
void usage(void);

#endif	/* OPTIONS_H */
