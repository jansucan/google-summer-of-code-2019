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

#include <sys/cdefs.h>

/*
 * This block of includes is needed here. It contains preprocessor
 * symbols for configuration of 'struct options' during build-time.
 */
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netipsec/ipsec.h>

#include <stdbool.h>

enum target_type {
	TARGET_UNKNOWN,
	TARGET_ADDRESS_IPV4,
	TARGET_ADDRESS_IPV6,
	TARGET_HOSTNAME_IPV4,
	TARGET_HOSTNAME_IPV6
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
	
	/* TODO: ordering of the variables vs. number of #ifdef directives */
	/* TODO: rationalize the data types */
	bool f_protocol_ipv4;
	bool f_protocol_ipv6;
	bool f_missed;
	bool f_audible;

	/* Max packets to transmit */
	bool f_packets;
	long n_packets;
	
	bool f_so_debug;
	bool f_numeric;
	bool f_once;

	/* Fill buffer with user pattern  */
	bool f_ping_filled;
	int  a_ping_filled[16];
	/* Number of bytes of the pattern */
	size_t ping_filled_size;
	
	bool f_somewhat_quiet;
	bool f_quiet;
	bool f_rroute;
	bool f_so_dontroute;
	
	const char *s_source;
	
	bool f_verbose;
	bool f_no_loop;
	bool f_dont_fragment;
	bool f_flood;

	bool f_preload;
	int  n_preload;

	/* Max value of payload in sweep */
	bool f_sweep_max;
	int  n_sweep_max;
        /* Start value of payload in sweep */
	bool f_sweep_min;
	int  n_sweep_min;
        /* Payload increment in sweep */
	bool f_sweep_incr;
	int  n_sweep_incr;

	bool f_ttl;
	int  n_ttl;

	bool f_multicast_ttl;
	int  n_multicast_ttl;

	bool          f_alarm_timeout;
	unsigned long n_alarm_timeout;

	/* Timeout for each packet */
	bool f_wait_time;
	int  n_wait_time;

	bool f_tos;
	int  n_tos;

#ifdef IPSEC
	bool f_policy;
	char *s_policy_in;
	char *s_policy_out;
#if defined(INET6) && !defined(IPSEC_POLICY_IPSEC)
	bool f_authhdr;
	bool f_encrypt;
#endif /* INET6 && IPSEC_POLICY_IPSEC */
#endif /* IPSEC */
	
	/* -I */
#if !defined(INET6) || !defined(USE_SIN6_SCOPE_ID)
	bool        f_interface;
#endif
	const char *s_interface;
	
	/* Wait between sending packets */
	bool    f_interval;
	struct timeval n_interval;
	
	/* Size of packet to send */
	bool f_packet_size;
	long n_packet_size;

	/* IPv4 -M */
	bool f_mask;
	bool f_time;

#if defined(INET6) && defined(SO_SNDBUF) && defined(SO_RCVBUF)
	bool          f_sock_buff_size;
	unsigned long n_sock_buff_size;
#endif

	const char *s_gateway;

	bool f_nigroup;
	int  c_nigroup;
	
#if defined(INET6) && defined(IPV6_USE_MIN_MTU)
	int  c_use_min_mtu;
#endif

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
#if defined(INET6) && defined(NI_NODEADDR_FLAG_ANYCAST)
	bool f_nodeaddr_flag_anycast;
#endif

	/* TODO: restrict numbre of IPv6 hops? */
#ifdef INET6
	const char **hops;
	struct addrinfo **hops_addrinfo;
	unsigned hop_count;
#endif
	/* TODO: cannot be const becuse of nigroup() in ping6 */
	char *target;
	struct addrinfo *target_addrinfo;
	enum target_type target_type;
};

void options_free(struct options *const options);
void options_parse(int argc, char **argv, struct options *const options);
void usage(void) __dead2;

#endif	/* OPTIONS_H */
