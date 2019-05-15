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

#include <err.h>
#include <sysexits.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "options.h"
#include "ping.h"
#include "ping6.h"

enum target_type {
	TARGET_ADDRESS_IPV4,
	TARGET_ADDRESS_IPV6,
	TARGET_HOSTNAME_IPV4,
	TARGET_HOSTNAME_IPV6
};

#define MAX_TARGET_TYPES  2

static void get_target_types(const char *const target, enum target_type *types, int *const count);
static void resolv_hostname(const char *const hostname, enum target_type *types, int *const count);

int
main(int argc, char *argv[])
{
	struct options options;
	char *ping_target;
	enum target_type types[MAX_TARGET_TYPES];
	int type_count;
	
	options_parse(&argc, argv, &options);
	ping_target = (argc > 0) ? argv[argc - 1] : NULL;

	if (ping_target == NULL)
		usage();
	
	get_target_types(ping_target, types, &type_count);
	
	/* Check for errors */
	if (type_count == 0)
		errx(EX_USAGE, "invalid ping target: `%s'", ping_target);
	else if (type_count == 1) {
		if ((options.f_protocol_ipv4) && (types[0] == TARGET_ADDRESS_IPV6))
			errx(EX_USAGE, "IPv4 requested but IPv6 target address provided");
		else if ((options.f_protocol_ipv6) && (types[0] == TARGET_ADDRESS_IPV4))
			errx(EX_USAGE, "IPv6 requested but IPv4 target address provided");
		else if ((options.f_protocol_ipv4) && (types[0] == TARGET_HOSTNAME_IPV6))
			errx(EX_USAGE, "IPv4 requested but the hostname has been resolved to IPv6");
		else if ((options.f_protocol_ipv6) && (types[0] == TARGET_HOSTNAME_IPV4))
			errx(EX_USAGE, "IPv6 requested but the hostname has been resolved to IPv4");
	}
	
	/* Call ping */
	if (type_count == 1) {
	       	if ((types[0] == TARGET_ADDRESS_IPV4) || (types[0] == TARGET_HOSTNAME_IPV4))
			return ping(&options, argc, argv);
		else if ((types[0] == TARGET_ADDRESS_IPV6) || (types[0] == TARGET_HOSTNAME_IPV6))
			return ping6(&options, argc, argv);
	} else if (options.f_protocol_ipv4)
		return ping(&options, argc, argv);
	else if (options.f_protocol_ipv6)
		return ping6(&options, argc, argv);
	else if (types[0] == TARGET_HOSTNAME_IPV4)
		return ping(&options, argc, argv);
	else
		return ping6(&options, argc, argv);
}

static void
get_target_types(const char *const target, enum target_type *types, int *const count)
{
	struct in_addr a;
	struct in6_addr a6;

	*count = 0;
	
	if (inet_pton(AF_INET, target, &a) == 1)
		types[(*count)++] = TARGET_ADDRESS_IPV4;
	else if (inet_pton(AF_INET6, target, &a6) == 1)
		types[(*count)++] = TARGET_ADDRESS_IPV6;
	else
		resolv_hostname(target, types, count);
}

static void
resolv_hostname(const char *const hostname, enum target_type *types, int *const count)
{
	struct addrinfo hints, *res, *r;

	*count = 0;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	
	if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
		for (r = res; r; r = r->ai_next) {
			if (r->ai_family == AF_INET)
				types[(*count)++] = TARGET_HOSTNAME_IPV4;
			else if (r->ai_family == AF_INET6)
				types[(*count)++] = TARGET_HOSTNAME_IPV6;
		}
		
		freeaddrinfo(res);
	}
}
