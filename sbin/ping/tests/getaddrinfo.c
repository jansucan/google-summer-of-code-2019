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

#include <sys/socket.h>

#include <netinet/in.h>

#include <atf-c.h>
#include <string.h>

#include "getaddrinfo.h"

int
getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res)
{
        const static struct sockaddr_in sin = {
                .sin_len = sizeof(struct sockaddr_in),
                .sin_family = AF_INET,
        };
#ifdef INET6
	const static struct sockaddr_in6 sin6 = {
                .sin6_len = sizeof(struct sockaddr_in6),
                .sin6_family = AF_INET6,
        };
#endif
        static struct addrinfo ai = {
                0, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                sizeof(struct sockaddr_in),
                NULL, (struct sockaddr*)&sin, NULL
        };

	if ((strcmp(hostname, "target_ipv4") == 0) ||
	    (strcmp(hostname, "127.0.0.1") == 0)) {
		ai.ai_family = AF_INET;
		ai.ai_addr = (struct sockaddr*)&sin;
#ifdef INET6
	} else if ((strcmp(hostname, "target_ipv6") == 0) ||
	    (strcmp(hostname, "::1") == 0)) {
		ai.ai_family = AF_INET6;
		ai.ai_addr = (struct sockaddr*)&sin6;
#endif
	} else if (strcmp(hostname, "target_unknown") == 0) {
		return (EAI_NONAME);
	} else {
		atf_tc_fail("mock getaddrinfo: Invalid hostname: %s", hostname);
	}

	*res = &ai;

        return (0);
}
