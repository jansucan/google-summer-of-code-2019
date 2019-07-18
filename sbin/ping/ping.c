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

#include <err.h>
#include <string.h>

#include "cap.h"
#include "ping.h"
#include "timing.h"

void
ping_init(struct options *const options, struct shared_variables *const vars,
    struct counters *const counters, struct timing *const timing)
{
	cap_channel_t *cap_channel;
	int protocol;

	/*
	 * The DNS channel has already been initialized for options
	 * parsing.
	 */
	cap_channel = vars->capdns;
	memset(vars, 0, sizeof(*vars));
	vars->capdns = cap_channel;

	memset(counters, 0, sizeof(*counters));
	timing_init(timing);

	/*
	 * Historicaly ping was using one socket 's' for sending and
	 * for receiving. After capsicum(4) related changes we use two
	 * sockets. It was done for special ping use case - when user
	 * issue ping on multicast or broadcast address replies come
	 * from different addresses, not from the address we
	 * connect(2)'ed to, and send socket do not receive those
	 * packets.
	 */
	if (options->target_type == TARGET_IPV4)
		protocol = IPPROTO_ICMP;
	else
		protocol = IPPROTO_ICMPV6;

	if ((vars->socket_send = socket(options->target_addrinfo->ai_family,
		    options->target_addrinfo->ai_socktype, protocol)) < 0)
		err(1, "socket() socket_send");
	if ((vars->socket_recv = socket(options->target_addrinfo->ai_family,
		    options->target_addrinfo->ai_socktype, protocol)) < 0)
		err(1, "socket() socket_recv");

	/* Revoke root privilege. */
	if (seteuid(getuid()) != 0)
		err(1, "seteuid() failed");
	if (setuid(getuid()) != 0)
		err(1, "setuid() failed");


}
