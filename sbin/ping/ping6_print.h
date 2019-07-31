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

#ifndef PING6_PRINT_H
#define PING6_PRINT_H 1

#include <stdbool.h>

#include "cap.h"
#include "options.h"
#include "ping.h"
#include "timing.h"

#define ICMP6_NIQLEN	(ICMP6ECHOLEN + 8)
#define CONTROLLEN	10240	/* ancillary data buffer size RFC3542 20.1 */

int		get_hoplim(const struct msghdr *const);
struct in6_pktinfo *get_rcvpktinfo(const struct msghdr *const);
bool		myechoreply(const struct icmp6_hdr *const, int);
bool		mynireply(const struct icmp6_nodeinfo *const,
    const uint8_t *const);
size_t		pingerlen(const struct options *const, size_t);
const char	*pr6_addr(const struct sockaddr *const, int, bool,
    cap_channel_t *const);
void		pr6_heading(const struct sockaddr_in6 *const,
    const struct sockaddr_in6 *const,
    const struct options *const, cap_channel_t *const);
void	 	pr6_pack(int, const struct msghdr *const,
    const struct options *const,
    const struct shared_variables *const, const struct timing *const, double);
void	 	pr6_summary(const struct counters *const,
    const struct timing *const, const char *const);

#endif
