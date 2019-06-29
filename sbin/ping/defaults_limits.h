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

#ifndef DEFAULTS_LIMITS_H
#define DEFAULTS_LIMITS_H 1

#include "timing.h"

/*
 * Defines for IPv4 ping.
 */
#define	MAX_TOS			255
#define	DEFAULT_DATALEN_IPV4	56
#define	DEFAULT_SWEEP_INCR	1

/*
 * Defines for IPv6 ping.
 */
#define	MAXPACKETLEN		131072
#define	IP6LEN			40
#define	ICMP6ECHOLEN		8	/* icmp echo header len excluding time */
#define	ICMP6ECHOTMLEN		sizeof(struct tv32)
#define	MAXDATALEN		(MAXPACKETLEN - IP6LEN - ICMP6ECHOLEN)
#define	DEFAULT_DATALEN_IPV6	ICMP6ECHOTMLEN
#define	MAX_HOPLIMIT		255

/*
 * Defines for IPv4 and IPv6 ping.
 */

/* Max. alarm value in seconds. */
#define	MAX_ALARM			3600
#define	DEFAULT_INTERVAL_TV_SEC		1
#define	DEFAULT_INTERVAL_TV_USEC	0
/* Default wait time for response in milliseconds. */
#define	DEFAULT_WAIT_TIME		10000

#endif
