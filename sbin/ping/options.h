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

#ifndef OPTIONS_H
#define OPTIONS_H 1

#include <stdbool.h>

struct options {
	/* TODO: conditional compilation of INET6 and IPSEC variables */
	bool f_protocol_ipv4;
	bool f_protocol_ipv6;
	bool f_missed;
	bool f_audible;
	int  n_packets;
	bool f_so_debug;
	bool f_numeric;
	bool f_once;
	bool f_ping_filled;
	const char *s_ping_filled;
	bool f_somewhat_quiet;
	bool f_quiet;
	bool f_rroute;
	bool f_so_dontroute;
	const char *s_source;
	bool f_verbose;
	bool f_no_loop;
	bool f_dont_fragment;

	/* IPv4 -M */
	bool f_mask;
	bool f_time;
};

void options_parse(int *const argc, char **argv, struct options *const options);
void usage(void) __dead2;

#endif	/* OPTIONS_H */
