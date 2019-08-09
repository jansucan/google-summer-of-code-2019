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

#include <sys/select.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "timing.h"
#include "utils.h"

void
fill(char *const bp, size_t bp_size, const struct options *const options)
{
	if (options->ping_filled_size > 0)
		for (size_t k = 0; k <= bp_size; k += options->ping_filled_size)
			for (size_t j = 0; j < options->ping_filled_size; ++j)
				bp[k + j] = options->a_ping_filled[j];
}

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(const u_char *addr, int len)
{
	int nleft, sum;
	union {
		u_short	us;
		u_char	uc[2];
	} last;
	u_short answer;

	nleft = len;
	sum = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		u_short data;

		memcpy(&data, addr, sizeof(u_short));
		sum += data;
		addr += sizeof(u_short);
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		last.uc[0] = *addr;
		last.uc[1] = 0;
		sum += last.us;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

void
print_error(const char *const fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ping: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	fflush(stderr);
}

void
print_error_strerr(const char *const fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ping: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	/* Add strerror() message. */
	if (errno != 0)
		fprintf(stderr, ": %s", strerror(errno));
	fprintf(stderr, "\n");
	fflush(stderr);
}

void
print_fill_pattern(const char *const bp, size_t pattern_size)
{
	(void)printf("PATTERN: 0x");
	for (size_t j = 0; j < pattern_size; ++j)
		(void)printf("%02x", bp[j] & 0xFF);
	(void)printf("\n");
}

void
write_char(int fd, char c)
{
	(void)write(fd, &c, sizeof(c));
}

bool
test_socket_for_reading(int socket, struct timeval *timeout,
    bool *const is_ready, bool *const is_eintr)
{
	fd_set rfds;
	int n;

	FD_ZERO(&rfds);
	FD_SET(socket, &rfds);

	n = select(socket + 1, &rfds, NULL, NULL, timeout);
	*is_ready = (n > 0);
	*is_eintr = (errno == EINTR);

	if ((n < 0 ) && !(*is_eintr)) {
		print_error_strerr("select()");
		return (false);
	}
	/*
	 * No error or EINTR was returned by the select(). Do
	 * no consider EINTR to be an error.
	 */
	return (true);
}
