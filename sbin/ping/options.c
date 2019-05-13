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

#include <unistd.h>

#include "options.h"

static void options_remove(int *const argc, char **const argv, const int *indices);

void
options_parse(int *const argc, char **const argv, int *const options, char **const ping_target)
{
	int ch;
	int i = 0;
	int optinds_to_remove[3] = {0};

	while ((ch = getopt(*argc, argv, ":46")) != -1) {
		switch(ch) {
		case '4':
			*options |= F_PROTOCOL_IPV4;
			optinds_to_remove[i++] = optind - 1;
			break;
		case '6':
			*options |= F_PROTOCOL_IPV6;
			optinds_to_remove[i++] = optind - 1;
			break;
		default:
			break;
		}
	}
	
	*ping_target = (optind < *argc) ? argv[*argc - 1] : NULL;

	optinds_to_remove[i] = -1;
	options_remove(argc, argv, optinds_to_remove);
	
	optreset = 1;
	optind = 1;
}

static void
options_remove(int *const argc, char **const argv, const int *indices)
{
	int i, j;
	
	for (i = j = 0; (argv[i] != NULL); i++) {
		if ((indices[j] >= 0) && (i == indices[j]))
			j++;
		else if (j > 0)
			argv[i - j] = argv[i];	
	}

	*argc -= j;
	argv[i - j] = argv[i];
}
