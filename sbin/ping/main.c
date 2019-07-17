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

#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "options.h"
#include "ping4.h"
#include "ping6.h"

int
main(int argc, char *argv[])
{
	struct options options;
	struct shared_variables vars;
	struct counters counters;
	struct timing timing;

	/* TODO: ping_init() */
	memset(&vars, 0, sizeof(vars));

	if ((vars.capdns = capdns_setup()) == NULL)
		exit(1);

	const int r = options_parse(argc, argv, &options, vars.capdns);
	if (r != EX_OK)
		exit(r);

	if (options.target_type == TARGET_IPV4) {
		ping4_init(&options, &vars, &counters, &timing);
		ping4_loop(&options, &vars, &counters, &timing);
		ping4_finish(&options, &vars, &counters, &timing);
	} else {
		ping6_init(&options, &vars, &counters, &timing);
		ping6_loop(&options, &vars, &counters, &timing);
		ping6_finish(&options, &vars, &counters, &timing);
	}
	/* NOTREACHED */
}
