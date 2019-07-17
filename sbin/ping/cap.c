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

#include <errno.h>
#include <string.h>

#include "cap.h"
#include "utils.h"

bool
cap_limit_socket(int socket, enum ping_socket_rights rights)
{
	cap_rights_t r;

	switch (rights) {
	case RIGHTS_RECV_EVENT_SETSOCKOPT:
		cap_rights_init(&r, CAP_RECV, CAP_EVENT, CAP_SETSOCKOPT);
		break;
	case RIGHTS_SEND_SETSOCKOPT:
		cap_rights_init(&r, CAP_SEND, CAP_SETSOCKOPT);
		break;
        case RIGHTS_RECV_EVENT:
		cap_rights_init(&r, CAP_RECV, CAP_EVENT);
		break;
	case RIGHTS_SEND:
		cap_rights_init(&r, CAP_SEND);
		break;
	default:
		print_error("cap_limit_socket: invalid specification of rights");
		return (false);
		/* NOTREACHED */
	}

	if (caph_rights_limit(socket, &r) < 0) {
		print_error("cap_rights_limit socket: %s", strerror(errno));
		return (false);
	}

	return (true);
}

cap_channel_t *
capdns_setup(void)
{
	/* TODO: cap_close(capdnsloc)? */
	cap_channel_t *capcas, *capdnsloc;
	const char *types[2];

	capcas = cap_init();
	if (capcas == NULL) {
		print_error("unable to create casper process: %s", strerror(errno));
		return (NULL);
	}
	capdnsloc = cap_service_open(capcas, "system.dns");
	/* Casper capability no longer needed. */
	cap_close(capcas);
	if (capdnsloc == NULL) {
		print_error("unable to open system.dns service: %s", strerror(errno));
		return (NULL);
	}
	types[0] = "NAME2ADDR";
	types[1] = "ADDR2NAME";
	if (cap_dns_type_limit(capdnsloc, types, 2) < 0) {
		print_error("unable to limit access to system.dns service: %s", strerror(errno));
		return (NULL);
	}

	return (capdnsloc);
}

bool
capdns_limit_family(cap_channel_t *const capdns, int family)
{
	if (cap_dns_family_limit(capdns, &family, 1) < 0) {
		print_error("unable to limit access to system.dns service: %s", strerror(errno));
		return (false);
	}
	return (true);
}

bool
capdns_limit_type(cap_channel_t *const capdns, const char *const type)
{
	if (cap_dns_type_limit(capdns, &type, 1) < 0) {
		print_error("unable to limit access to system.dns service: %s", strerror(errno));
		return (false);
	}
	return (true);
}

bool
cap_enter_capability_mode(void)
{
	caph_cache_catpages();
	if (caph_enter_casper() < 0) {
		print_error("cap_enter: %s", strerror(errno));
		return (false);
	}
	return (true);
}
