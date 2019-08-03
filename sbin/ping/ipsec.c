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

#include <sys/types.h>

#include <netipsec/ipsec.h>

#include <err.h>
#include <string.h>

#include "ipsec.h"
#include "utils.h"

#ifdef IPSEC
#ifdef IPSEC_POLICY_IPSEC
static bool ipsec_setpolicy(int socket, char *const policy,
    enum target_type target_type);
#endif
#endif

bool
ipsec_configure(int socket_send, int socket_recv,
    const struct options *const options)
{
#ifdef IPSEC
#ifdef IPSEC_POLICY_IPSEC
	if (options->f_policy) {
		if (!ipsec_setpolicy(socket_send, options->s_policy_out,
			options->target_type))
			return (false);
		if (!ipsec_setpolicy(socket_recv, options->s_policy_in,
			options->target_type))
			return (false);
	}
#else  /* !IPSEC_POLICY_IPSEC */
	if (options->f_authhdr) {
		const int optval = IPSEC_LEVEL_REQUIRE;
#ifdef IPV6_AUTH_TRANS_LEVEL
		if (setsockopt(vars.socket_send, IPPROTO_IPV6,
			IPV6_AUTH_TRANS_LEVEL, &optval, sizeof(optval)) != 0) {
			print_error_strerr("setsockopt(IPV6_AUTH_TRANS_LEVEL)");
			return (false);
		}

		if (setsockopt(vars.socket_recv, IPPROTO_IPV6,
			IPV6_AUTH_TRANS_LEVEL, &optval, sizeof(optval)) != 0) {
			print_error_strerr("setsockopt(IPV6_AUTH_TRANS_LEVEL)");
			return (false);
		}
#else /* old def */
		if (setsockopt(vars.socket_send, IPPROTO_IPV6, IPV6_AUTH_LEVEL,
			&optval, sizeof(optval)) != 0) {
			print_error_strerr("setsockopt(IPV6_AUTH_LEVEL)");
			return (false);
		}
		if (setsockopt(vars.socket_recv, IPPROTO_IPV6, IPV6_AUTH_LEVEL,
			&optval, sizeof(optval)) != 0) {
			print_error_strerr("setsockopt(IPV6_AUTH_LEVEL)");
			return (false);
		}
#endif
	}
	if (options->f_encrypt) {
		optval = IPSEC_LEVEL_REQUIRE;
		if (setsockopt(vars.socket_send, IPPROTO_IPV6,
			IPV6_ESP_TRANS_LEVEL, &optval, sizeof(optval)) != 0) {
			print_error_strerr("setsockopt(IPV6_ESP_TRANS_LEVEL)");
			return (false);
		}
		if (setsockopt(vars.socket_recv, IPPROTO_IPV6,
			IPV6_ESP_TRANS_LEVEL, &optval, sizeof(optval)) != 0) {
			print_error_strerr("setsockopt(IPV6_ESP_TRANS_LEVEL)");
			return (false);
		}
	}
#endif /* IPSEC_POLICY_IPSEC */
#endif /* IPSEC */
	return (true);
}

#ifdef IPSEC
#ifdef IPSEC_POLICY_IPSEC
static bool
ipsec_setpolicy(int socket, char *const policy, enum target_type target_type)
{
	char *buf;
	int level, optname;

	if (policy == NULL)
		return (true);	/* ignore */

	buf = ipsec_set_policy(policy, strlen(policy));
	if (buf == NULL) {
		print_error_strerr("ipsec_set_policy");
		return (false);
	}
#ifdef INET
#ifdef INET6
	if (target_type == TARGET_IPV4) {
#endif
		level = IPPROTO_IP;
		optname = IP_IPSEC_POLICY;
#ifdef INET6
	}
#endif
#endif
#ifdef INET6
#ifdef INET
	else {
#endif
		level = IPPROTO_IPV6;
		optname = IPV6_IPSEC_POLICY;
#ifdef INET
	}
#endif
#endif
	if (setsockopt(socket, level, optname, buf,
		ipsec_get_policylen(buf)) != 0) {
		print_error_strerr("setsockopt: Unable to set IPsec policy");
		return (false);
	}
	free(buf);

	return (true);
}
#endif
#endif
