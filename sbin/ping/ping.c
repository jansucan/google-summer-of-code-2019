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

#include <string.h>
#include <sysexits.h>

#include "cap.h"
#include "ipsec.h"
#include "ping.h"
#include "ping4.h"
#include "ping4_print.h"
#include "ping6.h"
#include "ping6_print.h"
#include "timing.h"
#include "utils.h"

int
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
	vars->ident = getpid() & 0xFFFF;

	memset(counters, 0, sizeof(*counters));
	timing_init(timing);

	if (options->f_timeout &&
	    (setitimer(ITIMER_REAL, &(options->n_timeout), NULL) != 0)) {
		print_error_strerr("setitimer() cannot set the timeout");
		return (EX_OSERR);
	}


	if (options->f_flood)
		setbuf(stdout, (char *)NULL);

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
		    options->target_addrinfo->ai_socktype, protocol)) < 0) {
		print_error_strerr("socket() socket_send");
		return (1);
	}
	if ((vars->socket_recv = socket(options->target_addrinfo->ai_family,
		    options->target_addrinfo->ai_socktype, protocol)) < 0) {
		print_error_strerr("socket() socket_recv");
		return (1);
	}

	/* Revoke root privilege. */
	if (seteuid(getuid()) != 0) {
		print_error_strerr("seteuid() failed");
		return (1);
	}
	if (setuid(getuid()) != 0) {
		print_error_strerr("setuid() failed");
		return (1);
	}

	if (options->f_so_debug) {
		int optval = 1;

		if (setsockopt(vars->socket_send, SOL_SOCKET, SO_DEBUG, (char *)&optval,
			sizeof(optval)) != 0) {
			print_error_strerr("setsockopt() socket_send");
			return (1);
		}
		if (setsockopt(vars->socket_recv, SOL_SOCKET, SO_DEBUG, (char *)&optval,
			sizeof(optval)) != 0) {
			print_error_strerr("setsockopt() socket_recv");
			return (1);
		}
	}

	if (!ipsec_configure(vars->socket_send, vars->socket_recv, options))
		return (1);

	/*
	 * Do protocol-specific initialization.
	 */
	if (options->target_type == TARGET_IPV4) {
		return (ping4_init(options, vars, counters, timing));
	} else {
		return (ping6_init(options, vars, timing));
	}
}

void
ping_free(struct options *const options, struct shared_variables *const vars)
{
	options_free(options);
	cap_close(vars->capdns);
#ifdef INET6
	if (vars->packet6 != NULL) {
                free(vars->packet6);
		vars->packet6 = NULL;
	}
	if (vars->smsghdr.msg_control != NULL) {
                free(vars->smsghdr.msg_control);
		vars->smsghdr.msg_control = NULL;
	}
#endif
}

bool
ping_send_initial_packets(struct options *const options, struct shared_variables *const vars,
    struct counters *const counters, struct timing *const timing)
{
	while (options->n_preload--) {
		if (options->target_type == TARGET_IPV4) {
			if (!pinger(options, vars, counters, timing))
				return (false);
		} else {
			if (!pinger6(options, vars, counters, timing))
				return (false);
		}
	}

	return (true);
}

int
ping_loop(struct options *const options, struct shared_variables *const vars,
    struct counters *const counters, struct timing *const timing,
    struct signal_variables *const signal_vars)
{
	struct timeval last;
	bool almost_done;

	if (gettimeofday(&last, NULL) != 0) {
		print_error_strerr("gettimeofday()");
		return (1);
	}

	almost_done = false;
	while (!signal_vars->sigint_sigalrm) {
		struct timeval now, timeout;
		bool is_ready, is_eintr;

		if (signal_vars->siginfo) {
			if (options->target_type == TARGET_IPV4)
				pr_status(counters, timing);
			else {
				pr6_summary(counters, timing, options->target);
				continue;
			}
			signal_vars->siginfo = false;
		}

		if (gettimeofday(&now, NULL) != 0) {
			print_error_strerr("gettimeofday()");
			return (1);
		}
		timeout = timeout_get(&last, &options->n_interval, &now);

		if (!test_socket_for_reading(vars->socket_recv, &timeout,
			&is_ready, &is_eintr))
			return (1);

		if (is_eintr)
			continue;
		if (is_ready) {
			bool next_iteration;

			if (options->target_type == TARGET_IPV4)
				next_iteration = !ping4_process_received_packet(options, vars, counters, timing);
			else {
				int r;

				r = ping6_process_received_packet(options, vars, counters, timing);
				if (r < 0)
					return (1);
				next_iteration = (r == 1);
			}

			if (next_iteration)
				continue;

			if ((options->f_once && (counters->received > 0)) ||
			    ((options->n_packets > 0) && (counters->received >= options->n_packets)))
				break;
		}
		if (!is_ready || options->f_flood) {
			if (options->target_type == TARGET_IPV4)
				update_sweep(options, vars, counters);
			if ((options->n_packets == 0) || (counters->transmitted < options->n_packets)) {
				if (options->target_type == TARGET_IPV4) {
					if (!pinger(options, vars, counters, timing))
						return (1);
				} else {
					if (!pinger6(options, vars, counters, timing))
						return (1);
				}
			} else {
				if (almost_done)
					break;
				almost_done = true;
				/*
				 * If we're not transmitting any more packets,
				 * change the timer to wait two round-trip times
				 * if we've received any packets or (options->n_wait_time)
				 * milliseconds if we haven't.
				 */
				options->n_interval.tv_usec = 0;
				if (counters->received) {
					options->n_interval.tv_sec = 2 * timing->max / 1000;
					if (options->n_interval.tv_sec == 0)
						options->n_interval.tv_sec = 1;
				} else {
					options->n_interval.tv_sec = options->n_wait_time / 1000;
					options->n_interval.tv_usec = options->n_wait_time % 1000 * 1000;
				}
			}
			if (gettimeofday(&last, NULL) != 0) {
				print_error_strerr("gettimeofday()");
				return (1);
			}
			if ((counters->transmitted - counters->received - 1) > counters->missedmax) {
				counters->missedmax = counters->transmitted - counters->received - 1;
				if (options->f_missed)
					write_char(STDOUT_FILENO, CHAR_BBELL);
			}
		}
	}

	return (EX_OK);
}

void
ping_print_summary(struct options *const options, const struct counters *const counters,
    const struct timing *const timing)
{
	if (options->target_type == TARGET_IPV4)
		pr_summary(counters, timing, options->target);
	else
		pr6_summary(counters, timing, options->target);
}
