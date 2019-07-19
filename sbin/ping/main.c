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
#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>

#include "options.h"
#include "ping4.h"
#include "ping4_print.h"
#include "ping6.h"
#include "ping6_print.h"

static struct signal_variables signal_vars;

static void signals_setup(struct options *const options,  struct shared_variables *const vars,
    const long *const counters_received);
static void signals_cleanup(void);
static void signal_handler_siginfo(int sig __unused);
static void signal_handler_sigint_sigalrm(int sig __unused);

int
main(int argc, char *argv[])
{
	struct options options;
	struct shared_variables vars;
	struct counters counters;
	struct timing timing;
	int r;

	if ((vars.capdns = capdns_setup()) == NULL)
		exit(1);

	if ((r = options_parse(argc, argv, &options, vars.capdns)) != EX_OK)
		exit(r);

	/* Initialization. */
	if (options.target_type == TARGET_IPV4) {
		r = ping4_init(&options, &vars, &counters, &timing);
	} else {
		r = ping6_init(&options, &vars, &counters, &timing);
	}
	if (r != EX_OK)
		exit(r);

	signals_setup(&options, &vars, &counters.received);

	/* Ping loop. */
	if (options.target_type == TARGET_IPV4) {
		r = ping4_loop(&options, &vars, &counters, &timing, &signal_vars);
	} else {
		r = ping6_loop(&options, &vars, &counters, &timing, &signal_vars);
	}
	if (r != EX_OK)
		exit(r);

	/* Cleanup. */
	signals_cleanup();

	if (options.target_type == TARGET_IPV4) {
		pr_summary(&counters, &timing, options.target);
	} else {
		pr6_summary(&counters, &timing, options.target);
	}

	ping_free(&options, &vars);

	exit((counters.received != 0) ? 0 : 2);
}

static void
signals_setup(struct options *const options, struct shared_variables *const vars,
    const long *const counters_received)
{
	struct sigaction si_sa;

	signal_vars.siginfo = false;
	signal_vars.sigint_sigalrm = false;
	signal_vars.options = options;
	signal_vars.vars = vars;

	/*
	 * Use sigaction() instead of signal() to get unambiguous semantics,
	 * in particular with SA_RESTART not set.
	 */
	sigemptyset(&si_sa.sa_mask);
	si_sa.sa_flags = 0;

	si_sa.sa_handler = signal_handler_siginfo;
	if (sigaction(SIGINFO, &si_sa, 0) == -1)
		err(EX_OSERR, "sigaction SIGINFO");

	si_sa.sa_handler = signal_handler_sigint_sigalrm;
	if (sigaction(SIGINT, &si_sa, 0) == -1)
		err(EX_OSERR, "sigaction SIGINT");

	if (options->f_timeout && (sigaction(SIGALRM, &si_sa, 0) == -1))
		err(EX_OSERR, "sigaction SIGALRM");
}

static void
signals_cleanup(void)
{
	struct sigaction si_sa;

	sigemptyset(&si_sa.sa_mask);
	si_sa.sa_flags = 0;
	si_sa.sa_handler = SIG_IGN;
	sigaction(SIGINFO, &si_sa, 0);
	sigaction(SIGINT, &si_sa, 0);
	sigaction(SIGALRM, &si_sa, 0);
}

static void
signal_handler_siginfo(int sig __unused)
{
	signal_vars.siginfo = true;
}

static void
signal_handler_sigint_sigalrm(int sig __unused)
{
	/*
	 * When doing reverse DNS lookups, the finish_up flag might not
	 * be noticed for a while.  Just exit if we get a second SIGINT.
	 */
	if (!signal_vars.options->f_numeric && signal_vars.sigint_sigalrm) {
		ping_free(signal_vars.options, signal_vars.vars);
		_exit(((signal_vars.counters_received != NULL) &&
			(*signal_vars.counters_received != 0)) ? 0 : 2);
	}
	signal_vars.sigint_sigalrm = true;
}
