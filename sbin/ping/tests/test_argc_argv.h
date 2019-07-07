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

#ifndef TEST_ARGC_ARGV_H
#define TEST_ARGC_ARGV_H 1

#define GETOPT_RESET \
	optreset = optind = 1

#define ARGC_ARGV_EMPTY      				                    \
	char *test_argv[] = { "ping", NULL };        		            \
	const int test_argc = sizeof(test_argv) / sizeof(test_argv[0]) - 1; \
	GETOPT_RESET

#define ARGC_ARGV(...)           				            \
	char *test_argv[] = { "ping", __VA_ARGS__, NULL };	            \
	const int test_argc = sizeof(test_argv) / sizeof(test_argv[0]) - 1; \
	GETOPT_RESET

#define	ARGV_BUFFER_SIZE	64

#define ARGV_SET_FROM_EXPR(argv, idx, expr)						\
	const unsigned long ul_##idx = expr;						\
	char ul_str_##idx[ARGV_BUFFER_SIZE];						\
	const int sr##idx = snprintf(ul_str_##idx, ARGV_BUFFER_SIZE, "%lu", ul_##idx);	\
	if (sr##idx < 0)								\
		atf_tc_fail("snprintf() error");					\
	else if (sr##idx >= ARGV_BUFFER_SIZE)						\
		atf_tc_fail("snprintf() buffer too small");				\
	argv[idx] = ul_str_##idx

#define ARGV_SET_LDBL_FROM_EXPR(argv, idx, expr)						\
	const long double ldbl_##idx = expr;							\
	char ldbl_str_##idx[ARGV_BUFFER_SIZE];							\
	const int sr##idx = snprintf(ldbl_str_##idx, ARGV_BUFFER_SIZE, "%Lg", ldbl_##idx);	\
	if (sr##idx < 0)									\
		atf_tc_fail("snprintf() error");						\
	else if (sr##idx >= ARGV_BUFFER_SIZE)							\
		atf_tc_fail("snprintf() buffer too small");					\
	argv[idx] = ldbl_str_##idx

#endif
