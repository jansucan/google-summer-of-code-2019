# $FreeBSD$

.include <bsd.own.mk>
.include <src.opts.mk>

WARNS?= 6

TESTSDIR=	${TESTSBASE}/sbin/ping/options

ATF_TESTS_C+=	options_test options_flood_test options_hops_target_test
ATF_TESTS_C+=	options_interface_test options_source_test

SRCS.options_test=	options_test.c test_argc_argv.c ../../cap.c
SRCS.options_test+=	../../options.c ../../utils.c
SRCS.options_flood_test=	options_flood_test.c test_argc_argv.c
SRCS.options_flood_test+=	cap_getaddrinfo.c ../../cap.c ../../options.c
SRCS.options_flood_test+=	../../utils.c
SRCS.options_hops_target_test=	options_hops_target_test.c test_argc_argv.c
SRCS.options_hops_target_test+=	cap_getaddrinfo.c ../../cap.c ../../options.c
SRCS.options_hops_target_test+=	../../utils.c
SRCS.options_interface_test=	options_interface_test.c  test_argc_argv.c
SRCS.options_interface_test+=	cap_getaddrinfo.c ../../cap.c ../../options.c
SRCS.options_interface_test+=	../../utils.c
SRCS.options_source_test=	options_source_test.c  test_argc_argv.c
SRCS.options_source_test+=	cap_getaddrinfo.c ../../cap.c ../../options.c
SRCS.options_source_test+=	../../utils.c

.if ${MK_INET_SUPPORT} != "no"
CFLAGS+= -DINET
ATF_TESTS_C+=	options_multicast_ttl_test options_no_loop_test
SRCS.options_multicast_ttl_test=	options_multicast_ttl_test.c
SRCS.options_multicast_ttl_test+=	test_argc_argv.c cap_getaddrinfo.c
SRCS.options_multicast_ttl_test+=	../../cap.c ../../options.c
SRCS.options_multicast_ttl_test+=	../../utils.c
SRCS.options_no_loop_test=	options_no_loop_test.c cap_getaddrinfo.c
SRCS.options_no_loop_test+=	test_argc_argv.c ../../cap.c ../../options.c
SRCS.options_no_loop_test+=	../../utils.c
.endif

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6
ATF_TESTS_C+=	options_gateway_test
SRCS.options_gateway_test=	options_gateway_test.c cap_getaddrinfo.c
SRCS.options_gateway_test+=	test_argc_argv.c ../../cap.c ../../options.c
SRCS.options_gateway_test+=	../../utils.c
SRCS.options_interface_test+=	if_nametoindex.c
LIBADD+=	md
.endif

.if ${MK_DYNAMICROOT} == "no"
.warning ${PROG} built without libcasper support
.elif ${MK_CASPER} != "no" && !defined(RESCUE)
LIBADD+=	casper
LIBADD+=	cap_dns
CFLAGS+=-DWITH_CASPER
.endif

.if !defined(RELEASE_CRUNCH) || ${MK_INET6_SUPPORT} != "no"
CFLAGS+=-DIPSEC
.endif

.include <bsd.test.mk>
