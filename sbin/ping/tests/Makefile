# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	tests

ATF_TESTS_SH=	ping_test

${PACKAGE}FILES+=       ping_c3.out ping6_c3.out

ATF_TESTS_C=	options_test options_hops_target_test options_interface_test options_multicast_ttl_test options_no_loop_test options_source_test

SRCS.options_test=	options_test.c ../cap.c ../options.c ../utils.c
SRCS.options_hops_target_test=	options_hops_target_test.c cap_getaddrinfo.c ../cap.c ../options.c ../utils.c
SRCS.options_interface_test=	options_interface_test.c cap_getaddrinfo.c ../cap.c ../options.c ../utils.c
SRCS.options_multicast_ttl_test=	options_multicast_ttl_test.c cap_getaddrinfo.c ../cap.c ../options.c ../utils.c
SRCS.options_no_loop_test=	options_no_loop_test.c cap_getaddrinfo.c ../cap.c ../options.c ../utils.c
SRCS.options_source_test=	options_source_test.c cap_getaddrinfo.c ../cap.c ../options.c ../utils.c

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6 -DKAME_SCOPEID
ATF_TESTS_C+=	options_gateway_test
SRCS.options_gateway_test=	options_gateway_test.c cap_getaddrinfo.c ../cap.c ../options.c ../utils.c
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
