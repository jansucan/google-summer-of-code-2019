# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	tests

ATF_TESTS_SH=	ping_test

${PACKAGE}FILES+=       ping_c3.out ping6_c3.out

ATF_TESTS_C=	options_test options_hops_target_test

SRCS.options_test=	options_test.c ../options.c
SRCS.options_hops_target_test=	options_hops_target_test.c getaddrinfo.c ../options.c

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6 -DKAME_SCOPEID -DUSE_RFC2292BIS
ATF_TESTS_C+=	options_source_test
SRCS.options_source_test=	options_source_test.c getaddrinfo.c ../options.c
.endif

.if ${MK_CASPER} != "no" && !defined(RESCUE)
CFLAGS+=-DWITH_CASPER
.endif

.if !defined(RELEASE_CRUNCH) || ${MK_INET6_SUPPORT} != "no"
CFLAGS+=-DIPSEC
.endif

.include <bsd.test.mk>
