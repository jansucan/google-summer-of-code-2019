# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	tests

ATF_TESTS_SH=	ping_test

${PACKAGE}FILES+=       opts_c3.out

ATF_TESTS_C=	options_test

SRCS.options_test=	options_test.c ../options.c

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6 -DKAME_SCOPEID -DUSE_RFC2292BIS
.endif

.if ${MK_CASPER} != "no" && !defined(RESCUE)
CFLAGS+=-DWITH_CASPER
.endif

.if !defined(RELEASE_CRUNCH) || ${MK_INET6_SUPPORT} != "no"
CFLAGS+=-DIPSEC
.endif

.include <bsd.test.mk>
