# $FreeBSD$

.include <src.opts.mk>

PACKAGE=tests

.if ${MK_INET_SUPPORT} != "no"
ATF_TESTS_SH+=		ping_test
${PACKAGE}FILES+=	ping_c3.out
.endif

.if ${MK_INET6_SUPPORT} != "no"
ATF_TESTS_SH+=		ping6_test
${PACKAGE}FILES+=	ping6_c3.out
.endif

ATF_TESTS_C=	in_cksum_test

SRCS.in_cksum_test=	in_cksum_test.c ../utils.c

TESTS_SUBDIRS=	options

.include <bsd.test.mk>
