# $FreeBSD$

.include <src.opts.mk>

PACKAGE=tests

ATF_TESTS_SH+=		ping_test
${PACKAGE}FILES+=	ping_c3.out

.if ${MK_INET6_SUPPORT} != "no"
ATF_TESTS_SH+=		ping6_test
${PACKAGE}FILES+=	ping6_c3.out
.endif

TESTS_SUBDIRS=	options

.include <bsd.test.mk>
