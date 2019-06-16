#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD$

.include <src.opts.mk>

PACKAGE=runtime
PROG=	ping
SRCS=	main.c options.c ping.c
MAN=	ping.8
BINOWN=	root
BINMODE=4555
WARNS?=	3
LIBADD=	m

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6 -DKAME_SCOPEID -DUSE_RFC2292BIS
SRCS+= ping6.c
MAN+= ping6.8
LIBADD=	md
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
LIBADD+=	ipsec
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
