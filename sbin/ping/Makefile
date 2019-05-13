#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD$

.include <src.opts.mk>

PACKAGE=runtime
PROG=	ping
SRCS=	main.c options.c ping.c ping6.c
MAN=	ping.8 ping6.8
BINOWN=	root
BINMODE=4555
WARNS?=	3
LIBADD=	ipsec m md
CFLAGS+=-DIPSEC -DKAME_SCOPEID -DUSE_RFC2292BIS

.if ${MK_DYNAMICROOT} == "no"
.warning ${PROG} built without libcasper support
.elif ${MK_CASPER} != "no" && !defined(RESCUE)
LIBADD+=	casper
LIBADD+=	cap_dns
CFLAGS+=-DWITH_CASPER
.endif

.if !defined(RELEASE_CRUNCH)
CFLAGS+=-DIPSEC
LIBADD+=	ipsec
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
