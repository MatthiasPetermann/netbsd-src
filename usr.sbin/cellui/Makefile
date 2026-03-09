#	$NetBSD$

.include <bsd.own.mk>

PROG=	cellui
SRCS=	main.c model.c adapter.c theme.c ui.c util.c
MAN=	cellui.8

WARNS?=	4
COPTS+=	-std=c99

DPADD+=	${LIBCURSES} ${LIBTERMINFO}
LDADD+=	-lcurses -lterminfo

.include <bsd.prog.mk>
