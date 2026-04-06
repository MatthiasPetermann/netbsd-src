#	$NetBSD$

.include <bsd.own.mk>

PROG=	cellui
SRCS=	main.c model.c adapter.c theme.c ui.c util.c
MAN=	cellui.8

WARNS?=	4
COPTS+=	-std=c99

LIBCELLMAN!=	cd ${.CURDIR}/../cellman && ${PRINTOBJDIR}
DPADD+=	${LIBCELLMAN}/libcellman.a ${LIBCURSES} ${LIBTERMINFO} ${LIBLUA} ${LIBM}
LDADD+=	-L${LIBCELLMAN} -lcellman -lcurses -lterminfo -llua -lm

.include <bsd.prog.mk>
