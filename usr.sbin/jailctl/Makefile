#	$NetBSD$

PROG=	jailctl
MAN=	jailctl.8 jailmgr.8
SCRIPTS=	jailmgr

DPADD+=	${LIBUTIL}
LDADD+=	-lutil

FILES+=	examples/README.jailmgr examples/jailmgr.conf.sample
FILESDIR=	/usr/share/examples/jailctl

.include <bsd.prog.mk>
