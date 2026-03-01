# $NetBSD$

.include "../Makefile.inc"

.PATH:	${S}/secmodel/jail

KMOD=	secmodel_jail
SRCS=	secmodel_jail.c \
	secmodel_jail_module.c \
	secmodel_jail_policy.c \
	secmodel_jail_secmodel.c \
	secmodel_jail_sysctl.c

.include <bsd.kmodule.mk>
