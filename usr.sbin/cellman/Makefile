#	$NetBSD$

PROG=	cellman
SRCS=	main.c
MAN=	cellman.8 cellman-spec.5

.PATH: ${.CURDIR}/api ${.CURDIR}/commands

WARNS?=	4
COPTS+=	-std=c99

LIBCELLMAN_OBJS=	log.o util.o proc_exec.o fs_util.o model.o template.o dsl_lua.o apply_exec.o \
		state.o command_backend.o command_runtime_snapshot.o command_system_bootstrap.o command_dispatch.o command_route.o command_read_opts.o command_cell.o command_volume.o command_system.o \
		command_backup_cli.o runtime_volume.o runtime_backup.o \
		api_core.o cmd_dispatch.o cmd_apply.o cmd_cell.o \
		cmd_volume.o cmd_system.o read_models.o actions.o

CLEANFILES+=	libcellman.a

libcellman.a: ${LIBCELLMAN_OBJS}
	${_MKTARGET_CREATE}
	${AR} -rcs ${.TARGET} ${.ALLSRC}

${PROG}: libcellman.a

DPADD+=	libcellman.a ${LIBLUA} ${LIBM}
LDADD+=	libcellman.a -llua -lm

.include <bsd.prog.mk>
