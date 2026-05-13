#	$NetBSD$

PROG=	cellman
SRCS=	main.c
MAN=	cellman.8 cellman-spec.5

.include <bsd.own.mk>

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

.if ${MKSHARE} != "no"
CELLMAN_EXAMPLESDIR=	/usr/share/examples/cellman
CELLMAN_EXAMPLE_FILES=	README \
		api-gateway/01-cells.lua \
		api-gateway/02-apply-app-a.lua \
		api-gateway/03-apply-app-b.lua \
		api-gateway/04-apply-app-c.lua \
		api-gateway/05-apply-nginx.lua \
		api-gateway/assets/app-a-index.html \
		api-gateway/assets/app-b-index.html \
		api-gateway/assets/app-c-index.html \
		api-gateway/assets/nginx.conf \
		blue-green/01-cells.lua \
		blue-green/02-apply-blue.lua \
		blue-green/03-apply-green.lua \
		blue-green/04-apply-nginx.lua \
		blue-green/assets/blue-index.html \
		blue-green/assets/green-index.html \
		blue-green/assets/nginx.conf \
		forgejo/01-volumes.lua \
		forgejo/02-cells.lua \
		forgejo/03-apply-forgejo.lua \
		forgejo/assets/app.ini \
		httpd/01-cells.lua \
		httpd/02-apply-httpd.lua \
		httpd/assets/index.html \
		luanti/01-volumes.lua \
		luanti/02-cells.lua \
		luanti/03-apply-luanti.lua \
		luanti/assets/install-mineclonia.sh \
		luanti/assets/minetest.conf \
		luanti/assets/world.mt \
		mantisbt/01-volumes.lua \
		mantisbt/02-cells.lua \
		mantisbt/03-apply-postgresql.lua \
		mantisbt/04-apply-phpfpm.lua \
		mantisbt/05-apply-nginx.lua \
		mantisbt/assets/app-configure.sh \
		mantisbt/assets/db-configure.sh \
		mantisbt/assets/nginx.conf \
		mantisbt/assets/php-fpm.conf \
		php-api/01-volumes.lua \
		php-api/02-cells.lua \
		php-api/03-apply-phpfpm.lua \
		php-api/04-apply-nginx.lua \
		php-api/assets/index.php \
		php-api/assets/nginx.conf \
		php-api/assets/php-fpm.conf \
		samples/01-volumes.lua \
		samples/02-cells.lua \
		samples/03-apply-web.lua \
		samples/04-apply-script.lua \
		samples/05-apply-template.lua \
		samples/README.md \
		samples/assets/bootstrap.sh \
		samples/assets/ensure-bootstrapped.sh \
		samples/assets/example.env.tmpl \
		samples/assets/index.html \
		samples/assets/runtime.txt.tmpl \
		ticketd/01-volumes.lua \
		ticketd/02-cells.lua \
		ticketd/03-apply-ticketd.lua \
		ticketd/assets/ticketadm \
		ticketd/assets/ticketd \
		ticketd/assets/ticketd-logo.svg \
		ticketd/assets/ticketd.conf \
		webdavd/01-cells.lua \
		webdavd/02-apply-webdavd.lua \
		webdavd/assets/webdavd \
		webdavd/assets/webdavd.conf

.for f in ${CELLMAN_EXAMPLE_FILES}
FILES+=	${.CURDIR}/examples/${f}
.if ${f:H} == "."
FILESDIR_${.CURDIR}/examples/${f}=	${CELLMAN_EXAMPLESDIR}
.else
FILESDIR_${.CURDIR}/examples/${f}=	${CELLMAN_EXAMPLESDIR}/${f:H}
.endif
FILESNAME_${.CURDIR}/examples/${f}=	${f:T}
.endfor
.endif

.include <bsd.prog.mk>
