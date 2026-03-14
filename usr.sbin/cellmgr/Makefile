#	$NetBSD$

MAN=	cellmgr.8
SCRIPTS=	cellmgr

.PATH:	${.CURDIR}/examples \
	${.CURDIR}/lib \
	${.CURDIR}/examples/mantisbt \
	${.CURDIR}/examples/httpd \
	${.CURDIR}/examples/api-gateway \
	${.CURDIR}/examples/blue-green \
	${.CURDIR}/examples/php-api \
	${.CURDIR}/examples/luanti

FILES+=	README cellmgr.conf.sample manifest.cell.sample manifest.apply.sample \
	legacy.sh cell.sh volume.sh system.sh ipc.sh dispatch.sh \
	manifest.volume.sample \
	mantisbt-webroot.volume mantisbt-secrets.volume mantisbt-postgres.volume \
	mantisbt-data-postgresql.cell mantisbt-data-postgresql.apply \
	mantisbt-app-phpfpm.cell mantisbt-app-phpfpm.apply \
	mantisbt-edge-nginx.cell mantisbt-edge-nginx.apply \
	mysite-edge-httpd.cell mysite-edge-httpd.apply \
	api-gateway-app-a-httpd.cell api-gateway-app-a-httpd.apply \
	api-gateway-app-b-httpd.cell api-gateway-app-b-httpd.apply \
	api-gateway-app-c-httpd.cell api-gateway-app-c-httpd.apply \
	api-gateway-edge-nginx.cell api-gateway-edge-nginx.apply \
	bluegreen-app-blue-httpd.cell bluegreen-app-blue-httpd.apply \
	bluegreen-app-green-httpd.cell bluegreen-app-green-httpd.apply \
	bluegreen-edge-nginx.cell bluegreen-edge-nginx.apply \
	php-api-webroot.volume \
	php-api-app-phpfpm.cell php-api-app-phpfpm.apply \
	php-api-edge-nginx.cell php-api-edge-nginx.apply \
	luanti-worlddata.volume \
	luanti-app-server.cell luanti-app-server.apply
FILESDIR=	/usr/share/examples/cellmgr

FILESDIR_mantisbt-data-postgresql.cell=	/usr/share/examples/cellmgr/mantisbt
FILESDIR_legacy.sh=	/usr/libexec/cellmgr
FILESDIR_cell.sh=	/usr/libexec/cellmgr
FILESDIR_volume.sh=	/usr/libexec/cellmgr
FILESDIR_system.sh=	/usr/libexec/cellmgr
FILESDIR_ipc.sh=	/usr/libexec/cellmgr
FILESDIR_dispatch.sh=	/usr/libexec/cellmgr
FILESDIR_mantisbt-data-postgresql.apply=	/usr/share/examples/cellmgr/mantisbt
FILESDIR_mantisbt-webroot.volume=	/usr/share/examples/cellmgr/mantisbt
FILESDIR_mantisbt-secrets.volume=	/usr/share/examples/cellmgr/mantisbt
FILESDIR_mantisbt-postgres.volume=	/usr/share/examples/cellmgr/mantisbt
FILESDIR_mantisbt-app-phpfpm.cell=	/usr/share/examples/cellmgr/mantisbt
FILESDIR_mantisbt-app-phpfpm.apply=	/usr/share/examples/cellmgr/mantisbt
FILESDIR_mantisbt-edge-nginx.cell=	/usr/share/examples/cellmgr/mantisbt
FILESDIR_mantisbt-edge-nginx.apply=	/usr/share/examples/cellmgr/mantisbt
FILESDIR_mysite-edge-httpd.cell=	/usr/share/examples/cellmgr/httpd
FILESDIR_mysite-edge-httpd.apply=	/usr/share/examples/cellmgr/httpd
FILESDIR_api-gateway-app-a-httpd.cell=	/usr/share/examples/cellmgr/api-gateway
FILESDIR_api-gateway-app-a-httpd.apply=	/usr/share/examples/cellmgr/api-gateway
FILESDIR_api-gateway-app-b-httpd.cell=	/usr/share/examples/cellmgr/api-gateway
FILESDIR_api-gateway-app-b-httpd.apply=	/usr/share/examples/cellmgr/api-gateway
FILESDIR_api-gateway-app-c-httpd.cell=	/usr/share/examples/cellmgr/api-gateway
FILESDIR_api-gateway-app-c-httpd.apply=	/usr/share/examples/cellmgr/api-gateway
FILESDIR_api-gateway-edge-nginx.cell=	/usr/share/examples/cellmgr/api-gateway
FILESDIR_api-gateway-edge-nginx.apply=	/usr/share/examples/cellmgr/api-gateway
FILESDIR_bluegreen-app-blue-httpd.cell=	/usr/share/examples/cellmgr/blue-green
FILESDIR_bluegreen-app-blue-httpd.apply=	/usr/share/examples/cellmgr/blue-green
FILESDIR_bluegreen-app-green-httpd.cell=	/usr/share/examples/cellmgr/blue-green
FILESDIR_bluegreen-app-green-httpd.apply=	/usr/share/examples/cellmgr/blue-green
FILESDIR_bluegreen-edge-nginx.cell=	/usr/share/examples/cellmgr/blue-green
FILESDIR_bluegreen-edge-nginx.apply=	/usr/share/examples/cellmgr/blue-green
FILESDIR_php-api-app-phpfpm.cell=	/usr/share/examples/cellmgr/php-api
FILESDIR_php-api-app-phpfpm.apply=	/usr/share/examples/cellmgr/php-api
FILESDIR_php-api-webroot.volume=	/usr/share/examples/cellmgr/php-api
FILESDIR_php-api-edge-nginx.cell=	/usr/share/examples/cellmgr/php-api
FILESDIR_php-api-edge-nginx.apply=	/usr/share/examples/cellmgr/php-api
FILESDIR_luanti-worlddata.volume=	/usr/share/examples/cellmgr/luanti
FILESDIR_luanti-app-server.cell=	/usr/share/examples/cellmgr/luanti
FILESDIR_luanti-app-server.apply=	/usr/share/examples/cellmgr/luanti

EXAMPLE_SUBDIRS=	mantisbt httpd api-gateway blue-green php-api luanti

beforeinstall: cellmgr-example-dirs

cellmgr-example-dirs:
	${INSTALL_DIR} ${DESTDIR}/usr/libexec/cellmgr
.for d in ${EXAMPLE_SUBDIRS}
	${INSTALL_DIR} ${DESTDIR}${FILESDIR}/${d}
.endfor

.include <bsd.prog.mk>
