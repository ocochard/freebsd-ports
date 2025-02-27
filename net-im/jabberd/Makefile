PORTNAME=	jabberd
PORTVERSION=	2.7.0
PORTREVISION=	5
CATEGORIES=	net-im
MASTER_SITES=	https://github.com/jabberd2/jabberd2/releases/download/${PORTNAME}-${DISTVERSION}/ \
		LOCAL/matthew/${PORTNAME}

MAINTAINER=	mm@FreeBSD.org
COMMENT=	Online presence and instant messaging server
WWW=		https://jabberd2.org/

LICENSE=	GPLv2

LIB_DEPENDS=	libexpat.so:textproc/expat2 \
		libgsasl.so:security/libgsasl \
		libidn.so:dns/libidn \
		libudns.so:dns/udns

USES=		autoreconf compiler:c11 iconv libtool perl5 pkgconfig \
		ssl tar:xz

OPTIONS_DEFINE=	MYSQL PGSQL LDAP BDB SQLITE PAM PIPE ANON FS DEBUG REQUIRES \
		DOCS SUPERSEDED EXPERIMENTAL
OPTIONS_DEFAULT=MYSQL DEBUG
OPTIONS_SUB=	yes

GNU_CONFIGURE=	yes
INSTALL_TARGET=	install-strip
USE_PERL5=	run
USE_RC_SUBR=	jabberd
USE_LDCONFIG=	${PREFIX}/lib/jabberd
CONFIGURE_ARGS=	--localstatedir=/var \
		--sysconfdir=${PREFIX}/etc/jabberd \
		--enable-ssl --enable-mio=kqueue \
		--disable-tests \
		--with-sasl=gsasl \
		--with-extra-include-path="${LOCALBASE}/include ${EIP}" \
		--with-extra-library-path="${LOCALBASE}/lib ${ELP}"

JABBER_USER=	jabber
JABBER_GROUP=	jabber

USERS=		${JABBER_USER}
GROUPS=		${JABBER_GROUP}

JABBER_ETCDIR=	"${PREFIX}/etc/jabberd"
JABBER_RUNDIR=	"/var/jabberd"

PLIST_SUB+=	JABBER_USER=${JABBER_USER} \
		JABBER_GROUP=${JABBER_GROUP} \
		JABBER_ETCDIR="${JABBER_ETCDIR}" \
		JABBER_RUNDIR="${JABBER_RUNDIR}"

SUB_LIST+=	JABBER_USER=${JABBER_USER} \
		JABBER_RUNDIR="${JABBER_RUNDIR}" \
		PERL="${PERL}"

PORTDOCS=	*

DOCFILES=	AUTHORS ChangeLog NEWS README README.config \
		README.protocol TODO

_REQUIRE=	LOGIN

ELP+=	${OPENSSLLIB}
EIP+=	${OPENSSLINC}

DEBUG_CONFIGURE_ENABLE=	debug

PGSQL_USES=		pgsql
PGSQL_CONFIGURE_ENABLE=	pgsql

SQLITE_CONFIGURE_ENABLE=sqlite
SQLITE_LIB_DEPENDS=	libsqlite3.so:databases/sqlite3

MYSQL_USES=		mysql
MYSQL_CONFIGURE_ENABLE=	mysql
MYSQL_VARS=	IGNORE_WITH_MYSQL="81"

BDB_USES=		bdb
BDB_CONFIGURE_ENABLE=	db
BDB_CONFIGURE_ON=	--oldincludedir=/nonexistant

LDAP_USES=		ldap
LDAP_CONFIGURE_ENABLE=	ldap

FS_CONFIGURE_ENABLE=	fs
FS_DESC=		Filesystem storage (only for testing)

PAM_CONFIGURE_ENABLE=	pam

PIPE_CONFIGURE_ENABLE=	pipe
PIPE_DESC=		Enable pipe (auth/reg)

ANON_CONFIGURE_ENABLE=	anon
ANON_DESC=		Enable anonymous (auth/reg)

SUPERSEDED_CONFIGURE_ENABLE=	superseded
SUPERSEDED_DESC=	Enable superseded features (ns_TIME)

EXPERIMENTAL_CONFIGURE_ENABLE=	experimental
EXPERIMENTAL_DESC=	Enable experimental features (TLS-Everywhere)

.include <bsd.port.options.mk>

.if ${PORT_OPTIONS:MPGSQL}
_REQUIRE+=		postgresql
.endif

.if ${PORT_OPTIONS:MMYSQL}
EIP+=${LOCALBASE}/include/mysql
ELP+=${LOCALBASE}/lib/mysql
_REQUIRE+=	mysql
.endif

.if ${PORT_OPTIONS:MBDB}
EIP+=${BDB_INCLUDE_DIR}
ELP+=${BDB_LIB_DIR}
.endif

.if ${PORT_OPTIONS:MLDAP}
_REQUIRE+=	slapd
.endif

.if ${PORT_OPTIONS:MREQUIRES}
SUB_LIST+=	REQUIRE="${_REQUIRE}"
.else
SUB_LIST+=	REQUIRE="LOGIN"
.endif
REQUIRES_DESC=	Add backend requires to startup script

.include <bsd.port.pre.mk>

post-patch:
.for FILE in c2s.xml jabberd.cfg router-filter.xml router-users.xml \
	router.xml s2s.xml sm.xml templates/roster.xml
	@${MV} ${WRKSRC}/etc/${FILE}.dist.in ${WRKSRC}/etc/${FILE}.sample.in
.endfor
.if ${PORT_OPTIONS:MMYSQL} && ${MYSQL_VER:U} == 80
	cd ${WRKSRC}/storage && \
	${REINPLACE_CMD} 's/my_bool/_Bool/g' authreg_mysql.c storage_mysql.c
.endif

post-install:
.for DIR in db logs pid
	@${MKDIR} ${STAGEDIR}${JABBER_RUNDIR}/${DIR}
.endfor
	@${CHMOD} -R go= ${STAGEDIR}${JABBER_RUNDIR}
.if ${PORT_OPTIONS:MDOCS}
	@${MKDIR} ${STAGEDIR}${DOCSDIR}
.for FILE in ${DOCFILES}
	${INSTALL_DATA} ${WRKSRC}/${FILE} ${STAGEDIR}${DOCSDIR}
.endfor
.for FILE in db-setup.mysql db-setup.pgsql db-setup.sqlite
	${INSTALL_DATA} ${WRKSRC}/tools/${FILE} ${STAGEDIR}${DOCSDIR}
.endfor
.endif

.include <bsd.port.mk>
