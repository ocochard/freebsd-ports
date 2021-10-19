# $FreeBSD: head/net/pimd/Makefile 385640 2015-05-07 17:26:05Z mat $

PORTNAME=	netmap-fwd
PORTVERSION=	0.2
CATEGORIES=	net

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	IPv4 router over netmap for FreeBSD

LICENSE=	BSD2CLAUSE

LIB_DEPENDS=	libevent.so:devel/libevent2 \
				libucl.so:textproc/libucl

USE_GITHUB=	yes
GH_ACCOUNT=	Netgate
GH_PROJECT=	${PORTNAME}
GH_TAGNAME=	6245f9a
USE_RC_SUBR=	netmapfwd

PLIST_FILES=	sbin/${PORTNAME} \
				etc/${PORTNAME}.conf

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/${PORTNAME} ${STAGEDIR}${PREFIX}/sbin
	${INSTALL_DATA} ${WRKSRC}/${PORTNAME}.conf ${STAGEDIR}${PREFIX}/etc

.include <bsd.port.mk>
