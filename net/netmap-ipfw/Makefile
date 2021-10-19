# New ports collection makefile for:	ipfw-user
# Date created:		14 August 2012
# Whom:			Olivier Cochard-Labbé (olivier@cochard.me)
#
# $FreeBSD$
#

PORTNAME=	netmap-ipfw
PORTVERSION=	0.1
CATEGORIES=	net

MAINTAINER=	oliver@cochard.me
COMMENT=	Netmap-enabled IPFW userspace version

#WRKSRC=	${WRKDIR}/${PORTNAME}-${COMMIT}
USES=	gmake

USE_GITHUB=	yes
GH_ACCOUNT= luigirizzo
GH_PROJECT= ${PORTNAME}
GH_TAGNAME= 81bf5d4

#Warning: conflict name with /sbin/ipfw
PLIST_FILES=	bin/ipfw \
		bin/kipfw

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/ipfw/ipfw \
		${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/kipfw \
		${STAGEDIR}${PREFIX}/bin

.include <bsd.port.mk>
