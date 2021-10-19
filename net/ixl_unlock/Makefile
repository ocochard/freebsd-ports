# $FreeBSD$

PORTNAME=	ixl_unlock
PORTVERSION=	1
CATEGORIES=	net

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	Disable SFP Module Qualification on Intel XL710 network cards

LICENSE=	BSD2CLAUSE

USE_GITHUB=	yes
GH_ACCOUNT=	bu7cher
GH_TAGNAME=	8e0c9a6

PLIST_FILES=	sbin/ixl_unlock

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/${PORTNAME} ${STAGEDIR}${PREFIX}/sbin/

.include <bsd.port.mk>
