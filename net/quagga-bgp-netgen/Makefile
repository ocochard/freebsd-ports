# $FreeBSD$

PORTNAME=	quagga-bgp-netgen
PORTVERSION=	0.2
CATEGORIES=	net

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	Generates Quagga/FRR bgp configuration file with lot's of routes

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

USE_GITHUB=	yes
GH_ACCOUNT=	ocochard

PLIST_FILES=	bin/${PORTNAME}

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/${PORTNAME} ${STAGEDIR}${PREFIX}/bin/

.include <bsd.port.mk>
