PORTNAME=	git-credential-oauth
PORTVERSION=	0.11.0
PORTREVISION=	2
DISTVERSIONPREFIX=	v
CATEGORIES=	security

MAINTAINER=	ehaupt@FreeBSD.org
COMMENT=	Git credential helper for GitHub and other forges using OAuth
WWW=		https://github.com/hickford/git-credential-oauth

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE.txt

USES=		go:modules
USE_GITHUB=	yes
GH_ACCOUNT=	hickford

GO_MODULE=	github.com/${GH_ACCOUNT}/${PORTNAME}

PLIST_FILES=	bin/git-credential-oauth

.include <bsd.port.mk>
