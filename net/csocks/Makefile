PORTNAME=	csocks
PORTVERSION=	1.7
PORTREVISION=	2
CATEGORIES=	net security
MASTER_SITES=	http://csocks.altervista.org/download/
DISTNAME=	${PORTNAME}_${PORTVERSION}

MAINTAINER=	raffaele.delorenzo@libero.it
COMMENT=	SOCKS Client v4/v5 RFC Compliant with many features
WWW=		http://csocks.altervista.org

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/../LICENSE

DEPRECATED=	Last release in 2013 and no development since, consider net/microsocks or net/3proxy
EXPIRATION_DATE=2024-03-31

PLIST_FILES=	etc/csocks.conf.sample lib/libcsocks.so lib/libcsocks.so.1 \
		bin/csocks share/man/man1/csocks.1.gz share/man/man5/csocks.conf.5.gz

USE_LDCONFIG=	yes

WRKSRC=		${WRKDIR}/src

post-patch:
	${REINPLACE_CMD} 's|libc.so|/lib/libc.so.7|' ${WRKSRC}/csocks.h

do-install:
	${INSTALL_SCRIPT} ${WRKDIR}/freebsd/csocks ${STAGEDIR}${PREFIX}/bin
	${INSTALL_LIB} ${WRKDIR}/src/libcsocks.so.1 ${STAGEDIR}${PREFIX}/lib
	${LN} -s libcsocks.so.1 ${STAGEDIR}${PREFIX}/lib/libcsocks.so
	${INSTALL_DATA} ${WRKDIR}/csocks.conf ${STAGEDIR}${PREFIX}/etc/csocks.conf.sample
	${INSTALL_MAN} ${WRKDIR}/man/csocks.1.gz ${STAGEDIR}${PREFIX}/share/man/man1
	${INSTALL_MAN} ${WRKDIR}/man/csocks.conf.5.gz ${STAGEDIR}${PREFIX}/share/man/man5

.include <bsd.port.mk>
