PORTNAME=	itcl
PORTVERSION=	3.4.4
PORTREVISION=	1
PORTEPOCH=	1
CATEGORIES=	lang tcl
MASTER_SITES=	SF/incrtcl/%5BIncr%20Tcl_Tk%5D-source/itcl%203.4.4
DISTNAME=	itcl${PORTVERSION}

MAINTAINER=	erik@bz.bzflag.bz
COMMENT=	Object-oriented extension to Tcl [incr Tcl]
WWW=		https://sourceforge.net/projects/incrtcl/

USES+=		tcl:85,86,tea

USE_LDCONFIG=	${PREFIX}/lib/itcl${PORTVERSION:R}

GNU_CONFIGURE_MANPREFIX=${PREFIX}/share

WRKSRC=		${WRKDIR}/${PORTNAME}${PORTVERSION}
TEST_TARGET=	test

PLIST_SUB+=	PORTVERSION=${PORTVERSION} \
		VERSION=${PORTVERSION:R} \
		MAJOR=${PORTVERSION:R:R} \
		SHORT=${PORTVERSION:R:S/.//}

MAN_3=		Itcl_RegisterC.3 Itcl_Stack.3 Itcl_Class.3 \
		Itcl_List.3 Itcl_Object.3 Itcl_Preserve.3

post-patch:
	${REINPLACE_CMD} -E '/^includedir/s|/include|/include/itcl${PORTVERSION:R}|' \
	    ${WRKSRC}/${CONFIGURE_SCRIPT}

post-install:
	${LN} -s itcl${PORTVERSION:R}/libitcl${PORTVERSION:R}.so \
		${STAGEDIR}${PREFIX}/lib/libitcl.so.${PORTVERSION:R:R}
	${LN} -s itcl${PORTVERSION:R}/libitcl${PORTVERSION:R}.so \
		${STAGEDIR}${PREFIX}/lib/libitcl.so

.for FILE in ${MAN_3}
	${INSTALL_DATA} ${WRKSRC}/doc/${FILE:S/Itcl_//} ${STAGEDIR}${PREFIX}/share/man/man3/${FILE}
.endfor

.include <bsd.port.mk>
