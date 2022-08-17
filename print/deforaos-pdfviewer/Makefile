PORTNAME=	pdfviewer
PORTVERSION=	0.1.0
PORTREVISION=	38
CATEGORIES=	print
MASTER_SITES=	https://ftp.defora.org/pub/DeforaOS/Apps/Desktop/src/PDFViewer/
PKGNAMEPREFIX=	deforaos-
DISTNAME=	PDFViewer-${PORTVERSION}

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	DeforaOS desktop PDF viewer

LICENSE=	GPLv3

LIB_DEPENDS=	libSystem.so:devel/deforaos-libsystem \
		libDesktop.so:x11/deforaos-libdesktop \
		libpoppler-glib.so:graphics/poppler-glib \
		libfontconfig.so:x11-fonts/fontconfig \
		libfreetype.so:print/freetype2 \
		libharfbuzz.so:print/harfbuzz

MAKE_ARGS+=	PREFIX=${PREFIX}
USES=		desktop-file-utils gnome pkgconfig
USE_GNOME=	gtk30 gdkpixbuf2 cairo
USE_XORG=	x11
MAKE_ENV+=	MANDIR=${STAGEDIR}${MANPREFIX}/man

OPTIONS_DEFINE=	DOCS NLS
OPTIONS_SUB=	yes
NLS_USES=	gettext
DOCS_BUILD_DEPENDS=	xsltproc:textproc/libxslt \
	${LOCALBASE}/share/xsl/docbook/manpages/docbook.xsl:textproc/docbook-xsl

post-patch-DOCS-off:
	${REINPLACE_CMD} 's|data doc po|data po|' \
		${WRKSRC}/Makefile

post-patch-NLS-off:
	${REINPLACE_CMD} 's|po src tools|src tools|' \
		${WRKSRC}/Makefile

post-install:
	${STRIP_CMD} ${STAGEDIR}${PREFIX}/bin/pdfviewer

.include <bsd.port.mk>
