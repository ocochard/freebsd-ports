PORTNAME=	browser
PORTVERSION=	0.5.5
CATEGORIES=	x11-fm
MASTER_SITES=	https://ftp.defora.org/pub/DeforaOS/Apps/Desktop/src/Browser/
PKGNAMEPREFIX=	deforaos-
DISTNAME=	Browser-${PORTVERSION}

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	DeforaOS desktop file browser

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/COPYING

LIB_DEPENDS=	libSystem.so:devel/deforaos-libsystem \
		libDesktop.so:x11/deforaos-libdesktop \
		libfontconfig.so:x11-fonts/fontconfig \
		libfreetype.so:print/freetype2 \
		libXrandr.so:x11/libXrandr \
		libharfbuzz.so:print/harfbuzz

USES=		desktop-file-utils gnome pkgconfig xorg
USE_GNOME=	gtk30 cairo gdkpixbuf2
USE_XORG=	x11
USE_LDCONFIG=	yes
MAKE_ARGS+=	PREFIX=${PREFIX}
MAKE_ENV+=	MANDIR=${STAGEDIR}${MANPREFIX}/man
# Fix namespace collision with xdg-utils
CPPFLAGS+=	-DPROGNAME_BROWSER=\"deforaos-browser\"\
			-DPROGNAME_COPY=\"deforaos-copy\"\
			-DPROGNAME_OPEN=\"deforaos-open\"

OPTIONS_DEFINE=	DOCS NLS
OPTIONS_SUB=	yes
NLS_USES=		gettext
DOCS_BUILD_DEPENDS=	xsltproc:textproc/libxslt \
    ${LOCALBASE}/share/xsl/docbook/manpages/docbook.xsl:textproc/docbook-xsl

CONFLICTS_INSTALL=	schilyutils silo # bin/browser bin/copy
post-patch:
	${REINPLACE_CMD} -e 's|/lib/|/libdata/|g' \
		${WRKSRC}/data/pkgconfig.sh
	${REINPLACE_CMD} -e 's|Exec=browser|Exec=deforaos-browser|g' \
		${WRKSRC}/data/org.defora.browser.desktop
	${REINPLACE_CMD} -e 's|Exec=browser|TryExec=deforaos-browser|g' \
		${WRKSRC}/data/org.defora.browser.desktop \
		${WRKSRC}/data/org.defora.browser-folder.desktop

post-patch-DOCS-off:
	${REINPLACE_CMD} -e '/^SUBDIRS/ s|doc||' ${WRKSRC}/Makefile

post-patch-NLS-off:
	${REINPLACE_CMD} 's|include po src|include src|' \
		${WRKSRC}/Makefile

post-install:
	${STRIP_CMD} ${STAGEDIR}${PREFIX}/bin/* \
		${STAGEDIR}${PREFIX}/lib/Desktop/widget/browser.so \
		${STAGEDIR}${PREFIX}/lib/Browser/plugins/* \
		${STAGEDIR}${PREFIX}/lib/libBrowser.so.0.0
	@${MV} ${STAGEDIR}${PREFIX}/bin/browser \
		${STAGEDIR}${PREFIX}/bin/deforaos-browser
	@${MV} ${STAGEDIR}${PREFIX}/bin/open \
		${STAGEDIR}${PREFIX}/bin/deforaos-open
	@${MV} ${STAGEDIR}${PREFIX}/bin/copy \
		${STAGEDIR}${PREFIX}/bin/deforaos-copy

.include <bsd.port.mk>
