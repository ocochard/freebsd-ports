PORTNAME=	libdesktop
PORTVERSION=	0.4.1
CATEGORIES=	x11
MASTER_SITES=	https://ftp.defora.org/pub/DeforaOS/Apps/Desktop/src/libDesktop/
DISTNAME=	libDesktop-${PORTVERSION}

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	DeforaOS desktop library

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/COPYING

LIB_DEPENDS=	libSystem.so:devel/deforaos-libsystem \
				libharfbuzz.so:print/harfbuzz

USES=		gnome pkgconfig
USE_GNOME=	gtk30 gdkpixbuf2 cairo
USE_XORG=	x11
USE_LDCONFIG=	yes
MAKE_ARGS+=	PREFIX=${PREFIX}
MAKE_ENV+=	MANDIR=${STAGEDIR}${MANPREFIX}/man

MAKE_JOBS_UNSAFE=	yes
OPTIONS_DEFINE=	DOCS

DOCS_BUILD_DEPENDS=	xsltproc:textproc/libxslt \
	${LOCALBASE}/share/xsl/docbook/manpages/docbook.xsl:textproc/docbook-xsl \
	gtkdoc-check:textproc/gtk-doc

post-patch:
	${REINPLACE_CMD} -e 's|/lib/|/libdata/|g' \
		${WRKSRC}/data/pkgconfig.sh

post-patch-DOCS-off:
	${REINPLACE_CMD} -e '/^SUBDIRS/ s|doc||' ${WRKSRC}/Makefile

post-install:
	${STRIP_CMD} ${STAGEDIR}${PREFIX}/bin/widget \
		${STAGEDIR}${PREFIX}/lib/libDesktop.so.0.0

.include <bsd.port.mk>
