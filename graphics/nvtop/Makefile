PORTNAME=	nvtop
PORTVERSION=	3.2.0
CATEGORIES=	graphics

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	Top like task monitor for GPUs
WWW=		https://github.com/Syllo/nvtop

LICENSE=	GPLv3+
LICENSE_FILE=	${WRKSRC}/COPYING

BUILD_DEPENDS=	${LOCALBASE}/include/sys/sysinfo.h:devel/libsysinfo
LIB_DEPENDS=	libudev.so:devel/libudev-devd \
		libdrm.so:graphics/libdrm

USES=		cmake ncurses pkgconfig desktop-file-utils

USE_GITHUB=	yes
GH_ACCOUNT=	Syllo
GH_TAGNAME=	6e91c74

CMAKE_ARGS=	-DCMAKE_BUILD_TYPE=Release \
		-DNVIDIA_SUPPORT=ON -DAMDGPU_SUPPORT=ON -DINTEL_SUPPORT=ON

PLIST_FILES=	bin/nvtop \
		share/applications/nvtop.desktop \
		share/icons/nvtop.svg \
		share/man/man1/nvtop.1.gz \
		share/metainfo/nvtop.metainfo.xml

post-patch:
	@${REINPLACE_CMD} -e '/sysmacros.h/d' \
		${WRKSRC}/src/extract_gpuinfo_amdgpu.c \
		${WRKSRC}/src/extract_gpuinfo_panfrost.c \
		${WRKSRC}/src/extract_processinfo_fdinfo.c

.include <bsd.port.mk>
