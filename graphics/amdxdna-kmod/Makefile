PORTNAME=	amdxdna-kmod
DISTVERSION=	g20261116
CATEGORIES=	graphics

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	Driver for AMD XDNA NPUs (Ryzen AI)
WWW=		https://github.com/ocochard/drm-kmod/tree/olivier-amdxdna

LICENSE=	GPLv2

ONLY_FOR_ARCHS=	amd64
ONLY_FOR_ARCHS_REASON=	the driver is ported for amd64 only

RUN_DEPENDS=	${KMODDIR}/drm.ko:graphics/drm-latest-kmod \
		/boot/firmware/amdnpu/17f0_11/npu_7.sbin:graphics/npu-firmware-amd-kmod

USES=		kmod uidfix
USE_GITHUB=	yes
GH_ACCOUNT=	ocochard
GH_PROJECT=	drm-kmod
GH_TAGNAME=	946037444e32c0a84b1d890b74640827d71a4bd0

MAKE_ENV+=	MAKEOBJDIRPREFIX=${WRKSRC}/obj
BUILD_WRKSRC=	${WRKSRC}/amdxdna
INSTALL_WRKSRC=	${WRKSRC}/amdxdna

SUB_FILES=	pkg-message

PLIST_FILES=	${KMODDIR}/amdxdna.ko

pre-build:
	${MKDIR} ${WRKSRC}/obj
	(cd ${BUILD_WRKSRC} ; ${SETENV} ${MAKE_ENV} ${MAKE_CMD} obj)

.include <bsd.port.mk>
