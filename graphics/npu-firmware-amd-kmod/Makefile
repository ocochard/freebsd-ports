PORTNAME=	npu-firmware-amd-kmod
PORTVERSION=	20261019
CATEGORIES=	graphics
DIST_SUBDIR=	linux-firmware/${PORTVERSION}
EXTRACT_ONLY=

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	Firmware for AMD XDNA NPUs (Ryzen AI)
WWW=		https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/tree/amdnpu

LICENSE=	AMDNPU
LICENSE_NAME=	AMD NPU firmware license
LICENSE_FILE=	${WRKSRC}/LICENSE.amdnpu
LICENSE_PERMS=	dist-mirror no-dist-sell pkg-mirror no-pkg-sell auto-accept

ONLY_FOR_ARCHS=	amd64
ONLY_FOR_ARCHS_REASON=	the amdxdna driver is only built for amd64

NO_ARCH=	yes
NO_BUILD=	yes
NO_WRKSUBDIR=	yes

FWDIR=		/boot/firmware

# From the amdnpu File: and Link: lines of the linux-firmware WHENCE
# file at tag ${PORTVERSION}.
FWFILES=	amdnpu/1502_00/npu.sbin.1.5.2.380 \
		amdnpu/1502_00/npu.sbin.1.5.5.391 \
		amdnpu/17f0_10/npu.sbin.1.0.0.63 \
		amdnpu/17f0_10/npu.sbin.1.1.2.64 \
		amdnpu/17f0_11/npu.sbin.1.0.0.166 \
		amdnpu/17f0_11/npu.sbin.1.1.2.65

FWLINKS=	amdnpu/1502_00/npu.sbin:npu.sbin.1.5.2.380 \
		amdnpu/1502_00/npu_7.sbin:npu.sbin.1.5.5.391 \
		amdnpu/17f0_10/npu.sbin:npu.sbin.1.0.0.63 \
		amdnpu/17f0_10/npu_7.sbin:npu.sbin.1.1.2.64 \
		amdnpu/17f0_11/npu.sbin:npu.sbin.1.0.0.166 \
		amdnpu/17f0_11/npu_7.sbin:npu.sbin.1.1.2.65

_FWSITE=	https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/

.include <bsd.port.pre.mk>

# One master site per file, so that the tag can be passed as a query
# string and the file still lands under its own path.
_FWDIST=	${FWFILES} LICENSES/LICENSE.amdnpu
.for _i in ${_FWDIST:range}
DISTFILES+=	${_FWDIST:[${_i}]}:fw${_i}
MASTER_SITES+=	${_FWSITE}${_FWDIST:[${_i}]}?h=${PORTVERSION}&dummy=/:fw${_i}
.endfor

PLIST_FILES=	${FWFILES:S,^,${FWDIR}/,} \
		${FWLINKS:C,:.*,,:S,^,${FWDIR}/,}
PLIST_DIRS=	${FWFILES:H:O:u:S,^,${FWDIR}/,} ${FWDIR}/amdnpu

post-extract:
	${CP} ${DISTDIR}/${DIST_SUBDIR}/LICENSES/LICENSE.amdnpu \
	    ${WRKSRC}/LICENSE.amdnpu

do-install:
.for _f in ${FWFILES}
	@${MKDIR} ${STAGEDIR}${FWDIR}/${_f:H}
	${INSTALL_DATA} ${DISTDIR}/${DIST_SUBDIR}/${_f} \
	    ${STAGEDIR}${FWDIR}/${_f}
.endfor
.for _l in ${FWLINKS}
	${LN} -s ${_l:C,^[^:]*:,,} ${STAGEDIR}${FWDIR}/${_l:C,:.*,,}
.endfor

.include <bsd.port.post.mk>
