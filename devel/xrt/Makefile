PORTNAME=	xrt
DISTVERSION=	2.27.20261110
CATEGORIES=	devel

MAINTAINER=	olivier@FreeBSD.org
COMMENT=	AMD Runtime and amdxdna plugin for Ryzen AI NPU devices
WWW=		https://github.com/Xilinx/XRT

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE

BUILD_DEPENDS=	libdrm>0:graphics/libdrm \
		ocl-icd>0:devel/ocl-icd \
		opencl>0:devel/opencl \
		rapidjson>0:devel/rapidjson
LIB_DEPENDS=	libboost_filesystem.so:devel/boost-libs \
		libuuid.so:misc/libuuid

USES=		cmake compiler:c++17-lang localbase:ldflags pkgconfig ssl
USE_GITHUB=	yes
GH_ACCOUNT=	Xilinx
GH_PROJECT=	XRT
GH_TAGNAME=	06c43a7f93fee129d32def1d372e17a8e69c05d2
GH_TUPLE=	serge1:ELFIO:f849001fc229c2598f8557e0df22866af194ef98:elfio/src/runtime_src/core/common/elf \
		microsoft:GSL:a3534567187d2edc428efd3f13466ff75fe5805c:gsl/src/runtime_src/core/common/gsl \
		Xilinx:aiebu:1b398e72a3ef1ad6e1af4d0f63997af523952e6a:aiebu/src/runtime_src/core/common/aiebu \
		jarro2783:cxxopts:10a7a647791fa3a24ec4f572f2573a6e0aaa881b:cxxopts/src/runtime_src/core/common/aiebu/src/cpp/cxxopts \
		facebook:zstd:f8745da6ff1ad1e7bab384bd1f9d742439278e99:zstd/src/runtime_src/core/common/aiebu/src/cpp/zstd \
		Xilinx:XDP:62034fcb5b6960526351ce6e17c5cd5deade73e8:xdp/src/runtime_src/xdp \
		Xilinx:aie-codegen:c97d788845dde6e5a26182ee8b7b238b786e1049:aiecodegen/src/runtime_src/xdp/aie-codegen \
		Xilinx:aie-regdb:3faba137f02db4dd3f64331e3a74a9b5584df8b7:aieregdb/src/runtime_src/xdp/aie-codegen/aie-regdb \
		amd:xdna-driver:ca385d85d88441715551fc55d229b3afdba973dc:xdna/src/xdna-driver

USE_LDCONFIG=	yes

CMAKE_SOURCE_PATH=	${WRKSRC}/src
CMAKE_ON=	CMAKE_DISABLE_FIND_PACKAGE_Python3 XRT_NPU XRT_UPSTREAM_DEBIAN
CMAKE_OFF=	AIEBU_BUILD_TESTS XRT_ENABLE_EMULATION XRT_ENABLE_HIP \
		XRT_ENABLE_USDT
CMAKE_ARGS=	-DLINUX_FLAVOR=freebsd -DLINUX_VERSION=${OSREL}
CFLAGS+=	-I${WRKSRC}/freebsd-compat
# The amdxdna plugin links with -z defs; pthreads are not in libc here.
LDFLAGS+=	-pthread
# Linux-only errno for a rejected xclbin signature (Alveo).  MAP_LOCKED
# pins the pages of a BO mapping: the driver's device pager keeps them.
# XRT links with -Bsymbolic, so each library keeps its own RTTI copies:
# compare type_info by name (libc++ NonUnique) or std::any built in the
# amdxdna plugin fails any_cast in libxrt_coreutil.
CXXFLAGS+=	-I${WRKSRC}/freebsd-compat -DEKEYREJECTED=EAUTH -DMAP_LOCKED=0 \
		-D_LIBCPP_TYPEINFO_COMPARISON_IMPLEMENTATION=2

OPTIONS_DEFINE=	DOCS

# aiebu vendors the same ELFIO commit as XRT: one distfile serves both.
# freebsd-compat holds the few Linux UAPI headers the Alveo code includes.
post-extract:
	${CP} -R ${FILESDIR}/freebsd-compat ${WRKSRC}/
	${RM} -r ${WRKSRC}/src/runtime_src/core/common/aiebu/src/cpp/ELFIO
	${CP} -R ${WRKSRC}/src/runtime_src/core/common/elf \
		${WRKSRC}/src/runtime_src/core/common/aiebu/src/cpp/ELFIO

# Userland code that branches on __linux__ only needs POSIX: take the same
# branch on FreeBSD.  Vendored zstd, json and catch already know FreeBSD.
LINUX_BRANCH_FILES=	core/common/aiebu/src/cpp/include/aiebu/detail/config.h \
			core/common/api/xrt_kernel.cpp \
			core/common/api/xrt_profile.cpp \
			core/common/config.h \
			core/common/config_reader.cpp \
			core/common/memalign.h \
			core/common/message.cpp \
			core/common/module_loader.cpp \
			core/common/scheduler.cpp \
			core/common/thread.cpp \
			core/include/xclerr_int.h \
			core/include/xgq_cmd_ert.h \
			core/include/xrt/deprecated/xrt.h \
			core/include/xrt/detail/config.h \
			core/include/xrt/detail/ert.h \
			core/include/xrt/detail/xclbin.h \
			core/tools/xbutil2/SubCmdValidate.cpp \
			xdp/config.h \
			xdp/profile/writer/vp_base/summary_writer.cpp \
			xocl/config.h \
			xrt/config.h

# aiebu's own PAGE_SIZE constant (8192) collides with <machine/param.h>.
# aiebu's ISA documentation downloads a tool at build time: skip it.
# The amdxdna plugin (xdna-driver, the commit pinning this XRT) builds in
# upstream mode inside XRT's tree, without SystemTap, its test installs or
# -Werror (its code is tuned for gcc warnings).
post-patch:
	@cd ${WRKSRC}/src/runtime_src && ${REINPLACE_CMD} \
		-e 's/defined(__linux__)/(defined(__linux__) || defined(__FreeBSD__))/g' \
		-e 's/#ifdef __linux__/#if defined(__linux__) || defined(__FreeBSD__)/' \
		${LINUX_BRANCH_FILES}
	@${ECHO_CMD} 'add_subdirectory(xdna-driver)' >> ${WRKSRC}/src/CMakeLists.txt
	@${REINPLACE_CMD} -e '/XRT_ENABLE_USDT/d' -e '/XDNA_BIN_DIR/d' -e '/"-Werror"/d' \
		${WRKSRC}/src/xdna-driver/src/shim/CMakeLists.txt
	@${REINPLACE_CMD} 's|^add_subdirectory(specification)|#&|' \
		${WRKSRC}/src/runtime_src/core/common/aiebu/CMakeLists.txt
	@cd ${WRKSRC}/src/runtime_src && ${REINPLACE_CMD} \
		-e 's|<linux/limits.h>|<limits.h>|' \
		-e 's|<linux/uuid.h>|<uuid/uuid.h>|' \
		core/common/api/xrt_xclbin.cpp \
		core/common/config_reader.cpp \
		core/common/message.cpp
	@${FIND} ${WRKSRC}/src/runtime_src/core/common/aiebu/src/cpp \
		\( -path '*/zstd' -o -path '*/ELFIO' -o -path '*/cxxopts' \) -prune -o \
		\( -name '*.cpp' -o -name '*.h' \) -print0 | \
		${XARGS} -0 ${GREP} -lw PAGE_SIZE | \
		${XARGS} ${REINPLACE_CMD} 's/[[:<:]]PAGE_SIZE[[:>:]]/AIEBU_PAGE_SIZE/g'

# The ICD file goes where ocl-icd looks; docs and version.json out of the
# top of PREFIX; the license is installed by the framework.
post-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/OpenCL/vendors ${STAGEDIR}${DATADIR}
	${MV} ${STAGEDIR}/etc/OpenCL/vendors/amdxrt.icd \
		${STAGEDIR}${PREFIX}/etc/OpenCL/vendors/
	${RM} -r ${STAGEDIR}/etc/OpenCL ${STAGEDIR}${PREFIX}/license
	${MV} ${STAGEDIR}${PREFIX}/version.json ${STAGEDIR}${DATADIR}/

post-install-DOCS-on:
	${MKDIR} ${STAGEDIR}${DOCSDIR}
	${MV} ${STAGEDIR}${PREFIX}/share/doc/CHANGELOG.rst \
		${STAGEDIR}${PREFIX}/share/doc/CONTRIBUTING.rst \
		${STAGEDIR}${PREFIX}/share/doc/NOTICE ${STAGEDIR}${DOCSDIR}/

post-install-DOCS-off:
	${RM} ${STAGEDIR}${PREFIX}/share/doc/CHANGELOG.rst \
		${STAGEDIR}${PREFIX}/share/doc/CONTRIBUTING.rst \
		${STAGEDIR}${PREFIX}/share/doc/NOTICE

.include <bsd.port.mk>
