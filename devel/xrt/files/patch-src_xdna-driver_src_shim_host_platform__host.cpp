--- src/xdna-driver/src/shim/host/platform_host.cpp.orig	2026-11-14 04:56:45 UTC
+++ src/xdna-driver/src/shim/host/platform_host.cpp
@@ -6,6 +6,10 @@
 #include "core/common/trace.h"
 #include <fstream>
 #include <fcntl.h>
+#ifdef __FreeBSD__
+#include <algorithm>
+#include "core/pcie/linux/pcidrv.h"
+#endif
 #include <drm/drm.h>
 #include <sys/ioctl.h>
 
@@ -357,6 +361,17 @@ get_sysfs(get_sysfs_arg& arg) const
 platform_drv_host::
 get_sysfs(get_sysfs_arg& arg) const
 {
+#ifdef __FreeBSD__
+  // sysfs_root() is /sys/bus/pci/devices/<bdf>; the attribute is a sysctl.
+  const auto& root = sysfs_root();
+  std::string val;
+  if (!xrt_core::pci::freebsd::attr("amdxdna", root.substr(root.rfind('/') + 1),
+                                    "", arg.sysfs_node, val))
+    shim_err(-ENOENT, "No attribute %s for %s", arg.sysfs_node.c_str(), root.c_str());
+  arg.real_size = std::min(val.size(), arg.data.size());
+  std::copy_n(val.data(), arg.real_size, arg.data.data());
+  return;
+#endif
   std::string path = sysfs_root() + "/" + arg.sysfs_node;
   std::ifstream ifs(path, std::ios::binary);
   if (!ifs.is_open())
@@ -372,6 +387,9 @@ put_sysfs(put_sysfs_arg& arg) const
 platform_drv_host::
 put_sysfs(put_sysfs_arg& arg) const
 {
+#ifdef __FreeBSD__
+  shim_err(-EOPNOTSUPP, "Writing %s is not supported", arg.sysfs_node.c_str());
+#endif
   std::string path = sysfs_root() + "/" + arg.sysfs_node;
   std::ofstream ofs(path, std::ios::binary);
   if (!ofs.is_open())
