--- src/xdna-driver/src/shim/host/pcidrv_amdxdna.cpp.orig	2026-11-14 04:56:45 UTC
+++ src/xdna-driver/src/shim/host/pcidrv_amdxdna.cpp
@@ -8,12 +8,21 @@
 #include "pcidrv_amdxdna.h"
 #include "core/pcie/linux/system_linux.h"
 #include <fstream>
+#ifdef __FreeBSD__
+#include "core/pcie/linux/pcidrv.h"
+#endif
 
 namespace {
 
 int
 get_dev_type(const std::string& sysfs)
 {
+#ifdef __FreeBSD__
+  std::string s;
+  if (!xrt_core::pci::freebsd::attr("amdxdna", sysfs, "", "device_type", s))
+    throw std::invalid_argument(sysfs + ": device_type is missing?");
+  return static_cast<int>(std::stoi(s));
+#endif
   const std::string dev_type_path = shim_xdna::dev_sysfs_root(sysfs) + "/device_type";
 
   std::ifstream ifs(dev_type_path);
