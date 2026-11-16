--- src/xdna-driver/src/shim/pcidrv.cpp.orig	2026-11-14 04:56:45 UTC
+++ src/xdna-driver/src/shim/pcidrv.cpp
@@ -18,6 +18,13 @@ get_dev_node(const std::string& sysfs_name) const
 drv::
 get_dev_node(const std::string& sysfs_name) const
 {
+#ifdef __FreeBSD__
+  // The device node number is the newbus unit (/dev/accel/accel<unit>).
+  int unit = xrt_core::pci::freebsd::unit_of(name(), sysfs_name);
+  if (unit >= 0)
+    return std::string("/dev/") + dev_node_dir() + "/" + dev_node_prefix() + std::to_string(unit);
+  throw std::invalid_argument(std::string("Bad sysfs name: ") + sysfs_name.c_str());
+#else
   const std::string dev_path_dir = dev_sysfs_root(sysfs_name) + "/" + sysfs_dev_node_dir();
   const auto prefix = dev_node_prefix();
 
@@ -36,6 +43,7 @@ get_dev_node(const std::string& sysfs_name) const
       return std::string("/dev/") + dev_node_dir() + "/" + valid;
   }
   throw std::invalid_argument(std::string("Bad sysfs name: ") + sysfs_name.c_str());
+#endif
 }
 
 }
