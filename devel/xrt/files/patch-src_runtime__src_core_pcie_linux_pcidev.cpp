--- src/runtime_src/core/pcie/linux/pcidev.cpp.orig	2026-11-10 18:38:00 UTC
+++ src/runtime_src/core/pcie/linux/pcidev.cpp
@@ -379,11 +379,47 @@ put(const std::string& name,
 
 } // sysfs
 
+#ifdef __FreeBSD__
 void
 dev::
 sysfs_get(const std::string& subdev, const std::string& entry,
           std::string& err, std::vector<std::string>& ret)
 {
+  std::string s;
+
+  ret.clear();
+  err.clear();
+  if (freebsd::attr(m_driver->name(), m_sysfs_name, subdev, entry, s))
+    ret.push_back(s);
+  else
+    err = "No attribute " + entry + " for " + m_sysfs_name + "\n";
+}
+
+void
+dev::
+sysfs_get(const std::string& subdev, const std::string& entry,
+          std::string& err, std::vector<uint64_t>& ret)
+{
+  std::vector<std::string> sv;
+
+  ret.clear();
+  sysfs_get(subdev, entry, err, sv);
+  for (auto& s : sv) {
+    char* end = nullptr;
+    auto n = std::strtoull(s.c_str(), &end, 0);
+    if (s.empty() || *end != '\0') {
+      err = "Attribute " + entry + " is not an integer: " + s + "\n";
+      break;
+    }
+    ret.push_back(n);
+  }
+}
+#else
+void
+dev::
+sysfs_get(const std::string& subdev, const std::string& entry,
+          std::string& err, std::vector<std::string>& ret)
+{
   sysfs::get(m_sysfs_name, subdev, entry, err, ret);
 }
 
@@ -394,6 +430,7 @@ sysfs_get(const std::string& subdev, const std::string
 {
   sysfs::get(m_sysfs_name, subdev, entry, err, ret);
 }
+#endif
 
 void
 dev::
@@ -408,7 +445,14 @@ sysfs_get(const std::string& subdev, const std::string
 sysfs_get(const std::string& subdev, const std::string& entry,
           std::string& err, std::string& s)
 {
+#ifdef __FreeBSD__
+  std::vector<std::string> sv;
+
+  sysfs_get(subdev, entry, err, sv);
+  s = sv.empty() ? "" : sv[0];
+#else
   sysfs::get(m_sysfs_name, subdev, entry, err, s);
+#endif
 }
 
 void
@@ -504,9 +548,13 @@ dev(std::shared_ptr<const drv> driver, std::string sys
   if (m_is_mgmt)
     sysfs_get("", "instance", err, m_instance, static_cast<uint32_t>(INVALID_ID));
   else
+#ifdef __FreeBSD__
+    m_instance = freebsd::unit_of(m_driver->name(), m_sysfs_name);
+#else
     m_instance = get_render_value(
       sysfs_path + "/" + m_driver->sysfs_dev_node_dir(),
       m_driver->dev_node_prefix());
+#endif
 
   if (is_pci) {
     // BAR-mapped register access used by xclRead/Write (pcieBarRead/Write).
