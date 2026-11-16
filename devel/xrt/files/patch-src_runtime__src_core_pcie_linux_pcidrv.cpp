--- src/runtime_src/core/pcie/linux/pcidrv.cpp.orig	2026-11-10 18:38:00 UTC
+++ src/runtime_src/core/pcie/linux/pcidrv.cpp
@@ -12,6 +12,30 @@ scan_devices(std::vector<std::shared_ptr<dev>>& ready_
 scan_devices(std::vector<std::shared_ptr<dev>>& ready_list,
              std::vector<std::shared_ptr<dev>>& nonready_list) const
 {
+#ifdef __FreeBSD__
+  const std::string drv_name = name();
+
+  for (int unit = 0, miss = 0; miss < 8; unit++) {
+    std::string bdf;
+    if (!freebsd::unit_bdf(drv_name, unit, bdf)) {
+      miss++;
+      continue;
+    }
+    miss = 0;
+    try {
+      auto pf = create_pcidev(bdf);
+      if (!pf || !std::filesystem::exists(pf->get_subdev_path("", -1)))
+        continue;
+      if (pf->m_is_ready)
+        ready_list.push_back(std::move(pf));
+      else
+        nonready_list.push_back(std::move(pf));
+    }
+    catch (const std::exception&) {
+      continue;
+    }
+  }
+#else
   namespace sfs = std::filesystem;
 
   // Each driver-bus root the device may be bound to, paired with whether
@@ -103,6 +127,7 @@ scan_devices(std::vector<std::shared_ptr<dev>>& ready_
     if (!ready_list.empty() || !nonready_list.empty())
       return;
   }
+#endif
 }
 
 std::shared_ptr<dev>
