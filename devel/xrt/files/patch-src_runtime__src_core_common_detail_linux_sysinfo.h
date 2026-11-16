--- src/runtime_src/core/common/detail/linux/sysinfo.h.orig	2026-11-10 18:38:00 UTC
+++ src/runtime_src/core/common/detail/linux/sysinfo.h
@@ -11,7 +11,13 @@
 
 // System - Include Files
 #include <cerrno>
+#ifdef __FreeBSD__
+#include <sys/param.h>
+#include <sys/sysctl.h>
+#include <kenv.h>
+#else
 #include <gnu/libc-version.h>
+#endif
 #include <sys/ioctl.h>
 #include <sys/utsname.h>
 #include <thread>
@@ -31,6 +37,35 @@ namespace {
 #endif
 
 namespace {
+#ifdef __FreeBSD__
+static std::string
+machine_info()
+{
+  char buf[128];
+  if (::kenv(KENV_GET, "smbios.system.product", buf, sizeof(buf)) > 0)
+    return buf;
+  return "unknown";
+}
+
+static boost::property_tree::ptree
+glibc_info()
+{
+  boost::property_tree::ptree pt;
+  pt.put("name", "FreeBSD libc");
+  pt.put("version", std::to_string(__FreeBSD_version));
+  return pt;
+}
+
+static std::string
+processor_name()
+{
+  char buf[256];
+  size_t len = sizeof(buf);
+  if (::sysctlbyname("hw.model", buf, &len, nullptr, 0) == 0)
+    return std::string(buf);
+  return "Unknown";
+}
+#else
 static std::string 
 machine_info()
 {
@@ -70,6 +105,7 @@ processor_name()
   }
   return model_name;
 }
+#endif
 } //end anonymous namespace
 
 
