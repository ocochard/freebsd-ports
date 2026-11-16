--- src/runtime_src/core/pcie/linux/pcidrv.h.orig	2026-11-10 18:38:00 UTC
+++ src/runtime_src/core/pcie/linux/pcidrv.h
@@ -6,6 +6,100 @@
 
 #include "pcidev.h"
 
+#ifdef __FreeBSD__
+#include <sys/types.h>
+#include <sys/sysctl.h>
+#include <cstdio>
+#include <string>
+#include <utility>
+#include <vector>
+
+// FreeBSD has no sysfs.  A device bound to driver <drv> is the newbus
+// device dev.<drv>.<unit>: its PCI location is in dev.<drv>.<unit>.%location
+// and its IDs in %pnpinfo.  LinuxKPI publishes the driver's sysfs
+// attributes as sys.device.<drv><unit>.<attr>.  The unit is also the
+// device node number (/dev/<dir>/<prefix><unit>).
+namespace xrt_core { namespace pci { namespace freebsd {
+
+inline bool
+sysctl_str(const std::string& name, std::string& out)
+{
+  size_t len = 0;
+  if (::sysctlbyname(name.c_str(), nullptr, &len, nullptr, 0) != 0)
+    return false;
+  std::vector<char> buf(len + 1, '\0');
+  if (::sysctlbyname(name.c_str(), buf.data(), &len, nullptr, 0) != 0)
+    return false;
+  out.assign(buf.data());
+  while (!out.empty() && (out.back() == '\n' || out.back() == ' '))
+    out.pop_back();
+  return true;
+}
+
+inline bool
+unit_bdf(const std::string& drv, int unit, std::string& bdf)
+{
+  std::string loc;
+  if (!sysctl_str("dev." + drv + "." + std::to_string(unit) + ".%location", loc))
+    return false;
+  auto pos = loc.find("dbsf=pci");
+  unsigned int d, b, s, f;
+  if (pos == std::string::npos ||
+      std::sscanf(loc.c_str() + pos, "dbsf=pci%u:%u:%u:%u", &d, &b, &s, &f) != 4)
+    return false;
+  char name[32];
+  std::snprintf(name, sizeof(name), "%04x:%02x:%02x.%x", d, b, s, f);
+  bdf = name;
+  return true;
+}
+
+inline int
+unit_of(const std::string& drv, const std::string& bdf)
+{
+  std::string b;
+  for (int unit = 0, miss = 0; miss < 8; unit++) {
+    if (!unit_bdf(drv, unit, b)) {
+      miss++;
+      continue;
+    }
+    miss = 0;
+    if (b == bdf)
+      return unit;
+  }
+  return -1;
+}
+
+inline bool
+attr(const std::string& drv, const std::string& bdf,
+     const std::string& subdev, const std::string& entry, std::string& out)
+{
+  static const std::pair<const char*, const char*> pnp[] = {
+    { "vendor", "vendor=" }, { "device", "device=" },
+    { "subsystem_vendor", "subvendor=" }, { "subsystem_device", "subdevice=" },
+  };
+  int unit;
+
+  if (!subdev.empty() || (unit = unit_of(drv, bdf)) < 0)
+    return false;
+  for (const auto& [file, key] : pnp) {
+    if (entry != file)
+      continue;
+    std::string info;
+    if (!sysctl_str("dev." + drv + "." + std::to_string(unit) + ".%pnpinfo", info))
+      return false;
+    auto pos = info.find(key);
+    if (pos == std::string::npos)
+      return false;
+    pos += std::string(key).size();
+    out = info.substr(pos, info.find(' ', pos) - pos);
+    return true;
+  }
+  return sysctl_str("sys.device." + drv + std::to_string(unit) + "." + entry, out);
+}
+
+} } } // namespace xrt_core :: pci :: freebsd
+#endif
+
 namespace xrt_core { namespace pci {
 
 class drv : public std::enable_shared_from_this<drv>
