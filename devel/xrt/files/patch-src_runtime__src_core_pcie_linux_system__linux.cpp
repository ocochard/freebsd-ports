--- src/runtime_src/core/pcie/linux/system_linux.cpp.orig	2026-11-10 18:38:00 UTC
+++ src/runtime_src/core/pcie/linux/system_linux.cpp
@@ -15,7 +15,11 @@
 #include <boost/algorithm/string/predicate.hpp>
 #include <boost/format.hpp>
 #include <boost/property_tree/ini_parser.hpp>
+#ifdef __FreeBSD__
+#include <sys/param.h>
+#else
 #include <gnu/libc-version.h>
+#endif
 #include <sys/utsname.h>
 
 // Local - Include files
