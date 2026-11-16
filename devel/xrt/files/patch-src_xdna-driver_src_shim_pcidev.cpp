--- src/xdna-driver/src/shim/pcidev.cpp.orig	2026-11-14 04:56:45 UTC
+++ src/xdna-driver/src/shim/pcidev.cpp
@@ -266,7 +266,12 @@ namespace {
 #if defined(__x86_64__) || defined(_M_X64)
 namespace {
 
+#ifdef __FreeBSD__
+// No _SC_LEVEL1_DCACHE_LINESIZE; every x86-64 CPU uses 64-byte lines.
+const long cacheline_size = 64;
+#else
 const long cacheline_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
+#endif
 
 void
 clflush_data(const void *base, size_t offset, size_t len)
