--- src/runtime_src/core/pcie/linux/shim.cpp.orig	2026-11-10 18:38:00 UTC
+++ src/runtime_src/core/pcie/linux/shim.cpp
@@ -88,6 +88,33 @@ inline unsigned numClocks(const std::string& name)
     return name.compare(0, 15, "xilinx_adm-pcie", 15) ? 2 : 1;
 }
 
+#ifdef __FreeBSD__
+// No Linux native AIO: the Alveo QDMA queues fall back to synchronous I/O.
+inline int io_setup(unsigned, aio_context_t *)
+{
+  errno = ENOSYS;
+  return -1;
+}
+
+inline int io_destroy(aio_context_t)
+{
+  errno = ENOSYS;
+  return -1;
+}
+
+inline int io_submit(aio_context_t, long, struct iocb **)
+{
+  errno = ENOSYS;
+  return -1;
+}
+
+inline int io_getevents(aio_context_t, long, long, struct io_event *,
+                        struct timespec *)
+{
+  errno = ENOSYS;
+  return -1;
+}
+#else
 inline int io_setup(unsigned nr, aio_context_t *ctxp)
 {
   return syscall(__NR_io_setup, nr, ctxp);
@@ -108,6 +135,7 @@ inline int io_getevents(aio_context_t ctx, long min_nr
 {
   return syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
 }
+#endif
 
 static
 xocl::shim*
