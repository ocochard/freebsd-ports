--- src/xdna-driver/src/shim/device.cpp.orig	2026-11-14 04:56:45 UTC
+++ src/xdna-driver/src/shim/device.cpp
@@ -2729,6 +2729,10 @@ import_fd(pid_t pid, int ehdl)
   if (pid == 0 || getpid() == pid)
     return ehdl;
 
+#ifdef __FreeBSD__
+  // No pidfd_getfd(): a BO cannot be imported from another process.
+  throw xrt_core::system_error(ENOTSUP, "importing a BO from another process");
+#else
   auto pidfd = syscall(SYS_pidfd_open, pid, 0);
   if (pidfd < 0)
     throw xrt_core::system_error(errno, "pidfd_open failed");
@@ -2745,6 +2749,7 @@ import_fd(pid_t pid, int ehdl)
     }
   }
   return fd;
+#endif
 }
 
 }
