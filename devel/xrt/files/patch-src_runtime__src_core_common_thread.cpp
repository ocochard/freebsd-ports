--- src/runtime_src/core/common/thread.cpp.orig	2026-11-10 18:38:00 UTC
+++ src/runtime_src/core/common/thread.cpp
@@ -25,8 +25,11 @@
 #include <boost/algorithm/string/trim.hpp>
 #include <boost/tokenizer.hpp>
 
-#ifdef __linux__
+#if ((((defined(__linux__) || defined(__FreeBSD__)) || defined(__FreeBSD__)) || defined(__FreeBSD__)) || defined(__FreeBSD__)) || defined(__FreeBSD__)
 # include <pthread.h>
+# ifdef __FreeBSD__
+#  include <pthread_np.h>
+# endif
 # include <sched.h>
 #endif
 
@@ -34,7 +37,7 @@ namespace platform_specific {
 
 namespace platform_specific {
 
-#ifdef __linux__
+#if ((((defined(__linux__) || defined(__FreeBSD__)) || defined(__FreeBSD__)) || defined(__FreeBSD__)) || defined(__FreeBSD__)) || defined(__FreeBSD__)
 
 static void
 debug_thread_policy(const std::string& str, int policy, int priority)
