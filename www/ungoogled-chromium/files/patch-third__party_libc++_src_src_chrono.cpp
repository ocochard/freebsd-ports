--- third_party/libc++/src/src/chrono.cpp.orig	2024-02-03 15:42:55 UTC
+++ third_party/libc++/src/src/chrono.cpp
@@ -31,7 +31,7 @@
 # include <sys/time.h> // for gettimeofday and timeval
 #endif
 
-#if defined(__APPLE__) || defined (__gnu_hurd__) || (defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0)
+#if defined(__APPLE__) || defined (__gnu_hurd__) || (defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0) || defined(__OpenBSD__)
 # define _LIBCPP_HAS_CLOCK_GETTIME
 #endif
 
