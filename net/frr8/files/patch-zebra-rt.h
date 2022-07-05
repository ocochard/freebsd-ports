--- zebra/rt.h.orig	2022-03-14 00:59:48.000000000 +0900
+++ zebra/rt.h	2022-03-30 11:44:27.327180000 +0900
@@ -85,7 +85,7 @@
  * Southbound Initialization routines to get initial starting
  * state.
  */
-extern void interface_list(struct zebra_ns *zns);
+extern void interface_list(struct zebra_ns *zns, int);
 extern void kernel_init(struct zebra_ns *zns);
 extern void kernel_terminate(struct zebra_ns *zns, bool complete);
 extern void macfdb_read(struct zebra_ns *zns);
