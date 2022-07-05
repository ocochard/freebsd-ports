--- zebra/if_ioctl.c.orig	2022-03-14 00:59:48.000000000 +0900
+++ zebra/if_ioctl.c	2022-03-30 11:44:27.323659000 +0900
@@ -287,7 +287,7 @@
 }
 
 /* Lookup all interface information. */
-void interface_list(struct zebra_ns *zns)
+void interface_list(struct zebra_ns *zns, __attribute__((unused)) int ifindex)
 {
 
 	zlog_info("interface_list: NS %u", zns->ns_id);
