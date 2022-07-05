--- zebra/zebra_ns.c.orig	2022-03-14 00:59:48.000000000 +0900
+++ zebra/zebra_ns.c	2022-03-30 11:44:27.327886000 +0900
@@ -124,7 +124,7 @@
 
 	kernel_init(zns);
 	zebra_dplane_ns_enable(zns, true);
-	interface_list(zns);
+	interface_list(zns, 0);
 	route_read(zns);
 	kernel_read_pbr_rules(zns);
 
