--- zebra/if_netlink.c.orig	2022-03-14 00:59:48.000000000 +0900
+++ zebra/if_netlink.c	2022-03-30 11:44:27.324771000 +0900
@@ -2068,7 +2068,7 @@
 }
 
 /* Interface information read by netlink. */
-void interface_list(struct zebra_ns *zns)
+void interface_list(struct zebra_ns *zns, __attribute__((unused)) int ifindex)
 {
 	interface_lookup_netlink(zns);
 	/* We add routes for interface address,
