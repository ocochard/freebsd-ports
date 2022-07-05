--- zebra/if_sysctl.c.orig	2022-03-14 00:59:48.000000000 +0900
+++ zebra/if_sysctl.c	2022-03-30 11:45:07.371719000 +0900
@@ -85,7 +85,7 @@
 }
 
 /* Interface listing up function using sysctl(). */
-void interface_list(struct zebra_ns *zns)
+void interface_list(struct zebra_ns *zns, int ifindex)
 {
 	caddr_t ref, buf, end;
 	size_t bufsiz;
@@ -94,8 +94,10 @@
 #define MIBSIZ 6
 	int mib[MIBSIZ] = {
 		CTL_NET,       PF_ROUTE, 0, 0, /*  AF_INET & AF_INET6 */
-		NET_RT_IFLIST, 0};
+		NET_RT_IFLIST, ifindex};
 
+	if (zns == NULL)
+		zns = ns_get_default();
 	if (zns->ns_id != NS_DEFAULT) {
 		zlog_debug("interface_list: ignore NS %u", zns->ns_id);
 		return;
