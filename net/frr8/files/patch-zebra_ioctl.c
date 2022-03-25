--- zebra/ioctl.c.orig	2022-03-24 17:14:56 UTC
+++ zebra/ioctl.c
@@ -136,7 +136,7 @@ void if_get_metric(struct interface *ifp)
 void if_get_metric(struct interface *ifp)
 {
 #ifdef SIOCGIFMETRIC
-	struct ifreq ifreq;
+	struct ifreq ifreq = {};
 
 	ifreq_set_name(&ifreq, ifp);
 
@@ -153,7 +153,7 @@ void if_get_mtu(struct interface *ifp)
 /* get interface MTU */
 void if_get_mtu(struct interface *ifp)
 {
-	struct ifreq ifreq;
+	struct ifreq ifreq = {};
 
 	ifreq_set_name(&ifreq, ifp);
 
@@ -410,7 +410,7 @@ void if_get_flags(struct interface *ifp)
 void if_get_flags(struct interface *ifp)
 {
 	int ret;
-	struct ifreq ifreq;
+	struct ifreq ifreq = {};
 
 	ifreq_set_name(&ifreq, ifp);
 
