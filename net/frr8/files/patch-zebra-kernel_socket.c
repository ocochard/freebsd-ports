--- zebra/kernel_socket.c.orig	2022-03-14 00:59:48.000000000 +0900
+++ zebra/kernel_socket.c	2022-03-30 11:56:55.549158000 +0900
@@ -442,20 +442,16 @@
 				"%s: creating interface for ifindex %d, name %s",
 				__func__, ifan->ifan_index, ifan->ifan_name);
 
-		/* Create Interface */
-		ifp = if_get_by_name(ifan->ifan_name, VRF_DEFAULT,
-				     VRF_DEFAULT_NAME);
-		if_set_index(ifp, ifan->ifan_index);
-
-		if_get_metric(ifp);
-		if_add_update(ifp);
+		/*
+		 * interface_list() creates the arrived interface:
+		 * if_sysctl.c: ifm_read() (i.e. RTM_IFINFO from
+		 *   the sysctl interface) calls if_add_update().
+		 * if_ioctl.c: interface_list_ioctl() calls if_add_update().
+		 */
+		interface_list(NULL, ifan->ifan_index);
 	} else if (ifp != NULL && ifan->ifan_what == IFAN_DEPARTURE)
 		if_delete_update(ifp);
 
-	if_get_flags(ifp);
-	if_get_mtu(ifp);
-	if_get_metric(ifp);
-
 	if (IS_ZEBRA_DEBUG_KERNEL)
 		zlog_debug("%s: interface %s index %d", __func__,
 			   ifan->ifan_name, ifan->ifan_index);
@@ -1350,12 +1346,12 @@
 			flog_err(EC_ZEBRA_RECVMSG_OVERRUN,
 				 "routing socket overrun: %s",
 				 safe_strerror(errno));
-			/*
-			 *  In this case we are screwed.
-			 *  There is no good way to
-			 *  recover zebra at this point.
+			/* XXX:
+			 * ENOBUFS indicates a temporary resource
+			 * shortage and is not harmful for consistency of
+			 * reading the routing socket.  Ignore it.
 			 */
-			exit(-1);
+			return 0;
 		}
 		if (errno != EAGAIN && errno != EWOULDBLOCK)
 			flog_err_sys(EC_LIB_SOCKET, "routing socket error: %s",
