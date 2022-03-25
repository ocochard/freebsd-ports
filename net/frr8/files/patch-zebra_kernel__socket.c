--- zebra/kernel_socket.c.orig	2022-03-13 15:59:48 UTC
+++ zebra/kernel_socket.c
@@ -159,6 +159,9 @@ const struct message rtm_type_str[] = {{RTM_ADD, "RTM_
 #ifdef RTM_IFANNOUNCE
 				       {RTM_IFANNOUNCE, "RTM_IFANNOUNCE"},
 #endif /* RTM_IFANNOUNCE */
+#ifdef RTM_IEEE80211
+						{RTM_IEEE80211, "RTM_IEEE80211"},
+#endif
 				       {0}};
 
 static const struct message rtm_flag_str[] = {{RTF_UP, "UP"},
@@ -450,12 +453,13 @@ static int ifan_read(struct if_announcemsghdr *ifan)
 		if_get_metric(ifp);
 		if_add_update(ifp);
 	} else if (ifp != NULL && ifan->ifan_what == IFAN_DEPARTURE)
-		if_delete_update(ifp);
+		if_delete_update(&ifp);
+		if (ifp) {
+			if_get_flags(ifp);
+			if_get_mtu(ifp);
+			if_get_metric(ifp);
+		}
 
-	if_get_flags(ifp);
-	if_get_mtu(ifp);
-	if_get_metric(ifp);
-
 	if (IS_ZEBRA_DEBUG_KERNEL)
 		zlog_debug("%s: interface %s index %d", __func__,
 			   ifan->ifan_name, ifan->ifan_index);
@@ -722,10 +726,10 @@ int ifm_read(struct if_msghdr *ifm)
 			 * will still behave correctly if run on a platform
 			 * without
 			 */
-			if_delete_update(ifp);
+			if_delete_update(&ifp);
 		}
 #endif /* RTM_IFANNOUNCE */
-		if (if_is_up(ifp)) {
+		if (ifp && if_is_up(ifp)) {
 #if defined(__bsdi__)
 			if_kvm_get_mtu(ifp);
 #else
@@ -734,15 +738,16 @@ int ifm_read(struct if_msghdr *ifm)
 			if_get_metric(ifp);
 		}
 	}
-
+	if (ifp) {
 #ifdef HAVE_NET_RT_IFLIST
-	ifp->stats = ifm->ifm_data;
+		ifp->stats = ifm->ifm_data;
 #endif /* HAVE_NET_RT_IFLIST */
-	ifp->speed = ifm->ifm_data.ifi_baudrate / 1000000;
+		ifp->speed = ifm->ifm_data.ifi_baudrate / 1000000;
 
-	if (IS_ZEBRA_DEBUG_KERNEL)
-		zlog_debug("%s: interface %s index %d", __func__, ifp->name,
-			   ifp->ifindex);
+		if (IS_ZEBRA_DEBUG_KERNEL)
+			zlog_debug("%s: interface %s index %d", __func__, ifp->name,
+				   ifp->ifindex);
+	}
 
 	return 0;
 }
@@ -1404,7 +1409,10 @@ static int kernel_read(struct thread *thread)
 #endif /* RTM_IFANNOUNCE */
 	default:
 		if (IS_ZEBRA_DEBUG_KERNEL)
-			zlog_debug("Unprocessed RTM_type: %d", rtm->rtm_type);
+			zlog_debug(
+				"Unprocessed RTM_type: %s(%d)",
+				lookup_msg(rtm_type_str, rtm->rtm_type, NULL),
+				rtm->rtm_type);
 		break;
 	}
 	return 0;
