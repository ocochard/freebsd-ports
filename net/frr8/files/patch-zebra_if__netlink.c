--- zebra/if_netlink.c.orig	2022-03-25 23:15:44 UTC
+++ zebra/if_netlink.c
@@ -101,7 +101,7 @@ static void set_ifindex(struct interface *ifp, ifindex
 					EC_LIB_INTERFACE,
 					"interface rename detected on up interface: index %d was renamed from %s to %s, results are uncertain!",
 					ifi_index, oifp->name, ifp->name);
-			if_delete_update(oifp);
+			if_delete_update(&oifp);
 		}
 	}
 	if_set_index(ifp, ifi_index);
@@ -2031,7 +2031,7 @@ int netlink_link_change(struct nlmsghdr *h, ns_id_t ns
 		else if (IS_ZEBRA_IF_VXLAN(ifp))
 			zebra_l2_vxlanif_del(ifp);
 
-		if_delete_update(ifp);
+		if_delete_update(&ifp);
 
 		/* If VRF, delete the VRF structure itself. */
 		if (zif_type == ZEBRA_IF_VRF && !vrf_is_backend_netns())
