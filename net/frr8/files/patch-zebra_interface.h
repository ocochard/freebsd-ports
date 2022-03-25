--- zebra/interface.h.orig	2022-03-25 11:53:13 UTC
+++ zebra/interface.h
@@ -474,7 +474,7 @@ extern void if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(stru
 						 struct in6_addr *address,
 						 int add);
 extern void if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(struct interface *ifp);
-extern void if_delete_update(struct interface *ifp);
+extern void if_delete_update(struct interface **ifp);
 extern void if_add_update(struct interface *ifp);
 extern void if_up(struct interface *);
 extern void if_down(struct interface *);
