--- zebra/interface.c.orig	2022-03-13 15:59:48 UTC
+++ zebra/interface.c
@@ -769,9 +769,10 @@ static void if_delete_connected(struct interface *ifp)
 }
 
 /* Handle an interface delete event */
-void if_delete_update(struct interface *ifp)
+void if_delete_update(struct interface **pifp)
 {
 	struct zebra_if *zif;
+	struct interface *ifp = *pifp;
 
 	if (if_is_up(ifp)) {
 		flog_err(
@@ -834,7 +835,7 @@ void if_delete_update(struct interface *ifp)
 		if (IS_ZEBRA_DEBUG_KERNEL)
 			zlog_debug("interface %s is being deleted from the system",
 				   ifp->name);
-		if_delete(&ifp);
+		if_delete(pifp);
 	}
 }
 
