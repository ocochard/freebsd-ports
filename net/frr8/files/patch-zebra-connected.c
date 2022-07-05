--- zebra/connected.c.orig	2022-03-14 00:59:48.000000000 +0900
+++ zebra/connected.c	2022-03-30 11:44:27.322751000 +0900
@@ -123,6 +123,9 @@
 			continue;
 		if (!CONNECTED_PEER(ifc) && !d)
 			return ifc;
+		/* XXX: an alias with the same prefixlen has non-NULL d. */
+		if (!CONNECTED_PEER(ifc))
+			return ifc;
 		if (CONNECTED_PEER(ifc) && d
 		    && prefix_same(ifc->destination, d))
 			return ifc;
