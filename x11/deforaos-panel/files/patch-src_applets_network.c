--- src/applets/network.c.orig	2022-08-17 21:14:26 UTC
+++ src/applets/network.c
@@ -24,11 +24,11 @@
 #endif
 #include <string.h>
 #include <errno.h>
+#include <libintl.h>
+#include <net/if.h>
 #if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
 # include <ifaddrs.h>
 #endif
-#include <libintl.h>
-#include <net/if.h>
 #include <System.h>
 #include "Panel/applet.h"
 #define _(string) gettext(string)
@@ -296,7 +296,14 @@ static void _refresh_interface_flags(Network * network
 	gboolean active = TRUE;
 	char const * icon = "network-offline";
 #ifdef SIOCGIFDATA
+# if defined(__NetBSD__)
 	struct ifdatareq ifdr;
+	struct if_data * pifdr = &ifdr.ifdr_data;
+# else
+	struct ifreq ifdr;
+	struct if_data ifd;
+	struct if_data * pifdr = &ifd;
+# endif
 # if GTK_CHECK_VERSION(2, 12, 0)
 	unsigned long ibytes;
 	unsigned long obytes;
@@ -313,42 +320,43 @@ static void _refresh_interface_flags(Network * network
 #ifdef SIOCGIFDATA
 		/* XXX ignore errors */
 		memset(&ifdr, 0, sizeof(ifdr));
+# if defined(__NetBSD__)
 		strncpy(ifdr.ifdr_name, ni->name, sizeof(ifdr.ifdr_name));
+# else
+		strncpy(ifdr.ifr_name, ni->name, sizeof(ifdr.ifr_name));
+		ifdr.ifr_data = (caddr_t)pifdr;
+# endif
 		if(ioctl(network->fd, SIOCGIFDATA, &ifdr) == -1)
 			network->helper->error(NULL, "SIOCGIFDATA", 1);
 		else
 		{
-			if(ifdr.ifdr_data.ifi_ipackets > ni->ipackets)
-				icon = (ifdr.ifdr_data.ifi_opackets
-						> ni->opackets)
+			if(pifdr->ifi_ipackets > ni->ipackets)
+				icon = (pifdr->ifi_opackets > ni->opackets)
 					? "network-transmit-receive"
 					: "network-receive";
-			else if(ifdr.ifdr_data.ifi_opackets > ni->opackets)
+			else if(pifdr->ifi_opackets > ni->opackets)
 				icon = "network-transmit";
 # ifdef LINK_STATE_DOWN
-			else if(ifdr.ifdr_data.ifi_link_state
-					== LINK_STATE_DOWN)
+			else if(pifdr->ifi_link_state == LINK_STATE_DOWN)
 				icon = "network-offline";
 # endif
 			else
 				icon = "network-idle";
 # if GTK_CHECK_VERSION(2, 12, 0)
-			ibytes = (ifdr.ifdr_data.ifi_ibytes >= ni->ibytes)
-				? ifdr.ifdr_data.ifi_ibytes - ni->ibytes
-				: ULONG_MAX - ni->ibytes
-				+ ifdr.ifdr_data.ifi_ibytes;
-			obytes = (ifdr.ifdr_data.ifi_obytes >= ni->obytes)
-				? ifdr.ifdr_data.ifi_obytes - ni->obytes
-				: ULONG_MAX - ni->obytes
-				+ ifdr.ifdr_data.ifi_obytes;
+			ibytes = (pifdr->ifi_ibytes >= ni->ibytes)
+				? pifdr->ifi_ibytes - ni->ibytes
+				: ULONG_MAX - ni->ibytes + pifdr->ifi_ibytes;
+			obytes = (pifdr->ifi_obytes >= ni->obytes)
+				? pifdr->ifi_obytes - ni->obytes
+				: ULONG_MAX - ni->obytes + pifdr->ifi_obytes;
 			snprintf(tooltip, sizeof(tooltip),
 					_("%s\nIn: %lu kB/s\nOut: %lu kB/s"),
 					ni->name, ibytes / 512, obytes / 512);
 # endif
-			ni->ipackets = ifdr.ifdr_data.ifi_ipackets;
-			ni->opackets = ifdr.ifdr_data.ifi_opackets;
-			ni->ibytes = ifdr.ifdr_data.ifi_ibytes;
-			ni->obytes = ifdr.ifdr_data.ifi_obytes;
+			ni->ipackets = pifdr->ifi_ipackets;
+			ni->opackets = pifdr->ifi_opackets;
+			ni->ibytes = pifdr->ifi_ibytes;
+			ni->obytes = pifdr->ifi_obytes;
 		}
 #endif
 	}
