--- util.c.orig	2017-01-15 08:26:45 UTC
+++ util.c
@@ -40,7 +40,7 @@
 #define	MAXBUFSZ	(BUFSZ * 1024)
 
 int
-dprintf(const char *fmt, ...)
+ddprintf(const char *fmt, ...)
 {
 	char tmp[MAXBUFSZ];
 	int expired, len;
