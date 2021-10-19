--- util.h.orig	2017-01-15 08:26:49 UTC
+++ util.h
@@ -26,11 +26,11 @@
  */
 
 #define	BUFSZ		256
-#define	DPRINTF(_fmt, args...)		if (verbose) dprintf(_fmt, ## args)
+#define	DPRINTF(_fmt, args...)		if (verbose) ddprintf(_fmt, ## args)
 
 extern int verbose;
 
-int dprintf(const char *, ...);
+int ddprintf(const char *, ...);
 int printf_buf(char **, int *, int *, const char *, ...);
 void printb(char **, int *, int *, const char *, unsigned, const char *);
 int pidfile_create(const char *);
