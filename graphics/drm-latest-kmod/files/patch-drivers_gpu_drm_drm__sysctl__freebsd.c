--- drivers/gpu/drm/drm_sysctl_freebsd.c.orig	2026-09-07 21:18:34 UTC
+++ drivers/gpu/drm/drm_sysctl_freebsd.c
@@ -43,6 +43,7 @@ SYSCTL_DECL(_hw_drm);
 	   struct sysctl_oid *top);
 
 SYSCTL_DECL(_hw_drm);
+SYSCTL_DECL(_hw_dri);
 
 #define DRM_SYSCTL_HANDLER_ARGS	(SYSCTL_HANDLER_ARGS)
 
@@ -79,14 +80,12 @@ drm_sysctl_init(struct drm_device *dev)
 	info = malloc(sizeof *info, DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
 	dev->sysctl = info;
 
-	/* Add the sysctl node for DRI if it doesn't already exist */
-	drioid = SYSCTL_ADD_NODE(&info->ctx, SYSCTL_CHILDREN(&sysctl___hw), OID_AUTO,
-	    "dri", CTLFLAG_RW, NULL, "DRI Graphics");
-	if (!drioid) {
-		free(dev->sysctl, DRM_MEM_DRIVER);
-		dev->sysctl = NULL;
-		return (-ENOMEM);
-	}
+	/*
+	 * hw.dri is static (drm_os_freebsd.c).  It must not join the device
+	 * context: sysctl_ctx_free() refuses to remove a static node and then
+	 * removes nothing, leaving hw.dri.N pointing at the freed device.
+	 */
+	drioid = &sysctl___hw_dri;
 
 	/* Find the next free slot under hw.dri */
 	i = 0;
