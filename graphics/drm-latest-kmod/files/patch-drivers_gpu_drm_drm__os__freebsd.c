--- drivers/gpu/drm/drm_os_freebsd.c.orig	2026-09-07 21:18:34 UTC
+++ drivers/gpu/drm/drm_os_freebsd.c
@@ -126,8 +126,10 @@ drm_dev_alias(struct device *ldev, struct drm_minor *m
 	struct linux_cdev *cdevp;
 	struct sysctl_oid *node;
 	device_t dev = ldev->parent->bsddev;
+	struct cdev *alias;
 	char buf[32];
 	u32 tmp;
+	int error;
 
 	MPASS(dev != NULL);
 	ctx_list = device_get_sysctl_ctx(dev);
@@ -151,7 +153,14 @@ drm_dev_alias(struct device *ldev, struct drm_minor *m
 	if (cdevp == NULL)
 		return (-ENXIO);
 	minor->bsd_device = cdevp->cdev;
-	make_dev_alias(cdevp->cdev, buf, minor->index);
+	/*
+	 * The alias is never destroyed, so it already exists when a driver
+	 * attaches again on this minor; it still names the same cdev.
+	 */
+	error = make_dev_alias_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK, &alias,
+	    cdevp->cdev, buf, minor->index);
+	if (error != 0 && error != EEXIST)
+		return (-error);
 	reset_debug_log();
 	return (0);
 }
