#ifndef UTILS_H
#define UTILS_H

#include <gtk/gtk.h>

// 检查冲突功能
GtkTreePath *checkConflict(GtkListStore *liststore, gchar *protocol, gchar *srcip, gchar *dstip, gchar *srcport, gchar *dstport, gchar *stime, gchar *etime, GtkTreePath *path);

#endif // UTILS_H