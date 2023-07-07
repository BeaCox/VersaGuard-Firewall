#ifndef UTILS_H
#define UTILS_H

#include <gtk/gtk.h>

// 检查冲突功能
GtkTreePath *checkConflict(GtkListStore *liststore, gchar *protocol, gchar *srcip, gchar *dstip, gchar *srcport, gchar *dstport, gchar *stime, gchar *etime, GtkTreePath *path);
// 搜索功能
void on_search_entry_search_changed(GtkSearchEntry *searchentry, gpointer data);
#endif // UTILS_H
