#ifndef UTILS_H
#define UTILS_H

#include "global.h"

// 检查冲突功能
GtkTreePath *checkConflict(GtkListStore *liststore, gchar *protocol, gchar *interface, gchar *srcip, gchar *dstip, gchar *srcport, gchar *dstport, gchar *stime, gchar *etime, GtkTreePath *path);
// 搜索功能
void on_search_entry_search_changed(GtkSearchEntry *searchentry, gpointer data);
// 检查设备文件权限功能
gboolean checkPermission();
// 检查内核模块是否加载功能，未加载则尝试从本地加载，失败则提示用户
gboolean checkModule();
#endif // UTILS_H

