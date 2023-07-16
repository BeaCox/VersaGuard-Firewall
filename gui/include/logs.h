#ifndef LOGS_H
#define LOGS_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include "global.h"

// 用来显示LOG文件新一行的字符串最大大小
#define LOG_BUF_SIZE 1024

// LOG文件发生变化的回调函数
void file_changed_callback(GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event_type, gpointer user_data);
// 建立LOG文件的软连接
void createLogLink();
// LOG搜索框
void on_log_searchentry_search_changed(GtkSearchEntry *search_entry, gpointer user_data);
// 切换搜索结果
gboolean on_log_searchentry_key_press_event(GtkWidget *widget, GdkEventKey *event, gpointer user_data);

#endif // LOGS_H



