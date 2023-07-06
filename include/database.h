#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <gtk/gtk.h>
#include "utils.h"


int initDatabase();
void closeDatabase();
gboolean insertData(const char *protocol, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks);
int importData(const char *filename, GtkListStore *liststore);
int exportData(const char *filename, GtkTreeView *data);
int deleteData(int id);
gboolean updateData(int id, const char *protocol, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks);
gboolean showData(GtkListStore *liststore);

#endif  // DATABASE_H


