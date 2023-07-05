#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <gtk/gtk.h>


int initDatabase();
void closeDatabase();
gboolean insertData(const char *protocol, const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks);
int importData(const char *filename);
int exportData(const char *filename, GtkTreeView *data);
int deleteData(int id);
gboolean updateData(int id, const char *protocol, const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks);
gboolean showData(GtkListStore *liststore);

#endif  // DATABASE_H


