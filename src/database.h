#ifndef DATABASE_H
#define DATABASE_H

#include <gtk/gtk.h>
#include <sqlite3.h>

int initDatabase();
void insertData(const char *protocol, const char *source, const char *destination);
void showData(GtkListStore *liststore);

#endif /* DATABASE_H */
