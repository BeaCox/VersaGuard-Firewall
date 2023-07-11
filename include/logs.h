#ifndef LOGS_H
#define LOGS_H

#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <pthread.h>

void *watchLog(void *data);
// void on_log_searchentry_search_changed(GtkSearchEntry *searchentry, gpointer data)

#endif // LOGS_H
