#ifndef LOGS_H
#define LOGS_H

#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <pthread.h>
#include "global.h"

#define LOG_BUF_SIZE 1024


void *watchLog(void *data);
// void on_log_searchentry_search_changed(GtkSearchEntry *searchentry, gpointer data)
void createLogLink();

#endif // LOGS_H

