#ifndef LOGS_H
#define LOGS_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include "global.h"


#define LOG_BUF_SIZE 1024

void file_changed_callback(GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event_type, gpointer user_data);
void createLogLink();

#endif // LOGS_H


