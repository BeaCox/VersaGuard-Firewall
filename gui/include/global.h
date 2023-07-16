#ifndef GLOBAL_H
#define GLOBAL_H

#include <gtk/gtk.h>

// 应用的数据库放在`~/.config/VersaGuard`下
#define APP_DIR ".config/VersaGuard"
#define APP_DB "rules.db"

// 设备文件路径
#define DEVICE_FILE "/dev/firewall"

// 日志文件路径
#define LOG_DIR "/var/log"
#define LOG_FILE "VersaGuard.log"

// 内核模块名称
#define MODULE_NAME "VersaGuard_core"

// 应用的版本号
#define APP_VERSION "v1.0.0"

#endif // GLOBAL_H

