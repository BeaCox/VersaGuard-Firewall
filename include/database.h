#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <gtk/gtk.h>
#include <unistd.h>
#include "utils.h"

// 应用的数据库放在`~/.config/VersaGuard`下
#define APP_DIR ".config/VersaGuard"
#define APP_DB "rules.db"

// 设备文件路径
#define DEVICE_FILE "/dev/firewall"


// 初始化数据库
int initDatabase();
// 关闭数据库
void closeDatabase();
// 插入一条数据
gboolean insertData(const char *protocol, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks);
// 导入数据
int importData(const char *filename, GtkListStore *liststore);
// 导出数据
int exportData(const char *filename, GtkTreeView *data);
// 删除数据
int deleteData(int id);
// 更新数据
gboolean updateData(int id, const char *protocol, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks);
// 在应用中刷新数据
gboolean showData(GtkListStore *liststore);
// 全部写入设备文件（删除和编辑用）
gboolean writeDataToDeviceFile();
// 追加到设备文件（添加和导入用）
gboolean appendDataToDeviceFile(const char *protocol, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action);
// 检查权限功能
gboolean checkPermission();
#endif  // DATABASE_H


