#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include "utils.h"


// 初始化数据库
int initDatabase();
// 关闭数据库
void closeDatabase();
// 插入一条数据
gboolean insertData(const char *protocol, const char *interface, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks);
// 导入数据
int importData(const char *filename, GtkListStore *liststore);
// 导出数据
int exportData(const char *filename, GtkTreeView *data);
// 删除数据
gboolean deleteData(int id);
// 更新数据
gboolean updateData(int id, const char *protocol, const char *interface, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks);
// 在应用中刷新数据
gboolean showData(GtkListStore *liststore);
// 全部写入设备文件（删除和编辑用）
gboolean writeDataToDeviceFile();
// 追加到设备文件（添加和导入用）
// gboolean appendDataToDeviceFile(const char *protocol, const char *interface, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action);
#endif  // DATABASE_H



