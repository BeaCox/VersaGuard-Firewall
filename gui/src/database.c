#include "database.h"

static sqlite3 *db;

// 初始化数据库并创建表
int initDatabase()
{
    // 获取用户家目录
    const char *homeDir = g_get_home_dir();
    // 构建数据库目录路径
    char dbDirPath[256];
    snprintf(dbDirPath, sizeof(dbDirPath), "%s/%s", homeDir, APP_DIR);
    if (!g_file_test(dbDirPath, G_FILE_TEST_IS_DIR))
    {
        g_mkdir_with_parents(dbDirPath, 0755);
    }
    // 构建数据库路径
    char dbPath[256];
    snprintf(dbPath, sizeof(dbPath), "%s/%s/%s", homeDir, APP_DIR, APP_DB);
    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK)
    {
        return rc;
    }

    const char *createTableQuery = "CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, protocol TEXT, interface TEXT, src_ip TEXT, dst_ip TEXT, src_port TEXT, dst_port TEXT, start_time TEXT, end_time TEXT, action INTEGER, remarks TEXT);";
    rc = sqlite3_exec(db, createTableQuery, 0, 0, 0);
    if (rc != SQLITE_OK)
    {
        return rc;
    }

    return SQLITE_OK;
}

void closeDatabase()
{
    sqlite3_close(db);
}

gboolean insertData(const char *protocol, const char *interface, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks)
{
    char *errorMsg = 0;
    char insertQuery[256];
    int actionValue = action ? 1 : 0;

    snprintf(insertQuery, sizeof(insertQuery), "INSERT INTO rules (protocol, interface, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, remarks) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, '%s');",
             protocol, interface, src_ip, dst_ip, src_port, dst_port, start_time, end_time, actionValue, remarks);

    // 插入数据到数据库
    int rc = sqlite3_exec(db, insertQuery, 0, 0, &errorMsg);
    if (rc != SQLITE_OK)
    {
        g_warning("插入数据错误: %s", errorMsg);
        sqlite3_free(errorMsg);
        return FALSE;
    }

    return TRUE;
}

int importData(const char *filename, GtkListStore *liststore)
{
    int count = 0;
    sqlite3 *importDb;
    int rc = sqlite3_open(filename, &importDb);
    if (rc != SQLITE_OK)
    {
        return 0;
    }

    sqlite3_stmt *stmt;
    const char *selectQuery = "SELECT * FROM rules;";
    rc = sqlite3_prepare_v2(importDb, selectQuery, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        count++;
        const char *protocol = (const char *)sqlite3_column_text(stmt, 1);
        const char *interface = (const char *)sqlite3_column_text(stmt, 2);
        const char *src_ip = (const char *)sqlite3_column_text(stmt, 3);
        const char *dst_ip = (const char *)sqlite3_column_text(stmt, 4);
        const char *src_port = (const char *)sqlite3_column_text(stmt, 5);
        const char *dst_port = (const char *)sqlite3_column_text(stmt, 6);
        const char *start_time = (const char *)sqlite3_column_text(stmt, 7);
        const char *end_time = (const char *)sqlite3_column_text(stmt, 8);
        gboolean action = sqlite3_column_int(stmt, 9) != 0;
        const char *remarks = (const char *)sqlite3_column_text(stmt, 10);

        if (checkConflict(liststore, (gchar *)protocol, (gchar *)interface, (gchar *)src_ip, (gchar *)dst_ip, (gchar *)src_port, (gchar *)dst_port, (gchar *)start_time, (gchar *)end_time, NULL) || !insertData(protocol, interface, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, remarks))
        {
            count--;
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(importDb);

    // 重新写入设备文件
    if (!writeDataToDeviceFile())
    {
        return FALSE;
    }

    return count;
}

int exportData(const char *filename, GtkTreeView *data)
{
    sqlite3 *exportDb;
    int rc = sqlite3_open(filename, &exportDb);
    // 不允许导出到应用正在使用的数据库（通过比较文件路径判断）
    char dbPath[256];
    snprintf(dbPath, sizeof(dbPath), "%s/%s/%s", g_get_home_dir(), APP_DIR, APP_DB);
    if (rc == SQLITE_OK && strcmp(filename, dbPath) == 0)
    {
        g_warning("不允许导出到应用正在使用的数据库");
        return 0;
    }
    else if (rc != SQLITE_OK)
    {
        g_warning("打开数据库错误: %s", sqlite3_errmsg(exportDb));
        return 0;
    }
    const char *createTableQuery = "CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, protocol TEXT, interface TEXT, src_ip TEXT, dst_ip TEXT, src_port TEXT, dst_port TEXT, start_time TEXT, end_time TEXT, action INTEGER, remarks TEXT);";
    rc = sqlite3_exec(exportDb, createTableQuery, 0, 0, 0);
    if (rc != SQLITE_OK)
    {
        g_warning("创建表错误: %s", sqlite3_errmsg(exportDb));
        return 0;
    }

    GtkTreeModel *model = gtk_tree_view_get_model(data);
    GtkTreeSelection *selection = gtk_tree_view_get_selection(data);
    GList *selectedRows = gtk_tree_selection_get_selected_rows(selection, &model);
    GList *row = selectedRows;
    // 将db暂时设置为exportDb
    sqlite3 *tempDb = db;
    db = exportDb;
    // 记录导出的数据条数
    int count = 0;
    while (row)
    {
        GtkTreePath *path = (GtkTreePath *)(row->data);
        GtkTreeIter iter;
        gtk_tree_model_get_iter(model, &iter, path);

        gchar *protocol;
        gchar *interface;
        gchar *src_ip;
        gchar *dst_ip;
        gchar *src_port;
        gchar *dst_port;
        gchar *start_time;
        gchar *end_time;
        gboolean action;
        gchar *remarks;

        gtk_tree_model_get(model, &iter,
                            1, &protocol,
                            2, &interface,
                            3, &src_ip,
                            4, &dst_ip,
                            5, &src_port,
                            6, &dst_port,
                            7, &start_time,
                            8, &end_time,
                            9, &action,
                            10, &remarks,
                            -1);

        insertData(protocol, interface, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, remarks);

        g_free(protocol);
        g_free(interface);
        g_free(src_ip);
        g_free(dst_ip);
        g_free(start_time);
        g_free(end_time);
        g_free(remarks);

        // 获取下一个选中行的路径
        row = g_list_next(row);
        // 释放当前路径的内存
        gtk_tree_path_free(path);
    }
    count = g_list_length(selectedRows);
    // 释放选中行列表的内存
    g_list_free(selectedRows);

    // 将db设置回原来的db
    db = tempDb;
    // 关闭数据库
    sqlite3_close(exportDb);
    return count;
}

gboolean deleteData(int id)
{
    char *errorMsg = 0;
    char deleteQuery[256];

    snprintf(deleteQuery, sizeof(deleteQuery), "DELETE FROM rules WHERE id = %d;", id);

    // 从数据库中删除数据
    int rc = sqlite3_exec(db, deleteQuery, 0, 0, &errorMsg);
    if (rc != SQLITE_OK)
    {
        g_warning("删除数据错误: %s", errorMsg);
        sqlite3_free(errorMsg);
        return FALSE;
    }
    // 从设备文件中删除数据
    if (!writeDataToDeviceFile())
    {
        return FALSE;
    }

    return TRUE;
}

gboolean updateData(int id, const char *protocol, const char *interface, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks)
{
    char *errorMsg = 0;
    char updateQuery[256];
    int actionValue = action ? 1 : 0;

    snprintf(updateQuery, sizeof(updateQuery), "UPDATE rules SET protocol = '%s', interface= '%s', src_ip = '%s', dst_ip = '%s', src_port = '%s', dst_port = '%s', start_time = '%s', end_time = '%s', action = %d, remarks = '%s' WHERE id = %d;",
             protocol, interface, src_ip, dst_ip, src_port, dst_port, start_time, end_time, actionValue, remarks, id);

    // 从数据库中更新数据
    int rc = sqlite3_exec(db, updateQuery, 0, 0, &errorMsg);
    if (rc != SQLITE_OK)
    {
        g_warning("更新数据错误: %s", errorMsg);
        sqlite3_free(errorMsg);
        return FALSE;
    }
    // 重新写入设备文件
    if (!writeDataToDeviceFile())
    {
        return FALSE;
    }

    return TRUE;
}

gboolean showData(GtkListStore *liststore)
{
    sqlite3_stmt *stmt;
    const char *selectQuery = "SELECT * FROM rules;";
    int rc = sqlite3_prepare_v2(db, selectQuery, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        g_warning("查询数据错误: %s", sqlite3_errmsg(db));
        g_printerr("查询数据错误: %s\n", sqlite3_errmsg(db));
        return FALSE;
    }

    gtk_list_store_clear(liststore);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        int id = sqlite3_column_int(stmt, 0);
        const char *protocol = (const char *)sqlite3_column_text(stmt, 1);
        const char *interface = (const char *)sqlite3_column_text(stmt, 2);
        const char *src_ip = (const char *)sqlite3_column_text(stmt, 3);
        const char *dst_ip = (const char *)sqlite3_column_text(stmt, 4);
        const char *src_port = (const char *)sqlite3_column_text(stmt, 5);
        const char *dst_port = (const char *)sqlite3_column_text(stmt, 6);
        const char *start_time = (const char *)sqlite3_column_text(stmt, 7);
        const char *end_time = (const char *)sqlite3_column_text(stmt, 8);
        gboolean action = sqlite3_column_int(stmt, 9) != 0;
        const char *remarks = (const char *)sqlite3_column_text(stmt, 10);

        GtkTreeIter iter;
        gtk_list_store_append(liststore, &iter);
        gtk_list_store_set(liststore, &iter,
                            0, id,
                            1, protocol,
                            2, interface,
                            3, src_ip,
                            4, dst_ip,
                            5, src_port,
                            6, dst_port,
                            7, start_time,
                            8, end_time,
                            9, action,
                            10, remarks,
                            -1);
    }

    sqlite3_finalize(stmt);

    return TRUE;
}

// 全部写入设备文件（删除和编辑用）
gboolean writeDataToDeviceFile()
{
    sqlite3_stmt *stmt;
    const char *selectQuery = "SELECT * FROM rules;";
    int rc = sqlite3_prepare_v2(db, selectQuery, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        g_warning("查询数据错误: %s", sqlite3_errmsg(db));
        g_printerr("查询数据错误: %s\n", sqlite3_errmsg(db));
        return FALSE;
    }

    FILE *fp = fopen(DEVICE_FILE, "w");
    if (fp == NULL)
    {
        g_warning("打开设备文件错误: %s", strerror(errno));
        g_printerr("打开设备文件错误: %s\n", strerror(errno));
        return FALSE;
    }
    
    // 先删除设备文件中的内容
    ftruncate(fileno(fp), 0);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        gboolean action = sqlite3_column_int(stmt, 9) != 0;
        if(!action) continue;
        // 除了protocol和action，其他都可能为空，若为空则写入占位0
        const char *protocol = (const char *)sqlite3_column_text(stmt, 1);
        const char *interface = (const char *)sqlite3_column_text(stmt, 2);
        const char *src_ip = (const char *)sqlite3_column_text(stmt, 3);
        const char *dst_ip = (const char *)sqlite3_column_text(stmt, 4);
        const char *src_port = (const char *)sqlite3_column_text(stmt, 5);
        const char *dst_port = (const char *)sqlite3_column_text(stmt, 6);
        const char *start_time = (const char *)sqlite3_column_text(stmt, 7);
        const char *end_time = (const char *)sqlite3_column_text(stmt, 8);

        char line[256];
        snprintf(line, sizeof(line), "%s %s %s %s %s %s %s %s ;",
                 protocol, interface[0] == '\0' ? "?" : interface, src_ip[0] == '\0' ? "?" : src_ip, dst_ip[0] == '\0' ? "?" : dst_ip, src_port[0] == '\0' ? "?" : src_port, dst_port[0] == '\0' ? "?" : dst_port, start_time[0] == '\0' ? "?" : start_time, end_time[0] == '\0' ? "?" : end_time);

        fputs(line, fp);

    }

    fclose(fp);
    sqlite3_finalize(stmt);

    return TRUE;
}

// 追加到设备文件（添加和导入用）
gboolean appendDataToDeviceFile(const char *protocol, const char *interface, const char *src_ip, const char *dst_ip, const char *src_port, const char *dst_port, const char *start_time, const char *end_time, gboolean action)
{
    if(!action) return TRUE;
    FILE *fp = fopen(DEVICE_FILE, "a");
    if (fp == NULL)
    {
        g_warning("打开设备文件错误: %s", strerror(errno));
        g_printerr("打开设备文件错误: %s\n", strerror(errno));
        return FALSE;
    }

    char line[256];
    snprintf(line, sizeof(line), "%s %s %s %s %s %s %s %s ;",
             protocol, interface[0] == '\0' ? "?" : interface , src_ip[0] == '\0' ? "?" : src_ip, dst_ip[0] == '\0' ? "?" : dst_ip, src_port[0] == '\0' ? "?" : src_port, dst_port[0] == '\0' ? "?" : dst_port, start_time[0] == '\0' ? "?" : start_time, end_time[0] == '\0' ? "?" : end_time);

    fputs(line, fp);

    fclose(fp);

    return TRUE;
}

// 检查权限功能
gboolean checkPermission()
{
    // 检查文件的读写权限，0为有权限，-1为无权限。两个权限都有返回1，否则返回0
    return access(DEVICE_FILE, R_OK | W_OK) == 0;
}


