#include "database.h"

static sqlite3 *db;

// 初始化数据库并创建表
int initDatabase()
{
    int rc = sqlite3_open("rules.db", &db);
    if (rc != SQLITE_OK)
    {
        return rc;
    }

    const char *createTableQuery = "CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, protocol TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, start_time TEXT, end_time TEXT, action INTEGER, remarks TEXT);";
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

gboolean insertData(const char *protocol, const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *start_time, const char *end_time, gboolean action, const char *remarks)
{
    char *errorMsg = 0;
    char insertQuery[256];
    int actionValue = action ? 1 : 0;

    snprintf(insertQuery, sizeof(insertQuery), "INSERT INTO rules (protocol, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, remarks) VALUES ('%s', '%s', '%s', %d, %d, '%s', '%s', %d, '%s');",
             protocol, src_ip, dst_ip, src_port, dst_port, start_time, end_time, actionValue, remarks);

    int rc = sqlite3_exec(db, insertQuery, 0, 0, &errorMsg);
    if (rc != SQLITE_OK)
    {
        g_warning("插入数据错误: %s", errorMsg);
        sqlite3_free(errorMsg);
        return FALSE;
    }

    return TRUE;
}

int importData(const char *filename)
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
        const char *src_ip = (const char *)sqlite3_column_text(stmt, 2);
        const char *dst_ip = (const char *)sqlite3_column_text(stmt, 3);
        int src_port = sqlite3_column_int(stmt, 4);
        int dst_port = sqlite3_column_int(stmt, 5);
        const char *start_time = (const char *)sqlite3_column_text(stmt, 6);
        const char *end_time = (const char *)sqlite3_column_text(stmt, 7);
        gboolean action = sqlite3_column_int(stmt, 8) != 0;
        const char *remarks = (const char *)sqlite3_column_text(stmt, 9);

        if(!insertData(protocol, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, remarks)){
            count--;
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(importDb);

    return count;
}

int exportData(const char *filename, GtkTreeView *data)
{
    sqlite3 *exportDb;
    int rc = sqlite3_open(filename, &exportDb);
    if (rc != SQLITE_OK)
    {
        g_warning("打开数据库错误: %s", sqlite3_errmsg(exportDb));
        return 0;
    }
    const char *createTableQuery = "CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, protocol TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, start_time TEXT, end_time TEXT, action INTEGER, remarks TEXT);";
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
        gchar *src_ip;
        gchar *dst_ip;
        gint src_port;
        gint dst_port;
        gchar *start_time;
        gchar *end_time;
        gboolean action;
        gchar *remarks;

        gtk_tree_model_get(model, &iter,
                           1, &protocol,
                           2, &src_ip,
                           3, &dst_ip,
                           4, &src_port,
                           5, &dst_port,
                           6, &start_time,
                           7, &end_time,
                           8, &action,
                           9, &remarks,
                           -1);

        insertData(protocol, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, remarks);

        g_free(protocol);
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
    count  =  g_list_length(selectedRows);
    // 释放选中行列表的内存
    g_list_free(selectedRows);

    // 将db设置回原来的db
    db = tempDb;
    // 关闭数据库
    sqlite3_close(exportDb);
    return count;
}


int deleteData(int id){
    char *errorMsg = 0;
    char deleteQuery[256];

    snprintf(deleteQuery, sizeof(deleteQuery), "DELETE FROM rules WHERE id = %d;", id);

    int rc = sqlite3_exec(db, deleteQuery, 0, 0, &errorMsg);
    if (rc != SQLITE_OK)
    {
        g_warning("删除数据错误: %s", errorMsg);
        sqlite3_free(errorMsg);
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
        const char *src_ip = (const char *)sqlite3_column_text(stmt, 2);
        const char *dst_ip = (const char *)sqlite3_column_text(stmt, 3);
        int src_port = sqlite3_column_int(stmt, 4);
        int dst_port = sqlite3_column_int(stmt, 5);
        const char *start_time = (const char *)sqlite3_column_text(stmt, 6);
        const char *end_time = (const char *)sqlite3_column_text(stmt, 7);
        gboolean action = sqlite3_column_int(stmt, 8) != 0;
        const char *remarks = (const char *)sqlite3_column_text(stmt, 9);

        // src_port和dst_port转换为char*后再插入liststore
        gchar *src_port_str = g_strdup_printf("%d", src_port);
        gchar *dst_port_str = g_strdup_printf("%d", dst_port);

        GtkTreeIter iter;
        gtk_list_store_append(liststore, &iter);
        gtk_list_store_set(liststore, &iter,
                           0, id,
                           1, protocol,
                           2, src_ip,
                           3, dst_ip,
                           4, src_port_str,
                           5, dst_port_str,
                           6, start_time,
                           7, end_time,
                           8, action,
                           9, remarks,
                           -1);
    }

    sqlite3_finalize(stmt);

    return TRUE;
}



