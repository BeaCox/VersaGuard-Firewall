#include "database.h"

static sqlite3 *db;

// 连接数据库并初始化表
int initDatabase() {
    int rc = sqlite3_open("rules.db", &db);
    if (rc != SQLITE_OK) {
        return rc;
    }

    // 创建规则表
    const char *createTableQuery = "CREATE TABLE IF NOT EXISTS rules (protocol TEXT, source TEXT, destination TEXT);";
    rc = sqlite3_exec(db, createTableQuery, 0, 0, 0);
    if (rc != SQLITE_OK) {
        return rc;
    }

    return SQLITE_OK;
}

// 插入数据到数据库
void insertData(const char *protocol, const char *source, const char *destination) {
    char *errorMsg = 0;
    char insertQuery[256];

    // 构建插入数据的 SQL 查询语句
    snprintf(insertQuery, sizeof(insertQuery), "INSERT INTO rules (protocol, source, destination) VALUES ('%s', '%s', '%s');", protocol, source, destination);

    // 执行插入查询
    int rc = sqlite3_exec(db, insertQuery, 0, 0, &errorMsg);
    if (rc != SQLITE_OK) {
        g_warning("插入数据错误: %s", errorMsg);
        // 输出错误到控制台
        g_printerr("插入数据错误: %s\n", errorMsg);
        sqlite3_free(errorMsg);
    }
}

// 将数据库中的数据显示到列表中
void showData(GtkListStore *liststore) {
    sqlite3_stmt *stmt;
    const char *selectQuery = "SELECT * FROM rules;";
    int rc = sqlite3_prepare_v2(db, selectQuery, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("查询数据错误: %s", sqlite3_errmsg(db));
        // 输出错误到控制台
        g_printerr("查询数据错误: %s\n", sqlite3_errmsg(db));
        return;
    }

    // 清空列表
    gtk_list_store_clear(liststore);

    // 遍历查询结果
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // 获取查询结果中的数据
        const char *protocol = (const char *)sqlite3_column_text(stmt, 0);
        const char *source = (const char *)sqlite3_column_text(stmt, 1);
        const char *destination = (const char *)sqlite3_column_text(stmt, 2);

        // 将数据添加到列表中
        GtkTreeIter iter;
        gtk_list_store_append(liststore, &iter);
        gtk_list_store_set(liststore, &iter, 0, protocol, 1, source, 2, destination, -1);
    }

    sqlite3_finalize(stmt);
}

