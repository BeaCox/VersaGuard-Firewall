#include <gtk/gtk.h>
#include <sqlite3.h>

sqlite3 *db;
// 连接数据库并初始化表
int initDatabase() {
    int rc = sqlite3_open("rules.db", &db);
    if (rc != SQLITE_OK) {
        g_warning("无法打开数据库: %s", sqlite3_errmsg(db));
        return rc;
    }

    // 创建规则表
    const char *createTableQuery = "CREATE TABLE IF NOT EXISTS rules (protocol TEXT, source TEXT, destination TEXT);";
    rc = sqlite3_exec(db, createTableQuery, 0, 0, 0);
    if (rc != SQLITE_OK) {
        g_warning("无法创建表: %s", sqlite3_errmsg(db));
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
        sqlite3_free(errorMsg);
    }
}


int main(int argc, char *argv[]) {
    GtkBuilder *builder;
    GtkWidget *window;
    GtkTreeView *treeview;
    // scroll window
    GtkWidget *scrolled_window;
    // list store
    GtkListStore *liststore;
    // list store column * 3
    GtkTreeViewColumn *col0;
    GtkTreeViewColumn *col1;
    GtkTreeViewColumn *col2;
    // list store column * 3
    GtkCellRenderer *col0r;
    GtkCellRenderer *col1r;
    GtkCellRenderer *col2r;


    
    gtk_init(&argc, &argv);
    
    // Load the Glade file
    builder = gtk_builder_new_from_file ("../ui/db.glade");
    
    // Get the main window
    window = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));
    
    // 连接关闭信号处理函数
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
        
    // Connect the signals
    gtk_builder_connect_signals(builder, NULL);
        
    scrolled_window	 = GTK_WIDGET(gtk_builder_get_object(builder, "scrolled_window"));
    treeview		 = GTK_TREE_VIEW(gtk_builder_get_object(builder, "view"));
    liststore		 = GTK_LIST_STORE(gtk_builder_get_object(builder, "liststore"));
    col0		 = GTK_TREE_VIEW_COLUMN(gtk_builder_get_object(builder, "col0"));
    col1		 = GTK_TREE_VIEW_COLUMN(gtk_builder_get_object(builder, "col1"));
    col2		 = GTK_TREE_VIEW_COLUMN(gtk_builder_get_object(builder, "col2"));
    col0r		 = GTK_CELL_RENDERER(gtk_builder_get_object(builder, "col0r"));
    col1r		 = GTK_CELL_RENDERER(gtk_builder_get_object(builder, "col1r"));
    col2r		 = GTK_CELL_RENDERER(gtk_builder_get_object(builder, "col2r"));

    // Set the tree view's model
    gtk_tree_view_set_model(treeview, GTK_TREE_MODEL(liststore));

    // Set the tree view's columns
    gtk_tree_view_column_add_attribute(col0, col0r, "text", 0);
    gtk_tree_view_column_add_attribute(col1, col1r, "text", 1);
    gtk_tree_view_column_add_attribute(col2, col2r, "text", 2);

    // Set the tree view's selection mode
    gtk_tree_selection_set_mode(gtk_tree_view_get_selection(treeview), GTK_SELECTION_MULTIPLE);


    // Destroy builder
    g_object_unref(builder);
    

    
    // 初始化数据库
    initDatabase();

    //插入示例数据
    insertData("tcp", "192.168.1.254", "192.168.1.253");
    insertData("udp", "192.168.1.254", "192.168.1.253");
    insertData("ping", "192.168.1.254", "192.168.1.253");

    // 将数据库中的数据显示到列表中
    sqlite3_stmt *stmt;
    const char *query = "SELECT protocol, source, destination FROM rules;";
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_warning("无法执行查询: %s", sqlite3_errmsg(db));
        return rc;
    }

    // 遍历查询结果
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // 从查询结果中获取数据
        const char *protocol = (const char *)sqlite3_column_text(stmt, 0);
        const char *source = (const char *)sqlite3_column_text(stmt, 1);
        const char *destination = (const char *)sqlite3_column_text(stmt, 2);

        // 将数据添加到列表中
        GtkTreeIter iter;
        gtk_list_store_append(liststore, &iter);
        gtk_list_store_set(liststore, &iter, 0, protocol, 1, source, 2, destination, -1);
    }

    // 释放查询结果
    sqlite3_finalize(stmt);

    // Show window
    gtk_widget_show(window);

    // Start main loop
    gtk_main();



    return 0;
}


