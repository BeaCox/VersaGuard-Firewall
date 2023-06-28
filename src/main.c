#include "database.h"
#include "headerbar.h"


int main(int argc, char *argv[])
{
    GtkBuilder *builder;
    GtkWidget *window;
    GtkListStore *liststore;

    gtk_init(&argc, &argv);

    // 加载Glade布局文件
    builder = gtk_builder_new_from_file("../ui/main.glade");

    // 获取窗口
    window = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));

    // 连接关闭信号处理函数
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // 连接builder中的信号
    gtk_builder_connect_signals(builder, NULL);

    liststore = GTK_LIST_STORE(gtk_builder_get_object(builder, "liststore"));

    // 初始化数据库
    initDatabase();

    // 显示数据
    showData(liststore);

    // 显示窗口
    gtk_widget_show_all(window);

    // 进入主循环
    gtk_main();

    // 释放资源
    g_object_unref(builder);

    // 关闭数据库
    closeDatabase();

    return 0;
}


