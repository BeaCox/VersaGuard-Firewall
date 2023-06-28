#include "database.h"
#include "headerbar.h"
#include "core_func.h"

int main(int argc, char *argv[])
{
    GtkBuilder *builder;
    GtkWidget *window;
    GtkWidget *headerBar;
    GtkListStore *liststore;

    gtk_init(&argc, &argv);

    // 加载Glade布局文件
    builder = gtk_builder_new_from_resource("/glade/main.glade");

    // 获取窗口
    window = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));

    // 连接关闭信号处理函数
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // 连接builder中的信号
    gtk_builder_connect_signals(builder, NULL);

    liststore = GTK_LIST_STORE(gtk_builder_get_object(builder, "liststore"));

    // 初始化数据库
    initDatabase();

    // 应用css文件
    GtkCssProvider *cssProvider = gtk_css_provider_new();
    gtk_css_provider_load_from_resource(cssProvider, "/css/main.css");
    // GdkScreen *screen = gdk_screen_get_default();
    // gtk_style_context_add_provider_for_screen(screen, GTK_STYLE_PROVIDER(cssProvider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    GtkStyleContext *styleContext = gtk_widget_get_style_context(window);
    gtk_style_context_add_provider(styleContext, GTK_STYLE_PROVIDER(cssProvider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref(cssProvider);
    // 设置标题栏
    headerBar = GTK_WIDGET(gtk_builder_get_object(builder, "headerbar"));
    gtk_window_set_titlebar(GTK_WINDOW(window), headerBar);

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



