#include "core_func.h"
#include "logs.h"

void on_main_window_destroy()
{
    // 退出主循环
    gtk_main_quit();

    // 关闭数据库
    closeDatabase();
}

int main(int argc, char *argv[])
{
    GtkBuilder *builder;
    GtkWidget *window;
    GtkWidget *headerBar;
    GtkListStore *liststore;
    GtkTextView *textview;

    gtk_init(&argc, &argv);

    // 检查内核模块是否加载
    if (!checkModule())
    {
        // 没有安装内核模块，提示用户并退出应用
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "Kernel module not installed! Please install it first!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return 0;
    }

    // 检查权限
    if (!checkPermission())
    {
        // 没有权限，弹出对话框
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "No write access to device files! Please run as root!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return 0;
    }

    // 加载Glade布局文件
    builder = gtk_builder_new_from_resource("/glade/main.glade");

    // 获取窗口
    window = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));

    // 连接builder中的信号
    gtk_builder_connect_signals(builder, NULL);

    // 连接关闭信号处理函数
    g_signal_connect(window, "destroy", G_CALLBACK(on_main_window_destroy), NULL);

    liststore = GTK_LIST_STORE(gtk_builder_get_object(builder, "liststore"));
    textview = GTK_TEXT_VIEW(gtk_builder_get_object(builder, "log_textview"));

    // 初始化数据库
    initDatabase();
    // 建立log软连接
    createLogLink();

    // 应用css文件
    GtkCssProvider *cssProvider = gtk_css_provider_new();
    gtk_css_provider_load_from_resource(cssProvider, "/css/main.css");
    GtkStyleContext *styleContext = gtk_widget_get_style_context(window);
    gtk_style_context_add_provider(styleContext, GTK_STYLE_PROVIDER(cssProvider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(cssProvider);
    // 设置标题栏
    headerBar = GTK_WIDGET(gtk_builder_get_object(builder, "headerbar"));
    gtk_window_set_titlebar(GTK_WINDOW(window), headerBar);

    // 数据库内容全部写入设备文件
    writeDataToDeviceFile();
    // 显示数据
    showData(liststore);

    // 创建GFile对象
    char log_file[PATH_MAX];
    sprintf(log_file, "%s/%s", LOG_DIR, LOG_FILE);
    GFile *file = g_file_new_for_path(log_file);

    // 创建文件监视器
    GFileMonitor *monitor = g_file_monitor_file(file, G_FILE_MONITOR_NONE, NULL, NULL);
    g_signal_connect(monitor, "changed", G_CALLBACK(file_changed_callback), textview);

    // 显示窗口
    gtk_widget_show_all(window);

    // 运行主循环
    gtk_main();

    // 释放资源
    g_object_unref(monitor);
    g_object_unref(file);
    g_object_unref(builder);

    return 0;
}

