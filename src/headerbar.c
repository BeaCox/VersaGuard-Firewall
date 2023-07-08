#include "headerbar.h"
// 暗黑模式切换回调函数
void on_dark_toggle_button_toggled(GtkToggleButton *toggle_button, gpointer data)
{
    gboolean active = gtk_toggle_button_get_active(toggle_button);

    if (active)
    {
        // 应用暗黑模式样式
        GtkSettings *settings = gtk_settings_get_default();
        g_object_set(settings, "gtk-application-prefer-dark-theme", TRUE, NULL);

        // 切换按钮图标为太阳
        gtk_button_set_image(GTK_BUTTON(toggle_button), gtk_image_new_from_icon_name("weather-clear-symbolic", GTK_ICON_SIZE_BUTTON));
    }
    else
    {
        // 应用默认（亮色）模式样式
        GtkSettings *settings = gtk_settings_get_default();
        g_object_set(settings, "gtk-application-prefer-dark-theme", FALSE, NULL);

        // 切换按钮图标为月亮
        gtk_button_set_image(GTK_BUTTON(toggle_button), gtk_image_new_from_icon_name("weather-clear-night-symbolic", GTK_ICON_SIZE_BUTTON));
    }
}
// 关于按钮回调函数（传入主窗口指针）
void on_about_button_clicked(GtkButton *button, gpointer data)
{
    // 从glade文件中获取about对话框
    GtkBuilder *builder = gtk_builder_new_from_resource("/glade/about.glade");
    GtkWidget *about_dialog = GTK_WIDGET(gtk_builder_get_object(builder, "about_dialog"));
    // 获取嵌入的图标文件路径
    const gchar *icon_path = "/img/versaguard-logo.png";
    // 设置logo
    GdkPixbuf *logo_pixbuf = gdk_pixbuf_new_from_resource(icon_path, NULL);
    // 设置图标为 About 对话框的 Logo
    gtk_about_dialog_set_logo(GTK_ABOUT_DIALOG(about_dialog), logo_pixbuf);
    // 禁用主窗口
    gtk_widget_set_sensitive(GTK_WIDGET(data), FALSE);
    // 保持对话框在最上层
    gtk_window_set_keep_above(GTK_WINDOW(about_dialog), TRUE);
    // 显示about对话框
    gtk_dialog_run(GTK_DIALOG(about_dialog));
    // 清理资源
    g_object_unref(logo_pixbuf);
    // 点击按钮后销毁对话框
    gtk_widget_destroy(about_dialog);
    // 启用主窗口
    gtk_widget_set_sensitive(GTK_WIDGET(data), TRUE);
}

// 应用程序数据目录按钮回调函数
void on_data_dir_button_clicked(GtkButton *button, gpointer data)
{
    // 获取应用程序数据目录
    char data_dir[256];
    snprintf(data_dir, sizeof(data_dir), "file://%s/%s", g_get_home_dir(), APP_DIR);
    // 打开文件管理器
    gtk_show_uri_on_window(NULL, data_dir, GDK_CURRENT_TIME, NULL);
}

