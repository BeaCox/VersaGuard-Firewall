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
    GtkBuilder *builder = gtk_builder_new_from_file("../ui/about.glade");
    GtkWidget *about_dialog = GTK_WIDGET(gtk_builder_get_object(builder, "about_dialog"));
    // 禁用主窗口
    gtk_widget_set_sensitive(GTK_WIDGET(data), FALSE);
    // 保持对话框在最上层
    gtk_window_set_keep_above(GTK_WINDOW(about_dialog), TRUE);
    // 显示about对话框
    gtk_dialog_run(GTK_DIALOG(about_dialog));
    // 点击按钮后销毁对话框
    gtk_widget_destroy(about_dialog);
    // 启用主窗口
    gtk_widget_set_sensitive(GTK_WIDGET(data), TRUE);
}