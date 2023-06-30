#ifndef CORE_FUNC_H
#define CORE_FUNC_H

#include <gtk/gtk.h>
#include "database.h"

// 选择行发生变化时的回调函数
void on_selection_changed(GtkTreeSelection *selection, gpointer user_data);
// 导入功能
void on_import_button_clicked(GtkButton *button, gpointer data);
// 添加功能
void on_ip_entry_icon_press(GtkEntry *entry, GtkEntryIconPosition icon_pos, GdkEvent *event, gpointer data);
void on_add_button_clicked(GtkButton *button, gpointer data);
// 导出功能
void on_export_button_clicked(GtkButton *button, gpointer data);
// 删除功能
void on_delete_button_clicked(GtkButton *button, gpointer data);
gboolean on_key_press_event(GtkWidget *widget, GdkEventKey *event, gpointer data);
// 全选功能
void on_select_all_button_clicked(GtkButton *button, gpointer data);

#endif // CORE_FUNC_H

