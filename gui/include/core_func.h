#ifndef CORE_FUNC_H
#define CORE_FUNC_H

#include "database.h"
#include "utils.h"
#include "global.h"

// 导入功能
void on_import_button_clicked(GtkButton *button, gpointer data);
// 添加功能
void on_add_button_clicked(GtkButton *button, gpointer data);
gboolean on_edit_dialog_key_press_event(GtkWidget *widget, GdkEventKey *event, gpointer data);
void on_ip_entry_icon_press(GtkEntry *entry, GtkEntryIconPosition icon_pos, GdkEvent *event, gpointer data);
gboolean on_key_press_event_ip(GtkWidget *widget, GdkEventKey *event, gpointer data);
void on_ip_ok_clicked(GtkButton *button, gpointer data);
void on_ip_clear_clicked(GtkButton *button, gpointer data);
void on_port_entry_icon_press(GtkEntry *entry, GtkEntryIconPosition icon_pos, GdkEvent *event, gpointer data);
gboolean on_key_press_event_port(GtkWidget *widget, GdkEventKey *event, gpointer data);
void on_port_ok_clicked(GtkButton *button, gpointer data);
void on_port_clear_clicked(GtkButton *button, gpointer data);
void on_time_entry_icon_press(GtkEntry *entry, GtkEntryIconPosition icon_pos, GdkEvent *event, gpointer data);
gboolean on_key_press_event_time(GtkWidget *widget, GdkEventKey *event, gpointer data);
void on_time_ok_clicked(GtkButton *button, gpointer data);
void on_time_clear_clicked(GtkButton *button, gpointer data);
// 导出功能
void on_export_button_clicked(GtkButton *button, gpointer data);
// 删除功能
void on_delete_button_clicked(GtkButton *button, gpointer data);
gboolean on_delete_press_event(GtkWidget *widget, GdkEventKey *event, gpointer data);
// 全选功能
void on_select_all_button_clicked(GtkButton *button, gpointer data);
// 双击编辑功能
void on_treeview_row_activated(GtkTreeView *treeview, GtkTreePath *path, GtkTreeViewColumn *column, gpointer data);
// 检查协议类型，ICMP不允许选择端口
void on_combox_protocol_changed(GtkComboBox *combobox, gpointer data);
#endif // CORE_FUNC_H


