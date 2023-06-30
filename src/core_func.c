#include "core_func.h"

// 全局变量，用于跟踪选中行的计数
gint selectedRowCount = 0;

// 选择行发生变化时的回调函数
void on_selection_changed(GtkTreeSelection *selection, gpointer user_data)
{
    // 更新选中行的计数
    selectedRowCount = gtk_tree_selection_count_selected_rows(selection);
}

// 导入按钮回调函数
void on_import_button_clicked(GtkButton *button, gpointer data)
{
    GtkWidget *dialog;
    gint res;
    gchar *filename;
    // 创建文件选择对话框
    dialog = gtk_file_chooser_dialog_new("Choose db file",
                                         NULL,
                                         GTK_FILE_CHOOSER_ACTION_OPEN,
                                         "Cancel", GTK_RESPONSE_CANCEL,
                                         "Open", GTK_RESPONSE_ACCEPT,
                                         NULL);

    // 设置对话框的属性
    gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), g_get_home_dir());

    // 运行对话框并等待用户选择文件
    res = gtk_dialog_run(GTK_DIALOG(dialog));
    // 如果文件不是 SQLite 文件，给出相应的提示并让用户重新选择文件
    while (res == GTK_RESPONSE_ACCEPT)
    {
        filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        if (g_str_has_suffix(filename, ".db"))
        {
            // 导入数据库
            int count = importData(filename);
            if (!count)
            {
                // 提示用户导入失败
                GtkWidget *error_dialog = gtk_message_dialog_new(GTK_WINDOW(dialog),
                                                                 GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                 GTK_MESSAGE_ERROR,
                                                                 GTK_BUTTONS_CLOSE,
                                                                 "Import failed! Please check the database file!");
                gtk_dialog_run(GTK_DIALOG(error_dialog));
                gtk_widget_destroy(error_dialog);
            }
            else{
                // 关闭对话框
                gtk_widget_destroy(dialog);
                // 提示用户导入成功，并显示导入记录数量
                GtkWidget *success_dialog = gtk_message_dialog_new(NULL,
                                                                   GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                   GTK_MESSAGE_INFO,
                                                                   GTK_BUTTONS_CLOSE,
                                                                   "Import successful! %d records imported!",
                                                                   count);

                gtk_dialog_run(GTK_DIALOG(success_dialog));
                gtk_widget_destroy(success_dialog);
            }

            // 显示数据
            showData(GTK_LIST_STORE(data));
            // 释放内存
            g_free(filename);
            return;
        }
        else
        {
            // 提示用户选择 SQLite 文件
            GtkWidget *hint_dialog = gtk_message_dialog_new(GTK_WINDOW(dialog),
                                                            GTK_DIALOG_DESTROY_WITH_PARENT,
                                                            GTK_MESSAGE_ERROR,
                                                            GTK_BUTTONS_CLOSE,
                                                            "Please select a SQLite database file with a .db suffix!");
            gtk_dialog_run(GTK_DIALOG(hint_dialog));
            gtk_widget_destroy(hint_dialog);
        }
        g_free(filename);
        res = gtk_dialog_run(GTK_DIALOG(dialog));
    }
    // 关闭对话框
    gtk_widget_destroy(dialog);
}

// 如果ip输入框旁边的secondary icon被点击，弹窗提示用户输入正确的ip地址
void on_ip_entry_icon_press(GtkEntry *entry, GtkEntryIconPosition icon_pos, GdkEvent *event, gpointer data)
{
    // 创建提示对话框(处于最顶层)
    GtkWidget *hint_dialog = gtk_message_dialog_new(GTK_WINDOW(gtk_widget_get_toplevel(GTK_WIDGET(entry))),
                                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    GTK_MESSAGE_INFO,
                                                    GTK_BUTTONS_CLOSE,
                                                    "Please enter a valid ip address!");
    // 运行对话框并等待用户点击关闭按钮
    gtk_dialog_run(GTK_DIALOG(hint_dialog));
    // 如果点击了关闭按钮，销毁对话框
    gtk_widget_destroy(hint_dialog);
}

// 添加按钮回调函数
void on_add_button_clicked(GtkButton *button, gpointer data)
{
    // 从glade文件中获取edit对话框和popover_cancel
    GtkBuilder *builder = gtk_builder_new_from_resource("/glade/edit.glade");
    GtkWidget *edit_dialog = GTK_WIDGET(gtk_builder_get_object(builder, "edit_dialog"));
    // 连接builder中的信号
    gtk_builder_connect_signals(builder, NULL);
    // 连接关闭信号处理函数
    g_signal_connect(edit_dialog, "destroy", G_CALLBACK(gtk_widget_destroy), NULL);
    // 运行对话框并等待用户选择
    // 保持对话框在最上层
    gtk_window_set_keep_above(GTK_WINDOW(edit_dialog), TRUE);
    gint res = gtk_dialog_run(GTK_DIALOG(edit_dialog));
    if(res == GTK_RESPONSE_OK){
    
    }
    gtk_widget_destroy(edit_dialog);
    // 释放资源
    g_object_unref(builder);
}


// 导出按钮回调函数, data为treeview
void on_export_button_clicked(GtkButton *button, gpointer data)
{
    //获取selection
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(data));
    // 如果没有选中任何行，给出相应的提示
    if (selectedRowCount == 0)
    {
        GtkWidget *hint_dialog = gtk_message_dialog_new(NULL,
                                                        GTK_DIALOG_DESTROY_WITH_PARENT,
                                                        GTK_MESSAGE_ERROR,
                                                        GTK_BUTTONS_CLOSE,
                                                        "Please select at least one row!");
        gtk_dialog_run(GTK_DIALOG(hint_dialog));
        gtk_widget_destroy(hint_dialog);
        return;
    }
    // 创建文件选择对话框
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Choose db file",
                                                    NULL,
                                                    GTK_FILE_CHOOSER_ACTION_SAVE,
                                                    "Cancel", GTK_RESPONSE_CANCEL,
                                                    "Save", GTK_RESPONSE_ACCEPT,
                                                    NULL);
    // 设置对话框的属性
    gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), g_get_home_dir());
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
    // 设置默认文件名
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "rules.db");
    // 运行对话框并等待用户选择文件
    gint res = gtk_dialog_run(GTK_DIALOG(dialog));
    // 如果用户选择了文件(while循环用于判断用户是否选择了文件)
    while (res == GTK_RESPONSE_ACCEPT)
    {
        //  获取用户选择的文件名
        gchar *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        // 将选择的数据导出到用户选择的文件中
        int count = exportData(filename, GTK_TREE_VIEW(data));
        // 如果导出成功，显示相应的提示
        if (count)
        {
            // 关闭对话框
            gtk_widget_destroy(dialog);
            // 提示用户导出成功，并显示导出记录数量
            GtkWidget *success_dialog = gtk_message_dialog_new(NULL,
                                                               GTK_DIALOG_DESTROY_WITH_PARENT,
                                                               GTK_MESSAGE_INFO,
                                                               GTK_BUTTONS_CLOSE,
                                                               "Export successful! %d records exported!",
                                                               count);

            gtk_dialog_run(GTK_DIALOG(success_dialog));
            gtk_widget_destroy(success_dialog);
            // 释放内存
            g_free(filename);
            return;
        }
        // 如果导出失败，提示用户导出失败，并让用户重新选择文件
        else
        {
            // 提示用户导出失败
            GtkWidget *error_dialog = gtk_message_dialog_new(GTK_WINDOW(dialog),
                                                             GTK_DIALOG_DESTROY_WITH_PARENT,
                                                             GTK_MESSAGE_ERROR,
                                                             GTK_BUTTONS_CLOSE,
                                                             "Export failed! Please check permissions!");
            gtk_dialog_run(GTK_DIALOG(error_dialog));
            gtk_widget_destroy(error_dialog);
        }
        // 释放内存
        g_free(filename);
    }
    // 关闭对话框
    gtk_widget_destroy(dialog);
}


void on_delete_button_clicked(GtkButton *button, gpointer data)
{
    // 如果没有选中任何行，给出相应的提示
    if (selectedRowCount == 0)
    {
        GtkWidget *hint_dialog = gtk_message_dialog_new(NULL,
                                                        GTK_DIALOG_DESTROY_WITH_PARENT,
                                                        GTK_MESSAGE_ERROR,
                                                        GTK_BUTTONS_CLOSE,
                                                        "Please select at least one row!");
        gtk_dialog_run(GTK_DIALOG(hint_dialog));
        gtk_widget_destroy(hint_dialog);
        return;
    }

    // 创建确认对话框
    GtkWidget *confirm_dialog = gtk_message_dialog_new(NULL,
                                                       GTK_DIALOG_DESTROY_WITH_PARENT,
                                                       GTK_MESSAGE_QUESTION,
                                                       GTK_BUTTONS_YES_NO,
                                                       "Are you sure to delete the selected rows?");
    // 运行对话框并等待用户选择
    gint res = gtk_dialog_run(GTK_DIALOG(confirm_dialog));
    // 如果用户选择了是，删除选中的行（同时更新数据库）
    if (res == GTK_RESPONSE_YES)
    {
        // 获取treeview
        GtkTreeView *treeview = GTK_TREE_VIEW(gtk_tree_selection_get_tree_view(GTK_TREE_SELECTION(data)));
        // 获取liststore
        GtkListStore *liststore = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
        // 获取selection
        GtkTreeSelection *selection = gtk_tree_view_get_selection(treeview);
        // 获取选中的行
        GList *selectedRows = gtk_tree_selection_get_selected_rows(selection, NULL);
        GList *lastRow = g_list_last(selectedRows);

            // 逆序遍历选中的行，以防删除后影响后续行的位置
        while (lastRow != NULL)
        {
            GtkTreePath *path = (GtkTreePath *)(lastRow->data);
            GtkTreeIter iter;
            if (gtk_tree_model_get_iter(GTK_TREE_MODEL(liststore), &iter, path))
            {
                // 获取选中行的id
                gint id;
                gtk_tree_model_get(GTK_TREE_MODEL(liststore), &iter, 0, &id, -1);
                // 删除选中行
                gtk_list_store_remove(liststore, &iter);
                // 删除数据库中的记录
                if (!deleteData(id))
                {
                    // 提示用户删除数据库失败
                    GtkWidget *error_dialog = gtk_message_dialog_new(NULL,
                                                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                    GTK_MESSAGE_ERROR,
                                                                    GTK_BUTTONS_CLOSE,
                                                                    "Delete database failed! Please check permissions!");
                    gtk_dialog_run(GTK_DIALOG(error_dialog));
                    gtk_widget_destroy(error_dialog);
                    // 释放内存
                    g_list_free(selectedRows);
                    gtk_widget_destroy(confirm_dialog);
                    return;
                }
            }
            // 移动到上一个节点
            lastRow = g_list_previous(lastRow);
        }
        int count = g_list_length(selectedRows);
        // 释放内存
        g_list_free(selectedRows);

        // 更新数据库
        if (!showData(liststore))
        {
            gtk_widget_destroy(confirm_dialog);
            // 提示用户更新数据库失败
            GtkWidget *error_dialog = gtk_message_dialog_new(NULL,
                                                             GTK_DIALOG_DESTROY_WITH_PARENT,
                                                             GTK_MESSAGE_ERROR,
                                                             GTK_BUTTONS_CLOSE,
                                                             "Update database failed! Please check permissions!");
            gtk_dialog_run(GTK_DIALOG(error_dialog));
            gtk_widget_destroy(error_dialog);
            // 释放内存
            g_list_free(selectedRows);
            return;
        }

        // 提示用户删除成功，并显示删除记录数量
        // 关闭对话框
        gtk_widget_destroy(confirm_dialog);
        GtkWidget *success_dialog = gtk_message_dialog_new(NULL,
                                                           GTK_DIALOG_DESTROY_WITH_PARENT,
                                                           GTK_MESSAGE_INFO,
                                                           GTK_BUTTONS_CLOSE,
                                                           "Delete successful! %d records deleted!",
                                                           count);
        gtk_dialog_run(GTK_DIALOG(success_dialog));
        // 如果点击了关闭按钮，销毁对话框
        gtk_widget_destroy(success_dialog);
        return;
    }

    // 如果用户选择了否，关闭对话框
    gtk_widget_destroy(confirm_dialog);
}

// 将Delete按键映射为delete_button的回调函数
gboolean on_key_press_event(GtkWidget *widget, GdkEventKey *event, gpointer data)
{
    if (event->keyval == GDK_KEY_Delete)
    {
        on_delete_button_clicked(NULL, data);  // 调用你的删除按钮点击事件处理函数
        return TRUE;  // 表示事件已处理
    }

    return FALSE;  // 表示事件未处理
}




// 全选按钮回调函数
void on_select_all_button_clicked(GtkButton *button, gpointer data)
{
    // 获取treeview
    GtkTreeView *treeview = GTK_TREE_VIEW(data);
    // 获取liststore
    GtkListStore *liststore = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
    // 获取selection
    GtkTreeSelection *selection = gtk_tree_view_get_selection(treeview);
    // 选中所有行
    gtk_tree_selection_select_all(selection);
}


// 双击treeview中的行时，弹出编辑对话框


