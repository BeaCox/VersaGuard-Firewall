#include "core_func.h"


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


// 添加按钮回调函数
void on_add_button_clicked(GtkButton *button, gpointer data)
{
    // 从glade文件中获取add对话框和popover_cancel
    GtkBuilder *builder = gtk_builder_new_from_resource("/glade/edit.glade");
    GtkWidget *edit_dialog = GTK_WIDGET(gtk_builder_get_object(builder, "edit_dialog"));
    // button_ok
    GtkWidget *button_ok = GTK_WIDGET(gtk_builder_get_object(builder, "button_ok"));
    // button_cancel
    GtkWidget *button_cancel = GTK_WIDGET(gtk_builder_get_object(builder, "button_cancel"));
    // popover_cancel
    GtkWidget *popover_cancel = GTK_WIDGET(gtk_builder_get_object(builder, "popover_cancel"));
    // btn_no
    GtkWidget *btn_no = GTK_WIDGET(gtk_builder_get_object(builder, "btn_no"));
    // btn_yes
    GtkWidget *btn_yes = GTK_WIDGET(gtk_builder_get_object(builder, "btn_yes"));
    // 显示add对话框
    gtk_dialog_run(GTK_DIALOG(edit_dialog));
    // 点击button_ok后关闭对话框
    g_signal_connect(button_ok, "clicked", G_CALLBACK(gtk_widget_destroy), edit_dialog);
    // 点击btn_yes后销毁对话框和popover_cancel
    g_signal_connect(btn_yes, "clicked", G_CALLBACK(gtk_widget_destroy), edit_dialog);

    // 销毁edit_dialog
    gtk_widget_destroy(edit_dialog);
}


// 导出按钮回调函数, data为treeview
void on_export_button_clicked(GtkButton *button, gpointer data)
{
    //获取selection
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(data));
    // 如果没有选中任何行，给出相应的提示
    if (gtk_tree_selection_count_selected_rows(GTK_TREE_SELECTION(selection)) == 0)
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


// 删除按钮回调函数
void on_delete_button_clicked(GtkButton *button, gpointer data)
{
    // 如果没有选中任何行，给出相应的提示
    if (gtk_tree_selection_count_selected_rows(GTK_TREE_SELECTION(data)) == 0)
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
        GList *row = selectedRows;
        // 遍历选中的行
        while (row)
        {
            GtkTreePath *path = (GtkTreePath *)(row->data);
            GtkTreeIter iter;
            gtk_tree_model_get_iter(GTK_TREE_MODEL(liststore), &iter, path);
            // 获取选中行的id
            gint id;
            gtk_tree_model_get(GTK_TREE_MODEL(liststore), &iter, 0, &id, -1);
            // 从数据库中删除选中行
            if(!deleteData(id)){
                // 提示用户删除失败
                GtkWidget *error_dialog = gtk_message_dialog_new(NULL,
                                                                 GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                 GTK_MESSAGE_ERROR,
                                                                 GTK_BUTTONS_CLOSE,
                                                                 "Delete failed! Please check permissions!");
                gtk_dialog_run(GTK_DIALOG(error_dialog));
                gtk_widget_destroy(error_dialog);

                // 释放内存
                g_list_free(selectedRows);
                gtk_widget_destroy(confirm_dialog);
                return;
            }
            // 从liststore中删除选中行
            gtk_list_store_remove(liststore, &iter);
            // 释放内存
            row = g_list_next(row);
            gtk_tree_path_free(path);
        }
        // 更新数据库
        if(!showData(liststore)){
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
            gtk_widget_destroy(confirm_dialog);
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
                                                           g_list_length(selectedRows));
        gtk_dialog_run(GTK_DIALOG(success_dialog));
        gtk_widget_destroy(success_dialog);
        // 释放内存
        g_list_free(selectedRows);
        return;
    }
    // 如果用户选择了否，关闭对话框
    gtk_widget_destroy(confirm_dialog);
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

