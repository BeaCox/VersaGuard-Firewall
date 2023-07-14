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
    if (res == GTK_RESPONSE_ACCEPT)
    {
        filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        if (g_str_has_suffix(filename, ".db"))
        {
            // 导入数据库
            int count = importData(filename, GTK_LIST_STORE(data));

            // 关闭对话框
            gtk_widget_destroy(dialog);
            if (!count)
            {
                // 提示用户导入失败
                GtkWidget *error_dialog = gtk_message_dialog_new(NULL,
                                                                 GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                 GTK_MESSAGE_ERROR,
                                                                 GTK_BUTTONS_CLOSE,
                                                                 "Import failed! Please check the database file!");
                gtk_dialog_run(GTK_DIALOG(error_dialog));
                gtk_widget_destroy(error_dialog);
            }
            else
            {
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
            GtkWidget *hint_dialog = gtk_message_dialog_new(NULL,
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
    // 从glade文件中获取edit对话框
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

    if (res == GTK_RESPONSE_OK)
    {
        // 传入的是treeviw，获取treeview对应的ListStore
        GtkListStore *liststore = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(data)));
        // 如果点击OK，将所有修改的内容作为新的一行（如果没有和已有规则冲突）写入database和ListStore并刷新TreeView
        // 获取entry中的内容
        // protocol的内容从comboboxtext中获取
        gchar *protocol = (gchar *)gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(gtk_builder_get_object(builder, "combox_protocol")));
        gchar *interface = (gchar *)gtk_entry_get_text(GTK_ENTRY(gtk_builder_get_object(builder, "entry_interface")));
        gchar *srcip = (gchar *)gtk_entry_get_text(GTK_ENTRY(gtk_builder_get_object(builder, "entry_srcip")));
        gchar *dstip = (gchar *)gtk_entry_get_text(GTK_ENTRY(gtk_builder_get_object(builder, "entry_dstip")));
        gchar *srcport = (gchar *)gtk_entry_get_text(GTK_ENTRY(gtk_builder_get_object(builder, "entry_srcport")));
        gchar *dstport = (gchar *)gtk_entry_get_text(GTK_ENTRY(gtk_builder_get_object(builder, "entry_dstport")));
        gchar *stime = (gchar *)gtk_entry_get_text(GTK_ENTRY(gtk_builder_get_object(builder, "entry_stime")));
        gchar *etime = (gchar *)gtk_entry_get_text(GTK_ENTRY(gtk_builder_get_object(builder, "entry_etime")));
        // block的内容从checkbutton中获取
        gboolean block = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(builder, "ckbt_block")));
        gchar *remarks = (gchar *)gtk_entry_get_text(GTK_ENTRY(gtk_builder_get_object(builder, "entry_remarks")));

        // 检查是否有冲突
        GtkTreePath *conflict_path = checkConflict(liststore, protocol, interface, srcip, dstip, srcport, dstport, stime, etime, NULL);
        if (conflict_path != NULL)
        {
            // 如果有冲突，提示用户
            GtkWidget *conflict_dialog = gtk_message_dialog_new(GTK_WINDOW(edit_dialog),
                                                                GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                GTK_MESSAGE_ERROR,
                                                                GTK_BUTTONS_CLOSE,
                                                                "Conflict with existing rules!");
            gtk_dialog_run(GTK_DIALOG(conflict_dialog));
            gtk_widget_destroy(conflict_dialog);
            // 滚动到冲突的行
            GtkTreeView *treeview = GTK_TREE_VIEW(data);
            // 清除之前的选择
            gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(treeview));
            gtk_tree_view_scroll_to_cell(treeview, conflict_path, NULL, FALSE, 1.0, 0.0);
            // 高亮冲突的行
            gtk_tree_selection_select_path(gtk_tree_view_get_selection(treeview), conflict_path);

            // 释放资源
            gtk_tree_path_free(conflict_path);
        }
        else
        {
            // 如果没有冲突，将新的一行写入database和ListStore并刷新TreeView，追加到设备文件尾部
            insertData(protocol, interface, srcip, dstip, srcport, dstport, stime, etime, block, remarks);
            appendDataToDeviceFile(protocol, interface, srcip, dstip, srcport, dstport, stime, etime, block);
            // 将新的一行写入ListStore
            GtkTreeIter iter;
            gtk_list_store_append(liststore, &iter);
            gtk_list_store_set(liststore, &iter,
                               1, protocol,
                               2, interface,
                               3, srcip,
                               4, dstip,
                               5, srcport,
                               6, dstport,
                               7, stime,
                               8, etime,
                               9, block,
                               10, remarks,
                               -1);
            // 刷新TreeView
            showData(liststore);
            // 提示用户添加成功
            GtkWidget *success_dialog = gtk_message_dialog_new(GTK_WINDOW(edit_dialog),
                                                               GTK_DIALOG_DESTROY_WITH_PARENT,
                                                               GTK_MESSAGE_INFO,
                                                               GTK_BUTTONS_CLOSE,
                                                               "Add successful!");
            gtk_dialog_run(GTK_DIALOG(success_dialog));
            gtk_widget_destroy(success_dialog);

            // 滚动到新添加的行（最后一行）
            GtkTreeView *treeview = GTK_TREE_VIEW(data);
            GtkTreePath *path = gtk_tree_path_new_from_indices(gtk_tree_model_iter_n_children(gtk_tree_view_get_model(treeview), NULL) - 1, -1);
            gtk_tree_view_scroll_to_cell(treeview, path, NULL, FALSE, 1.0, 0.0);
            // 高亮新添加的行
            gtk_tree_selection_select_path(gtk_tree_view_get_selection(treeview), path);
            gtk_tree_path_free(path);
        }
    }

    gtk_widget_destroy(edit_dialog);
    // 释放资源
    g_object_unref(builder);
}

// 将ESC映射到编辑对话框的Cancel按钮
gboolean on_edit_dialog_key_press_event(GtkWidget *widget, GdkEventKey *event, gpointer data)
{
    // 如果按下的是ESC键，将其映射到编辑对话框的Cancel按钮
    if (event->keyval == GDK_KEY_Escape)
    {
        gtk_dialog_response(GTK_DIALOG(widget), GTK_RESPONSE_CANCEL);
    }
    return FALSE;
}

// 如果entry_srcip或者entry_dstip的secondary icon被点击，弹出ip_popover
void on_ip_entry_icon_press(GtkEntry *entry, GtkEntryIconPosition icon_pos, GdkEvent *event, gpointer data)
{
    // 从data参数获取对应的popover对象
    GtkPopover *ip_popover = GTK_POPOVER(data);

    // 通过ip_popover子对象获取对应的ip_box对象
    GtkBox *ip_box = GTK_BOX(gtk_bin_get_child(GTK_BIN(ip_popover)));

    // 获取ip_box的子对象列表
    GList *children = gtk_container_get_children(GTK_CONTAINER(ip_box));

    // 获取ip_box的第一个子对象ip
    GtkWidget *first_child = GTK_WIDGET(g_list_nth_data(children, 0));

    // 获取ip的子对象列表(4个spinbutton对象)
    children = gtk_container_get_children(GTK_CONTAINER(first_child));

    // 获取spinbutton对象
    GtkWidget *spin1 = GTK_WIDGET(g_list_nth_data(children, 0));
    GtkWidget *spin2 = GTK_WIDGET(g_list_nth_data(children, 2));
    GtkWidget *spin3 = GTK_WIDGET(g_list_nth_data(children, 4));
    GtkWidget *spin4 = GTK_WIDGET(g_list_nth_data(children, 6));

    // 释放资源
    g_list_free(children);

    // 将entry对象附加到popover对象的数据
    g_object_set_data(G_OBJECT(ip_popover), "entry", entry);

    // 将spinbutton对象附加到popover对象的数据
    g_object_set_data(G_OBJECT(ip_popover), "spin1", spin1);
    g_object_set_data(G_OBJECT(ip_popover), "spin2", spin2);
    g_object_set_data(G_OBJECT(ip_popover), "spin3", spin3);
    g_object_set_data(G_OBJECT(ip_popover), "spin4", spin4);

    // 如果entry中有内容，将内容写入ip_popover中的spinbutton
    gchar *ip = (gchar *)gtk_entry_get_text(entry);
    if (strlen(ip))
    {
        // 将ip字符串分割为4个字符串
        gchar **ip_split = g_strsplit(ip, ".", 4);
        // 将4个字符串转换为4个整数
        gint ip1 = atoi(ip_split[0]);
        gint ip2 = atoi(ip_split[1]);
        gint ip3 = atoi(ip_split[2]);
        gint ip4 = atoi(ip_split[3]);
        // 将4个整数写入4个spinbutton
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin1), ip1);
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin2), ip2);
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin3), ip3);
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin4), ip4);
        // 释放资源
        g_strfreev(ip_split);
    }

    // 设置ip_popover的位置
    gtk_popover_set_relative_to(GTK_POPOVER(ip_popover), GTK_WIDGET(entry));

    // 显示ip_popover
    gtk_popover_popup(ip_popover);
}

// 将Enter映射到on_ip_entry_icon_press，将Delete映射到on_ip_clear_clicked
gboolean on_key_press_event_ip(GtkWidget *widget, GdkEventKey *event, gpointer data)
{
    // 如果按下的是Enter键，将其映射到on_ip_entry_icon_press
    if (event->keyval == GDK_KEY_Return)
    {
        on_ip_entry_icon_press(GTK_ENTRY(widget), GTK_ENTRY_ICON_SECONDARY, NULL, data);
    }
    // 如果按下的是Delete键，将其映射到on_ip_clear_clicked
    else if (event->keyval == GDK_KEY_Delete)
    {
        on_ip_clear_clicked(NULL, data);
    }
    return FALSE;
}

// 如果ip_popover的OK按钮被点击，将edit_dialog中对应的entry中的内容替换为用户输入的ip
void on_ip_ok_clicked(GtkButton *button, gpointer data)
{
    // 从data参数获取对应的popover对象
    GtkPopover *ip_popover = GTK_POPOVER(data);

    // 获取对应的entry对象
    GtkEntry *entry = GTK_ENTRY(g_object_get_data(G_OBJECT(ip_popover), "entry"));

    // 获取对应的spinbutton对象
    GtkSpinButton *ip1 = GTK_SPIN_BUTTON(g_object_get_data(G_OBJECT(ip_popover), "spin1"));
    GtkSpinButton *ip2 = GTK_SPIN_BUTTON(g_object_get_data(G_OBJECT(ip_popover), "spin2"));
    GtkSpinButton *ip3 = GTK_SPIN_BUTTON(g_object_get_data(G_OBJECT(ip_popover), "spin3"));
    GtkSpinButton *ip4 = GTK_SPIN_BUTTON(g_object_get_data(G_OBJECT(ip_popover), "spin4"));

    // 获取用户输入的ip
    gchar *ip = g_strdup_printf("%d.%d.%d.%d",
                                gtk_spin_button_get_value_as_int(ip1),
                                gtk_spin_button_get_value_as_int(ip2),
                                gtk_spin_button_get_value_as_int(ip3),
                                gtk_spin_button_get_value_as_int(ip4));

    // 将ip写入entry
    gtk_entry_set_text(entry, ip);
    // 释放资源
    g_free(ip);

    gtk_popover_popdown(ip_popover);
}

void on_ip_clear_clicked(GtkButton *button, gpointer data)
{
    // 从data参数获取对应的popover对象
    GtkPopover *ip_popover = GTK_POPOVER(data);

    // 获取对应的entry对象
    GtkEntry *entry = GTK_ENTRY(g_object_get_data(G_OBJECT(ip_popover), "entry"));

    // 清空entry中的内容
    gtk_entry_set_text(entry, "");

    // 隐藏ip_popover
    gtk_popover_popdown(ip_popover);
}

// 如果entry_srcport或者entry_dstport的secondary icon被点击，弹出port_popover
void on_port_entry_icon_press(GtkEntry *entry, GtkEntryIconPosition icon_pos, GdkEvent *event, gpointer data)
{
    // 从data参数获取对应的popover对象
    GtkPopover *port_popover = GTK_POPOVER(data);

    // 通过port_popover子对象获取对应的port_box对象
    GtkBox *port_box = GTK_BOX(gtk_bin_get_child(GTK_BIN(port_popover)));

    // 获取port_box的子对象列表
    GList *children = gtk_container_get_children(GTK_CONTAINER(port_box));

    // 获取port_box的第一个子对象port
    GtkWidget *port = GTK_WIDGET(g_list_nth_data(children, 0));

    // 释放资源
    g_list_free(children);

    // 将entry对象附加到popover对象的数据
    g_object_set_data(G_OBJECT(port_popover), "entry", entry);

    // 将prot(spinbutton)对象附加到popover对象的数据
    g_object_set_data(G_OBJECT(port_popover), "port", port);

    // 如果entry中有内容，将内容写入port_popover中的spinbutton
    gchar *port_str = (gchar *)gtk_entry_get_text(entry);
    if (strlen(port_str))
    {
        // 将port字符串转换为整数
        gint port_int = atoi(port_str);
        // 将整数写入spinbutton
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(port), port_int);
    }

    // 设置port_popover的位置
    gtk_popover_set_relative_to(GTK_POPOVER(port_popover), GTK_WIDGET(entry));

    // 显示port_popover
    gtk_popover_popup(port_popover);
}

// 将Enter映射到on_port_entry_icon_press，将Delete映射到on_port_clear_clicked
gboolean on_key_press_event_port(GtkWidget *widget, GdkEventKey *event, gpointer data)
{
    // 如果按下的是Enter键，将其映射到on_port_entry_icon_press
    if (event->keyval == GDK_KEY_Return)
    {
        on_port_entry_icon_press(GTK_ENTRY(widget), GTK_ENTRY_ICON_SECONDARY, NULL, data);
    }
    // 如果按下的是Delete键，将其映射到on_port_clear_clicked
    else if (event->keyval == GDK_KEY_Delete)
    {
        on_port_clear_clicked(NULL, data);
    }
    return FALSE;
}

// 如果port_popover的OK按钮被点击，将edit_dialog中对应的entry中的内容替换为用户输入的port
void on_port_ok_clicked(GtkButton *button, gpointer data)
{
    // 从data参数获取对应的popover对象
    GtkPopover *port_popover = GTK_POPOVER(data);

    // 获取对应的entry对象
    GtkEntry *entry = GTK_ENTRY(g_object_get_data(G_OBJECT(port_popover), "entry"));

    // 获取对应的spinbutton对象
    GtkSpinButton *port = GTK_SPIN_BUTTON(g_object_get_data(G_OBJECT(port_popover), "port"));

    // 获取用户输入的port
    gchar *port_str = g_strdup_printf("%d", gtk_spin_button_get_value_as_int(port));

    // 将port写入entry
    gtk_entry_set_text(entry, port_str);
    // 释放资源
    g_free(port_str);

    gtk_popover_popdown(port_popover);
}

// 如果port_popover的Clear按钮被点击，清空entry中的内容
void on_port_clear_clicked(GtkButton *button, gpointer data)
{
    // 从data参数获取对应的popover对象
    GtkPopover *port_popover = GTK_POPOVER(data);

    // 获取对应的entry对象
    GtkEntry *entry = GTK_ENTRY(g_object_get_data(G_OBJECT(port_popover), "entry"));

    // 清空entry中的内容
    gtk_entry_set_text(entry, "");

    // 隐藏port_popover
    gtk_popover_popdown(port_popover);
}

// 如果entry_stime或者entry_etime的secondary icon被点击，弹出time_popover
void on_time_entry_icon_press(GtkEntry *entry, GtkEntryIconPosition icon_pos, GdkEvent *event, gpointer data)
{
    // 从data参数获取对应的popover对象
    GtkPopover *time_popover = GTK_POPOVER(data);

    // 通过time_popover子对象获取对应的time_box对象
    GtkBox *time_box = GTK_BOX(gtk_bin_get_child(GTK_BIN(time_popover)));

    // 获取time_box的子对象列表
    GList *children = gtk_container_get_children(GTK_CONTAINER(time_box));

    // 获取time_box的第一个子对象time
    GtkWidget *time = GTK_WIDGET(g_list_nth_data(children, 0));

    // 释放资源
    g_list_free(children);

    // 获取time的第1个子对象date（GtkCalendar）
    GtkWidget *date = GTK_WIDGET(g_list_nth_data(gtk_container_get_children(GTK_CONTAINER(time)), 0));

    // 获取time的第2，4，6个子对象hour，minute，second（GtkSpinButton）
    GtkWidget *hour = GTK_WIDGET(g_list_nth_data(gtk_container_get_children(GTK_CONTAINER(time)), 1));
    GtkWidget *minute = GTK_WIDGET(g_list_nth_data(gtk_container_get_children(GTK_CONTAINER(time)), 3));
    GtkWidget *second = GTK_WIDGET(g_list_nth_data(gtk_container_get_children(GTK_CONTAINER(time)), 5));

    // 获取date的年月日
    gint year, month, day;
    gtk_calendar_get_date(GTK_CALENDAR(date), &year, &month, &day);

    // 获取hour，minute，second的值
    gint hour_int = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(hour));
    gint minute_int = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(minute));
    gint second_int = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(second));

    // 将entry对象附加到popover对象的数据
    g_object_set_data(G_OBJECT(time_popover), "entry", entry);

    // 将所有time附加到popover对象的数据
    g_object_set_data(G_OBJECT(time_popover), "date", date);
    g_object_set_data(G_OBJECT(time_popover), "hour", hour);
    g_object_set_data(G_OBJECT(time_popover), "minute", minute);
    g_object_set_data(G_OBJECT(time_popover), "second", second);

    // 如果entry中有内容，将内容写入time_popover中的Calendar和SpinButton
    gchar *time_str = (gchar *)gtk_entry_get_text(entry);
    if (strlen(time_str))
    {
        // 将time字符串先分割为日期和时间
        gchar **time_split = g_strsplit(time_str, " ", 2);
        // 将日期字符串分割为年月日
        gchar **date_split = g_strsplit(time_split[0], "-", 3);
        // 将时间字符串分割为时分秒
        gchar **time_split2 = g_strsplit(time_split[1], ":", 3);
        // 将年月日字符串转换为整数
        gint year_int = atoi(date_split[0]);
        gint month_int = atoi(date_split[1]);
        gint day_int = atoi(date_split[2]);
        // 将时分秒字符串转换为整数
        gint hour_int = atoi(time_split2[0]);
        gint minute_int = atoi(time_split2[1]);
        gint second_int = atoi(time_split2[2]);
        // 将整数写入Calendar和SpinButton
        gtk_calendar_select_month(GTK_CALENDAR(date), month_int - 1, year_int);
        gtk_calendar_select_day(GTK_CALENDAR(date), day_int);
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(hour), hour_int);
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(minute), minute_int);
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(second), second_int);
        // 释放资源
        g_strfreev(time_split);
        g_strfreev(date_split);
        g_strfreev(time_split2);
    }

    // 设置time_popover的位置
    gtk_popover_set_relative_to(GTK_POPOVER(time_popover), GTK_WIDGET(entry));

    // 显示time_popover
    gtk_popover_popup(time_popover);
}

// 将Enter映射到on_time_entry_icon_press，将Delete映射到on_time_clear_clicked
gboolean on_key_press_event_time(GtkWidget *widget, GdkEventKey *event, gpointer data)
{
    // 如果按下的是Enter键，将其映射到on_time_entry_icon_press
    if (event->keyval == GDK_KEY_Return)
    {
        on_time_entry_icon_press(GTK_ENTRY(widget), GTK_ENTRY_ICON_SECONDARY, NULL, data);
    }
    // 如果按下的是Delete键，将其映射到on_time_clear_clicked
    else if (event->keyval == GDK_KEY_Delete)
    {
        on_time_clear_clicked(NULL, data);
    }
    return FALSE;
}

// 如果time_popover的OK按钮被点击，将edit_dialog中对应的entry中的内容替换为用户输入的time
void on_time_ok_clicked(GtkButton *button, gpointer data)
{
    // 从data参数获取对应的popover对象
    GtkPopover *time_popover = GTK_POPOVER(data);

    // 获取对应的entry对象
    GtkEntry *entry = GTK_ENTRY(g_object_get_data(G_OBJECT(time_popover), "entry"));

    // 获取对应的Calendar对象
    GtkCalendar *date = GTK_CALENDAR(g_object_get_data(G_OBJECT(time_popover), "date"));

    // 获取date的年月日
    gint year, month, day;
    gtk_calendar_get_date(GTK_CALENDAR(date), &year, &month, &day);

    // 获取对应的SpinButton对象
    GtkSpinButton *hour = GTK_SPIN_BUTTON(g_object_get_data(G_OBJECT(time_popover), "hour"));
    GtkSpinButton *minute = GTK_SPIN_BUTTON(g_object_get_data(G_OBJECT(time_popover), "minute"));
    GtkSpinButton *second = GTK_SPIN_BUTTON(g_object_get_data(G_OBJECT(time_popover), "second"));

    // 获取hour，minute，second的值
    gint hour_int = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(hour));
    gint minute_int = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(minute));
    gint second_int = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(second));

    // 获取用户输入的time
    gchar *time_str = g_strdup_printf("%d-%02d-%02d %02d:%02d:%02d",
                                      year,
                                      month + 1,
                                      day,
                                      hour_int,
                                      minute_int,
                                      second_int);

    // 将time写入entry
    gtk_entry_set_text(entry, time_str);
    // 释放资源
    g_free(time_str);

    gtk_popover_popdown(time_popover);
}

// 如果time_popover的Clear按钮被点击，清空entry中的内容
void on_time_clear_clicked(GtkButton *button, gpointer data)
{
    // 从data参数获取对应的popover对象
    GtkPopover *time_popover = GTK_POPOVER(data);

    // 获取对应的entry对象
    GtkEntry *entry = GTK_ENTRY(g_object_get_data(G_OBJECT(time_popover), "entry"));

    // 清空entry中的内容
    gtk_entry_set_text(entry, "");

    // 隐藏time_popover
    gtk_popover_popdown(time_popover);
}

// 导出按钮回调函数, data为treeview
void on_export_button_clicked(GtkButton *button, gpointer data)
{
    // 如果没有选中任何行，给出相应的提示
    if (gtk_tree_selection_count_selected_rows(GTK_TREE_SELECTION(gtk_tree_view_get_selection(data))) == 0)
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
    if (res == GTK_RESPONSE_ACCEPT)
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
        // 如果导出失败，提示用户导出失败
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
    GtkTreeSelection *selection = GTK_TREE_SELECTION(data);
    if (gtk_tree_selection_count_selected_rows(selection) == 0)
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
        GtkTreeView *treeview = GTK_TREE_VIEW(gtk_tree_selection_get_tree_view(selection));
        // 获取liststore
        GtkListStore *liststore = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
        // 获取选中的行
        GList *selectedRows = gtk_tree_selection_get_selected_rows(selection, NULL);
        GList *lastRow = g_list_last(selectedRows);
        int count = g_list_length(selectedRows);

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

        // 释放内存
        g_list_free(selectedRows);

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
    }
    else
    {
        // 如果用户选择了否，关闭对话框
        gtk_widget_destroy(confirm_dialog);
    }
}

// 将Delete按键映射为delete_button的回调函数
gboolean on_key_press_event(GtkWidget *widget, GdkEventKey *event, gpointer data)
{
    if (event->keyval == GDK_KEY_Delete)
    {
        on_delete_button_clicked(NULL, data); // 调用你的删除按钮点击事件处理函数
        return TRUE;                          // 表示事件已处理
    }

    return FALSE; // 表示事件未处理
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

// 双击treeview中的行或选择treeview中的行后点击Enter时，弹出编辑对话框
void on_treeview_row_activated(GtkTreeView *treeview, GtkTreePath *path, GtkTreeViewColumn *column, gpointer data)
{
    // 从glade文件中获取edit对话框
    GtkBuilder *builder = gtk_builder_new_from_resource("/glade/edit.glade");
    GtkWidget *edit_dialog = GTK_WIDGET(gtk_builder_get_object(builder, "edit_dialog"));
    GtkComboBoxText *combox_protocol = GTK_COMBO_BOX_TEXT(gtk_builder_get_object(builder, "combox_protocol"));
    GtkEntry *entry_interface = GTK_ENTRY(gtk_builder_get_object(builder, "entry_interface"));
    GtkEntry *entry_srcip = GTK_ENTRY(gtk_builder_get_object(builder, "entry_srcip"));
    GtkEntry *entry_dstip = GTK_ENTRY(gtk_builder_get_object(builder, "entry_dstip"));
    GtkEntry *entry_srcport = GTK_ENTRY(gtk_builder_get_object(builder, "entry_srcport"));
    GtkEntry *entry_dstport = GTK_ENTRY(gtk_builder_get_object(builder, "entry_dstport"));
    GtkEntry *entry_stime = GTK_ENTRY(gtk_builder_get_object(builder, "entry_stime"));
    GtkEntry *entry_etime = GTK_ENTRY(gtk_builder_get_object(builder, "entry_etime"));
    GtkCheckButton *ckbt_block = GTK_CHECK_BUTTON(gtk_builder_get_object(builder, "ckbt_block"));
    GtkEntry *entry_remarks = GTK_ENTRY(gtk_builder_get_object(builder, "entry_remarks"));

    // 将双击的行的内容写入对话框中
    GtkListStore *liststore = GTK_LIST_STORE(data);
    GtkTreeIter iter;
    gtk_tree_model_get_iter(GTK_TREE_MODEL(liststore), &iter, path);
    gchar *protocol, *interface, *srcip, *dstip, *srcport, *dstport, *stime, *etime, *remarks;
    gboolean block;
    gtk_tree_model_get(GTK_TREE_MODEL(liststore), &iter,
                       1, &protocol,
                       2, &interface,
                       3, &srcip,
                       4, &dstip,
                       5, &srcport,
                       6, &dstport,
                       7, &stime,
                       8, &etime,
                       9, &block,
                       10, &remarks,
                       -1);
    gtk_combo_box_text_append(combox_protocol, NULL, protocol);
    gtk_entry_set_text(entry_interface, interface);
    gtk_entry_set_text(entry_srcip, srcip);
    gtk_entry_set_text(entry_dstip, dstip);
    gtk_entry_set_text(entry_srcport, srcport);
    gtk_entry_set_text(entry_dstport, dstport);
    gtk_entry_set_text(entry_stime, stime);
    gtk_entry_set_text(entry_etime, etime);
    // checkbutton的状态
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ckbt_block), block);
    gtk_entry_set_text(entry_remarks, remarks);
    // 连接builder中的信号
    gtk_builder_connect_signals(builder, NULL);
    // 连接关闭信号处理函数
    g_signal_connect(edit_dialog, "destroy", G_CALLBACK(gtk_widget_destroy), NULL);
    // 运行对话框并等待用户选择
    // 保持对话框在最上层
    gtk_window_set_keep_above(GTK_WINDOW(edit_dialog), TRUE);
    gint res = gtk_dialog_run(GTK_DIALOG(edit_dialog));

    if (res == GTK_RESPONSE_OK)
    {
        // 获取entry中的内容
        // protocol的内容从comboboxtext中获取
        protocol = gtk_combo_box_text_get_active_text(combox_protocol);
        interface = (gchar *)gtk_entry_get_text(entry_interface);
        srcip = (gchar *)gtk_entry_get_text(entry_srcip);
        dstip = (gchar *)gtk_entry_get_text(entry_dstip);
        srcport = (gchar *)gtk_entry_get_text(entry_srcport);
        dstport = (gchar *)gtk_entry_get_text(entry_dstport);
        stime = (gchar *)gtk_entry_get_text(entry_stime);
        etime = (gchar *)gtk_entry_get_text(entry_etime);
        block = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt_block));
        remarks = (gchar *)gtk_entry_get_text(entry_remarks);

        // 检查是否有冲突
        GtkTreePath *conflict_path = checkConflict(liststore, protocol, interface, srcip, dstip, srcport, dstport, stime, etime, path);
        if (conflict_path != NULL)
        {
            // 如果有冲突，提示用户
            GtkWidget *conflict_dialog = gtk_message_dialog_new(GTK_WINDOW(edit_dialog),
                                                                GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                GTK_MESSAGE_ERROR,
                                                                GTK_BUTTONS_CLOSE,
                                                                "Conflict with existing rules!");
            gtk_dialog_run(GTK_DIALOG(conflict_dialog));
            gtk_widget_destroy(conflict_dialog);
            // 清除之前的选择
            gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(treeview));
            // 滚动到冲突的行
            gtk_tree_view_scroll_to_cell(treeview, conflict_path, NULL, FALSE, 1.0, 0.0);
            // 选中冲突的行
            gtk_tree_selection_select_path(gtk_tree_view_get_selection(treeview), conflict_path);
            // 释放资源
            gtk_tree_path_free(conflict_path);
        }
        else
        {
            // 如果没有冲突，修改数据库中的记录和treeview中的记录
            // 获取双击的行（path和id）
            GtkTreeIter iter;
            gtk_tree_model_get_iter(GTK_TREE_MODEL(liststore), &iter, path);
            gint id;
            gtk_tree_model_get(GTK_TREE_MODEL(liststore), &iter, 0, &id, -1);

            if (!updateData(id, protocol, interface, srcip, dstip, srcport, dstport, stime, etime, block, remarks))
            {
                // 提示用户修改数据库失败
                GtkWidget *error_dialog = gtk_message_dialog_new(GTK_WINDOW(edit_dialog),
                                                                 GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                 GTK_MESSAGE_ERROR,
                                                                 GTK_BUTTONS_CLOSE,
                                                                 "Update database failed! Please check permissions!");
                gtk_dialog_run(GTK_DIALOG(error_dialog));
                gtk_widget_destroy(error_dialog);
                return;
            }
            // 修改treeview中的记录
            gtk_list_store_set(liststore, &iter,
                               1, protocol,
                               2, interface,
                               3, srcip,
                               4, dstip,
                               5, srcport,
                               6, dstport,
                               7, stime,
                               8, etime,
                               9, block,
                               10, remarks,
                               -1);

            // 提示用户编辑成功
            GtkWidget *success_dialog = gtk_message_dialog_new(GTK_WINDOW(edit_dialog),
                                                               GTK_DIALOG_DESTROY_WITH_PARENT,
                                                               GTK_MESSAGE_INFO,
                                                               GTK_BUTTONS_CLOSE,
                                                               "Edit successful!");
            gtk_dialog_run(GTK_DIALOG(success_dialog));
            gtk_widget_destroy(success_dialog);

            // 释放资源
            gtk_tree_path_free(conflict_path);
        }
    }

    gtk_widget_destroy(edit_dialog);
    // 释放资源
    g_object_unref(builder);
}

