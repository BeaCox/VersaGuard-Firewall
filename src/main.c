#include <gtk/gtk.h>
// 暗黑模式切换回调函数
void on_dark_toggle_button_toggled(GtkToggleButton *toggle_button, gpointer data) {
    gboolean active = gtk_toggle_button_get_active(toggle_button);
    
    if (active) {
        // 应用暗黑模式样式
        GtkSettings *settings = gtk_settings_get_default();
        g_object_set(settings, "gtk-application-prefer-dark-theme", TRUE, NULL);
        
        // 切换按钮图标为太阳
        gtk_button_set_image(GTK_BUTTON(toggle_button), gtk_image_new_from_icon_name("weather-clear-symbolic", GTK_ICON_SIZE_BUTTON));
    } else {
        // 应用默认（亮色）模式样式
        GtkSettings *settings = gtk_settings_get_default();
        g_object_set(settings, "gtk-application-prefer-dark-theme", FALSE, NULL);
        
        // 切换按钮图标为月亮
        gtk_button_set_image(GTK_BUTTON(toggle_button), gtk_image_new_from_icon_name("weather-clear-night-symbolic", GTK_ICON_SIZE_BUTTON));
    }
}
// 关于按钮回调函数（传入主窗口指针）
void on_about_button_clicked(GtkButton *button, gpointer data, GtkWidget *main_window) {
    //从glade文件中获取about对话框
    GtkBuilder *builder = gtk_builder_new_from_file("../ui/about.glade");
    GtkWidget *about_dialog = GTK_WIDGET(gtk_builder_get_object(builder, "about_dialog"));
    // 禁用主窗口
    gtk_widget_set_sensitive(GTK_WIDGET(main_window), FALSE);
    // 保持对话框在最上层
    gtk_window_set_keep_above(GTK_WINDOW(about_dialog), TRUE);
    //显示about对话框
    gtk_dialog_run(GTK_DIALOG(about_dialog));
    // 点击按钮后销毁对话框
    gtk_widget_destroy(about_dialog);
    // 启用主窗口
    gtk_widget_set_sensitive(GTK_WIDGET(main_window), TRUE);
}
// 添加按钮回调函数
void on_add_button_clicked(GtkButton *button, gpointer data) {
    //从glade文件中获取add对话框和popover_cancel
    GtkBuilder *builder = gtk_builder_new_from_file("../ui/edit.glade");
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
    //显示add对话框
    gtk_dialog_run(GTK_DIALOG(edit_dialog));
    // 点击button_ok后销毁对话框
    g_signal_connect(button_ok, "clicked", G_CALLBACK(gtk_widget_destroy), edit_dialog);
    // 点击btn_yes后销毁对话框和popover_cancel
    g_signal_connect(btn_yes, "clicked", G_CALLBACK(gtk_widget_destroy), edit_dialog);

    // 销毁edit_dialog
    gtk_widget_destroy(edit_dialog);
}

int main(int argc, char *argv[]) {
    GtkBuilder *builder;
    GtkWidget *window;
    // main_grid
    GtkWidget *main_grid;
    // headerbar
    GtkWidget *headerbar;
    // dark_toggle_button
    GtkWidget *dark_toggle_button;
    // about_button
    GtkWidget *about_button;
    // menu_grid
    GtkWidget *menu_grid;
    // edit_grid
    GtkWidget *edit_grid;
    // import_button
    GtkWidget *import_button;
    // add_button
    GtkWidget *add_button;
    // export_button
    GtkWidget *export_button;
    // delete_button
    GtkWidget *delete_button;
    // search_entry
    GtkWidget *search_entry;
    // scroll window
    GtkWidget *scrolledWindow;
    // treeview
    GtkTreeView *treeview;
    // list store
    GtkListStore *liststore;
    // selection
    GtkTreeSelection *selection;
    // list store column * 3
    GtkTreeViewColumn *c0;
    GtkTreeViewColumn *c1;
    GtkTreeViewColumn *c2;
    // list store column * 3
    GtkCellRenderer *cr0;
    GtkCellRenderer *cr1;
    GtkCellRenderer *cr2;

    gtk_init(&argc, &argv);
    
    // 加载Glade布局文件
    builder = gtk_builder_new_from_file ("../ui/main.glade");
    
    // 获取窗口
    window = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));
    
    // 连接关闭信号处理函数
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
        
    // 连接builder中的信号
    gtk_builder_connect_signals(builder, NULL);

    // 获取所有对象
    main_grid           = GTK_WIDGET(gtk_builder_get_object(builder, "main_grid"));
    headerbar           = GTK_WIDGET(gtk_builder_get_object(builder, "headerbar"));
    dark_toggle_button  = GTK_WIDGET(gtk_builder_get_object(builder, "dark_toggle_button"));
    about_button        = GTK_WIDGET(gtk_builder_get_object(builder, "about_button"));
    menu_grid           = GTK_WIDGET(gtk_builder_get_object(builder, "menu_grid"));
    edit_grid           = GTK_WIDGET(gtk_builder_get_object(builder, "edit_grid"));
    import_button       = GTK_WIDGET(gtk_builder_get_object(builder, "import_button"));
    add_button          = GTK_WIDGET(gtk_builder_get_object(builder, "add_button"));
    export_button       = GTK_WIDGET(gtk_builder_get_object(builder, "export_button"));
    delete_button       = GTK_WIDGET(gtk_builder_get_object(builder, "delete_button"));
    search_entry        = GTK_WIDGET(gtk_builder_get_object(builder, "search_entry"));
    scrolledWindow      = GTK_WIDGET(gtk_builder_get_object(builder, "scrolledWindow"));
    treeview            = GTK_TREE_VIEW(gtk_builder_get_object(builder, "treeview"));
    liststore           = GTK_LIST_STORE(gtk_builder_get_object(builder, "liststore"));
    selection           = GTK_TREE_SELECTION(gtk_builder_get_object(builder, "selection"));
    c0                  = GTK_TREE_VIEW_COLUMN(gtk_builder_get_object(builder, "c0"));
    c1                  = GTK_TREE_VIEW_COLUMN(gtk_builder_get_object(builder, "c1"));
    c2                  = GTK_TREE_VIEW_COLUMN(gtk_builder_get_object(builder, "c2"));
    cr0                 = GTK_CELL_RENDERER(gtk_builder_get_object(builder, "cr0"));
    cr1                 = GTK_CELL_RENDERER(gtk_builder_get_object(builder, "cr1"));
    cr2                 = GTK_CELL_RENDERER(gtk_builder_get_object(builder, "cr2"));

    // 显示窗口
    gtk_widget_show_all(window);
    
    // 进入主循环
    gtk_main();
    
    return 0;
}

