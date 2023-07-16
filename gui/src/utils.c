#include "utils.h"

// 检查规则是否冲突，如果冲突，返回具体冲突规则的path，否则返回NULL（为便于编辑时检查冲突，将编辑的行的path传入, path默认为NULL，表示新增规则）
GtkTreePath *checkConflict(GtkListStore *liststore, gchar *protocol, gchar *interface, gchar *srcip, gchar *dstip, gchar *srcport, gchar *dstport, gchar *stime, gchar *etime, GtkTreePath *path)
{
    GtkTreeIter iter;
    gboolean valid;
    gboolean flag = FALSE; // 标记是否已出现编辑的行

    // 遍历ListStore中的每一行
    valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(liststore), &iter);

    // 如果ListStore为空，直接返回NULL
    if (!valid)
        return NULL;

    // 存储每一行的数据
    gchar *storedProtocol, *storedInterface, *storedSrcIP, *storedDstIP, *storedSrcPort, *storedDstPort, *storedSTime, *storedETime;
    GtkTreePath *conflict_path = NULL;

    while (valid)
    {
        // 如果是编辑的行，跳过（只可能出现一次，用flag标记）
        if (path != NULL && !flag && gtk_tree_path_compare(path, gtk_tree_model_get_path(GTK_TREE_MODEL(liststore), &iter)) == 0)
        {
            flag = TRUE;
            valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(liststore), &iter);
            continue;
        }

        gtk_tree_model_get(GTK_TREE_MODEL(liststore), &iter,
                            1, &storedProtocol,
                            2, &storedInterface,
                            3, &storedSrcIP,
                            4, &storedDstIP,
                            5, &storedSrcPort,
                            6, &storedDstPort,
                            7, &storedSTime,
                            8, &storedETime,
                            -1);

        // 进行冲突检查
        if (g_strcmp0(storedProtocol, protocol) == 0 &&
            g_strcmp0(storedInterface, interface) == 0 &&
            g_strcmp0(storedSrcIP, srcip) == 0 &&
            g_strcmp0(storedDstIP, dstip) == 0 &&
            g_strcmp0(storedSrcPort, srcport) == 0 &&
            g_strcmp0(storedDstPort, dstport) == 0 &&
            g_strcmp0(storedSTime, stime) == 0 &&
            g_strcmp0(storedETime, etime) == 0)
        {
            // 规则冲突，返回冲突的行的路径
            conflict_path = gtk_tree_model_get_path(GTK_TREE_MODEL(liststore), &iter);
            break;
        }

        valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(liststore), &iter);
    }

    return conflict_path;
}

void on_search_entry_search_changed(GtkSearchEntry *searchentry, gpointer data)
{
    GtkTreeView *treeview = GTK_TREE_VIEW(data);
    GtkTreeModel *model = gtk_tree_view_get_model(treeview);

    // 获取搜索框中的文本
    const gchar *search_text = gtk_entry_get_text(GTK_ENTRY(searchentry));

    GtkTreeSelection *selection = gtk_tree_view_get_selection(treeview);
    gtk_tree_selection_unselect_all(selection); // 清除之前的选择

    // 如果搜索框中的文本为空，直接返回
    if (strlen(search_text) == 0)
        return;

    GtkTreeIter iter;
    gboolean valid = gtk_tree_model_get_iter_first(model, &iter);
    gboolean first_match = TRUE; // 用于记录第一个匹配的行

    while (valid)
    {
        gchar *storedProtocol, *storedInterface, *storedSrcIP, *storedDstIP, *storedSrcPort, *storedDstPort, *storedSTime, *storedETime, *storedRemrks;
        gtk_tree_model_get(model, &iter,
                           1, &storedProtocol,
                            2, &storedInterface,
                            3, &storedSrcIP,
                            4, &storedDstIP,
                            5, &storedSrcPort,
                            6, &storedDstPort,
                            7, &storedSTime,
                            8, &storedETime,
                            10, &storedRemrks,
                           -1);

        // 进行搜索(只要有一个字段包含搜索文本即可，对大小写不敏感)
        gchar *lower_text = g_ascii_strdown(search_text, -1);
        gboolean match =    (storedProtocol != NULL && strstr(g_ascii_strdown(storedProtocol, -1), lower_text) != NULL) ||
                            (storedInterface != NULL && strstr(g_ascii_strdown(storedInterface, -1), lower_text) != NULL) ||
                            (storedSrcIP != NULL && strstr(g_ascii_strdown(storedSrcIP, -1), lower_text) != NULL) ||
                            (storedDstIP != NULL && strstr(g_ascii_strdown(storedDstIP, -1), lower_text) != NULL) ||
                            (storedSrcPort != NULL && strstr(g_ascii_strdown(storedSrcPort, -1), lower_text) != NULL) ||
                            (storedDstPort != NULL && strstr(g_ascii_strdown(storedDstPort, -1), lower_text) != NULL) ||
                            (storedSTime != NULL && strstr(g_ascii_strdown(storedSTime, -1), lower_text) != NULL) ||
                            (storedETime != NULL && strstr(g_ascii_strdown(storedETime, -1), lower_text) != NULL) ||
                            (storedRemrks != NULL && strstr(g_ascii_strdown(storedRemrks, -1), lower_text) != NULL);

        if (match)
        {
            // 高亮匹配的行
            GtkTreePath *path = gtk_tree_model_get_path(model, &iter);
            gtk_tree_selection_select_path(selection, path);

            if (first_match)
            {
                // 滚动到第一个匹配的行
                gtk_tree_view_scroll_to_cell(treeview, path, NULL, TRUE, 1.0, 0);
                first_match = FALSE;
            }

            gtk_tree_path_free(path);
        }

        valid = gtk_tree_model_iter_next(model, &iter);
    }
}


// 检查设备文件权限功能
gboolean checkPermission()
{
    // 检查文件的读写权限，0为有权限，-1为无权限。两个权限都有返回1，否则返回0
    return access(DEVICE_FILE, R_OK | W_OK) == 0;
}


// 检查内核模块是否加载
gboolean checkModule()
{
    // 执行lsmod | grep命令，检查是否加载了VersaGuard_ker模块
    char command[256];
    sprintf(command, "lsmod | grep %s", MODULE_NAME);

    FILE *lsmodOutput = popen(command, "r");
    if (lsmodOutput)
    {
        char line[256];
        if (fgets(line, sizeof(line), lsmodOutput))
        {
            pclose(lsmodOutput);
            return 1; // 内核模块已加载
        }
        pclose(lsmodOutput);
    }

    // 检查当前目录下是否有VersaGuard_ker.ko文件
    // MODULE_NAME.ko为内核模块的文件名
    if (access(MODULE_NAME ".ko", F_OK) == 0){
        system("insmod " MODULE_NAME ".ko"); // 加载内核模块
        return 1; // 内核模块已加载
    }

    return 0; // 内核模块未加载
}
