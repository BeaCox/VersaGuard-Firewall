#include "utils.h"

// 检查规则是否冲突，如果冲突，返回具体冲突规则的path，否则返回NULL（为便于编辑时检查冲突，将编辑的行的path传入, path默认为NULL，表示新增规则）
GtkTreePath *checkConflict(GtkListStore *liststore, gchar *protocol, gchar *srcip, gchar *dstip, gchar *srcport, gchar *dstport, gchar *stime, gchar *etime, GtkTreePath *path){
    GtkTreeIter iter;
    gboolean valid;
    gboolean flag = FALSE; // 标记是否已出现编辑的行

    // 遍历ListStore中的每一行
    valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(liststore), &iter);

    // 如果ListStore为空，直接返回NULL
    if (!valid)
        return NULL;

    // 存储每一行的数据
    gchar *storedProtocol, *storedSrcIP, *storedDstIP, *storedSrcPort, *storedDstPort, *storedSTime, *storedETime;


    while (valid) {

        // 如果是编辑的行，跳过（只可能出现一次，用flag标记）
        if(path != NULL && !flag && gtk_tree_path_compare(path, gtk_tree_model_get_path(GTK_TREE_MODEL(liststore), &iter)) == 0){
            flag = TRUE;
            valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(liststore), &iter);
            continue;
        }

        gtk_tree_model_get(GTK_TREE_MODEL(liststore), &iter,
                           1, &storedProtocol,
                           2, &storedSrcIP,
                           3, &storedDstIP,
                           4, &storedSrcPort,
                           5, &storedDstPort,
                           6, &storedSTime,
                           7, &storedETime,
                           -1);

        // 进行冲突检查
        if (g_strcmp0(storedProtocol, protocol) == 0 &&
            g_strcmp0(storedSrcIP, srcip) == 0 &&
            g_strcmp0(storedDstIP, dstip) == 0 &&
            g_strcmp0(storedSrcPort, srcport) == 0 &&
            g_strcmp0(storedDstPort, dstport) == 0 &&
            g_strcmp0(storedSTime, stime) == 0 &&
            g_strcmp0(storedETime, etime) == 0) {
            // 规则冲突，返回冲突的行的路径
            // 释放资源
            // g_free(storedProtocol);
            // if(strlen(storedSrcIP))
            //     g_free(storedSrcIP);
            // if(strlen(storedDstIP))
            //     g_free(storedDstIP);
            // if(strlen(storedSrcPort))
            //     g_free(storedSrcPort);
            // if(strlen(storedDstPort))
            //     g_free(storedDstPort);
            // if(strlen(storedSTime)) 
            //     g_free(storedSTime);
            // if(strlen(storedETime))
            //     g_free(storedETime);
            return gtk_tree_model_get_path(GTK_TREE_MODEL(liststore), &iter);
        }

        // 获取下一行
        valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(liststore), &iter);
    }

    // 释放资源
    // g_free(storedProtocol);
    // if(strlen(storedSrcIP))
    //     g_free(storedSrcIP);
    // if(strlen(storedDstIP))
    //     g_free(storedDstIP);
    // if(strlen(storedSrcPort))
    //     g_free(storedSrcPort);
    // if(strlen(storedDstPort))
    //     g_free(storedDstPort);
    // if(strlen(storedSTime)) 
    //     g_free(storedSTime);
    // if(strlen(storedETime))
    //     g_free(storedETime);

    return NULL;
}