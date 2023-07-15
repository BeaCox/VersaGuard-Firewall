#include "logs.h"

static off_t size = 0; // 记录文件大小

// 监视日志文件的回调函数，当文件变化时调用

void file_changed_callback(GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event_type, gpointer user_data)
{
    GtkTextView *textview = GTK_TEXT_VIEW(user_data);
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(textview);

    if (event_type == G_FILE_MONITOR_EVENT_CHANGED)
    {
        // 文件发生改变，处理文件变化事件
        // 获取文件大小
        struct stat st;
        gchar *filename = g_file_get_path(file);
        stat(filename, &st);
        off_t new_size = st.st_size;
        // 如果文件大小没有变化，直接返回
        if (new_size == size)
            return;

        // 文件大小变化，读取新增内容
        char buf[LOG_BUF_SIZE];
        memset(buf, 0, LOG_BUF_SIZE);

        FILE *fp = fopen(filename, "r");
        if (fp == NULL)
        {
            perror("fopen");
            exit(1);
        }
        fseek(fp, size, SEEK_SET);
        fread(buf, 1, new_size - size, fp);

        GtkTextIter iter;
        gtk_text_buffer_get_end_iter(buffer, &iter);

        GtkTextTag *common_tag = gtk_text_buffer_create_tag(buffer, "common", "size", 12 * PANGO_SCALE, "font", "Monospace", NULL);
        GtkTextTag *warning_tag = gtk_text_buffer_create_tag(buffer, "warning", "foreground", "red", "weight", PANGO_WEIGHT_BOLD, "size", 12 * PANGO_SCALE, "font", "Monospace", NULL);
        GtkTextTag *time_tag = gtk_text_buffer_create_tag(buffer, "time", "foreground", "green", "weight", PANGO_WEIGHT_BOLD, "size", 12 * PANGO_SCALE, "font", "Monospace", NULL);
        GtkTextTag *tcp_tag = gtk_text_buffer_create_tag(buffer, "tcp", "foreground", "blue", "weight", PANGO_WEIGHT_BOLD, "size", 12 * PANGO_SCALE, "font", "Monospace", NULL);
        GtkTextTag *udp_tag = gtk_text_buffer_create_tag(buffer, "udp", "foreground", "pink", "weight", PANGO_WEIGHT_BOLD, "size", 12 * PANGO_SCALE, "font", "Monospace", NULL);
        GtkTextTag *icmp_tag = gtk_text_buffer_create_tag(buffer, "icmp", "foreground", "purple", "weight", PANGO_WEIGHT_BOLD, "size", 12 * PANGO_SCALE, "font", "Monospace", NULL);

        // 每一行的不同字段用不同的tag显示
        char *line = strtok(buf, "\n");
        while (line != NULL)
        {
            // 获取行的第一个字段（时间，格式为XXXX-XX-XX XX:XX:XX）
            char *date = strtok(line, " ");
            char *time = strtok(NULL, " ");

            // 拼接时间
            char time_str[24];
            memset(time_str, 0, 24);
            sprintf(time_str, "%s %s", date, time);
            // 应用time_tag（补充完整前面的[）
            gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, "[", -1, "time", NULL);
            gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, time_str, -1, "time", NULL);
            // 插入空格
            gtk_text_buffer_insert(buffer, &iter, " ", -1);
            // 获取行的第二个字段（协议）
            char *protocol = strtok(NULL, " ");
            // 应用protocol_tag
            if (strcmp(protocol, "TCP") == 0)
            {
                gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, protocol, -1, "tcp", NULL);
            }
            else if (strcmp(protocol, "UDP") == 0)
            {
                gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, protocol, -1, "udp", NULL);
            }
            else if (strcmp(protocol, "ICMP") == 0)
            {
                gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, protocol, -1, "icmp", NULL);
            }
            // 插入空格
            gtk_text_buffer_insert(buffer, &iter, " ", -1);
            // 获取字符串剩下的部分
            char *rest = strtok(NULL, "");
            // 应用common_tag
            gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, rest, -1, "common", NULL);
            // 插入换行
            gtk_text_buffer_insert(buffer, &iter, "\n", -1);
            // 获取下一行
            line = strtok(NULL, "\n");
        }

        // 更新文件大小
        size = new_size;

        // 关闭文件
        fclose(fp);
    }

    return;
}

// 建立log文件的软连接
void createLogLink()
{
    // APP_DIR/LOG_FILE到LOG_DIR/LOG_FILE的软连接，需要root权限
    char log_file[PATH_MAX];
    memset(log_file, 0, PATH_MAX);
    sprintf(log_file, "%s/%s", LOG_DIR, LOG_FILE);
    // 初始化文件大小
    struct stat st;
    stat(log_file, &st);
    size = st.st_size;
    char app_log_file[PATH_MAX];
    memset(app_log_file, 0, PATH_MAX);
    sprintf(app_log_file, "%s/%s/%s", g_get_home_dir(), APP_DIR, LOG_FILE);

    // 如果软连接不存在，创建软连接
    if (access(app_log_file, F_OK) != 0)
    {
        symlink(log_file, app_log_file);
    }
}

