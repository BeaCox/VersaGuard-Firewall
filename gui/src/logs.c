#include "logs.h"

// 监视日志文件的线程，一旦有更新，就更新日志显示到textview

void* watchLog(void* data)
{
    char log_file[PATH_MAX];
    memset(log_file, 0, PATH_MAX);
    sprintf(log_file, "%s/%s", LOG_DIR, LOG_FILE);
    // 获取textview
    GtkTextView* textview = GTK_TEXT_VIEW(data);
    GtkTextBuffer* buffer = gtk_text_view_get_buffer(textview);
    // 创建tag
    GtkTextTag* tag1 = gtk_text_buffer_create_tag(buffer, "mono-spaced", "family", "monospace", NULL);
    GtkTextTag* tag2 = gtk_text_buffer_create_tag(buffer, "12", "size", 12 * PANGO_SCALE, NULL);
    GtkTextTag* tag3 = gtk_text_buffer_create_tag(buffer, "green_foreground", "foreground", "green", NULL);
    GtkTextTag* warning_tag = gtk_text_buffer_create_tag(buffer, "warning", "foreground", "red", "weight", PANGO_WEIGHT_BOLD, "size", 12 * PANGO_SCALE, NULL);

    // 打开日志文件
    FILE* fp = fopen(log_file, "r");
    if (fp == NULL)
    {
        // 日志文件打开失败，在textview中显示错误信息，提示用户先安装内核模块
        GtkTextIter iter;
        gtk_text_buffer_get_end_iter(buffer, &iter);
        gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, "Failed to open log file! Please install kernel module and restart!\n", -1, "warning", NULL);
        return NULL;
    }

    // 获取文件描述符
    int fd = fileno(fp);

    // 获取文件大小
    struct stat st;
    stat(log_file, &st);
    off_t size = st.st_size;

    // 读取文件内容
    char buf[LOG_BUF_SIZE];
    memset(buf, 0, LOG_BUF_SIZE);

    // 监视文件描述符
    while (TRUE)
    {
        // 休眠1秒
        g_usleep(1000000);

        // 获取文件大小
        stat(log_file, &st);
        off_t new_size = st.st_size;

        // 如果文件大小没有变化，继续休眠
        if (new_size == size)
            continue;

        // 文件大小变化，读取新增内容
        memset(buf, 0, LOG_BUF_SIZE);
        fp = fopen(log_file, "r");
        if (fp == NULL)
        {
            perror("fopen");
            exit(1);
        }
        fseek(fp, size, SEEK_SET);
        fread(buf, 1, new_size - size, fp);

        // 将新增内容显示到textview
        GtkTextIter iter;
        gtk_text_buffer_get_end_iter(buffer, &iter);
        gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, buf, -1, "mono-spaced", "12", "green_foreground", NULL);
        // 更新文件大小
        size = new_size;

        // 关闭文件
        fclose(fp);
    }

    return NULL;
}

// 建立log文件的软连接
void createLogLink()
{
    // APP_DIR/LOG_FILE到LOG_DIR/LOG_FILE的软连接，需要root权限
    char log_file[PATH_MAX];
    memset(log_file, 0, PATH_MAX);
    sprintf(log_file, "%s/%s", LOG_DIR, LOG_FILE);
    char app_log_file[PATH_MAX];
    memset(app_log_file, 0, PATH_MAX);
    sprintf(app_log_file, "%s/%s/%s", g_get_home_dir(), APP_DIR, LOG_FILE);

    // 如果软连接不存在，创建软连接
    if (access(app_log_file, F_OK) != 0) {
        symlink(log_file, app_log_file);
    }
}


