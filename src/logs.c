#include "logs.h"

// 监视日志文件的线程，一旦有更新，就更新日志显示到textview
#define LOG_BUF_SIZE 1024
#define LOG_FILE "./logs.txt"

void* watchLog(void* data)
{
    // 获取textview
    GtkTextView* textview = GTK_TEXT_VIEW(data);
    GtkTextBuffer* buffer = gtk_text_view_get_buffer(textview);
    // 创建tag
    GtkTextTag* tag1 = gtk_text_buffer_create_tag(buffer, "mono-spaced", "family", "monospace", NULL);
    GtkTextTag* tag2 = gtk_text_buffer_create_tag(buffer, "12", "size", 12 * PANGO_SCALE, NULL);
    GtkTextTag* tag3 = gtk_text_buffer_create_tag(buffer, "green_foreground", "foreground", "green", NULL);

    // 打开日志文件
    FILE* fp = fopen(LOG_FILE, "r");
    if (fp == NULL)
    {
        perror("fopen");
        exit(1);
    }

    // 获取文件描述符
    int fd = fileno(fp);

    // 获取文件大小
    struct stat st;
    stat(LOG_FILE, &st);
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
        stat(LOG_FILE, &st);
        off_t new_size = st.st_size;

        // 如果文件大小没有变化，继续休眠
        if (new_size == size)
            continue;

        // 文件大小变化，读取新增内容
        memset(buf, 0, LOG_BUF_SIZE);
        fp = fopen(LOG_FILE, "r");
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
