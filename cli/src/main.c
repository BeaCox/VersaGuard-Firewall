#include "common.h"
#include "cmd_mode.h"
#include "interact_mode.h"
#include "utils.h"


int main(int argc, char *argv[])
{
    char *error_message = 0;
    // 检查数据库文件是否存在
    int file_exists = access("rules.db", F_OK);
    if (file_exists != 0) 
    {
        // 文件不存在，进行数据库的初始化和创建
        sqlite3 *db;
        int result = sqlite3_open("rules.db", &db);
        if (result != SQLITE_OK) {
            fprintf(stderr, "\033[1;31m无法打开规则数据库: %s\033[0m\n", sqlite3_errmsg(db));
            return result;
            }

        // 创建规则表
        const char *create_table_sql = "CREATE TABLE rules ("
                                        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                        "protocol TEXT,"
                                        "interface TEXT,"
                                        "src_ip TEXT,"
                                        "dst_ip TEXT,"
                                        "src_port TEXT,"
                                        "dst_port TEXT,"
                                        "start_time TEXT,"
                                        "end_time TEXT,"
                                        "action INTEGER,"
                                        "remarks TEXT);";
        result = sqlite3_exec(db, create_table_sql, 0, 0, &error_message);

        if (result != SQLITE_OK) {// 处理创建表失败的情况
            fprintf(stderr, "\033[1;31m创建表失败: %s\033[0m\n", error_message);
            sqlite3_free(error_message);
            return result;
        }

        // 关闭数据库连接
        sqlite3_close(db);
    }

    // 打开数据库连接
    sqlite3 *db;
    int result = sqlite3_open("rules.db", &db);
    if (result != SQLITE_OK) {
        fprintf(stderr, "\033[1;31m无法打开规则数据库: %s\033[0m\n", sqlite3_errmsg(db));
        return result;
    }

     if (argc > 1) 
     { // 命令行参数模式
        parseParam(argc, argv, db);
     } 
     else 
     { // 交互模式
        printf("\n");
        printLogo();
        printf("\n");

        printf("欢迎使用VersaGuard.\n");
        printf("\n");

        printUsage();
        printf("\n");
        printf("输入0-8进行相应操作:");
        
        int option;
        char choice;
        //无限循环等待用户输入命令
        while(1)
        {
            scanf("%d", &option);
            interaction(option, db);
            printf("\n");

            printf("是否要继续执行其他操作？[y/n]: ");
            scanf("%c", &choice);

            if (choice != 'y')
                break;
            else {
                printf("\n");
                printf("(查看使用说明请输入8)输入0-8进行相应操作:");
            }
        }
     }
    

    // 关闭数据库连接
    sqlite3_close(db);
    return 0;
}