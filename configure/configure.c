#include <sqlite3.h>
#include <regex.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "configure.h"

#define DEVICE_FILE "/dev/firewall"  // 设备文件路径


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
            fprintf(stderr, "无法打开规则数据库: %s\n", sqlite3_errmsg(db));
            return result;
            }

        // 创建规则表
        const char *create_table_sql = "CREATE TABLE rules ("
                                        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                        "protocol TEXT,"
                                        "src_ip TEXT,"
                                        "dst_ip TEXT,"
                                        "src_port INTEGER,"
                                        "dst_port INTEGER,"
                                        "start_time TEXT,"
                                        "end_time TEXT,"
                                        "action INTEGER,"
                                        "remarks TEXT);";
        result = sqlite3_exec(db, create_table_sql, 0, 0, &error_message);


        if (result != SQLITE_OK) {// 处理创建表失败的情况
            fprintf(stderr, "创建表失败: %s\n", error_message);
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
        fprintf(stderr, "无法打开规则数据库: %s\n", sqlite3_errmsg(db));
        return result;
    }

     if (argc > 1) 
     { // 命令行参数模式
        parseParam(argc, argv, db);
     } 
     else 
     { // 交互模式
        printf("\n");

        printf("██╗   ██╗███████╗██████╗ ███████╗ █████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ \n");
        printf("██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗\n");
        printf("██║   ██║█████╗  ██████╔╝███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║\n");
        printf("╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\n");
        printf(" ╚████╔╝ ███████╗██║  ██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\n");
        printf("  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ \n");

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

            getchar();
            scanf("%c", &choice);

            if (choice != 'y')
                break;
            else {
                printf("\n");
                printf("(使用说明请输入8)输入0-8进行相应操作:");
            }
        }
     }
    

    // 关闭数据库连接
    sqlite3_close(db);
    return 0;
}


// 命令行参数模式使用说明
void printCmdUsage()
    {
        printf("使用说明:\"./configure -o [option]\"\n");
        printf("\n");
        printf("[option]: add,del,upd,imp,exp,rule,write\n");
        printf("add:添加规则,后接九个参数,分别表示协议类型(tcp,udp,icmp,all),源IP,目标IP,源端口,目标端口,开始时间(格式为带引号的\"YYYY-MM-DD HH:MM:SS\"),结束时间,执行动作(0拦截,1通过),备注\n");
        printf("del:删除规则,后接一个参数表示要删除的规则的序号\n");
        printf("upd:修改规则,后接三个参数,分别表示要修改的规则的序号,要修改哪一项参数(ptc,sip,dip,spt,dpt,stm,etm,act,rmk),修改后的结果\n");
        printf("imp:导入规则,后接一个参数表示要导入的规则文件路径\n");
        printf("exp:导出规则,后接一个参数表示要导出的规则文件名\n"); 
        printf("rule:打印规则\n");
        printf("write:写规则到设备文件\n");
        printf("help:打印使用说明\n");
        printf("\n");
        printf("也可以输入./configure以交互模式运行程序\n");
    }
        
// 命令行参数模式
void parseParam(int argc, char* argv[], sqlite3 *db) 
{
    //参数无效，打印使用说明
    if (argc < 3) 
    {
        printf("无效的参数数量。\n");
        printCmdUsage();
        exit(1);
    }

    const char* operation = argv[1]; //进行何种操作

    if (strcmp(operation, "-o") == 0) 
    {
        const char* option = argv[2];

        if (strcmp(option, "add") == 0 && argc == 12) {
            Rule rule = parseRuleParam(argv + 3);
            if (addRule(db, &rule)) {
        	printf("规则添加成功！\n");
    		} else {
        	printf("规则添加失败。\n");
    		}
        } else if (strcmp(option, "del") == 0 && argc == 4) {
            int ruleId = atoi(argv[3]);
            if(deleteRule(db, ruleId)){
            printf("规则删除成功！\n");
    		} else {
        	printf("规则删除失败。\n");
            }
        } else if (strcmp(option, "upd") == 0 && argc == 6) {
            int ruleId = atoi(argv[3]);
            char* field = argv[4];
            char* value = argv[5];
            Rule ruleToUpdate = findRuleById(db, ruleId);

            if (strcmp(field, "ptc") == 0) {
                if(isValidProtocol(value)){
                    strcpy(ruleToUpdate.protocol, value);
                } else {printf("输入的协议无效。"); exit(0);}
            }
            else if (strcmp(field, "sip") == 0) {
                if(isValidIPAddress(value)){
                    strcpy(ruleToUpdate.src_ip, value);
                } else {printf("输入的源ip无效。"); exit(0);}
            }
            else if (strcmp(field, "dip") == 0) {
                if(isValidIPAddress(value)){
                    strcpy(ruleToUpdate.dst_ip, value);
                } else {printf("输入的目标ip无效。"); exit(0);}
            }
            else if (strcmp(field, "spt") == 0) {
                if(isValidPort(atoi(value))){
                    ruleToUpdate.src_port = atoi(value);
                } else {printf("输入的源端口无效。"); exit(0);}
            }
            else if (strcmp(field, "dpt") == 0) {
                 if(isValidPort(atoi(value))){
                    ruleToUpdate.dst_port = atoi(value);
                } else {printf("输入的目标端口无效。"); exit(0);}
            }
            else if (strcmp(field, "stm") == 0) {
                 if(isValidDateTime(value)){
                    strcpy(ruleToUpdate.start_time, value);
                } else {printf("输入的开始时间无效。"); exit(0);}
            }
            else if (strcmp(field, "etm") == 0) {
                if(isValidDateTime(value)){
                    strcpy(ruleToUpdate.end_time, value);
                } else {printf("输入的结束时间无效。"); exit(0);}
            }
            else if (strcmp(field, "act") == 0) {
                ruleToUpdate.action = atoi(value);
            }
            else if (strcmp(field, "rmk") == 0) {
                strcpy(ruleToUpdate.remarks, value);
            }
            else {
                printf("无效的规则字段\n"); 
                exit(0);
            }

            if(updateRule(db, ruleId, &ruleToUpdate)){
                printf("规则更新成功！\n");
    		} else {
        	    printf("规则更新失败。\n");
            }
        } else if (strcmp(option, "imp") == 0 && argc == 4) {
            const char* filePath = argv[3];
            importRules(filePath, db);
        } else if (strcmp(option, "exp") == 0 && argc == 4) {
            const char* fileName = argv[3];
            exportRules(fileName, db);
        } else if (strcmp(option, "rule") == 0 && argc == 3) {
            printRules(db);
        } else if (strcmp(option, "write") == 0 && argc == 3) {
            writeRulesToDevice(db);
        } else if (strcmp(option, "help") == 0 && argc == 3) {
            printCmdUsage();
        } else {
            printf("无效的操作选项或参数数量\n");
            printf("\n");
            printCmdUsage();
            printf("\n");
            exit(1);
        }
    } 
    
}


// 交互模式的使用方法提示
void printUsage()
{
    printf("0. 退出程序\n");
	printf("1. 添加规则\n");
	printf("2. 删除规则\n");
	printf("3. 修改规则\n");
	printf("4. 导入规则\n");
	printf("5. 导出规则\n");
	printf("6. 打印规则\n");
	printf("7. 写规则到设备文件\n");
    printf("8. 使用说明\n");
}


// 交互模式
void interaction(int op, sqlite3 *db) 
{
    int ruleId;
    Rule rule;
    char filename[256];

    switch (op) 
    {
        case 0:
            exit(0);
            break;

        case 1:// 添加规则
            rule = getRuleFromUserInput();

    		if (addRule(db, &rule)) {
        	printf("规则添加成功！\n");
    		} else {
        	printf("规则添加失败。\n");
    		}

            break;

        case 2:// 删除规则
            printf("请输入要删除的规则ID:");
			scanf("%d", &ruleId);

			if (deleteRule(db, ruleId)) {
        	printf("规则删除成功！\n");
    		} else {
        	printf("规则删除失败。\n");
    		}
			 
            break;

        case 3:// 更新规则
            printf("请输入要更新的规则ID:");
			scanf("%d", &ruleId);

            char * field = malloc(100);
            printf("请输入要修改的参数：");
            scanf("%s", field);

            char * value = malloc(100);
            printf("将%s修改为:", field);
            getchar();
            scanf("%s", value);

            Rule ruleToUpdate = findRuleById(db, ruleId);
            if (strcmp(field, "ptc") == 0) {
                if(isValidProtocol(value)){
                    strcpy(ruleToUpdate.protocol, value);
                } else {printf("输入的协议无效。");return ;}
            }
            else if (strcmp(field, "sip") == 0) {
                if(isValidIPAddress(value)){
                    strcpy(ruleToUpdate.src_ip, value);
                } else {printf("输入的源ip无效。");return ;}
            }
            else if (strcmp(field, "dip") == 0) {
                if(isValidIPAddress(value)){
                    strcpy(ruleToUpdate.dst_ip, value);
                } else {printf("输入的目标ip无效。");return ;}
            }
            else if (strcmp(field, "spt") == 0) {
                if(isValidPort(atoi(value))){
                    ruleToUpdate.src_port = atoi(value);
                } else {printf("输入的源端口无效。");return ;}
            }
            else if (strcmp(field, "dpt") == 0) {
                 if(isValidPort(atoi(value))){
                    ruleToUpdate.dst_port = atoi(value);
                } else {printf("输入的目标端口无效。");return ;}
            }
            else if (strcmp(field, "stm") == 0) {
                 if(isValidDateTime(value)){
                    strcpy(ruleToUpdate.start_time, value);
                } else {printf("输入的开始时间无效。");return ;}
            }
            else if (strcmp(field, "etm") == 0) {
                if(isValidDateTime(value)){
                    strcpy(ruleToUpdate.end_time, value);
                } else {printf("输入的结束时间无效。");return ;}
            }
            else if (strcmp(field, "act") == 0) {
                ruleToUpdate.action = atoi(value);
            }
            else if (strcmp(field, "rmk") == 0) {
                strcpy(ruleToUpdate.remarks, value);
            }
            else {
                printf("无效的规则字段\n");
                return ;
            }

    		if (updateRule(db, ruleId, &ruleToUpdate)) {
        	    printf("规则更新成功！\n");
    		} else {
        	    printf("规则更新失败。\n");
    		}
            free(field);
            free(value);
            break;

		case 4:// 从文件导入规则
			printf("请输入规则文件的路径：");
			scanf("%s", filename);

			importRules(filename, db);

			break;

		
		case 5:// 导出规则到文件
			printf("请输入导出文件名:");
			scanf("%s", filename);

			exportRules(filename, db);

			break;
		
		case 6:// 打印规则
			printRules(db);

			break;

		case 7:// 写规则到设备文件
			if (writeRulesToDevice(db)) {
                printf("规则写入设备文件成功。\n");
            } else {
                printf("规则写入设备文件失败。\n");
            }

			break;

        case 8:// 打印使用说明
            printUsage();
            break;

        default:
            printf("无效参数。\n");
            break;
    }
}



/*=======================================================TOOLS===========================================================*/


// 增添规则
bool addRule(sqlite3 *db, const Rule *rule) 
{
    char sql[512];
    sprintf(sql, "INSERT INTO rules (protocol, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, remarks) "
                 "VALUES ('%s', '%s', '%s', %d, %d, '%s', '%s', %d, '%s');",
            rule->protocol, rule->src_ip, rule->dst_ip, rule->src_port, rule->dst_port,
            rule->start_time, rule->end_time, rule->action, rule->remarks);

    int result = sqlite3_exec(db, sql, 0, 0, 0);
    return result == SQLITE_OK;
}


// 删除规则
bool deleteRule(sqlite3 *db, int ruleId) 
{
    char sql[256];
    sprintf(sql, "DELETE FROM rules WHERE id = %d;", ruleId);

    int result = sqlite3_exec(db, sql, 0, 0, 0);
    return result == SQLITE_OK;
}


// 修改规则
bool updateRule(sqlite3 *db, int ruleId, const Rule *rule) 
{
    char sql[512];
     snprintf(sql, sizeof(sql), "UPDATE rules SET protocol = '%s', src_ip = '%s', dst_ip = '%s', "
                                "src_port = %d, dst_port = %d, start_time = '%s', end_time = '%s', "
                                "action = %d, remarks = '%s' WHERE id = %d;",
             rule->protocol, rule->src_ip, rule->dst_ip, rule->src_port, rule->dst_port,
             rule->start_time, rule->end_time, rule->action, rule->remarks, ruleId);

    int result = sqlite3_exec(db, sql, 0, 0, 0);
    return result == SQLITE_OK;
}


// 打印规则
void printRules(sqlite3* db) 
{
    const char* sql;
    sql = "SELECT * FROM rules";
    
    sqlite3_stmt* statement;
    
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) {
        printf("查询规则失败。\n");
        return;
    }

    printf("规则列表:\n");
    printf("ID\tProtocol\tSrc IP\t\tDst IP\t\tSrc Port\tDst Port \tStart Time\t\tEnd Time\t\tAction\tRemarks\n");

    while (sqlite3_step(statement) == SQLITE_ROW) {
        int id = sqlite3_column_int(statement, 0);
        const char* protocol = (const char*)sqlite3_column_text(statement, 1);
        const char* src_ip = (const char*)sqlite3_column_text(statement, 2);
        const char* dst_ip = (const char*)sqlite3_column_text(statement, 3);
        int src_port = sqlite3_column_int(statement, 4);
        int dst_port = sqlite3_column_int(statement, 5);
        const char* start_time = (const char*)sqlite3_column_text(statement, 6);
        const char* end_time = (const char*)sqlite3_column_text(statement, 7);
        int action = sqlite3_column_int(statement, 8);
        const char* remarks = (const char*)sqlite3_column_text(statement, 9);
        
        printf("%-3d\t%-8s\t%-15s\t%-15s\t%-8d\t%-8d\t%-16s\t%-16s\t%-6d\t%s\n", id, protocol, src_ip, dst_ip, 
               src_port, dst_port, start_time, end_time, action, remarks);
               
    }
    
    sqlite3_finalize(statement);
}



// 从文件导入规则
void importRules(const char *filename, sqlite3 *db) 
{
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("找不到或无法打开文件 %s\n", filename);
        return;
    }

    // 逐行读取文件内容并解析规则数据
    char line[256];
    while (fgets(line, sizeof(line), file)) 
	{
        // 解析规则数据并创建相应的规则对象
        Rule* rule = malloc(sizeof(Rule));
        rule->protocol = malloc(100);
        rule->src_ip = malloc(100);
        rule->dst_ip = malloc(100);
        rule->start_time = malloc(100);
        rule->end_time = malloc(100);
        rule->remarks = malloc(100);

        int actionValue;
        char startDate[11];
        char startTime[9];
        char endDate[11];
        char endTime[9];
        sscanf(line, "%d %s %s %s %d %d %10s %8s %10s %8s %d %s", &rule->id, rule->protocol, rule->src_ip,
                rule->dst_ip, &rule->src_port, &rule->dst_port, startDate, startTime, endDate, endTime,
                &actionValue, rule->remarks);

        rule->action = (bool)actionValue;
        // 处理日期时间字段
        strcpy(rule->start_time, startDate);
        strcat(rule->start_time, " ");
        strcat(rule->start_time, startTime);
        strcpy(rule->end_time, endDate);
        strcat(rule->end_time, " ");
        strcat(rule->end_time, endTime);      

		// 将规则对象添加到规则表中
        bool add = addRule(db, rule);
        if (add) {
            printf("规则已添加到数据库。\n");
        } else {
            printf("无法添加规则到数据。\n");
        }

        free(rule->protocol);
        free(rule->src_ip);
        free(rule->dst_ip);
        free(rule->start_time);
        free(rule->end_time);
        free(rule->remarks);
        free(rule);
    }
    fclose(file);
}


// 导出规则到文件
void exportRules(const char *filename, sqlite3 *db) 
{
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        printf("找不到或无法打开文件 %s\n", filename);
        return;
    }

    char sql[] = "SELECT * FROM rules;";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (result != SQLITE_OK) {
        printf("无法准备 SQL 语句：%s\n", sqlite3_errmsg(db));
        fclose(file);
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) 
    {
        Rule rule;
        
        rule.id = sqlite3_column_int(stmt, 0);
        rule.protocol = strdup((const char*)sqlite3_column_text(stmt, 1));
        rule.src_ip = strdup((const char*)sqlite3_column_text(stmt, 2));
        rule.dst_ip = strdup((const char*)sqlite3_column_text(stmt, 3));
        rule.src_port = sqlite3_column_int(stmt, 4);
        rule.dst_port = sqlite3_column_int(stmt, 5);
        rule.start_time = strdup((const char*)sqlite3_column_text(stmt, 6));
        rule.end_time = strdup((const char*)sqlite3_column_text(stmt, 7));
        rule.action = sqlite3_column_int(stmt, 8);
        rule.remarks = strdup((const char*)sqlite3_column_text(stmt, 9));

        fprintf(file, "%d %s %s %s %d %d %s %s %d %s\n", rule.id, rule.protocol,
                rule.src_ip, rule.dst_ip, rule.src_port, rule.dst_port, rule.start_time,
                rule.end_time, rule.action, rule.remarks);

        // 释放动态分配的内存
        free(rule.protocol);
        free(rule.src_ip);
        free(rule.dst_ip);
        free(rule.start_time);
        free(rule.end_time);
        free(rule.remarks);
    }

    sqlite3_finalize(stmt);
    fclose(file);
    printf("规则已导出到文件: %s\n", filename);
}


// 将控制规则写入设备文件传入核心层
bool writeRulesToDevice(sqlite3* db) 
{
    const char* sql = "SELECT * FROM rules";
    sqlite3_stmt* statement;

    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) 
    {
        printf("查询规则失败。\n");
        return false;
    }

    // 打开设备文件以写入规则
    int fd = open(DEVICE_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) 
    {
        printf("无法打开或创建设备文件。\n");
        sqlite3_finalize(statement);
        return false;
    }
    while (sqlite3_step(statement) == SQLITE_ROW) 
    {
        int id = sqlite3_column_int(statement, 0);
        const char* protocol = (const char*)sqlite3_column_text(statement, 1);
        const char* src_ip = (const char*)sqlite3_column_text(statement, 2);
        const char* dst_ip = (const char*)sqlite3_column_text(statement, 3);
        int src_port = sqlite3_column_int(statement, 4);
        int dst_port = sqlite3_column_int(statement, 5);
        const char* start_time = (const char*)sqlite3_column_text(statement, 6);
        const char* end_time = (const char*)sqlite3_column_text(statement, 7);
        int action = sqlite3_column_int(statement, 8);
        const char* remarks = (const char*)sqlite3_column_text(statement, 9);

        // 将规则转换为字符串格式并写入设备文件
        char rule[512];
        snprintf(rule, sizeof(rule), "%d %s %s %s %d %d %s %s %d %s\n", id, protocol, src_ip, dst_ip,
                 src_port, dst_port, start_time, end_time, action, remarks);

        ssize_t bytes_written = write(fd, rule, strlen(rule));
        if (bytes_written < 0) 
        {
            printf("写入设备文件失败。\n");
            close(fd);
            sqlite3_finalize(statement);
            return false;
        }
    }

    // 关闭设备文件
    printf("规则已成功写入设备文件/dev/firewall。");
    close(fd);
    sqlite3_finalize(statement);
    return true;
}


//规则参数解析
Rule parseRuleParam(char* argv[])
{
    Rule rule;
    memset(&rule, 0, sizeof(Rule));

    // 为字符指针成员分配内存
    rule.protocol = malloc(strlen(argv[0]) + 1);
    rule.src_ip = malloc(strlen(argv[1]) + 1);
    rule.dst_ip = malloc(strlen(argv[2]) + 1);
    rule.start_time = malloc(strlen(argv[5]) + 1);
    rule.end_time = malloc(strlen(argv[6]) + 1);
    rule.remarks = malloc(strlen(argv[8]) + 1);

    // 复制字符串到字符指针成员
    if(!isValidProtocol(argv[0])){
        printf("输入的协议无效。\n");
    }else {strcpy(rule.protocol, argv[0]);}

    if(!isValidIPAddress(argv[1])){
        printf("输入的源ip无效。\n");
    }else {strcpy(rule.src_ip, argv[1]);}

    if(!isValidIPAddress(argv[2])){
        printf("输入的目标ip无效。\n");
    }else {strcpy(rule.dst_ip, argv[2]);}

    if(!isValidPort(atoi(argv[3]))){
        printf("输入的源端口无效。\n");
    }else {rule.src_port = atoi(argv[3]);}

    if(!isValidPort(atoi(argv[4]))){
        printf("输入的目标端口无效。\n");
    }else {rule.dst_port = atoi(argv[4]);}
    

    if(!isValidDateTime(removeQuotes(argv[5]))){
        printf("输入的开始时间无效。\n");
    }else {strcpy(rule.start_time, argv[5]);}

    if(!isValidDateTime(removeQuotes(argv[6]))){
        printf("输入的结束时间无效。\n");
    }else {strcpy(rule.end_time, argv[6]);}

    rule.action = atoi(argv[7]);
    strcpy(rule.remarks, argv[8]);

    return rule;
}


//去掉在命令行参数模式为避免空格引起歧义而将时间括起来的引号
char* removeQuotes(char* str) 
{
    int len = strlen(str);
    if (len >= 2 && str[0] == '"' && str[len - 1] == '"') {
        memmove(str, str + 1, len - 2);
        str[len - 2] = '\0';
    }
    return str;
}


//交互模式从输入获得规则
Rule getRuleFromUserInput() 
{
    Rule rule;
    memset(&rule, 0, sizeof(Rule));

    printf("请输入规则的参数：");

    printf("协议类型 (tcp/udp/icmp/all): ");
    getchar(); 
    char* input;
    while (1) 
    {
        input = getInputString();
        if (isValidProtocol(input)) {
            rule.protocol = input;
            break; 
        } else {
            printf("输入的协议无效，请重新输入：");
            free(input);
            
        }
    }
    
    printf("源 IP 地址: ");
    while (1) 
    {
        input = getInputString();
        if (isValidIPAddress(input)) {
            rule.src_ip = input;
            break; 
        } else {
            printf("输入的源ip无效，请重新输入：");
            free(input);
        }
    }

    printf("目标 IP 地址: "); 
    while (1) 
    {
        input = getInputString();
        if (isValidIPAddress(input)) {
            rule.dst_ip = input;
            break; 
        } else {
            printf("输入的目标ip无效，请重新输入：");
            free(input);
        }
    }

    printf("源端口: ");
    int srcPort;
    while(1)
    {
        scanf("%d", &srcPort);
        if(isValidPort(srcPort)){
            rule.src_port = srcPort;
            break;
        } else {
            printf("输入的源端口无效，请重新输入：");
        }
    }

    printf("目标端口: ");
    int dstPort;
    while(1)
    {
        scanf("%d", &dstPort);
        if(isValidPort(dstPort)){
            rule.dst_port = dstPort;
            break;
        } else {
            printf("输入的目标端口无效，请重新输入：");
        }
    }

    printf("开始时间 (YYYY-MM-DD HH:MM:SS): ");
    getchar(); 
    while (1) 
    {
        input = getInputString();
        if (isValidDateTime(input)) {
            rule.start_time = input;
            break; 
        } else {
            printf("输入的开始时间无效，请重新输入：");
            free(input);
        }
    }
    
    printf("结束时间 (YYYY-MM-DD HH:MM:SS): "); 
    while (1) 
    {
        input = getInputString();
        if (isValidDateTime(input)) {
            rule.end_time = input;
            break; 
        } else {
            printf("输入的结束时间无效，请重新输入：");
            free(input);
        }
    }

    printf("执行动作 (0拦截/1通过): ");
    int action = 0;
    scanf("%d", &action);
    rule.action = (bool)action;

    printf("备注: ");
    char buffer[100]; 
    scanf("%s", buffer);
    rule.remarks = malloc(strlen(buffer) + 1);
    strcpy(rule.remarks, buffer);

    return rule;
}

// 根据规则ID查找规则对象
Rule findRuleById(sqlite3 *db, int ruleId) 
{
    Rule rule;
    memset(&rule, 0, sizeof(Rule));

    // 构造SQL查询语句
    char sql[256];
    sprintf(sql, "SELECT * FROM rules WHERE id = %d", ruleId);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "无法执行查询: %s\n", sqlite3_errmsg(db));
        return rule;
    }

    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        // 提取查询结果中的字段值，并赋值给 rule 对应的字段
        rule.id = sqlite3_column_int(stmt, 0);
        rule.protocol = strdup((const char*)sqlite3_column_text(stmt, 1));
        rule.src_ip = strdup((const char*)sqlite3_column_text(stmt, 2));
        rule.dst_ip = strdup((const char*)sqlite3_column_text(stmt, 3));
        rule.src_port = sqlite3_column_int(stmt, 4);
        rule.dst_port = sqlite3_column_int(stmt, 5);
        rule.start_time = strdup((const char*)sqlite3_column_text(stmt, 6));
        rule.end_time = strdup((const char*)sqlite3_column_text(stmt, 7));
        rule.action = sqlite3_column_int(stmt, 8);
        rule.remarks = strdup((const char*)sqlite3_column_text(stmt, 9));
    }

    sqlite3_finalize(stmt); // 释放查询结果的资源

    return rule;
}

// 给规则的字符指针动态分配内存并获取输入的字符串
char* getInputString()
{
    const int buffer_size = 100;
    char buffer[buffer_size];
    fgets(buffer, buffer_size, stdin);
    buffer[strcspn(buffer, "\n")] = '\0';  // 去除输入字符串末尾的换行符
    char* input = malloc(strlen(buffer) + 1);
    strcpy(input, buffer);
    return input;
}


// 验证协议的有效性
bool isValidProtocol(const char* protocol) 
{
    return (strcmp(protocol, "tcp") == 0 || strcmp(protocol, "udp") == 0 || strcmp(protocol, "icmp") == 0 || strcmp(protocol, "all") == 0);
}

// 验证IP的有效性
bool isValidIPAddress(const char* ip) 
{
    // 正则表达式，匹配 IPv4 地址
    const char* pattern = "^([0-9]{1,3}\\.){3}[0-9]{1,3}$";
    
    regex_t regex;
    int ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret != 0) 
    {// 正则表达式编译失败
        return false;
    }
    
    ret = regexec(&regex, ip, 0, NULL, 0);
    regfree(&regex);
    
    return (ret == 0);
}

// 验证端口的有效性
bool isValidPort(int port) 
{
    return (port >= 0 && port <= 65535);
}


// 验证时间的有效性
bool isValidDateTime(const char* datetime) 
{
    // 正则表达式模式，匹配 "YYYY-MM-DD HH:MM:SS" 格式的日期时间
    const char* pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$";
    
    regex_t regex;
    int ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret != 0) 
    {// 正则表达式编译失败
        return false;
    }
    
    ret = regexec(&regex, datetime, 0, NULL, 0);
    regfree(&regex);
    
    return (ret == 0);
}

                             
// // 将输入的字符串时间转换为time_t数据类型
// time_t convertToTimeT(const char* datetimeStr) 
// {
//     struct tm timeStruct;
//     memset(&timeStruct, 0, sizeof(struct tm));

//     // 使用 strptime 函数解析日期和时间字符串
//     if (strptime(datetimeStr, "%Y-%m-%d %H:%M:%S", &timeStruct) == NULL) 
// 	{
//         printf("日期时间格式不正确\n");
//         return (time_t) -1;
//     }

//     // 使用 mktime 函数将 struct tm 结构转换为 time_t
//     time_t convertedTime = mktime(&timeStruct);
//     if (convertedTime == (time_t) -1) 
// 	{
//         printf("无法将日期时间转换为 time_t\n");
//         return (time_t) -1;
//     }

//     return convertedTime;
// }
