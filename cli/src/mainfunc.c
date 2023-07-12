#include "common.h"
#include "mainfunc.h"
#include "utils.h"


// 增添规则
bool addRule(sqlite3 *db, const Rule *rule) 
{
    if (isRuleExists(db, rule)) {
        printf("\033[1;31m错误：规则重复。\033[0m\n");
        return false;
    }

    char sql[512];
    sprintf(sql, "INSERT INTO rules (protocol, interface, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, remarks) "
                 "VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, '%s');",
                rule->protocol, rule->interface, rule->src_ip, rule->dst_ip, rule->src_port, rule->dst_port, rule->start_time, 
                rule->end_time, rule->action, rule->remarks);

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
    if (isRuleExists(db, rule) && rule->action == findRuleById(db, ruleId).action) {
        printf("\033[1;31m符合要求的规则已存在，无需修改。\033[0m\n");
        return false;
    }

    char sql[512];
     snprintf(sql, sizeof(sql), "UPDATE rules SET protocol = '%s', interface = '%s', src_ip = '%s', dst_ip = '%s', "
                                "src_port = '%s', dst_port = '%s', start_time = '%s', end_time = '%s', "
                                "action = %d, remarks = '%s' WHERE id = %d;",
             rule->protocol, rule->interface, rule->src_ip, rule->dst_ip, rule->src_port, rule->dst_port,
             rule->start_time, rule->end_time, rule->action, rule->remarks, ruleId);

    int result = sqlite3_exec(db, sql, 0, 0, 0);
    return result == SQLITE_OK;
}


// 从文件导入规则
void importRules(const char *filename, sqlite3 *db) 
{
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("\033[1;31m找不到或无法打开文件 %s 。\033[0m\n", filename);
        return;
    }

    // 逐行读取文件内容并解析规则数据
    bool success = true;
    char line[256];
    int ruleIndex = 1;

    while (fgets(line, sizeof(line), file)) 
    {
        // 解析规则数据并创建相应的规则对象
        Rule* rule = malloc(sizeof(Rule));
        rule->protocol = malloc(100);
        rule->interface = malloc(100);
        rule->src_ip = malloc(100);
        rule->dst_ip = malloc(100);
        rule->src_port = malloc(100);
        rule->dst_port = malloc(100);
        rule->start_time = malloc(100);
        rule->end_time = malloc(100);
        rule->remarks = malloc(100);


        int actionValue;
        char startDate[11];
        char startTime[9];
        char endDate[11];
        char endTime[9];
        sscanf(line, "%d %s %s %s %s %s %s %s %s %s %s %d %s", &rule->id, rule->protocol, rule->interface, rule->src_ip,
                rule->dst_ip, rule->src_port, rule->dst_port, startDate, startTime, endDate, endTime,
                &actionValue, rule->remarks);

        rule->action = (bool)actionValue;

        // 处理日期时间字段
        strcpy(rule->start_time, startDate);
        strcat(rule->start_time, " ");
        strcat(rule->start_time, startTime);
        strcpy(rule->end_time, endDate);
        strcat(rule->end_time, " ");
        strcat(rule->end_time, endTime);      


        // 将NULL字段对应指针指向空字符串
        if (strcmp(rule->interface, "NULL") == 0) {
            free(rule->interface);
            rule->interface = malloc(1);
            strcpy(rule->interface, "");
        }

        if (strcmp(rule->src_ip, "NULL") == 0) {
            free(rule->src_ip);
            rule->src_ip = malloc(1);
            strcpy(rule->src_ip, "");
        }

        if (strcmp(rule->dst_ip, "NULL") == 0) {
            free(rule->dst_ip);
            rule->dst_ip = malloc(1);
            strcpy(rule->dst_ip, "");
        }

        if (strcmp(rule->src_port, "NULL") == 0) {
            free(rule->src_port);
            rule->src_port = malloc(1);
            strcpy(rule->src_port, "");
        }
        
        if (strcmp(rule->dst_port, "NULL") == 0) {
            free(rule->dst_port);
            rule->dst_port = malloc(1);
            strcpy(rule->dst_port, "");
        }

        if (strcmp(rule->start_time, "NULL NULL") == 0) {
            free(rule->start_time);
            rule->start_time = malloc(1);
            strcpy(rule->start_time, "");
        }
        
        if (strcmp(rule->end_time, "NULL NULL") == 0) {
            free(rule->end_time);
            rule->end_time = malloc(1);
            strcpy(rule->end_time, "");
        }
        
        if (strcmp(rule->remarks, "NULL") == 0) {
            free(rule->remarks);
            rule->remarks = malloc(1);
            strcpy(rule->remarks, "");
        }
        
        // 验证规则的有效性
        if (!isValidProtocol(rule->protocol) || !isValidIPAddress(rule->src_ip) || !isValidIPAddress(rule->dst_ip)
            || !isValidPort(rule->src_port) || !isValidPort(rule->dst_port) || !isValidDateTime(rule->start_time)
            || !isValidDateTime(rule->end_time) || !isEndLaterThanStart(rule->start_time, rule->end_time)) {
            success = false;
            printf("\033[1;31m第 %d 条规则无效。\033[0m\n", ruleIndex);
        }
        else {
            bool add = addRule(db, rule);
            if (!add) {
                success = false;
                printf("\033[1;31m无法将第 %d 条规则添加到数据库。\033[0m\n", ruleIndex);
            }
        }
        
        // 释放规则对象及其字段内存
        free(rule->protocol);
        free(rule->interface);
        free(rule->src_ip);
        free(rule->dst_ip);
        free(rule->src_port);
        free(rule->dst_port);
        free(rule->start_time);
        free(rule->end_time);
        free(rule->remarks);
        free(rule);

        ruleIndex++;
    }

    if (success) {
        printf("\033[1;32m文件中的规则已添加到数据库。\033[0m\n");
    } else {
        printf("\033[1;31m无法导入规则文件。\033[0m\n");
    }
    fclose(file);
}


// 导出规则到文件
void exportRules(const char *filename, sqlite3 *db) 
{
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        printf("\033[1;31m找不到或无法打开文件 %s 。\033[0m\n", filename);
        return;
    }

    char sql[] = "SELECT * FROM rules;";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (result != SQLITE_OK) {
        printf("\033[1;31m无法准备 SQL 语句：%s 。\033[0m\n", sqlite3_errmsg(db));
        fclose(file);
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) 
    {
        Rule rule;
        
        rule.id = sqlite3_column_int(stmt, 0);
        rule.protocol = strdup((const char*)sqlite3_column_text(stmt, 1));
        rule.interface = strdup((const char*)sqlite3_column_text(stmt, 2));
        rule.src_ip = strdup((const char*)sqlite3_column_text(stmt, 3));
        rule.dst_ip = strdup((const char*)sqlite3_column_text(stmt, 4));
        rule.src_port = strdup((const char*)sqlite3_column_text(stmt, 5));
        rule.dst_port = strdup((const char*)sqlite3_column_text(stmt, 6));
        rule.start_time = strdup((const char*)sqlite3_column_text(stmt, 7));
        rule.end_time = strdup((const char*)sqlite3_column_text(stmt, 8));
        rule.action = sqlite3_column_int(stmt, 9);
        rule.remarks = strdup((const char*)sqlite3_column_text(stmt, 10));

        fprintf(file, "%d %s %s %s %s %s %s %s %s %d %s\n", rule.id, rule.protocol, 
        (strcmp(rule.interface, "") != 0) ? rule.interface : "NULL",
        (strcmp(rule.src_ip, "") != 0) ? rule.src_ip : "NULL", 
        (strcmp(rule.dst_ip, "") != 0) ? rule.dst_ip : "NULL", 
        (strcmp(rule.src_port, "") != 0) ? rule.src_port : "NULL",
        (strcmp(rule.dst_port, "") != 0) ? rule.dst_port : "NULL", 
        (strcmp(rule.start_time, "") != 0) ? rule.start_time : "NULL NULL",
        (strcmp(rule.end_time, "") != 0) ? rule.end_time : "NULL NULL", 
        rule.action, (strcmp(rule.remarks, "") != 0) ? rule.remarks : "NULL");

        // 释放动态分配的内存
        free(rule.protocol);
        free(rule.interface);
        free(rule.src_ip);
        free(rule.dst_ip);
        free(rule.src_port);
        free(rule.dst_port);
        free(rule.start_time);
        free(rule.end_time);
        free(rule.remarks);
    }

    sqlite3_finalize(stmt);
    fclose(file);
    printf("\033[1;32m规则已导出到文件: %s 。\033[0m\n", filename);
}


// 打印规则
void printRules(sqlite3* db) 
{
    const char* sql;
    sql = "SELECT * FROM rules";
    
    sqlite3_stmt* statement;
    
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) {
        printf("\033[1;31m查询规则失败。\033[0m\n");
        return;
    }

    printf("\033[1;93m+----+----------+-------------+---------------+---------------+----------+----------+----------------------+----------------------+--------+------------------+\033[0m\n");
    printf("\033[1;93m| ID | Protocol |  interface  |     Src IP    |     Dst IP    | Src Port | Dst Port |     Start Time       |      End Time        | Action |     Remarks      |\033[0m\n");
    printf("\033[1;93m+----+----------+-------------+---------------+---------------+----------+----------+----------------------+----------------------+--------+------------------+\033[0m\n");

    while (sqlite3_step(statement) == SQLITE_ROW) 
    {

        int id = sqlite3_column_int(statement, 0);
        const char* protocol = (const char*)sqlite3_column_text(statement, 1);
        const char* interface = (const char*)sqlite3_column_text(statement, 2);
        const char* src_ip = (const char*)sqlite3_column_text(statement, 3);
        const char* dst_ip = (const char*)sqlite3_column_text(statement, 4);
        const char* src_port = (const char*)sqlite3_column_text(statement, 5);
        const char* dst_port = (const char*)sqlite3_column_text(statement, 6);
        const char* start_time = (const char*)sqlite3_column_text(statement, 7);
        const char* end_time = (const char*)sqlite3_column_text(statement, 8);
        int action = sqlite3_column_int(statement, 9);
        const char* remarks = (const char*)sqlite3_column_text(statement, 10);

        printf("| %-2d | %-8s | %-11s | %-13s | %-13s | %-8s | %-8s | %-20s | %-20s | %-6d | %-16s |\n",
               id, protocol, interface, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, remarks);
    }

    printf("\033[1;93m+----+----------+-------------+---------------+---------------+----------+----------+----------------------+----------------------+--------+------------------+\033[0m\n");

    sqlite3_finalize(statement);
}


// 将控制规则写入设备文件传入核心层
bool writeRulesToDevice(sqlite3* db) 
{
    const char* sql = "SELECT * FROM rules";
    sqlite3_stmt* statement;

    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) 
    {
        printf("\033[1;31m查询规则失败。\033[0m\n");
        return false;
    }

    // 打开设备文件以写入规则
    int fd = open(DEVICE_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) 
    {
        printf("\033[1;31m无法打开或创建设备文件，请检查权限或文件路径。\033[0m\n");
        sqlite3_finalize(statement);
        return false;
    }
    while (sqlite3_step(statement) == SQLITE_ROW) 
    {
        const char* protocol = (const char*)sqlite3_column_text(statement, 1);
        const char* interface = (const char*)sqlite3_column_text(statement, 2);
        const char* src_ip = (const char*)sqlite3_column_text(statement, 3);
        const char* dst_ip = (const char*)sqlite3_column_text(statement, 4);
        const char* src_port = (const char*)sqlite3_column_text(statement, 5);
        const char* dst_port = (const char*)sqlite3_column_text(statement, 6);
        const char* start_time = (const char*)sqlite3_column_text(statement, 7);
        const char* end_time = (const char*)sqlite3_column_text(statement, 8);
        int action = sqlite3_column_int(statement, 9);

        // 跳过不拦截的规则
        if(action == 1){continue;}

         // 为空时写入?
        interface = (strcmp(interface, "") != 0) ? interface : "?";
        src_ip = (strcmp(src_ip, "") != 0) ? src_ip : "?";
        dst_ip = (strcmp(dst_ip, "") != 0) ? dst_ip : "?";
        src_port = (strcmp(src_port, "") != 0) ? src_port : "?";
        dst_port = (strcmp(dst_port, "") != 0) ? dst_port : "?";
        start_time = (strcmp(start_time, "") != 0) ? start_time : "?";
        end_time = (strcmp(end_time, "") != 0) ? end_time : "?";


        // 将规则转换为字符串格式并写入设备文件
        char rule[512];
        snprintf(rule, sizeof(rule), "%s %s %s %s %s %s %s %s ;", protocol, interface, src_ip, dst_ip,
                 src_port, dst_port, start_time, end_time);

        ssize_t bytes_written = write(fd, rule, strlen(rule));
        if (bytes_written < 0) 
        {
            close(fd);
            sqlite3_finalize(statement);
            return false;
        }
    }

    // 关闭设备文件
    close(fd);
    sqlite3_finalize(statement);
    return true;
}
