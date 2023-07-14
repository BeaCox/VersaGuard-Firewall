#include "common.h"
#include "utils.h"


// 打印Logo
void printLogo()
{
    printf("\033[1;32m██╗   ██╗███████╗██████╗ ███████╗ █████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ \033[0m\n");
    printf("\033[1;32m██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗\033[0m\n");
    printf("\033[1;32m██║   ██║█████╗  ██████╔╝███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║\033[0m\n");
    printf("\033[1;32m╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\033[0m\n");
    printf(" \033[1;32m╚████╔╝ ███████╗██║  ██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\033[0m\n");
    printf("  \033[1;32m╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ \033[0m\n");
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
        fprintf(stderr, "\033[1;31m无法执行查询: %s 。\033[0m\n", sqlite3_errmsg(db));
        return rule;
    }

    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        // 提取查询结果中的字段值，并赋值给 rule 对应的字段
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
        
    }

    sqlite3_finalize(stmt); // 释放查询结果的资源

    return rule;
}


// 验证规则是否为空
bool isRuleEmpty(const Rule* rule) 
{
    if (rule->id == 0 &&
        rule->protocol == NULL &&
        rule->interface == NULL &&
        rule->src_ip == NULL &&
        rule->dst_ip == NULL &&
        rule->src_port == 0 &&
        rule->dst_port == 0 &&
        rule->start_time == NULL &&
        rule->end_time == NULL &&
        rule->action == 0 &&
        rule->remarks == NULL) {
        return true;
    } else {
        return false;
    }
}


// 验证规则是否已存在
bool isRuleExists(sqlite3* db, const Rule* rule) 
{
    char sql[512];
    sprintf(sql, "SELECT COUNT(*) FROM rules WHERE protocol = ? AND interface = ? AND src_ip = ? AND dst_ip = ? "
                 "AND src_port = ? AND dst_port = ? AND start_time = ? AND end_time = ?");

    sqlite3_stmt* statement;
    int result = sqlite3_prepare_v2(db, sql, -1, &statement, NULL);
    if (result != SQLITE_OK) {
        printf("\033[1;31m无法执行查询: %s\033[0m\n", sqlite3_errmsg(db));
        return false;
    }

    // 绑定参数的值
    sqlite3_bind_text(statement, 1, rule->protocol, -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 2, rule->interface, -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 3, rule->src_ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 4, rule->dst_ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 5, rule->src_port, -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 6, rule->dst_port, -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 7, rule->start_time, -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 8, rule->end_time, -1, SQLITE_STATIC);

    int count = 0;
    if (sqlite3_step(statement) == SQLITE_ROW) {
        count = sqlite3_column_int(statement, 0);
    }

    sqlite3_finalize(statement);

    return count > 0;
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
    // 检查ip字符串是否为空
    if (strcmp(ip, "") == 0) {
        return true;
    }

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
bool isValidPort(const char* port) 
{
    // 检查端口字符串是否为空
    if (strcmp(port, "") == 0) {
        return true;
    }
    
    // 尝试将端口字符串转换为长整型
    char* endPtr;
    long int portNum = strtol(port, &endPtr, 10);

    // 检查转换后的指针是否指向了字符串的结尾，以及端口值是否在有效范围内
    if (*endPtr == '\0' && portNum >= 0 && portNum <= 65535) {
        return true;
    } else {
        return false;
    }
}


// 验证时间的有效性
bool isValidDateTime(const char* datetime) 
{
    // 检查时间字符串是否为空
    if (strcmp(datetime, "") == 0) {
        return true;
    }

    // YYYY-MM-DD HH:MM:SS
    const char* pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$";
    
    regex_t regex;
    int ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret != 0) {return false;}
    
    ret = regexec(&regex, datetime, 0, NULL, 0);
    regfree(&regex);
    
    if (ret != 0) {return false;}
    
    // 提取日期和时间
    int year, month, day, hour, minute, second;
    sscanf(datetime, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second);
    
    // 检查年份和月份是否合法
    if (year < 0 || month < 1 || month > 12) {return false;}
    
    // 检查天数是否合法
    int maxDays = 31;
    
    if (month == 4 || month == 6 || month == 9 || month == 11) {maxDays = 30;} 
    else if (month == 2) 
    {
    bool isLeapYear = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    maxDays = isLeapYear ? 29 : 28;
    }
    
    if (day < 1 || day > maxDays) {return false;}
    
    // 检查小时、分钟和秒是否合法
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {return false;}
    
    return true;
}


// 验证结束时间是否晚于开始时间
bool isEndLaterThanStart(const char* start, const char* end) 
{
    // 检查时间字符串是否为空
    if (strcmp(start, "") == 0 || strcmp(end, "") == 0) {
        return true;
    }
    
    // 将开始时间和结束时间解析为日期时间对象
    struct tm tmStart, tmEnd;
    memset(&tmStart, 0, sizeof(struct tm));
    memset(&tmEnd, 0, sizeof(struct tm));
    
    strptime(start, "%Y-%m-%d %H:%M:%S", &tmStart);
    strptime(end, "%Y-%m-%d %H:%M:%S", &tmEnd);
    
    // 将日期时间对象转换为时间戳
    time_t timestampStart = mktime(&tmStart);
    time_t timestampEnd = mktime(&tmEnd);
    
    // 比较时间戳，验证结束时间是否晚于开始时间
    return (timestampEnd > timestampStart);
}
