#ifndef UTILS_H
#define UTILS_H

#include "common.h"

// 打印Logo
void printLogo();

// 根据规则ID查找规则对象
Rule findRuleById(sqlite3 *db, int ruleId);

// 验证规则是否为空
bool isRuleEmpty(const Rule* rule);

// 验证规则是否已存在
bool isRuleExists(sqlite3* db, const Rule* rule);

// 获取输入的字符串
char* getInputString();

// 验证协议的有效性
bool isValidProtocol(const char* protocol);

// 验证IP的有效性
bool isValidIPAddress(const char* ip);

// 验证端口的有效性
bool isValidPort(const char* port);

// 验证时间的有效性
bool isValidDateTime(const char* datetime);

// 验证结束时间是否晚于开始时间
bool isEndLaterThanStart(const char* start, const char* end);


#endif