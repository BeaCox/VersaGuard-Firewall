#ifndef MAINFUNC_H
#define MAINFUNC_H

#include "common.h"

// 增添规则
bool addRule(sqlite3 *db, const Rule *rule);

// 删除规则
bool deleteRule(sqlite3 *db, int ruleId);

// 修改规则
bool updateRule(sqlite3 *db, int ruleId, const Rule *rule);

// 从文件导入规则
void importRules(const char *filename, sqlite3 *db);

// 导出规则到文件
void exportRules(const char *filename, sqlite3 *db);

// 打印规则
void printRules(sqlite3* db);

// 将控制规则写入设备文件传入核心层
bool writeRulesToDevice(sqlite3* db);


#endif