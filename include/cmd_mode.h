#ifndef CMD_MODE_H
#define CMD_MODE_H

#include "common.h"

// 命令行参数模式使用说明
void printCmdUsage();

// 命令行参数模式
void parseParam(int argc, char* argv[], sqlite3 *db);

// 规则参数解析
Rule parseRuleParam(char* argv[]);

// 去掉在命令行参数模式为避免空格引起歧义而将时间括起来的引号
char* removeQuotes(char* str);


#endif