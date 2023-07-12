#ifndef INTERACT_MODE_H
#define INTERACT_MODE_H

#include "common.h"

// 交互模式的使用方法提示
void printUsage();

// 交互模式
void interaction(int op, sqlite3 *db);

// 交互模式从输入获得规则
Rule getRuleFromUserInput();


#endif