#ifndef CONFIGURE_H
#define CONFIGURE_H

// 规则结构体
typedef struct 
{
    int id; //规则序号
	char *protocol; //协议类型：tcp，udp，icmp, all
	char *src_ip; //源IP
	char *dst_ip; //目的IP
	int src_port; //源端口
	int dst_port; //目的端口
	char *start_time; //开始时间
	char *end_time; //结束时间
	bool action; //动作(0拦截,1通过)
	char *remarks; //备注
}Rule;

// 交互模式的使用方法提示
void printUsage();

// 交互模式
void interaction(int op, sqlite3 *db);

// 命令行参数模式使用说明
void printCmdUsage();

// 命令行参数模式
void parseParam(int argc, char* argv[], sqlite3 *db);

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

// 规则参数解析
Rule parseRuleParam(char* argv[]);

// 去掉在命令行参数模式为避免空格引起歧义而将时间括起来的引号
char* removeQuotes(char* str);

// 交互模式从输入获得规则
Rule getRuleFromUserInput();

// 根据规则ID查找规则对象
Rule findRuleById(sqlite3 *db, int ruleId);

// 验证规则是否存在
bool isRuleEmpty(const Rule* rule);

// 获取输入的字符串
char* getInputString();

// 验证协议的有效性
bool isValidProtocol(const char* protocol);

// 验证IP的有效性
bool isValidIPAddress(const char* ip);

// 验证端口的有效性
bool isValidPort(int port);

// 验证时间的有效性
bool isValidDateTime(const char* datetime);

// 验证结束时间是否晚于开始时间
bool isEndLaterThanStart(const char* start, const char* end);

#endif