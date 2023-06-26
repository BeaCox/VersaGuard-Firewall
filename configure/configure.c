// #include <gtk/gtk.h>
// #include <sqlite3.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#define DEVICE_FILE "/dev/firewall"  // 设备文件路径

// 规则结构体
typedef struct 
{
	int protocol; //协议类型：0为tcp，1为udp，2为ping
	char src_ip[20]; //源IP
	char dst_ip[20]; //目的IP
	int src_port; //源端口
	int dst_port; //目的端口
	time_t start_time; //开始时间
	time_t end_time; //结束时间
	bool action; //动作(0丢弃,1通过)
	bool log; //是否记录日志(0不记录,1记录)
	char remarks[64]; //备注
}Rule;

int main(int argc, char *argv[])
{
    printf("██╗   ██╗███████╗██████╗ ███████╗ █████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ \n");
    printf("██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗\n");
    printf("██║   ██║█████╗  ██████╔╝███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║\n");
    printf("╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\n");
    printf(" ╚████╔╝ ███████╗██║  ██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\n");
    printf("  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ \n");

	sqlite3 *db; //与数据库交互的指针
    char *error_message = 0; //错误信息
	
    // 打开数据库连接
    int result = sqlite3_open("rules.db", &db);
    if (result != SQLITE_OK) {// 处理打开数据库失败的情况
        fprintf(stderr, "无法打开规则数据库: %s\n", sqlite3_errmsg(db));
        return result;
    }

	// 创建规则表
    const char *create_table_sql = "CREATE TABLE rules ("
                                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                   "protocol INT,"
                                   "src_ip TEXT,"
                                   "dst_ip TEXT,"
                                   "src_port INT,"
                                   "dst_port INT,"
                                   "start_time INT,"
                                   "end_time INT,"
                                   "action INT,"
								   "log INT,"
                                   "remarks TEXT);";
    result = sqlite3_exec(db, create_table_sql, 0, 0, &error_message);
    if (result != SQLITE_OK) {// 处理创建表失败的情况
        fprintf(stderr, "创建表失败: %s\n", error_message);
        sqlite3_free(error_message);
        return result;
    }

	//...
	//对规则进行操作
	//...

	const char* rule = "这是从db中提取的规则,写入设备文件";
    if (writeRuleToDevice(rule)) {
        printf("规则写入设备文件成功\n");
    } else {
        printf("规则写入设备文件失败\n");
    }

    // 关闭数据库连接
    sqlite3_close(db);
    return 0;
}


// 将控制规则传入内核
bool writeRuleToDevice(const char* rule, int ruleId) 
{
    int fd = open(DEVICE_FILE, O_RDWR);  // 打开设备文件
    if (fd < 0) {
        perror("无法打开设备文件");
        return false;
    }

    // 构建要传递给内核的命令字符串
    char command[512];
    if (ruleId != -1) {
        snprintf(command, sizeof(command), "WRITE_RULE %d %s", ruleId, rule);
    } else {
        snprintf(command, sizeof(command), "WRITE_ALL_RULES %s", rule);
    }

    ssize_t bytes_written = write(fd, command, strlen(command));
    if (bytes_written < 0) {
        perror("写入设备文件失败");
        close(fd);
        return false;
    }

    // 从设备文件读取内核模块的响应
    char response[256];
    ssize_t bytes_read = read(fd, response, sizeof(response) - 1);
    if (bytes_read < 0) {
        perror("读取设备文件失败");
        close(fd);
        return false;
    }

    response[bytes_read] = '\0';
    printf("从内核模块接收到的响应：%s\n", response);
    close(fd);  // 关闭设备文件

    return true;
}

// 重载一下
bool writeRuleToDevice(const char* rule) 
{
    return writeRuleToDevice(rule, -1);
}


// 参数格式提示
void printUsage()
{
    printf("Usage: VersaGuard [options]\n");
	printf("-o operations");
	printf("1. add a rule\n");
	printf("2. delete a rule\n");
	printf("3. update a rule\n");
	printf("4. import rules from file\n");
	printf("5. export rules to file\n");
	printf("6. print a rule/rules\n");
	printf("7. write rules to device file");
	printf("8. print logs\n");
	printf("input your choice(1-8) or 0 to quit:\n");
}


// 命令行操作参数解析, 即对-o参数操作
void parseOpParam(int argc, char* argv[], sqlite3 *db) 
{
    if (argc < 3) {
        printf("无效的参数数量\n");
        printUsage();
        exit(1);
    }

    int option = atoi(argv[2]);

    switch (option) {
        case 1:// 添加规则
            printf("添加规则\n");
            printf("请输入要添加的规则,格式为VersaGuard [parameters]");
			printf("-p protocol 指明要控制的协议类型，取值为 0 (tcp)、1 (udp)、2 (ping)\n");
  		 	printf("-x source_ip 指明要控制报文的源 IP 地址\n");
   		    printf("-y dst_ip 指明要控制报文的目标 IP 地址\n");
    		printf("-m source_port 指明要控制报文的源端口地址\n");
    		printf("-n dst_port 指明要控制报文的目标端口地址\n");
    		printf("-s start_time 指明规则的开始时间，格式为 \"YYYY-MM-DD HH:MM:SS\"\n");
    		printf("-e end_time 指明规则的结束时间，格式为 \"YYYY-MM-DD HH:MM:SS\"\n");
    		printf("-a action 指明规则的执行动作，取值为 0 (丢弃) 或 1 (通过)\n");
    		printf("-l log 指明是否记录日志，取值为 0 (不记录) 或 1 (记录)\n");
			printf("-r remarks 指明对该规则的备注\n");
    		printf("\n");

            Rule rule = parseRuleParam(argc, argv);
    
    		if (addRule(db, &rule)) {
        	printf("规则添加成功！\n");
    		} else {
        	printf("规则添加失败。\n");
    		}
            break;

        case 2:// 删除规则
            printf("删除规则\n");
            printf("请输入要删除的规则ID:");

			int ruleId;
			scanf("%d", &ruleId);

			if (delRule(db, ruleId)) {
        	printf("规则删除成功！\n");
    		} else {
        	printf("规则删除失败。\n");
    		}
			 
            break;

        case 3:// 更新规则
			printf("更新规则\n");
            printf("请输入要更新的规则ID:");

			scanf("%d", &ruleId);

			printf("请输入更新后的规则,格式为VersaGuard [parameters]");
			printf("-p protocol 指明要控制的协议类型，取值为 0 (tcp)、1 (udp)、2 (ping)\n");
  		 	printf("-x source_ip 指明要控制报文的源 IP 地址\n");
   		    printf("-y dst_ip 指明要控制报文的目标 IP 地址\n");
    		printf("-m source_port 指明要控制报文的源端口地址\n");
    		printf("-n dst_port 指明要控制报文的目标端口地址\n");
    		printf("-s start_time 指明规则的开始时间，格式为 \"YYYY-MM-DD HH:MM:SS\"\n");
    		printf("-e end_time 指明规则的结束时间，格式为 \"YYYY-MM-DD HH:MM:SS\"\n");
    		printf("-a action 指明规则的执行动作，取值为 0 (丢弃) 或 1 (通过)\n");
    		printf("-l log 指明是否记录日志，取值为 0 (不记录) 或 1 (记录)\n");
    		printf("\n");

			Rule newrule = parseRuleParam(argc, argv);
    
    		if (updateRule(db, ruleId, &newrule)) {
        	printf("规则添加成功！\n");
    		} else {
        	printf("规则添加失败。\n");
    		}
            break;

		case 4:// 从文件导入规则
			printf("从文件导入规则\n");
			printf("请输入规则文件的路径：");

			char filename[256];
			scanf("%s", filename);
			importRules(filename, db);
			break;

		
		case 5:// 导出规则到文件
			printf("导出规则到文件\n");
			printf("请输入文件名\n");
		
			char filename[256];
			scanf("%s", filename);
			exportRules(filename, db);
			break;
		
		case 6:// 打印规则
			printf("打印规则\n");
			printf("请输入要打印的规则ID,不输入则打印全部规则\n");

			scanf("%d", &ruleId);				 
			printRules(db, ruleId);
			break;

		case 7:// 写规则到设备文件
			printf("写规则到设备文件\n");
			printf("请输入要传到内核的规则ID,不输入则写入全部规则\n");

			scanf("%d", &ruleId);	
			writeRuleToDevice(db, ruleId);

			break;

		case 8:// 打印日志
			break;

        default:
            printf("Invalid operation\n");
            break;
    }
}


// 规则参数解析
Rule parseRuleParam(int argc, char* argv[]) 
{
    Rule rule;
    memset(&rule, 0, sizeof(Rule));

    for (int i = 1; i < argc; i++) 
	{	
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            rule.protocol = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
            strncpy(rule.src_ip, argv[i + 1], sizeof(rule.src_ip) - 1);
        } else if (strcmp(argv[i], "-y") == 0 && i + 1 < argc) {
            strncpy(rule.dst_ip, argv[i + 1], sizeof(rule.dst_ip) - 1);
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            rule.src_port = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            rule.dst_port = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            rule.start_time = convertToTimeT(argv[i + 1]);
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            rule.end_time = convertToTimeT(argv[i + 1]);
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            rule.action = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            rule.log = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            strncpy(rule.remarks, argv[i + 1], sizeof(rule.remarks) - 1);
		} else {
            printf("无效的参数或参数值：%s\n", argv[i]);
            printUsage();
            exit(1);
        }
    }

    return rule;
}


// 增添规则
bool addRule(sqlite3 *db, const Rule *rule) 
{
    char sql[512];
    sprintf(sql, "INSERT INTO rules (protocol, src_ip, dst_ip, src_port, dst_port, start_time, end_time, action, log, remarks) "
                 "VALUES (%d, '%s', '%s', %d, %d, %ld, %ld, %d, %d, %s);",
            rule->protocol, rule->src_ip, rule->dst_ip, rule->src_port, rule->dst_port,
            rule->start_time, rule->end_time, rule->action, rule->log, rule->remarks);

    
    return result == SQLITE_OK;
}


// 删除规则
bool delRule(sqlite3 *db, int ruleId) 
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
    sprintf(sql, "UPDATE rules SET protocol = %d, src_ip = '%s', dst_ip = '%s', "
                 "src_port = %d, dst_port = %d, start_time = %ld, end_time = %ld, "
                 "action = %d, log = %d, remarks = %s WHERE id = %d;",
            rule->protocol, rule->src_ip, rule->dst_ip, rule->src_port, rule->dst_port,
            rule->start_time, rule->end_time, rule->action, rule->log, rule->remarks, ruleId);

    int result = sqlite3_exec(db, sql, 0, 0, 0);
    return result == SQLITE_OK;
}


// 打印规则
void printRules(sqlite3* db, int ruleId) 
{
    const char* sql;
    
    if (ruleId != -1) {
        sql = "SELECT * FROM rules WHERE id = ?";
    } else {
        sql = "SELECT * FROM rules";
    }
    
    sqlite3_stmt* statement;
    
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) {
        printf("查询规则失败。\n");
        return;
    }
    
    printf("规则列表:\n");
    printf("ID\tProtocol\tSrc IP\t\tDst IP\t\tSrc Port\tDst Port\tStart Time\tEnd Time\tAction\tLog\tRemarks\n");
    
    if (ruleId != -1) {
        sqlite3_bind_int(statement, 1, ruleId);
    }
    
    while (sqlite3_step(statement) == SQLITE_ROW) {
        int id = sqlite3_column_int(statement, 0);
        int protocol = sqlite3_column_int(statement, 1);
        const char* src_ip = (const char*)sqlite3_column_text(statement, 2);
        const char* dst_ip = (const char*)sqlite3_column_text(statement, 3);
        int src_port = sqlite3_column_int(statement, 4);
        int dst_port = sqlite3_column_int(statement, 5);
        long start_time = sqlite3_column_int64(statement, 6);
        long end_time = sqlite3_column_int64(statement, 7);
        int action = sqlite3_column_int(statement, 8);
        int log = sqlite3_column_int(statement, 9);
		const char* remarks = (const char*)sqlite3_column_text(statement, 10);
        
        printf("%d\t%d\t\t%s\t%s\t%d\t\t%d\t\t%ld\t%ld\t%d\t%d\t%s\n", id, protocol, src_ip, dst_ip, 
								src_port, dst_port, start_time, end_time, action, log, remarks);
    }
    
    sqlite3_finalize(statement);
}

//重载一下
void printRules(sqlite3* db) 
{
    printRules(db, -1);
}



// 从文件导入规则
void importRules(const char *filename, sqlite3 *db) 
{
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("无法打开文件 %s\n", filename);
        return;
    }

    // 逐行读取文件内容并解析规则数据
    char line[256];
    while (fgets(line, sizeof(line), file)) 
	{
        // 解析规则数据并创建相应的规则对象
        Rule rule;
        sscanf(line, "%d %s %s %d %d %ld %ld %d %d %s", &rule.protocol, rule.src_ip, 
			rule.dst_ip, &rule.src_port, &rule.dst_port, &rule.start_time, 
			&rule.end_time, &rule.action, &rule.log, rule.remarks);

		// 将规则对象添加到规则表中
        bool add = addRule(db, &rule);
        if (add) {
            printf("规则已添加到数据库\n");
        } else {
            printf("无法添加规则到数据库\n");
        }
    }
    fclose(file);
}


// 导出规则到文件
void exportRules(const char *filename, sqlite3 *db) 
{
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        printf("无法打开文件 %s\n", filename);
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

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Rule rule;

        rule.protocol = sqlite3_column_int(stmt, 0);
        strcpy(rule.src_ip, sqlite3_column_text(stmt, 1));
        strcpy(rule.dst_ip, sqlite3_column_text(stmt, 2));
        rule.src_port = sqlite3_column_int(stmt, 3);
        rule.dst_port = sqlite3_column_int(stmt, 4);
        rule.start_time = sqlite3_column_int(stmt, 5);
        rule.end_time = sqlite3_column_int(stmt, 6);
        rule.action = sqlite3_column_int(stmt, 7);
        rule.log = sqlite3_column_int(stmt, 8);
		strcpy(rule.remarks, sqlite3_column_text(stmt, 9));

        fprintf(file, "%d %s %s %d %d %ld %ld %d %d %s\n", rule.protocol, rule.src_ip,
                rule.dst_ip, rule.src_port, rule.dst_port, rule.start_time,
                rule.end_time, rule.action, rule.log, rule.remarks);
    }

    sqlite3_finalize(stmt);
    fclose(file);
    printf("规则已导出到文件 %s\n", filename);
}


/*=======================================================TOOLS===========================================================*/
                                   
// 将输入的时间转换为time_t类型
time_t convertToTimeT(const char* datetimeStr) 
{
    struct tm timeStruct;
    memset(&timeStruct, 0, sizeof(struct tm));

    // 使用 strptime 函数解析日期和时间字符串
    if (strptime(datetimeStr, "%Y-%m-%d %H:%M:%S", &timeStruct) == NULL) 
	{
        printf("日期时间格式不正确\n");
        return (time_t) -1;
    }

    // 使用 mktime 函数将 struct tm 结构转换为 time_t
    time_t convertedTime = mktime(&timeStruct);
    if (convertedTime == (time_t) -1) 
	{
        printf("无法将日期时间转换为 time_t\n");
        return (time_t) -1;
    }

    return convertedTime;
}
