#include "common.h"
#include "cmd_mode.h"
#include "mainfunc.h"
#include "utils.h"


// 命令行参数模式使用说明
void printCmdUsage()
    {
        printf("\n");
        printf("使用说明: \033[1;103m\033[1;30m./configure -o [option] <parameters>\033[0m\033[0m(或输入 \033[1;103m\033[1;30m./configure\033[0m\033[0m 以交互模式运行程序)\n");
        printf("\033[1;36m[option]: add,del,upd,imp,exp,rule,write,help\033[0m\n");
        printf("\033[1;36madd\033[0m————添加规则，后接九个参数，分别表示协议类型(tcp/udp/icmp/all)，源IP，目标IP，源端口，目标端口(默认禁止所有端口则输入\033[1;93m\"\"\033[0m)，开始时间，结束时间(\033[1;93m\"\033[0mYYYY-MM-DD HH:MM:SS\033[1;93m\"\033[0m)，执行动作(0拦截/1通过)，备注(无则输入\033[1;93m\"\"\033[0m)\n");
        printf("\033[1;36mdel\033[0m————删除规则，后接一个参数表示要删除的规则的序号\n");
        printf("\033[1;36mupd\033[0m————修改规则，后接三个参数，分别表示要修改的规则的序号，要修改哪一项参数(ptc/sip/dip/spt/dpt/stm/etm/act/rmk)，修改后的结果\n");
        printf("\033[1;36mimp\033[0m————导入规则，后接一个参数表示要导入的规则文件路径\n");
        printf("\033[1;36mexp\033[0m————导出规则，后接一个参数表示要导出的规则文件名\n"); 
        printf("\033[1;36mrule\033[0m————打印规则\n");
        printf("\033[1;36mwrite\033[0m————写规则到设备文件\n");
        printf("\033[1;36mhelp\033[0m————打印使用说明\n");
        printf("\n");
    }
        
        
// 命令行参数模式
void parseParam(int argc, char* argv[], sqlite3 *db) 
{
    //参数无效，打印使用说明
    if (argc < 3) 
    {
        printf("\033[1;31m无效的参数数量。\033[0m\n");
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
        	    printf("\033[1;32m规则添加成功！\033[0m\n");
    		} else {
        	    printf("\033[1;31m规则添加失败。\033[0m\n");
    		}
        } 
        else if (strcmp(option, "del") == 0 && argc == 4) {
            int ruleId = atoi(argv[3]);
            Rule rule = findRuleById(db, ruleId);
            if(isRuleEmpty(&rule)){
                printf("\033[1;31m规则不存在。\033[0m\n");
                exit(1);
            }
            else if(deleteRule(db, ruleId)){
                printf("\033[1;32m规则删除成功！\033[0m\n");
    		} else {
        	    printf("\033[1;31m规则删除失败。\033[0m\n");
            }
        } 
        else if (strcmp(option, "upd") == 0 && argc == 6) {
            int ruleId = atoi(argv[3]);
            char* field = argv[4];
            char* value = argv[5];
            Rule ruleToUpdate = findRuleById(db, ruleId);

            if(isRuleEmpty(&ruleToUpdate)){
                printf("\033[1;31m规则不存在。\033[0m\n");
                exit(1);
            } else if (strcmp(field, "ptc") == 0) {
                if(isValidProtocol(value)){
                    strcpy(ruleToUpdate.protocol, value);
                } else {printf("\033[1;31m输入的协议无效。\033[0m\n"); exit(0);}
            }
            else if (strcmp(field, "sip") == 0) {
                if(isValidIPAddress(value)){
                    strcpy(ruleToUpdate.src_ip, value);
                } else {printf("\033[1;31m输入的源ip无效。\033[0m\n"); exit(0);}
            }
            else if (strcmp(field, "dip") == 0) {
                if(isValidIPAddress(value)){
                    strcpy(ruleToUpdate.dst_ip, value);
                } else {printf("\033[1;31m输入的目标ip无效。\033[0m\n"); exit(0);}
            }
            else if (strcmp(field, "spt") == 0) {
                if(isValidPort(value) || isValidPort(removeQuotes(value))){
                    if(strcmp(value, "\"\"") == 0){
                        strcpy(ruleToUpdate.src_port, "");
                    }else {
                        strcpy(ruleToUpdate.src_port, value);
                    }
                } else {printf("\033[1;31m输入的源端口无效。\033[0m\n"); exit(0);}
            }
            else if (strcmp(field, "dpt") == 0) {
                if(isValidPort(value) || isValidPort(removeQuotes(value))){
                    if(strcmp(value, "\"\"") == 0){
                        strcpy(ruleToUpdate.dst_port, "");
                    }else {
                        strcpy(ruleToUpdate.dst_port, value);
                    }
                } else {printf("\033[1;31m输入的目标端口无效。\033[0m\n"); exit(0);}
            }
            else if (strcmp(field, "stm") == 0) {
                 if(!isValidDateTime(value)){
                    printf("\033[1;31m输入的开始时间无效。\033[0m\n"); exit(0);
                } else if(!isEndLaterThanStart(value, ruleToUpdate.end_time)){
                    printf("\033[1;31m时间无效，输入的开始时间不早于原定的结束时间。\033[0m\n"); exit(0);
                } else {strcpy(ruleToUpdate.start_time, value);}
            }
            else if (strcmp(field, "etm") == 0) {
                 if(!isValidDateTime(value)){
                    printf("\033[1;31m输入的结束时间无效。\033[0m\n"); exit(0);
                } else if(!isEndLaterThanStart(ruleToUpdate.start_time, value)){
                    printf("\033[1;31m时间无效，输入的结束时间不晚于原定的开始时间。\033[0m\n"); exit(0);
                } else {strcpy(ruleToUpdate.end_time, value);}
            }
            else if (strcmp(field, "act") == 0) {
                if(atoi(value) == 0 || atoi(value) == 1){
                    ruleToUpdate.action = atoi(value);
                } else {printf("\033[1;31m输入的动作无效。\033[0m\n"); exit(0);}
                
            }
            else if (strcmp(field, "rmk") == 0) {
                strcpy(ruleToUpdate.remarks, value);
            }
            else {
                printf("\033[1;31m无效的规则字段。\033[0m\n"); 
                exit(1);
            }

            if(updateRule(db, ruleId, &ruleToUpdate)){
                printf("\033[1;32m规则更新成功！\033[0m\n");
    		} else {
        	    printf("\033[1;31m规则更新失败。\033[0m\n");
            }
        } 
        else if (strcmp(option, "imp") == 0 && argc == 4) {
            const char* filePath = argv[3];
            importRules(filePath, db);
        } 
        else if (strcmp(option, "exp") == 0 && argc == 4) {
            const char* fileName = argv[3];
            exportRules(fileName, db);
        } 
        else if (strcmp(option, "rule") == 0 && argc == 3) {
            printRules(db);
        } 
        else if (strcmp(option, "write") == 0 && argc == 3) {
            if (writeRulesToDevice(db)) {
                printf("\033[1;32m规则已成功写入设备文件/dev/firewall。\033[0m\n");
            } else {
                printf("\033[1;31m规则写入设备文件失败。\033[0m\n");
            }
        } 
        else if (strcmp(option, "help") == 0 && argc == 3) {
            printCmdUsage();
        } 
        else {
            printf("\033[1;31m无效的操作选项或参数数量。\033[0m\n");
            printf("\n");
            printCmdUsage();
            printf("\n");
            exit(1);
        }
    } 
    else {
        printf("\033[1;31m无效的参数数量。\033[0m\n");
        exit(1);
    }

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
    rule.src_port = malloc(strlen(argv[3]) + 1);
    rule.dst_port = malloc(strlen(argv[4]) + 1);
    rule.start_time = malloc(strlen(argv[5]) + 1);
    rule.end_time = malloc(strlen(argv[6]) + 1);
    rule.remarks = malloc(strlen(argv[8]) + 1);

    // 复制字符串到字符指针成员
    if(!isValidProtocol(argv[0])){
        printf("\033[1;31m输入的协议无效。\033[0m\n");
        exit(0);
    } else {strcpy(rule.protocol, argv[0]);}

    if(!isValidIPAddress(argv[1])){
        printf("\033[1;31m输入的源ip无效。\033[0m\n");
        exit(0);
    } else {strcpy(rule.src_ip, argv[1]);}

    if(!isValidIPAddress(argv[2])){
        printf("\033[1;31m输入的目标ip无效。\033[0m\n");
        exit(0);
    } else {strcpy(rule.dst_ip, argv[2]);}

    if(!isValidPort(argv[3]) && !isValidPort(removeQuotes(argv[3]))){
        printf("\033[1;31m输入的源端口无效。\033[0m\n");
        exit(0);
    } else {
        if(strcmp(argv[3], "\"\"") == 0){
            strcpy(rule.src_port, "");
        } else {
            strcpy(rule.src_port, argv[3]);
        }
    }

    if(!isValidPort(argv[4]) && !isValidPort(removeQuotes(argv[4]))){
        printf("\033[1;31m输入的目标端口无效。\033[0m\n");
        exit(0);
    } else {
        if(strcmp(argv[4], "\"\"") == 0){
            strcpy(rule.dst_port, "");
        } else {
            strcpy(rule.dst_port, argv[4]);
        }
    }
    
    if(!isValidDateTime(removeQuotes(argv[5]))){
        printf("\033[1;31m输入的开始时间无效。\033[0m\n");
        exit(0);
    } else if(!isValidDateTime(removeQuotes(argv[6]))){
        printf("\033[1;31m输入的结束时间无效。\033[0m\n");
        exit(0);
    } else if(!isEndLaterThanStart(removeQuotes(argv[5]), removeQuotes(argv[6]))){
        printf("\033[1;31m时间无效，结束时间不晚于开始时间。\033[0m\n");
        exit(0);
    } else {
        strcpy(rule.start_time, argv[5]);
        strcpy(rule.end_time, argv[6]);
    }

    if(atoi(argv[7]) == 0 || atoi(argv[7]) == 1){
        rule.action = atoi(argv[7]);
    } else {
        printf("\033[1;31m输入的动作无效。\033[0m\n");
        exit(0);
    }
    
    if(strcmp(argv[8], "\"\"") == 0){
        strcpy(rule.remarks, "");
    } else{
        strcpy(rule.remarks, argv[8]);
    }
    
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