#include "common.h"
#include "interact_mode.h"
#include "mainfunc.h"
#include "utils.h"


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
        	printf("\033[1;32m规则添加成功！\033[0m\n");
    		} else {
        	printf("\033[1;31m规则添加失败。\033[0m\n");
    		}

            break;

        case 2:// 删除规则
            printf("请输入要删除的规则ID:");
			scanf("%d", &ruleId);
            Rule rule = findRuleById(db, ruleId);
            if(isRuleEmpty(&rule)){
                printf("\033[1;31m规则不存在。\033[0m\n");
            } else if (deleteRule(db, ruleId)) {
        	printf("\033[1;32m规则删除成功！\033[0m\n");
    		} else {
        	printf("\033[1;31m规则删除失败。\033[0m\n");
    		}

			getchar();
            break;

        case 3:// 更新规则
            printf("请输入要更新的规则ID:");
			scanf("%d", &ruleId);
            rule = findRuleById(db, ruleId);
            if(isRuleEmpty(&rule)){
                printf("\033[1;31m规则不存在。\033[0m\n");
                getchar();
                break;
            }
            char * field = malloc(100);
            printf("请输入要修改的参数：");
            scanf("%s", field);

            // 检查输入的字段是否有效
            if (strcmp(field, "ptc") != 0 && strcmp(field, "sip") != 0 && strcmp(field, "dip") != 0 &&
                strcmp(field, "spt") != 0 && strcmp(field, "dpt") != 0 && strcmp(field, "stm") != 0 &&
                strcmp(field, "etm") != 0 && strcmp(field, "act") != 0 && strcmp(field, "rmk") != 0) {
                printf("\033[1;31m要修改的参数不存在。\033[0m\n");
                getchar();
                free(field);
                break;}

            char * value = malloc(100);
            printf("将%s修改为:", field);
            getchar();
            value = getInputString();

            Rule ruleToUpdate = findRuleById(db, ruleId);
            if (strcmp(field, "ptc") == 0) {
                if(isValidProtocol(value)){
                    strcpy(ruleToUpdate.protocol, value);
                } else {printf("\033[1;31m输入的协议无效。\033[0m\n");return ;}
            }
            else if (strcmp(field, "sip") == 0) {
                if(isValidIPAddress(value)){
                    strcpy(ruleToUpdate.src_ip, value);
                } else {printf("\033[1;31m输入的源ip无效。\033[0m\n");return ;}
            }
            else if (strcmp(field, "dip") == 0) {
                if(isValidIPAddress(value)){
                    strcpy(ruleToUpdate.dst_ip, value);
                } else {printf("\033[1;31m输入的目标ip无效。\033[0m\n");return ;}
            }
            else if (strcmp(field, "spt") == 0) {
                if(isValidPort(value)){
                    strcpy(ruleToUpdate.src_port, value);
                }else {printf("\033[1;31m输入的源端口无效，请输入0-65535之间的数字或回车。\033[0m\n"); exit(0);}
            }
            else if (strcmp(field, "dpt") == 0) {
                 if(isValidPort(value)){
                        strcpy(ruleToUpdate.dst_port, value);
                } else {printf("\033[1;31m输入的目标端口无效，请输入0-65535之间的数字或回车。\033[0m\n");return ;}
            }
            else if (strcmp(field, "stm") == 0) {
                 if(!isValidDateTime(value)){
                    printf("\033[1;31m输入的开始时间无效。\033[0m\n"); return ;
                } else if(!isEndLaterThanStart(value, ruleToUpdate.end_time)){
                    printf("\033[1;31m时间无效，输入的开始时间不早于原定的结束时间。\033[0m\n"); return ;
                } else {strcpy(ruleToUpdate.start_time, value);}
            }
            else if (strcmp(field, "etm") == 0) {
                 if(!isValidDateTime(value)){
                    printf("\033[1;31m输入的结束时间无效。\033[0m\n"); return ;
                } else if(!isEndLaterThanStart(ruleToUpdate.start_time, value)){
                    printf("\033[1;31m时间无效，输入的结束时间不晚于原定的开始时间。\033[0m\n"); return ;
                } else {strcpy(ruleToUpdate.end_time, value);}
            }
            else if (strcmp(field, "act") == 0) {
                if(atoi(value) == 0 || atoi(value) == 1){
                    ruleToUpdate.action = atoi(value);
                } else {
                    printf("\033[1;31m输入的动作无效。\033[0m\n"); return ;
                }
            }
            else if (strcmp(field, "rmk") == 0) {
                strcpy(ruleToUpdate.remarks, value);
            }
            else {
                printf("\033[1;31m无效的规则字段\033[0m\n");
                return ;
            }
            
            if (updateRule(db, ruleId, &ruleToUpdate)) {
                printf("\033[1;32m规则更新成功！\033[0m\n");
            } else {
                printf("\033[1;31m规则更新失败。\033[0m\n");
            }

            free(field);
            free(value);

            break;

		case 4:// 从文件导入规则
			printf("请输入规则文件的路径：");
			scanf("%s", filename);

			importRules(filename, db);

            getchar();
			break;

		
		case 5:// 导出规则到文件
			printf("请输入导出文件名:");
			scanf("%s", filename);

			exportRules(filename, db);

            getchar();
			break;
		
		case 6:// 打印规则
			printRules(db);

            getchar();
			break;

		case 7:// 写规则到设备文件
			if (writeRulesToDevice(db)) {
                printf("\033[1;32m规则已成功写入设备文件/dev/firewall。\033[0m\n");
            } else {
                printf("\033[1;31m规则写入设备文件失败。\033[0m\n");
            }

            getchar();
			break;

        case 8:// 打印使用说明
            printUsage();

            getchar();
            break;

        default:
            printf("\033[1;31m无效参数。\033[0m\n");

            getchar();
            break;
    }
}


//交互模式从输入获得规则
Rule getRuleFromUserInput() 
{
    Rule rule;
    memset(&rule, 0, sizeof(Rule));

    printf("请按照提示输入规则的参数");

    printf("协议类型 (all/tcp/udp/icmp): ");
    getchar(); 
    char* input;
    while (1) 
    {
        input = getInputString();
        if (isValidProtocol(input)) {
            rule.protocol = input;
            break; 
        } else {
            printf("\033[1;31m输入的协议无效。\033[0m\n");
            printf("请重新输入：");
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
            printf("\033[1;31m输入的源ip无效。\033[0m\n");
            printf("请重新输入：");
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
            printf("\033[1;31m输入的目标ip无效。\033[0m\n");
            printf("请重新输入：");
            free(input);
        }
    }

    printf("源端口: ");
    while(1)
    {
        input = getInputString();
        if(isValidPort(input)){
            rule.src_port = input;
            break;
        } else {
            printf("\033[1;31m输入的源端口无效。\033[0m\n");
            printf("请重新输入：");
            free(input);
        }
    }

    printf("目标端口: ");
    while(1)
    {
        input = getInputString();
        if(isValidPort(input)){
            rule.dst_port = input;
            break;
        } else {
            printf("\033[1;31m输入的目标端口无效。\033[0m\n");
            printf("请重新输入：");
            free(input);
        }
    }

    printf("开始时间 (YYYY-MM-DD HH:MM:SS): ");
    while (1) 
    {
        input = getInputString();
        if (isValidDateTime(input)) {
            rule.start_time = input;
            break; 
        } else {
            printf("\033[1;31m输入的开始时间无效。\033[0m\n");
            printf("请重新输入：");
            free(input);
        }
    }
    
    printf("结束时间 (YYYY-MM-DD HH:MM:SS): "); 
    while (1) 
    {
        input = getInputString();
        if (!isValidDateTime(input)) {
            printf("\033[1;31m输入的结束时间无效。\033[0m\n");
            printf("请重新输入：");
            free(input);
        } else if(!isEndLaterThanStart(rule.start_time, input)){
            printf("\033[1;31m输入的结束时间不晚于开始时间。\033[0m\n");
            printf("请重新输入：");
            free(input);
        } else{
            rule.end_time = input;
            break;
        }
    }

    printf("执行动作 (0拦截/1通过): ");
    while(1)
    {
        int action = -1;
        scanf("%d", &action);
        if(action == 0 || action == 1){
            rule.action = (bool)action; 
            break;    
        } else {
            printf("\033[1;31m输入的动作无效。\033[0m\n");
            printf("请重新输入：");
        }
    }
    

    printf("备注: ");
    getchar();
    input = getInputString();
    rule.remarks = input;

    return rule;
}
