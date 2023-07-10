#ifndef COMMON_H
#define COMMON_H

#define _POSIX_C_SOURCE 200809L  // 定义POSIX C为2008年的标准版
#define _GNU_SOURCE  // 启用GNU扩展特性
#define DEVICE_FILE "/dev/firewall"  // 设备文件路径


#include <sqlite3.h>
#include <regex.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


// 规则结构体
typedef struct 
{
    int id; //规则序号
	char *protocol; //协议类型：tcp，udp，icmp, all
	char *src_ip; //源IP
	char *dst_ip; //目的IP
	char *src_port; //源端口
	char *dst_port; //目的端口
	char *start_time; //开始时间
	char *end_time; //结束时间
	bool action; //动作(0拦截,1通过)
	char *remarks; //备注
}Rule;


#endif