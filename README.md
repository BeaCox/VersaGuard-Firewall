# 输入
字符设备文件，每次读取多个规则，每个规则包含以下九项内容
```
    int protocol_type;      //0为tcp，1为udp，2为icmp
    char *dev_rule;         //网络接口
    char *ip_saddr_rule;    //源ip
    char *ip_daddr_rule;    //目的ip
    char *deny_src_port;    //源端口
    char *deny_dst_port;    //目的端口
    char *time_start_rule;  //开始时间
    char *time_end_rule;    //结束时间
```
规则与规则间以换行符';'作为间隔，规则中的每一项之间以空格' '间隔。
请按照下面格式写入
```
tcp eth0 192.168.0.1 192.168.0.2 1234 4321 2023-7-9 10:00:00 2023-7-9 12:59:59;udp eth1 192.168.0.1 192.168.0.2 1234 5678 2023-7-9 11:00:00 2023-7-9 13:59:59;
```
每段元素长度不固定，但注意每一条规则之后都应有分号';'。
# 输出
一个元素为下面结构体的数组rules，储存了规则的信息。规则数量存放在num_rules中。
```
struct rule
{
    int protocol_type;      //0为tcp，1为udp，2为icmp
    char *dev_rule;         //网络接口
    char *ip_saddr_rule;    //源ip
    char *ip_daddr_rule;    //目的ip
    char *deny_src_port;    //源端口
    char *deny_dst_port;    //目的端口
    char *time_start_rule;  //开始时间
    char *time_end_rule;    //结束时间
};
```
# 使用
编译
```
make
```
加载进内核
```
insmod rule_read.ko
```
测试，写入规则（例如1 tcp 192.168.0.1 192.168.0.2 1234 5678 2023-7-9 10:00:00 2023-7-9 12:00:00 1;2 udp 192.168.0.3 192.168.0.4 8765 4321 2023-7-9 14:00:00 2023-7-9 16:00:00 0;）
```
echo "tcp ? 192.168.0.1 192.168.0.2 1234 ? 2023-7-9 10:00:00 2023-7-9 12:59:59;? eth1 192.168.0.1 ? 1234 5678 2023-7-9 11:00:00 2023-7-9 13:59:59;" > /dev/firewall
```
可以在日志中查看设备注册情况和规则保存情况（打印规则需先取消注释打印函数）
```
dmesg
```
注销模块
```
rmmod rule_read
```
