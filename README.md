# 输入
字符设备文件，每次读取多个规则，每个规则包含以下九项内容
```
    int id;
    char *protocol;
    char *src_ip;      // 源IP
    char *dst_ip;      // 目的IP
    char *src_port;      // 源端口
    char *dst_port;      // 目的端口
    char *start_time;  // 开始时同
    char *end_time;    // 结束时同
    int action;       // 动作（0拦截,1通过）
```
规则与规则间以换行符';'作为间隔，规则中的每一项之间以空格' '间隔。
请按照下面格式写入
```
1 tcp 192.168.0.1 192.168.0.2 1234 5678 10:00 12:00 1;2 udp 192.168.0.3 192.168.0.4 8765 4321 14:00 16:00 0;
```
注意每一条规则之后都应有分号';'。
# 输出
一个元素为下面结构体的数组rules，储存了规则的信息。规则数量存放在num_rules中。
```
struct rule
{
    int id;
    char *protocol;
    char *src_ip;      // 源IP
    char *dst_ip;      // 目的IP
    char *src_port;      // 源端口
    char *dst_port;      // 目的端口
    char *start_time;  // 开始时同
    char *end_time;    // 结束时同
    int action;       // 动作（0拦截,1通过）
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
测试，写入规则（例如1 tcp 192.168.0.1 192.168.0.2 1234 5678 10:00 12:00 1;2 udp 192.168.0.3 192.168.0.4 8765 4321 14:00 16:00 0;）
```
echo "1 tcp 192.168.0.1 192.168.0.2 1234 5678 10:00 12:00 1;2 udp 192.168.0.3 192.168.0.4 8765 4321 14:00 16:00 0;" > /dev/firewall
```
可以在日志中查看设备注册情况和规则保存情况（打印规则需先取消注释打印函数）
```
dmesg
```
注销模块
```
rmmod rule_read
```
