# 输入
字符设备文件
# 输出
结构体
```
struct rule
{
    int id;
    char *protocol;
    int protocol_type; // 0为tcp，1为udp，2为ping
    char *src_ip;      // 源IP
    char *dst_ip;      // 目的IP
    int src_port;      // 源端口
    int dst_port;      // 目的端口
    char *start_time;  // 开始时同
    char *end_time;    // 结束时同
    bool action;       // 动作（0拦截,1通过）
};
```