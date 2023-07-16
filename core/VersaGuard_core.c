#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/timekeeping.h>
#include <linux/inet.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>

#define DEVICE_NAME "firewall" // 设备文件名称
#define BUF_SIZE 5120          // 读取字符串的最大长度，应大于最大规则数*100
#define MAX_RULES 50           // 最大规则数
#define LOG_FILE "/var/log/VersaGuard.log"
char buf[256];
loff_t pos = 0;
struct file *filep = NULL;
struct rw_semaphore file_lock;
static struct semaphore my_semaphore;
static DECLARE_WAIT_QUEUE_HEAD(my_wait_queue);

struct firewall_rule
{
    int protocol_type;     // 0为tcp，1为udp，2为icmp
    char *dev_rule;        // 网络接口
    char *ip_saddr_rule;   // 源ip
    char *ip_daddr_rule;   // 目的ip
    char *deny_src_port;   // 源端口
    char *deny_dst_port;   // 目的端口
    char *time_start_rule; // 开始时间
    char *time_end_rule;   // 结束时间

    char *protocol;
    char *start_day;
    char *start_sec;
    char *end_day;
    char *end_sec;
};

//用于转换ip地址到字符串
#define IPADDRESS(addr)              \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

static struct nf_hook_ops *nf_blockpkt_ops = NULL;

static char device_buffer[BUF_SIZE];
static struct firewall_rule rules[MAX_RULES];
static int num_rules = 0;

// 比较时间是否在起始时间和终止时间之间，支持特殊规则
bool is_time_between(const char *cur_time, const char *start_time, const char *end_time)
{
    if (strcmp(start_time, "?") == 0)
        return strcmp(cur_time, end_time) <= 0;
    else if (strcmp(end_time, "?") == 0)
        return strcmp(cur_time, start_time) >= 0;
    else
        return strcmp(cur_time, start_time) >= 0 && strcmp(cur_time, end_time) <= 0;
}

//打印日志信息到日志文件
static int logprint(const char *str)
{

    ssize_t len = snprintf(buf, sizeof(buf), "%s", str);

    if (len < 0) {
        pr_err("Failed to format data\n");
        return -1;
    }

    // 获取文件锁
    down_write(&file_lock);

    kernel_write(filep, buf, len, &pos);

    // 释放文件锁
    up_write(&file_lock);

    return 0;

}

// 将读取到的字符串解析并保存在结构体数组中
static void parse_rules(void)
{
    char *pos;
    char *rule_str;
    const char *delim = " ";
    pos = device_buffer;
    while ((rule_str = strsep(&pos, ";")) != NULL && num_rules < MAX_RULES)
    {
        char *token;
        struct firewall_rule rule;
        if (rule_str[0] == 0 || rule_str[1] == 0)
            break;
        memset(&rule, 0, sizeof(struct firewall_rule));

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (protocol)\n");
            return;
        }
        rule.protocol = kstrdup(token, GFP_KERNEL);

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (dev_rule)\n");
            return;
        }
        rule.dev_rule = kstrdup(token, GFP_KERNEL);

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (ip_saddr_rule)\n");
            return;
        }
        rule.ip_saddr_rule = kstrdup(token, GFP_KERNEL);

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (ip_daddr_rule)\n");
            return;
        }
        rule.ip_daddr_rule = kstrdup(token, GFP_KERNEL);

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (src)\n");
            return;
        }
        rule.deny_src_port = kstrdup(token, GFP_KERNEL);

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (dst)\n");
            return;
        }
        rule.deny_dst_port = kstrdup(token, GFP_KERNEL);

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (s_day)\n");
            return;
        }
        rule.start_day = kstrdup(token, GFP_KERNEL);

        if (rule.start_day[0] == '?' && rule.start_day[1] == 0)
        {
            rule.time_start_rule = kmalloc(strlen("?") + 1, GFP_KERNEL);
            rule.time_start_rule[0] = '?';
            rule.time_start_rule[1] = 0;
        }
        else
        {
            token = strsep(&rule_str, delim);
            if (token == NULL)
            {
                pr_err("Invalid rule format (s_sec)\n");
                return;
            }
            rule.start_sec = kstrdup(token, GFP_KERNEL);
        }

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (e_day)\n");
            return;
        }
        rule.end_day = kstrdup(token, GFP_KERNEL);

        if (rule.end_day[0] == '?' && rule.end_day[1] == 0)
        {
            rule.time_end_rule = kmalloc(strlen("?") + 1, GFP_KERNEL);
            rule.time_end_rule[0] = '?';
            rule.time_end_rule[1] = 0;
        }
        else
        {
            token = strsep(&rule_str, delim);
            if (token == NULL)
            {
                pr_err("Invalid rule format (e_sec)\n");
                return;
            }
            rule.end_sec = kstrdup(token, GFP_KERNEL);
        }
        // 将protocol类型转化成int编号
        if (rule.protocol[0] == 'A' && rule.protocol[1] == 'L' && rule.protocol[2] == 'L' && rule.protocol[3] == 0)
            rule.protocol_type = 3;
        else if (rule.protocol[0] == 'T' && rule.protocol[1] == 'C' && rule.protocol[2] == 'P' && rule.protocol[3] == 0)
            rule.protocol_type = 0;
        else if (rule.protocol[0] == 'U' && rule.protocol[1] == 'D' && rule.protocol[2] == 'P' && rule.protocol[3] == 0)
            rule.protocol_type = 1;
        else if (rule.protocol[0] == 'I' && rule.protocol[1] == 'C' && rule.protocol[2] == 'M' && rule.protocol[3] == 'P' && rule.protocol[4] == 0)
            rule.protocol_type = 2;
        else
        {
            rule.protocol_type = -1; // 输入格式错误
            pr_err("Invalid protocol format\n");
            return;
        }

        if (rule.start_day[0] != '?')
        {
            // 将时间字符串拼接为正确格式
            rule.time_start_rule = kmalloc(sizeof(char) * (strlen(rule.start_sec) + strlen(rule.start_day) + 10), GFP_KERNEL);
            rule.time_start_rule[0] = '\0'; // 初始化为空字符串
            strlcpy(rule.time_start_rule, rule.start_day, strlen(rule.start_sec) + strlen(rule.start_day) + 10);
            strlcat(rule.time_start_rule, " ", strlen(rule.start_sec) + strlen(rule.start_day) + 10);
            strlcat(rule.time_start_rule, rule.start_sec, strlen(rule.start_sec) + strlen(rule.start_day) + 10);
        }
        if (rule.end_day[0] != '?')
        {
            rule.time_end_rule = kmalloc(sizeof(char) * (strlen(rule.end_sec) + strlen(rule.end_day) + 10), GFP_KERNEL);
            rule.time_end_rule[0] = '\0'; // 初始化为空字符串
            strlcpy(rule.time_end_rule, rule.end_day, strlen(rule.end_sec) + strlen(rule.end_day) + 10);
            strlcat(rule.time_end_rule, " ", strlen(rule.end_sec) + strlen(rule.end_day) + 10);
            strlcat(rule.time_end_rule, rule.end_sec, strlen(rule.end_sec) + strlen(rule.end_day) + 10);
        }
        rules[num_rules++] = rule;
    }
}

// 匹配过滤规则
bool match_rule(const struct sk_buff *skb, const struct firewall_rule *rule)
{
    struct iphdr *iph = ip_hdr(skb);

    // 检查协议类型
    int pkt_protocol=5;
    if(iph->protocol == IPPROTO_TCP)pkt_protocol=0;
    if(iph->protocol == IPPROTO_UDP)pkt_protocol=1;
    if(iph->protocol == IPPROTO_ICMP)pkt_protocol=2;
    if (rule->protocol_type != 3 && pkt_protocol != rule->protocol_type)
        return false;

    u32 sip_saddr,sip_daddr;
    char str_saddr[16] ={};
    char str_daddr[16] ={};

    // 检查源IP地址
    sip_saddr=ntohl(iph->saddr);
    sprintf(str_saddr,"%u.%u.%u.%u",IPADDRESS(sip_saddr));
    if (strcmp(rule->ip_saddr_rule, "?") != 0 && strcmp(str_saddr, rule->ip_saddr_rule) != 0){
        return false;
    }

    // 检查目标IP地址
    sip_daddr=ntohl(iph->daddr);
    sprintf(str_daddr,"%u.%u.%u.%u",IPADDRESS(sip_daddr));
    if (strcmp(rule->ip_daddr_rule, "?") != 0 && strcmp(str_daddr, rule->ip_daddr_rule) != 0){
        return false;
    }

    // 检查网络接口
    if (strcmp(rule->dev_rule, "?") != 0 && strcmp(skb->dev->name, rule->dev_rule) != 0)
        return false;

    // 检查源端口
    if (strcmp(rule->deny_src_port, "?") != 0)
    {
        if (iph->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp_header = tcp_hdr(skb);
            if (ntohs(tcp_header->source) == *(unsigned short *)rule->deny_src_port)
                return false;
        }
        else if (iph->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp_header = udp_hdr(skb);
            if (ntohs(udp_header->source) == *(unsigned short *)rule->deny_src_port)
                return false;
        }
    }

    // 检查目标端口
    if (strcmp(rule->deny_dst_port, "?") != 0)
    {
        if (iph->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp_header = tcp_hdr(skb);
            if (ntohs(tcp_header->dest) == *(unsigned short *)rule->deny_dst_port)
                return false;
        }
        else if (iph->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp_header = udp_hdr(skb);
            if (ntohs(udp_header->dest) == *(unsigned short *)rule->deny_dst_port)
                return false;
        }
    }

    //检查时间段
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[20];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
            result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
            result.tm_hour, result.tm_min, result.tm_sec);
    if (!is_time_between(cur_time, rule->time_start_rule, rule->time_end_rule))
        return false;

    return true;
}

// 数据包处理函数
static unsigned int nf_blockpkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    //获取信号量
    if (down_interruptible(&my_semaphore)) {
        /* 若信号量获取失败，则进入等待队列并阻塞 */
        wait_event_interruptible(my_wait_queue, (my_semaphore.count > 0));
    }
    for (int i = 0; i < num_rules; i++)
    {
        if (match_rule(skb, &rules[i]))
        {
            struct iphdr *iph = ip_hdr(skb);
            struct tcphdr *tcp_header = tcp_hdr(skb);
            struct udphdr *udp_header = udp_hdr(skb);

            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            u16 src_port = 0, dst_port = 0;

            if (iph->protocol == IPPROTO_TCP)
            {
                src_port = ntohs(tcp_header->source);
                dst_port = ntohs(tcp_header->dest);
            }
            else if (iph->protocol == IPPROTO_UDP)
            {
                src_port = ntohs(udp_header->source);
                dst_port = ntohs(udp_header->dest);
            }

            u32 sip_saddr = ntohl(iph->saddr);
            u32 sip_daddr = ntohl(iph->daddr);
            snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u", IPADDRESS(sip_saddr));
            snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u", IPADDRESS(sip_daddr));

            struct timespec64 ts;
            ktime_get_real_ts64(&ts);
            struct tm result;
            time64_to_tm(ts.tv_sec, 0, &result);
            char cur_time[20];
            snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
                     result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
                     result.tm_hour+8, result.tm_min, result.tm_sec);

            char log_info[100];

            if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
            {
                printk(KERN_INFO "[%s] %s %s %s:%d blocked %s:%d\n",
                       cur_time,
                       iph->protocol == IPPROTO_TCP ? "TCP" : "UDP",
                       skb->dev->name,
                       src_ip,
                       src_port,
                       dst_ip,
                       dst_port);
                snprintf(log_info,sizeof(log_info),"[%s] %s %s %s:%d blocked %s:%d\n",
                         cur_time,
                         iph->protocol == IPPROTO_TCP ? "TCP" : "UDP",
                         skb->dev->name,
                         src_ip,
                         src_port,
                         dst_ip,
                         dst_port);
            }
            else
            {
                printk(KERN_INFO "[%s] ICMP %s %s blocked %s\n",
                       cur_time,
                       skb->dev->name,
                       src_ip,
                       dst_ip);
                snprintf(log_info,sizeof(log_info),"[%s] ICMP %s %s blocked %s\n",
                         cur_time,
                         skb->dev->name,
                         src_ip,
                         dst_ip);
            }

            up(&my_semaphore);

            logprint(log_info);

            return NF_DROP;
        }
    }
    up(&my_semaphore);
    return NF_ACCEPT;
}

static ssize_t my_read(struct file *file, char __user *user_buffer, size_t count, loff_t *ppos)
{
    return simple_read_from_buffer(user_buffer, count, ppos, device_buffer, BUF_SIZE);
}

static ssize_t my_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos)
{
    ssize_t retval = simple_write_to_buffer(device_buffer, BUF_SIZE, ppos, user_buffer, count);
    if (retval > 0)
    {
        // 解析规则
        memset(rules, 0, sizeof(rules));
        num_rules = 0;
        //请求信号量
        if (down_interruptible(&my_semaphore)) {
            /* 若信号量获取失败，则进入等待队列并阻塞 */
            wait_event_interruptible(my_wait_queue, (my_semaphore.count > 0));
        }
        parse_rules();
        //释放信号量
        up(&my_semaphore);
    }
    // 初始化设备缓冲区
    memset(device_buffer, 0, sizeof(device_buffer));
    return retval;
}

// 字符设备文件操作结构体
static const struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .read = my_read,
    .write = my_write,
};

// 设备信息
static struct miscdevice my_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &my_fops,
};

// 初始化模块
static int __init my_module_init(void)
{
    int ret;
    sema_init(&my_semaphore, 1);
    if (filep == NULL) {
        filep = filp_open(LOG_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);
    }

    if (IS_ERR(filep)) {
        pr_err("Open file %s error\n",LOG_FILE);
        return -1;
    }

    if (filep != NULL) {
        // 清空文件内容
        vfs_truncate(&filep->f_path, 0);
    }

    init_rwsem(&file_lock);

    ret = misc_register(&my_misc_device);
    if (ret)
    {
        pr_err("Failed to register misc device\n");
        return ret;
    }

    pr_info("VersaGuard loaded\n");

    nf_blockpkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockpkt_ops == NULL)
        return -ENOMEM;

    nf_blockpkt_ops->hook = nf_blockpkt_handler;
    nf_blockpkt_ops->hooknum = NF_INET_PRE_ROUTING;
    nf_blockpkt_ops->pf = NFPROTO_IPV4;
    nf_blockpkt_ops->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, nf_blockpkt_ops);

    // 初始化设备缓冲区
    memset(device_buffer, 0, sizeof(device_buffer));

    return 0;
}

// 模块注销
static void __exit my_module_exit(void)
{
    int i;

    if (nf_blockpkt_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blockpkt_ops);
        kfree(nf_blockpkt_ops);
    }

    if (filep != NULL) {
        // 清空文件内容
        filp_close(filep, NULL);
    }

    for (i = 0; i < num_rules; i++)
    {
        kfree(rules[i].protocol);
        kfree(rules[i].dev_rule);
        kfree(rules[i].ip_saddr_rule);
        kfree(rules[i].ip_daddr_rule);
        kfree(rules[i].deny_src_port);
        kfree(rules[i].deny_dst_port);
        kfree(rules[i].time_start_rule);
        kfree(rules[i].time_end_rule);
        kfree(rules[i].start_day);
        kfree(rules[i].end_day);
        kfree(rules[i].start_sec);
        kfree(rules[i].end_sec);
    }
    memset(rules, 0, sizeof(rules));
    misc_deregister(&my_misc_device);
    pr_info("VersaGuard unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");



