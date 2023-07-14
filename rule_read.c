#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/timekeeping.h>

#define DEVICE_NAME "firewall" // 设备文件名称
#define BUF_SIZE 1024          // 读取字符串的最大长度，应大于最大规则数*100
#define MAX_RULES 10           // 最大规则数
#define RULE_MAX 10
#define IPADDRESS(addr)              \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

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

static struct firewall_rule rules[MAX_RULES] = {
    {2, "192.168.1.1", "192.168.2.2", "1970-01-01 00:00:00", "2099-12-31 23:59:59", "ens33", "80", "80"},
    // 其他元素的初始化
};
static struct nf_hook_ops *nf_blocktcppkt_ops = NULL;
static struct nf_hook_ops *nf_blockudppkt_ops = NULL;
static struct nf_hook_ops *nf_blockicmppkt_ops = NULL;
static struct nf_hook_ops *nf_blockipsaddr_ops = NULL;
static struct nf_hook_ops *nf_blockipdaddr_ops = NULL;
static struct nf_hook_ops *nf_blocksrcport_ops = NULL;
static struct nf_hook_ops *nf_blockdstport_ops = NULL;
static struct nf_hook_ops *nf_blocktime_ops = NULL;
static struct nf_hook_ops *nf_blockdev_ops = NULL;

inline char *get_protocol(int type)
{
    if (type == 0)
        return "TCP";
    else if (type == 1)
        return "UDP";
    else if (type == 2)
        return "ICMP";
    else
        return "ALL";
}
// #define deinfo(s) ((s[0]==0)?"?":s)

static char device_buffer[BUF_SIZE];
static int num_rules = 0;

inline char *change(char *s)
{
    if (s[0] == 0)
        return "?";
    else
        return s;
}

int rule_num = 1;

bool is_time_between(const char *cur_time, int i)
{
    // 比较字符串，如果cur_time在time_start_rule之后且在time_end_rule之前，则返回true
    return (strcmp(cur_time, rules[i].time_start_rule) >= 0) && (strcmp(cur_time, rules[i].time_end_rule) <= 0);
}

static unsigned int nf_blocktcppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // TCP
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[21];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
             result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
             result.tm_hour + 8, result.tm_min, result.tm_sec);

    for (int i = 0; i < rule_num; i++)
    {
        if (rules[i].protocol_type == 3)
            continue;
        if (rules[i].protocol_type == 0)
        {
            struct iphdr *iph;
            struct udphdr *udph;
            if (!skb)
                return NF_ACCEPT;
            iph = ip_hdr(skb);
            if (iph->protocol == IPPROTO_UDP)
            {
                udph = udp_hdr(skb);
                if (ntohs(udph->dest) == 53)
                {
                    return NF_ACCEPT;
                }
            }
            else if (iph->protocol == IPPROTO_TCP)
            {
                printk(KERN_INFO "Drop TCP packet \n");
                //[当前时间] 协议 网络接口 目的ip:目的端口 blocked 源ip:源端口
                //[2023-07-12 08:06:00] TCP ens33 192.168.1.1:80 blocked 192.168.1.2:21
                printk(KERN_INFO "[%s] %s %s %s:%s blocked %s:%s\n", cur_time, get_protocol(rules[i].protocol_type), change(rules[i].dev_rule),
                       change(rules[i].ip_daddr_rule), change(rules[i].deny_dst_port), change(rules[i].ip_saddr_rule), change(rules[i].deny_src_port));
                return NF_DROP;
            }
            else if (iph->protocol == IPPROTO_ICMP)
            {
                return NF_ACCEPT;
            }
        }
    }
    return NF_ACCEPT;
}

static unsigned int nf_blockudppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // UDP
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[21];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
             result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
             result.tm_hour + 8, result.tm_min, result.tm_sec);
    for (int i = 0; i < rule_num; i++)
    {
        if (rules[i].protocol_type == 3)
            continue;
        if (rules[i].protocol_type == 1)
        {
            struct iphdr *iph;
            if (!skb)
                return NF_ACCEPT;
            iph = ip_hdr(skb);
            if (iph->protocol == IPPROTO_UDP)
            {
                printk(KERN_INFO "Drop UDP packet \n");
                printk(KERN_INFO "[%s] %s %s %s:%s blocked %s:%s\n", cur_time, get_protocol(rules[i].protocol_type), change(rules[i].dev_rule),
                       change(rules[i].ip_daddr_rule), change(rules[i].deny_dst_port), change(rules[i].ip_saddr_rule), change(rules[i].deny_src_port));
                return NF_DROP;
            }
            else if (iph->protocol == IPPROTO_TCP)
            {
                return NF_ACCEPT;
            }
            else if (iph->protocol == IPPROTO_ICMP)
            {
                return NF_ACCEPT;
            }
        }
    }
    return NF_ACCEPT;
}
static unsigned int nf_blockicmppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // ICMP
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[21];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
             result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
             result.tm_hour + 8, result.tm_min, result.tm_sec);
    for (int i = 0; i < rule_num; i++)
    {
        if (rules[i].protocol_type == 3)
            continue;
        if (rules[i].protocol_type == 2)
        {
            struct iphdr *iph;
            struct udphdr *udph;
            if (!skb)
                return NF_ACCEPT;
            iph = ip_hdr(skb);
            if (iph->protocol == IPPROTO_UDP)
            {
                udph = udp_hdr(skb);
                if (ntohs(udph->dest) == 53)
                {
                    return NF_ACCEPT;
                }
            }
            else if (iph->protocol == IPPROTO_TCP)
            {
                return NF_ACCEPT;
            }
            else if (iph->protocol == IPPROTO_ICMP)
            {
                printk(KERN_INFO "Drop ICMP packet \n");
                printk(KERN_INFO "[%s] %s %s %s:%s blocked %s:%s\n", cur_time, get_protocol(rules[i].protocol_type), change(rules[i].dev_rule),
                       change(rules[i].ip_daddr_rule), change(rules[i].deny_dst_port), change(rules[i].ip_saddr_rule), change(rules[i].deny_src_port));
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}
static unsigned int nf_blockipsaddr_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 源IP地址
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[21];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
             result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
             result.tm_hour + 8, result.tm_min, result.tm_sec);
    if (!skb)
    {
        return NF_ACCEPT;
    }
    else
    {
        char *str = (char *)kmalloc(16, GFP_KERNEL);
        u32 sip;
        struct sk_buff *sb = NULL;
        struct iphdr *iph;

        sb = skb;
        iph = ip_hdr(sb);
        sip = ntohl(iph->saddr);

        sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip));

        for (int i = 0; i < rule_num; i++)
        { // 遍历所有规则
            if (rules[i].ip_saddr_rule == NULL)
                continue;
            if (!strcmp(str, rules[i].ip_saddr_rule)) // 与设定过滤的源ip地址对比
            {
                printk(KERN_INFO "Drop SRC_IP packet \n");
                printk(KERN_INFO "[%s] %s %s %s:%s blocked %s:%s\n", cur_time, get_protocol(rules[i].protocol_type), change(rules[i].dev_rule),
                       change(rules[i].ip_daddr_rule), change(rules[i].deny_dst_port), change(rules[i].ip_saddr_rule), change(rules[i].deny_src_port));
                return NF_DROP;
            }
        }
        return NF_ACCEPT;
    }
}

static unsigned int nf_blockipdaddr_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 目标IP地址
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[21];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
             result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
             result.tm_hour + 8, result.tm_min, result.tm_sec);
    if (!skb)
    {
        return NF_ACCEPT;
    }
    else
    {
        char *str = (char *)kmalloc(16, GFP_KERNEL);
        u32 sip;
        struct sk_buff *sb = NULL;
        struct iphdr *iph;

        sb = skb;
        iph = ip_hdr(sb);
        sip = ntohl(iph->daddr);

        sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip));

        for (int i = 0; i < rule_num; i++)
        {
            if (rules[i].ip_daddr_rule == NULL)
                continue;
            if (!strcmp(str, rules[i].ip_daddr_rule))
            {
                printk(KERN_INFO "Drop DST_IP packet \n");
                printk(KERN_INFO "[%s] %s %s %s:%s blocked %s:%s\n", cur_time, get_protocol(rules[i].protocol_type), change(rules[i].dev_rule),
                       change(rules[i].ip_daddr_rule), change(rules[i].deny_dst_port), change(rules[i].ip_saddr_rule), change(rules[i].deny_src_port));
                return NF_DROP;
            }
        }
        return NF_ACCEPT;
    }
}

static unsigned int nf_blocksrcport_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 源端口
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[21];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
             result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
             result.tm_hour + 8, result.tm_min, result.tm_sec);
    struct iphdr *iph;
    if (!skb)
        return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *thead = (struct tcphdr *)(skb->data + (iph->ihl * 4));
        for (int i = 0; i < rule_num; i++)
        {
            if (rules[i].deny_src_port == NULL)
                continue;
            if ((thead->source) == *(unsigned short *)rules[i].deny_src_port)
            {
                printk(KERN_INFO "Drop SRC_PORT packet \n");
                printk(KERN_INFO "[%s] %s %s %s:%s blocked %s:%s\n", cur_time, get_protocol(rules[i].protocol_type), change(rules[i].dev_rule),
                       change(rules[i].ip_daddr_rule), change(rules[i].deny_dst_port), change(rules[i].ip_saddr_rule), change(rules[i].deny_src_port));
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static unsigned int nf_blockdstport_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 目标端口
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[21];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
             result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
             result.tm_hour + 8, result.tm_min, result.tm_sec);
    struct iphdr *iph;
    if (!skb)
        return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *thead = (struct tcphdr *)(skb->data + (iph->ihl * 4));
        for (int i = 0; i < rule_num; i++)
        {
            if (rules[i].deny_dst_port == NULL)
                continue;
            if ((thead->dest) == *(unsigned short *)rules[i].deny_dst_port)
            {
                printk(KERN_INFO "Drop DST_PORT packet \n");
                printk(KERN_INFO "[%s] %s %s %s:%s blocked %s:%s\n", cur_time, get_protocol(rules[i].protocol_type), change(rules[i].dev_rule),
                       change(rules[i].ip_daddr_rule), change(rules[i].deny_dst_port), change(rules[i].ip_saddr_rule), change(rules[i].deny_src_port));
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static unsigned int nf_blocktime_handler(void *priv, const struct nf_hook_state *state) // 时间
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[21];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
             result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
             result.tm_hour + 8, result.tm_min, result.tm_sec);

    for (int i = 0; i < rule_num; i++)
    {
        bool is_between = is_time_between(cur_time, i);
        if (is_between)
        {
            printk(KERN_INFO "Drop TIME packet\n");
            printk(KERN_INFO "[%s] %s %s %s:%s blocked %s:%s\n", cur_time, get_protocol(rules[i].protocol_type), change(rules[i].dev_rule),
                   change(rules[i].ip_daddr_rule), change(rules[i].deny_dst_port), change(rules[i].ip_saddr_rule), change(rules[i].deny_src_port));
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static unsigned int nf_blockdev_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 网络接口
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);
    char cur_time[21];
    snprintf(cur_time, sizeof(cur_time), "%04ld-%02d-%02d %02d:%02d:%02d",
             result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
             result.tm_hour + 8, result.tm_min, result.tm_sec);
    struct net_device *dev;
    if (!skb)
        return NF_ACCEPT;
    dev = skb->dev;
    if (!dev)
        return NF_ACCEPT;
    for (int i = 0; i < rule_num; i++)
    {
        if (rules[i].dev_rule == NULL)
            continue;
        if (!strcmp(dev->name, rules[i].dev_rule))
        {
            printk(KERN_INFO "Drop DEV packet \n");
            printk(KERN_INFO "[%s] %s %s %s:%s blocked %s:%s\n", cur_time, get_protocol(rules[i].protocol_type), change(rules[i].dev_rule),
                   change(rules[i].ip_daddr_rule), change(rules[i].deny_dst_port), change(rules[i].ip_saddr_rule), change(rules[i].deny_src_port));
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

// 将读取到的字符串解析并保存在结构体数组中
static void parse_rules(void)
{
    char *pos;
    char *rule_str;
    const char *delim = " ";
    int i;
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
        if (rule.dev_rule[0] == '?' && rule.dev_rule[1] == 0)
            rule.dev_rule[0] = 0;

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (ip_saddr_rule)\n");
            return;
        }
        rule.ip_saddr_rule = kstrdup(token, GFP_KERNEL);
        if (rule.ip_saddr_rule[0] == '?' && rule.ip_saddr_rule[1] == 0)
            rule.ip_saddr_rule[0] = 0;

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (ip_daddr_rule)\n");
            return;
        }
        rule.ip_daddr_rule = kstrdup(token, GFP_KERNEL);
        if (rule.ip_daddr_rule[0] == '?' && rule.ip_daddr_rule[1] == 0)
            rule.ip_daddr_rule[0] = 0;

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (src)\n");
            return;
        }
        rule.deny_src_port = kstrdup(token, GFP_KERNEL);
        if (rule.deny_src_port[0] == '?' && rule.deny_src_port[1] == 0)
            rule.deny_src_port[0] = 0;

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (dst)\n");
            return;
        }
        rule.deny_dst_port = kstrdup(token, GFP_KERNEL);
        if (rule.deny_dst_port[0] == '?' && rule.deny_dst_port[1] == 0)
            rule.deny_dst_port[0] = 0;

        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format (s_day)\n");
            return;
        }
        rule.start_day = kstrdup(token, GFP_KERNEL);

        if (rule.start_day[0] == '?' && rule.start_day[1] == 0)
        {
            // 分配内存给 start_day
            rule.start_day = kmalloc(strlen("1970-01-01") + 1, GFP_KERNEL);
            if (!rule.start_day)
                return;

            // 分配内存给 start_sec
            rule.start_sec = kmalloc(strlen("00:00:00") + 1, GFP_KERNEL);
            if (!rule.start_sec)
            {
                kfree(rule.start_day);
                return;
            }

            // 将 "1970-01-01" 赋值给 start_day
            strcpy(rule.start_day, "1970-01-01");

            // 将 "00:00:00" 赋值给 start_sec
            strcpy(rule.start_sec, "00:00:00");
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
            rule.end_day = kmalloc(strlen("1970-01-01") + 1, GFP_KERNEL);
            if (!rule.end_day)
                return;

            rule.end_sec = kmalloc(strlen("00:00:00") + 1, GFP_KERNEL);
            if (!rule.end_sec)
            {
                kfree(rule.end_day);
                return;
            }

            strcpy(rule.end_day, "2099-12-31");

            strcpy(rule.end_sec, "23:59:59");
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
        else if (rule.protocol[0] == 't' && rule.protocol[1] == 'c' && rule.protocol[2] == 'p' && rule.protocol[3] == 0)
            rule.protocol_type = 0;
        else if (rule.protocol[0] == 'u' && rule.protocol[1] == 'd' && rule.protocol[2] == 'p' && rule.protocol[3] == 0)
            rule.protocol_type = 1;
        else if (rule.protocol[0] == 'i' && rule.protocol[1] == 'c' && rule.protocol[2] == 'm' && rule.protocol[3] == 'p' && rule.protocol[4] == 0)
            rule.protocol_type = 2;
        else
        {
            rule.protocol_type = -1; // 输入格式错误
            pr_err("Invalid protocol format\n");
            return;
        }

        // 将时间字符串拼接为正确格式
        rule.time_start_rule = kmalloc(sizeof(char) * (strlen(rule.start_sec) + strlen(rule.start_day) + 10), GFP_KERNEL);
        rule.time_start_rule[0] = '\0'; // 初始化为空字符串
        strlcpy(rule.time_start_rule, rule.start_day, strlen(rule.start_sec) + strlen(rule.start_day) + 10);
        strlcat(rule.time_start_rule, " ", strlen(rule.start_sec) + strlen(rule.start_day) + 10);
        strlcat(rule.time_start_rule, rule.start_sec, strlen(rule.start_sec) + strlen(rule.start_day) + 10);

        rule.time_end_rule = kmalloc(sizeof(char) * (strlen(rule.end_sec) + strlen(rule.end_day) + 10), GFP_KERNEL);
        rule.time_end_rule[0] = '\0'; // 初始化为空字符串
        strlcpy(rule.time_end_rule, rule.end_day, strlen(rule.end_sec) + strlen(rule.end_day) + 10);
        strlcat(rule.time_end_rule, " ", strlen(rule.end_sec) + strlen(rule.end_day) + 10);
        strlcat(rule.time_end_rule, rule.end_sec, strlen(rule.end_sec) + strlen(rule.end_day) + 10);

        rules[num_rules++] = rule;
        rule_num=num_rules;
    }

    // // 打印读取到的信息到日志
    // for (i = 0; i < num_rules; i++)
    // {
    //     // 有缺省是直接打印空字符串，有点问题
    //     // pr_info("Rule%d: protocol_type=%d, dev_rule=%s, ip_saddr_rule=%s, ip_daddr_rule=%s, deny_src_port=%s, deny_dst_port=%s, time_start_rule=%s, time_end_rule=%s",
    //     //         i + 1, rules[i].protocol_type, rules[i].dev_rule, rules[i].ip_saddr_rule, rules[i].ip_daddr_rule, rules[i].deny_src_port, rules[i].deny_dst_port, rules[i].time_start_rule, rules[i].time_end_rule);

    //     // 有缺省打印'？'，能正常打印
    //     pr_info("Rule%d: protocol_type=%d, dev_rule=%s, ip_saddr_rule=%s, ip_daddr_rule=%s, deny_src_port=%s, deny_dst_port=%s, time_start_rule=%s, time_end_rule=%s",
    //             i + 1, rules[i].protocol_type, change(rules[i].dev_rule), change(rules[i].ip_saddr_rule), change(rules[i].ip_daddr_rule), change(rules[i].deny_src_port), change(rules[i].deny_dst_port), change(rules[i].time_start_rule), change(rules[i].time_end_rule));
    // }
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
        rule_num=0;
        parse_rules();
    }
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

    ret = misc_register(&my_misc_device);
    if (ret)
    {
        pr_err("Failed to register misc device\n");
        return ret;
    }

    pr_info("My module loaded\n");

    // 初始化设备缓冲区
    memset(device_buffer, 0, sizeof(device_buffer));

    nf_blocktcppkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blocktcppkt_ops != NULL)
    {
        nf_blocktcppkt_ops->hook = (nf_hookfn *)nf_blocktcppkt_handler;
        nf_blocktcppkt_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blocktcppkt_ops->pf = NFPROTO_IPV4;
        nf_blocktcppkt_ops->priority = NF_IP_PRI_FIRST;

        nf_register_net_hook(&init_net, nf_blocktcppkt_ops);
    }

    nf_blockudppkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockudppkt_ops != NULL)
    {
        nf_blockudppkt_ops->hook = (nf_hookfn *)nf_blockudppkt_handler;
        nf_blockudppkt_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockudppkt_ops->pf = NFPROTO_IPV4;
        nf_blockudppkt_ops->priority = NF_IP_PRI_FIRST + 1;

        nf_register_net_hook(&init_net, nf_blockudppkt_ops);
    }

    nf_blockicmppkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockicmppkt_ops != NULL)
    {
        nf_blockicmppkt_ops->hook = (nf_hookfn *)nf_blockicmppkt_handler;
        nf_blockicmppkt_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockicmppkt_ops->pf = NFPROTO_IPV4;
        nf_blockicmppkt_ops->priority = NF_IP_PRI_FIRST + 2;

        nf_register_net_hook(&init_net, nf_blockicmppkt_ops);
    }

    nf_blockipsaddr_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockipsaddr_ops != NULL)
    {
        nf_blockipsaddr_ops->hook = (nf_hookfn *)nf_blockipsaddr_handler;
        nf_blockipsaddr_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockipsaddr_ops->pf = NFPROTO_IPV4;
        nf_blockipsaddr_ops->priority = NF_IP_PRI_FIRST + 3;

        nf_register_net_hook(&init_net, nf_blockipsaddr_ops);
    }
    nf_blockipdaddr_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockipdaddr_ops != NULL)
    {
        nf_blockipdaddr_ops->hook = (nf_hookfn *)nf_blockipdaddr_handler;
        nf_blockipdaddr_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockipdaddr_ops->pf = NFPROTO_IPV4;
        nf_blockipdaddr_ops->priority = NF_IP_PRI_FIRST + 4;

        nf_register_net_hook(&init_net, nf_blockipdaddr_ops);
    }
    nf_blocksrcport_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blocksrcport_ops != NULL)
    {
        nf_blocksrcport_ops->hook = (nf_hookfn *)nf_blocksrcport_handler;
        nf_blocksrcport_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blocksrcport_ops->pf = NFPROTO_IPV4;
        nf_blocksrcport_ops->priority = NF_IP_PRI_FIRST + 5;

        nf_register_net_hook(&init_net, nf_blocksrcport_ops);
    }
    nf_blockdstport_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockdstport_ops != NULL)
    {
        nf_blockdstport_ops->hook = (nf_hookfn *)nf_blockdstport_handler;
        nf_blockdstport_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockdstport_ops->pf = NFPROTO_IPV4;
        nf_blockdstport_ops->priority = NF_IP_PRI_FIRST + 6;

        nf_register_net_hook(&init_net, nf_blockdstport_ops);
    }
    nf_blocktime_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blocktime_ops != NULL)
    {
        nf_blocktime_ops->hook = (nf_hookfn *)nf_blocktime_handler;
        nf_blocktime_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blocktime_ops->pf = NFPROTO_IPV4;
        nf_blocktime_ops->priority = NF_IP_PRI_FIRST + 7;

        nf_register_net_hook(&init_net, nf_blocktime_ops);
    }
    nf_blockdev_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockdev_ops != NULL)
    {
        nf_blockdev_ops->hook = (nf_hookfn *)nf_blockdev_handler;
        nf_blockdev_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockdev_ops->pf = NFPROTO_IPV4;
        nf_blockdev_ops->priority = NF_IP_PRI_FIRST + 8;

        nf_register_net_hook(&init_net, nf_blockdev_ops);
    }

    return 0;
}

// 模块注销
static void __exit my_module_exit(void)
{
    int i;

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

    if (nf_blocktcppkt_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blocktcppkt_ops);
        kfree(nf_blocktcppkt_ops);
    }
    if (nf_blockudppkt_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blockudppkt_ops);
        kfree(nf_blockudppkt_ops);
    }
    if (nf_blockicmppkt_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blockicmppkt_ops);
        kfree(nf_blockicmppkt_ops);
    }
    if (nf_blockipsaddr_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blockipsaddr_ops);
        kfree(nf_blockipsaddr_ops);
    }
    if (nf_blockipdaddr_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blockipdaddr_ops);
        kfree(nf_blockipdaddr_ops);
    }
    if (nf_blocksrcport_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blocksrcport_ops);
        kfree(nf_blocksrcport_ops);
    }
    if (nf_blockdstport_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blockdstport_ops);
        kfree(nf_blockdstport_ops);
    }
    if (nf_blocktime_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blocktime_ops);
        kfree(nf_blocktime_ops);
    }
    if (nf_blockdev_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blockdev_ops);
        kfree(nf_blockdev_ops);
    }

    pr_info("My module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
