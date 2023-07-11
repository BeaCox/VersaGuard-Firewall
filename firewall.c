#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/timekeeping.h>

#define IPADDRESS(addr)              \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

#define RULE_MAX 100
typedef struct
{
    int protocol_type;     // 过滤协议类型：0为tcp，1为udp，2为icmp
    char *ip_saddr_rule;   // 源IP地址过滤规则
    char *ip_daddr_rule;   // 目标IP地址过滤规则
    char *time_start_rule; // 起始时间过滤规则
    char *time_end_rule;   // 终止时间过滤规则，在该时间段内的报文将被过滤
    char *dev_rule;        // 网络接口过滤规则
    char *deny_src_port;   // 源端口过滤规则
    char *deny_dst_port;   // 目标端口过滤规则
} Rule;

Rule rules[RULE_MAX] = {
    {3, NULL, NULL, "1970-01-01 00:00:00", "2099-12-31 23:59:59", NULL, NULL, NULL},
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

// rule_read
int rule_num = 1;

bool is_time_between(const char *cur_time, int i)
{
    // 比较字符串，如果cur_time在time_start_rule之后且在time_end_rule之前，则返回true
    return (strcmp(cur_time, rules[i].time_start_rule) >= 0) && (strcmp(cur_time, rules[i].time_end_rule) <= 0);
}

static unsigned int nf_blocktcppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // TCP
{
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
    for (int i = 0; i < rule_num; i++)
    {
        if (rules[i].protocol_type == 3)
            continue;
        if (rules[i].protocol_type == 1)
        {
            struct iphdr *iph;
            struct udphdr *udph;
            if (!skb)
                return NF_ACCEPT;
            iph = ip_hdr(skb);
            if (iph->protocol == IPPROTO_UDP)
            {
                printk(KERN_INFO "Drop UDP packet \n");
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
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}
static unsigned int nf_blockipsaddr_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 源IP地址
{

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
                return NF_DROP;
            }
        }
        return NF_ACCEPT;
    }
}

static unsigned int nf_blockipdaddr_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 目标IP地址
{
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
                return NF_DROP;
            }
        }
        return NF_ACCEPT;
    }
}

static unsigned int nf_blocksrcport_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 源端口
{
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
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static unsigned int nf_blockdstport_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 目标端口
{
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
             result.tm_hour, result.tm_min, result.tm_sec);

    for (int i = 0; i < rule_num; i++)
    {
        bool is_between = is_time_between(cur_time, i);
        if (is_between)
        {
            printk(KERN_INFO "Drop TIME packet\n");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static unsigned int nf_blockdev_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 网络接口
{
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
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static int __init nf_firewall_init(void)
{

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

static void __exit nf_firewall_exit(void)
{

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
    printk(KERN_INFO "Exit");
}

module_init(nf_firewall_init);
module_exit(nf_firewall_exit);

MODULE_LICENSE("GPL");
