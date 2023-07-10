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

int protocol_type = 0;                                // 过滤协议类型：0为tcp，1为udp，2为icmp
static char *ip_saddr_rule = "172.217.194.99";        // 源IP地址过滤规则
static char *ip_daddr_rule = "172.217.194.99";        // 目标IP地址过滤规则
static char *time_start_rule = "2023-06-28 08:09:10"; // 起始时间过滤规则
static char *time_end_rule = "2023-06-29 08:09:10";   // 终止时间过滤规则，在该时间段内的报文将被过滤
static char *dev_rule = "eth0";                       // 网络接口过滤规则
int deny_src_port = 80;                               // 源端口过滤规则
int deny_dst_port = 80;                               // 目标端口过滤规则
static struct nf_hook_ops *nf_blocktcppkt_ops = NULL;
static struct nf_hook_ops *nf_blockudppkt_ops = NULL;
static struct nf_hook_ops *nf_blockicmppkt_ops = NULL;
static struct nf_hook_ops *nf_blockipsaddr_ops = NULL;
static struct nf_hook_ops *nf_blockipdaddr_ops = NULL;
static struct nf_hook_ops *nf_blocksrcport_ops = NULL;
static struct nf_hook_ops *nf_blockdstport_ops = NULL;
static struct nf_hook_ops *nf_blocktime_ops = NULL;
static struct nf_hook_ops *nf_blockdev_ops = NULL;

bool is_time_between(const char *cur_time)
{
    // 比较字符串，如果cur_time在time_start_rule之后且在time_end_rule之前，则返回true
    return (strcmp(cur_time, time_start_rule) >= 0) && (strcmp(cur_time, time_end_rule) <= 0);
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
        if (!strcmp(str, ip_saddr_rule)) // 与设定过滤的源ip地址对比
        {
            printk(KERN_INFO "Drop IP_SOURCE \n");
            return NF_DROP;
        }
        else
        {
            return NF_ACCEPT;
        }
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
        if (!strcmp(str, ip_daddr_rule))
        {
            return NF_DROP;
            printk(KERN_INFO "Drop IP_DESTINATION \n");
        }
        else
        {
            return NF_ACCEPT;
        }
    }
}

static unsigned int nf_blocktcppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // TCP
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
    return NF_ACCEPT;
}

static unsigned int nf_blockudppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // UDP
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
            printk(KERN_INFO "Drop UDP packet \n");
            return NF_DROP;
        }
    }
    else if (iph->protocol == IPPROTO_TCP)
    {
        return NF_ACCEPT;
    }
    else if (iph->protocol == IPPROTO_ICMP)
    {
        return NF_ACCEPT;
    }
    return NF_ACCEPT;
}

static unsigned int nf_blockicmppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // ICMP
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
    return NF_ACCEPT;
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
        if ((thead->source) == htons(deny_src_port))
        {
            printk(KERN_INFO "Drop SRC_PORT \n");
            return NF_DROP;
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
        if ((thead->dest) == htons(deny_dst_port))
        {
            printk(KERN_INFO "Drop DST_PORT \n");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static unsigned int nf_blocktime_handler(void *priv, const struct nf_hook_state *state)
{
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);

    struct tm result;
    time64_to_tm(ts.tv_sec, 0, &result);

    char YMD[15] = {0};
    char HMS[10] = {0};
    strftime(YMD, sizeof(YMD), "%F ", &result);
    strftime(HMS, sizeof(HMS), "%T", &result);

    char *cur_time = (char *)kmalloc(21 * sizeof(char), GFP_KERNEL);
    strncpy(cur_time, YMD, 11);
    strncat(cur_time, HMS, 8);

    bool is_between = is_time_between(cur_time);
    kfree(cur_time);

    if (is_between)
    {
        return NF_ACCEPT;
    }
    else
    {
        printk(KERN_INFO "Drop TIME packet\n");
        return NF_DROP;
    }
}
static unsigned int nf_blockdev_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) // 网络接口
{
    struct net_device *dev;
    if (!skb)
        return NF_ACCEPT;
    dev = skb->dev;
    if (!dev)
        return NF_ACCEPT;
    if (strcmp(dev->name, dev_rule) == 0)
    {
        printk(KERN_INFO "Drop DEV \n");
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static int __init nf_firewall_init(void)
{
    switch (protocol_type)
    {
    case 0:
        nf_blocktcppkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
        if (nf_blocktcppkt_ops != NULL)
        {
            nf_blocktcppkt_ops->hook = (nf_hookfn *)nf_blocktcppkt_handler;
            nf_blocktcppkt_ops->hooknum = NF_INET_PRE_ROUTING;
            nf_blocktcppkt_ops->pf = NFPROTO_IPV4;
            nf_blocktcppkt_ops->priority = NF_IP_PRI_FIRST;

            nf_register_net_hook(&init_net, nf_blocktcppkt_ops);
        }
        break;
    case 1:
        nf_blockudppkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
        if (nf_blockudppkt_ops != NULL)
        {
            nf_blockudppkt_ops->hook = (nf_hookfn *)nf_blockudppkt_handler;
            nf_blockudppkt_ops->hooknum = NF_INET_PRE_ROUTING;
            nf_blockudppkt_ops->pf = NFPROTO_IPV4;
            nf_blockudppkt_ops->priority = NF_IP_PRI_FIRST;

            nf_register_net_hook(&init_net, nf_blockudppkt_ops);
        }
        break;
    case 2:
        nf_blockicmppkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
        if (nf_blockicmppkt_ops != NULL)
        {
            nf_blockicmppkt_ops->hook = (nf_hookfn *)nf_blockicmppkt_handler;
            nf_blockicmppkt_ops->hooknum = NF_INET_PRE_ROUTING;
            nf_blockicmppkt_ops->pf = NFPROTO_IPV4;
            nf_blockicmppkt_ops->priority = NF_IP_PRI_FIRST;

            nf_register_net_hook(&init_net, nf_blockicmppkt_ops);
        }
        break;
    default:
        break;
    }

    nf_blockipsaddr_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockipsaddr_ops != NULL)
    {
        nf_blockipsaddr_ops->hook = (nf_hookfn *)nf_blockipsaddr_handler;
        nf_blockipsaddr_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockipsaddr_ops->pf = NFPROTO_IPV4;
        nf_blockipsaddr_ops->priority = NF_IP_PRI_FIRST + 1;

        nf_register_net_hook(&init_net, nf_blockipsaddr_ops);
    }
    nf_blockipdaddr_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockipdaddr_ops != NULL)
    {
        nf_blockipdaddr_ops->hook = (nf_hookfn *)nf_blockipdaddr_handler;
        nf_blockipdaddr_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockipdaddr_ops->pf = NFPROTO_IPV4;
        nf_blockipdaddr_ops->priority = NF_IP_PRI_FIRST + 2;

        nf_register_net_hook(&init_net, nf_blockipdaddr_ops);
    }
    nf_blocksrcport_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blocksrcport_ops != NULL)
    {
        nf_blocksrcport_ops->hook = (nf_hookfn *)nf_blocksrcport_handler;
        nf_blocksrcport_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blocksrcport_ops->pf = NFPROTO_IPV4;
        nf_blocksrcport_ops->priority = NF_IP_PRI_FIRST + 3;

        nf_register_net_hook(&init_net, nf_blocksrcport_ops);
    }
    nf_blockdstport_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockdstport_ops != NULL)
    {
        nf_blockdstport_ops->hook = (nf_hookfn *)nf_blockdstport_handler;
        nf_blockdstport_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockdstport_ops->pf = NFPROTO_IPV4;
        nf_blockdstport_ops->priority = NF_IP_PRI_FIRST + 4;

        nf_register_net_hook(&init_net, nf_blockdstport_ops);
    }
    nf_blocktime_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blocktime_ops != NULL)
    {
        nf_blocktime_ops->hook = (nf_hookfn *)nf_blocktime_handler;
        nf_blocktime_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blocktime_ops->pf = NFPROTO_IPV4;
        nf_blocktime_ops->priority = NF_IP_PRI_FIRST + 5;

        nf_register_net_hook(&init_net, nf_blocktime_ops);
    }
    nf_blockdev_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nf_blockdev_ops != NULL)
    {
        nf_blockdev_ops->hook = (nf_hookfn *)nf_blockdev_handler;
        nf_blockdev_ops->hooknum = NF_INET_PRE_ROUTING;
        nf_blockdev_ops->pf = NFPROTO_IPV4;
        nf_blockdev_ops->priority = NF_IP_PRI_FIRST + 6;

        nf_register_net_hook(&init_net, nf_blockdev_ops);
    }
    return 0;
}

static void __exit nf_firewall_exit(void)
{
    switch (protocol_type)
    {
    case 0:
        if (nf_blocktcppkt_ops != NULL)
        {
            nf_unregister_net_hook(&init_net, nf_blocktcppkt_ops);
            kfree(nf_blocktcppkt_ops);
        }
        break;
    case 1:
        if (nf_blockudppkt_ops != NULL)
        {
            nf_unregister_net_hook(&init_net, nf_blockudppkt_ops);
            kfree(nf_blockudppkt_ops);
        }
        break;
    case 2:
        if (nf_blockicmppkt_ops != NULL)
        {
            nf_unregister_net_hook(&init_net, nf_blockicmppkt_ops);
            kfree(nf_blockicmppkt_ops);
        }
        break;
    default:
        break;
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
