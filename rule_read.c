#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/slab.h>

#define DEVICE_NAME "firewall" // 设备文件名称
#define BUF_SIZE 1024          // 读取字符串的最大长度，应大于最大规则数*100
#define MAX_RULES 10           // 最大规则数
// #define deinfo(s) ((s[0]==0)?"?":s)
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

static char device_buffer[BUF_SIZE];
static struct firewall_rule rules[MAX_RULES];
static int num_rules = 0;

inline char *change(char *s)
{
    if (s[0] == 0)
        return "?";
    else
        return s;
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
        if (rule.protocol[0] == '?' && rule.protocol[1] == 0)
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
    }

    // 打印读取到的信息到日志
    for (i = 0; i < num_rules; i++)
    {
        // 有缺省是直接打印空字符串，有点问题
        // pr_info("Rule%d: protocol_type=%d, dev_rule=%s, ip_saddr_rule=%s, ip_daddr_rule=%s, deny_src_port=%s, deny_dst_port=%s, time_start_rule=%s, time_end_rule=%s",
        //         i + 1, rules[i].protocol_type, rules[i].dev_rule, rules[i].ip_saddr_rule, rules[i].ip_daddr_rule, rules[i].deny_src_port, rules[i].deny_dst_port, rules[i].time_start_rule, rules[i].time_end_rule);

        // 有缺省打印'？'，能正常打印
        pr_info("Rule%d: protocol_type=%d, dev_rule=%s, ip_saddr_rule=%s, ip_daddr_rule=%s, deny_src_port=%s, deny_dst_port=%s, time_start_rule=%s, time_end_rule=%s",
                i + 1, rules[i].protocol_type, change(rules[i].dev_rule), change(rules[i].ip_saddr_rule), change(rules[i].ip_daddr_rule), change(rules[i].deny_src_port), change(rules[i].deny_dst_port), change(rules[i].time_start_rule), change(rules[i].time_end_rule));
    }
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
    pr_info("My module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
