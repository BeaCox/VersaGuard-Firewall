#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/slab.h>

#define DEVICE_NAME "firewall"
#define BUF_SIZE 256
#define MAX_RULES 10

struct firewall_rule
{
    int id;
    char *protocol;
    char *src_ip;
    char *dst_ip;
    char *src_port;
    char *dst_port;
    char *start_time;
    char *end_time;
    int action;
};

static char device_buffer[BUF_SIZE];
static struct firewall_rule rules[MAX_RULES];
static int num_rules = 0;

static void parse_rules(void)
{
    char *pos;
    char *rule_str;
    const char *delim = " ";
    char *endptr;
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
            pr_err("Invalid rule format 1\n");
            return;
        }
        rule.id = (int)simple_strtol(token, &endptr, 10);

        if (*endptr != '\0')
        {
            pr_err("Invalid rule format 11\n");
            return;
        }
        token = strsep(&rule_str, delim);

        if (token == NULL)
        {
            pr_err("Invalid rule format 2\n");
            return;
        }

        rule.protocol = kstrdup(token, GFP_KERNEL);
        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format 3\n");
            return;
        }
        rule.src_ip = kstrdup(token, GFP_KERNEL);
        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format 4\n");
            return;
        }
        rule.dst_ip = kstrdup(token, GFP_KERNEL);
        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format 5\n");
            return;
        }
        rule.src_port = kstrdup(token, GFP_KERNEL);
        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format 6\n");
            return;
        }
        rule.dst_port = kstrdup(token, GFP_KERNEL);
        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format 7\n");
            return;
        }
        rule.start_time = kstrdup(token, GFP_KERNEL);
        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format 8\n");
            return;
        }
        rule.end_time = kstrdup(token, GFP_KERNEL);
        token = strsep(&rule_str, delim);
        if (token == NULL)
        {
            pr_err("Invalid rule format 9\n");
            return;
        }
        rule.action = (int)simple_strtol(token, &endptr, 10);
        if (*endptr != '\0')
        {
            pr_err("Invalid rule format 99\n");
            return;
        }

        rules[num_rules++] = rule;
    }
    // for (i = 0; i < num_rules; i++)
    // {
        // pr_info("Rule %d: protocol=%s, src_ip=%s, dst_ip=%s, src_port=%s, dst_port=%s, start_time=%s, end_time=%s, action=%d\n",
                // rules[i].id, rules[i].protocol, rules[i].src_ip, rules[i].dst_ip, rules[i].src_port, rules[i].dst_port, rules[i].start_time, rules[i].end_time, rules[i].action);
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

        parse_rules();
    }
    return retval;
}

static const struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .read = my_read,
    .write = my_write,
};

static struct miscdevice my_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &my_fops,
};

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

static void __exit my_module_exit(void)
{
    int i;

    for (i = 0; i < num_rules; i++)
    {
        kfree(rules[i].protocol);
        kfree(rules[i].src_ip);
        kfree(rules[i].dst_ip);
        kfree(rules[i].src_port);
        kfree(rules[i].dst_port);
        kfree(rules[i].start_time);
        kfree(rules[i].end_time);
    }

    misc_deregister(&my_misc_device);
    pr_info("My module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
