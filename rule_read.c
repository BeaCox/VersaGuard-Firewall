#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <stdbool.h>

// 模块信息
MODULE_LICENSE("GPL");
MODULE_AUTHOR(" ");
MODULE_DESCRIPTION(" ");

// 设备名称和主机号
#define DEVICE_NAME "my_device"
#define DEVICE_MAJOR 240

// 存储规则的结构体
struct Rule
{
    int id;
    char *protocol;
    int protocol_type;  // 0为tcp，1为udp，2为ping
    char *src_ip;       // 源IP
    char *dst_ip;       // 目的IP
    int src_port;       // 源端口
    int dst_port;       // 目的端口
    char *start_time;   // 开始时同
    char *end_time;     // 结束时同
    int action;        // 动作（0拦截,1通过）
};

// 存储规则的数组
struct Rule rules[100];
int num_rules = 0;

// 声明字符设备文件
static struct file_operations fops;

// 将规则写入设备文件
static ssize_t my_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    char data[256];
    copy_from_user(data, buf, len);

    // 处理和存储规则
    char *line;
    char *rule;
    char *context;

    // 根据换行符将数据拆分为若干单独的规则
    line = strtok(data, "\n");
    while (line != NULL)
    {
        rule = line;

        // 使用空格作为分隔符将规则拆分为多个组件
        int index = 0;
        char *token = strtok_r(rule, " ", &context);
        while (token != NULL)
        {
            // 将规则的每一项存储在结构中
            switch (index)
            {
            case 0:
                rules[num_rules].id = atoi(token);
                break;
            case 1:
                rules[num_rules].protocol = kstrdup(token, GFP_KERNEL);
                if (strcmp(rules[num_rules].protocol, "tcp") == 0)
                    rules[num_rules].protocol_type == 0;
                else if (strcmp(rules[num_rules].protocol, "udp") == 0)
                    rules[num_rules].protocol_type == 1;
                else if (strcmp(rules[num_rules].protocol, "ping") == 0)
                    rules[num_rules].protocol_type == 2;
                else
                    rules[num_rules].protocol_type == -1;  // 类型输入错误
                break;
            case 2:
                rules[num_rules].src_ip = kstrdup(token, GFP_KERNEL);
                break;
            case 3:
                rules[num_rules].dst_ip = kstrdup(token, GFP_KERNEL);
                break;
            case 4:
                rules[num_rules].src_port = atoi(token);
                break;
            case 5:
                rules[num_rules].dst_port = atoi(token);
                break;
            case 6:
                rules[num_rules].start_time = kstrdup(token, GFP_KERNEL);
                break;
            case 7:
                rules[num_rules].end_time = kstrdup(token, GFP_KERNEL);
                break;
            case 8:
                rules[num_rules].action = atoi(token);
                break;
            default:
                break;
            }
            index++;
            token = strtok_r(NULL, " ", &context);
        }

        num_rules++;
        line = strtok(NULL, "\n");
    }

    return len;
}

// 从设备文件中读取规则
static ssize_t my_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    char data[256];
    char rule[256];
    int position = 0;

    for (int i = 0; i < num_rules; i++)
    {
        sprintf(rule, "%d %s %s %s %d %d %s %s %d\n", rules[i].id, rules[i].protocol, rules[i].src_ip, rules[i].dst_ip, rules[i].src_port, rules[i].dst_port, rules[i].start_time, rules[i].end_time, rules[i].action ? "true" : "false");
        strcat(data, rule);
    }

    int remaining = strlen(data) - *offset;
    if (remaining == 0)
    {
        return 0;
    }

    // 将规则复制到用户缓冲区
    if (remaining <= len)
    {
        copy_to_user(buf, data + *offset, remaining);
        *offset += remaining;
        return remaining;
    }
    else
    {
        copy_to_user(buf, data + *offset, len);
        *offset += len;
        return len;
    }
}

// 模块初始化函数
static int __init my_init(void)
{
    // 将写和读函数分配给文件操作结构
    fops.write = my_write;
    fops.read = my_read;

    // 注册字符设备
    int result = register_chrdev(DEVICE_MAJOR, DEVICE_NAME, &fops);
    if (result < 0)
    {
        printk(KERN_ALERT "Failed to register character device\n");
        return result;
    }

    printk(KERN_INFO "Initialized character device\n");
    return 0;
}

// 模块注销函数
static void __exit my_exit(void)
{
    // 注销字符设备
    unregister_chrdev(DEVICE_MAJOR, DEVICE_NAME);
    printk(KERN_INFO "Exited character device\n");
}

// 主要功能测试
int main(void)
{
    // 初始化模块
    if (my_init() != 0)
    {
        printk(KERN_ALERT "Failed to initialize module\n");
        return -1;
    }

    // 模拟向设备文件写入两条规则
    char rules_data[256] = "1 tcp 192.168.0.1 192.168.0.2 8080 80 12:00 14:00 1\n2 udp 10.0.0.1 10.0.0.2 1234 4321 09:00 11:00 0";
    my_write(NULL, rules_data, strlen(rules_data), 0);

    // 模拟从设备文件中读取规则
    char read_buffer[256];
    my_read(NULL, read_buffer, sizeof(read_buffer), 0);

    // 打印规则
    printk(KERN_INFO "Read rules from device file:\n%s\n", read_buffer);

    // 退出模块
    my_exit();

    return 0;
}
