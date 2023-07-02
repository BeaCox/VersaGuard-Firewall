#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define DEVICE_NAME "controlinfo"
#define MAX_RULES 100  //规则数量上限

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

static struct rule rules[MAX_RULES];
static int num_rules = 0;
static dev_t dev;
static struct cdev cdev;
static struct class *dev_class;

// 模块初始化函数
static int __init module_init(void)
{
    // 分配设备编号
    if (alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME) < 0)
    {
        printk(KERN_ALERT "Failed to allocate device numbers\n");
        return -1;
    }

    // 初始化字符设备结构
    cdev_init(&cdev, NULL);
    cdev.owner = THIS_MODULE;

    // 将字符设备添加到系统
    if (cdev_add(&cdev, dev, 1) < 0)
    {
        printk(KERN_ALERT "Failed to add the character device\n");
        unregister_chrdev_region(dev, 1);
        return -1;
    }

    // 为设备创建一个类
    dev_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(dev_class))
    {
        printk(KERN_ALERT "Failed to create the device class\n");
        cdev_del(&cdev);
        unregister_chrdev_region(dev, 1);
        return -1;
    }

    // 创建设备
    if (device_create(dev_class, NULL, dev, NULL, DEVICE_NAME) == NULL)
    {
        printk(KERN_ALERT "Failed to create the device\n");
        class_destroy(dev_class);
        cdev_del(&cdev);
        unregister_chrdev_region(dev, 1);
        return -1;
    }

    printk(KERN_INFO "Module initialized\n");
    return 0;
}

// 模块注销函数
static void __exit module_exit(void)
{
    device_destroy(dev_class, dev);
    class_destroy(dev_class);
    cdev_del(&cdev);
    unregister_chrdev_region(dev, 1);
    printk(KERN_INFO "Module exited\n");
}

// 读字符设备函数
static ssize_t controlinfo_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    int len, remaining;
    char *data;
    int i, j;
    struct rule *current_rule;

    if (*f_pos >= num_rules)
        return 0; // End of file

    current_rule = &rules[*f_pos];

    // 计算规则文本的长度
    len = snprintf(NULL, 0, "%d\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%d\n",
                   current_rule->id, current_rule->protocol, current_rule->src_ip,
                   current_rule->dst_ip, current_rule->src_port, current_rule->dst_port,
                   current_rule->start_time, current_rule->end_time, current_rule->action);

    data = kmalloc(len + 1, GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    snprintf(data, len + 1, "%d\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%d\n",
             current_rule->id, current_rule->protocol, current_rule->src_ip,
             current_rule->dst_ip, current_rule->src_port, current_rule->dst_port,
             current_rule->start_time, current_rule->end_time, current_rule->action);

    remaining = copy_to_user(buf, data, len);
    kfree(data);

    if (remaining == 0)
    {
        *f_pos += 1;
        return len;
    }

    if (strcmp(current_rule->protocol, "tcp") == 0)
        current_rule->protocol_type == 0;
    else if (strcmp(current_rule->protocol, "udp") == 0)
        current_rule->protocol_type == 1;
    else if (strcmp(current_rule->protocol, "ping") == 0)
        current_rule->protocol_type == 2;
    else
        current_rule->protocol_type == -1; // 类型输入错误
    return -EFAULT;
}

// 文件操作结构体
static struct file_operations mydevice_fops = {
    .owner = THIS_MODULE,
    .read = controlinfo_read,
};

// 注册模块初始化和注销函数
module_init(module_init);
module_exit(module_exit);

// 模块信息
MODULE_LICENSE("GPL");
MODULE_AUTHOR(" ");
MODULE_DESCRIPTION(" ");