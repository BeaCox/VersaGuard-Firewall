# VersaGuard-Firewall
NIS3302信息安全科技创新课程大作业——基于内核模块的包过滤防火墙

[![made-with-C](https://img.shields.io/badge/Made%20with-C-blue?logo=C)](https://www.cprogramming.com/) [![linux](https://img.shields.io/badge/Platform-linux-blue?logo=linux)](https://www.linux.org/) [![Built with GTK](https://img.shields.io/badge/Built%20with-GTK-blue?logo=gtk)](https://www.gtk.org/)

[![](https://custom-icon-badges.demolab.com/github/languages/code-size/BeaCox/VersaGuard-Firewall?logo=file-code&logoColor=white)](https://github.com/BeaCox/VersaGuard-Firewall) [![GitHub release](https://img.shields.io/github/release/BeaCox/VersaGuard-Firewall.svg)](https://GitHub.com/BeaCox/VersaGuard-Firewall/releases/)

## Usage

内核模块、CLI、GUI都在`bin`目录下，下载该目录即可使用

### 内核模块使用

安装：

```bash
sudo insmod VersaGuard_core.ko
```

查看：

```bash
sudo lsmod |grep VersaGuard_core
```

卸载：

```bash
sudo rmmod VersaGuard_core
```

### CLI使用

- **命令行参数模式**

  ```shell
  ./VersaGuard-cli -o [option] <parameters>
  ```

  - `add`：添加规则，后接**十**个参数（默认则输入""），分别表示协议类型(tcp/udp/icmp/all)，网络接口，源IP，目标IP，源端口，目标端口，开始时间，结束时间(格式为**带引号的**"YYYY-MM-DD HH:MM:SS")，执行动作(0拦截/1通过)，备注

  - `del`：删除规则，后接**一**个参数表示要删除的规则的序号

  - `upd`：修改规则，后接**三**个参数，分别表示要修改的规则的序号，要修改哪一项参数(ptc/sip/dip/spt/dpt/stm/etm/act/rmk)，修改后的结果

  - `imp`：导入规则，后接**一**个参数表示要导入的规则文件路径

  - `exp`：导出规则，后接**一**个参数表示要导出的规则文件名

  - `rule`：打印规则

  - `write`：写规则到设备文件（需提权）

  - `help`：打印使用说明

- **交互模式**

  ```shell
  ./VersaGuard-cli
  ```
### GUI使用

Features:

+ 启动应用自动检查内核模块并安装
+ 暗黑模式切换
+ 应用数据路径直达按钮
+ 添加、删除、导入、导出规则
+ 双击或选择后点击`Enter`编辑规则
+ 搜索规则（匹配项高亮并选择）
+ 规则按字段排序（GTK原生功能）
+ 日志输出框
+ 搜索日志（上下键切换搜索结果）

```bash
sudo ./VersaGuard-gui
```

## Compile

+ 全部编译

  主目录执行：

  ```bash
  make clean
  make
  ```

+ 分别编译

  切换到对应的目录下执行：

  ```bash
  make clean
  make
  ```

## Authors

[@BeaCox](https://github.com/BeaCox)

[@Luke](https://github.com/YiboChen03)

[@G-AOi](https://github.com/G-AOi)

[@Wang Yiting](https://github.com/wytili)

[@ZYXDDDDDSG](https://github.com/ZYXDDDDDSG)

（按照名称首字母排序）
