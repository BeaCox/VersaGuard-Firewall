# VersaGuard-Firewall
NIS3302信息安全科技创新课程大作业——基于内核模块的包过滤防火墙

## TODO

- [x] 暗黑模式
- [x] 关于界面 
- [x] 应用数据路径按钮
- [x] 导入规则
- [x] 导出规则
- [x] 添加规则
- [x] 双击编辑规则
- [x] 删除规则
- [x] 搜索规则
- [x] 规则按字段排序（GTK原生支持）
- [x] 写入设备文件
- [ ] 日志输出框

## Compile

在主目录执行：

```bash
make clean
make
```

## Usage

可执行程序在`bin`目录下，需要root权限运行

```bash
sudo ./VersaGuard
```

数据库文件位于`~/.config/VersaGuard/`目录下，名为`rules.db`

可以导入`test`目录下的`rules.db`进行测试
