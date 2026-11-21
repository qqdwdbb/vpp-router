# RK3588 开发板的 RTL8125 热重启验证

2026-11-20，在 10.61.20.1 的 `vpp-router.service` 上排查重启耗时。
当前服务使用 `/etc/vpp/router.conf`，DPDK 26.03 的 r8169 PMD 静态链接在
`/usr/local/lib/vpp-router/vpp_plugins/dpdk_plugin.so` 内。

## 结果与现场变更

当前版本没有复现旧初始化脚本注释所描述的“热重启后持续无法收包”。
保持 PMD 二进制不变，跳过内核驱动接管后，首次探测及随后连续五次热重启
都能恢复 WAN 收发，恢复后网关探测无丢包，两个物理接口保持 adaptive。
因此没有基于旧注释修改 PMD 复位顺序，而是在这台设备的服务文件中删除了
两个调用 `rtl8125-init.py` 的 `ExecStartPre`，保留 `vpp-router-ctl prep`。

旧脚本逐块将网卡从 UIO 交给 r8125，设置 link up，固定等待 3 秒，再交回
UIO。两块网卡串行执行，固定等待合计 6 秒，另有驱动绑定开销。

| 条件 | `systemctl restart` 耗时（秒） |
|---|---|
| 跳过接管，首次探测 | 4.262 |
| 跳过接管，连续五轮 | 5.062 / 3.517 / 3.601 / 5.596 / 5.508 |
| 恢复旧接管流程，两轮对照 | 11.498 / 11.547 |
| 删除两条冷初始化命令后的最终验收 | 5.107 |

最终验收中，VPP 到上游网关的 10 包探测及 Linux 经 VPP 转发的 5 包探测
均无丢包，WAN 恢复为 2.5 Gbps，`dpdk-input` 和 `session-queue` 均进入
中断等待。独立的自动回退定时器在 `FINAL_PASS` 后已取消。
PMD 所在 `dpdk_plugin.so` 修改前后 SHA-256 相同：
`c13ef30f90d75cfbb6c7c6131e5ced1a04d90f1499d78bfc13dc8a1efade650f`。

以上时间为整条 restart 命令耗时，不等于网络业务恢复时间。两种流程下，
服务变为 active 后的前几次网关探测仍有丢包；本次每批两包、批间等待一秒的
探测在约 8 秒后才得到完整响应。PMD 的 PHY 初始化会复位 PHY 并重启
自协商，这与暂时的链路恢复等待相符，但没有单独测量每个硬件阶段。
不能把服务提前 active 宣称为链路立即恢复。

## 备份与回退

设备记录、原服务文件、原 PMD 插件和回退脚本保存于：

```
/var/lib/vpp-router/maintenance/pmd-warm-20261120/
```

`baseline.log` 保存首次热重启结果；`repeat.log` 保存五轮热重启；
`cold.log` 保存旧流程对照；`final.log` 保存最终配置验收。
试验通过独立的 systemd 定时器保护，连接中断时也可以恢复旧服务。
手动恢复旧流程会再次短暂中断转发：

```sh
sudo /var/lib/vpp-router/maintenance/pmd-warm-20261120/rollback.sh
```

## 验证边界

- 现场只验证了已连接的 WAN RTL8125，LAN 无载波，不能声称其收发已验收。
- 没有验证整机冷启动、强杀后恢复、长期稳定性或其他 RTL8125 平台。
- 本次仅修改该设备的服务文件；通用安装器仍保留冷初始化流程，重新安装或
  重新生成服务文件可能恢复它。没有据单台设备的热重启结果改变其他平台默认行为。
- 进一步减少链路协商时间需要单独验证 PMD 的 PHY 状态保留，不能简单跳过
  PHY 初始化或删除硬件复位。

## PD 同步服务的退出等待

进一步按 systemd 日志拆分最终 5.107 秒的重启：依赖服务停止约 1.66 秒，
VPP 自身停止约 0.66 秒，重新启动到 active 约 2.76 秒。依赖停止的主要
等待来自 `vpp-router-pd-sync.service`，其 SIGTERM 处理函数只设置标志，
Python 的 `time.sleep()` 仍会继续等到当前两秒周期结束。

`deploy/ipv6/pd-sync.py` 改为使用 `threading.Event` 等待相同的同步周期，
收到 SIGTERM/SIGINT 时唤醒等待；正在进行的同步仍会完成。没有改变正常
同步间隔、前缀发布或 IPsec 地址配置。增加真实子进程信号测试，在 30 秒
周期中验证两个退出信号都能使程序及时正常退出；相关五项单元测试通过。

现场脚本与仓库修改前版本的 SHA-256 一致，备份后部署相同修改。
加载新版本后，单独停止 PD 同步服务耗时 0.067 秒；随后整次 VPP 重启
实测 3.500 秒。该耗时是一次现场采样，不代表所有负载下的上限。
验收中 VPP 的五包探测及 Linux 经 VPP 的三包探测均无丢包。
备份为同一维护目录中的 `pd-sync.before.py`，日志为 `pd-fast.log`，
`pd-rollback.sh` 可恢复原脚本并重启 PD 同步服务。

## 启动阶段的 2.769 秒

使用临时控制脚本的 Bash 时间戳和 VPP 自带的 CLI event logger 采样，
服务开始启动到 active 的单调时钟差为 2.768649 秒，整次 restart 为
3.495510 秒。记录保存在设备
`/var/lib/vpp-router/maintenance/startup-timing-20261120/`。

| 阶段 | 本次耗时 |
|---|---|
| 服务开始到 VPP 主进程启动，含网卡 prep | 84 毫秒 |
| `startup-config-process` 固定挂起 | 2000 毫秒（源码规定） |
| 执行主配置及两份 exec 文件 | 176 毫秒 |
| IPsec/Linux 地址、路由等收尾 | 46 毫秒 |
| 其余初始化、调度及就绪轮询间隙，按总量扣除上述阶段 | 约 463 毫秒 |

其中 2 秒来自设备源码
`/usr/local/src/vpp-router/vpp/src/vlib/unix/main.c` 的
`startup_config_process()`：先 `vlib_process_suspend(vm, 2.0)`，然后以
100 毫秒间隔检查 `unix_config_complete`，最后执行配置。
该固定挂起占本次启动阶段约 72%，不能归因于网卡固件或 PHY 等待。

CLI event logger 记录从 2.426793 到 2.602528 秒的配置执行窗口。
按嵌套命令排除重复计算后，主要命令耗时如下：

| 命令类别 | 次数 | 合计耗时 |
|---|---:|---:|
| create tap | 6 | 58.5 毫秒 |
| set interface state | 15 | 57.5 毫秒 |
| nat44 ei plugin | 1 | 14.7 毫秒 |
| create bridge-domain | 2 | 11.6 毫秒 |
| ip table | 2 | 6.9 毫秒 |
| set interface ip address | 11 | 6.6 毫秒 |

`show version` 在 post 脚本的第二次探测已成功，此时启动配置尚未执行。
因此 CLI socket 可用不能作为配置完成的标志。post 的多次 500 毫秒轮询
与 VPP 的 2 秒挂起并行发生，不能将这些等待再次相加。
本次没有分别测量 ELF/插件加载、EAL 和 PMD 内部初始化；它们只包含在
上述剩余开销中。

没有修改固定挂起或 PMD；采样结束已移除临时服务覆盖，恢复原启动入口。
下一步若优化固定挂起，应确认实际初始化依赖和进程调度顺序，使用明确
就绪条件替代，不能仅凭 CLI socket 已出现就执行全部配置。

## 用初始化顺序替代固定挂起（0029，已部署）

检查 `vlib_main_or_worker_loop()` 后确认：所有 init/config 函数和
main-loop-enter 函数（含 worker 启动）先完成，随后主线程对所有 process
逐一执行首次调度，之后才进入主循环并递增 `main_loop_count`。
`dpdk_process()` 在首次调度中同步完成 `dpdk_lib_init()` 和 worker 释放，
然后才等待事件。因此配置进程现在等待两个已有条件：

```c
while (um->unix_config_complete == 0 || vm->main_loop_count == 0)
  vlib_process_suspend (vm, 0.001);
```

1 毫秒只是条件尚未满足时的让出调度间隔，不是启动必须等待的时长。
这保证所有 process 首次调度都已返回或挂起，不依赖节点排列顺序。
此条件不承诺任意插件在首次挂起之后的异步任务均已完成；当前 DPDK 的
接口创建在首次挂起前完成。没有以 CLI socket 可用或链路 up 作为门槛。

补丁为 `patches/vpp/0029-unix-startup-config-wait-for-process-init.patch`，
已加入 `series`。只修改 `src/vlib/unix/main.c`，没有新增状态字段或改变
ABI 布局。重建前比较构建基线与现网库，`.text`、`.rodata` 和 `.data`
均逐字节相同。候选 libvlib 编译成功，保留生产 RUNPATH 后原子替换。

验证：

- 隔离 VPP、不接物理网卡：无 worker 和单 worker 的 startup-config
  分别在 0.146 秒、0.549 秒内创建接口。测试脚本为
  `tests/integration/integration_startup_config_ready.py`。
- 真实双 RTL8125 配置，连续三次重启：

| 轮次 | 整次 restart | 启动到 active |
|---|---:|---:|
| 1 | 1.626 秒 | 0.746 秒 |
| 2 | 1.654 秒 | 0.750 秒 |
| 3 | 1.515 秒 | 0.730 秒 |

每轮 VPP 到上游网关的三包探测均无丢包；最终 Linux 经 VPP 的五包探测也
无丢包。wan0/lan0 均为 adaptive，dpdk-input 与 session-queue 为中断等待，
VPP、PD 同步、nginx-hoststack 均 active，IPv6 地址和委派前缀随后恢复。
仍未验证 LAN 实际收包、整机冷启动或长期稳定性；restart 时间依旧不等于
物理链路及所有外部协议完成恢复的时间。

设备备份、构建日志、隔离测试结果、三轮验收和补丁保存在：

```
/var/lib/vpp-router/maintenance/startup-ready-20261120/
```

`libvlib.before.so` 为原库，`rollback.sh` 原子恢复原库后重启 VPP。
`verify.log` 最终为 `VERIFY_PASS`，独立自动回退计时器已取消。
部署库 SHA-256：
`9e761dcf58c52f35446669f7a43b7ce78050dc069a5190ec19f8f84b224cc3bd`。
