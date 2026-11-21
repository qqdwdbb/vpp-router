# RK3588 开发板 worker 空闲 CPU

2026-11-14，支持 RX 中断的 r8169 PMD 部署后，worker 仍占用约一个 CPU 核。
两个条件共同阻止了空闲等待：

- Host Stack 使用共享 RX 消息队列，`session-queue` 持续 polling。
- `vlib_file_poll()` 在每次主线程同步屏障释放后的 500 ms 内不允许 worker
  阻塞等待。持续的控制面更新使这个窗口反复出现。

RK3588 开发板的 `/etc/vpp/startup.conf` 加入：

```
session { use-private-rx-mqs }
```

此选项使 session worker 启用已有的 adaptive 调度与 timerfd 唤醒。
nginx 的 VCL 配置已包含 `use-mq-eventfd`。仅把网卡设为 adaptive 不能解决
session 队列轮询；不要直接强制 session 节点状态，避免遗漏应用消息唤醒。

`patches/vpp/0017-vlib-worker-idle-after-barrier.patch` 将屏障后的轮询窗口
缩短为 1 ms。屏障同步本身通过 `vlib_thread_wakeup()` 唤醒 worker，正常的
输入事件、timerfd 和 VPP 定时器机制仍然生效；有 polling 节点或忙流量时仍轮询。

设备已部署重建的 `libvlib.so.26.06.0`。网卡启动设置仍通过
`/etc/systemd/system/rk3588-vpp.service.d/90-rx-adaptive.conf` 对两块网卡启用 adaptive。
生产 `libvlib` 与保留构建基线具有相同的 ELF build ID；构建仅替换 `file.c.o`，
并保持生产 RUNPATH。

验证：10 秒 `/proc/<pid>/task/<tid>/stat` 增量采样中 worker CPU 约 2.1%；
Host Stack HTTP 返回 200，成功传输 8 MiB；外网 ICMP、队列模式和服务状态另外核验。
这是现场轻载结果，不代表满载吞吐或时延测试。未连接的 eth1 无法验证实收流量。

设备备份分别位于：

- `/var/lib/vpp-rk3588/session-adaptive-20261114/startup.orig`
- `/var/lib/vpp-rk3588/worker-idle-20261114/libvlib.orig`

回退需要恢复上述配置、库并重启 `rk3588-vpp`；库须通过临时文件加原子 rename 替换，
不能覆盖正在映射的库文件。重启将短暂中断转发。

2026-11-15 补充：多队列跨 worker NAT 压测暴露出另一处等待问题。
主循环先从 handoff 队列取帧，调用 `vlib_file_poll()`，随后才分发待处理帧；
仅检查上一轮向量数可能在已有待处理帧时进入 epoll 等待。
`0018-vlib-do-not-sleep-with-pending-handoff-frames.patch` 对待分发帧和新发布的
frame-queue 工作增加忙状态检查，不修改 NAT worker 选择和队列容量。
已部署到 RK3588 开发板；单流 0.5 Mpps 跨 worker 的 adaptive 实收由约 0.166–0.173 Mpps
升至约 0.4992–0.4993 Mpps，但仍有约 0.14%–0.15% 的交接丢包。
空闲 worker 仍能休眠。完整条件和限制见
[四队列性能定位与修正](rk3588/r8169-multi-queue-performance.md)。

同日进一步部署 0019：入队方在发布每批帧后执行屏障并检查可合并的唤醒，消费方
宣布休眠后执行配对屏障并再次检查交接工作。原 0.5 Mpps 单流跨 worker 场景
三次复测的交接丢包增量均为零；空闲 worker 仍会休眠。
单 IP 多流容量未因此解决，详见[后续实测](rk3588/rk3588-handoff-wakeup-capacity.md)。

## 忙碌后的 1024 轮空转（0022）

2026-11-15，RK3588 开发板四个 A55 worker、两个方向都启用 return handoff，局域网主机上 8 路并发下载
mensura.cdn-apple.com（约 1.1 Gbps）时 worker 读数 60–95%，但每次调度向量数仅 13–19。
`vlib_file_poll()` 在上一轮有 ≥2 个向量时设 `file_poll_skip_loops = 1024`，之后约 1 ms
不检查 epoll，也不休眠；纯 interrupt 收包模式下读数同样高。

0022 增加 `set file-poll busy-loops <n>` / `show file-poll`，默认 1024。同一进程逐档切换，
每档 10 s 采样，同时从 198 ping 10.61.10.1（avg/max ms）：

| 收包模式 | busy-loops | Mbps | 四 worker CPU 合计 | dpdk-intr | ping avg/max |
|---|---:|---:|---:|---:|---|
| adaptive | 1024 | 1106 / 1092 | 249 / 318 | 13.8 / 15.0 | 1.28/7.4，1.60/18.7 |
| adaptive | 64 | 1102 / 1113 | 234 / 270 | 18.7 / 20.3 | 1.18/13.3，1.59/17.3 |
| adaptive | 16 | 1060 / 1106 | 216 / 235 | 25.7 / 27.6 | 1.08/8.5，1.04/7.2 |
| interrupt | 64 | 1106 | 225 | 17.8 | 0.98/11.2 |
| interrupt | 16 | 1109 | 219 | 26.4 | 1.16/13.2 |

同档两轮差异主要来自 8 条流被 RSS 分到哪些队列。busy-loops 16 时 worker 合计约降 20%，
最忙 worker 从约 94% 降到约 69%，dpdk-intr（cpu4，A76）约增 12 个百分点，速度与延迟未见变化。
剩余占用来自每次唤醒的开销：共享 INTx 每次唤醒全部队列，跨线程交接也会唤醒对方线程。
