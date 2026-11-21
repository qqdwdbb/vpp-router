# RK3588 开发板 r8169 四队列中断实测

2026-11-14 在 RK3588 开发板（Linux 6.1.57、DPDK 26.03、VPP 26.06）上部署
`patches/dpdk/0002-net-r8169-multi-queue-rx-interrupts.patch`。
从与生产 PMD SHA-256 一致的构建基线叠加该补丁，重新编译 ethdev/hw/rxtx 并链接 PMD；
保留现有 VPP dpdk 插件和其他驱动优化。

配置为 4 个 worker（CPU 1–4）、每张 RTL8125 4 个 RX 队列、2 个 TX 队列。
VPP 显示 TX 队列由多个线程共享。`buffers-per-numa` 从 8192 增至 32768，
避免两张网卡共 8 个 RX ring（各 1024 描述符）耗尽原 buffer 池。

## 验证

eth2-dpdk（0003:31:00.0，2.5 Gbps 链路）四个 RX 队列分别分配给四个 worker。
初次抓包中各队列均收到了 80 个带 RSS hash 的报文。

为排除“其他队列依靠队列 0 的 IRQ 唤醒”，将 eth1 所有队列设为 interrupt，
将 eth2 除待测队列外的队列设为 polling，仅待测队列设为 interrupt。
等待 2 秒后，在 4 秒窗口内记录 PCI legacy IRQ 和待测队列抓包：

| 唯一启用 RX 中断的 eth2 队列 | IRQ 增量 | 待测队列抓包数（上限 30） |
|---|---:|---:|
| 0 | 73 | 30 |
| 1 | 94 | 30 |
| 2 | 72 | 30 |
| 3 | 156 | 30 |

全部恢复 adaptive 后，10 秒 `/proc/<pid>/task/<tid>/stat` 增量采样：
主线程单核 CPU 约 10.0%，四个 worker 分别约 1.3%、1.1%、1.3%、1.4%。
这是现场轻载结果，不是满载吞吐或尾延迟测试。

- 上游网关 10.61.10.1：5 发 5 收。
- Linux 经 VPP/NAT 到 223.5.5.5：3 发 3 收。
- Host Stack 首页和 `/backend/empty.php`：HTTP 200。
- 服务保持 active，四队列均为 adaptive；超时恢复计时器已取消。

启动初期、DHCP/拓扑尚未完成时的一次网关探测为 5 发 0 收；
初始化完成后重测正常，不能将前一次失败计为成功测试。

## 已部署状态与限制

RK3588 开发板当前保留四队列与四 worker 配置，PMD SHA-256 为
`6285f38720d8ab84aa85cdda2a20d82403720a190c1f92bfd00ee333d156f8d0`。
构建源码、命令、逐队列抓包和 CPU 采样位于设备的
`/usr/local/src/vpp-rk3588/maintenance/multi-queue-rx-intr-20261114/`。
按用户要求没有为此次操作创建备份；超时恢复使用原已存在的单队列构建产物。

eth1 未接线，仅验证了其队列配置与模式设置，未验证实际收包。
尚未验证持续满载、长时间稳定性、其他 RTL8125 硬件版本或 RTL8126/8127。
共享 IRQ 仍会唤醒所有已等待中断的队列，可能产生额外空轮询。

后续四 A55 压测采用 main CPU4、worker CPU0–3，发现跨 worker NAT 与 adaptive
等待相关的低速异常。2026-11-15 已部署 VPP 0018 修正；本次修正未修改 PMD。
结果、仍有丢包的条件和复现数据见
[四队列性能定位与修正](r8169-multi-queue-performance.md)。
