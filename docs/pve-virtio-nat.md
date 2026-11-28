# PVE 虚拟网卡（virtio + vhost-net）上的 NAT 性能（2026-11-28）

结论：VPP 跑在 Proxmox VE 的虚拟机里，经 PVE 默认的虚拟网卡（Linux 网桥 + tap + vhost-net）做 NAT，64 字节小包的上限约 **0.6 Mpps**。同一台机器、同一个虚拟机把 ConnectX-3 直通进去时约 6.1 Mpps，差了 10 倍。瓶颈在宿主机内核的 vhost-net：每个 virtio 队列只有一个 vhost 内核线程，每转发一个包要花约 2.9 µs CPU，两个队列满载时合计只能转发约 0.6 Mpps。虚拟机里的 VPP 一直有余量，把收包方式从 adaptive 换成纯轮询，结果不变。

超过上限后不是平稳饱和，而是崩溃：宿主机收包的软中断把非隔离的 CPU 全占满，vhost 线程分不到 CPU，3 Mpps 时几乎一个包都转发不出去。

## 测试环境

- 硬件：i5-9300H（4 核 8 线程），8 GB 内存，ConnectX-3（mlx4），10G 接交换机。
- 宿主机：Proxmox VE 9.3，内核 7.0。`isolcpus=2,3,6,7`，虚拟机的 4 个 vCPU 固定在 6、2、3、7；宿主机自己的进程、网卡中断和 vhost 线程只能用 CPU 0、1、4、5（两个物理核的 4 个超线程）。2M 大页 2048 个。
- 宿主机网络：CX3 的一个口由宿主机 mlx4_en 驱动，加入 Linux 网桥 `vmbr1`（MTU 9000）。虚拟机网卡 `virtio,bridge=vmbr1,queues=2,mtu=9000`，vhost=on（PVE 默认）。
- 虚拟机：4 vCPU，4 GB（2M 大页），Ubuntu，内核 7.0。VPP 26.06 + 本项目补丁，主线程 vCPU0，2 个 worker 在 vCPU1、vCPU2，virtio 网卡交给 DPDK virtio PMD（vfio-pci 无 IOMMU 模式），2 个收包队列，每个 worker 一个。单臂：WAN VLAN 100，LAN VLAN 2，NAT44-EI。
- 发包：另一台机器上的 TRex，ConnectX-4 Lx 一个口，从 LAN VLAN 发 64 字节 UDP（8 个源地址，1024 个源端口随机），经 NAT 从 WAN VLAN 回到同一个口。

方法和直通测试相同（`benchmarks/vrouter_trex_stable_nat.py`）：先以目标速率预热 5 秒，让 adaptive 转入轮询，再计数 20 秒，只统计计数段的包。每档 2 轮。CPU 每秒采样一次：宿主机按 CPU 和线程（vhost、vCPU、ksoftirqd）、宿主机网卡收发包速率；虚拟机里按 vCPU 和 VPP 线程。按宿主机网卡收包速率达到目标值的区间取平均。

## 结果

### 丢包率

| 发送速率 | adaptive 丢包率 | 纯轮询丢包率 | 实际转发 |
|---:|---:|---:|---:|
| 0.2 Mpps | 0 | 0–0.0012% | 0.20 Mpps |
| 0.3 Mpps | 0 | 0–0.0008% | 0.30 Mpps |
| 0.4 Mpps | 0.014–0.016% | 0–0.004% | 0.40 Mpps |
| 0.5 Mpps | 0.015–0.024% | 0.015–0.022% | 0.50 Mpps |
| 0.6 Mpps | 0.69–0.88% | 0.55% | 0.595 Mpps |
| 0.8 Mpps | 31% | 29% | 0.55–0.57 Mpps |

超载（adaptive，每档 1 轮）：

| 发送速率 | 实际转发 | 丢包率 |
|---:|---:|---:|
| 1.0 Mpps | 0.45 Mpps | 55% |
| 1.5 Mpps | 0.21 Mpps | 86% |
| 2.0 Mpps | 0.03 Mpps | 98% |
| 3.0 Mpps | 0.0004 Mpps | 99.99% |

宿主机网卡在所有速率下都收全了（收包速率等于发送速率，`rx_dropped`、`rx_fifo_errors` 为 0）。超载时的丢包记在宿主机虚拟机 tap 口（`tap100i1`）的 TX dropped 上，也就是 vhost 线程来不及把包送进虚拟机。没到上限时的少量丢包在另一个方向，见下一节。

### 没饱和时的丢包

0.2–0.5 Mpps 时 vhost 线程平均只用了 30–75%，仍有 0.001–0.1% 的丢包，而且轮间差别大（0.4 Mpps 时测到过 0.015% 和 0.096%）。逐段读计数（0.4 Mpps 一轮，计数段 800 万包，丢 7712 个）：

| 位置 | 这轮新增 |
|---|---:|
| 宿主机网卡收包（`rx_dropped`、`rx_fifo_errors`、`rx_missed_errors`） | 0 |
| 宿主机 tap 口和它的 qdisc | 0 |
| 虚拟机里 VPP port0 的 `tx-error` | 9234（含预热和收尾） |

上一轮 0.3 Mpps 丢 246 个，`tx-error` 是 245。丢包发生在 VPP 往 virtio 网卡发包时，收包方向一个没丢：

- virtio 每个发送队列只有 256 个描述符。PVE 给 QEMU 的是 `rx_queue_size=1024,tx_queue_size=256`，而 QEMU 只允许 vhost-user 后端加大发送队列，tap + vhost-net 最多 256。每个队列每秒发 0.1–0.13 Mpps 时，256 个描述符约够 2 ms。
- 把虚拟机发出的包取走的是宿主机的 vhost 线程。同一个线程还负责把包送进虚拟机，并且和网卡中断、软中断、PVE 自己的进程挤在同样 4 个超线程上，软中断会打断它。
- vhost 线程只要一次停顿超过约 2 ms，发送队列就满，VPP 发不进去直接丢弃并计 `tx-error`。所以这类丢包取决于宿主机的调度抖动，不取决于平均负载。

这和网卡直通时约 0.03% 的残余丢包不是同一个原因，那是网卡往内存 DMA 时丢的。可能的改善（未测）：把网卡中断和软中断移出 vhost 线程所在的 CPU；用 QEMU tap 后端的 `poll-us` 让 vhost 线程忙轮询（PVE 没有这个选项，要写在 `args` 里，会多占宿主机 CPU）；或者换成 vhost-user，发送队列可以加到 1024。

### CPU 占用（adaptive，2 轮平均）

| 发送速率 | 宿主机 vhost 线程合计 | 宿主机 CPU 0、1、4、5 合计 | 虚拟机 worker（各） | 虚拟机主线程 |
|---:|---:|---:|---:|---:|
| 0.2 Mpps | 58% | 66–70% | 86–91% | 10% |
| 0.3 Mpps | 89% | 110–116% | 100% | 10% |
| 0.4 Mpps | 116% | 158–166% | 99–100% | 10% |
| 0.5 Mpps | 146% | 211–215% | 96–98% | 10% |
| 0.6 Mpps | 178% | 254% | 87–90% | 10% |
| 0.8 Mpps | 200%（两个线程都满） | 286–289% | 66–68% | 10% |

纯轮询时宿主机的数字几乎相同（0.5 Mpps 时 vhost 146–147%，CPU 0、1、4、5 合计 214–217%），虚拟机 worker 固定 100%。

超载时（2–3 Mpps）CPU 0、1、4、5 全是 100%，其中 ksoftirqd 合计 280–340%，两个 vhost 线程各只剩约 30%，虚拟机 worker 几乎没有包可收。

### 每包开销

- vhost-net：58% / 0.2 Mpps、146% / 0.5 Mpps、178% / 0.6 Mpps，都约 **2.9 µs 每个转发的包**。每个包进虚拟机、出虚拟机各经过一次 vhost（同一队列的收发由同一个线程处理）。一个线程满载约 0.3 Mpps，两个队列约 0.6 Mpps，和实测上限一致。
- 宿主机网卡收发和网桥转发（CPU 0、1、4、5 合计减去 vhost）：0.5 Mpps 以上约 1.3 µs 每包。低速率时中断合并摊薄了开销，0.2 Mpps 时只有约 0.5 µs。
- 虚拟机里的中断通知不是开销来源：adaptive 和纯轮询（VPP 关掉 virtio 的中断通知）下，vhost 的开销一样。

## 为什么是 vhost-net 限制

PVE 默认的虚拟网卡路径，每个包都要在宿主机内核里走一遍：

```
CX3 → mlx4_en（skb）→ Linux 网桥 → tap 队列 → vhost 线程拷贝进虚拟机内存 → virtio 环
                                                                          ↓
CX3 ← mlx4_en ← Linux 网桥 ← tap ← vhost 线程从虚拟机内存拷出 ← virtio 环 ← VPP
```

- 每个 virtio 队列对应一个 vhost 内核线程，按包处理：分配 skb、拷贝数据、更新 virtio 环。这部分开销和虚拟机里跑什么无关，VPP 换成任何程序都一样。
- vhost 线程、网卡中断和软中断都在宿主机的非隔离 CPU 上，彼此争抢。速率一高，网卡收包的软中断优先级更高，把 vhost 线程饿死，于是吞吐不是停在上限，而是掉到接近 0（接收活锁）。
- 增加队列只能多用几个宿主机核，每包开销不变。这台机器的宿主机只有 4 个超线程可用，量级不会改变。

## 和直通的对比

| 接入方式 | 64B NAT 上限 | 宿主机 CPU |
|---|---:|---|
| ConnectX-3 直通进虚拟机（vfio-pci，DPDK mlx4 PMD） | 约 6.1 Mpps 饱和；5.5 Mpps 丢包约 0.03% | 几乎不占 |
| virtio + vhost-net（PVE 默认） | 约 0.6 Mpps；超载后崩溃 | 0.5 Mpps 时约 2 个核 |
| 物理机（同一硬件，不经虚拟化） | 7.4–7.9 Mpps | — |

要在虚拟机里跑高包速率的 VPP，网卡应当直通（整卡或 SR-IOV VF）。vhost-user 可以绕开内核，但宿主机要另跑一个 DPDK 程序（OVS-DPDK、VPP 等）驱动物理网卡，并占用宿主机的 CPU 核做轮询。

0.6 Mpps 是 64 字节小包的数字。按平均包长约 1000 字节算约 4–5 Gbps，千兆、2.5G 宽带的家用 NAT 一般够用。不推荐的是把这类网卡用在高包速率的转发入口上（小包多、攻击流量、多台设备压满），因为超载后不是停在上限，而是转发跌到接近 0。

## 其他虚拟化平台

下面几种没有实测，按数据路径推断和 vhost-net 属于同一类：每个包都经宿主机（或根分区）里的软件交换转发、拷贝，包速率上限低，超载时宿主机 CPU 会先被占满。

- **Hyper-V 的合成网卡（NetVSC）**：包经根分区里的 Hyper-V 虚拟交换机和 VMBus 送进虚拟机。DPDK 的 netvsc PMD 只是换掉了虚拟机里的驱动，没开加速网络时宿主机这一段不变。开了加速网络（SR-IOV VF，Azure 和 Windows Server 都支持）时，数据走 VF，性能接近直通，这是 Hyper-V 上应当使用的方式。本项目的安装器目前不认 NetVSC 设备，只能以 AF_PACKET 接入，性能还会更低。
- **VMware ESXi 的 vmxnet3**：经 ESXi 的虚拟交换机转发，同样是宿主机软件交换。要高包速率应使用 SR-IOV 或 PCI 直通（DirectPath I/O）。
- **其他 KVM 平台**（libvirt、OpenStack 未用 OVS-DPDK 时等）：默认也是 virtio + vhost-net，和本文测的相同。

在这些平台上部署时：转发网卡用直通或 SR-IOV VF；软件虚拟网卡只用来做管理口，或者只用在低速、测试环境。

## 配置中遇到的问题

- **IOMMU 组**：这台机器上 ConnectX-3 和 SATA 控制器挂在 CPU 的两个 PCIe 根端口下，根端口没有 ACS，二者在同一个 IOMMU 组。直通 SATA 控制器（虚拟机系统盘所在）时 PVE 会把整组设备交给 vfio-pci，宿主机就用不了 ConnectX-3。测试 vhost-net 时把系统盘改成整盘 virtio-scsi 透传（`scsi0: /dev/disk/by-id/...`），SATA 控制器留给宿主机。
- **virtio 网卡的 MTU**：PVE 给 virtio 网卡设 `host_mtu` 为网桥的 MTU（默认 1500）。virtio PMD 报告的 `max_rx_pktlen` 固定是 9728，真正的上限在 `max_mtu`；VPP 原来只按前者配置 MTU（8996），`rte_eth_dev_configure` 拒绝，网卡初始化失败（`pmd-init-fail`）。本文的测试是把网桥和网卡的 MTU 都设成 9000 绕过的。VPP 补丁 0050 已修复：最大帧长不超过 PMD 报告的 `max_mtu` 加帧开销，PVE 默认的 `host_mtu=1500` 下网卡直接可用（最大帧长 1526）。
- **`no-multi-seg`**：DPDK 段里的 `no-multi-seg` 对所有 DPDK 网卡生效，安装器和面板在有 mlx4 网卡时会自动加这一行。修补前它和上一条叠加，virtio PMD 拒绝建立收包队列（`rte_eth_rx_queue_setup` 返回 -22）。0050 之后，`host_mtu=1500` 时加着 `no-multi-seg` 也能启动和转发（实测 0.3 Mpps 丢包 0.004%）。`host_mtu` 设成 9000 这类大值时仍会失败：VPP 按 26 字节算帧开销，virtio 按 30 字节，MTU 2022 的帧比 2 KB 的 buffer 多 4 字节。
- **固定 MAC**：直通时 `router.vpp` 把 port0 的 MAC 设成 ConnectX-3 的 MAC。改用网桥后宿主机的 `vmbr1` 自己就用这个 MAC，虚拟机再用它，发给它的包会被宿主机截下。虚拟机网卡要用 PVE 分配的 MAC。
