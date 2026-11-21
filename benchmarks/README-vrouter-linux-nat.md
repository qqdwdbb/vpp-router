# Linux 双口隔离 NAT 测试

下文使用示例地址、网卡名和 PCI BDF。运行时按实验设备的 profile 渲染。

在 Linux 发包机上，将 ConnectX-4 Lx 第二个物理口放入独立 network namespace。
测试仍经过 VROUTER 的物理 WAN、NAT 和 LAN；Linux 根 namespace 的管理口保持原状。

```text
Linux/TRex enp3s0f0 (PCIe 03:00.0)
  -> VROUTER WAN VLAN 100 / 10.61.10.2:45996
  -> NAT44 EI 静态映射
  -> VROUTER LAN
  -> Linux enp3s0f1 (PCIe 03:00.1)
       namespace vrouter-nat-rx / DHCP 地址
       AF_PACKET / TPACKET_V3 / 序号位图
```

管理仍走 `eno1 / 10.61.20.134`，不得把该接口或 WAN 发包口移入 namespace。
这是对 VROUTER NAT 的隔离接收测试，不是 Linux 内核 NAT 性能测试。

## 一次性准备（Linux root）

将 `vrouter_linux_nat_namespace.py`、`vrouter_linux_sequence_capture.c`、共享头
`vrouter_sequence_tracker.h` 和
`test_vrouter_linux_sequence_capture.py` 复制到 Linux 的 `/tmp/`，然后执行：

```sh
python3 /tmp/vrouter_linux_nat_namespace.py setup
python3 /tmp/vrouter_linux_nat_namespace.py tune
cc -O3 -Wall -Wextra -Werror /tmp/vrouter_linux_sequence_capture.c -o /tmp/vrouter-linux-sequence-capture
python3 /tmp/test_vrouter_linux_sequence_capture.py
```

`setup` 验证端口型号、PCI 地址、载波、无现有地址和活动 NetworkManager 连接，
然后移入 namespace、关闭 IPv6/GRO，并通过临时 DHCP 服务取得 LAN 地址。
使用 `status` 查看地址，不能假定重建后仍为 `10.61.20.198`。

`tune` 保存并调整专用接收口 RX ring 为 8192，
将该口 completion IRQ 绑定 CPU 5；序号接收进程使用 CPU 4，TRex worker 使用 CPU 2。
这些 CPU 编号针对当前六物理核主机。设置 namespace 内的 netdev ingress
规则，在 AF_PACKET 全协议 tap 取得测试包后丢弃该 UDP 流，省去后续 IP/UDP 栈。
规则只匹配源 `203.0.113.10:50000`、DHCP 目标地址及 UDP 45996，不影响 DHCP/ARP。
该规则的 drop 计数是预期行为，不是测试链路丢包数。
Linux 接收顺序参见 [net/core/dev.c](https://github.com/torvalds/linux/blob/master/net/core/dev.c)
的 `__netif_receive_skb_core` 和 `nf_ingress`。

接收器使用 64 MiB mmap 环，BPF 只接收固定布局的 IPv4/UDP 流，位图统计唯一序号、
重复和乱序；每次 run 上限 3000 万包，单接收进程上限 32 个 run、1800 秒。
记录 PACKET_STATISTICS 的环丢弃和冻结计数。AF_PACKET 使用 ETH_P_ALL，
不能改回 ETH_P_IP，否则 ingress 丢弃会发生在该协议专用 socket 收包之前。

## 启动接收和压测

Linux root 执行（地址替换为 `status` 的实际 DHCP 地址；JSON 使用新的文件名）：

```sh
systemd-run --unit=vrouter-nat-rx-capture --property=RuntimeMaxSec=1850 \
  /usr/sbin/ip netns exec vrouter-nat-rx taskset -c 4 \
  /tmp/vrouter-linux-sequence-capture enp3s0f1 /tmp/vrouter-linux-rx.json 1800 10.61.20.198
```

本地仓库根目录执行（需要已有 SSH control sockets，远程 sudo 密码交互输入）：

```sh
python3 benchmarks/vrouter_trex_sequence_benchmark.py \
  --linux-rx-namespace vrouter-nat-rx --receiver-ip 10.61.20.198 \
  --capture-json /tmp/vrouter-linux-rx.json \
  --rates 1000,1000000,1400000,1500000 --seconds 20 --run-base 400000 \
  --output artifacts/vrouter/linux-nat-test.json --stop-capture
```

`--capture-json` 在 Linux 模式下是远端路径。每次运行必须更换 `--run-base`，
避免相同 run 被位图当成重复。1000 PPS 的功能检查固定只发 1 秒。
脚本沿用有界发包和 15 分钟清理 timer，结束后移除测试 NAT 映射、停止 TRex、
恢复发包口 pause 设置。不重启 VPP，不改 PMD、startup.conf 或恢复基线。

## 判读与恢复

对照实际 TRex 发包数、NAT 会话包数、接收唯一序号以及 Linux `ethtool -S`
的 `rx_out_of_buffer` / 接收错误与 AF_PACKET 环丢弃增量。
NAT 少包属于 NAT 会话计数前缺口；NAT 与接收器的差值不能单独证明 VROUTER TX 丢包。
只有排除接收端和发包速率限制后，才能讨论这条测试路径的无损上限。
单次 20 秒收齐不能证明长期稳定；该测试是单流、最小以太帧、入站静态 NAT，
不覆盖多会话建连、双向通信或普通出站动态 NAT。

```sh
# Linux root：保留隔离环境，仅停止抓包
systemctl stop vrouter-nat-rx-capture.service
# 查看状态 / 单独恢复接收口调优
python3 /tmp/vrouter_linux_nat_namespace.py status
python3 /tmp/vrouter_linux_nat_namespace.py untune
# 完全拆除：停止 DHCP/抓包，恢复 ring/IRQ/GRO/NetworkManager 和原接口状态
python3 /tmp/vrouter_linux_nat_namespace.py teardown
```

namespace、辅助脚本与 DHCP 状态位于 `/run` 或 `/tmp`，不作为开机配置。
在 DHCP 目标地址变化后，拆除并重建环境，使用新地址重启接收器。


## DPDK 接收模式（2026-10-30）

`vrouter_dpdk_sequence_capture.c` 与 AF_PACKET 接收器复用
`vrouter_sequence_tracker.h`，保留相同的 run/expected/unique/duplicate/reordered 语义。
接收端用 DPDK 25.11 `mlx5` PMD，namespace 中单 RX queue / 8192 descriptors，
CPU 4 busy poll，每批最多 64 包；mempool 16383 mbufs。创建一个未使用的 TX queue
以满足当前 mlx5 启动要求，接收程序不发包。

调用 `rte_flow_isolate()` 并安装精确 IPv4/UDP 五元组 RX flow，其他流量留给内核。
保留 mlx5_core 绑定；不改 VFIO、不修改巨大页池或 RDMA 的全局 namespace 模式。
EAL 使用独立 file-prefix、`--no-huge -m 128` 和 VA IOVA，能与另一 PCI function 上的
TRex 发包进程并存。CPU affinity 不保证该核无其他进程抢占。

Linux 构建依赖（root；本轮新增 26 个包，无升级/卸载）：

```sh
apt-get install -y --no-install-recommends librte-net-mlx5-26 librte-mempool-ring26 libnuma-dev libbsd-dev
mkdir -p /tmp/vrouter-dpdk-sdk
cd /tmp/vrouter-dpdk-sdk
apt-get download libdpdk-dev
# 本轮头文件和 runtime 均为 25.11-2；重建时应使用匹配版本。
dpkg-deb -x libdpdk-dev_*.deb .
```

只解包 SDK 头文件，无需安装 libdpdk-dev 的全部 PMD 依赖。
将 DPDK C 文件和共享头复制到 `/tmp` 后编译：

```sh
cc -O3 -Wall -Wextra -Werror \
  -I/tmp/vrouter-dpdk-sdk/usr/include/dpdk \
  -I/tmp/vrouter-dpdk-sdk/usr/include/x86_64-linux-gnu/dpdk \
  /tmp/vrouter_dpdk_sequence_capture.c -o /tmp/vrouter-dpdk-sequence-capture \
  -Wl,--no-as-needed -l:librte_ethdev.so.26 -l:librte_eal.so.26 \
  -l:librte_mbuf.so.26 -l:librte_mempool.so.26 -l:librte_ring.so.26 -l:librte_net.so.26
```

停止 AF_PACKET 接收，启动 DPDK（目标地址仍使用 namespace 的实际 DHCP 地址）：

```sh
systemctl stop vrouter-nat-rx-capture.service
systemd-run --unit=vrouter-nat-rx-dpdk --property=RuntimeMaxSec=1850 \
  /usr/sbin/ip netns exec vrouter-nat-rx /tmp/vrouter-dpdk-sequence-capture \
  -l 4 -a 0000:b0:00.1 --no-huge -m 128 --file-prefix=vrouter-nat-rx --no-telemetry \
  -- /tmp/vrouter-dpdk-rx.json 1800 10.61.20.198
```

在本地 harness 命令中增加 `--linux-dpdk`，其他 namespace/receiver/capture 参数不变，
`--capture-json` 对应 DPDK 输出路径；文件中 method 必须为 DPDK_MLX5。
每次接收进程生命周期依旧最多 32 个 run，重测使用新 run-base；重启用新 JSON 路径。
DPDK JSON 中 `dpdk_stats` 记录 ipackets、imissed、ierrors、rx_nombuf，不能将它们
与 AF_PACKET 的环丢弃概念混用。结束后对照这些增量、NIC 硬件计数与唯一序号。

停止 DPDK 使用 `systemctl stop vrouter-nat-rx-dpdk.service`，程序释放 flow、queue、mempool。
原有 namespace teardown 也会先停止 DPDK。停止后硬件 flow 被移除，测试五元组重新
回到内核；保留的 netdev ingress drop 只影响测试流，DHCP/ARP/ICMP 不受影响。
