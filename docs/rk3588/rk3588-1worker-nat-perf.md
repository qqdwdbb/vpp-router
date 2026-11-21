# RK3588 开发板：单 A76 worker 的 NAT 性能

2026-11-15，配置改为 `cpu { main-core 0 corelist-workers 4 }`（main 与 dpdk-intr 在 A55 cpu0，
唯一 worker 在 A76 cpu4），eth1/eth2 各 1 个 RX 队列；其余（PMD、0017–0022、return handoff 插件）不变。

方法同前：发包机上 TRex 单发包线程经 f1 发 LAN→动态 SNAT→WAN VLAN100，mlx5 DPDK 接收端
按唯一序号计数，每档 PPS×10 包、20 s 一档，同一 VPP 进程。包长含 FCS。
接收端 imissed/ierrors/rx_nombuf 为零。网卡 `rx missed` 计数会回绕，不作丢包依据。

| 模式 | 包长 | 源 IP | 流 | 输入 Mpps | 实收 Mpps | 丢失 |
|---|---:|---:|---:|---:|---:|---:|
| adaptive | 64 | 16 | 1 万 | 0.5 | 0.499 | 0.13% |
| adaptive | 64 | 16 | 1 万 | 1.0 | 0.999 | 0.11% |
| adaptive | 64 | 16 | 1 万 | 1.5 | 1.497 | 0.19% |
| adaptive | 64 | 16 | 1 万 | 2.0 | 1.635 | 18.3% |
| polling | 64 | 16 | 1 万 | 1.5 | 1.500 | 0 |
| polling | 64 | 16 | 1 万 | 2.0 | 1.655 | 17.3% |
| polling | 64 | 16 | 1 万 | 2.5 | 1.654 | 33.9% |
| adaptive | 64 | 1 | 1 万 | 1.0 | 0.998 | 0.24% |
| adaptive | 64 | 1 | 1 万 | 1.5 | 1.490 | 0.69% |
| adaptive | 64 | 1 | 1 | 1.0 | 0.999 | 0.12% |
| adaptive | 64 | 1 | 1 | 2.0 | 1.996 | 0.21% |
| adaptive | 1518 | 16 | 1 万 | 0.19（约 2.3 Gbps） | 0.189 | 0.56% |

- 多流饱和约 1.64–1.66 Mpps，与源 IP 数无关；单流约 2.0 Mpps 仍未饱和。
- 对比四个 A55 worker：16 IP polling 约 1.48 Mpps，单 IP 1 万流 0.63（交回后约 0.95–0.99）Mpps。
  单 A76 worker 各项都更高，且无线程间交接。
- adaptive 在未饱和时仍有 0.1%–0.7% 缺包，polling 1.5 Mpps 无丢失；1518B 接近 2.5G 线速时 0.56%。
  这部分与 adaptive 的中断/轮询切换有关，未逐包归因。
- 数据：`artifacts/rk3588-natperf-1worker-20261115/`。

## 未饱和时的少量丢包：CPU 升频延迟

adaptive 下 0.5–1.0 Mpps 每档缺约 0.1%，几乎全部对应网卡 `rx missed`（收包环溢出）；
1.0 Mpps 档每轮稳定缺约 1 万包，相当于每档开头约 10 ms 的流量。逐项排除（均为同一进程内对比）：

| 尝试 | 结果 |
|---|---|
| dpdk-intr 挪到 cpu1 / SCHED_FIFO 50 | 0.5 Mpps 有时变 0，1.0 Mpps 仍约 0.1% |
| `set file-poll busy-loops 16` | 1.0 Mpps 仍约 0.1% |
| RX 描述符 1024 → 4096 | 1.0 Mpps 仍约 0.1%；1.5 Mpps 丢包升到 8.8%–13.1%，已撤回 |
| `set file-poll max-sleep-ms 1`（0022 新增） | 1.0 Mpps 仍约 0.1% |
| cpu4（policy4，cpu4–5）调频 | ondemand 0.03%–0.12%，schedutil 0.16%–0.46%，**performance 0**（0.5/1.0 Mpps 各两轮） |

原因是 worker 所在 A76 的 `ondemand` 调频：空闲时降到 408 MHz–1.2 GHz，流量突然到来时
升频需要约一个采样周期，这段时间来不及收包。polling 下核心持续满载、始终最高频，所以不丢。

处理：`/etc/rc.local` 在原有 `cpufreq-set -c 0-3 -g performance` 后增加
`cpufreq-set -c 4 -g performance`，并已在运行中生效（cpu4–5 固定 2.256 GHz）。
代价是 A76 空闲时也处于最高频，功耗与发热略增；备份在
`/var/lib/vpp-rk3588/backups/pre-cpu4-performance-20261115/`。
1.5 Mpps 档已接近单核上限（约 1.65 Mpps），那里的丢包属于容量问题。
数据：`artifacts/rk3588-lossfind*-20261115/`。

## 对照：worker 放在 A55（main cpu0、worker cpu1）

同方法，同 PMD/插件/libvlib，cpu0–3 调频为 performance（1.8 GHz）。

| 模式 | 包长 | 源 IP | 流 | 输入 Mpps | 实收 Mpps | 丢失 |
|---|---:|---:|---:|---:|---:|---:|
| adaptive | 64 | 16 | 1 万 | 0.3 | 0.299 | 0.24% |
| adaptive | 64 | 16 | 1 万 | 0.5 | 0.493 / 0.497 | 1.39% / 0.69% |
| adaptive | 64 | 16 | 1 万 | 0.6 / 0.7 / 0.8 | 0.513 / 0.514 / 0.484 | 饱和 |
| polling | 64 | 16 | 1 万 | 0.5 | 0.500 | 0 |
| polling | 64 | 16 | 1 万 | 0.6 / 0.8 | 0.514 / 0.513 | 饱和 |
| adaptive | 64 | 1 | 1 万 | 0.5 / 0.6 | 0.489 / 0.494 | 2.23% / 饱和 |
| adaptive | 64 | 1 | 1 | 0.5 / 0.8 | 0.499 / 0.571 | 0.17% / 饱和 |
| adaptive | 1518 | 16 | 1 万 | 0.19（约 2.3 Gbps） | 0.190 | 0 |

- A55 单 worker 多流饱和约 0.51 Mpps，单流约 0.57 Mpps；A76 分别约 1.65 和 ≥2.0 Mpps（约 3.2 倍）。
- 1518B 接近 2.5G 线速时两者都不丢包。
- A55 在 adaptive 下 0.3 Mpps（约六成负载）仍有 0.24% 缺包，polling 0.5 Mpps 无丢失；
  调频已固定，这部分与 A76 上的升频原因不同，未进一步归因。
- 数据：`artifacts/rk3588-natperf-a55-1worker-20261115/`。

## 根本原因：中断状态下 1024 轮不读 eventfd（更正）

前一节的升频延迟只解释了 A76 上的丢包。worker 放到 A55（调频已固定）后，adaptive 下
0.3–0.5 Mpps 仍丢 0.1%–2.7%。

- 对照：同一单 worker 配置下换回本次会话开始时的 `nat44_ei_plugin.so`、`nat_ei_context_plugin.so`、
  libvlib 与 `topology.vpp`，同样丢包（0.5 Mpps 2.7%/0.11%，单流 2.8%/1.4%），丢包不是本次插件改动引入的。
- 丢失全在进入 VPP 之前：`l2-input` 收到多少就转发多少；网卡 `rx missed` 会回绕，不能与缺包数对应。
- 机制：adaptive 在每次调用向量数 ≤5 时把 dpdk-input 切回中断状态，此时只在读到 RX eventfd 后才收包；
  而 `vlib_file_poll()` 在上一轮 ≥2 个向量后 1024 轮内不检查 epoll（A55 上约 0.5–1 ms），收包环（1024）溢出。
  dpdk-input 也没有实现 vlib 在切换前留给驱动的那次处理（`VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE`）。
- 会话之前的配置：11-14 前为 polling；之后为四 RX 队列四 worker，每队列负载约四分之一，同样的空档影响小。

同一进程逐档交替（A55 worker，64B，16 IP 1 万流除非注明）：

| busy-loops | 0.3 Mpps | 0.4 Mpps | 0.5 Mpps | 单流 0.4 Mpps |
|---|---|---|---|---|
| 1024 | 0.25% / 0 | 0 / 0.08% | 1.9% / 0.18% | 0.73% / 0.17% |
| 16 | 0 / 0 | 0 / 0 | 0 / 0.11% | 0 / 0 |

处理：`/etc/vpp/topology.vpp` 在 `nat44 ei return-handoff enable` 后加 `set file-poll busy-loops 16`，
已在运行中生效（备份 `/var/lib/vpp-rk3588/backups/pre-busy-loops-16-20261115/`）。此行依赖带 0022 的 libvlib，
回退 libvlib 时必须同时删除。数据：`artifacts/rk3588-session-ab-20261115/`、`artifacts/rk3588-lossfind6-a55-busyloops-20261115/`。

## 修正 adaptive 的中断武装（0023/0024）

进一步排查发现，adaptive 下即使节点处于轮询状态，dpdk-intr 仍占 12%–38% CPU：
`dpdk_rx_read_ready()` 每次读 eventfd 都重新武装一次性中断，轮询期间网卡持续中断；
而 vlib 切回中断状态前留给驱动的那次调度（`SWITCH_FROM_POLLING_TO_INTERRUPT_MODE`）
dpdk-input 并不处理。"空闲 2 ms 再切换"（0023 的 `set adaptive idle-us`）未改善丢包。

- 0023 另外：轮询窗口变忙时清除待切换标记，切换需要连续两个空闲窗口。
- 0024（dpdk 插件 common.c/node.c）：eventfd 处理只在节点为中断状态时重新武装；
  在标记切换的那次调度里先武装、再收包。武装状态按 vnet RX 队列号另存，不改 `dpdk_rx_queue_t`。
- RK3588 开发板：libvlib `9fbcc20f…`，dpdk_plugin.so `3e104388…`（基线代码段与生产一致后构建），
  备份 `/var/lib/vpp-rk3588/backups/pre-adaptive-arm-20261115/`。

效果（A76 worker，同进程交替，64B）：dpdk-intr 降到约 0%。

| cpu4 调频 | 0.5 Mpps | 1.0 Mpps | 单流 1.0 Mpps | 其他 |
|---|---|---|---|---|
| performance | 0 / 0 | 0.25% / 0 | 0.13% / 0 | 1.5 Mpps 0；1518B 0；0.3 Mpps 0；单 IP 1 万流 0.06% |
| ondemand | 0 / 0.03% | 0.27% / 0.15% | 0.11% / 0.21% | — |

ondemand 下每档开头仍有约 10 ms 升频（最短采样 10 ms，不可调小），阶跃到 1 Mpps 时丢包；
performance 下 11 档中 9 档为 0，余下 2 档原因未定。数据：`artifacts/rk3588-lossfind11-arm-20261115/`、
`artifacts/rk3588-lossfind12-arm-governor-20261115/`。

## 精简后的状态（2026-11-15）

按实测结果去掉了无效部分并重测：

- 0022 去掉 `max-sleep-ms`（测 1 ms 无效），只保留 `busy-loops`。
- 0023 去掉 `set adaptive idle-us`（测 1/2 ms 无效），只保留"忙窗口取消待切换"，它是 0024 的前提。
  上文提到的 `max-sleep-ms`、`idle-us` 实验所用的 libvlib 已不再部署。
- RK3588 开发板 `topology.vpp` 去掉 `nat44 ei return-handoff enable`：单 worker 下交回没有意义，
  下载方向还多走一个节点；插件功能保留、默认关闭，供多 worker 部署使用。`set file-poll busy-loops 16` 保留。
- RK3588 开发板 libvlib `f2b5b4f0…`（构建前复现了 `9fbcc20f…`），备份 `/var/lib/vpp-rk3588/backups/pre-trim-20261115/`。

回归（A76 worker，cpu4 ondemand，adaptive）：

| 条件 | 结果 |
|---|---|
| 64B 16 IP 0.5 / 1.0 Mpps（两轮） | 0.088%、0 / 0.080%、0.157% |
| 64B 单流 1.0 Mpps（两轮） | 0.111% / 0.088% |
| 64B 单 IP 1 万流 1.0 Mpps | 0.177% |
| 64B 16 IP 1.5 Mpps；1518B 0.19 Mpps | 0；0 |
| 饱和：adaptive / polling 2.0 Mpps 输入 | 1.638 / 1.648 Mpps |
| Apple 8 路下载 | 1114 / 1119 Mbps，worker 读数 71–73%，ping 10.61.10.1 平均约 1 ms |

与精简前同条件（`artifacts/rk3588-lossfind11-arm-20261115/`）一致。ondemand 下阶跃到 1 Mpps 的约 0.1% 丢包来自升频，
见上文。数据：`artifacts/rk3588-lossfind13-trimmed-20261115/`。
