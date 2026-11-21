# RK3588 开发板：NAT 后交回收包 worker（return handoff）

2026-11-15，针对[单 IP、1 万流的四 A55 容量](rk3588-handoff-wakeup-capacity.md)。
约束不变：main CPU4、worker CPU0–3（A55），NAT44-EI 归属规则、端口分配、用户限额、
会话语义和防火墙规则不变。

## 定位

1 Mpps、单 IP、1 万流时 RSS 均匀（四队列各约 2.2M 包/10 s），三个收包 worker 约 81%，
NAT worker 满核，只发出约 0.63 Mpps。交接点在 ip4-output 的
`nat44-ei-in2out-output-worker-handoff`，其后的 NAT、`nat-ei-context-exit`、
`acl-plugin-out-ip4-fa`、interface-output 和 TX 全在 NAT worker 上：
每个交接包约 23 ticks（24 MHz），其中必须在归属 worker 上做的 NAT 只有约 7。

## 改动

- `patches/vpp/0020`：EI 输出 handoff 在 `vnet_buffer2 (b)->unused[4]` 记录收包线程 +1。
- `plugins/nat-ei-context`：`nat44 ei return-handoff enable|disable`（默认关）。
  context-exit 在归属 worker 上把已转换的包交回收包线程，由它执行输出 arc 余下部分
  （ACL、MSS、WireGuard）和 TX。同一条流固定走 RX→归属→RX，保持顺序；
  收包线程队列将满时在归属 worker 上完成（不丢包，过载时该流可能乱序）。
  计数 `returned-to-rx-thread`、`return-congestion-drop`。只覆盖 in2out 方向。
- 回归：`tests/unit/test_nat_ei_context_next.py` 新增 `return-to-rx`、`return-full-or-off`。

## 实测

同一 VPP 进程内逐档开关，64B 含 FCS，物理 LAN→动态 SNAT→WAN VLAN100，每档 PPS×10 包，
mlx5 接收端按唯一序号计数；接收端 imissed/ierrors/rx_nombuf 为零。

| 条件 | 输入 Mpps | 关 | 开 |
|---|---:|---:|---:|
| 单 IP 1 万流，adaptive | 1.0 | 0.629 / 0.629 | 0.944 / 0.981 |
| 单 IP 1 万流，polling | 1.0 | 0.654 | 0.992 |
| 单 IP 1 万流，adaptive / polling | 1.5 | — | 0.846 / 0.905 |
| 16 IP 1 万流，adaptive | 1.5 | 1.104 | 1.070 |
| 16 IP 1 万流，adaptive | 2.1 | 1.110 | 1.078 |
| 16 IP 1 万流，polling | 1.5 | 1.486 | 1.482 |
| 单流，adaptive | 0.5 | 0.500 | 0.499 |

- 单 IP 1 Mpps：+50%–56%，NAT 交接拥塞丢包从约 3.2–3.4M/档降到 7–55k，交回零丢弃。
- 1.5 Mpps 单 IP 已过载，实收低于 1 Mpps 档，NAT 交接仍有大量拥塞丢弃。
- 多客户端：adaptive 两档约 −3%，polling 持平。每个 worker 都是若干用户的归属时，
  交回只增加一次线程间传递。
- 16 IP adaptive 本身（约 1.1）远低于 polling（约 1.48），与此改动无关，是另一问题。

## 部署状态

- RK3588 开发板已换上候选插件；2026-11-15 按用户决定长期启用：`/etc/vpp/topology.vpp` 在
  `nat44 ei output-chain eth2-dpdk.100` 后加 `nat44 ei return-handoff enable`，并已在运行中启用。
  多客户端 adaptive 约 3% 的代价接受，不做按积压切换。插件：
  `nat44_ei_plugin.so` `de145791…`，`nat_ei_context_plugin.so` `2f2f9d8c…`。
  构建前证明：同法链接原对象与生产 `nat44_ei_plugin.so` 逐字节一致；仓库 HEAD 的
  `nat_ei_context.c` 与生产插件代码/数据段一致，差异仅为本改动。
- 原插件和原 `topology.vpp` 在 `/var/lib/vpp-rk3588/backups/pre-return-handoff-20261115/`；构建、部署脚本在
  `/usr/local/src/vpp-rk3588/maintenance/return-handoff-20261115/`（`deploy.sh real backup rollback` 回退）。
- 数据与脚本：`artifacts/rk3588-return-handoff-20261115/`。
- 未做长期稳定性、TCP/逐流乱序和 WAN→LAN 方向验收。

## 下载方向（out2in）

2026-11-15 加入 `patches/vpp/0021` 与 `nat-ei-out2in-return`：out2in 转换后的
ip4-lookup、二层与 TX 交回收包线程；`topology.vpp` 那行 `enable` 现同时启用两个方向。
插件 `nat44_ei_plugin.so` `6769b91b…`、`nat_ei_context_plugin.so` `874fd6f7…`，
备份 `/var/lib/vpp-rk3588/backups/pre-return-handoff-out2in-20261115/`。

局域网主机上 8 路并发下载 mensura.cdn-apple.com（约 1.1 Gbps，受外网限制），同进程交替开关：

| out2in 交回 | Mbps | wk_0 节点工作（10 s 窗口） | wk_0 发包 | wk_0 CPU |
|---|---:|---:|---:|---:|
| 关 | 1109 / 1111 | 3.11 s | 1.02M | 94% / 97% |
| 开 | 1090 / 1114 | 2.07 s | 0.27M | 92% / 96% |

wk_0 实际工作降约三分之一，但 CPU 读数不变：每次调度向量数仅 13–19，远未饱和，
读数主要是空转。vlib 主循环只要上一轮有 ≥2 个包，就在 1024 轮内不检查休眠
（`file.c` 的 `file_poll_skip_loops`），1.1 Gbps 下突发间隔远短于此，worker 不会休眠；
纯 interrupt 收包模式下 CPU 同样为 60–94%，与 adaptive 相同。
单 IP 下载的容量收益未在饱和负载下测量。

## 当前部署（2026-11-15 晚）

RK3588 开发板改为单 A76 worker 后，`topology.vpp` 已去掉 `nat44 ei return-handoff enable`：只有一个 worker 时
交回不会发生，下载方向的改接只增加一次节点调度。功能保留，默认关闭，多 worker 时再启用。
