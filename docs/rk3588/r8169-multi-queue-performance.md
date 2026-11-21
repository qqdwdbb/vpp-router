# RK3588 开发板四队列 NAT 性能定位与修正

2026-11-15，针对原四 A55 报告（`artifacts/rk3588-nat-4a55-20261114/report.md`，未入库）
中的单流 0.5 Mpps 输入、实收仅 0.156–0.179 Mpps 的异常，完成受控定位与部署。
以下为短时、现场流量背景下的结果，不代表长期或满载无损验收。

## 条件与可比性

- main CPU4，worker CPU0–3；四 RX 队列、两 TX 队列，buffer 32768。
- 物理 LAN → 动态 SNAT → 物理 WAN VLAN100，64B 含 FCS，TRex 单发包 worker。
- 单流源 10.61.20.198:53000，目的 10.61.10.250:45996；每档指定包数为 PPS×10，
  接收端 mlx5 DPDK 按载荷唯一序号计数。实际发送时长另存日志，约 10 秒。
- 同一轮内保持 VPP PID、PMD、CPU 绑定和 RSS 不变，只交换 RX 队列的 worker 分配及收包模式。
  源 IP 198 按 NAT44-EI 规则归 worker 0：对齐时把测试 RX 队列分给 worker 0，
  跨 worker 时分给 worker 1；与该队列交换的另一个队列仍保持每 worker 一个 RX 队列。
- PMD 未指定 RSS key 时会随机初始化，重启可能改变同一条流的 RX 队列。
  修正前轮 PID 158103、测试流落 queue 3；修正后轮因换库重启，PID 193472、落 queue 1。
  两轮分别控制逻辑归属；不能当作物理队列不变的精确吞吐收益 A/B。
- 修正前轮预热 10 万包，修正后为保证抓包识别窗口而预热 50 万包，均为 0.1 Mpps。

## 定位结果

在修正前的同一进程中，仅改变测试 RX 队列归属即可复现异常：

| 单流条件 | 输入 Mpps | 唯一实收 Mpps | 逐档 NAT handoff congestion drop 增量 |
|---|---:|---:|---:|
| 对齐、adaptive | 0.5 | 0.499947 | 0 |
| 对齐、polling | 0.5 | 0.500000 | 0 |
| 跨 worker、adaptive | 0.5 | 0.173072 | 3,269,541 |
| 跨 worker、polling | 0.5 | 0.500000 | 0 |
| 跨 worker、adaptive | 1.0 | 0.796020 | 546,827 |
| 跨 worker、polling | 1.0 | 0.866818 | 0 |
| 跨 worker、adaptive 重复 | 0.5 | 0.165573 | 3,344,628 |
| 对齐、adaptive 重复 | 0.5 | 0.500000 | 0 |

跨 worker、adaptive、0.5 Mpps 档，RX worker 单核 CPU 约 98%，NAT worker 只有约 16%。
交接拥塞增量与唯一缺包数接近，但包含后台业务，不能认为逐包一一对应。
这表明该异常与跨线程消费/等待路径有关，不是一个 CPU 已满的 NAT worker 的普通吞吐上限。

主循环 `main.c` 在调用 `vlib_file_poll()` 前从线程间队列取帧，调用后才处理
`node_main.pending_frames`。原文件轮询仅依赖上一轮向量数、input node 状态等，
可能在已有待分发帧时等待 epoll。源代码回归检查可直接复现这个条件。

## 修正与验证

`patches/vpp/0018-vlib-do-not-sleep-with-pending-handoff-frames.patch` 在有待分发帧
或新 frame-queue 工作时跳过休眠。未改变 NAT worker 归属、交接队列容量和 PMD。
RK3588 开发板重建时只替换 libvlib 的 `file.c.o`；先用原对象链接复现了生产库的完整 SHA-256。

| 修正后单流条件 | 输入 Mpps | 唯一实收 Mpps | 交接拥塞增量 |
|---|---:|---:|---:|
| 对齐、adaptive | 0.5 | 0.491669 | 0 |
| 对齐、polling | 0.5 | 0.500000 | 0 |
| 跨 worker、adaptive | 0.5 | 0.499234 | 7,664 |
| 跨 worker、polling | 0.5 | 0.500000 | 0 |
| 跨 worker、adaptive | 1.0 | 0.865648 | 0 |
| 跨 worker、polling | 1.0 | 0.870874 | 0 |
| 跨 worker、adaptive 重复 | 0.5 | 0.499289 | 7,106 |
| 对齐、adaptive 重复 | 0.5 | 0.496896 | 0 |

主要的非单调低速异常已显著消除，但不能宣称无损：跨 worker 0.5 Mpps 两档仍缺
7,664/7,106 包（约 0.15%/0.14%），均有对应交接拥塞计数；对齐 adaptive 也有
其他路径缺包，尚未逐包归因。1 Mpps 下仍有 CPU/收包容量相关损失，不能靠此修正消除。

单 IP、1 万源端口流、1 Mpps 输入，两组队列映射下修正前实收约 0.658/0.667 Mpps，
修正后约 0.661/0.656 Mpps，仍有大量交接拥塞。它们始终归一个 NAT worker，
不能据四 RX 队列推断 NAT 工作会自动均摊到四核；单流的“对齐”映射也不代表
1 万条 RSS 流全部对齐。这部分未证明有性能收益。

两轮接收端 duplicates、imissed、ierrors、rx_nombuf 均为零；乱序不计为丢包。
原始硬件统计保留在逐档文件中，部分计数存在回绕，不能未经位宽/采样核对直接作累计差值。

完成后恢复各 RX 队列的原 worker 分配及全部 adaptive。轻载 10 秒增量采样中四个
worker 单核 CPU 为约 2.7%、1.1%、2.8%、1.2%，主线程约 9.5%；网关 5 发 5 收，
Host Stack HTTP 200。发包与接收服务退出，接收口归还原 namespace，无 IP 地址，
pause 恢复 RX/TX on，管理连接恢复。未为此次操作新建备份，恢复机制使用既有库产物；
验证后已取消自动恢复计时器。

## 记录与部署状态

- 第一次模式对照：原始结果（`artifacts/rk3588-rx-mode-ab-20261114/report.md`，未入库）。
- 修正前受控结果：`artifacts/rk3588-rx-owner-ab-20261115/controlled/summary.json`。
- 修正后结果：`artifacts/rk3588-handoff-idle-fix-20261115/summary.json`。
- `attempt1` 的预热抓包被后台报文占满，控制脚本退出，没有执行预定模式切换；
  该目录数据不作为 A/B。正式受控轮绑定实际运行 PID 后完成所有十档。
- 回归检查：`tests/unit/check_vlib_handoff_sleep.py`；旧源在待处理帧场景失败，
  0017+0018 源通过，且验证无待处理工作时仍可休眠。ARM64 实际编译和上述流量测试通过。
- 当前 PMD SHA-256 保持
  `6285f38720d8ab84aa85cdda2a20d82403720a190c1f92bfd00ee333d156f8d0`。
- 0018 轮测试时部署的 libvlib SHA-256：
  `ac3715df2c6ffc8f37f6bb6f06aacfa7bb50e2d765d9d443fab76ded507d1233`。
- 设备构建记录：`/usr/local/src/vpp-rk3588/maintenance/handoff-pending-frames-20261115/`。

本修正针对已入队交接工作的等待决策，未证明覆盖所有并发唤醒竞态。
仍需单独验证剩余小比例交接丢包、长时间运行、满载及其他网卡/平台。

后续已对剩余约 0.14%–0.15% 的单流交接丢包验证并部署 0019，三次相关复测的
交接丢包增量均为零；单 IP 多流容量仍未突破。当前部署状态及失败试验见
[交接唤醒与单 IP 容量后续实测](rk3588-handoff-wakeup-capacity.md)。
