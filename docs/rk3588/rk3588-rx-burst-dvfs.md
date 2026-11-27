# RX burst 触发异步升频（0049）

2026-11-27，VPP 26.06、DPDK 26.03，RK3588 开发板，内核 6.1.57。

## 实现

0049 是独立补丁，排在既有补丁之后；不改 0024 的中断武装逻辑，也不在 eventfd 回调中查询 RX ring。
在 `dpdk_device_input()` 每次 `rte_eth_rx_burst()` 返回后观察该次的包数，**不是节点多次收包后的累计数**：

- 一次 ≥16 包：请求升频。
- 连续两次 ≥8 包，且间隔不超过 1 ms：请求升频。小于 8 包的调用（包括 0）打断连续条件。
- 最近一次满足条件后保持 100 ms；零星小包不延长保持时间。
- 同一 worker 上的 RX 队列共用连续条件，同一 CPUFreq policy 内所有 worker 共用频率保护。

收包线程只写自己的时间戳；一个新的忙碌周期通过非阻塞 eventfd 唤醒独立的 `dpdk-dvfs` pthread。
它不分配内存、不获取互斥锁、不操作 sysfs，也不等待升频。持续负载只更新时间戳，不逐包写 eventfd。
控制线程使用 SCHED_OTHER，继承创建它的主线程 CPU affinity；不占用新的 worker，不修改 dpdk-intr 优先级。

控制线程把 policy 的 `scaling_min_freq` 临时提高到指定 boost，100 ms 到期后写回指定 idle。
保持期内允许原 governor 继续决定频率，最高频率不变。等待到期期间会重新检查所有 worker 的最新请求，
即使收包线程已经休眠也能释放保护。控制线程不采样当前频率；空闲时阻塞等待 eventfd。

本版显式配置一个 policy，支持该组内多个 worker；第二次 enable 返回 busy，需先 disable。
默认关闭，不自动写入 startup CLI 或管理面板配置。线程迁移到其他 policy 后须重新配置。

## 使用

```text
set dpdk dvfs policy policy0 idle 408000 boost 1800000
show dpdk dvfs
set dpdk dvfs disable
```

idle/boost 必须是该 policy 支持的频率，并适合当前流量容量。408 MHz 仅是本次实验值，**长测未达到零丢包**。
`disable` 和正常 VPP 退出恢复启用前读回的有效最低频率；程序被强制杀死不能执行退出恢复。
有效下限可能暂时高于此前用户请求值，因此 `show` 显示 `idle_khz`、`boost_khz` 和 `original_khz`，
不把有效下限快照当成管理服务保存的请求值。若需要回到保存的管理配置，可在 disable 后运行：

```sh
/usr/local/bin/vpp-system frequency-guard --config /etc/vpp/system.json
```

实验期间不要同时通过其他程序改该 policy 的频率下限。测试使用脱离 SSH 的超时救援任务；结束后恢复
管理服务保存的 1.2 GHz 保护，并关闭实验控制器；没有改写该持久配置。

`show dpdk dvfs` 保存最近 256 个已结束周期：

| 字段 | 含义 |
|---|---|
| trigger_ns | 第一次满足条件的 RX burst 时间，CLOCK_MONOTONIC 纳秒 |
| wake_us | 控制线程处理该周期的时间，相对 trigger |
| write_begin_us / write_end_us | boost 写入开始/结束时间，相对 trigger |
| hold_us | 从最后一次满足条件到 idle 写入完成的时间，不是到物理降频的时间 |
| error | 请求或恢复写入的 errno；0 只表示写入成功，不表示硬件已达到目标频率 |

## 以内核事件测量升频完成

使用独立 trace instance，避免改变全局 tracer；trace clock 设为 mono，与 RX 时间戳使用相同时间域。
policy0 的代表 CPU 是 0，因此只记录 `cpu_id == 0`，避免把同一 policy 的多个 CPU 通知算成多次升频。
[上游 Linux 6.1 CPUFreq 实现](https://github.com/torvalds/linux/blob/v6.1/drivers/cpufreq/cpufreq.c#L351-L363)
在 POSTCHANGE 路径发出 `power:cpu_frequency`。这里测的是驱动完成通知，仍不是电压/PLL 的外部物理测量。

```sh
D=/sys/kernel/tracing/instances/dvfs-experiment
mkdir "$D"
echo mono >"$D/trace_clock"
echo 2048 >"$D/buffer_size_kb"
echo 'cpu_id == 0' >"$D/events/power/cpu_frequency/filter"
echo 1 >"$D/events/power/cpu_frequency/enable"
echo 1 >"$D/tracing_on"
vppctl set dpdk dvfs policy policy0 idle 408000 boost 1800000
# 执行受控突发测试；结束后等待最后的 100 ms 保持期释放。
vppctl show dpdk dvfs >requests.txt
echo 0 >"$D/tracing_on"
cat "$D/trace" >frequency-trace.txt
cat "$D"/per_cpu/cpu*/stats
vppctl set dpdk dvfs disable
/usr/local/bin/vpp-system frequency-guard --config /etc/vpp/system.json
echo 0 >"$D/events/power/cpu_frequency/enable"
rmdir "$D"
python3 benchmarks/analysis/vrouter_dvfs_latency.py \
  --requests requests.txt --trace frequency-trace.txt --cpu 0 --target 1800000 >latency.csv
```

分析工具区分已在高频、写入前 governor 已自然升频、写入后达标、没有观测到和缺少基线的样本。
不能把前两类当作本次写入的升频延迟。本次内核缓冲区 3392 个事件完整保留，各 CPU 的 overrun、
commit overrun、dropped events 均为 0。

## RK3588 开发板结果与限制

主线程 cpu1、A55 worker cpu2、dpdk-intr FIFO 10；policy0 使用 schedutil，最高 1.8 GHz。
4 个 UDP 流、64B 帧（含 FCS），LAN → NAT44-ED → WAN VLAN100 → 独立 Linux 命名空间。
先预热会话和邻居，每次突发 20 ms，间隔 600 ms，目标 300 kpps；实测 297479–299341 pps。
使用 TPACKET_V3 接收器按唯一序号对账，并确认源地址已被 NAT 改写；家庭网络背景流量未隔离。

正常控制器、不做同步频率读回，内核事件观测：100 次突发对应 100 个升频周期，36 个在触发前已经达标，
64 个在写入后达到 1.8 GHz。下面只统计其中 **56 个触发前最近频率事件为 408 MHz** 的周期。
P95 用 nearest-rank；样本较少，最大值只是本次观测，不是最坏情况上界。

| 从 RX 触发起计 | 中位数 | P95 | 最大 |
|---|---:|---:|---:|
| 控制线程开始处理 | 0.154 ms | 0.305 ms | 0.311 ms |
| boost 写入完成 | 0.279 ms | 0.477 ms | 0.489 ms |
| 内核报告达到 1.8 GHz | 0.842 ms | 1.797 ms | **13.239 ms** |

最慢周期 id=53：请求写入在 0.197 ms 完成，频率完成事件在 13.239 ms 才出现。
所以提前触发确实缩短了通常情况下的响应，但写入完成并不消除内核/硬件生效的长尾。
最后一次高负载后恢复 idle 的时间，全部 100 个周期中位数为 100.103 ms、最大 101.125 ms。

同次 NAT 测试发送 600000，唯一接收 597953，缺 2047（**0.3412%**）；无重复，
发送端 tx_dropped、接收器 capture_dropped 和 capture_freezes 均为 0。
这不能据此把全部缺包归因于单个长尾，也不能宣称 408 MHz 下限已经解决零丢包问题。
[逐周期数据](measurements/rx-burst-dvfs-trace-20261127.csv)保留了正常模式的请求与频率事件关联结果。

早期短测 30 次、18 万包曾零丢包；另一轮 100 次也曾零丢包，延长和复测后未稳定复现。
最初的实验代码曾在请求写入前同步读取 cpuinfo_cur_freq、随后每 100 μs 读回，发现它会引入长尾：
408 MHz 组保留的 168 个低频样本最大 8.457 ms，同次 60 万包缺 1603；1.2 GHz 组的 19 个低频样本
最大 6.254 ms，同次 18 万包零丢包。该同步读回逻辑已从最终补丁移除，不作为生产测量方式。
去掉读回后的额外 10 次短测收齐 60000 包，但上面的内核事件长测仍有缺包，因此保留 1.2 GHz 保护。

ARM64 插件构建通过；控制器在 Linux ARM64、AMD64 上通过 ASan/UBSan 测试，覆盖阈值、唤醒合并、
多 worker 延长保持、空闲释放、disable 恢复及写入失败；另有两项 Python 测试验证 trace 解析和关联边界。
相关 DPDK 源文件按完整补丁顺序应用检查通过。x86 尚未进行该异步机制的实机调频延迟测量。

部署备份：`/var/lib/vpp-router/backups/pre-dvfs-async-20261127/`。
最终构建重新部署后，以 1.2 GHz 下限完成 5 次突发，30000 包全部收到；随后关闭实验控制器并恢复保存的保护。
六项相关服务均 active，外网 ping 3 次零丢包，已安装插件与构建产物 SHA256 一致；测试 namespace 和 trace instance 已清理。
本次没有重启整机，也没有改变 CPU 布局、RT 优先级、NAT 模式或保存的 governor/频率保护配置。
