# 补丁

基于 VPP 26.06，在源码根目录用 `patch -p1` 按 `vpp/series` 的顺序应用。
`dpdk/series` 基于 DPDK 26.03，同样在源码根目录用 `patch -p1` 应用；使用
`platforms/rtl8125-noncoherent/dpdk-patches` 时排在它之后。

| 补丁 | 内容 | 硬件相关 |
|---|---|---|
| 0001 | dpdk 插件注册 r8169 驱动，并让它尝试收包中断 | 只有用 RTL8125 时需要 |
| 0002 | WireGuard 接口级 peer 和 show 命令 | 否 |
| 0003 | dpdk 插件 RX 调用上限 64、校验和状态传递 | 否 |
| 0004 | ACL 帧内普通 permit 缓存 | 否 |
| 0005 | TAP RX 回填重试 | 否 |
| 0006 | IPv6 RA 保留 PD 标志 | 否 |
| 0007 | IPv6 ESP UDP 校验和 | 否 |
| 0008 | NAT44-EI：handoff 与重组顺序、端口回滚、会话回收、单 worker | 否 |
| 0009 | FIB：路径复制时保留已删除接口的 DROP 标志 | 否 |
| 0010 | NAT44-EI：in2out 批量查找 | 否 |
| 0011 | NAT44-EI：out2in 的 DHCP 下一跳与 handoff | 否 |
| 0012 | NAT44-EI：会话导出包含外部主机 | 否 |
| 0013 | 插件文件名常量 | 否 |
| 0014 | vppinfra：时钟频率修正改为调整速率，不再跳变时间 | 否 |
| 0015 | IPv6 ND：邻居请求校验目标地址后才学习 MAC | 否 |
| 0016 | tlsopenssl：OpenSSL 3.2 起直接取协商组名（安装器不编译此插件） | 否 |
| 0017 | vlib：同步屏障后空闲 worker 的忙轮询窗口由 500 ms 缩短到 1 ms | 否 |
| 0018 | vlib：有待分发帧或新 handoff 工作时不进入休眠，避免 adaptive 下 NAT 交接拥塞 | 否 |
| 0019 | vlib：发布交接帧与进入休眠使用配对屏障，发布每批帧后检查可合并的唤醒 | 否 |
| 0020 | NAT44-EI：输出 handoff 在 `vnet_buffer2 (b)->unused[4]` 记录收包线程，供 nat-ei-context 交回 | 否 |
| 0021 | NAT44-EI：out2in 与内侧输入 handoff 也记录收包线程（供下载方向交回） | 否 |
| 0022 | vlib：忙碌后跳过 file poll 的轮数可用 `set file-poll busy-loops <n>` 调整（默认 1024 不变） | 否 |
| 0023 | vlib：adaptive 待切换期间出现忙窗口时取消切换，需连续两个空闲窗口才切回中断 | 否 |
| 0024 | dpdk：adaptive 收包中断只在中断状态重新武装，切回中断前的那次调度先武装再收包（依赖 0023） | 否 |
| 0025 | NAT44-EI：输出特性不转换源地址是 NAT 地址池地址的包（VPP 自己发出的，比如回应 WAN 上的 ping），否则回复被换了 ICMP ID 或端口，对方丢弃 | 否 |
| 0026 | ACL：`show acl-plugin acl` 打印完释放输出缓冲，原来每次调用每个 ACL 泄漏一个主堆 vector（RK3588 开发板上每 2 秒轮询时约 3.5 MiB/小时） | 否 |
| 0027 | interface：adaptive 节点一律从轮询开始，由 vlib 自己切到中断态（切换前那次调度让驱动武装中断，见 0024）；原来一个线程上的队列全变成 adaptive 时直接进中断态，r8169 已触发过的一次性中断不再武装，网卡停止收包 | 否 |
| 0028 | 启动日志去噪：mfib 不再给没有 MAC 的接口（local0、WireGuard、TUN）加组播 MAC；dpdk 插件在 PMD 不支持 MAC 过滤（-ENOTSUP）时接受组播地址，端口启动时本来就开了 all-multicast；tap 把旧内核对 `VHOST_SET_FORK_FROM_OWNER` 返回的 EPERM 当作不支持；r8169 系列 PCI ID 不再报 Unsupported PCI device | 否 |

0014–0016 原本只在 RK3588 开发板构建所用的 VPP 源码包里（版本串 `v26.06-1-geth1test`），
2026-11-14 补进本系列。按完整系列打好补丁后，这几个文件与该源码包逐字节相同；
RK3588 开发板上的 libvppinfra 和 libvnet 含有 0014、0015。

VPP 0029 将启动配置前固定的 2 秒等待替换为 Unix 配置完成且主循环已完成
首轮的条件；首轮开始前所有 process 节点均已首次调度，保证 dpdk-process
先创建接口。只修改 libvlib，不改变结构体布局；验证记录见
[RK3588 开发板热重启](../docs/rk3588/rk3588-pmd-warm-restart.md)。

VPP 0030 让 mlx4（ConnectX-3）支持 interrupt、adaptive 收包模式。原来 `net_mlx4` 和
qede、bnxt 共用一个驱动条目，没有 `.enable_rxq_int`，设置 adaptive 时返回 Unimplemented (-9)。
只加这个标记还不够：mlx4 的队列 fd 是 ibverbs 完成通道，不是 eventfd，事件要用
`ibv_get_cq_event` 取出并确认（PMD 在 `rx_intr_disable` 里做），VPP 原来 `read()` 8 字节
取不走事件，CQ 不再武装，worker 睡下后再也收不到包。补丁加驱动标志 `int_ack_by_disable`：
有事件时通过 `rte_eth_dev_rx_intr_disable` 取走并确认，切回轮询时把它返回的 -EAGAIN
（没有待取的事件）当作成功。136（i5-9300H、ConnectX-3、2 worker／2 队列、NAT44-EI）实测：
空闲时每个 worker 0.9% CPU（轮询为 100%），1 kpps 到 1 Mpps 由中断唤醒不丢包，
满载 7.3–8.1 Mpps 与轮询相同，轮询和 adaptive 可以来回切换。

VPP 0031 让同一 PCI 设备的几个口分别命名。dpdk 段的 `dev` 块按 PCI 地址匹配，PMD 为这个
地址建的每个口都用它的设置和名字；mlx4 经一个 PCI 功能驱动 ConnectX-3 的两个口，第二个口
因重名被丢掉，而且 `dpdk_lib_init` 直接返回重名错误，排在它后面的设备也不再初始化。不写
`name` 时默认名取自 PCI 地址，同样重名。现在 `name` 可以写成逗号分隔的列表，按 PMD 建口的
顺序（mlx4 是 ConnectX 的口号，即 Linux 的 `dev_port`）命名：`dev 0000:01:00.0 { name port0,lan0 }`；
列表里没有名字的口（包括只写一个名字时的第二个口）记一条 notice 后跳过，不再中断初始化。
单口设备写一个名字时和原来一样。只改 dpdk 插件。面板“系统”页加口时检查插件里有没有这条
notice 的文字，没有就不允许。2026-11-21 在 ConnectX-3 主机上实测：`port0,lan0` 得到两个接口，
`port0` 的 WAN 照常。

VPP 0032 让 admin down 的 DPDK 口也能设收包方式。端口没启动时还没探测过收包中断
（`DPDK_DEVICE_FLAG_INT_SUPPORTED` 在 `dpdk_device_start` 里探测），原来设 interrupt、adaptive
都报 `unsupported op (is the interface up?)`，队列停在轮询；轮询的队列让它所在的 worker
永远不休眠，哪怕这个口收不到包。ConnectX-3 主机上第二个口没接线、down 着，两个 worker
因此 100% 空转（CPU 包 28 W、69 °C，修复后 3.5 W、43 °C）。现在端口没启动时接受设置，
vnet 记在队列上；端口启动、探测完以后按每个队列的方式打开中断，探测不到中断时改回轮询并
记 notice。另外原来每次启动端口都把队列的中断 fd 再加入 epoll 一次（日志里每次 down/up 都有
`epoll_ctl` EEXIST），旧文件也留着；现在停止端口时删除这些文件，fd 属于 PMD，不关闭。
只改 dpdk 插件。2026-11-21 在 ConnectX-3 主机上实测：down 时设的三种方式在 up 后都生效，5 次 down/up
后每个队列只有一个文件、没有 epoll 报错，WAN 口 3 次 down/up 后 worker 休眠时 ping 全部收到。

DPDK 补丁：

| 补丁 | 内容 | 硬件相关 |
|---|---|---|
| dpdk/0001 | r8169 PMD 收包中断（VPP 的 interrupt、adaptive 收包模式） | RTL8125/8126/8127、RTL8168 |
| dpdk/0002 | 扩展到最多 4 个 RX 队列，各自使用 eventfd | RK3588 开发板的 RTL8125 四队列已实测 |

DPDK 26.03 的 r8169 PMD 只有链路中断。它沿用旧的中断映射，所有中断都走第一个向量，
由 DPDK 中断线程读取，没有可以交给应用的队列向量。补丁给 RX 队列建一个 eventfd，
队列处于等待中断状态时，中断处理函数写这个 eventfd 唤醒 VPP；中断是一次性的，
VPP 下次等待时重新打开。0002 将此机制扩展到最多 4 个 RX 队列，其他队列使用
16 位 IMR1/ISR1 寄存器组。中断到来时唤醒所有已启用中断的队列，避免收包路径
提前清除状态造成漏唤醒；可能有额外的空轮询。单队列网卡仍使用原寄存器。
2026-11-14 已在 RK3588 开发板的 RTL8125 上部署 4 RX 队列和 4 worker，逐队列单独启用
中断时均观察到硬件 IRQ 增长与实际收包。轻载 CPU、验证范围及限制见
[多队列实测记录](../docs/rk3588/r8169-multi-queue-interrupts.md)。
不打这个补丁时，VPP 0001 的 `.enable_rxq_int` 也只是探测失败后保持轮询。

源码包 SHA-256（`deploy/install/vpp-router-install.sh` 用这两个地址和哈希）：

| 文件 | 地址 | SHA-256 |
|---|---|---|
| VPP v26.06 | `https://github.com/FDio/vpp/archive/refs/tags/v26.06.tar.gz` | 9541cb9fc889b963f537117907e16b8e37339d3446bad71cdf9e7d05622db990 |
| DPDK 26.03 | `https://fast.dpdk.org/rel/dpdk-26.03.tar.xz` | 84989202bbe0fbaeeb62f8fdc63f691880ac0b66cd0dc64c167843c59db29d2c |

2026-11-12 下载核对过，与 N1 构建时记录的哈希相同。

0009 的背景和曾经发生的回归见 [docs/fib-path-copy-fix.md](../docs/fib-path-copy-fix.md)。重建 libvnet 时必须包含全部补丁，安装器会校验 libvnet 哈希。

树外插件补丁随源码存放在对应的 `../plugins/` 子目录，不加入上游 VPP 的 `vpp/series`：

| 补丁 | 内容 | 应用位置 |
|---|---|---|
| [nat-ei-context-invalid-next.patch](../plugins/nat-ei-context/nat-ei-context-invalid-next.patch) | context-enter/exit 校验下一跳索引；非法包丢弃、计数并限频记录 | 本仓库旧版本源码根目录 |
| [nat-ei-context-cursor-check.patch](../plugins/nat-ei-context/nat-ei-context-cursor-check.patch) | context-exit 校验特性链游标位置；错位包丢弃并计数 | 已应用上一个补丁的源码根目录 |

当前插件源码已包含这些修复。构建、部署和回归测试说明见
[nat-ei-context README](../plugins/nat-ei-context/README.md#invalid-feature-next-indices)。
