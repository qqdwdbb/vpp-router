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

0037–0045 的目的、遇到的问题和 `ip4-local` 的缺陷见 [NAT44：TAP 校验和 offload 与 hairpinning](../docs/nat44-offload-hairpin.md)。

VPP 0046 修 0027 留下的问题：节点设回 adaptive 后可能一直轮询。0027 让 adaptive 节点从轮询开始，
一个线程上最后一个轮询队列改回 adaptive 时，节点要的状态仍是轮询；vnet 只在轮询列表、中断数或
`rxq_vector_poll` 变化时才更新。`rxq_vector_poll` 只在 adaptive 时替换，adaptive → polling → adaptive
后它和原来一样；中断数只有在最后改回的队列索引最大时才变。其余情况跳过更新，节点拿不到
`VLIB_NODE_FLAG_ADAPTIVE_MODE`，空转 100% CPU。启动时按创建顺序设置，最后一个索引最大，不受影响；
面板“系统”页单独切换一个口（不是索引最大的那个）就会触发。补丁比较节点现有的 adaptive 标志。
只改 libvnet。2026-11-26 在 RK3588 开发板上发现，在 ConnectX-3 主机上复现并验证，
切换时间的实测见 [adaptive 收包的切换时间](../docs/rk3588/rk3588-adaptive-switch-timing.md)。

VPP 0047 把 NAT44-EI 和 NAT44-ED 的 worker 交接队列从 64 个元素加到 512 个（`NAT_FQ_NELTS_DEFAULT`），
并修正 vlib 的 frame-queue 跟踪：跟踪数组只有 `FRAME_QUEUE_MAX_NELTS`（64）项，dequeue 时按队列长度
写，队列超过 64 个元素时 `trace frame-queue on` 会写出数组。每个元素装一次入队调用的包，轻载时
常常只有十几个，64 个元素约容一千个包。一个局域网主机的会话都在同一个 worker 上，另一个 worker
把 RSS 分给它的包全部交过去；线速突发到来时，接收方正在唤醒或被 powersave 压在低频，队列满了就按
`congestion drop` 丢掉，表现为 TCP 重传。每个元素约 2.1 KB，每个队列每个线程约多占 1 MB；单 worker
不建交接队列。改 libvlib、nat44_ei_plugin 和 nat_plugin。原因和实测见
[NAT 交接队列（0047）](../docs/worker-idle.md#nat-交接队列0047)。

VPP 0048 给 `abf-input-ip6` 注册错误计数。上游注册这个节点时写的是 `.n_errors = 0`，但 ip4/ip6 共用的
`abf_input_inline` 照样在它上面计 `matched`（1）和 `missed`（2）；它的错误表起点是 0，计数落到全局下标
1、2，也就是错误表里排第一的那个节点。这里的 26.06 构建上那是 `wg4-output-tun-handoff`：每个没命中 ABF 的
IPv6 包都显示成一次 WireGuard `congestion drop`。2026-11-26 在 RK3588 开发板上看到约 267 万次（每秒约 60 次，
那个节点一次都没运行过，同时段 `abf-input-ip6` 处理的包数与之相同）。补丁让 ip6 节点使用和 ip4 相同的错误
字符串，只改 abf_plugin。在 ConnectX-3 主机上验证：从局域网 ping6 路由器 200 次，修补前计到
`wg4-output-tun-handoff congestion drop`，修补后计到 `abf-input-ip6 missed`。

VPP 0049 在每次 DPDK RX burst 后提交异步升频请求：一次 ≥16 包，或 1 ms 内连续两次 ≥8 包；
独立 SCHED_OTHER 控制线程按 policy 合并请求，最后一次高负载后保持 100 ms，再恢复指定空闲下限。
收包线程不操作 sysfs；默认关闭，显式配置一个 policy。记录请求和写入时间，通过内核 CPUFreq 事件
测量实际生效延迟，不同步采样频率。实现、CLI、观测开销和 RK3588 开发板实测见
[RX burst 异步升频](../docs/rk3588/rk3588-rx-burst-dvfs.md)。

VPP 0050 让 dpdk 插件按 PMD 报告的 `max_mtu` 限制最大帧长。`dpdk_device_setup` 原来只看
`max_rx_pktlen`；virtio 的 `max_rx_pktlen` 固定是 9728，真正的上限是宿主机给的 `host_mtu`（Proxmox VE
默认取网桥的 MTU，1500）。VPP 按 8996 的 MTU（`no-multi-seg` 时 2022）配置，`rte_eth_dev_configure`
拒绝，所有队列建立失败，网卡一直是 `pmd-init-fail`。现在 PMD 报了 `max_mtu`（不是 UINT16_MAX）时，
最大帧长不超过 `max_mtu` 加驱动帧开销；两个值一致的 PMD 不受影响。只改 dpdk_plugin。在 PVE 的 virtio
网卡（`host_mtu=1500`）上验证：修补前起不来，修补后最大帧长 1526，加不加 `no-multi-seg` 都能启动和转发。
`host_mtu` 设成 9000 这类大值时 `no-multi-seg` 仍会失败：VPP 按 26 字节算帧开销，virtio 按 30 字节，
MTU 2022 的帧比 2 KB 的 buffer 多 4 字节。见 [PVE 虚拟网卡上的 NAT](../docs/pve-virtio-nat.md)。

VPP 0051 改接口名时只给有发送函数的设备类改 `<名字>-tx`、`<名字>-output` 节点的名字。没有发送函数的
设备类注册接口时不建这对节点，`tx_node_index` 是 0，`output_node_index` 是 0 或者共用的输出节点，
`vnet_rename_interface` 原来照样改名，改掉的是 0 号节点或共用节点。PPPoE 客户端插件
（[plugins/pppoeclient](../plugins/pppoeclient/README.md)）的 PPPoX 接口就是这种设备类，每建一个都会改名
（`pppoxN` 或 `create pppoe client ... name` 给的名字）。取自插件作者 VPP 分支 `feat/pr-pppoeclient`
的提交 50476c3c8，只改 libvnet。

VPP 0037（NAT44-ED）和 0038（NAT44-EI）让 NAT 正确改写"校验和未完成"的包。TAP 打开
`csum-offload` 或 `gso` 时，Linux 自己发出的 TCP/UDP 带 `NEEDS_CSUM` 进入 VPP，L4 校验和
字段里只有伪首部的和（未取反），由下一个 TAP 或网卡补全。NAT 原来把它当完整校验和做增量
更新：地址增量方向反了，端口和 MSS 的增量本不该加也加了；EI 的 hairpinning 改端口时还把
UDP 字段清零，丢掉了伪首部。从 TAP 或没有校验和 offload 的网卡发出时会被重写或软件重算，
看不出来；交给按字段原值计算的网卡（DPDK 只给 Intel 驱动重写伪首部）时发出错误的校验和。
现在这类包只把地址增量按正确方向加进字段，端口和 MSS 不加（MSS 选项照样改写）；这时 UDP
字段为 0 也要更新（是和，不是"没有校验和"）。ICMP 差错报文里的内层包总是完整校验和，照旧。
不带标志的包路径不变，只多一次缓冲区头部的标志判断。ED 只改 `nat_6t_flow_ip4_translate`
一处；EI 改 in2out 和 out2in 的慢路径、双包和单包快路径，以及 hairpinning，只改各自的
NAT 插件。

`tests/integration/integration_nat44_partial_checksum.py`（root）在独立的 VPP 里用两个带
校验和 offload 的 TAP 测 in/out 和输出特性两种接法：静态映射改端口、MSS 钳制改 SYN，回包
测 out2in。`pcap trace rx tx` 在 TAP 重写字段之前抓包，每个发出的包按它收进来时的样子判断：
Linux 并非每个包都留部分校验和（有些纯 ACK 带完整校验和），收进来是部分的，发出时必须等于
翻译后的伪首部和，收进来是完整的，发出时必须仍是完整校验和；再关掉 Linux 的 TX checksum
各测一遍。有 inside 接口时（`inout`、`mixed`）还测 hairpinning，依赖 0039、0040。2026-11-25
在 ConnectX-3 主机上：带 0037–0044 的 ED、EI 在 `inout`、`output`、`mixed`、`hairpin` 四种接法、Linux 校验和
offload 开和关下全部通过；它上面装的不带这些补丁的插件第一个 SYN 就失败（字段 `0xf94c`，
应为 `0xfe2e`），关掉 offload 时 hairpin 的 TCP 连不上。

VPP 0039（NAT44-EI）和 0040（NAT44-ED）修 hairpinning：从局域网访问路由器外网地址上的
端口映射（比如局域网设备用公网地址访问自己的端口转发）。上游 26.06 和当前 master 都有这两个
问题，与本项目其他补丁无关。

- EI：in2out 把源地址换成外网地址后，包按目的地址进 `ip4-local`，应由 `nat44-ei-hairpinning`
  改写目的地址。EI 把这个节点挂在 `local0` 的 `ip4-local` 特性链上，`ip4-local` 按
  `ip.rx_sw_if_index` 选特性链，但这个字段只在源地址检查里赋值，而带 `VNET_BUFFER_F_IS_NATED`
  的包跳过这一检查，字段里是和它共用内存的分片重组数据，特性链落在不存在的接口上，包被
  punt（`ip4-local: unknown ip protocol`）。0039 在 in2out 标记 `IS_NATED` 的地方把这个字段
  设成 `local0`。
- ED：hairpin 会话的 o2i 流把回包的源地址改回外网地址，却没把源端口从内部端口改回映射端口，
  客户端收到来自内部端口的回包后丢弃。0040 补上源端口改写；非 hairpin 时它等于原端口，
  不起作用。

只改各自的 NAT 插件。两者都只在有 inside 接口时生效：只有输出特性（安装脚本现在的配法，
`set interface nat44 out <WAN> output-feature`）时，发往外网地址的包不经过 in2out，VPP 不做
hairpinning，有没有这两个补丁都一样。在输出特性之外把局域网接口也设成 inside（测试的
`mixed`）时，EI、ED 的 hairpin 和普通出站都通过了测试，但 2026-11-26 在 ConnectX-3 主机上实测，这样做
NAT 吞吐从约 6.8 Mpps 降到约 3.0 Mpps：局域网流量在入口转换一次，到出口的输出特性又处理一次，
而且输出特性的 worker 交接按源地址选 worker，源地址都成了同一个外网地址，全部压到一个 worker
上。所以不用 `mixed`，改用 0043/0044 的 hairpinning 接法。

VPP 0041（NAT44-EI）和 0042（NAT44-ED）调整 inside 接口上 NAT 的位置：in2out 一侧的特性
（EI 的 `nat44-ei-in2out`、`nat44-ei-in2out-worker-handoff`、两个 classify；ED 的
`nat-pre-in2out`、`nat44-ed-in2out`、`nat44-in2out-worker-handoff`、两个 classify）排到
`abf-input-ip4` 和 `dns-intercept-ip4` 之后。原来 NAT 在前，局域网设为 inside 后，源地址
先被改成外网地址，按局域网源地址匹配的策略就失效了：2026-11-25 在 ConnectX-3 主机上把 `loop0` 设成
inside 后，Gate 的 DNS 劫持（ABF，ACL 匹配源 `10.61.30.0/24`）不再生效，局域网 DNS 直接发往
公网解析器，没有任何报错。调整后被 ABF 重定向的流量不经过 NAT，和只有输出特性时一样；其余
流量照常转换，out2in 不变。这两个名字只用于排序，不要求加载对应插件。测试里有 inside 接口时
检查 ABF 重定向收到的是客户端自己的地址：没有 0041 的 EI 在 `inout`、`mixed` 下失败；没有
0042 的 ED 在 `inout` 下失败，`mixed` 下 ED 本来就不转换经输出特性出口离开的被重定向流量，
有没有 0042 都通过。

VPP 0043（NAT44-EI）和 0044（NAT44-ED）让不是 inside 的局域网接口也能 hairpin：
`set interface nat44 ei hairpinning <接口> [del]`（ED 为 `set interface nat44 hairpinning`），
查看用 `show nat44 ei hairpinning interfaces`（ED 为 `show nat44 hairpinning interfaces`）。它在
接口的 `ip4-unicast` 上加一个分类节点（排在输入 ACL、分片重组、dns-intercept 和 ABF 之后），
只把 hairpin 能找到目的地的 TCP/UDP 送进 in2out：EI 是命中 out2in 会话或非恒等的静态映射，
ED 是命中非恒等的静态映射，或者目的是地址池地址且属于已有的流（hairpin 会话里内部服务的回包）。
其余流量原样放行，发往外网地址的其他流量（比如 ping 路由器外网地址）也不受影响。ICMP 和非首个
分片不做 hairpin；在 inside 接口上启用会被拒绝。EI 的 in2out 转换后直接去 `ip4-lookup`，hairpin
的目的地址由 `ip4-local` 的 `nat44-ei-hairpinning` 改写，依赖 0039；ED 的 in2out 自己改写两个
地址，依赖 0040，ED 的分类节点是 `nat-default` 的 sibling，因为 ED 的 in2out 按 `nat.arc_next`
走下一跳，编号必须在同一张下一跳表里（最初没这样做时 in2out 按错的编号循环，堆耗尽）。
2026-11-26 在 ConnectX-3 主机上（2 个 worker，`loop0` 开 hairpinning，WAN 输出特性，Gate DNS 劫持，
WireGuard 和桥接出口）：DNS 劫持、各出口、hairpin 和外部访问端口转发都正常；TRex 64 字节 UDP
在 6 Mpps 以内与只有输出特性时相同，饱和点约 6.2 Mpps（只有输出特性约 6.8 Mpps），是每个
TCP/UDP 包两三次哈希查找的代价。安装脚本和面板还没有接上这个命令。

```sh
sudo python3 tests/integration/integration_nat44_partial_checksum.py --nat ed|ei \
  --plugins <含 nat_plugin.so 或 nat44_ei_plugin.so 的目录> [--vpp /usr/local/bin/vpp] \
  [--system-plugins /usr/local/lib/vpp-router/vpp_plugins] [--mode inout|output|mixed]... \
  [--offload on|off]... [--dump]
```

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
