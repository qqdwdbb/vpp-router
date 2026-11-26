# NAT44：TAP 校验和 offload 与 hairpinning（补丁 0037–0045）

下文的地址和接口名是示例，按目标设备的配置替换。测试机是一台 ConnectX-3 主机（i5-9300H，2 个 worker），
按安装脚本的布局部署：WAN 是输出特性（`set interface nat44 ei out <WAN> output-feature`），局域网是桥域加
BVI `loop0`，Linux 经 TAP `vpp-host` 接入，Gate 的 DNS 劫持是 `loop0` 上的 ABF。

## 目的

1. **TAP 打开校验和 offload 时 NAT 要正确。** VPP 和 Linux 之间的 TAP 打开 `csum-offload` 或 `gso` 后，Linux
   自己发出的 TCP/UDP（sing-box 代理、面板、测速等）不再算完校验和，交给下游补全；NAT 必须按这种状态改写。
2. **Hairpinning。** 局域网主机用路由器自己的外网地址访问端口转发（比如用公网地址访问自己的服务），路由器要
   同时改写源地址和目的地址，再把包送回局域网。安装脚本的配法下 VPP 一直做不到。

## 补丁一览

| 补丁 | 插件 | 内容 |
|---|---|---|
| 0037 | ED | 未完成校验和的包只按正确方向加地址增量，端口和 MSS 不加 |
| 0038 | EI | 同 0037，覆盖 in2out、out2in 的慢路径和两种快路径以及 hairpinning |
| 0039 | EI | hairpin 节点从来不执行：in2out 给 `ip.rx_sw_if_index` 赋值（见下文 `ip4-local` 的缺陷） |
| 0040 | ED | hairpin 会话的回包没有把源端口改回映射端口 |
| 0041 | EI | inside 接口上 in2out 排到 ABF、dns-intercept 之后 |
| 0042 | ED | 同 0041 |
| 0043 | EI | `set interface nat44 ei hairpinning <接口>`：不把局域网设成 inside 也能 hairpin |
| 0044 | ED | `set interface nat44 hairpinning <接口>`：同 0043 |
| 0045 | EI | 多 worker 共用的端口位图在运行时扩容，写坏堆 |

每个补丁的细节见补丁文件开头的说明和 [补丁 README](../patches/README.md)。全部只改 NAT 插件（`nat_plugin.so`、
`nat44_ei_plugin.so`），不改 libvnet，`nat44_ei_main_t` 的布局不变。

## 遇到的问题

### NAT 把未完成的校验和当成完整的改写（0037、0038）

Linux 交给 TAP 的 `NEEDS_CSUM` 包，L4 校验和字段里只有伪首部的和（未取反），TAP 收包时标成
`VNET_BUFFER_OFFLOAD_F_TCP/UDP_CKSUM`。ED 和 EI 都按完整校验和做增量更新：地址增量方向反了，端口和 MSS 的
增量本不该加也加了。之后从 TAP 或没有校验和 offload 的网卡发出时字段会被重写或软件重算，看不出来；交给
按字段原值计算的网卡（DPDK 只给 Intel 驱动重写伪首部）时，线上的校验和就是错的。

改法是只把地址增量按正确方向加进字段（VPP 的 `ip_csum_add_even` 实际做减法，`ip_csum_update` 交换新旧值即可），
端口和 MSS 不加，UDP 字段为 0 时也更新（是和，不是“没有校验和”）。这比“先补全再改写”快，而且 GSO 大包也能
正确处理。

测试中踩过的两个坑：VPP 的 pcap 默认每包只抓 512 字节，按截断的长度算伪首部会误报；Linux 并不是每个包都留
未完成的校验和（有些纯 ACK 是完整的），所以测试按每个发出包收进来时的状态判断，而不是假定全都是未完成的。

### EI 的 hairpin 节点从不执行（0039）

见下文“`ip4-local` 的缺陷”。现象是 hairpin 的 SYN 在 in2out 改完源地址后进了 `ip4-receive`，被 punt
（`ip4-local: unknown ip protocol`）。手工把 hairpin 节点挂到各个接口上也没用。

### ED 的 hairpin 回包端口不对（0040）

ED 建 hairpin 会话时，回程流把源地址改回外网地址，却没把源端口从内部端口（比如 5003）改回映射端口（6003）。
客户端发往 6003，收到来自 5003 的回包就丢掉，TCP 连不上。动态会话和静态映射两个分支都漏了这一步。普通流量里
这个端口本来就等于原端口，补上的改写不起作用。

### 把局域网设成 inside（mixed 接法）的两个问题（0041、0042，最终不用）

最先试的办法是在输出特性之外把 `loop0` 也设成 inside。hairpin 通了，但：

- **Gate 的 DNS 劫持被悄悄绕过。** `loop0` 的 `ip4-unicast` 上 NAT 排在 ABF 前面，源地址先被改成外网地址，
  ABF 的 ACL（匹配局域网源地址）就匹配不上，DNS 直接发往公网解析器，客户端照样拿到答案，看不出异常。
  0041/0042 把 in2out 一侧的特性排到 ABF 和 dns-intercept 后面，修好了这一点（in/out 接法同样受益）。
- **吞吐减半。** TRex 64 字节 UDP 从约 6.8 Mpps 降到约 3.0 Mpps。局域网流量在入口转换一次，到出口又经过输出
  特性的交接和慢路径；而 EI 的交接按源地址选 worker，源地址都成了同一个外网地址，全部压到一个 worker 上。

所以不采用 mixed 接法。

### hairpin 分类节点（0043、0044）

在局域网接口上加一个分类节点（排在输入 ACL、分片重组、dns-intercept、ABF 之后），只把 hairpin 能找到目的地
的 TCP/UDP 送进 in2out，其余流量原样放行：

- EI：命中 out2in 会话（也覆盖内部服务的回包），或命中非恒等的静态映射。
- ED：命中非恒等的静态映射，或目的是 NAT 地址且属于已有的流（hairpin 会话里内部服务的回包不对应任何静态
  映射，最初漏了这一种，TCP 连不上）。

恒等映射（比如 IKE 的 UDP 500/4500）不算 hairpin；ICMP 和非首个分片不做 hairpin；在 inside 接口上启用会被拒绝。

做的过程中的问题：

- **ED 的下一跳编号。** 特性链上存的“下一个特性”编号是相对于前一个特性节点的下一跳表算的。ED 的 in2out 按
  `nat.arc_next` 走下一跳，最初分类节点用自己的下一跳表，编号对不上，in2out 把包不停地送回自己，帧越积越多，
  堆耗尽崩溃。改成 `nat-default` 的 sibling、共用一张下一跳表后正常。EI 的 in2out 转换后总是去 `ip4-lookup`，
  不受影响。
- **预过滤。** 分类节点先把目的地址和一个小数组比较：地址池地址和非恒等静态映射的外部地址。不在里面的包不做
  哈希查找。数组在增删地址和静态映射、关闭插件时重建；DHCP 改地址时可能没有同步屏障，所以先清计数、最后写
  计数，并发读到的最坏情况只是一个包分错类，in2out 或后续特性都能正确处理。超过 64 个地址时退回每包查找。
- EI 的端口映射外部地址必须是地址池地址（`External address must be allocated`），所以 EI 里不在地址池的外部地址
  只来自只映射地址的静态映射；这两种都测过。

### EI 共用的端口位图在运行时扩容（0045）

每个地址池地址每种协议有一张端口占用位图，所有 worker 共用（主线程添加静态映射时也会写）。它在加地址时是空的，
随着分配的端口号变大，由 `clib_bitmap_set` 扩容。冷启动后第一波新会话时，一个 worker 扩容、把位图搬到新内存，
另一个 worker 还在往旧内存写，堆被写坏：dlmalloc 在 `nat44_ei_alloc_default_cb` 的扩容里 `try_realloc_chunk`
中止，或者别的线程在下一次分配时卡死在堆锁上。只影响多 worker 的 EI。

0045 在加地址时把位图一次分配到 65536 位（每种协议 8 KB），置位和清位改成原子字操作（worker 数不能整除端口
空间时，两个 worker 的端口范围会共用一个字），删地址时释放。冷启动后立刻上流量的试验，带和不带 0045 都各通过
4 次，所以崩溃没能按需复现；0045 的依据是代码分析和两次崩溃的现场。

### 测试环境的问题

- **TRex 的回程帧在 VLAN 100 泛洪。** TRex 在 VLAN 2 上发、在 VLAN 100 上收；交换机在 VLAN 100 里从没见过
  TRex 的 MAC，把回程帧当未知单播泛洪到 VLAN 100 的所有端口，包括同一交换机上另一台路由器的 WAN 口和光猫。
  修法：每轮额外发一路每秒 20 个、源 MAC 是 TRex 端口的 VLAN 100 小帧（目的是被测路由器的 WAN MAC，本地实验
  以太网类型 `0x88b5`，被测路由器丢弃），主流量推迟 0.5 秒开始，结果里扣掉这些学习帧。以后回程走另一个 VLAN
  的测试都要这样做。
- `kill -9` 结束卡死的 VPP 后，网卡在下一次运行里持续丢约 6%（`rx_fifo_errors`），重新正常重启后恢复；比较
  吞吐时不能用这样的数据。

## `ip4-local` 的缺陷

上游 VPP 26.06 和当前 master 都有，与本项目的其他补丁无关。

1. EI 把 `nat44-ei-hairpinning` 挂在 `local0`（接口 0）的 `ip4-local` 特性链上
   （`nat44_ei.c` 的 `nat44_ei_hairpinning_enable`）。
2. `ip4-local`/`ip4-receive` 按 `vnet_buffer (b)->ip.rx_sw_if_index` 启动特性链
   （`ip4_forward.c` 的 `ip4_local_set_next_and_error`）。
3. 这个字段只在 `ip4_local_check_src` 里赋值：先取接收接口，命中 receive DPO 时换成地址所在的接口。
4. 已被 NAT 改写的包（`VNET_BUFFER_F_IS_NATED`）由 `ip4_local_classify` 归为 `IP_LOCAL_PACKET_TYPE_NAT`，
   **跳过**源地址检查，于是字段没有赋值。
5. 这个字段在缓冲区里和分片重组的数据（TCP 序号等）共用内存，残值等于一个随机的接口号，特性链落在不存在的
   接口上，hairpin 节点永远不执行。

影响不只 EI 的 hairpin：任何挂在 `ip4-local` 特性链上的节点，碰到 NAT 过的包都会落空；残值恰好等于某个启用了
别的 `ip4-local` 特性的接口时，还会错误地执行那个特性。

本项目的处理（0039）只改 NAT 插件：EI 的 in2out 给包打 `IS_NATED` 标记时，把 `rx_sw_if_index` 设成 `local0`，
和 EI 注册 hairpin 节点的接口一致。in2out 之后没有节点再读与它共用内存的分片重组数据。

更彻底的修法在 libvnet：`ip4-local` 对 NAT 类型的包也按 `ip4_local_check_src` 的规则给 `rx_sw_if_index` 赋值。
单独这样还不够：hairpin 的目的是外网地址，命中 receive DPO 后字段会是外网接口，而不是 `local0`，所以 EI 还要改成在
outside 接口上注册 hairpin 节点。这要换每台设备的 libvnet，代价大得多，目前不做；如果以后向上游提交，应该按这个
思路改。

## 测试

```sh
sudo python3 tests/integration/integration_nat44_partial_checksum.py --nat ed|ei \
  --plugins <含 nat_plugin.so 或 nat44_ei_plugin.so 的目录> [--vpp /usr/local/bin/vpp] \
  [--system-plugins /usr/local/lib/vpp-router/vpp_plugins] [--mode inout|output|mixed|hairpin]... \
  [--offload on|off]... [--dump]
```

隔离的 VPP，两个带校验和 offload 的 TAP 加一个扮演 Gate 的命名空间。检查：

- in2out（静态映射改端口、MSS 钳制）、out2in 回包、hairpin 的 TCP/UDP；
- ABF 重定向收到的是客户端自己的地址；
- `pcap trace rx tx` 抓到的每个发出包，按它收进来时是不是未完成校验和，判断字段是否正确；
- Linux 校验和 offload 开和关各一遍。

2026-11-26 带 0037–0045：ED、EI 各四种接法、offload 开和关共 16 种组合全部通过；不带这些补丁的插件第一个 SYN
就失败，关掉 offload 后 hairpin 的 TCP 连不上，没有 0041 的 EI 在有 inside 接口时 ABF 检查失败。

在测试机的真实布局上，`loop0` 开 hairpinning：

- Gate 的 DNS 劫持收到的仍是客户端地址；
- 上网、端口转发、hairpin 都正常；普通流量分类节点一个都不送走；
- WireGuard 加桥接出口的多出口实验结果与对照组相同。

吞吐（TRex，64 字节 UDP，8 个源地址 × 1024 个端口）：

- 6 Mpps 以内与只有输出特性时一样，丢包都在 1% 以内；
- 饱和点的差别在两次测量之间约 0.3–0.4 Mpps 的波动范围内；
- 3 Mpps 时每包多约 75 个时钟周期：分类节点 31–35，`loop0` 上的分片重组 41–43。

## 未完成和已知问题

- 只有输出特性、不开 hairpinning 时，VPP 仍然不做 hairpin。因为有上面的开销，hairpinning 做成开关、默认关：
  安装脚本问一次（开时在 `loop0` 上写 `set interface nat44 [ei] hairpinning loop0`），面板接口页按接口开关
  （vpp-interfaces），系统页切换 EI/ED 时这一行跟着改写。
- 分类节点依赖接口上的分片重组；自己解析未分片的 TCP/UDP、只给送往 in2out 的包补字段，每包还能省约 40 个时钟
  周期，代价是要跟着分片重组节点的输出格式走。
- ICMP 和分片不做 hairpin。
- 原来就有、与这些补丁无关：EI 下从 WireGuard 隧道另一端 ping 出口自己的地址没有回应。
