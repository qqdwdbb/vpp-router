# PPPoE 客户端插件（pppoeclient）

VPP 的 PPPoE 拨号客户端：RFC 2516 发现阶段（PADI/PADO/PADR/PADS/PADT）、会话数据面、
LCP/PAP/CHAP-MD5/IPCP/IPv6CP（移植自 pppd），每个客户端一个点对点的 PPPoX 接口，拨通后
得到 IPv4 地址、默认路由和对端 DNS，发出的 TCP SYN 自动修正 MSS。控制报文交给主线程处理，
会话数据在 worker 上转发。

## 来源

取自 [Hi-Jiajun/vpp-pppoeclient](https://github.com/Hi-Jiajun/vpp-pppoeclient) 的 `master` 分支
26c69c6（2026-11-17），即作者 VPP 分支 `feat/pr-pppoeclient` 上的提交 b1fa142b0
（`src/plugins/pppoeclient`）。`LICENSE`、`NOTICE`、`THIRD_PARTY_LICENSES.md` 取自该仓库的
`main` 分支，分发源码或二进制时要一起带上：插件本身是 Apache-2.0，`pppox/pppd/` 下从 pppd
移植的文件保留各自的 BSD 类许可，见 `THIRD_PARTY_LICENSES.md` 和各文件头。`PROVENANCE.md`、
`FEATURE.yaml` 是原样的上游文件。

作者分支上另外两个改动：`interface.c` 改名保护在本仓库是 VPP 补丁
[0051](../../patches/vpp/0051-interface-rename-no-output-class.patch)；dhcp 插件导出 DHCPv6
运行状态（FD.io master 的 0a143dac6 加 098921fc6，改了 dhcp 插件 475 行，只用于
`show pppoe client detail` 的 DHCPv6 一节）没有移植，见下文。

## 本仓库的修改

都标了 `vpp-router:` 注释。

移植到 VPP 26.06：

- 控制报文交给主线程的队列：上游用 VPP master 的 `vlib_handoff_alloc_queues`（`vlib/handoff.h`，
  26.06 没有），改成 26.06 的 `vlib_frame_queue_main_init`，`vlib_buffer_enqueue_to_thread`
  加上 26.06 的 `drop_on_congestion` 参数（拥塞时两个版本都释放报文）。
- `dhcp6_runtime_compat.h`：DHCPv6 运行状态的结构体（照抄 0a143dac6）。26.06 的
  dhcp_plugin.so 没有这些函数，`vlib_get_plugin_symbol` 找不到，详情里 DHCPv6 一节显示
  `<unavailable>`；拨号、IPv6CP 和 DHCPv6-PD 本身不受影响。

在本仓库实测（rp-pppoe 服务器）发现并修正的问题：

- LCP 请求对端认证自己：`lcp_init` 在想要的选项里设了 `neg_upap`，Configure-Request 带
  `<auth pap>`。拒绝这个选项的 BRAS 没事，pppd 做服务器时会接受，随后以 “PAP server mode not
  supported” 断开。客户端不需要对端认证，去掉。
- 经输出特性的报文被丢弃：PPPoX 接口只设了 `hi->output_node_index`，没有设
  `output_node_next_index`。ip4-rewrite 直接送到会话输出节点的报文正常，经过输出特性
  （NAT44 output-feature、MSS clamping）再到 interface-output 的报文去了 `local0-output`。
  改用 `vnet_set_interface_output_node`，局域网经 NAT 上网才通。
- 没算完的校验和：从 Linux TAP、host stack 来的 TCP/UDP 报文可能只带伪首部校验和，等网卡补全。
  封装成 PPPoE 后不能指望网卡还找得到 TCP/UDP 头，MSS 修正的增量更新也只对完整校验和才对。
  会话输出节点在封装前先算完（`vnet_calc_checksums_inline`），和 VPP 自带的隧道封装一样。
- VPP 重启后旧会话留在 BRAS 上：会话文件（`/run/vpp/pppoeclient-*.session`，VPP 重启后还在）
  原本只在退出时用来经 Linux 网卡发原始 PADT，而且不管发没发都删掉。DPDK 网卡没有 Linux 网卡，
  旧会话一直留到 BRAS 自己超时，限制单会话的账号在这期间认证被拒。现在退出时发不了就保留文件，
  下次建客户端时读出旧会话，先经 VPP 发 PADT，等 2 秒再开始 PADI。安装器固定了 WAN 的 MAC，
  所以 PADT 的源 MAC 和旧会话相同。

## 用法

安装器在 WAN 方式里选 “PPPoE 拨号”，`/etc/vpp/router.vpp` 里生成：

```
create pppoe client port0.100 host-uniq 1 name pppoe0 username 账号 password 密码 use-peer-dns add-default-route4
nat44 ei add interface address pppoe0
set interface nat44 ei out pppoe0 output-feature
```

`router.vpp` 因此只给 root 读（0600）。面板“接口”页的“新建其他接口”可以选 PPPoE 拨号，
编辑 pppoeN 可以看拨号状态、改账号密码。插件总是加载，没有客户端时只有一个不运行的 process
节点（主堆多约 2 MB）。

常用命令：

```
show pppoe client                  # 各客户端的状态、会话号
show pppoe client debug pppoe0     # 重拨次数、上次断开原因、认证失败次数、LCP/IPCP 状态
show pppoe client detail           # 地址、对端 DNS、IPv6CP 链路本地地址
pppoe client restart pppoe0        # 重新拨号
set pppoe client pppoe0 username 账号 password 密码
```

账号和密码由 CLI 按空白分词读取，不能含空格。名字（`name`）要写：插件默认的 pppoxN 按创建
顺序编号，删掉再建会和配置文件对不上。

## 实测

2026-11-28 在 x86 测试机上，VPP 26.06（本仓库补丁 0001–0051，不含 0049）的临时实例经 AF_PACKET
接一对 veth，对端是命名空间里的 rp-pppoe 3.15 + pppd（CHAP）：

- 发现、CHAP、IPCP（地址、对端 DNS）、IPv6CP（链路本地地址双向 ping 通），默认路由经 pppoe0。
- 局域网主机经 NAT44-EI 出 pppoe0：ping，50 MB 下载、20 MB 上传逐字节一致，SYN 的 MSS 改成 1452。
  无 worker 和 1 个 worker（控制报文交给主线程）两种都测了。
- 服务器端结束会话（杀掉 pppd）后约 31 秒重拨成功（插件的默认冷却 35 秒，防止 BRAS 来不及释放）。
- 密码错误：记为 `auth-fail`，按退避重试，不会连续猛拨；改回密码后恢复。
- 重启 VPP：新实例先给旧会话发 PADT（服务器上旧会话的 pppd 随即退出），再拨新会话。
- 面板：新建、改账号（含 60 秒回滚）、删除前的检查，密码不出现在页面数据和日志里。

没有测过：真实 BRAS、VLAN/QinQ 上的拨号、DHCPv6-PD 经 PPPoE（需要能分配前缀的 DHCPv6 服务器）、
DPDK 网卡上的吞吐。PPPoX 接口还不能作为 Gate 的出口（Gate 写路由要下一跳），默认路由走它不受影响。
