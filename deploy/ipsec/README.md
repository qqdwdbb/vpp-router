# VROUTER：strongSwan 控制面与 VPP ESP 数据面

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

当前已生产部署。`vrouter-strongswan` 使用私有网络与挂载空间，读取 `/etc/vpp/ipsec.conf`；
自定义插件位于 `/usr/local/lib/vpp-vrouter/ipsec-plugins`，通过私有挂载提供给 charon。
VPP 私有库已脱离旧 `/opt` 路径。当前目录规范及迁移验收见
[安装说明](../install/README.md)。下文构建和隔离验证命令保留早期实验记录；旧构建树
现位于 `/usr/local/src/vpp-vrouter/`，重新构建前须按新目录重新配置构建系统。

## 实现与边界

- strongSwan 5.9.8 保留 IKE、认证、地址分配；`kernel-vpp` 下发 SA/SPD。
- `kernel-netlink` 仍提供 Linux 接口/路由发现；必须先加载 `kernel-vpp!`，
  业务 SA 不允许静默回退到 Linux XFRM。
- UDP 500 与 UDP 4500 的 Non-ESP Marker 报文通过控制 TAP 到 charon。
  ESP 及 NAT-T 封装的 ESP 在 VPP 中处理。
- `ipsec cleartext ingress TAP` 设置解密后包的逻辑 RX，然后进入 VPP IP
  输入节点；不把业务明文发给 Linux。该逻辑接口可作为 NAT44-EI inside。
- 回程先进行 IPsec 策略匹配，再进入 EI 输出 NAT，避免重复改写 VPN 流量。
- 后端根据 Linux 接口名查找 VPP 的接口索引，因此控制命名空间中承载服务端
  IKE 地址的 Linux 接口名必须与 VPP 外网接口名一致。控制链路使用独立 transit
  地址，服务端 IKE 地址是 Linux 接口的 /32 别名；这不是把 WAN 网卡交回 Linux。

## 构建

`build/history/build-strongswan.py` 使用配置过的官方 5.9.8 源码头文件，应用现有
VPP 26.06 API 适配补丁及 `strongswan-5.9-vrouter.patch`，从已安装 API JSON 更新
消息 CRC，只编译 IPsec 后端。产物为：

```
/opt/vpp-vrouter-migration/strongswan-build/vpp-sswan-5.9/libstrongswan-kernel-vpp.so
```

5.9 适配恢复 `kernel_vpp_plugin_create()` 入口，并增加
`charon.plugins.kernel-vpp.api_prefix`。它调用 `vl_set_memory_root_path()` 后映射
`/vpe-api`；直接将带前缀的名称传入 `vl_client_api_map()` 会触发该版本 VPP
客户端的重复前缀拼接，等待不存在的共享内存文件。

## 隔离验证

```sh
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py --workers 0 --nat
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py --workers 2 --nat
```

测试建立独立 VPP、IKE 服务端、Linux IPsec 客户端及目标主机。插件目录和
/run 在各自私有 mount namespace 中绑定；连接使用随机临时 PSK，或 `--eap` 生成的临时 CA、服务端证书和 EAP 密码。
各端的 `/etc/ipsec.d` 同样私有绑定，stroke 显式指定临时 secrets 文件，完全
不加载生产连接/凭据。

检查项：

- strongSwan API 客户端连接 VPP，双方 CHILD_SA 安装成功；VPP 有 SA 对。
- 服务端网络命名空间的 Linux XFRM 为空。
- IPv4 和 IPv6 内层 ICMP、两族各 64 KiB 随机 TCP 内容回显。
- 无 NAT 时目标看到原始 VPN IPv4 地址；启用 EI 后看到转换地址；IPv6 源不变。
- `esp4-encrypt`、`esp4-decrypt`、`ipsec-cleartext-input` 的包计数均增加。
- CHILD_SA 换钥成功并继续转发；断开连接后 VPP SA 被删除。
- 测试结束销毁全部测试进程和命名空间。

默认用例是 IPv4 NAT-T，`--outer6` 另行验证 IPv6 外层（见下文）。
结果在服务器 `logs/ipsec-workers*.json`，汇总见
`artifacts/vrouter/ipsec-vpp-20261017.json`；私有失败日志不直接打印 SA/密钥。
VPP 使用复制的可执行文件及其相对目录下的 crypto engines；记录实际 engine 与
handler 选择，不能只凭插件加载推断加密加速。普通 AES-GCM buffer 选择 native，
链式 buffer 的 handler 选择需要单独看输出，不能概括成全部路径都走 native。

## 证书、EAP-MSCHAPv2 与动态双栈池

```sh
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py --workers 0 --nat --eap
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py --workers 2 --nat --eap
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py --workers 0 --eap --bad-password
```

服务端以临时 CA 签发的 RSA 证书认证，客户端使用 EAP-MSCHAPv2；测试核对
服务端 EAP 方法成功及客户端 RSA 认证成功日志，不把配置字段本身当作认证证据。
客户端没有预设隧道地址，以 `%config4,%config6` 请求地址；服务端池为
`10.254.61.100–10.254.61.200` 和 `2001:db8:61::100–2001:db8:61::200`。
检查客户端确实安装各一个池内地址，再以这些地址验证双栈 ICMP/TCP、EI 和换钥。
错误密码用例必须看到服务端明确拒绝，VPP SA 数量保持零。

这证明原有接入功能组合可以使用 VPP 数据面，不表示现有生产证书、真实终端、
地址池重编号及会话迁移已经验证。结果见 `artifacts/vrouter/ipsec-eap-20261017.json`。

## 生产切换前仍需完成

现有生产证书/EAP-MSCHAPv2、动态双栈地址池及 IPv6 PD 重编号需要真实客户端
联测。临时证书/EAP 与双栈动态池已完成隔离验证；实际生产材料和终端仍需接入验收。
PD 同步程序已有池文件更新能力，但不能在没有连接迁移策略的情况下直接重载
生产服务。还需整合实际 WAN 接口/地址、NAT、入口防火墙和启动恢复流程，并在
具备恢复通道时执行生产切换。

本测试证明功能路径，不代表物理网卡吞吐、多连接容量或长期稳定性指标。

## 实际 PD 变更与客户端重连

```sh
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py --workers 0 --nat --eap --pd
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py --workers 2 --nat --eap --pd
```

扩展用例 `integration_vrouter_ipsec_pd.py` 使用真实 DHCPv6-PD Solicit/Request/Renew
报文；WAN 上游同时发送 RA，VPP 原生消费 PD 到 LAN。实际运行 `pd-sync.py`，
以两个 rightsourceip 指令的配置启动隔离 strongSwan，依次验证：

1. 初始前缀分配 `::100–::200`，续租不改写池文件。
2. 旧前缀撤销、新前缀发布后，starter 通过 SIGHUP 更新连接定义；charon PID
   和已有 IKE 会话保持，IPv4 转发继续工作。客户端显式重连后获新 IPv6。
3. PD 全部撤销后移除 IPv6 池及回程路由，保留原 IPv4 池；双栈请求重连可只获
   IPv4，IPv4 TCP 正常，客户端不再保留旧 IPv6 虚拟地址。
4. PD 恢复后重连重新获得双栈地址；每阶段验证 ICMP 和 64 KiB 随机 TCP 内容。

`ipsec_pool_routes=true` 让同一 Publisher 管理池范围的更具体 IPv6 回程路由，
使用当前 WAN 默认网关，并将归属记录保存在 `/run` 的同一状态文件。原始
`::100–::200` 通常对应 `/120` 和 `/128` 两条路由；有 DHCP 租约排除时按剩余
范围拆分。它们覆盖 LAN connected /64，让回包走 WAN SPD 进行加密。池撤销、
网关变化时清理旧路径；VPP API socket 代际改变后重新安装。

`ipsec_reload_command` 是按配置变化触发的参数数组，不是周期重启服务。本用例
针对隔离 starter PID 发送 SIGHUP，并等待真实 charon 状态/日志确认新配置加载。
生产迁移配置目前只启用池路由选项，尚未设置生产重载命令；正式启动集成时必须
将命令指向 VPP 对应的 starter，不能误操作当前 Linux 生产 IPsec 实例。

旧 IPv6 公网前缀被上游撤销后，既有 IPv6 连接不能保证继续使用；验证的保证是
配置更新不主动重启 charon/拆除 IKE，IPv4 继续可用，重连使用新前缀。
结果见 `artifacts/vrouter/ipsec-pd-20261017.json`。生产没有切换。

## IPv6 外层：原生 ESP 与 UDP 封装

```sh
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py --workers 0 --nat --eap --outer6
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py --workers 0 --nat --eap --outer6 --native-esp
# 上述两条分别以 --workers 2 再验证。
```

IPv6 外层端点为隔离测试网段的 `2001:db8:60::1`、`::2`，IKE 控制 TAP 的
IPv6 transit 为 `fd76:7070:3961::/64`。服务端 Linux 在与 VPP WAN 同名的接口
上绑定端点 /128，IPv6 默认路由经控制 TAP 到 VPP。VPP 配置 IPv6 UDP 500
punt 和 IPv6 punt redirect；现有 Non-ESP Marker 插件分离 UDP 4500 的 IKE。

默认强制 UDP 封装；`--native-esp` 关闭 forceencaps，保持 mobike=no，验证
IPv6 next-header 50 的原生 ESP。两种模式均检查：

- VPP SA 标记 tunnel-v6，UDP encapsulation 标记与选择的模式一致。
- 证书/EAP 和动态双栈池正常；隧道内 IPv4/IPv6 ICMP、各 64 KiB 随机 TCP
  内容回显正常；IPv4 经过 EI，IPv6 源地址不变。
- VPP 的 IPv6 ESP 解密、两族加密及明文转发节点计数增加，服务端 Linux
  XFRM 为空；CHILD_SA 换钥以及完整断开后的重连成功，最终 SA 清理。
- 独立透明桥接命名空间的 mgmt0 实际双向报文包含 IPv6 IKE 及所选类型的 ESP；封装模式
  同时看到 UDP 4500 Non-ESP Marker。没有另一种 ESP 类型、IPv4 IPsec 回退
  或测试业务明文泄漏。

`integration_vrouter_ipsec_outer.py` 只在内存统计报文，不保存载荷/密钥；收到
SIGUSR1 时写一次统计快照。抓包点独立于客户端 XFRM：直接在 Linux 客户端抓包
会看到解密后重新注入的明文，不能据此判断线上泄漏。

IPv6 外层用例明确将 TAP/VPP 及桥接链路 MTU 统一为 1500，避免 VPP 默认 9000
产生超过桥接 MTU 的加密包。实际观察到部分 VPP 回程 IPv6 外层分片，客户端
重组后的 TCP 内容校验通过；统计分别记录外层分片数量、最大 L3 长度与超 MTU
包数量，ESP 类型计数针对无 Fragment Header 的包。两种模式均要求线上最大
L3 长度不超过 1500，无明文泄漏和 IPv4 回退。完整 ICMP Packet Too Big、不同
路径 MTU、MSS 优化、扩展头及分片边界仍需后续专门验收。

结果见 `artifacts/vrouter/ipsec-outer6-20261017.json`。这是 VROUTER 上实际 VPP 与 Linux
IPsec 客户端的隔离验证，不代表运营商公网入站、光猫防火墙或真实终端已经验收。
生产 strongSwan、WAN/nic0 没有切换。

## MTU/PMTU/MSS 专项验收（隔离进行中）

```sh
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py \
  --workers 0 --nat --eap --outer6 --pmtu --wan-mtu 1500
# --native-esp 切换为原生 ESP；另测 workers 2 和 --wan-mtu 1280。
```

## 定点诊断结论（2026-10-17）

隔离用例：workers 0、EI NAT、原生 ESP、端点 1500、路由器 `to-client` 出口 1280。

外层 ICMPv6 PTB 原先被 punt 到控制 TAP，LAN 没有内层 ICMP。VPP 26.06 的 SA 没有
PMTU 字段。已在现有 `ipsec_ike_punt` 插件内按 Linux XFRM 语义补上，不改
`ipsec_sa` 布局，也不把 ESP 或明文送到 Linux TAP：

1. `icmp6_register_type(ICMP6_packet_too_big, ipsec-ptb-input)`，解析引用的外层
   IPv6 与 ESP SPI（含 NAT-T UDP/4500）。匹配 outbound SPI 后记下广告外层 MTU。
2. `ipsec4/6-output-feature` 在 protect 后进入 `ipsec4/6-pmtu-check`；若
   `inner + ESP overhead > sa_pmtu`，发内层 ICMPv4 type 3 code 4 或 ICMPv6 PTB
   并丢弃该报文。GCM 不能从外层 PTB 恢复内层五元组，所以必须等下一包。
3. 内层 ICMP 经 `ip4/ip6-icmp-error` → lookup 回到 LAN，不经过 IKE 控制 TAP。

隔离复验（workers 0、EI NAT、原生 ESP、路由 1280）：LAN IPv6 `-s 1300 -M do`
首包触发外层 PTB 1280，随后两包 LAN 收到 `From 2001:db8:62::1 Packet too big:
mtu=1206`（AES-GCM16 未分片内层上限）。控制 TAP 无 PTB；`fate=inner-icmp`，
`associated_with_sa=true`。`-M do` 仍不能在内层 IPv6 最小 MTU 1280 以下收敛，
这不是黑洞。

NAT-T 与 workers 2 已在同一插件上复跑：workers 2 原生 LAN IPv6 内层 PTB
1206，workers 2 / workers 0 NAT-T 为 1198；`ptb_blackhole_observed=false`。

IPv4 内层 fragmentation-needed：客户端大包在 XFRM 上 ENOBUFS；对 EI outside
`10.254.62.1` 的 ping 是 VPP 本机应答。映射后的 LAN DF UDP 1200 命中
`ipsec4-pmtu-check`。`ipsec-pmtu-save-dst` 在 `nat44-ei-out2in` 之前保存原始
dest，加密前还原 quoted 五元组；未改 NAT 插件。它只在启用了 EI out2in
（含 handoff 和 classify）的接口上开启，随 NAT 接口增删自动跟随；其他接口上的包不经过它。LAN 抓到 type 3 code 4
（mtu=1206，quoted dest `10.254.62.1:mapped_port`），发送端 EMSGSIZE。证据见
`artifacts/vrouter/ipsec-pmtu-acceptance-20261017.json`。不能用夹 MSS 宣称完整
PMTU 验收。

IPv4 TCP 曾因 `nat44-ei-out2in` 跳到 `ip4-lookup` 而跳过
`tcp-mss-clamping-ip4-in`。已在 `ipsec_ike_punt` 的 ip4-unicast 上约束
clamp-in 先于 NAT；未改 NAT 插件。路由 1280 未 clamp 时双栈 TCP 仍失败：
IPv6 内层 PTB 为 1206/1198，低于 IPv6 最小 MTU 1280；IPv4 客户端大包 ENOBUFS，
VPP 映射回程会发内层 ICMPv4，LAN 已观察到 type 3 code 4 / EMSGSIZE。隔离 TAP 上夹 MSS 后
两族 256 KiB 均恢复（原生 1166/1146，NAT-T 1158/1138）。这些值只用于隔离对照。
矩阵见 `artifacts/vrouter/ipsec-pmtu-acceptance-20261017.json`。

定位 PTB 与 IPv4 TCP 实际丢包节点时，先跑定点诊断，不要把夹 MSS 当作完整修复：

```sh
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py \
  --workers 0 --nat --eap --outer6 --native-esp --pmtu --wan-mtu 1500 --diagnose
```

该选项在路由 1280 瓶颈上记录外层 ICMPv6 PTB 的 VPP 节点路径（丢弃 / punt 到控制 TAP / 是否关联 SA）、LAN 与控制 TAP 上的内层 ICMP，以及同一连接中 SYN/SYN-ACK 经过 MSS clamp、NAT、IPsec 的 MSS、校验和与节点计数。当前测试 MSS 值只用于隔离对照。

`--pmtu` 在原有隔离生命周期内增加双向 IPv4 DF/IPv6 边界探测，记录请求的
内层 L3 长度、预期未分片外层长度、线上长度分布和首片/非首片。抓包按 IP
头中的长度统计，不计二层填充；支持遍历 Hop-by-Hop、Routing、Destination、
AH 与 Fragment Header。独立 LAN 抓包只记录 TCP SYN/SYN-ACK 的 MSS，不保存载荷。
TCP 随机内容扩展至每族 256 KiB，记录两端 TCP_INFO 的累计重传及有效 MSS。

AES-128-GCM16 的未分片 IPv6 外层长度为
`72 + (NAT-T ? 8 : 0) + roundup(inner_l3_bytes + 2, 4)`。对应理论边界：

| 外层 MTU | 原生 ESP 最大内层 L3 | NAT-T 最大内层 L3 |
| --- | --- | --- |
| 1500 | 1426 | 1418 |
| 1280 | 1206 | 1198 |

这些是未分片边界，不是已经批准的生产接口 MTU。尤其 IPv6 内层最小 MTU 为
1280，不能直接将 1198/1206 配成 IPv6 接口 MTU，也不能把可重组的外层分片
当作 PMTU 收敛。

1500 用例还将测试桥临时改为 IPv6 路由器：端点接口仍为 1500，路由器的 `to-client` 出口
降为 1280（反向出口仍为 1500），先做小包对照，再观察 PTB 与重复大包。抓包点 mgmt0 位于 VPP 与
路由器之间，因此可以看到进入路由器、尚未经过其 1280 出口的大包；此阶段
mgmt0 的 1500 字节输入不属于 1280 出口超限证据。仅在测试 namespace 内调整
转发、邻居与路由；不使用生产接口或生产 strongSwan。

专项结果独立标记 `acceptance`，脚本正常退出只表示隔离用例和清理完成，
不表示全部 PMTU 验收通过。只有未 clamp 的路径 TCP 失败、而同一路径的小包
对照成功时，测试才临时启用 VPP 现有 `mss_clamp_plugin`，在隔离 LAN
`tap3962` 上双向夹 MSS 后复验两族 256 KiB 内容，随即关闭 clamp；这不会改写
生产配置。不得只引用未分片边界作为生产参数。

2026-10-17 插件复验：**隔离内层 ICMP 路径已通，整体验收仍为 incomplete**。

- workers 2 原生、workers 2 NAT-T、workers 0 NAT-T 路由 1280：LAN IPv6 内层
  PTB 1206/1198，`ptb_blackhole_observed=false`。
- 映射后的 LAN DF UDP 1200：`ipsec4-pmtu-check` 发出内层 ICMPv4；LAN 没有
  EMSGSIZE。客户端大包仍是 XFRM ENOBUFS。
- 未 clamp 双栈 TCP 失败；隔离 clamp 恢复两族。IPv6 不能 PMTUD 到 1206/1198。
- Hop-by-hop PadN 已记录；主动外层扩展头/分片注入结果见下节。
- 没有批准生产 MTU/MSS。生产 charon PID 1941，nic0 UP/r8125。不进入生产切换。


## 外层扩展头/分片注入（2026-10-17）

```sh
python3 /opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec.py \
  --workers 0 --nat --eap --outer6 --outer-injection --wan-mtu 1500
# --native-esp 切换为原生 ESP；另外覆盖 workers 2 与 MTU 1280。
# 与 --pmtu / --diagnose 分开运行；不重跑已通过的 TCP/rekey 验收。
```

测试仅在隔离 wire namespace 安装 bridge nft 表 `vrouter_ipsec_inject`，拦下原始
客户端到服务端 ESP。AF_PACKET 在 forward 丢弃前取得临时密文，只修改 IPv6
外层，不改变 ESP/UDP 字节；每个序列只注入一次。正例采用真实内层 IPv6 echo，
包括 Hop-by-Hop PadN、Destination PadN、两者组合、原子分片、MTU 边界分片、
非首片先到和 8 字节首片。反例为单独非首片、8 字节重叠和非 /8 首片长度。
不落盘密文，不读取或输出 SA 密钥，结束时删除 nft 表、停止注入进程。

另用当前临时 SA 的 SPI 构造外层 ICMPv6 PTB quote，分别检查普通 ESP/NAT-T、
扩展头链、首片/原子分片，以及非首片伪 SPI、截断扩展头/SPI、声明长度过短、
Non-ESP Marker。quote 关联和真实扩展头数据交付是独立的验收项。

为修复已复现的 quote 边界问题，插件使用 `ipsec_ptb_quote.h` 中的有界解析器，
按实际可用长度与 quoted IPv6 声明长度的较小值读取，最多遍历 16 层，非首片
不读取 SPI。保持原来的 outbound SPI 关联、PMTU 表、quoted-destination 还原
及内层 ICMP 路径；不改 NAT 插件。C 解析器由本地编译测试直接覆盖。

八组合结果：88 项 quote 检查通过；实际数据的分片正例和畸形片反例通过，
注入后普通流量正常。三类实际扩展头报文仍未交付：Hop-by-Hop 已见
`ip6-local-hop-by-hop` Unknown protocol；Destination 的具体失败节点还需定位。
因此本阶段仍未通过，不能将 quote 检查通过或脚本退出 0 当作完整验收。

结果见 `artifacts/vrouter/ipsec-outer-injection-20261017.json`。扩展头收包修复及专项
复验已按用户要求暂缓；本轮主动改写仅为客户端到 VPP，其他方向、Routing/AH
等类型不在当前真实数据交付覆盖内。隔离 clamp 仍是缓解，IPv6 不能靠 PMTUD
收敛至 1206/1198，生产 MTU/MSS 未批准。


本轮新插件还通过 workers 2 NAT-T PMTU 回归：映射后的 LAN DF UDP 收到
正确 quoted outside destination 的 type 3/code 4，发送端 EMSGSIZE；隔离 clamp
后两族 256 KiB 内容校验通过。25 项本地 IPsec 测试通过。清理核查无测试
namespace/VPP、实验目录、共享内存或 nft 规则残留，大页 0；生产 strongSwan
active、charon PID 1941，nic0 UP/r8125。


## 当前推进范围（2026-10-17）

按用户明确要求，先跳过人工外层扩展头、畸形分片及人为低 MTU 等特殊场景，
不再将这些专项的修复或复验作为下一阶段前置条件。已有失败与边界记录保留，
暂缓不代表专项验收通过，隔离 clamp 仍只是缓解，生产 MTU/MSS 未批准。

下一步以真实客户端、当前接入配置和实际公网路径的隔离联测为主；只有现场
实际遇到相关问题时才针对性处理。生产 strongSwan 和 nic0 继续保持原状。


## 真实客户端公网接入（2026-10-17）

用户已明确允许联测期间停止当前 Linux IKEv2。新增 `real-client-lab.py` 和
`clear-ike-conntrack.c`，保留原域名与认证配置，凭据只读挂载不复制。仅在
原 WAN 地址 UDP 500/4500 上临时 DNAT 到私有 VPP/charon；nic0 不重配，
Linux 继续提供物理上游路由/NAT。运行与自动恢复见
[真实客户端联测说明](real-client-lab.README.md)。

已完成短时接管/恢复演练，当前 30 分钟窗口观察到真实 `cert` 认证、IKE/CHILD、
VPP 两条 SA 和 ESP 业务转发；服务端 Linux XFRM 为空。用户已确认 cert 网页/DNS/IPv6 公网 `::100` 正常；EAP
认证及上网已由用户确认正常；分配地址变化与既有策略路由导致出口变化，
后续用户明确 EAP IPv4 应经 10.61.50.1，已移除实验 VPP 提前 SNAT，
使原有源地址策略可匹配；用户重连复验确认出口与上网正常。EAP IPv6 已确认符合预期，
IPv6 公网外层尚需单独核对。特殊场景仍暂缓，生产 MTU/MSS 未批准。窗口过期
后以服务器 state/status 为准，不把本文的就绪记录当作持续运行承诺。

IPv6 外层后续已完成真实 Android 复验：固定私有 namespace 的控制下一跳
IPv6 邻居后，IKE 初始响应可经 VPP/Linux 到达 WAN；选用独立 ESP 校验和
修复库、无 tc 补偿时，用户确认 VPN/DNS/网页正常。见
`../../../patches/history/README-ipsec-ip6-udp.md` 和
`artifacts/vrouter/ipsec-ike-response-path-20261017.json`。当时未安装永久生产库，
后续现场生产部署见下节。

## 现场 IPv6 NAT-T 回程修复记录（2026-10-24）

真实 Android/证书客户端通过 IPv6 建立 CHILD_SA 后，现场 WAN 抓包确认服务端
回程 IPv6 UDP/4500 ESP 的 UDP checksum 为零，导致网页和测速异常；客户端到
服务端的入站 checksum 正常。最终根因是 ESP 加密完成后的校验和修复使用了
错误的 VPP buffer 偏移基准。修复必须使用 `b->data + l3/l4_hdr_offset`，并在
软件计算后清除 UDP checksum offload 标志；不能用临时 tc 规则或全局关闭网卡
offload 代替。

最终补丁为 `docs/history/patches/ipsec-ip6-udp-family-flags.patch`，生产库 SHA256：
`f88c49facf7f665ce9bc3767dfb523667d60bada29ab4b58a74c9e069fb64cc9`。重启
`vrouter-vpp.service` 后重连证书客户端，IPv6 inbound/outbound SA 计数增长，用户
确认连续测速正常。

本次另行恢复了 LAN `tap2000/vpp-lan` 的 GSO：VPP `gso-enabled=1`，Linux
仅开启 GSO/GRO，TX checksum offload 与 TSO 保持关闭。IPsec 专用 `tap4061`
保持 VPP GSO/CSUM 关闭；WAN DPDK checksum 路径和全局网卡 offload 不作改动。
现场有效 MTU/PMTU 值及备份路径见根目录 `docs/internal/HANDOFF.md` 的
2026-10-24 章节。
