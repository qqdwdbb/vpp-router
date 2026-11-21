# VROUTER 分阶段迁移与隔离验证

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。
部署时使用渲染后的设备配置。参见[部署说明](../docs/deployment.md)。

本目录的隔离测试只绑定测试口 nic1。运行前通过设备配置核对生产口与测试口的 PCI BDF。

## 测试环境

服务器新增文件隔离在 `/opt/vpp-vrouter-migration/`；原构建树为
`/opt/vpp-nic1-test/`。生产配置备份保留在服务器 root 私有目录
`/root/vpp-vrouter-backup/<backup-id>`，包含凭据，不复制到项目。

`nic1-smoke.py` 要求对端以静态地址连接 nic1，通过 `--peer-ip` 指定对端静态地址。
驱动重新绑定会中断链路；依赖生产 dnsmasq 的 DHCP 地址可能丢失，使 ping
测试失去意义。脚本临时使用 `.250` 及 `.160`–`.239`，只用于独立测试链路。

脚本验证物理 ping、不同目标地址的 RX 队列分布，以及 TAP 命名空间经过
物理口的 NAT44-EI ICMP 回程。任何失败均保留日志并停止 VPP，再恢复 nic1
驱动、MAC、MTU、桥成员、管理状态和大页预留。恢复程序发现 UIO 仍被进程
占用时拒绝解绑。`--restore` 可重新执行未完成的恢复。

服务器用临时 systemd oneshot 单元运行测试，`TimeoutStartSec=180`，
`KillMode=control-group`，`ExecStopPost` 执行恢复。该单元不启用开机启动。
不能通过 SSH 前台裸跑代替超时及断线恢复保护。

## 2026-10-16 验证结果

- ARM64 的 NAT44-EI、WireGuard、ACL、DHCP、MSS、ping、TAP 与自定义插件已构建。
- native/OpenSSL 加密引擎产物已保存；尚未据此验证真实加密隧道。
- 当前 6.1.57 内核没有 `CONFIG_VHOST_NET`。已用其头文件和符号版本构建
  `source/vhost/vhost_net.ko`，先加载 `tap`、`vhost` 后可加载，产生
  `/dev/vhost-net`。未替换内核，也未配置该模块开机加载。
- 隔离的单主线程双出口 EI 集成测试通过 UDP 端点独立映射、地址池隔离、
  TCP 和 ICMP 回程。
- `integration_nat44_ei.py --workers 2` 原先在 UDP 阶段失败；2026-10-17 已修复
  入站 handoff 顺序，并通过两个 worker 各自持有会话的 UDP/TCP/ICMP 检查。
  此选项固定主线程 CPU4、worker CPU5–6，供 VROUTER 验证使用。
- nic1 初始化可显示 4 RX / 2 TX，链路 2.5G；启用缓存同步实验后，单主线程
  已通过四 RX 队列实包、双向 ping 和物理 EI NAT，具体 RTT 见下文。
  这不等于吞吐或长期稳定性已验证。
- 修复前用户报告偶发回复 RTT 为 1–9 秒，因此先前收发不能视为质量通过。
  不再把主动 ping 失败归因于电脑防火墙：启用下述缓存同步后，同一电脑
  立即能回复 VPP 主动 ping。
- 每次隔离测试后 nic1 恢复 r8125/lan；nic0 保持原生产驱动。
- mgmt0 未接线。用户可使用本机终端，但独立远程管理通道未验证。

## 生产迁移前仍需完成

1. 按真实转发负载评估吞吐、CPU 和功能边界；用户已停止低速长测，不再把
   百万分之几的偶发超时作为硬门槛。
2. 双 worker 功能及 nic1 四 RX/两 TX 已完成短时验证；后续仍需实际吞吐验证。
3. nic1 上 VLAN 100 三层、VLAN 10 二层、LAN BD/BVI 与管理 TAP SSH 已通过。
   生产形态 VLAN 10 桥见 `vps-bridge/`：VPP `.10` pop 1 ↔ TAP `vrouter-vps`，
   BVI `loop10` 为 `10.61.50.3` / `fd42:1111:2222:20::3`，nftset
   `vpn`/`vpn6` 经该 BVI 指向 br0 网关 `.1` / `::1`。Linux `br0` 只留 TAP
   + Nebula gretap `tap0`。隔离测试不绑 nic0。
   nic0 的所有 VLAN 必须一起迁移，不能部分交给 Linux，也不能形成双口桥接环路。
4. 明确并验证 Nebula/GRETAP、sg 等出口的 NAT 和回程；Linux TUN 需要保留
   对应转发通道，不能一律关闭 Linux forwarding。
5. 完成 Linux DNS `.2` 经 TAP 的生产启动及 IPv6 路径、TPROXY、动态
   nftset 路由恢复、DHCPv6-PD、远程 VPN 地址池及 strongSwan ARM 后端验证。
6. 在控制台验证可执行的生产回滚。先停止 VPP 并确认释放 UIO，再解绑驱动；
   恢复完整 Linux 地址、VLAN、桥、路由和服务。现有 `restore-nic0.sh` 未经
   此流程演练，不能直接作为切换保障。

轮询模式先验证正确性与吞吐。RX 中断需要 PMD、UIO 及 VPP 注册能力共同支持，
不能仅通过 CLI 切换来视为已实现。

## 2026-10-17 WireGuard 配置预迁移

新增 `render-wireguard.py`，复用项目解析器，仅生成原生 VPP 接口、peer、
服务端 peer 主机路由。它不执行 PostUp、修改 Linux 隧道、安装 NAT 或默认路由，
也不调用依赖旧服务器接口名称的安装器。输出拒绝覆盖，文件权限 0600。
实际密钥仅在 VROUTER `/opt/vpp-vrouter-migration/private-wireguard/`（0700）中保存。
当前外层 src `192.0.2.250` 为隔离验证值，不是生产配置。

`check-wireguard.py --interface wg0|sg` 在无物理网卡的独立 VPP 中逐条加载，
核对接口 up 和 peer 数量，结束后停止实例并删除临时运行目录。实机结果：

- `wg0.conf` → VPP `wg0`：28 个 peer，IPv4/IPv6 配置加载通过。
- `sg.conf` → VPP `wg8`：4 个 peer，IPv4/IPv6 配置加载通过。
- 原插件同时加载失败：sg 第 4 个 peer 与 wg0 共用公钥。现已通过
  `docs/history/patches/wireguard-interface-peer.patch` 修复跨接口查重与握手查找，重新编译
  整个插件并部署到迁移目录。wg0 的 28 个和 wg8 的 4 个 peer 同时加载通过。
  同接口重复公钥仍拒绝，原插件保存在 baseline 目录。
- `wg1.conf` 的原 endpoint 为 `127.0.0.1:44441`，Linux gost 确实在此监听。
  已准备专用 TAP（VPP 10.63.50.1、Linux .2）和精确回环 DNAT 配置，
  服务器私有 wg1 文件以 .1 为外层 src、.2:44441 为 endpoint。生成器不会
  自动猜测地址；显式指定后不更改原 /etc/wireguard/wg1.conf 或 gost。

日志在服务器 `logs/wireguard-config-check-all.json`。
最新检查包含 wg0（28）、wg1（1）、wg8/sg（4），共 33 个 peer 同时加载通过。
临时密钥的隔离集成测试已在单主线程及双 worker 下验证真实握手、加密
IPv4/IPv6 ping、同接口重复拒绝、删除/重建 peer，以及缺失 peer 时不能
误用其他接口同公钥 peer；同时覆盖本机密钥相同/不同两种情况。
详见 `docs/history/patches/README-wireguard-interface-peer.md` 和
`logs/wireguard-interface-peer-workers0.json`、`workers2.json`。
尚未验证真实生产客户端的握手、NAT 或吞吐；Linux wg0/wg1/sg 继续运行，
生产 nic0 未切换。

### wg1 回环代理接入验证

`tests/integration/integration_wireguard_loopback_proxy.py --workers 0|2` 使用临时密钥、
root TAP、精确 DNAT、仅监听回环的 UDP 转发器和临时 Linux WireGuard 服务端。
单主线程及双 worker 均通过真实握手、双向 IPv4/IPv6 加密 ping（各 5/5），
同时核对 DNAT 和转发器双向计数。未接入真实 gost/上游，避免同一生产密钥
引发远端 endpoint 漫游。临时接口、nft 表和 VPP 已清理。

生产接入准备文件及切换顺序见 `wg-proxy/README.md`。只在新建专用 TAP 上
启用 route_localnet，不在 WAN/LAN 或 all/default 上启用；conntrack 处理
回包反向转换，不需要增加 UDP 转发守护进程。正式切换还需集成该 TAP/nft
启动顺序、wg1 的 EI 出口/目的路由/回程及回滚，尚未替换 Linux wg1。

### wg1 EI/目的分流与回程

在回环代理测试上增加 `--nat-egress`，通过真实 WireGuard 加密路径验证普通
WAN/context 0 和 wg1/context 101；两个内网源以相同 UDP 源端口访问两个
出口，各自使用独立地址池，同出口更换目的地址保持 EI 映射。两个源的 ICMP
回程、64 KiB TCP 数据校验通过；VPN 对端捕获的明文 SYN MSS 均为 1240。
临时阻断 VPN 外层后，VPN 请求超时、WAN 继续通信；解除阻断后原源端口恢复。
双 worker 验证要求 thread 1、2 均持有 NAT 会话。

实现复用回环代理测试，新增 `tests/integration/integration_wireguard_nat_egress.py`，
不调用生产密钥或真实目标。日志为 `logs/wireguard-nat-egress-workers0.json`
和 `workers2.json`。每轮使用新的 VPP 外层 UDP 源端口，要求新 DNAT 规则
命中，避免前一轮残留 conntrack 条目让新规则的验证失去意义。

已准备 `wg-proxy/wg1-egress.vpp.conf`，含当前 10.62.30.2 的 EI pool、
context 101、MSS 1240 和设备配置指定的目的路由。`check-wireguard.py --interface all --egress-config FILE`
已在隔离 VPP 中验证实际 33 个 peer 与该片段同时加载，目的路由解析到 wg1。
配置仅部署在迁移目录，尚未启用生产路由；生产 WAN 接口/地址池、Linux
控制面回程、启动集成及整体回滚仍需按最终拓扑完成。

### DNS/nftset Binary API 分流准备

已将同版本官方 `vpp_papi` 隔离复制到 `runtime/python`，复用项目 DNS gate
与事件同步程序，未增加 CLI 提交兼容路径。VROUTER 配置只启用 altroute→wg1，
其他出口不自动推断。准备文件见 `dns-route-gate/README.md`。

`tests/integration/integration_vrouter_dns_route_gate.py` 使用真实 dnsmasq、临时 nft 表、
独立 VPP systemd 单元、实际 gate 主进程和 Binary API，验证 UDP 应答屏障、
TCP DNS、未匹配域名不装路由、直接 nft 事件、monitor 断线恢复、受控重建
WireGuard 接口后的新索引恢复、VPP 重启恢复、路由失败 SERVFAIL，以及
内存账本只在正常停止时保存。未检查 WireGuard 握手或修改生产 DNS。

Linux 管理地址 .2 的 gate 配置、专用 nft 规则、API 环境和 service drop-in
仅保存在迁移目录。用户已选择直接公布 Linux DNS .2，网关 .1 不提供 DNS。
IPv6 DNS、br-mgmt 地址和服务启动依赖仍待整体集成；不能仅部署此目录就
视为客户端 DNS 已迁移。二层 DHCP/DNS 验证及准备文件见 `lan-services/README.md`。

### VPP 网关与 Linux 二层 TAP DHCP/DNS

示例中网关 10.61.20.1 位于 VPP、DNS 10.61.20.2 位于 Linux。
`lan-services/` 提供 BVI/桥/TAP 与 IPv4 dnsmasq 配置示例；Linux TAP 加入
br-mgmt，.2 地址只放在 bridge 上，DHCP 广播由 VPP 二层桥传递。
原 DHCP 池含 .2，准备配置将其排除，保留 .3–.254 和 6h 租期，显式下发
option 3=.1、option 6=.2。生产文件尚未修改。

`tests/integration/integration_vrouter_lan_services.py --workers 0|2` 与原始 DHCP 探针
`benchmarks/vrouter_dhcp_client.py` 验证 DORA、内核 UDP 单播续租、桥接口 DNS 重定向、
UDP/TCP 应答屏障与 Binary API 路由，以及客户端的网关 ICMP 和 WAN EI TCP
回程。停止 gate 后仍保留重定向，DNS 不能绕过 gate 访问 dnsmasq。
所有地址使用隔离的 198.18.44/45 测试网段，未向物理 LAN 广播 DHCP。

日志为 `logs/lan-services-workers0.json`、`workers2.json`。不用网关 .1 的 DNS
转送或 ABF，未安装额外前端插件。生产 nic0 切换、持久网络配置、IPv6/PD
与整体回滚仍需后续完成。

## 物理口测试边界

非一致性 DMA 缓存同步实验未形成稳定性结论，已从生产启动、安装和 cutover
路径移除。历史失败结果仍保留在 `artifacts/vrouter/nic1-dma-soak-20261016-failed.json`
和 `artifacts/vrouter/nic1-dma-diagnostic-20261017.json`，仅作审计记录；当前
`nic1-smoke.py` 使用标准 DPDK PMD，不再替换 PMD 或设置实验环境变量。

物理口、多队列、VLAN 和 TAP/NAT 的短时功能验证仍属于隔离测试，不代表
生产 `nic0` 已切换或证明长期稳定性。生产迁移须继续使用现有回滚与恢复流程。

## 2026-10-17 后续功能迁移

本轮不重启低速稳定性测试，只做有明确目标的短时功能检查。

### 双 worker EI 回程修复

`docs/history/patches/nat44-ei-handoff-reassembly-order.patch` 为 VPP 26.06 的两个入站
handoff feature 增加 `runs_after ip4-sv-reassembly-feature`。修复前已有合法
NAT 会话，但回包轨迹跳过端口解析，报 `no translation`；修复后能命中同一会话。
通过复制源码和记录的 Ninja 命令只重编 NAT 插件，未改原 VPP 构建/安装文件。

已部署到 `/opt/vpp-vrouter-migration/plugins/nat44_ei_plugin.so`，SHA256：
`2ef9f9f8b4f04e7064e7fa22a6128b91ba0cf4720ee494123db15220b652ac22`。
旧插件保存在 `baseline/nat44_ei_plugin-before-handoff.so`。

`integration_nat44_ei.py` 用 `.2`、`.3` 两个源地址，让两个 worker 分别持有
会话，检查双出口池选择、同源端点独立映射、UDP/TCP/ICMP 回程；另做单主线程
回归。相同邻居预热下，旧插件仍报 `no translation`，新插件通过。LAN 邻居
预热单独处理，避免异步 ARP 学习导致一次性 UDP RPC 的首包命中 glean。
纯 TAP fixture 使用 4 KiB buffer 页，不改变服务器大页预留。

物理口检查日志：`/opt/vpp-vrouter-migration/logs/nic1-workers2-<run-id>`。
四条 RX 队列均有实包；两条 TX 队列映射到 main/两个 worker；两个 worker
分别持有 4、2 条 NAT 会话，两个命名空间源地址经 EI/nic1 的回程均 5/5 成功，
预热后 RTT 约 0.4–1 ms。这里没有测吞吐或宣称长期稳定性。

### VLAN、BD/BVI 与实际 SSH

日志：`/opt/vpp-vrouter-migration/logs/nic1-workers2-<run-id>`。
`nic1-smoke.py --workers 2 --rx-queues 4 --vlan-management-seconds 180`
创建一个有超时保护的交互检查窗口，通过 `management-done` 提前正常结束。

- VLAN 100：`dot1q 100 exact-match`，VPP `.250` ↔ 对端 `.134`，测试网段
  `192.0.2.0/24`，5/5 成功。三层子接口必须声明 `exact-match`。
- VLAN 10：`dot1q 10 exact-match` ↔ BD3210 ↔ TAP/命名空间；入站 pop 1，
  出站反向加标签。测试网段 `198.18.10.0/24`，5/5 成功，RTT 约 0.3–0.7 ms。
- 未打标 LAN：nic1 ↔ BD3200 ↔ BVI `10.61.40.1`，管理 TAP 的 Linux 地址
  为 `10.61.40.2`。对端 `.134` 与管理 TAP 5/5 成功。
- 从独立对端登录管理 TAP，核对 SSH 回程使用管理接口和该接口的源地址。
  登录结果保存在 `ssh-validation.json`。

对端的 NetworkManager 会在网卡重绑引起链路重连时清除 profile 以外手工添加
的 IPv4 地址。应将对端所需的两个静态地址一并写入临时内存 profile，再 reapply；
不能只用 `ip address add` 添加第二地址。测试后恢复原 DHCP、删除测试 VLAN。

nic0 始终保持 r8125 和生产配置。本轮只更新隔离目录中的构建产物，未注册
会接管生产口的开机服务；后续仍需迁移 WireGuard、DNS 分流、TPROXY、IPsec、
IPv6 PD 和 Nebula/VPS 等业务，并演练生产回滚。

### 共用 LAN/DNS TAP 的 IPv4/IPv6 TPROXY

`--tproxy` 扩展 LAN services 隔离 fixture，复用已有 DNS TAP、Linux br-mgmt，
不创建代理专用 TAP。`deploy/tproxy/` 提供相同 nft 规则和一次性策略设置；
只处理 proxylist/proxylist6 的 TCP/UDP，保留本机 DNS、DHCP 和 IPv6 控制报文。

单主线程与两个 worker 均通过 IPv4/IPv6 TCP 64 KiB、UDP 1000 字节原目标回显；
nft 元素经现有 gate/Binary API 生成指向 BVI/Linux 的目标路由。代理启用后再次
验证 DHCP DORA/续租、UDP/TCP DNS 和普通 WAN EI NAT，forward 兜底计数为零。
结果见 `artifacts/vrouter/shared-tproxy-20261017.json`；服务器同名日志位于 `logs/`。

代码部署在迁移 source 目录，生产 proxylist/proxylist6 映射暂时禁用，未新增 TAP 或
启动/替换生产代理。正式启用须整合 LAN/IPv6、INPUT 防火墙、实际 SOCKS 上游
地址排除和开机初始化；本次没有测试真实上游网站或物理吞吐。

### 原生 IPv6 PD、RA 与前缀变更验证

`integration_vrouter_lan_services.py --workers 0|2 --ipv6` 增加独立 PD/RA 上游，
验证 VPP WAN SLAAC、RA 默认路由、DHCPv6-PD Solicit/Request/Renew、BVI 消费
前缀及客户端 SLAAC/IPv6 WAN 转发。上游明确撤销旧前缀后，验证 BVI 与客户端
切换新前缀。Linux DNS 的固定 ULA 经现有 TAP 可达。

`deploy/ipv6/` 保存迁移片段与边界说明；片段未应用到生产。LAN 公网 PIO
与 IPsec 池文件现由 `ipv6/pd-sync.py` 自动跟随 PD 更新；IPv6 DNS 公布/gate 也已完成隔离验证；
wg0 NAT66 已接入同一 PD 同步进程；IPsec 控制面与 ESP 数据面已完成隔离验证，
生产认证/动态池接入仍待联测。未更改现有 dhcpcd、dnsmasq 或生产 WAN/nic0。


### PD 自动发布与 IPsec 池文件同步

`ipv6/pd-sync.py` 自动处理首发、续租、重编号、撤销和重新获取，状态位于
`/run`，只在池内容变化时改写指定 IPsec 配置，保留 `::100–::200` 范围。
`docs/history/patches/ip6-ra-preserve-pd-flags.patch` 修复原生 PD 续租重置 PIO 标志的问题，
隔离 `libvnet` 位于 `ipv6-pd/lib`，原构建/安装不改动。实际加载路径与续租后的
L=0/A=1 都由集成测试验证。配置、systemd 单元和 VPP 环境 drop-in 仅部署到
迁移 source 目录，生产没有安装启用；生产 IPsec 配置不修改、不重载。


### IPv6 DNS 公布与应答屏障

复用已有 gate 的 IPv6 支持，不增加 DNS 进程。Linux DNS ULA 为
`fd42:1111:2222:10::2`，br-mgmt 上的 IPv6 UDP/TCP :53 重定向到 gate :1053。
辅助 dnsmasq RA 通过 RDNSS 公布同一 ULA，router lifetime=0，stateless
DHCPv6 也下发同一地址。Linux 关闭 br-mgmt 的 accept_ra/autoconf，使用静态
默认路由到 VPP，constructor 只消费 ULA，防止重新宣告公网 PD 为 on-link。

集成测试检查实际 DHCPv6 回复与 RA 报文、客户端仅经 VPP 的默认路由、
IPv6 上的 A/AAAA UDP/TCP 查询、AAAA→nftset→Binary API /128 路由，以及 gate
停止后无绕过。IPv6 UDP 请求在路由锁阻塞期间必须等待 ACK。配置只部署到迁移
source 目录，生产 dnsmasq、nft 与网络管理配置未改变。


### wg0 NAT66 随 PD 更新

`nat66/` 提供一次性 inside/outside 配置；原生 NAT66 插件已在隔离构建树编译并
复制到迁移 plugins，原安装不改动。WireGuard renderer 可同时导出静态 /128
策略，服务器 wg0 实际为 5 个 IPv6 地址，文件权限 0600。PD 同步程序加载该
策略，复用原 NAT66 映射核对函数，在 PD `:66::/80` 范围生成公网地址，撤销/
恢复时同步更新。运行时不查询握手、不导入 WireGuard、不增加定时器。

集成测试 `--ipv6 --nat66` 使用实际 Linux WireGuard 客户端、独立测试密钥，
核对两个源地址的加密流量、ICMP/UDP/TCP 数据、公网源地址和前缀变更，并确认
普通 LAN 原生 IPv6 源地址及无关映射保持不变。支持与 `--tproxy` 叠加联测。
生产仍未切换；完整出口防火墙、PMTU/ICMPv6 错误处理与真实公网接入尚未验证。

### strongSwan / VPP IPsec 数据面

`ipsec/README.md` 说明 strongSwan 5.9.8 后端构建、隔离测试与生产边界。
`tests/integration/integration_vrouter_ipsec.py` 使用临时密钥和私有 mount/net namespace，验证
SA/SPD 下发、VPP ESP 加解密、IPv4/IPv6 内层 TCP、EI NAT、换钥和 SA 清理；
服务端 Linux XFRM 必须为空。构建与测试代码只部署到迁移目录。
临时证书/EAP-MSCHAPv2、双栈动态池和错误密码拒绝也已完成隔离验证；实际生产
证书/终端、真实公网入口/上游 PD 接入与物理吞吐仍需后续验收，生产服务未替换。

IPsec 的 `--pd` 联测进一步使用真实 DHCPv6-PD 和实际 Publisher，验证重编号、
撤销与恢复后的客户端重连，及同前缀续租不改写池文件。新增池范围到 WAN SPD
的更具体回程路由，避免 LAN connected /64 截走回包。starter 更新连接定义时
charon/IKE 不重启，已有 IPv4 可继续转发；生产服务仍未切换。

IPv6 外层 IPsec 增加 `--outer6`，分别验证原生 ESP 与 IPv6 UDP 4500 封装。
使用相同证书/EAP、双栈地址池和 EI，并核对实际双向报文、VPP tunnel-v6 SA、
加解密节点、换钥/重连与清理。统计只保存在内存，按请求输出快照。生产公网
入站及完整 MTU/分片仍待后续验证，结果见 `artifacts/vrouter/ipsec-outer6-20261017.json`。
