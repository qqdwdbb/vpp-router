# VROUTER 切换配置清单与 Linux 恢复

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

主机服务统一入口的 IPv4 候选见 [host-services/README.md](../host-services/README.md)。
通过 prepare 的 `--host-service-path` 单独启用；现有 bundle 和生产网卡不自动修改。

## 独立管理入口

VROUTER mgmt0 `10.61.60.1/24`，管理机 `10.61.60.2/24`。
SSH 回程必须为 `dev mgmt0 src 10.61.60.1`，mgmt0 不得有 bridge master。
这是独立网络管理通道，不是串口控制台，不覆盖内核崩溃或启动失败。
已核对 `/etc/network/interfaces`：mgmt0 独立静态地址，LAN bridge_ports 为 nic1 nic0。
恢复仍逐接口操作，避免 restart networking、ifup -a 或 ifup --force lan 扩大影响。

## 最终配置清单

| 对象 | 当前 Linux 基线 / VPP 目标 | 切换前要求 |
| --- | --- | --- |
| mgmt0 | 独立管理，始终由 Linux 持有 | 已从持久 LAN 桥成员中排除；重启后独立可达尚未演练 |
| nic0 | PCI 0000:01:00.0，r8125 → VPP | 只操作此 BDF；nic1 0000:02:00.0 不解绑 |
| LAN | 无标签 nic0，网关 10.61.20.1、fd42:1111:2222:10::1 | VPP BVI 网关；保留网关 MAC 02:00:00:00:10:02；Linux DNS/DHCP 用 .2；明确 nic1 与 TAP 桥接，防环路 |
| WAN | nic0 VLAN100，10.61.10.2/24，经 10.61.10.1 | VPP 子接口，MAC 02:00:00:00:10:01；output NAT、WAN identity mapping、ACL 顺序使用已验收实现 |
| VPS | nic0 VLAN10 → br0；Linux 10.61.50.2/24 | VLAN10 经 VPP BD/TAP 接 br0；VPP .3；保留 tap0、Linux .2 与原出口 .1 |
| MTU | nic0/wan/vps/lan 1500；br0/tap0 1342 | 不把 br0 改成 1500；生产 IPsec MTU/MSS 另行批准 |
| IPv6 | WAN RA 默认路由、DHCPv6-PD 给 LAN | 重学动态前缀，不固化当前 GUA；保留 ULA；验证续租、前缀变化与 DNS/IPsec 池更新 |
| 源策略 | 10.62.20.0/24、10.62.40.0/24 → 10.61.50.1 loop10；EAP ULA fd42:1111:2222:60::/64 与 wg8 fd42:1111:2222:70::/64 → fd42:1111:2222:20::1 loop10 | VPP ABF + loop10 EI SNAT（IPv4）；IPv6 直出 loop10，VPS 把 EAP/WireGuard 路由到 ::3，mark 0x1 经 wg1 FULLCONENAT（与 IPv4 10.61.50.0/24 相同）。br-mgmt TPROXY 仍对 EAP、WireGuard 源地址 return，避免偶发送到 Linux 的内层被 LAN 接管链送到 SOCKS。 |
| 目的策略 | vpn/vpn6 → VPS；altroute → wg1；proxylist/proxylist6 → Linux TPROXY | 导入现有集合和优先级；uk 当前空表继续回落主路由，不能凭名称新增出口 |
| WireGuard | wg0、wg1、sg，保留现有端点与策略 | 密钥留在设备；wg1 代理链、独立 NAT VRF 与真实 peer 逐项验收 |
| 其他隧道 | Nebula、GRETAP、gost、TPROXY | 保留依赖的 Linux 转发与 br0；不全局清空或禁用 |
| strongSwan | Linux IKE + VPP ESP | 使用已验收私有 namespace/run/config 启动链；原服务与新服务不得争抢地址/端口 |
| 服务链 | namespace 预备 → VPP → network-prep → firewall → IKE/DNS → PD | 先解决启动前 namespace 创建；部署真实配置路径；验证开机与恢复流程 |
| 插件 | /opt/vpp-vrouter-migration/plugins 中已验收三插件 | 成组核对 SHA256；不恢复已删除的问题版本 |

以上是目标与门槛，不能把隔离测试通过视为物理切换完成。
完整生产切换尚需持久配置落地、真实 WG/策略链联测、物理吞吐和公网复验。

## 恢复前准备

在独立 mgmt0 SSH 中确认路径与 sudo，保持管理网线连接。先核对无 VPP 运行、nic0
仍为 r8125，保存 Linux 基线（仅网络状态和防火墙，不读取 VPN/WG 密钥）：

```sh
sudo python3 linux-recovery-audit.py capture --directory /root/vpp-vrouter-backup/UNIQUE
sudo python3 linux-recovery-audit.py check --directory /root/vpp-vrouter-backup/UNIQUE
```

基线目录权限 0700，恢复防火墙事务预先经过 `nft -c -f` 检查。不得在 VPP
切换完成后重新捕获该目录来掩盖基线变化。

## Linux 恢复顺序

1. 从 mgmt0 登录，确认回程与 mgmt0 无 master。停止已部署的 VPP 依赖链与 VPP，
   确认进程退出、UIO 无占用；不要杀无关进程。当前未部署新链时，不操作生产 strongSwan。
2. 执行 `../restore-nic0.sh`，将 nic0 归还 r8125，重建 VLAN100/10 与桥成员。
   此工具只恢复基础链路，不代表完整恢复成功。
3. 根据 `linux-state.json` 恢复 nic0 原 MAC、vps MAC、LAN/br0 MAC/MTU，
   LAN .1/ULA 与 br0 .2/ULA；确认 nic1 仍在 lan，vps/tap0 仍在 br0。
   不把 mgmt0 加入桥；若实际切换创建 br-mgmt，先解除其与 LAN 的冲突。
4. 恢复 Linux IPv4 默认路由和策略表：vpn 经 br0 的 10.61.50.1，altroute 经
   wg1 的 10.62.30.1，proxylist 为 lo local default；IPv6 vpn 经 br0 的
   fd42:1111:2222:20::1，proxylist 为 lo local default。按基线恢复 mark 规则。
5. 需要还原已修改的防火墙时：`sudo nft -f BASELINE/restore-firewall.nft`。
   不要启动当前 inactive 的 nftables.service 来替代现场规则。
6. 对 WAN 执行 `dhcpcd --rebind wan`，等待 RA 默认路由和新 PD；不静态重放过期 GUA。
   按切换记录恢复原先 active 服务；strongSwan 如仍 active 不重启。
7. 执行 audit check，必须无 differences；另核对上游连通、DNS、公网 IPv4/IPv6、
   EAP 出口、WG peer。配置一致不等同于所有业务已恢复。

## 演练覆盖范围

`nic0-recovery-drill.sh BASELINE` 仅供当前 Linux 基线、独立 mgmt0 管理下运行。
应由 systemd 临时 service 执行，并配置 ExecStopPost 同一脚本的 `--restore`
作为退出恢复。它临时解绑 nic0 的 r8125 后归还驱动，不启动 VPP，不停止 strongSwan，
恢复基线防火墙事务以重新绑定 WAN flowtable，不改策略路由。会短暂中断 nic0 上的 LAN/WAN/VPS。

这是物理驱动/VLAN 恢复演练，不能替代从完整 VPP 生产配置撤回、开机恢复或串口演练。
完整切换后的回退仍需按上述全部步骤及实际配置差异逐项执行。

## 成对切换工具（2026-10-18）

新增 `prepare.py`、`validate.py`、`transition.py` 和两个 shell 入口。当前部署源码：
`/opt/vpp-vrouter-migration/cutover-source-20261017/scripts/vrouter/cutover/`。
生成的真实配置仅保存在 VROUTER root 私有目录：
`/opt/vpp-vrouter-migration/cutover-release-20261018-v4`。

- `prepare.py --directory NEW_DIRECTORY` 从现场生成完整配置与基线，拒绝覆盖，
  不操作网卡、现有服务或 `/etc`。原证书与 secrets 由私有服务只读引用；
  WG 生成文件含密钥，只留在设备，禁止打印。
- `validate.py --bundle DIRECTORY` 用断网 namespace 和临时 WG 密钥加载拓扑，
  检查 NAT/ABF/ACL、前缀 ACL 重用、真实认证配置的 strongSwan 私有启动、
  systemd、dnsmasq、nft 语法；不接入真实 WG 对端。
- 两个切换入口默认只检查；`--apply` 才改变现场。源码、配置或 Linux 基线变化会
  拒绝应用，需重新准备与验证，不能复用旧 validation.json。
- 切换与主动回退由独立 systemd oneshot 执行，SSH 断线不终止任务。
  切换前启动 600 秒独立回退 timer；启动失败的 ExecStopPost 也执行恢复。
  全局锁及 active bundle 记录防止两套部署互相清理。
- 配置仅安装到 `/run/systemd/system`，不改变开机模式。首次试切成功也不能据此
  声称开机/完整物理回退已通过；持久启动另行验收。

操作顺序（在 VROUTER mgmt0 SSH 中执行，路径为本轮生成的部署包）：

```sh
SOURCE=/opt/vpp-vrouter-migration/cutover-source-20261017/scripts/vrouter/cutover
BUNDLE=/opt/vpp-vrouter-migration/cutover-release-20261018-v4

# 只读预检，保留 SSH_CONNECTION 供独立管理路径校验。
sudo env SSH_CONNECTION="$SSH_CONNECTION" sh "$SOURCE/switch-to-vpp.sh" --bundle "$BUNDLE"

# 显式试切：会中断现有连接，600 秒内未确认会自动回 Linux。
sudo env SSH_CONNECTION="$SSH_CONNECTION" sh "$SOURCE/switch-to-vpp.sh" --bundle "$BUNDLE" --apply
sudo python3 "$SOURCE/transition.py" status --bundle "$BUNDLE"

# 客户端复验成功后才执行此命令取消自动回退。
sudo env SSH_CONNECTION="$SSH_CONNECTION" python3 "$SOURCE/transition.py" commit --bundle "$BUNDLE"

# 主动切回 Linux，后台执行恢复，恢复成功后 phase 应为 linux。
sudo env SSH_CONNECTION="$SSH_CONNECTION" sh "$SOURCE/switch-to-linux.sh" --bundle "$BUNDLE" --apply
sudo python3 "$SOURCE/transition.py" status --bundle "$BUNDLE"
```

服务日志仅在设备上查看；不要直接分享完整日志或 VPP WireGuard/SA 详情。
`recovery-failed` 时 root 私有 `state.json` 记录未恢复项，使用同一部署包重试回退，
不要重新 capture 覆盖基线。

实际配置选择：

- 父口使用原 WAN MAC；WAN 子接口不能单独改 MAC。LAN BVI 使用原网关 MAC。
- VPP 主堆为 1 GiB，避免完整 ACL 会话表加载时耗尽原先的 128 MiB 上限。
- Linux WG 设备保留配置和密钥，但交接时停接口并移除全局地址，防止同密钥双端漫游；
  回退恢复地址、MTU、状态和静态路由，不执行原 wg-quick 钩子。
- IPsec / sg 的源策略先经共享 TAP 到 Linux，保留原 nft 分类顺序及 br0 出口；
  返回 VPP 的 LAN TAP 不附加此源策略，避免 altroute 回注循环。
- 物理 LAN 父口应用源校验 ACL；共享主机 TAP 保留 Linux 既有过滤与 TUN/代理回程，
  不套用只允许 LAN 源地址的 ACL，避免丢弃合法代理回复。nic1 继续属于 Linux 这一侧。
- dnsmasq 改为 Linux `.2`，DHCP 从 `.3` 开始，并拒绝 `.2` 已有有效租约的现场。
  LAN 客户端需更新 DHCP/DNS；原 WG DNS `10.62.10.1` 通过 punt、Linux lo 地址与 gate 保留。
- PD watcher 同步 LAN 公网源 ACL；Linux 公网 IPv6 地址放在 lo，以 /128 路由回主机，
  避免 dnsmasq 在共享桥上把公网 PD 再通告为 on-link。
- 保留真实 DNS 集合与原 Linux 隧道规则；不套用示例里会阻断 Nebula/GRETAP 的全局 drop。
- 该方案停用 miniupnpd。已有的固定 UDP 转发需按设备配置保留。
  NAT44-EI 不提供 UPnP 动态端口申请接口。

当前验收范围以设备 `validation.json` 为准。配置加载/私有启动通过，不等于公网
客户端、真实 WG 对端、物理吞吐或首次完整切换/回退已经验收。

## 2026-10-18：生产双 worker NAT 回程修复

当前现场运行 `cutover-release-20261018-v7`，nic0 已由 VPP 接管。
生产确认的限制覆盖前文“整地址 WAN identity mapping”建议：**不能在当前 EI 26.06
双 worker 配置中使用整地址 identity mapping**。其 addr-only 静态映射先于动态端口
分区选择回程 worker，可能用另一个 worker 中同索引的会话改写目的客户端。

现场抓到一个 LAN 客户端的 ICMP 请求在 worker 2 建立会话，回包被整地址
映射送到 worker 1，错误还原为 `10.61.20.2`。改为按 IKE 与 WireGuard 的监听端口做精确 UDP identity mapping 后，客户端 IPv4 恢复。
不放宽 WAN ACL，也不需要调整生产 TX 队列；诊断时的临时队列调整已恢复。

另一个已确认的问题是隔离测试用的每 worker 4096 NAT 会话上限被带入生产，
worker 1 满表并丢弃新连接。生产改为每 worker 65536 sessions / 4096 users /
每用户 16384 sessions；通过 NAT 插件池重建在线应用，VPP PID 未变化，原 NAT44
会话需重建，未重启 VPP/IPv6/strongSwan。已有固定 UDP 转发和 wg1 VRF101 均保留。
生成器、profile 与当前 v7 的 topology 配置已同步。

隔离回归入口（不操作物理接口）：

```sh
python3 tests/integration/integration_nat44_ei.py --workers 2 --wan-identity ports \
  --nat-sessions 65536 --reinit-nat --plugin-path PLUGIN_DIRECTORY
# 以下为故障复现负例，当前插件下预期失败，不作为部署配置：
python3 tests/integration/integration_nat44_ei.py --workers 2 --wan-identity address \
  --plugin-path PLUGIN_DIRECTORY
```

v7 在运行中还存在 PD 配置更新及用户策略修改，旧 manifest/validation 不自动重签。
当前服务重启会读取已修正的启动配置；从 Linux 再次试切前，应在 Linux 基线上重新
生成并验证新部署包，不绕过校验或将旧 validation.json 当作新配置的验收证明。

### 原生 UDP 端口的配置来源

`profile.json` 的 `wan_identity_udp_ports` 是 VPP 精确 UDP Identity Mapping
的唯一端口清单，普通路径与 host-service 候选路径均读取它。新增 WireGuard 等
原生监听端口时更新此字段，并核对服务监听与 ACL；`host-services/services.json`
不维护该清单。prepare 拒绝缺失、空或无效清单，不回退到代码内的默认端口。
此调整不改变已有会话、精确映射、整地址 host fallback 的选择顺序。

### 2026-10-18：共享 DMZ 出口（覆盖此前主机独立地址方案）

主机服务路径现使用 `10.61.10.2` 的 VRF0 动态池供 LAN 和 Linux 主机共用，
取消 `.0.4` 分池、VRF4094 保留池及整地址主机映射。明确配置的固定主机端口在
outside 分配启用前装入；coturn 保留完整中继范围并使用专用 TAP/cgroup 策略，
Nebula 不按监听清单生成固定映射。详见 [主机服务说明](../host-services/README.md)。

最终 shared-WAN v2 包从 Linux 基线重新生成并验证，包含不预留 Nebula 监听端口
的生成器，以及修复静态端口占用表字节序的 EI 插件。旧包及 manifest 保留原样。
本次确认不改变设备开机启动方式。

### 后续固定目录安装

现场现已使用 `/usr/local/lib/vpp-vrouter`、`/etc/vpp`、`/var/lib/vpp-vrouter` 和
`/etc/systemd/system` 的本地安装布局。本文的旧 bundle/source 路径是迁移历史，
不要使用旧试部署控制器管理已安装服务。规范安装与恢复步骤见
[安装说明](../install/README.md)，本次没有启用开机 VPP 接管。
