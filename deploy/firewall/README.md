# VROUTER 统一防火墙策略架构与运维规范

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

## 当前设备的持久化入口

`/etc/nftables.conf` 是完整重载入口，末尾包含 `/etc/nftables.d/vrouter-vpp.nft`，
后者统一包含 `/etc/vpp/wg-proxy.nft`、`host-path.nft` 和 `dns-route-gate.nft`。
执行 `nft -f /etc/nftables.conf` 会在同一事务中恢复这些规则，而不是等服务重启。
`persistent-rules.py` 的渲染保留 Linux 基础策略，并将 LAN 接口匹配扩展为同时
支持 `lan` 和 `br-mgmt`；移除无法绑定已交给 DPDK 的 WAN 设备的 Linux flowtable。

全局规则加载发生在 VPP topology 阶段、wg1 启用之前。后续 Linux host 准备只
更新各服务自己的表，禁止再加载带 `flush ruleset` 的旧 `host.nft` 清掉 wg1 DNAT。

coturn 的 socket/cgroup 所有权取决于当次启动的 cgroup，不能把旧 cgroup 路径
无条件放进开机配置。持久化 `host-path.nft` 使用无 owner 的安全初始策略，保留
默认拒绝；运行中的 host-services 监控通过策略签名发现全局重载，在下一次 2 秒
轮询内恢复当前 owner 规则。重载窗口内 UDP 中继可能短暂被拒绝，不会放宽所有权检查。
监控根据内核中的签名判断状态，不再仅依赖 Python 中的上次策略缓存。

完整重载仍按 nftables 语义重置动态集合；DNS 分流程序继续根据解析事件更新集合。

## 1. 架构目标与安全分域

在 NanoPi VROUTER 迁移为 VPP/DPDK 路由器后，防火墙策略采用**双层纵深防御体系**：
- **VPP 数据面 ACL（Datapath Security）**：处理物理 WAN（`nic1`/`nic0-dpdk`）、LAN BVI（`loop200`）、WireGuard 隧道接口与 IPsec 解密流的极速包过滤、防欺骗与防泄漏。
- **Linux 控制面 nftables（Control-Plane & Host Services）**：保护宿主机本地协议栈与服务（`br-mgmt` 上的 DHCP/DNS/SSH、control TAP、TPROXY、Nebula `br0`），拦截非授权管理访问并提供 DNS 重定向与防绕过屏障。

```
                                  ┌───────────────────────────────┐
                                  │      外部公网 (WAN Zone)       │
                                  └───────────────┬───────────────┘
                                                  │
                                   [VPP WAN Ingress ACL]
                                   - Drop 伪造内网源地址 (Anti-Spoofing)
                                   - 仅放行 IKE (500/4500)、WG（配置端口）、DHCPv6 (546)、ICMP/ICMPv6
                                   - 丢弃未授权主动入站扫描与嗅探
                                                  │
                                                  ▼
┌─────────────────────────────────────────── VPP 数据面 ───────────────────────────────────────────┐
│                                                                                                  │
│   NAT44-EI (WAN VRF 0, wg1 VRF 101, loop10 VRF 102) ─── WireGuard / IPsec ESP                    │
│                                                                                                  │
│   [VPP WAN Egress ACL]                                                                           │
│   - 防私网泄漏 (Anti-Leak): 严禁未经 NAT 或加密的 RFC 1918 (10/8, 172.16/12, 192.168/16) 裸出 WAN │
│                                                                                                  │
│   [VPP LAN Ingress ACL (loop200 BVI)]                                                            │
│   - 源地址校验 (BCP 38): 仅允许 10.61.20.0/24、ULA 与 DHCP 初始化报文，丢弃伪造源地址               │
│   - 网关保护: 仅允许 ICMP/ICMPv6 ping 网关 .1/::1，丢弃针对网关 .1 未开放端口的扫描与嗅探          │
│                                                                                                  │
│                      BD 200 (Bridge Domain)                                                      │
│                        ├─ loop200 (BVI, 10.61.20.1 / ULA ::1)                                   │
│                        └─ tap2000 ↔ Linux vpp-lan                                                │
└──────────────────────────────────────┬───────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌────────────────────────────────────── Linux 宿主机控制面 ────────────────────────────────────────┐
│                                                                                                  │
│   [br-mgmt (10.61.20.2 / ULA ::2) - nftables table inet vrouter_firewall]                          │
│   - DHCP: 仅允许 UDP 67/68 到 dnsmasq                                                           │
│   - DNS: 拦截 UDP/TCP 53 强制重定向至 DNS Gate (:1053)                                           │
│   - DNS Anti-Bypass: DNS Gate 故障或停止时处于 fail-closed 状态，严防绕过与明文泄漏                │
│   - SSH 管理: 严格限制仅允许受信管理网段 (@trusted_mgmt) 访问端口 22，拒绝外部及未知地址        │
│   - 代理防护: 严禁从 LAN 直接访问本地透明代理端口 (1080/2080)                                    │
│   - TPROXY: 匹配 @proxylist / @proxylist6 流量重定向至 :2080，QUIC (UDP 443) 阻断回退 TCP                │
│                                                                                                  │
│   [control TAP (vrouter-ipsec-ctrl)]                                                                 │
│   - 仅允许 strongSwan IKE UDP 500/4500 报文进入 Linux 控制协议栈                                 │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. 策略明细与过滤规则

### 2.1 WAN 边界防御（VPP WAN ACL）
- **入站规则（Ingress）**：
  1. **上游控制例外**：在防伪造规则前允许链路本地源 ICMPv6 和 DHCPv6 回复；仅允许配置的 `wan_gateway4` 向 `wan_ipv4` 发送 ICMPv4。
  2. **防伪造源地址（Anti-Spoofing）**：丢弃源地址为 `10.0.0.0/8`、`172.16.0.0/12`、`10.61.10.0/16`、`127.0.0.0/8`、`224.0.0.0/4`、`fc00::/7`、`fe80::/10` 的入站包。
  2. **放行 VPN 服务**：放行目标 UDP 500、4500（IKEv2）与 配置的 WireGuard UDP 监听端口。
  3. **放行网络控制**：放行上游 DHCPv6 客户端响应（sport 547 dport 546）、ICMPv4（proto 1）与 ICMPv6（proto 58，含 ND/PTB/RA）。
  4. **状态化返回（Stateful Return）**：NAT44-EI 自动匹配并放行回程；IPv6 仅由 WAN 出站 `permit+reflect` 创建会话；WAN 入站不设置宽泛的 TCP/UDP 放行。
  5. **默认丢弃**：所有其他未授权入站流量均被静默丢弃。
- **出站规则（Egress）**：
  1. **私网 WAN 例外**：`wan_ipv4`（当前 `10.61.10.2`）以精确 /32 放行，允许本机和 NAT 后流量；不能放行整个上游子网。`wan_gateway4` 当前为 `10.61.10.1`。WAN 地址变化时须同步配置。
  2. **防私网泄漏（Anti-Leak）**：严格拦截私网 IPv4（`10/8`、`172.16/12`、`192.168/16`）及 ULA 裸包出 WAN，防止 NAT 故障或路由失误导致的内网明文泄露。

### 2.2 LAN 边界与网关防御（VPP LAN BVI ACL）
- **入站规则（Ingress on `loop200`）**：
  1. **防欺骗（Anti-Spoofing）**：仅放行来自 `10.61.20.0/24`、`fd42:1111:2222:10::/64`、链路本地地址或 DHCP 初始化（`0.0.0.0/32` sport 68 dport 67）的数据包。
  2. **网关保护**：对发往网关 `.1` / `::1` 的报文，仅放行 ICMP echo-request，其余发往网关 IP 的 TCP/UDP 探测全部丢弃（网关服务如 DNS/DHCP 集中位于 Linux `.2`）。
  3. **受控转发**：合法 LAN 报文通过 `permit+reflect` 允许转发至公网、VPN 或代理。

### 2.3 宿主机与控制面防护（Linux nftables）
- **输入链（Input Chain, Default Drop）**：
  1. 状态维持：`ct state established,related accept`；丢弃 `ct state invalid`。
  2. 本地回环：`iifname "lo" accept`。
  3. `br-mgmt` 接口保护：
     - 放行 DHCP 服务端口（UDP 67、68）。
     - 放行 DNS Gate 服务端口（TCP/UDP 1053）。
     - 放行本机 DNS 端口（TCP/UDP 53）。
     - 放行受信任管理网段（`@trusted_mgmt`）访问 SSH（TCP 22），其余来源一律丢弃。
     - 放行 ICMP/ICMPv6 必要信令（ND、RA、RS、Echo）。
     - 显式拦截并丢弃直接访问本地透明代理端口（`1080`、`2080`）的尝试。
  4. 控制 TAP 接口保护（`vrouter-ipsec-ctrl`）：仅放行 UDP 500 与 4500。
  5. 丢弃其余一切未受信任入站连接。
- **转发链（Forward Chain, Default Drop）**：
  - 宿主机 Linux 默认不担任二层/三层数据转发路由，转发链策略设为 `drop`。
- **预路由与透明代理（Prerouting NAT / Mangle）**：
  - **DNS 屏障**：发往 `10.61.20.2:53` 或 `[fd42:1111:2222:10::2]:53` 的查询强制重定向至 `:1053`（DNS Route Gate）。未配置或私自指定公共 DNS 的异常查询同样重定向至 Gate，防止绕过。
  - **TPROXY 分流**：目标匹配 `@proxylist` / `@proxylist6` 的流量重定向至 `:2080`（`ipt2socks`），QUIC（UDP 443）阻断以强制降级至 TCP。

## 3. 运维命令与管理

管理入口脚本为：`/opt/vpp-vrouter-migration/source/scripts/vrouter/firewall/vrouter-firewall.py`

### 3.1 规则语法与完整性检查
```sh
python3 vrouter-firewall.py --check --config /etc/vpp/firewall.json
```

### 3.2 应用统一防火墙规则
```sh
sudo python3 vrouter-firewall.py --apply --config /etc/vpp/firewall.json
```

### 3.3 检查当前状态与命中计数
```sh
sudo python3 vrouter-firewall.py --status --config /etc/vpp/firewall.json
```

### 3.4 回滚与清空规则
```sh
sudo python3 vrouter-firewall.py --flush --config /etc/vpp/firewall.json
```

### 3.5 systemd 服务集成
防火墙服务已纳入系统服务依赖树：
```sh
sudo systemctl status vrouter-firewall.service
```
依赖关系：
```
vrouter-vpp.service
  └─► vrouter-network-prep.service
        └─► vrouter-firewall.service
              ├─► vrouter-dns-route-gate.service
              └─► vrouter-strongswan.service
                    └─► vrouter-pd-sync.service
```
当 VPP 重启时，`PartOf=vrouter-vpp.service` 保证防火墙单元随之安全重新加载，自动重建 VPP ACL 绑定与 nftables 规则。

## 本轮修正与部署要求

LAN 源地址 ACL 必须通过 `vpp.lan_interfaces` 显式绑定真实 LAN 入站成员接口，
不能绑定 BVI。BVI 接收从路由侧注入桥域的回程包，对其套用 LAN 源地址限制会误杀回程。
默认列表为空，部署前必须填写；示例中的占位接口不能直接应用。
DNS/IKE 服务现在 Requires/After 防火墙，防火墙启动失败时不启动依赖服务。

隔离回归使用私网 WAN、全球 IPv6 LAN、真实 TCP/UDP 监听器和严格 ping 断言。
启动编排测试尚未覆盖真实 strongSwan 完整启动链；不能据此宣称已完成生产启动验收。
