# VPP 网关 + Linux TAP DHCP/DNS

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

示例中 DHCP 下发网关 `10.61.20.1`、DNS `10.61.20.2`：

```
LAN 客户端 / 物理 LAN → VPP BD 200
                          ├─ BVI loop200：10.61.20.1（网关、转发、NAT）
                          └─ tap2000 ↔ Linux vpp-lan → br-mgmt：10.61.20.2
                                                       ├─ dnsmasq DHCP / DNS :53
                                                       └─ DNS gate :1053
```

DHCP 广播经二层桥直接到 Linux，不需要 DHCP relay。客户端通过 DHCP option 3
获取 VPP 网关 .1，option 6 获取 Linux DNS .2。VPP 不响应 .1:53，Linux 不重复
持有 .1；不安装 DNS ABF 转送或额外 DNS NAT。Linux 中只在 LAN TAP/bridge
入站将发给 .2:53 的 TCP/UDP 查询重定向至 gate；gate 的本机查询直接到 dnsmasq。
原 nftset→Binary API 路由屏障继续工作。

## 生产准备

`lan.vpp.conf.example` 为全新启动的 BVI/桥/TAP 示例，实际生产 LAN 口名称、
BD/BVI/TAP 编号需要纳入整体配置，不能附加到仍持有网关 .1 的现有 Linux LAN。
VLAN 100 WAN 按整体 nic0 迁移处理。VLAN 10 VPS 二层见 `deploy/vps-bridge/`。
Linux vpp-lan 必须加入 br-mgmt，.2/24 放在 bridge 上，不放在 TAP 从接口上；
Linux 到外部网络的默认出口指向 VPP .1。mgmt0 的管理桥接和持久网络配置须随
现有网络管理系统一并集成，不能直接执行示例后视为迁移完成。

`dnsmasq-ipv4.conf.example` 只替换现有 IPv4 LAN 声明，不是完整 dnsmasq.conf，
不自动加载。保留原上游 DNS、域名 nftset 规则、租约文件及其他业务配置。
原池从 .2 开始，必须改为 .3–.254，排除 Linux 固定地址 .2；原来的
`dhcp-option=lan,6,10.61.20.1,10.62.10.1` 替换为 DNS .2，并显式设置网关 .1。
只读检查未发现 .2 的 DHCP 租约；正式切换仍需复核在线地址占用。

IPv6 使用 `dnsmasq-ipv6.conf.example` 替换旧 `constructor:lan` 声明，
`linux-ipv6.conf.example` 合入最终 br-mgmt 网络配置。Linux 仅持有固定 ULA
`fd42:1111:2222:10::2/64`，关闭 accept_ra/autoconf，默认 IPv6 路由经 VPP
`fd42:1111:2222:10::1`。不能让 constructor 消费 Linux 自动获取的公网前缀。
VPP 发布公网 PD 的 SLAAC PIO 与默认路由；dnsmasq 只发布 ULA、RDNSS 和
stateless DHCPv6 DNS 选项，辅助 RA 的 router lifetime 固定为 0。
这些示例尚未应用到生产，不删除或重启现有 IPv6 配置。
`dns-route-gate/` 中已有 .2 监听、br-mgmt 重定向、Binary API 环境与 service
drop-in 可以复用；应先完成 bridge/.2，再启动 dnsmasq、DNS gate，最后接入客户端。

本目录目前只部署在 `/opt/vpp-vrouter-migration/source/scripts/vrouter/lan-services/`。
生产 nic0、Linux lan、dnsmasq 和 WireGuard 没有切换。

## 实测

`tests/integration/integration_vrouter_lan_services.py --workers 0|2` 创建独立 VPP、LAN 客户端、
Linux DNS 和 WAN 命名空间。使用 198.18.44.0/24、198.18.45.0/24 隔离地址，
不接入物理 LAN、不向生产广播 DHCP。

- 客户端无初始 IPv4，通过真实 DHCP Discover/Offer/Request/ACK 获取地址，
  核对 option 3/6，并通过内核 UDP 单播完成续租。
- 网关 .1 仅在 VPP BVI，DHCP/DNS 服务 .2 仅在 Linux TAP。
- 客户端 UDP/TCP :53 经 Linux gate 得到 DNS 答案，确认对应 /32 已经由
  Binary API 加入 VPP；gate 到同机 dnsmasq 不递归。
- 客户端 ICMP 网关和 WAN、TCP WAN 请求通过，WAN 服务端看到 EI 转换后的源地址。
- 停止 gate 后 UDP/TCP DNS 不得绕过保留的重定向规则直接访问 dnsmasq。

测试结束停止 VPP/DHCP/DNS/临时上游并删除所有命名空间。日志在服务器
`logs/lan-services-workers0.json`、`lan-services-workers2.json`。
IPv6 扩展同时检查 DHCPv6 Information-request、实际 RA 的 RDNSS/零路由器寿命、
Linux 不持有/宣告公网 PD、IPv6 UDP/TCP DNS、AAAA 的 /128 Binary API 路由及
停止 gate 后无 IPv6 DNS 绕过。通过接口锁阻塞路由提交时，IPv6 UDP 答案必须等待。
这是隔离功能验证，不是生产 DHCP 切换、物理吞吐或实际上游网站验证。
