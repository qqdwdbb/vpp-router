# 共用 LAN/DNS TAP 的透明代理

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

本目录是 VROUTER 整体迁移的待启用配置。复用 `lan-services/` 的 BD 200、BVI
`loop200` 和 `tap2000`；Linux TAP 从接口加入 `br-mgmt`。不新建代理 TAP。

路径：客户端 → VPP 的目标 /32 或 /128 路由 → Linux br-mgmt → ipt2socks
`127.0.0.1/[::1]:2080` → 本机 SOCKS `127.0.0.1:1080`。
回包使用 Linux 的 LAN 直连路由，经相同 TAP 返回客户端。

2080 是内部透明截获端口，不是客户端直接连接的服务。`host-services/services.json`
将其记录在 `internal_services`，不参与服务端口放行。TPROXY 显式选择回环 socket；
网关 `.1:2080` 普通 DNAT 到 `.2:2080` 不会自动命中 `127.0.0.1:2080`。
本机 SOCKS `127.0.0.1:1080` 是内部后端；若需 LAN 通过 `.1:1080` 访问 SOCKS，
还须提供 `.2:1080` 或 `0.0.0.0:1080` 监听，不能仅靠 DNAT 暴露回环监听。
候选全端口 host-service 路径统一处理 LAN DNAT，不再叠加 `socks-frontend.nft`；
未启用该候选的原迁移路径仍使用专用 SOCKS 规则。

## 启用前提与步骤

1. 完成 LAN 网关迁移：VPP `loop200` 为 `10.61.20.1/24`，Linux `br-mgmt`
   为 `10.61.20.2/24`。Linux 默认路由指向 VPP .1。
2. IPv6 使用稳定 ULA 下一跳：VPP BVI 保留 `fd42:1111:2222:10::1/64`，
   Linux bridge 配置 `fd42:1111:2222:10::2/64`。这只提供代理下一跳，
   客户端公网 IPv6、默认路由与 PD/RA 仍须由整体 IPv6 方案配置。
3. 保留现有 `inet/mangle/proxylist`（ipv4_addr）和 `proxylist6`（ipv6_addr）集合、
   dnsmasq 域名规则；不要运行旧的 `tools/tproxy/tproxy-setup.py`。
4. 使用现有 ipt2socks 二进制，监听 IPv4/IPv6 loopback 2080，并确认本机 SOCKS
   1080 可用。独立管理现有进程，不重复启动生产监听器。
5. 以 root 执行一次（重启后的系统网络初始化也需执行）：

   ```sh
   python3 /opt/vpp-vrouter-migration/source/scripts/vrouter/tproxy/setup-shared.py \
     --rules-file /opt/vpp-vrouter-migration/source/scripts/vrouter/tproxy/shared.nft
   ```

6. 在 `dns-route-gate/nftset-route-sync.json` 中启用已有的 proxylist/proxylist6 映射：
   IPv4 经 `10.61.20.2 loop200`，IPv6 经 `fd42:1111:2222:10::2 loop200`。
   先确认实际生产 BVI 名称。两项目前均为 `enabled: false`。
   真实 SOCKS 上游服务器地址必须从动态路由中排除，否则代理自身连接可能绕回
   Linux。不能只排除本机 SOCKS 监听地址；需核对后端实际公网服务器 IP。

Linux 规则仅处理 `br-mgmt` 入站且目标属于指定集合的 TCP/UDP；本机地址、
IPv4 广播/组播及 IPv6 链路本地/组播提前放行，保留 DNS/DHCP/ND。
mark `0x2080/0xffff`、策略优先级 `12080`、本地路由表 `2080` 用于 TPROXY。
本配置不需要旧方案的 OUTPUT mark 2081 或回程表 2081。
规则仅刷新两个自有 chain，不刷新集合或现有 mangle 表；设置脚本可重复执行。
透明代理未接住的集合流量由自有 forward chain 丢弃，避免绕过代理。
现有防火墙的后续 INPUT 链仍须允许打标透明流量；nft 的 accept 不跳过其他链。

## 验证范围

`tests/integration/integration_vrouter_lan_services.py --workers 0|2 --tproxy` 使用独立 VPP 和
命名空间，在已有 DNS TAP 上加载相同规则。受控 SOCKS5 后端验证 IPv4/IPv6
TCP 64 KiB、UDP 1000 字节内容及原始目标；nft 元素经 gate 的 Binary API
生成路由。另复测 DHCP DORA/续租、UDP/TCP DNS、普通 WAN EI NAT，检查两类
TPROXY 计数增长和 forward 兜底计数为零。测试不会接入生产 LAN。

这是共享 TAP 的功能验证；未验证真实 SOCKS 上游、生产防火墙整合、物理吞吐，
也没有切换 nic0 或改变现有代理进程。开机持久化随整体迁移安装脚本集成。
