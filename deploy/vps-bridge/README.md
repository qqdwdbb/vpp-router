# VLAN 10 VPS 二层桥与 br0 网关三层

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

生产 `br0` 现在是 Linux `vps@nic0`（802.1Q 10）加 Nebula 上的 gretap `tap0`。
VPP 不实现 Nebula，也不建 GRETAP。迁完后 VLAN 10 在 VPP 里拆标签，和 TAP
`vrouter-vps` 同一桥域；Linux `br0` 只留 `vrouter-vps` + `tap0`。

```
nftset vpn/vpn6 ── FIB via 10.61.50.1 / fd42:1111:2222:20::1
                          │
                     loop10 BVI 10.61.50.3
                          fd42:1111:2222:20::3
                          IPv4 NAT44-EI VRF 102
                          │
本地 VPS ── VLAN 10 ── nic0-dpdk.10 ── BD 10 (pop 1) ── tap2010
                                                          │
                                                     vrouter-vps
                                                          │
Linux br0 10.61.50.2/24 ── tap0 gretap ── Nebula ── 远端 10.61.50.1
```

- VPP 在 BD 10 上用 BVI `loop10` 做三层，地址 `.3` / `::3`，直接 ARP
  远端网关 `.1` / `::1`。
- `loop10` 抑制 RA，避免在 VPS 二层再宣告一条默认路由。
- Linux br0 仍持有 `10.61.50.2/24`、现网 EUI-64 ULA、表 102、Nebula 证书。
- TAP MTU 1342，与现网 `tap0`/`br0` 一致。`vps` 现为 1500，切过去后跟桥。
- `linux-br0.sh.example --apply` 仅在 nic0 已离开 r8125 且 TAP 已出现时使用。
  nic0 仍是 r8125 时拒绝执行，避免把生产 `vps` 从 `br0` 拆掉。
- 生产 IPv4 `vpn` 在 `loop10` 上做 NAT44-EI（VRF 102，池 `10.61.50.3`），
  FIB 下一跳是远端 `.1`。`vrouter-vps` 已经把 BD 10 接到 br0，不再另加 TAP。
  Linux br0 不再为这条 VPP 流量 SNAT 或 inet mangle 打标。`vpn6` 仍经 `::1`；
  本地 VPP 不做 NAT66。
- 远端 VPS 对从 `lan` 进入、经 `ens5` 出口的全球单播 IPv6 做 MASQUERADE。
  连接标记 `0x2` 在回包上恢复为路由标记，策略表 102 经 `lan` 指向
  `fd42:1111:2222:20::3`，使解 NAT 后的客户端地址返回 VROUTER；不依赖
  家庭 PD 的当前前缀。EAP `fd42:1111:2222:60::/64` 与 wg8 `fd42:1111:2222:70::/64` 由
  VPS 路由到 `::3`；源地址 mark `0x1`，与 `10.61.50.0/24` / 链路 ULA 相同，
  经表 100、`wg1`（`fd42:1111:2222:80::3`）FULLCONENAT 出网，不走 `ens5`。远端防火墙规则
  保存在 `/etc/iptables/rules.v6`，由现有 `/etc/rc.local` 恢复；路由与
  `ip -6 rule` 配置在 `/etc/network/interfaces` 的 `lan inet6` 接口启动/停止
  钩子中。现有 ULA `0x1`/WireGuard 策略保持不变。
- 隔离测试用远端回程经 `.3`/`::3` 验证转发，不加载 EI。

nftset `vpn`/`vpn6` 映射见 `../dns-route-gate/nftset-route-sync.json`。

隔离测试：

- L2：`tests/integration/integration_vrouter_vps_bridge.py --workers 0|2`
- BVI + vpn/vpn6 FIB：`tests/integration/integration_vrouter_vpn_br0.py --workers 0|2`

均用 TAP 模拟打标物理口和 Linux `br0`+veth（代替 gretap），不绑 nic1/nic0，
不碰现网 Nebula，不改生产 `inet mangle vpn/vpn6`。
