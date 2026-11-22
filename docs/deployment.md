# 部署

## 拓扑

一个物理口（`nic0`）承载：不打标的 LAN、VLAN 100 的 WAN。VPP 持有 LAN 网关，Linux 通过 TAP 提供 DHCP、DNS 和控制面服务。独立的管理口（`mgmt0`）始终由 Linux 持有，切换前必须确认它可以独立登录。

## 步骤

1. 按 [rebuild.md](rebuild.md) 构建 VPP、DPDK 和插件，安装到 `/usr/local/lib/vpp-vrouter`。
2. 将 `deploy/profiles/example.profile.json` 复制到仓库外。按设备配置填写 `replace`，包括接口名、PCI BDF、MAC、地址前缀、下一跳和业务端口。仓库中的值为合成示例。升级已有部署时，将示例值映射到目标设备当前使用的值。
3. 用 `deploy/install/stage-source.py` 渲染源码目录。
4. 从渲染后的目录运行 `scripts/vrouter/cutover/prepare.py` 生成配置，再用 `install/` 安装。说明见 `deploy/cutover/README.md` 和 `deploy/install/README.md`。

切换会重绑网卡，请先准备好串口或独立管理口，并确认回退流程可用。

需要压测脚本时，可在渲染时传入 `--with-benchmarks`。旧压测脚本中的 SSH 账号、目标地址、接口名和报文参数也使用示例值。按实验环境填写私有 profile 后，再从输出目录运行压测。打包会跳过本地 profile、密钥、符号链接、构建产物和抓包文件。

## 模块

| 模块 | 目录 | 说明 |
|---|---|---|
| 防火墙 | `deploy/firewall` | VPP ACL 和 nftables |
| IPv6 | `deploy/ipv6`、`deploy/nat66` | PD、RA、NAT66 |
| IPsec | `deploy/ipsec` | strongSwan 控制面，VPP 数据面 |
| LAN 服务 | `deploy/lan-services`、`deploy/host-services` | DHCP、DNS、本机服务入口 |
| DNS 分流 | `deploy/dns-route-gate`、`deploy/dns-intercept` | 按域名把解析结果下发为路由 |
| 代理 | `deploy/fakeip`、`deploy/tproxy`、`deploy/wg-proxy`、`deploy/vps-bridge` | Fake-IP、TPROXY、WireGuard 出口。不含域名和服务规则 |
