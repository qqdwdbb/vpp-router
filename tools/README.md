# tools

部署时 `deploy/install/stage-source.py` 把这个目录原样放到设备的 `scripts/`，安装脚本和 systemd 单元按这里的文件名引用，所以顶层的单文件脚本没有再分子目录。

## 管理面板（Go）

面板由 `vpp-monitor` 提供网页和统计，其余程序以 root 运行在本机 Unix socket 上，由 `vpp-monitor` 转发。安装方式见 `deploy/install/README.md`。

| 目录 | 面板页面 | 作用 |
|---|---|---|
| [`vpp-monitor`](vpp-monitor/README.md) | 全部 | 网页、登录、读取 VPP 统计段和历史数据 |
| [`vpp-interfaces`](vpp-interfaces/README.md) | 接口、局域网 | 地址、VLAN、桥域、MTU，改错 60 秒内自动回滚；LAN 的 DHCP 地址池、静态分配和设备 |
| [`vpp-firewall`](vpp-firewall/README.md) | 防火墙 | 端口转发、开放本机端口、IPv6 入站防火墙 |
| [`vpp-wireguard`](vpp-wireguard/README.md) | WireGuard | 隧道和节点，VPP 重启后恢复 |
| [`vpp-system`](vpp-system/README.md) | 系统 | 线程布局、DPDK 网卡增删、收包方式、NAT 超时、调速器 |
| [`vpp-proxy`](vpp-proxy/README.md) | 代理 | sing-box 上游 |
| [`gate-admin`](gate-admin/README.md) | 路由 | Gate 规则的写入端 |
| [`vpp-egress-gate`](vpp-egress-gate/README.md) | — | 按域名和设备选择出口的路由程序（Gate） |

## 脚本（Python）

| 文件 | 作用 |
|---|---|
| `dns-route-gate.py`、`dns-route-gate.json`、`dns-route-gate.nft` | DNS 应答放行前先确认对应的 VPP 路由已下发 |
| `nftset-route-sync.py`、`nftset-route-sync.json` | DNS Gate 和导入工具共用的 VPP 路由后端，见 [README-nftset-route-sync.md](README-nftset-route-sync.md) |
| `dns-nftsets.nft`、`vpp-dns-nftsets.service`、`vpp-dns-route-gate.service`、`vpp-nft-route-sync.service` | 上面两者的 nft 集合和 systemd 单元 |
| `vpp-egress-nat.py`、`vpp-egress-nat.service` | 维护 NAT44 地址池和 wg0 的 IPv6 源地址转换 |
| `napt66-sync.py` | 按 WAN 当前 IPv6 地址更新单地址 NAPT66 |
| `nat44-ei-context.conf` | `nat-ei-context` 插件的映射域示例 |
| `import-wireguard.py`、`import-wireguard-client.py`、`install-wireguard.py`、`vpp-wireguard-static.py`、`vpp-wg-syncconf.py`、`wg1-routes.conf` | 不经面板时把 `/etc/wireguard` 配置装进 VPP，见 [README-wireguard-static.md](README-wireguard-static.md) |
| `nebula.service` | Nebula 覆盖网络的 systemd 单元示例 |
| `vpp-net-prepare-*.patch` | 对旧版 `vpp-net-prepare` 的补丁，仅供参考 |

## 其他目录

| 目录 | 作用 |
|---|---|
| `wireguard` | WireGuard 端点刷新定时器和 wg0 NAT66 说明 |
| `templates/wireguard` | VPP WireGuard 全流量 VPN 的服务端、客户端模板 |
| `ipsec` | strongSwan + VPP IPsec 配置、客户端地址池前缀同步 |
| `tproxy` | VPP → TAP → ipt2socks → SOCKS5 透明代理 |

`vpp-wireguard`（面板后端）和 `wireguard`（脚本方式的附件）是两套独立的做法，选一种即可。
