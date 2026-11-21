# VPP → TAP → ipt2socks → SOCKS5

服务器：10.61.10.3。IPv4 使用 `inet/mangle/proxylist`，IPv6 使用 `inet/mangle/proxylist6`，原 altroute/wg1 配置不变。
真实 SOCKS5 后端应监听 `127.0.0.1:1080`（无认证）；ipt2socks 监听 `127.0.0.1:2080` 和 `[::1]:2080`，
提供 TCP/UDP TPROXY 入口。UDP 还要求 SOCKS5 后端支持 UDP ASSOCIATE。

```text
LAN 客户端
  → VPP proxylist /32 或 proxylist6 /128 路由
  → tap2080 10.63.50.1/30
  → Linux vpp-tproxy 10.63.50.2/30
  → nftables TPROXY 127.0.0.1:2080
  → ipt2socks
  → SOCKS5 127.0.0.1:1080
  → Linux WAN eno1
```

VPP TAP 保留客户端源地址和原始目标地址，不对 TAP 添加 NAT。
Linux 入口只匹配 `vpp-tproxy` 和源网段 `10.61.30.0/24`。
fwmark 0x2080/0xffff、优先级 12080、表 2080 的 local 默认路由用于本地接管；
nft route/output 链仅给发往 LAN 的 transparent socket 回复打 0x2081 标记，
优先级 12081、表 2081 将回复送回 TAP。Linux 本来的 LAN 直连路由和 dnsmasq 回复不变。
代理自身的上游连接直接使用 Linux 默认路由，不经过 TAP，不需要全局 OUTPUT 代理规则。
入口其他未被接管的转发包会丢弃，避免通过 Linux 转发绕过代理。

## 当前状态与启用

TAP、Linux 策略规则、两个 service 已部署并启用。由于真实 1080 后端未监听，
`/etc/vpp/nftset-route-sync.json` 内的 proxylist/proxylist6 映射均设为 `enabled: false`。
后端就绪后执行：

```sh
sudo vpp-tproxy-enable enable
# 只启用 IPv6
sudo vpp-tproxy-enable enable --set proxylist6
# 只启用 IPv4
sudo vpp-tproxy-enable enable --set proxylist
# 关闭两个集合的代理分流
sudo vpp-tproxy-enable disable
```

启用命令检查 SOCKS5 无认证握手及两个 service，更新选中集合映射并重启 DNS gate。
不会修改 altroute。后端启动后不会自动启用，避免临时测试监听被误当成生产服务。
启用后继续使用现有 nft 元素监控和 DNS 应答前路由屏障，不新增周期任务。
这里只按目标 IP 分流；选中目标的 TCP/UDP 会被代理，ICMP 不提供透明代理。
禁用后目的地址恢复普通路由，并非转回 wg1。

IPv6 TAP 使用 `fd76:7070:2080::1/64`（VPP）和 `::2/64`（Linux）。
IPv6 同样使用 2080/2081 表及 mark，本地接管路由为 `local ::/0`，
回程表默认经 `fd76:7070:2080::1`。入口根据 Linux FIB 判断源地址经 br-vpp-lan
可达，不写死动态 PD 前缀；接管连接设置 ct mark，其 transparent socket 回复设置回程 mark。
TAP 禁止 RA/自动配置，避免 Linux 从 VPP 学到错误默认路由。
AAAA 地址仅在进入 proxylist6、启用该映射且 SOCKS5 支持 IPv6 目标时经过代理。

## 文件对应

| 项目文件 | 服务器文件 |
| --- | --- |
| tproxy.conf | /etc/vpp/tproxy.conf |
| tproxy.nft | /etc/vpp/tproxy.nft |
| tproxy-setup.py | /usr/local/sbin/vpp-tproxy-setup |
| tproxy-enable.py | /usr/local/sbin/vpp-tproxy-enable |
| ipt2socks-vpp.default | /etc/default/ipt2socks-vpp |
| vpp-tproxy.service | /etc/systemd/system/vpp-tproxy.service |
| ipt2socks-vpp.service | /etc/systemd/system/ipt2socks-vpp.service |

`startup.conf` 启用 `tap_plugin.so`；`nat.conf` 最后追加 `exec /etc/vpp/tproxy.conf`。
`vpp-tproxy.service` 在 VPP 建立 TAP 后一次性恢复 Linux nft/策略路由，
`ipt2socks-vpp.service` 运行现有二进制，2 个线程、NOFILE 65536。
两个服务随 VPP 启动/重启，没有 timer。部署需要系统已有 `ip`、`nft`、Python 3 和
`/usr/local/bin/ipt2socks`；这些配置不执行源码编译。

## 验证与限制

现场已实际重启 VPP，TAP、两个服务、WireGuard 静态配置和 IPv6 PD 恢复。
使用临时受限 SOCKS5 后端和模拟 LAN 客户端验证：
TCP 请求经测试目的 198.18.0.10:443 代理到百度 HTTPS，返回 200，约 130ms；
UDP SOCKS5 回显回复保留原始端点；nft TPROXY 和 transparent socket 回程计数增长，
forward 丢弃计数为 0。临时后端、测试 /32 和命名空间已清理。
此测试验证转发机制，不证明尚未启动的真实 SOCKS5 后端可用，也不是性能基准。
IPv6 TCP HTTPS 200（约 129ms）和 UDP 原始端点回复也已验证；实际 proxylist6 临时成员
生成经 TAP 的 /128 路由，并完成撤销清理。
生产 proxylist/proxylist6 映射均未启用。原配置备份位于 `/root/vpp-nat-backup/before-tproxy/`。

参考：[ipt2socks](https://github.com/zfl9/ipt2socks)、
[Linux TPROXY](https://cdn.kernel.org/doc/html/latest/networking/tproxy.html)。

TAP 收包显式使用 `set interface rx-mode tap2080 interrupt`。默认 polling 会在无代理流量时
占满一个 VPP 核心；现网已切换并持久化，轻载采样从 100% 降至约 10%。
