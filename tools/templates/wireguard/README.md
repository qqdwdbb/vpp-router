# VPP WireGuard 全流量 VPN 模板

适用于现有服务器的 VPP 26.06、`host-vpp-wan` 外网口和 `10.61.30.0/24` 内网。仅提供模板，未部署服务、修改服务器配置、创建密钥或添加 peer。

路径：客户端 → WireGuard `wg0` → VPP → 内网，或 NAT44 → `host-vpp-wan` → 上游。无需 Linux wg-quick，也无需开启 Linux IPv4 forwarding。

## 文件

- `server.vpp.conf.example`：服务器接口、NAT inside、外网监听端口的 NAT identity mapping。
- `peer.vpp.conf.example`：客户端公钥、允许的隧道地址和回程路由。
- `client.conf.example`：标准 WireGuard 客户端配置。

模板中的 `<...>` 均须替换。示例使用 VPN 网段 `10.66.66.0/24`，服务器 `.1`，第一个客户端 `.2`；如果与客户端所在地网络冲突，请整体更换。

## 1. 启用插件和加密引擎

服务器已有 `wireguard-tools`，但当前 VPP 启动配置采用插件白名单，尚未启用 WireGuard，也未安装 `vpp-crypto-engines`。部署时执行：

```sh
sudo apt-get install vpp-crypto-engines
```

在 `/etc/vpp/startup.conf` 现有 `plugins { ... }` 中增加：

```text
plugin wireguard_plugin.so { enable }
```

重启 VPP 后核对命令与算法是否可用：

```sh
sudo systemctl restart vpp
sudo vppctl help wireguard create
sudo vppctl help wireguard peer add
sudo vppctl show crypto engines
sudo vppctl show crypto handlers
sudo vppctl show dhcp client
```

检查 ChaCha20-Poly1305 的处理引擎。重启会清空原有 NAT 会话。

## 2. 密钥与外网地址

在适当主机上分别生成服务器和客户端密钥。以下为服务器密钥示例，在有权限写入的安全目录执行：

```sh
umask 077
wg genkey > server.private
wg pubkey < server.private > server.public
```

客户端独立生成自己的密钥，仅将客户端公钥用于服务器 peer 配置。模板不包含真实密钥。

`<VPP_WAN_IPV4>` 填写 `vppctl show interface address` 中 **host-vpp-wan 的地址**：当前是 `10.61.20.68`，不是 Linux 管理地址 `10.61.20.134`。`src` 是 VPP 的实际外网源地址；即使客户端使用公网地址连接，路由器后方的 VPP 仍填写自己的私网 WAN 地址。

当前 WAN 使用 DHCP。应为 WAN MAC `02:76:70:70:00:01` 配置 DHCP 地址保留，或在租约改变后重建 WireGuard 接口与 peer。WireGuard 的 `src` 不会因为 WAN DHCP 地址变化而自动同步。

## 3. 应用服务器与 peer 配置

填好模板后，将它们放到服务器上，例如 `/etc/vpp/wireguard-server.conf` 和 `/etc/vpp/wireguard-peers.conf`，文件权限设为 `0600`。确认 `host-vpp-wan` 已经获得 IPv4 地址后执行：

```sh
sudo vppctl exec /etc/vpp/wireguard-server.conf
sudo vppctl exec /etc/vpp/wireguard-peers.conf
```

`instance 0` 固定接口名为 `wg0`，使用前确认该实例未被占用。这些是创建命令，不能反复执行来替代更新。

服务器的每个 peer 使用其独立 `/32` 作为 `allowed-ip`，并配置对应 `/32` 路由；客户端的 `AllowedIPs` 使用默认路由。服务器 peer 不填 `0.0.0.0/0`，否则会把其他客户端的地址归属和回程路由混淆。

模板为客户端主动连接的服务器配置：初始 endpoint 为 `0.0.0.0:0`，服务器从认证成功的报文学习 endpoint。客户端设置 `PersistentKeepalive = 25`。固定对端也可以填写其真实 endpoint 和 UDP 端口。

## 4. DNS 和 Linux 本机服务的回程路由

dnsmasq 在 Linux 的 `10.61.30.2`，Linux 需要知道 VPN 客户端应经 VPP 返回。服务器部署时执行：

```sh
sudo ip route replace 10.66.66.0/24 via 10.61.30.1 dev br-vpp-lan
```

要持久化，将以下一行加入服务器 `/usr/local/sbin/vpp-net-prepare` 中桥地址配置之后：

```sh
ip route replace 10.66.66.0/24 via 10.61.30.1 dev br-vpp-lan
```

这是 Linux 本机响应的路由，不是开启 Linux 转发。内网其他设备的默认网关应为 `10.61.30.1`；若使用其他网关，需要为 VPN 网段配置回程路由。

## 5. 外网入口

当前服务器位于上游路由器后方，需要将 **UDP 51820 转发到 VPP WAN 地址 `10.61.20.68:51820`**。多级 NAT 要逐级转发；实际公网入口和地址保留由上游网络配置决定。

客户端 `Endpoint` 填公网 IP 或域名。端口放行需覆盖实际入口设备。VPP 中的 NAT identity mapping 让发往本机 WireGuard 端口的 UDP 报文可交给 WireGuard 插件；它不替代上游路由器的端口转发。

## 6. 开机恢复

上面的 `vppctl exec` 只影响当前运行实例。需要开机恢复时，启用插件仍通过 `startup.conf` 持久化；服务器和 peer 命令则需要在 **VPP 启动且 DHCP WAN 租约就绪后** 执行。

不要仅将 `exec /etc/vpp/wireguard-server.conf` 追加到当前 `nat.conf`，并假设前面的 DHCP 命令已经同步获得地址。当前模板没有安装自动等待租约的 systemd 服务。静态 WAN、DHCP 保留和启动时租约检查须结合实际部署确定。

## 7. 可选：VPN 内的原生 IPv6

基础模板提供 IPv4 NAT 上网。客户端同时配置 `::/0`，将 IPv6 流量导入隧道；在配置下面的原生 IPv6 前，IPv6 不具备出网路径，避免直接绕过 VPN。测试时也要确认客户端软件实际安装了 IPv6 默认路由。

若上游委派 `/56` 或 `/60`，可以给 LAN 和 WireGuard 分配不同 `/64`。现有 LAN 使用第一个 `/64`，可给 `wg0` 使用第二个：

```text
enable ip6 interface wg0
set ip6 address wg0 prefix group wan-pd 0:0:0:1::1/64
```

例如获得 `2001:db8:1234:5600::/56` 时，LAN 是 `2001:db8:1234:5600::/64`，VPN 是 `2001:db8:1234:5601::/64`。`2001:db8::/32` 仅用于文档，必须替换为真实委派前缀。若上游仅委派一个 `/64` 且已用于 LAN，此配置不适用。

为客户端分配 VPN `/64` 中的独立地址，例如 `2001:db8:1234:5601::2/128`。将 peer 示例中的单条添加命令改为同时包含两个 `allowed-ip`，不要重复添加同一公钥：

```text
wireguard peer add wg0 public-key <CLIENT_PUBLIC_KEY_BASE64> endpoint 0.0.0.0 dst-port 0 allowed-ip 10.66.66.2/32 allowed-ip 2001:db8:1234:5601::2/128 persistent-keepalive 0
ip route add 10.66.66.2/32 via 10.66.66.2 wg0
ip route add 2001:db8:1234:5601::2/128 via 2001:db8:1234:5601::2 wg0
```

客户端同时填写：

```ini
Address = 10.66.66.2/32, 2001:db8:1234:5601::2/128
AllowedIPs = 0.0.0.0/0, ::/0
```

IPv6 由 VPP 原生路由，不使用 NAT66。WireGuard 不向客户端提供 DHCP/SLAAC；客户端的隧道地址由配置文件指定。VPP 网关地址可随 PD 改变，peer 的 IPv6 allowed-ip、回程路由以及客户端文件中的固定 IPv6 地址仍需同步更新。本模板不包含动态前缀同步。

## 检查与验证范围

```sh
sudo vppctl show wireguard interface
sudo vppctl show wireguard peer
sudo vppctl show interface wg0
sudo vppctl show ip fib 10.66.66.2/32
sudo vppctl show nat44 ei interfaces
sudo vppctl show nat44 ei static mappings
sudo vppctl show nat44 ei sessions
```

客户端连接后先检查握手，再测试 `10.66.66.1`、`10.61.30.1`、DNS `10.61.30.2` 和公网出口。`show wireguard interface` 可能包含密钥信息，不应直接公开其完整输出。

本次仅只读检查服务器环境，并核对 VPP 26.06 分支的命令解析、peer endpoint 更新实现及当前 NAT 命令帮助；没有启用插件、安装加密引擎、导入模板或进行真实 WireGuard 握手测试。

参考：[VPP WireGuard CLI 源码](https://github.com/FDio/vpp/blob/stable/2606/src/plugins/wireguard/wireguard_cli.c)、[peer 与 endpoint 更新实现](https://github.com/FDio/vpp/blob/stable/2606/src/plugins/wireguard/wireguard_peer.c)。
