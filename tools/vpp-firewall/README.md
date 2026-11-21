# vpp-firewall

管理 VPP 路由器从 WAN 进来的流量：IPv4 端口转发、开放给路由器本机的端口、WAN 上的 ping，以及有状态的 IPv6 入站防火墙。以 root 运行，只在本机 Unix socket 上提供接口，由 `vpp-monitor` 转发（面板的“防火墙”页面）。

VPP 不保存运行时加的 NAT 映射和 ACL，它的启动 CLI 文件里也没有这些规则，所以规则存在 `/etc/vpp/firewall.json`，每次修改同时改文件和运行中的 VPP，VPP 重启后由本程序装回去。

## 构建和安装

```sh
make                                   # 生成 dist/vpp-firewall-linux-{arm64,amd64}
sudo install dist/vpp-firewall-linux-arm64 /usr/local/bin/vpp-firewall
sudo install -m 644 vpp-firewall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpp-firewall
```

单元文件里的 `--vpp-unit vpp-router.service` 是安装器装的 VPP 服务，其他部署改成实际的单元名。VPP 需要 `nat44_ei` 和 `acl` 插件（安装器都启用）。

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--socket` | `/run/vpp-firewall/firewall.sock` | 面板连接的 socket |
| `--config` | `/etc/vpp/firewall.json` | 规则 |
| `--api-socket` | `/run/vpp/api.sock` | VPP API socket |
| `--vpp-unit` | 无 | 配置 VPP 的 systemd 单元，它变成 active 后立即装回规则。不设置时等 VPP socket 存在满 30 秒 |

## WAN 接口

默认是 NAT44-EI 翻译出站流量的接口（`set interface nat44 ei out ... output-feature`，面板接口页的“设为出口”），多个上行口都算。要指定，在配置文件里写 `"wan_interfaces": ["接口", ...]` 后重启服务；这样可以把没有 NAT 的接口（比如只有 IPv6 的上行）也纳入 IPv6 防火墙。端口转发和本机端口只能开在 NAT 出口上：映射要用 NAT 地址池里的接口地址，在别的接口上 VPP 不会让它生效。

规则只挂在 WAN 接口上，局域网、隧道、TAP 不受影响，改错了也不会断开局域网上的面板，所以修改立即生效，没有 60 秒确认。

## 端口转发（IPv4）

`nat44 ei add static mapping ... external <WAN 接口>`：转发跟着接口地址走，DHCP 换了地址也不用改。

- 协议 TCP、UDP 或两者。NAT44-EI 的静态映射只能一个端口一条，端口段一一对应展开成单个映射：一条规则最多 1024 个端口，端口转发和本机端口合计最多 4096 个映射（TCP、UDP 各算一个）。每个映射占 VPP 一点主堆，VPP 重启后要一个个装回。
- 转发的外部端口不再参与动态 NAT 的端口分配。只有一个 WAN 地址又转发大段端口时，局域网出站能用的端口相应变少。
- 外部端口正被动态 NAT 会话占用时，VPP 拒绝这个映射，整条规则撤回，页面指出被占用的端口。动态会话的端口分布在 1024 以上的整个范围，一个 WAN 地址上有上千个会话时（RK3588 开发板实测约 2000 个），新加一大段高端口几乎一定撞上几个，要等那些连接结束；1024 以下不分配给动态会话。
- NAT44-EI 的 API 不是 mp-safe：VPP 列出静态映射时停住所有 worker，直到列完。N1 上 4096 个映射一次要停 20–40 ms。所以每 10 秒的检查（开着 IPv6 防火墙、禁 ping、来源限制或 LAN 阻断时）只读 identity mapping，不读也不对比静态映射，静态映射只在修改规则和 VPP 重启时完整读取并装回。页面每 5 秒刷新，静态映射缓存一分钟（VPP 重启后立即重读），其他程序新加的转发最多晚一分钟显示。

N1（4×A53，VPP 只有主线程）上实测（2026-11-20）：一条 1024 端口的 TCP+UDP 转发（2048 个映射）加入用 0.76 s，加到 4096 个用 1.0 s，删除 0.7–1.0 s，期间 VPP 的响应延迟最大 12–20 ms；4096 个映射占主堆约 0.8 MiB，删除后回到原值；VPP 重启后 6.4 s 应答，8.8 s 全部装回。
- 内部地址要在 VPP 某个非 WAN 接口的 IPv4 网段里（局域网、隧道对端都可以），不能是 VPP 自己的地址、网络地址或广播地址。
- 外部端口不能和已有的映射冲突，包括其他程序加的（WireGuard 的监听端口、IPsec 的 500/4500）。
- 同一个内部地址、端口和协议只能转发一次：NAT44-EI 的静态映射也按内部地址和端口区分，第二条会被拒绝，WAN 还没有地址时 VPP 甚至会收下它但永远不生效。
- 局域网里的设备用 WAN 地址访问转发的端口（回环，hairpin）不通（在 N1 上实测），要用内部地址。
- 路由页选了其他默认出口时，转发的回包从那个出口出去，转发不能用（见 `tools/vpp-egress-gate/README.md` 的“默认出口”）。
- Linux 主机上的服务（SSH 等）在局域网一侧，转发到它的管理地址即可。

## 路由器本机端口

### 可选的配置文件过滤条件

端口转发可带 `sources`（IPv4 网段列表），例如 `"sources": ["198.51.100.0/24"]`。只放行这些来源访问该转发端口，其余来源由 WAN 入站 ACL 拒绝；未写时保持原有行为。需要 ACL 插件。

`lan_deny` 可声明独立的 LAN 目的地址阻断，例如 `[{"interface":"loop0","destination":"203.0.113.0/24","protocol":"tcp"}]`。它只作用于指定的非 WAN 接口，其余 LAN 流量保持放行。默认没有此类规则；它不设置出口或策略路由。

状态接口的 `applied` 表示配置已应用到当前 VPP 实例，供依赖服务等待端口预留完成。

`nat44 ei add identity mapping external <WAN 接口> <协议> <端口>`，给 VPP 自己监听的端口开口，比如手动建的 WireGuard。NAT44-EI 默认丢弃 WAN 上不属于任何会话的包，没有这一行 VPP 收不到。页面同时列出其他程序加的 identity mapping（vpp-wireguard、IPsec），只读。其他程序的映射里连续的端口合成一行显示，比如 coturn 的 1000 个中继端口。IPv6 防火墙给本机端口放行时，连续的端口也合成一条 ACL 规则。

## WAN 上的 ping

关闭后在 WAN 的入站 ACL 里丢弃 ICMP echo request 和 ICMPv6 echo request（type 8、128），路由器自己和局域网主机的 IPv6 地址都不再响应。NAT 后面的 IPv4 主机本来就 ping 不到，不需要按地址区分。

## IPv6 入站防火墙

用 acl 插件的 reflexive ACL，带 tag `vpp-firewall-in`、`vpp-firewall-out`：

- **WAN 出站**：IPv4 permit，IPv6 `permit+reflect`。局域网和路由器发出的 IPv6 连接建立会话，回程由会话放行。
- **WAN 入站**，按顺序：（ping 关闭时）丢弃 echo request；IPv4 permit，交给 NAT；ICMPv6 错误、echo reply、邻居发现（1–4、129、133–137），ping 打开时加 echo request（128）；DHCPv6 回复（UDP 547 → 546）；本机端口（所有 identity mapping，目的地址是 WAN 自己的全球 IPv6 地址，有 UDP 500 时同时放行 ESP）；放行规则；最后丢弃其余 IPv6。
- 接口上已有别人挂的 ACL 时保持在前面，本程序的放在后面。
- 开着 ACL 时每 10 秒读一次 WAN 的地址和映射，WAN 的 IPv6 地址变了（SLAAC、DHCPv6）、其他程序新开了端口，规则跟着更新；没变化时不写 VPP。

放行规则写主机的完整地址或一个前缀，协议 TCP、UDP、两者或全部，端口可以是端口段。运营商换了委派前缀后，写死的地址要跟着改。

### 开销

acl 插件挂到接口上后对 IPv4 和 IPv6 一起生效，WAN 上进来的每个 IPv4 包也要查一次 ACL（第一条就命中 permit）。出站方向不受影响：NAT44-EI 的输出特性把 IPv4 直接交给 `interface-output`，不经过出站 ACL。

N1（Cortex-A53，单个 VPP 线程，计时器 24 MHz）上用 iperf3 4 条流经端口转发实测：吞吐在开和关之间没有可见差别（都在 650–770 Mbit/s，受测试路径限制）；`acl-plugin-in-ip4-fa` 每个入站 IPv4 包约 8.6 个计时器周期（约 0.36 微秒），是 `nat44-ei-out2in`（约 6.1，0.25 微秒）的 1.4 倍左右。包速率高的部署要算上这一项。只关闭 ping 时同样会挂上入站 ACL，代价相同。

### 局限

- VPP 重启到规则装回之间有几秒没有过滤（N1 上 VPP 应答后 1 秒内装回）。
- 会话按 acl 插件的默认超时回收，表满时新的出站连接不建会话，回程会被丢弃。

## 配置文件

```json
{
  "block_ping": false,
  "ipv6_firewall": true,
  "forwards": [{"id": 1, "name": "web", "protocol": "tcp", "interface": "port0.100", "external_port": 8080, "internal_ip": "10.61.30.10", "internal_port": 80}],
  "ports": [{"id": 2, "name": "wg", "protocol": "udp", "interface": "port0.100", "port": 51820}],
  "ipv6_rules": [{"id": 3, "name": "nas", "protocol": "tcp", "address": "2001:db8:1::10", "port": 443}],
  "next_id": 4
}
```

VPP 里的映射带 tag `vpp-firewall`，ACL 带上面的两个 tag，本程序只改带自己 tag 的项，别的不动。直接改文件后重启服务生效。

每次修改都写入服务日志（`journalctl -u vpp-firewall | grep audit`）。VPP 拒绝修改的一部分时，已做的部分撤回，文件不改。

## 接口

| 路径 | 内容 |
|---|---|
| `GET /firewall` | WAN 接口和地址、开关、规则（含其他程序的映射）、可转发到的网段、VPP 读取错误和应用错误 |
| `POST /firewall/forward` | `{"name","protocol","interface","external_port","last_port","internal_ip","internal_port"}`，`interface` 留空用第一个 WAN，`internal_port` 为 0 时同外部端口 |
| `POST /firewall/port` | `{"name","protocol","interface","port","last_port"}` |
| `POST /firewall/ipv6/rule` | `{"name","protocol","address","port","last_port"}` |
| `POST /firewall/delete` | `{"id"}`，三种规则共用 |
| `POST /firewall/ping`、`/firewall/ipv6` | `{"allow"}`、`{"enable"}` |

面板从 `/api/firewall/*` 转发过来，出错时返回 409 和 `{"error": "原因"}`。

## 测试

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o dist/vpp-firewall.test .
# 把 dist/vpp-firewall.test 复制到 Linux 主机上运行
```
