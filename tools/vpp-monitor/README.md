# vpp-monitor

用 GoVPP Stats API 读取 VPP 统计段的监控面板。采集、历史存储和网页都在一个静态链接的程序里，不依赖 Prometheus、Grafana 或数据库，面向 N1 这类低端 ARM 主机。

读取只访问与 VPP 共享的内存，不经过 VPP 的 API 或 CLI。图表由浏览器绘制，主机只提供 JSON。

## 构建和安装

```sh
make                                   # 生成 dist/vpp-monitor-linux-{arm64,amd64}
sudo install dist/vpp-monitor-linux-arm64 /usr/local/bin/vpp-monitor
sudo install -m 644 vpp-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpp-monitor
```

VPP 需要开启统计 socket：

```text
statseg { socket-name /run/vpp/stats.sock }
```

启动前先设置登录密码（用户名默认 `admin`，用 `--user` 改）。没有设置时服务不会启动，修改后要重启服务：

```sh
read -rs PW; printf '%s\n' "$PW" | sudo vpp-monitor --set-password; unset PW
```

面板只提供 HTTPS，首次启动时在 `/var/lib/vpp-monitor/` 生成 10 年的自签证书，第一次访问时浏览器会提示，确认即可。默认只监听 `127.0.0.1:9480`，可以用 SSH 转发访问：

```sh
ssh -L 9480:127.0.0.1:9480 user@host   # 然后打开 https://127.0.0.1:9480/
```

要从局域网直接访问，在 unit 的 `ExecStart` 加 `--listen 10.61.30.2:9480`。面板内容包含接口名、流量和内网设备访问的外部地址，即使有登录也不要监听在 WAN 地址上。

VPP 的 worker 绑定了核心时，在 unit 里设置 `CPUAffinity=` 把监控放到其他核心，例如 worker 在 1-3 时用 `CPUAffinity=0`。

## 登录

所有页面和接口都要登录。会话 12 小时不活动后失效，服务重启后需要重新登录。同一地址连续输错 5 次后锁定 1 分钟。登录、退出和被拒绝的跨站请求都会写入服务日志（`journalctl -u vpp-monitor | grep audit`）。

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--socket` | `/run/vpp/stats.sock` | 统计 socket |
| `--auth-file` | `/var/lib/vpp-monitor/auth.json` | 账号文件，只允许属主读取 |
| `--tls-cert`、`--tls-key` | `/var/lib/vpp-monitor/tls.{crt,key}` | 证书和私钥，不存在时自动生成 |
| `--set-password`、`--user` | 否、`admin` | 从标准输入读密码，写入账号文件后退出 |
| `--listen` | `127.0.0.1:9480` | 面板地址 |
| `--proxy-socket` | `/run/vpp-proxy/proxy.sock` | `vpp-proxy` 的 socket，见“代理” |
| `--interfaces-socket` | `/run/vpp-interfaces/interfaces.sock` | `vpp-interfaces` 的 socket，见“接口管理” |
| `--firewall-socket` | `/run/vpp-firewall/firewall.sock` | `vpp-firewall` 的 socket，见“防火墙” |
| `--system-socket` | `/run/vpp-system/system.sock` | `vpp-system` 的 socket，见“系统” |
| `--api-socket` | `/run/vpp/api.sock` | VPP API socket，只在查看出口连接和 VPN 页面时使用 |
| `--stroke`、`--ipsec-socket` | `/usr/lib/ipsec/stroke`、无 | 读取 strongSwan 状态，见“VPN 客户端” |
| `--vpp-runs` | `/var/lib/vpp-monitor/vpp-runs.json` | VPP 启动记录，只在 VPP 重启时写入 |
| `--vpn-names` | 无 | WireGuard 公钥到客户端名字的 JSON 文件 |
| `--interval` | `1s` | 接口计数器的采样周期，整秒 |
| `--slow-interval` | `10s` | 其余指标的采样周期，须是 `--interval` 的整数倍并能整除 60 秒 |
| `--stale-after` | `30s` | `/sys/heartbeat` 这么久不变就认为 VPP 已失去响应，须大于 `statseg { update-interval }` |

## 采集内容

| 周期 | 统计路径 | 面板内容 |
|---|---|---|
| 快 | `/if/{names,rx,tx,drops,punt,rx-miss,rx-no-buf,rx-error,tx-error}` | 接口带宽、包速率、丢弃和错误 |
| 慢 | `/sys/*` | 向量率、输入速率、各线程向量率 |
| 慢 | `/buffer-pools/*`、`/mem/*` | Buffer 和内存堆用量 |
| 慢 | `/err/*` | 节点计数器的累计和速率，见下文 |
| 慢 | `/nat44-{ei,ed}/total-{users,sessions}` | NAT 用户和会话，VPP 有这些计数器时才显示 |
| 慢 | `/sys/node/*` | 节点开销表 |
| 慢 | `/proc/{stat,meminfo,uptime}`、`/sys/class/thermal`（没有时用 `/sys/class/hwmon`）、根分区 | 主机 CPU、内存、温度、磁盘，VPP 没运行时也继续采集 |

`/err/*` 名字叫 error，实际是各节点的通用计数器，很多只是正常的收发计数。统计段里没有分级信息，VPP `show errors` 的分级也不可靠（`no error` 被标成 `error`）。所以 `counters.go` 用一份名称清单挑出明确属于正常计数的项，默认折叠在“正常计数”里，其余全部放在“需关注”，不认识的名称也归入“需关注”。“需关注”不等于故障，比如 `unknown ethernet type` 在局域网里常见。

VPP worker 是忙轮询，所在核心的 CPU 使用率一直接近 100%，整机 CPU 使用率也因此偏高，转发压力要看向量率。同样的原因，每个轮询的 worker 都会给系统负载加 1，所以面板不显示负载。

`/net/*` 不采集，路由表大的主机上这部分每条路由一个计数器，读取开销最大。

`/sys/*`、`/buffer-pools/*` 由 VPP 主线程按 `statseg { update-interval }` 刷新，默认 10 秒，比这更快地读取也不会得到新值。节点开销表需要 `statseg { per-node-counters on }`，没开时面板会提示。

## 出口连接

点“NAT 会话”卡片或顶部的“出口连接”按钮，可以看每个出口的流量、各客户端，以及“客户端 → 外部地址”的每条连接和速率（NAT44-EI）。数据来自 NAT 会话表，VPP 本来就在维护，不增加转发开销，也不修改 VPP 的状态。

外部地址需要 `patches/vpp/0012-nat44-ei-session-dump-external-host.patch`：VPP 建立会话时记录了外部地址，但 API 没有返回。没打这个补丁时页面不显示外部地址这一列，其余内容不受影响。

这些数据不在统计段里，要通过 VPP Binary API（`--api-socket`，默认 `/run/vpp/api.sock`）查询，而这类查询默认要让 worker 在屏障处暂停，所以：

- 只在窗口打开时才查询，关闭 30 秒后断开 API 连接，平时不访问 API。
- 无论多少人打开，最多每 5 秒查询一次。
- 一次最多读取 5000 条，按用户的会话数从多到少读取，放不下的用户不读取，页面会标明；最多显示 300 条。

只统计 IPv4。IPv6 是 1:1 转换，没有需要统计的连接状态，页面不显示 IPv6 连接。

客户端里，路由器自己的地址标为“本机”。源地址是外部公网、目的地却是私网或本地网段的连接标为“回程残留”：多半是发给已断开 VPN 客户端的回程包又从出口发了出去，被 NAT 当成了内网用户。这两类单独放在“本机与回程残留”里，不算客户端。

局限：

- 只能看到做 NAT 的出口。出口由连接转换后的地址对应到拥有这个地址的接口，地址不在任何接口上时直接显示地址。
- 速率是相邻两次查询的累计流量之差，至少要读两次才有。VPP 每条连接只有一个累计值，所以是收发双向合计。
- EI 按“内网地址加端口”建连接，外部地址是第一个目的地。同一个内网端口连多个目的地时（P2P、部分 UDP 应用）只显示第一个。
- NAT44-ED 只显示会话数，暂不支持查看连接。

## 路由管理

添加规则时可填写关键词（每行一个），也可以只填关键词，不选择列表文件。
规则表每行的“编辑”按钮打开一个窗口，一次修改该组的出口、DNS、域名表、网段表和关键词，
IPv4/IPv6 一起更新，作为一次修改走确认流程。网段表按地址族分给组里对应的规则。
关键词忽略大小写，匹配域名任意位置的子串；域名、关键词、网段满足任意一项即可匹配。
不能删除规则最后的匹配条件。default 行的“编辑”修改默认出口和默认 DNS。

安装了面板代理服务时，路由页自动提供“代理（真实 IP）”和“代理（Fake-IP）”出口，
复用代理页的监听端口、Fake-IP DNS 和地址池。前者用于域名和网段，后者用于域名。
节点配置和服务启停仍在代理页管理。

“路由”页面用来切换规则的出口、调整规则优先级、添加和删除规则、上传、新建、编辑和删除域名表和网段表。这些操作由 `gate-admin` 执行（见 `tools/gate-admin/README.md`），面板通过 `--gate-admin-socket` 转发请求。管理服务没运行时，这个页面显示不可用，其他页面不受影响。

Gate 只在启动时读配置，所以每次修改都会：备份涉及的文件，写入新内容，用 Gate 自己的 `--sync-devices --dry-run` 校验，重新同步并重启 Gate，等 DNS 恢复应答，然后倒计时 60 秒（`--confirm`）等待确认。没确认、Gate 没有恢复、或者管理服务中途重启，都会自动恢复旧配置并再次重启 Gate。重启期间局域网 DNS 会中断，实际时长显示在页面上。

- **出口：** 同一组域名的规则（通常是 IPv4 和 IPv6 两条）一起切换，出口相关的属性（下一跳、Fake-IP DNS 和地址池等）从已经使用该出口的规则复制。只有每个地址族都有下一跳的出口才可选。带 `ip_range_files` 的规则组切换时静态网段跟着走，但有两个限制：不能切到带 `tproxy_port` 的出口，Gate 的 TPROXY 只拦截 Fake-IP 地址池，真实地址到了那里进不了代理；网段和其他规则的 Fake-IP 地址池重叠时不能切走，要先从网段文件里去掉重叠的行。
- **出口和下一跳：** “出口”一栏列出所有出口和它们的下一跳。VPP 接口的出口可以手动设置下一跳，可以是网关，也可以是经这个接口能到达的其他地址；IPv4 也可以用 DHCP 网关，跟着租约变，这样的出口只能做默认出口。接口页设了静态网关或 DHCP 的接口自动出现在这里，手动设置的优先。有规则在用这个出口时，修改会同时改这些规则（每个地址族都要有下一跳），走确认流程；没有时直接保存，不重启 Gate。Linux 出口和代理的下一跳由 Gate 的设备配置生成，只显示。
- **出口名称：** 页面上的出口显示接口的可读名字（规则、下拉框和提示），规则文件里写的和提交的仍是 VPP 接口名。
- **统计：** 规则列表上方显示规则数、Gate 当前装进 VPP 的路由总数（静态网段和地址池、按域名学到的各多少）和各出口的路由数，来自 Gate 的路由账本，不包括不在账本里的路由。
- **清空路由：** 停止 Gate，用 `--flush` 撤销账本里的路由并删除 DNS 租约，再启动 Gate。规则和文件不变，不需要确认，也不能回滚。静态网段和 Fake-IP 地址池马上重新安装，按域名学到的真实 IP 路由要等客户端重新查询。不在账本里的路由不受影响。有等待确认的修改时不能清空。
- **DNS：** 每条规则可以单独指定 DNS，写 `IP` 或 `IP:端口`，留空用默认 DNS。添加规则和编辑规则时都能填，编辑时换了出口，DNS 自动带上新出口的默认值（只有 Fake-IP 出口有默认值，其他出口默认留空）。只改 DNS 不改出口也可以，同样走确认流程。Fake-IP 出口必须有 DNS。
- **default：** 规则表最后一行代表所有没匹配到规则的流量，出口和 DNS 都可以修改。出口默认是系统路由表；选了某个出口后，这些流量（包括路由器自己的流量，隧道端点和私网地址除外）都从这个出口出去，出口断开（接口不在或没有 up）期间自动回落到系统路由表，“出口”一栏会标出来。可选的出口除了规则用的出口，还有接口页里设了网关或开了 DHCP 的接口（多个 WAN 时用它指定走哪个口，不选时 VPP 在几条默认路由之间按流分担）；DHCP 接口只能做默认出口，没有租约时也回落。Fake-IP 出口不能选。从 WAN 进来的连接（端口转发、IPsec 服务端等）的回包也会走所选出口，细节见 `tools/vpp-egress-gate/README.md` 的“默认出口”。DNS 是 Gate 的默认上游。
- **优先级：** 就是规则在配置里的顺序，靠前的先匹配，按组移动。
- **域名表和网段表：** 只能查看和修改规则实际引用的 `domain_files`、`ip_range_files`，以及列表目录下的 `*.domains`、`*.ranges` 文件，保留注释和空行。
- **按目的 IP 添加路由：** 新建 `.ranges` 网段表，每行一个地址、CIDR 或 `起始IP-结束IP`，添加规则时可以选择一个或多个网段表，也可以和一个或多个域名表同时用。只选网段表时，地址族由网段表决定。出口的 IPv4 和 IPv6 是两条规则时，要把网段分成 IPv4 和 IPv6 两个文件。网段和其他出口的 Fake-IP 地址池重叠，或没有对应地址族的下一跳时，会在重启 Gate 之前拒绝。

## 接口管理

“接口”页面分网桥和接口两部分。网桥是一个二层网络（比如局域网），在这里设置它的网关地址、加入和移出成员、新建网桥；网关地址在 VPP 里由 BVI（loopback 接口）承载，所以 BVI 不出现在接口表里。接口表是物理口和 VLAN 子接口，可以按 IPv4（静态、DHCP）和 IPv6（静态、SLAAC、DHCPv6）分别设置地址，新建、删除 VLAN 子接口和修改 VLAN ID，切换 up/down 和修改 MTU，把接口设为出口（NAT，第二条上行不用再手写 NAT 配置）。这些操作由 `vpp-interfaces` 执行（见 `tools/vpp-interfaces/README.md`），面板通过 `--interfaces-socket` 转发请求，它没运行时这个页面显示不可用。

每次修改同时写入 VPP 的启动 CLI 文件并立即生效，60 秒内不确认就自动恢复。修改 VLAN ID 要重启 VPP。配置文件里没有的接口（WireGuard、TAP 等）只显示，不能修改。依赖接口地址的其他配置（dnsmasq、Gate、Linux 管理口）不会跟着修改。

## 局域网

“局域网”页面管理 LAN 的 DHCP 和设备，修改由 `vpp-interfaces` 执行（见 `tools/vpp-interfaces/README.md` 的“LAN 的 DHCP”），面板通过 `--interfaces-socket` 转发。安装脚本没有配置 LAN 的 dnsmasq 时，这个页面显示不可用。

- **DHCP**：显示网段、网关和发给设备的 DNS，修改地址池和租期（dnsmasq 重启，DHCP 和 DNS 中断约 1 秒）。DNS 的上游不在这里改：局域网的 DNS 由 Gate 接管时，在路由页 default 行修改。
- **设备**：按设备列出，一台设备可以有几个 MAC 地址（手机连 Wi-Fi 的随机地址），显示主机名、地址、租约、厂商类别和最后出现时间。“详情”里可以命名、拆出 MAC、合并、按提示合并或忽略、设为静态分配和删除。
- **按设备统计流量**（开关，默认关闭）：开启后由 `vpp-interfaces` 在局域网网关接口上挂计数用的 ACL（见它的 README），本程序在每个慢周期（`--slow-interval`）从统计段读每条规则的字节数，算出每个地址的上传和下载速率（`GET /api/lan/traffic`），每个 MAC 的速率作为 `lan/up/<MAC>`、`lan/down/<MAC>` 进入历史，详情里画成曲线。走代理、IPv6 和隧道的流量都算在内，读取不经过 VPP API。规则文件由 `--lan-meter` 指定（默认 `/run/vpp-interfaces/meter.json`）。
- **未开启时的速率和连接数**：来自 NAT 会话，和“出口连接”一样只在页面打开时读取（最多每 5 秒一次），不在后台采集，也不保存历史：读取 NAT 会话的 API 要让 worker 在屏障处暂停。只统计经 NAT 出去的 IPv4 流量：走代理（流量由路由器本机发出）、IPv6 和不经 NAT 的出口都统计不到；一台设备有几个地址时相加。状态“有连接”表示当前有 NAT 会话，“租约中”表示有未过期的租约但没有连接。
- **静态分配**：增删 `MAC,IP[,名字]` 形式的静态分配，其他写法只显示。dnsmasq 重新读取，不中断服务。

## 代理

“代理”页面管理代理入口 sing-box（安装脚本里选装）：显示运行状态和各入口（局域网 SOCKS5、TPROXY、Fake-IP DNS），启动、停止、重启；用向导设置和编辑上游，选协议、填地址和认证信息，不用写 sing-box 配置，“删除”换回拒绝所有代理流量的占位配置；从 sing-box 配置、分享链接或订阅导入节点，导入的节点可以逐个移除或清空，订阅可以删除；测试表单、节点或当前上游能不能通。这些操作由 `vpp-proxy` 执行（见 `tools/vpp-proxy/README.md`），面板通过 `--proxy-socket` 转发，它没运行时这个页面显示不可用。

## 防火墙

“防火墙”页面管理从 WAN 进来的流量：IPv4 端口转发（WAN 端口转给局域网主机，可以是端口段）、开放给路由器本机的端口（同时列出 WireGuard、IPsec 已经开放的）、WAN 上是否响应 ping，以及有状态的 IPv6 入站防火墙和它的放行规则。WAN 接口默认是接口页设为出口（NAT）的接口。这些操作由 `vpp-firewall` 执行（见 `tools/vpp-firewall/README.md`），面板通过 `--firewall-socket` 转发，它没运行时这个页面显示不可用。

修改立即生效并写入 `/etc/vpp/firewall.json`，VPP 重启后由 `vpp-firewall` 装回，没有 60 秒确认：规则只作用在 WAN 上，改错了也不会断开局域网上的面板。开启 IPv6 防火墙或关闭 ping 会在 WAN 上挂 ACL，WAN 进来的每个 IPv4 包也要多查一次，N1 上约 0.36 微秒。局域网里用 WAN 地址访问转发的端口不通，要用内部地址。

## 系统

“系统”页面修改 VPP 和主机的运行参数，由 `vpp-system` 执行（见 `tools/vpp-system/README.md`），面板通过 `--system-socket` 转发，它没运行时这个页面显示不可用。

- 网卡收包：每个接口的收包方式（轮询、中断、自适应）和每个收包队列由哪个线程处理。立即生效，VPP 重启后自动恢复。
- VPP 线程：主线程和 worker 所在的 CPU、调度策略和优先级、DPDK 网卡的收包队列数。改 VPP 的启动文件并立即重启 VPP，60 秒内不确认就恢复。
- CPU 频率：每组 CPU 的 cpufreq 调速器，立即生效，开机时由 `vpp-system` 重新设置。
- NAT44-EI：会话超时立即生效；会话表大小要重启 VPP，和线程一样需要确认。

## VPN 客户端

“VPN”页面显示 WireGuard 和 IPsec 的客户端，只在页面打开时读取，最多每 5 秒一次。

- **WireGuard** 来自 VPP 的 `wg show`（`patches/vpp/0002`），没有这个命令时改读原版的 `show wireguard peer`，页面只显示节点和地址，不显示在线状态、握手和流量。`wg show` 提供：公钥、内网地址、公网地址、最近握手和累计流量，3 分钟内有握手算在线。`wg show` 的流量是取整到 0.01 GB 的文字，所以不显示速率。结果只取已知字段，私钥不会进入面板。可以用 `--vpn-names` 指定一个 JSON 文件给客户端命名，比如 `{"公钥":"手机"}`。
- **添加和删除 WireGuard 节点**由 `vpp-wireguard` 执行（见 `tools/vpp-wireguard/README.md`），面板通过 `--wireguard-socket` 转发请求，它没运行时页面不显示这些按钮。添加时填接口、客户端自己生成的公钥和内网地址，地址必须是该接口网段内没被占用的单个地址（`/32` 或 `/128`）。修改立即生效并写入 VPP 启动时加载的文件，不重启 Gate，也没有 60 秒确认。默认路由的节点是上游隧道，不能删除。名字保存在 `--vpn-names` 文件里，`vpp-wireguard` 的 `--names` 要指向同一个文件。IPv6 地址依赖 `wg0-nat66.json` 这类按节点列出的 NAT66 策略时，新节点要另外加进策略。
- **WireGuard 配置**：粘贴 wg-quick 格式的配置，或用“导入配置”选择（拖入）标准 `.conf` 文件，名字默认取文件名，保存后可以启动、停止或删除。保存后不会自动启动，启动过的配置在 VPP 重启后自动恢复。需要运行中的 `vpp-wireguard`，细节见它的 README。
- **IPsec** 来自 strongSwan 的 `stroke statusall`：用户身份、虚拟地址、公网地址和连接时长。charon 用非默认 socket（比如运行在独立命名空间里）时，用 `--ipsec-socket unix:///run/rk3588-strongswan/charon.ctl` 指定。没有流量计数时显示“—”。

## 历史

| 分辨率 | 时长 |
|---|---|
| `--interval`（1 秒） | 15 分钟 |
| `--slow-interval`（10 秒） | 3 小时 |
| 1 分钟 | 24 小时 |
| 5 分钟 | 7 天 |

历史只放在内存里，避免持续写 eMMC 或 SD 卡，**监控进程或主机重启后清空**，VPP 重启不影响。粗粒度上的值是该时间段内的平均值，短时尖峰会被抹平。从未出现过非零值的序列不占存储。

计数器变小（VPP 重启、`clear interfaces`）时，这一段时间显示为断点，不会画出尖峰。VPP 崩溃后 socket 文件还在时，下一次慢周期读取会发现连接被拒绝，最多延迟一个 `--slow-interval`，这段时间接口流量显示为 0。VPP 卡死但 socket 仍可连接时，要等 `--stale-after`。

## 实测开销

N1（Amlogic S905D，4 核 A53，VPP 26.06，1 个 worker，5 个接口，78 条序列），默认参数，含主机指标：

| 项目 | 结果 |
|---|---|
| CPU，无人查看 | 单核的 0.97% |
| CPU，一个页面每 2 秒刷新 | 单核的 1.43% |
| 进程内存 RSS | 约 12 MiB（启动后约 2 分钟），历史写满前会随非零序列增长 |
| VPP 重启后恢复 | 自动重连 |
| `kill -9` 后发现并恢复 | 2 秒发现，VPP 就绪后自动恢复 |

GoVPP 0.13 和 0.14-alpha 不认识 VPP 的 gauge 类型，会把 `/sys/vector_rate`、`/sys/input_rate`、`/sys/num_worker_threads` 和 `/buffer-pools/*` 读成空值，所以 `gauges.go` 直接按 `vlib/stats/shared.h` 的格式读取这些条目。

## 接口

| 路径 | 内容 |
|---|---|
| `GET /api/status` | 当前值 |
| `GET /api/series?range=<秒>&key=<序列>&key=...` | 历史，空缺为 `null`，一次最多 64 个序列 |

接口行里的 `label` 是便于阅读的名字，只用于显示，序列和选择仍按 VPP 的接口名：TAP 和 TUN 用 Linux 侧的名字，和其他接口重名时显示为 `名字 (tapN)`；loopback 显示为 `loopN (地址)`，优先用 IPv4。

没有地址、不在桥上、计数器也全为 0 的 loopback 只是 NAT 或路由配置里的占位接口，接口行带 `hidden`，不出现在接口表和下拉框里。它一旦有流量或错误计数就会重新显示。

这些信息从 API socket 用短连接读取：接口列表变化或 VPP 重启时读一次，1 分钟后再读一次，之后每 5 分钟读一次。

序列名形如 `if/<接口>/rx_bps`、`sys/input_rate`、`sys/worker/<线程>/vector_rate`、`buf/<池>/used`。

## 测试

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o dist/vpp-monitor.test .
# 把 dist/vpp-monitor.test 复制到 Linux 主机上运行
```

页面用到的 uPlot 1.6.32 在 `web/` 里（MIT，见 `web/uPlot.LICENSE`），打包进程序，不需要外网。
