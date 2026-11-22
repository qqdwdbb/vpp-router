# VPP Egress Gate 使用手册

本文适用于 `tools/vpp-egress-gate` 构建的 Go 程序。文中的安装路径、systemd
服务名、接口和地址均为示例，部署到不同设备时应替换为实际值。

Gate 转发 DNS 查询，并在真实地址应答命中分流规则时，通过 VPP Binary API
提交目的地址路由。提交成功后才释放应答；失败则返回不含记录的 SERVFAIL。
Fake-IP 规则在启动时安装整个地址池路由，查询时不新增主机路由或租约。

本程序原名 `dns-route-gate`，手动迁移现有部署时对照下表。配置里写明的路径和 `--config` 指定的文件照常生效，不必搬动。

| 旧 | 新 |
|---|---|
| 程序 `dns-route-gate-go` | `vpp-egress-gate` |
| `dns-route-gate.service`、`dns-route-gate-links.service` | `vpp-egress-gate.service`、`vpp-egress-gate-links.service` |
| 默认配置 `/etc/vpp/dns-route-gate.json` | `/etc/vpp/egress-gate.json` |
| `/var/lib/dns-route-gate/`（设备记录、生成的配置、VPP 片段） | `/var/lib/vpp-egress-gate/`，VPP 启动 CLI 的 `exec` 行也要跟着改 |
| 默认 `state_file`、`state_socket`（`vpp-nft-route-sync` 目录） | `/var/lib/vpp-egress-gate/state.json`、`/run/vpp-egress-gate/state.sock` |
| 排他锁 `/run/lock/vpp-nft-route-sync.lock` | `/run/lock/vpp-egress-gate.lock` |
| `90-dns-route-gate.conf`、`10-dns-route-gate.network` | `90-vpp-egress-gate.conf`、`10-vpp-egress-gate.network` |
| nft 表 `dns_route_gate`、`dns_gate_linux` | `egress_gate`、`egress_gate_linux` |

排他锁改名后，新旧程序不再互斥，须先停旧程序。新程序不管旧表，旧表留着会继续生效，停掉旧程序后要手动删除；表里如有自己加的规则，先确认还需不需要：

```sh
sudo nft delete table inet dns_gate_linux
sudo nft delete table inet dns_route_gate
```

## 1. 运行条件与构建

设备的 Linux 端、VPP、Gate 三者独立。VPP 和设备互不依赖，谁先启动都可以：

```text
vpp-egress-gate-links（oneshot） ──> vpp-egress-gate <── VPP
```

设备是持久的 TAP，VPP 只是接上去（`attach persist`）。VPP 重启或崩溃不影响 Linux 端的设备、地址、路由和规则；
期间设备没有载波，流量不通，也不会转到其他接口。VPP 先于 oneshot 启动时，它的 attach 会创建设备，oneshot 随后补上配置；
在此之前只影响走这些设备的分流，其他转发不受影响。

Gate 必须等 oneshot 完成，它失败时 Gate 不启动：进入设备的路由都由 Gate 提交，而没有防火墙规则的设备不能承载流量。
因此**不要在 VPP 启动 CLI 里手写指向这些设备的静态路由**，路由都交给 Gate。

Gate 可以先于 VPP 启动。VPP 还不可用，或路由要用的 VPP 接口还不存在（比如启动 CLI 没执行完）时，Gate 不退出，每秒检查一次，一直等下去。
**等待期间 Gate 不监听 DNS**，就绪后才开始。日志里看到的是：

```text
waiting for VPP: stat /run/vpp/cli.sock: no such file or directory
VPP is ready after 12s (11 failures)
```

相同的错误只打印一次，之后每分钟报告一次重复次数；后台协调失败时同样如此，恢复后打印 `background reconciliation recovered`。

构建目标 Linux 架构的程序后，在目标设备执行一次：

```sh
sudo python3 install.py --binary dist/vpp-egress-gate-linux-arm64 --dry-run
```

去掉 `--dry-run` 执行安装。`install.py` 要求 systemd，不依赖特定的网络管理器，只需 `nft` 命令，不使用 `nftables.service`。

`/etc/vpp/egress-gate.json`（可用 `--config` 指定）不存在时，脚本询问你的网络情况并生成配置；已存在时直接使用，不再询问。哪个接口接客户端、哪个接口是出口，只有部署者清楚，所以脚本不做判断，只列出现有接口和地址，选择时填序号、接口名或接口地址都可以：

| 询问的内容 | 对应参数（可重复的写多次） | 没有终端且没写参数时 |
|---|---|---|
| 客户端网段，比如 `10.61.30.0/24` | `--lan-prefix` | 报错 |
| Gate 的上游 DNS，回车使用 `/etc/resolv.conf` 的第一个 nameserver | `--upstream` | 报错 |
| VPP 出口和下一跳，每个地址族一个 | `--vpp-exit wg1=10.62.30.1,fd00::1` | 不生成 |
| Linux 出口和网关。直连对端的隧道不写网关；多个 IPv4 网关生成多条规则；直连隧道要带 IPv6 时写 `ipv6` | `--linux-exit wg0`、`--linux-exit eth1=192.0.2.1,fe80::1`、`--linux-exit wg0=ipv6` | 不生成 |
| 是否劫持客户端自己设置的公网 DNS（比如 8.8.8.8，见下文），回车表示开启；只在能生成 `hijack_vpp` 时询问 | `--hijack-public-dns`、`--no-hijack-public-dns` | 开启 |
| 代理客户端 TPROXY 入站的监听地址和端口；监听所有地址时只填端口。客户端网段有 IPv6 又写了地址时，两个地址族各填一个 | `--tproxy 127.0.0.1:7893`、`--tproxy 127.0.0.1:7893,[::1]:7893`、`--tproxy 7893` | 端口 2082，不限地址 |
| 代理客户端 Fake-IP DNS 的地址和端口 | `--fake-dns 127.0.0.1:5354` | `127.0.0.1:5354` |
| Gate 自己监听 DNS 的端口（客户端发往 53 的查询重定向到这里）；不询问 | `--listen-port 10053` | 1053 |

写了参数的项不再询问。客户端所在的接口不能作为出口，列表里不编号。填错时只重问这一项。填写的网段不在任何 VPP 接口上时，脚本会提示检查。

以下内容从系统读取，不询问：

| 配置项 | 来源 | 读不到时 |
|---|---|---|
| `vpp_service` | 正在运行 `vpp` 的 systemd 服务 | 报错，须写 `--vpp-service` |
| `vpp_socket`、`api_socket` | VPP 启动文件的 `cli-listen`、`socket-name` | 用默认值 |

**DNS 默认经过 Gate。** 规则只在 Gate 里维护一份，LAN 的 DNS 服务只作为上游，不放规则。机器上有接口的地址落在 `lan_prefixes` 内时（比如接在 VPP 局域网网桥上的接口，下例中是 `lan0`），生成的配置写入：

```text
"listen": [["127.0.0.1", 1053], ["10.61.30.2", 1053]],
"hijack_dns": true,
"hijack_interfaces": ["lan0"]
```

发到这些接口的 53 端口查询（TCP 和 UDP）会被重定向到 Gate，客户端不用改设置。`listen` 列出接口的所有全局地址，因为重定向的目标是内核选的入接口地址。这些地址是生成时的快照，变化后要手动更新 `listen`。同时生成 `hijack_vpp`（比如 `[{"interface": "loop0", "via": ["10.61.30.2"], "sources": ["10.61.30.0/24"]}]`）：VPP 用 ACL 和 ABF 把这些客户端发往任意地址的 53 端口查询先送到 Linux，再由上面的规则交给 Gate，所以手动设置了公网 DNS 的客户端也会经过 Gate。这一项是可选的：脚本先说明作用和限制（客户端自选的 DNS 不再起作用、DoH/DoT 不受影响、LAN 客户端的每个包多一次 ACL 匹配），再询问，回车即开启；不开启时不写 `hijack_vpp`，发到本机的查询仍然经过 Gate。回包的来源地址由 conntrack 还原。这需要两个条件，不满足时 Gate 照常运行，`install.py` 和日志（`DNS sent elsewhere is not going through Gate`）会提示，这时只有发给 Linux 的查询经过 Gate：

- VPP 加载了 `acl`、`abf` 插件。
- NAT44 在 WAN 上用 `output-feature`。写 `set interface nat44 ei in LAN out WAN` 时，NAT 排在 ABF 之前，源地址已被改写，ACL 匹配不到客户端，VPP 也不能调整这个顺序。要改的话，把启动 CLI 里这一行换成 `set interface nat44 ei out WAN output-feature`，重启 VPP。

DoH、DoT 不会被劫持。

当 `hijack_vpp.interface` 同时列在 `lan_interfaces` 中时，Gate 会把该接口当前的 IPv6 前缀加入 DNS 劫持的来源范围，并在前缀变化时更新 ACL。Linux 本机的 IPv6 源地址会排除，避免上游 DNS 查询循环。

`hijack_vpp` 的可选字段 `via_interface` 指定通向 Linux 下一跳的 VPP 接口。默认与 `interface` 相同；VPN 入接口与 Linux 所在 LAN 不同时，可用 `{"interface":"wg0","via_interface":"loop0","via":["10.61.30.2"],"sources":["10.10.0.0/24"]}`，避免把 DNS 下一跳错误地送回隧道。该选项不改变非 DNS 流量的路由。

没有这样的接口时不开启劫持，Gate 只监听 `127.0.0.1:1053`，而不经过 Gate 的域名不会下发路由，`install.py` 结束时会提示。已存在的配置不会被修改；`listen` 只有回环地址且没开 `hijack_dns` 时同样提示，本机已有解析器转发给 Gate 时可以不管。Gate 退出时撤掉两侧的劫持，被强杀时规则留到下次启动，这期间 LAN 的 DNS 不通，服务 5 秒后重启。

VPP 启动 CLI 文件取自启动文件的 `exec`，读不到时须写 `--vpp-cli-file`。多条物理上行可以各自作为出口分流。

询问时列出的是有地址的接口：VPP 这边来自 `show interface addr`，Linux 这边是已启动、有全局地址的网卡，不含回环和本程序生成的设备（`tap-*`、`gw-*`、`gm-*`、`gate-tproxy`）。列表只是参考，不代表它们适合做出口，比如容器网桥和 VPP 自己的 TAP 也可能列在里面。

VPP 出口的下一跳：普通接口填网关地址；WireGuard 隧道填对端的隧道地址，配置里没有时填同网段里本机以外的地址，比如本机是 `10.14.0.2/16` 就填 `10.14.0.1`，这个地址要落在对端的 `AllowedIPs` 内。一个接口下有多个对端（WireGuard 服务端）时，下一跳只对应其中一个对端。Linux 的 WireGuard 隧道不需要网关，直接回车。

只有填写的客户端网段里有 IPv6 时才能填 IPv6 下一跳和网关，这时 TPROXY 模板也加上地址池 `2001:2::/48`。Linux 出口带 IPv6 时生成 `"ipv6": true`。

生成的规则都写明 `owner`，同名的 Linux `wg1` 和 VPP `wg1` 也不会混淆。每个出口生成一条规则和一个空的域名文件：Linux 出口是 `/etc/vpp/gate/<出口>.domains`，默认开启 `masquerade`，对端已有回到 LAN 的路由时可关掉；
VPP 内部出口是 `/etc/vpp/gate/vpp-<接口>.domains`，规则名是 `vpp-<接口>`，只提交 VPP 路由，不涉及 Linux 设备和防火墙。

**规则为空就不生效**：同步时跳过，不进入 Gate 配置，Linux 出口也不创建设备。这是有意的，因为 Linux 接口一旦成为出口，转发就受限（只放行回包和 DNAT），`rp_filter` 也被改成 0，
经它转发的其他流量（如 WireGuard 服务端、站点互联）会中断。所以安装时不创建出口，也不改 `ip_forward` 和 `rp_filter`。确认某个接口用作出口后再加规则，把管理用的网卡设为出口前尤其要想清楚；用不到的规则可以留空或删除：

```sh
echo example.org | sudo tee -a /etc/vpp/gate/wg1.domains
sudo systemctl restart vpp-egress-gate
```

生成的配置总有一条 TPROXY 规则 `proxy`，域名文件是 `/etc/vpp/gate/proxy.domains`：透明代理只是一个监听端口的程序，无法可靠检测，所以总是给出这条规则，
TPROXY 入站和 Fake-IP DNS 的地址、端口按询问的回答填写。代理客户端（比如 mihomo、sing-box、xray）要开启 TPROXY 入站和 Fake-IP DNS，Fake-IP 网段设成 `198.18.0.0/15`
（LAN 有 IPv6 时再加 `2001:2::/48`）。规则为空时同样不生效。要使用时启动代理客户端，再加域名并重启 Gate，此时生成 TAP 设备 `gate-tproxy`。代理客户端未运行时，这些域名的 DNS 查询或连接会失败。

规则清空后重启 Gate，Gate 会撤掉它提交的 VPP 路由，Linux 出口的设备按删除处理。同步会跳过所有空规则；不经过同步直接让 Gate 加载时，Gate 仍要求每条规则有内容。

脚本只做一次性工作：
安装程序到 `/usr/local/bin/vpp-egress-gate`，写入两个 systemd 单元和网络管理器配置（networkd 配置会让它不再清理外来路由和策略规则），运行一次 `--sync-devices`，
并在 VPP 启动 CLI 文件（原文件备份为 `.gate-backup`）末尾加一行
`exec /var/lib/vpp-egress-gate/vpp-devices.cli`。它不重启 VPP，也不修改已有的 `egress-gate.json`。可以重复运行，用于升级程序；重复运行也会应用当前的 JSON，且不会重启 Gate，完成后须手动重启 Gate 才会用上新程序和新单元。

### 两个模式

| | `--setup-links` | `--config FILE --sync-devices` |
|---|---|---|
| 何时运行 | 每次开机（`vpp-egress-gate-links.service`） | 改完配置后手动运行 |
| 输入 | 只读上次同步的记录，不读你的 JSON | 你的 JSON |
| Linux 端 | 设备、地址、回程路由、策略规则、固定防火墙规则 | 同左 |
| VPP 端 | 不碰 | 改写静态片段，并把缺少的设备热添加到运行中的 VPP |
| Gate 配置 | 不碰 | 重新生成 |

两者重复运行都安全。`--sync-devices` 加 `--dry-run` 只打印计划。

配置文件是唯一来源，且只读：**没有写 `interface`** 的规则由它生成设备，已写的（如 VPP 原生接口或已有设备）不受影响。详见第 8 节。
开机不同步，JSON 写错或改到一半都不影响开机，机器总是按上一次成功的同步起来；相应地，改 JSON 后要重启 Gate 才生效。

| 文件 | 内容 |
|---|---|
| `/etc/vpp/egress-gate.json` | 你的规则，须包含 `upstream` 和 `lan_prefixes`；安装时可按回答生成 |
| `/etc/vpp/gate/*.domains` | 生成的配置引用的域名文件，初始为空 |
| `/var/lib/vpp-egress-gate/devices.json` | 上次同步的记录，按设备名保存编号，增删其他规则时已有设备的编号不变；不要删除 |
| `/var/lib/vpp-egress-gate/vpp-devices.cli` | VPP 静态片段 |
| `/var/lib/vpp-egress-gate/fixed.nft` | 固定防火墙规则 |
| `/var/lib/vpp-egress-gate/gate.json` | 补全后的配置，Gate 服务读取它 |

改了 JSON 或列表文件，不用分辨改了什么，重启 Gate 就行，它启动前会先同步：

```sh
sudo systemctl restart vpp-egress-gate
```

服务启动前运行 `--sync-on-start`，它做的就是 `--sync-devices`，只有两点不同：

- **同步失败不阻止启动。** 比如 JSON 写错，Gate 仍按上一次成功的同步启动，DNS 不中断，但你的改动没有生效。`systemctl restart` 这时也返回成功，要用下面的命令确认，错误写在日志里：

  ```sh
  sudo journalctl -u vpp-egress-gate -n 20 --no-pager | grep 'not applied'
  ```

- **开机时不同步。** 开机总是按上一次同步起来，也避开和 VPP 启动 CLI 同时创建设备。开机后要应用改动，重启一次 Gate。

列表文件有问题时，Gate 忽略有问题的部分，其余照常启动，并打印警告：

| 问题 | 忽略范围 |
|---|---|
| 某一行写错 | 这一行 |
| 文件不存在或读不了 | 这个文件 |
| 规则的所有列表文件都没有可用内容 | 这条规则，它暂时不生效 |

**被忽略的域名和地址会走默认路由，不再走这条规则的出口。** 这些流量不会被拦下，需要走隧道的域名此时可能直连，所以要留意日志。修好文件后重启 Gate。写在 JSON 里的内容（比如 `domains`）出错仍按配置错误处理。

重启时的同步也按这个规则处理列表文件，其他改动照常生效。想严格检查，运行下面的命令，手动的 `--sync-devices` 和 `install.py` 遇到这些问题都会报错：

```sh
sudo vpp-egress-gate --config /etc/vpp/egress-gate.json --sync-devices --dry-run
```

手动运行 `--sync-devices` 仍然可用，它不重启 Gate，Gate 下次启动才读取新配置。

| 场景 | 需要重启 VPP 吗 |
|---|---|
| 新增出口，或给空规则加上内容：重启 Gate 时热添加 | 不需要 |
| 只改已生效规则的 `domain_files` | 不需要 |
| 删除出口：回程路由和策略规则立即撤掉，防火墙继续丢弃其流量。VPP 接口和设备留到 VPP 释放后的下一次同步或开机才删除，避免在线删除 VPP 接口 | 可选 |

单文件配置缺少 `listen`、`state_file`、`lease_file`、`overlap_policy`、`exclude_prefixes` 时，生成的配置会补上默认值；已写的保持不变。
拆分配置中 `route_config`、`domain_routes_file` 须为绝对路径。`domain_routes_file` 的内容会合并进生成的配置；`route_config` 仍只是引用，Gate 启动时读取原文件。VPP 的 systemd 服务名不是
`vpp.service` 时在配置中写 `vpp_service`。默认 `exclude_prefixes` 排除私网、回环和链路本地网段，LAN 为公网地址时也一并排除；
需要把内网域名分流到某出口时，须调整它。等待 VPP 不算失败；其他原因导致 Gate 退出时，每 5 秒重试，不受启动次数限制。

**`ip_forward` 对整台机器生效。** Gate 的规则只管自己的设备和出口，从其他网卡进来的转发流量由系统防火墙负责。机器原本没开转发时，第一个出口生效后，把这台机器设为网关的邻居就能到达它的其他网络和出口对端（隧道另一侧）。
所以 Gate 打开转发时，如果 `iptables`、`ip6tables` 或 nftables 都没有默认丢弃转发流量，会打印警告。要堵上时把默认策略改为丢弃，Gate 会自己放行它的设备：

```sh
sudo iptables -P FORWARD DROP
```

这条命令重启后失效，需要用你平时持久化防火墙的方式保存。Gate 不替你设置，因为机器上其他程序可能也依赖转发。

固定防火墙规则由 `nft -f` 写入，先于启用设备。系统有 `iptables` 时（开了 IPv6 的出口还包括 `ip6tables`），配置了 `linux_exit` 的 Gate 在启动时和每次后台协调时确认 `FORWARD` 链放行从各出口设备进入的流量和发往它们的回包，
否则默认丢弃的链会挡住转发。报文须同时通过 iptables 和 nftables，分类和拦截仍由 nftables 决定。
防火墙工具恢复规则清掉它们后，下一次协调（默认最多 60 秒）补回，此前流量被丢弃。

Fake-IP 还需要独立运行的 DNS 和透明代理程序。系统其他防火墙链也须允许相关流量。

- Linux、systemd，以及已运行且 API 版本兼容的 VPP。
- VPP 的 API socket、CLI socket 可访问；规则中写明的 VPP 接口及下一跳已准备好（没写 `interface` 的规则由设备同步生成）。
- 全局 DNS 上游、规则指定的 DNS 上游均可达，监听地址已经配置在 Linux 上。
- 运行账户能访问 VPP、创建锁及状态文件，并执行所需的 nftables 操作；通常使用 root。
- PATH 中提供 `ip`、`vppctl`、`systemctl`、`nft`。
- Fake-IP 场景还需要独立运行的 Fake-IP DNS 和透明代理。Gate 服务本身不创建代理进程、设备
  或 Linux TPROXY 所需的策略路由；没写 `interface` 的 Fake-IP 规则由设备同步生成设备和策略路由，见第 7 节。

本程序只在 Linux 上运行，但在任何平台上都能编译。在本目录执行 `make`，生成 Linux arm64 和 x64 两个程序：

```sh
cd tools/vpp-egress-gate
make              # dist/vpp-egress-gate-linux-arm64 和 dist/vpp-egress-gate-linux-amd64
make ARCHES=arm64 # 只生成一个架构
make clean
```

也可以直接用 `go build`，非 Linux 系统上要指明目标，否则会报 `this_program_only_supports_Linux`：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /tmp/vpp-egress-gate ./cmd/vpp-egress-gate
```

测试须在 Linux 上运行（`go test ./...`）；在其他系统上可以先交叉编译测试程序，再拿到 Linux 上运行：`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o gate.test .`。

Go 版本要求以 [go.mod](go.mod) 为准。构建产物不会自动安装或重启服务。

## 2. 命令行用法

```text
vpp-egress-gate [--config CONFIG.json]
vpp-egress-gate --config CONFIG.json --sync-devices [--dry-run]
vpp-egress-gate --config CONFIG.json --flush [--dry-run]
vpp-egress-gate --setup-links
vpp-egress-gate --help
```

| 参数 | 默认值 | 作用 |
|---|---|---|
| `--config PATH` | `/etc/vpp/egress-gate.json` | 读取入口 JSON 配置并启动服务 |
| `--sync-devices` | 关闭 | 应用 `--config` 指向的 JSON：配置设备的 Linux 端，改写 VPP 静态片段并热添加设备，生成 Gate 配置，然后退出 |
| `--flush` | 关闭 | 撤销 Gate 运行时的改动后退出，须先停止 Gate，见第 11 节 |
| `--dry-run` | 关闭 | 只能与 `--sync-devices` 或 `--flush` 同用，打印计划，不改动系统 |
| `--sync-on-start` | 关闭 | 服务在启动 Gate 前运行，等同 `--sync-devices`，但开机时跳过，配置文件不存在时也跳过 |
| `--setup-links` | 关闭 | 按上次同步的记录恢复设备的 Linux 端，然后退出；不读 JSON，也不碰 VPP |
| `-h`、`--help` | — | 显示参数帮助；当前入口输出帮助后退出码为 1 |

`-config PATH`、`--config=PATH` 同样有效。无需位置参数。当前没有 `--check`、
`--reload`、`--version` 或单独设置监听地址的命令行参数。

前台启动示例：

使用设备同步时，服务读取生成的配置；你写的 JSON 里没有 `interface` 的规则，Gate 无法直接加载：

```sh
sudo /usr/local/bin/vpp-egress-gate --config /var/lib/vpp-egress-gate/gate.json
```

规则都写明 `interface` 和 `via` 时，可以直接用入口 JSON：

```sh
sudo /usr/local/bin/vpp-egress-gate \
  --config /etc/vpp/egress-gate.json
```

程序保持前台运行，日志写入标准错误。SIGINT / SIGTERM 触发正常退出及账本保存。
使用 systemd 管理时，通过 `systemctl` 操作服务；不要同时手动启动第二个实例。
实例共用 `/run/lock/vpp-egress-gate.lock` 排他锁。

## 3. 配置加载与路径规则

支持两种组织方式：

1. **单文件配置**：入口 JSON 同时包含监听参数、VPP 参数和 `routes`。
2. **拆分配置**：入口 JSON 用 `route_config` 引用运行参数文件，用
   `domain_routes_file` 引用域名出口文件。

加载顺序：

```text
--config 指定的入口 JSON
  ├─ listen / upstream / lease_file 等入口参数
  ├─ route_config → VPP、状态及路由参数；未指定则读取入口 JSON
  └─ domain_routes_file → routes；未指定且入口含 routes，则读取入口 JSON
```

`routes` 的 `domain_files`、`ip_range_files` 写绝对路径或文件名：只写文件名（如 `wg1.domains`）时在
`/etc/vpp/gate` 下查找，带目录的相对路径会被拒绝。`route_config`、`domain_routes_file`、
状态文件及 socket 等顶层路径不会自动相对入口文件解析，建议全部使用绝对路径；
相对路径会受进程工作目录影响。

配置和列表文件仅在启动时加载。修改后必须重启 Gate；后台租约协调不重新读取配置。
JSON 使用标准语法，不支持注释或尾逗号。未知字段在同步时报错（包括重启 Gate 前的同步和安装），并提示可能的正确写法，一次列出所有问题；这时改动不生效，Gate 按上次同步启动。Gate 直接加载配置时只警告，因为它没有上一次配置可以退回。`linux_exit` 里的未知字段一直会报错。

## 4. 单文件配置示例

以下示例假设 `10.61.20.2` 已配置在 Linux 上，dnsmasq 监听其 53 端口，
VPP 中存在 `wg1` 接口，下一跳为 `10.62.30.1`。
保存为 `/etc/vpp/egress-gate.json`：

```json
{
  "listen": [["10.61.20.2", 1053]],
  "upstream": ["10.61.20.2", 53],
  "lease_file": "/var/lib/vpp-egress-gate/dns-leases.json",
  "state_file": "/var/lib/vpp-egress-gate/state.json",
  "vpp_socket": "/run/vpp/cli.sock",
  "api_socket": "/run/vpp/api.sock",
  "vpp_service": "vpp.service",
  "overlap_policy": "first",
  "dns_upstream_policy": "first",
  "routes": [
    {
      "name": "altroute",
      "interface": "wg1",
      "via": "10.62.30.1",
      "domain_files": ["altroute.domains"]
    }
  ]
}
```

创建 `/etc/vpp/gate/altroute.domains`，每行一个域名，匹配自身及子域名：

```text
# 示例域名，替换为实际需要分流的域名
example.org
example.net
```

这里的规则都写明了 `interface`、`via`，可以直接由 Gate 加载；配合 `install.py` 或设备同步使用时，还须加上 `lan_prefixes`。更多出口示例见
[example/egress-gate.json](example/egress-gate.json)。

## 5. 拆分配置示例

入口 `/etc/vpp/egress-gate.json`：

```json
{
  "listen": [["10.61.20.2", 1053]],
  "upstream": ["10.61.20.2", 53],
  "lease_file": "/var/lib/vpp-egress-gate/dns-leases.json",
  "route_config": "/etc/vpp/gate-runtime.json",
  "domain_routes_file": "/etc/vpp/dns-route-domains.json"
}
```

运行参数 `/etc/vpp/gate-runtime.json`：

```json
{
  "vpp_socket": "/run/vpp/cli.sock",
  "api_socket": "/run/vpp/api.sock",
  "vpp_service": "vpp.service",
  "state_file": "/var/lib/vpp-egress-gate/state.json",
  "overlap_policy": "first",
  "dns_upstream_policy": "first",
  "monitor_resync_seconds": 60,
  "max_routes": 10000,
  "idle_seconds": 604800
}
```

域名出口 `/etc/vpp/dns-route-domains.json`：

```json
{
  "routes": [
    {
      "name": "altroute",
      "interface": "wg1",
      "via": "10.62.30.1",
      "domain_files": ["altroute.domains"]
    }
  ]
}
```


## 6. 配置字段参考

### 6.1 入口参数

这些字段放在 `--config` 指定的入口 JSON 中。

| 字段 | 类型 / 默认值 | 说明 |
|---|---|---|
| `listen` | `[[地址, 端口], ...]` | 应配置至少一个本机地址；每个地址同时监听 UDP、TCP |
| `upstream` | `[地址, 端口]`，必填 | 未选择专用上游时使用的 DNS；配置加载和面板保存时拒绝指向 Gate 自身监听端点的上游，规则 DNS 同样检查。同机不同端口（如 Fake-IP DNS `127.0.0.1:5354`）允许 |
| `lan_prefixes` | 网段数组（IPv4、IPv6 均可），设备同步必填 | VPP 后方的客户端网段，用于生成回程路由；只有设备同步读取，Gate 服务不使用，也不写入生成的配置 |
| `lan_interfaces` | VPP 接口名或数组，可省略 | 局域网所在的 VPP 接口（如 `loop0`）。Gate 运行时每 2 秒读取这些接口上的 IPv6 前缀（全球单播和 ULA，不含链路本地），当作客户端网段，变化时更新 Linux 的回程路由和主表路由，适合运营商委派、会变的前缀。读到的前缀记在 `/run/vpp-egress-gate/lan-prefixes.json`，设备同步和重启时保留；VPP 暂时读不到时路由保持不变，前缀撤销后对应路由删除。设置后即使 `lan_prefixes` 没有 IPv6 网段，生成的出口也可以开 IPv6。IPv4 仍只来自 `lan_prefixes` |
| `lease_file` | 路径，应显式配置 | DNS 观察租约账本，正常停止时保存 |
| `route_config` | 路径，可省略 | 运行参数文件；省略时使用入口 JSON |
| `domain_routes_file` | 路径，可省略 | 出口规则文件；入口含 `routes` 时可省略 |
| `hijack_dns` | 布尔值，不写时 `false`；生成的配置可能写 `true`，见第 1 节 | 启用指定 Linux 接口上的客户端 TCP/UDP 53 重定向 |
| `hijack_interfaces` | 字符串或字符串数组 | 开启劫持时必填，例如 `["br-mgmt"]`；所有 `listen` 须使用同一端口 |
| `hijack_vpp` | 对象数组，可省略 | 需要 `hijack_dns`。每项有 `interface`（VPP 入接口）、`via`（该接口网段上的 Linux 地址，每个地址族一个）、`sources`（客户端网段），让 VPP 把这些客户端的 53 端口查询送到 Linux。Linux 自己的地址不受影响 |

若启用 DNS 劫持，确认已使用的 nftables 规则不会与 Gate 重复重定向；它不劫持 DoH / DoT。

### 6.2 VPP 与路由运行参数

这些字段放在 `route_config` 指向的文件中；单文件模式下放在入口 JSON 中。

| 字段 | 默认值 | 说明 |
|---|---|---|
| `api_socket` | `/run/vpp/api.sock` | 持久 Binary API 连接，路由提交使用此 socket |
| `vpp_socket` | `/run/vpp/cli.sock` | VPP CLI socket |
| `vpp_service` | `vpp` | 用于识别 VPP 运行代次；应填写实际的 VPP systemd 服务名 |
| `state_file` | `/var/lib/vpp-egress-gate/state.json` | 路由归属和待提交账本 |
| `state_socket` | `/run/vpp-egress-gate/state.sock` | 提供当前账本的本地 Unix socket |
| `monitor_resync_seconds` | `60` | 后台协调间隔，范围 1–3600 秒；不表示配置重载或 FIB 审计间隔 |
| `max_routes` | `10000` | 受管理路由数量限制，范围 1–1000000 |
| `idle_seconds` | `604800` | DNS 观察租约空闲期限，范围 0–7776000 秒；0 表示不按空闲期限过期 |
| `exclude_prefixes` | 空数组 | 禁止管理的前缀列表，例如 LAN、回环和链路本地网段；规则命中时返回 SERVFAIL。设备同步未见此项时默认生成私网、回环和链路本地网段 |
| `lock_files` | 两个 WireGuard 导入锁 | 接口重建协调锁；只有确认无需与接口导入器协调时才设为 `[]` |
| `overlap_policy` | `error` | `error` 拒绝出口冲突；`first` 按出口顺序处理已观察到的重叠地址 |
| `dns_upstream_policy` | `first-upstream` | `first-upstream` 选择首个带专用 DNS 的匹配规则；`first` 使用首个匹配规则，无专用 DNS 时走全局上游 |

默认 `lock_files` 为 `/run/lock/vpp-wireguard-client-import.lock` 和
`/run/lock/vpp-wireguard-import.lock`。
`interval_seconds`、`fib_audit_seconds` 是仍被解析的兼容字段；当前 Go 服务循环
固定每 2 秒检查一次后台协调时机，且不自动审计 FIB，不能用这两个字段启用查询期间的 FIB 校验。

### 6.3 域名出口规则

以下字段位于 `routes` 数组的每个对象中。数组前面的出口具有更高顺序优先级，
不是按域名后缀长度重新排序。

| 字段 | 类型 / 默认值 | 说明 |
|---|---|---|
| `name` | 必填字符串 | 唯一出口名，允许字母、数字、下划线、连字符 |
| `interface` | 字符串；Gate 加载时必填 | VPP 出口接口名，不是 Linux 接口名。带 `linux_exit` 或 Fake-IP 的规则省略它时，由设备同步生成设备并填入 |
| `owner` | `host` 或 `vpp`，可省略 | 出口网卡归属。`host` 是 Linux 网卡，写 `linux_exit`；`vpp` 是 VPP 内部接口，写 `interface` 和 `via`。设备同步会校验是否相符（规则为空时也校验），省略时按规则形式判断。只有设备同步读取，不写入生成的配置 |
| `exit` | 字符串，可省略 | 出口名，管理服务在一个 `interface` 上有多个出口（不同下一跳）时写上，用来区分。Gate 按 `interface` 和 `via` 选路，不读取它 |
| `ipv6` | 布尔，省略时跟随出口 | 只用于生成设备的 `linux_exit` 规则：同时生成 IPv6 中转地址、回程路由和下一跳，要求 `lan_prefixes` 有 IPv6 网段或设置了 `lan_interfaces`。省略时，客户端网段有 IPv6 且出口有 IPv6 就打开（见“8. Linux 内部接口出口”），客户端网段没有 IPv6 时关闭且不报错；写 `false` 总是关闭。没开时这条规则的 AAAA 返回空应答，客户端回落到 IPv4。写明 `interface` 的规则直接在 `via` 写两个下一跳；Fake-IP 规则看 `fakeip_range` 有没有 IPv6 地址池。只有设备同步读取，不写入生成的配置 |
| `via` | 字符串或数组；Gate 加载时必填 | 省略 `interface` 时不能写，由设备同步填入。下一跳 IP；可写一个 IPv4 和一个 IPv6，例如 `["10.61.50.1", "fd00::1"]` |
| `fib_table` | 整数，`0` | VPP 表 ID；该表须处于实际流量的查表路径中 |
| `domains` | 字符串数组 | 内联域名，匹配自身及子域名，不使用 `*` 通配符 |
| `domain_files` | 字符串或数组 | 域名列表文件，每行一条；支持空行及 `#` 注释。写绝对路径或文件名，只写文件名时在 `/etc/vpp/gate` 下查找 |
| `domain_keywords` | 字符串数组 | 域名任意位置的子串匹配，忽略大小写 |
| `ip_range_files` | 字符串或数组 | 静态网段文件，路径写法同 `domain_files`；支持 CIDR 和 `起始IP-结束IP`；禁止默认路由，须有对应地址族下一跳 |
| `dns` / `dns_upstream` | `[地址, 端口]` | 专用 DNS 上游，二者为别名；省略则按上游选择策略处理 |
| `fake_dns` | `[地址, 端口]` | Fake-IP DNS，须同时提供 `fakeip_range` |
| `fakeip_range` | 字符串或数组 | 固定 Fake-IP 池，可各含一个 IPv4 和 IPv6 前缀，须与下一跳及 DNS 配置匹配 |
| `tproxy_port` | 整数，1–65535 | 创建 TCP/UDP TPROXY 规则。带 `fakeip_range` 时拦截地址池；真实 IP 模式须指定专用 `tproxy_interface`，拦截该入接口上的真实地址流量 |
| `tproxy_interface` | 字符串，可省略 | 限制 TPROXY 的 Linux 入接口；省略则不限制入接口，与 `interface` 含义不同 |
| `tproxy_address` | 字符串或数组，可省略 | 代理监听的地址，比如 `127.0.0.1` 或 `["127.0.0.1", "::1"]`；需要 `tproxy_port`，每个地址池要有同族的地址。省略时由内核取入接口的地址，代理须监听所有地址 |
| `dhcp_gateway` | 布尔，默认 `false` | IPv4 下一跳在运行时取 VPP 在 `interface` 上的 DHCP 租约里的路由器，租约变了跟着改，没有租约时回落。只能用于带 `default_route`、没有域名和网段的规则；`via` 只能再写一个 IPv6 下一跳 |
| `default_route` | 布尔，默认 `false` | 这条规则的出口同时承载默认路由，见下文“默认出口”。有它的规则可以没有域名和网段。每个地址族只能有一个出口，IPv4 和 IPv6 两条规则可以同时写；不能用于 Fake-IP 出口 |

一个出口至少需要域名、关键字或非空静态前缀文件（带 `default_route` 的除外）；`routes` 可以是空数组，此时 Gate 只转发 DNS。
不同 DNS 别名同时出现时必须指定相同上游。只配置 IPv4 出口且首个匹配规则无 IPv6
出口时，AAAA 返回 NODATA，不查询上游；NODATA 与提交失败时的 SERVFAIL 不同。

`routes` 所在 JSON 顶层还支持 `fakeip_ttl`（默认 `604800`，范围
1–2147483647 秒），覆盖 Fake-IP 应答的 A / AAAA / CNAME TTL。该 TTL 不控制真实地址路由租约。
规则文件顶层可设置 `overlap_policy`、`dns_upstream_policy`，会覆盖运行参数文件中的值；
含 `fakeip_range` 或 `fake_dns` 的配置自动采用 `first` / `first`。
同一地址池可供多个域名规则复用，但池路由和 DNS 上游必须一致；不同策略的重叠池会被拒绝。

## 7. Fake-IP 与透明代理配置

在 `routes` 中加入：

```json
{
  "name": "proxy",
  "interface": "tap2490",
  "via": ["10.63.30.2", "fd42:1111:2222:30::2"],
  "domain_files": ["proxy.domains"],
  "fake_dns": ["127.0.0.1", 5354],
  "fakeip_range": ["198.18.0.0/15", "2001:2::/48"],
  "tproxy_port": 2082,
  "tproxy_interface": "vpp-tproxy"
}
```

规则里省略 `interface` 和 `via` 时，设备同步生成设备 `gate-tproxy`、地址、`tproxy_port`（默认 2082）、`tproxy_interface`、
fwmark 策略路由和本地投递路由，无需手动准备（地址池有 IPv6 时两个地址族都生成），最多一条。上面的示例是手写的完整形式。

启动时安装地址池的 VPP 路由，按配置生成 Linux TPROXY 规则；随后 Fake-IP 查询只转发
DNS 并处理 TTL，不逐地址提交路由，也不写租约。Gate 不逐个检查应答地址是否属于池，
应确保专用 DNS 对这些域名确实返回所配置池中的地址。

TPROXY 规则使用标记 1。手写时，Linux 必须已有相应的 fwmark 策略路由及本地投递路由，
代理须在指定端口开启透明接收。`tproxy_interface` 是流量进入 Linux 的接口，
不一定与 VPP 中的 `tap2490` 同名。若这些规则由现有防火墙维护，省略
`tproxy_port`、`tproxy_interface`，保留 Fake-IP DNS、地址池和 VPP 出口即可。

同步 IPv6 TPROXY 规则时，Gate 把运行中的 `net.ipv4.tcp_early_demux` 设为 0。
Linux 的 IPv6 TCP 也读取这个主机级设置。此项只写入运行中的内核，系统重启时失效。

## 8. Linux 内部接口出口：每个出口一个设备

WireGuard、PPP 等 Linux 转发出口各用一个独占的 TAP 设备，TPROXY 另用一个。出口本身可以是任何三层接口，包括 OpenVPN 这类 TUN 接口。
在普通出口规则中添加 `linux_exit` 即可启用。`interface`、`via` 仍描述 VPP
到 Linux 的路径；`linux_exit.interface` 描述 Linux 实际出接口。

VPP 路由选择设备，设备决定出口。Linux 不保存目的地址，也不随 DNS 查询变化，规则在启动后基本不变。

VPP 与 Linux 之间固定用 TAP，规则里写 `device` 会报错。在一台 4 核 arm64 设备上经真实 WireGuard 出口实测（对调隧道后结论不变，只代表相对差异），TAP 上传约 250 Mbit/s，TUN 约 110–135 Mbit/s，下载差距则跟随隧道，
与设备类型无关；一张网卡多个网关也需要 MAC 区分下一跳。设备不开 GSO：LAN 侧是非 GSO 网卡时，`gso` 几乎没有收益（帧仍约 1430 字节）；`gso gro-coalesce` 会使上传几乎中断（0–16 Mbit/s），不要使用。

规则里只需写出口接口。`linux_exit` 中的 `masquerade`、`block_input`、`gateway` 等按需填写：

```json
{
  "upstream": ["10.61.20.2", 53],
  "lan_prefixes": ["10.64.30.0/24", "10.62.0.0/16"],
  "routes": [
    {
      "owner": "host",
      "domains": ["example.org"],
      "linux_exit": { "interface": "wg0", "masquerade": true }
    },
    {
      "owner": "host",
      "domains": ["example.net"],
      "linux_exit": { "interface": "ppp0", "masquerade": true, "block_input": true }
    }
  ]
}
```

同步后，`/var/lib/vpp-egress-gate/gate.json` 中的规则如下，这也是不用设备同步时需要手写的完整形式：

```json
{
  "routes": [
    {
      "name": "wg0",
      "domains": ["example.org"],
      "interface": "tap2100",
      "via": "172.30.10.2",
      "linux_exit": {
        "input_interface": "tap-wg0",
        "interface": "wg0",
        "table": 1101,
        "mark": 101,
        "priority": 11101,
        "masquerade": true
      }
    },
    {
      "name": "ppp0",
      "domains": ["example.net"],
      "interface": "tap2101",
      "via": "172.30.10.6",
      "linux_exit": {
        "input_interface": "tap-ppp0",
        "interface": "ppp0",
        "table": 1102,
        "mark": 102,
        "priority": 11102,
        "masquerade": true,
        "block_input": true
      }
    }
  ]
}
```

- 设备按出口命名：`wg0` 得到 `tap-wg0`，`ppp0` 得到 `tap-ppp0`。未写 `name` 时用出口接口名，其中的 `.` 换成 `_`。
- Linux 接口名最长 15 个字符。设备名放不下时，保留开头并加上由完整名字算出的 4 位标记：`enp3s0f0` 得到 `tap-enp16s-` 加标记，比如 `tap-enp16s-a1b2`。
  同步时日志会打印对应关系（`devices: enp3s0f0 uses device …`），`devices.json` 的 `exit` 字段也有记录。万一两个名字得到同一个设备名，同步报错 `two rules ask for device`，改规则名或手写设备。VPP 接口名只能是
  `tap<id>`，`show tap` 的 `name` 字段显示对应的 Linux 接口。
- Fake-IP 或真实 IP TPROXY 规则没有 `interface` 时共用设备 `gate-tproxy`（VPP 接口 id 2081，`172.30.20.0/24`），`tproxy_port` 默认 2082，TPROXY 重定向由 Gate 按此字段安装。Fake-IP 地址池优先于真实 IP 拦截规则。
- 分配范围：设备 id 2100 起、`172.30.10.0/24` 中的 /30（最多 64 个出口）、路由表 1101 起、mark 101 起、优先级 11101 起，
  以及回程表 2101 起、回程优先级 12101 起。自己写的 `table`、`mark`、`priority` 会保留，分配时自动避开，表 1002 和
  优先级 11002 留给 TPROXY。
- 规则没有 `interface` 时不能写 `via` 或 `input_interface`，这些字段描述的是已有设备。
- 同一张网卡可以有多个网关：写多条规则，每条有自己的 `name` 和 `gateway`。VPP 只看到一个设备 `gw-<网卡>`，host 上每个网关一个 macvlan `gm-<规则名>`，VPP 路由的下一跳决定进哪个 macvlan，host 按入接口选网关，不需要 nft 集合。见下文示例。
- 设备带 IPv6 时再从 `fd67:7465:6500::/64` 分配 /126（TPROXY 用 `fd67:7465:6501::/64`）。规则写 `"ipv6": true` 或 `false` 时照写的办；不写时，客户端网段有 IPv6、出口也有 IPv6 就打开：写了 `gateway6`，或者出口网卡有全球单播或 ULA 的 IPv6 地址，并且（有 `gateway` 的出口）主表里有经它的 IPv6 默认路由。这样打开的 IPv6 记在设备记录里（`ipv6_found`），出口暂时没了 IPv6（比如隧道断开时 Linux 清掉了地址）也不关；要关就写 `false`。有 `gateway` 却没写 `gateway6` 的出口，IPv6 下一跳用主表里经该网卡的 IPv6 默认路由（通常来自路由通告），Gate 每次后台协调时重新读取，路由器换了跟着换，没有这条路由时撤掉出口的 IPv6 路由，流量由兜底路由拒绝。规则可以随时开关 IPv6，同步会让设备和运行中的 VPP 跟上。隧道本身仍须自行建立；手动 `ip link set down` 会让 Linux 清掉隧道的 IPv6 地址，须由隧道的管理工具恢复。
- VPP 启动 CLI 可以在 `exec` 那一行之后为这些设备绑定 ACL/NAT，但不要写指向它们的静态路由。

同一张网卡多个网关（比如一个网段里有两台上游路由器）这样写，IPv6 同样写 `ipv6` 和 `gateway6`：

```text
{ "name": "eth1-a", "owner": "host", "domain_files": ["eth1-a.domains"],
  "linux_exit": { "interface": "eth1", "masquerade": true, "gateway": "192.0.2.1" } }
{ "name": "eth1-b", "owner": "host", "domain_files": ["eth1-b.domains"],
  "linux_exit": { "interface": "eth1", "masquerade": true, "gateway": "192.0.2.2" } }
```

```text
VPP：目的 A via 172.30.10.2 tap2100，目的 B via 172.30.10.6 tap2100（一个设备，每个网关一个 /30）
host：gm-eth1-a(.2) ──> 策略路由 ──> 192.0.2.1 ──> eth1
      gm-eth1-b(.6) ──> 策略路由 ──> 192.0.2.2 ──> eth1
```

回包都经第一个网关的 macvlan 回到 VPP。规则从一条变成多条时，设备从 `tap-eth1` 换成 `gw-eth1`，旧设备按删除处理。去掉一个网关时，它的 macvlan 立即删除，VPP 地址也撤掉，其他网关不受影响；只剩一个网关时也继续用 macvlan，不会换设备。生成配置时，给 Linux 出口填多个 IPv4 网关，就每个网关生成一条规则（`eth1-1`、`eth1-2`），这时不加 IPv6，须手动补上。

部署前准备：

- 手写时，为每个出口创建持久设备并配置两端地址。`ip tuntap add mode tap multi_queue name tap-wg0`，VPP 用
  `create tap id 2100 host-if-name tap-wg0 hw-addr 02:67:74:08:34:01 host-mac-addr 02:67:74:08:34:02 host-mtu-size 1500 attach persist` 和 `set interface mtu packet 1500 tap2100`；`multi_queue` 和 `persist` 都不能省：前者不一致时内核拒绝打开，
  只写 `attach` 会清除持久标志。`host-mtu-size` 只设置 Linux 一侧，VPP 一侧不设置时是 9000。`hw-addr` 和 `host-mac-addr` 要写死，否则 VPP 重启后 MAC 会变。
  Gate 启动时检查 `via` 是否配置在该接口上，缺失时报错退出；设备暂不存在时等它出现后再检查。
- 建立并启动 Linux 出口接口，配置隧道对端、WireGuard AllowedIPs 等；Gate 不管理隧道。
- 启用 Linux 转发。第一个出口生效时，设备同步和开机服务设置 IPv4 转发；第一个开了 IPv6 的出口生效时，如果 `net.ipv6.conf.all.forwarding` 还是 0，就设为 1。转发打开后接口默认不再接受路由通告，所以会先把现有接口 `accept_ra=1` 改成 2，主机的 IPv6 地址不受影响；已经开启（包括值为 2）时不改动。这些设置移除出口后不会自动恢复。
- 将 `net.ipv4.conf.all.rp_filter` 设为 0（第一个出口生效时，设备同步和开机服务会设置，这影响整台主机，移除所有出口后也不会自动恢复）。出口回包不带 mark，反向路径校验走主路由表，
  可能把回包丢弃。Gate 启动时和每次后台协调时把 TAP 和出口接口上的值改为 0；`all` 影响整台主机，Gate 只记录日志不修改。这样出口接口不再校验来源，防护依赖下文的
  forward 过滤和 `block_input`。
- 每个经此路径出去的客户端网段（各 LAN、VPN 网段）都要有回程路由，让回包经同一设备回到 VPP。设备同步按 `lan_prefixes` 为每个出口生成一张回程表，由出口接口的策略规则选择：
  `ip rule add priority 12101 iif wg0 lookup 2101` 和
  `ip route replace 10.64.30.0/24 via 172.30.10.1 dev tap-wg0 table 2101`。
- 主路由表也要有一条到客户端网段的路由，供 Linux 自身发给客户端的报文（代理回包、ICMP 错误）使用。设备同步放在配置中第一个生成的设备上；
  主表已有其他接口的路由时不改动，直接沿用。
- PATH 中提供 `ip` 和 `nft`。为 Gate 分配专用路由表、规则优先级和 mark。
- 不使用 `install.py` 时，以下两项须自行配置（安装脚本已包含）：
  - 使用 networkd 时，设置 `ManageForeignRoutes=no` 和 `ManageForeignRoutingPolicyRules=no`，
    否则 networkd 重启后会删除 Gate 的路由和规则，出口中断到下一次后台协调。
  - 在持久防火墙中为每个出口设备加入 `iifname "<设备>" meta mark 0 drop`（设备同步已写入 `fixed.nft`）。这样 nftables 重载删除 Gate 的表时，
    流量仍被丢弃，不会经主路由表泄漏。

`linux_exit` 参数。“要求”一列针对 Gate 加载的完整形式；用设备同步时只有 `interface` 必填，`table`、`mark`、`priority` 可省略并自动分配，`input_interface` 不能写：

| 字段 | 要求 | 作用 |
|---|---|---|
| `input_interface` | 必填，Linux 接口名，各出口唯一 | 该出口独占设备（TAP）的 Linux 端接口 |
| `interface` | 必填，Linux 接口名 | 实际转发出口，与入接口不同 |
| `table` | 必填，整数 ≥ 256，各出口唯一 | Gate 专用 Linux 策略路由表，不是 VPP FIB 表；已被其他路由或规则占用时拒绝 |
| `mark` | 必填，整数 ≥ 2，各出口唯一 | 分类标记；1 留给现有 TPROXY 规则 |
| `priority` | 必填，1–32765，各出口唯一 | Linux 策略路由规则优先级；须避开已有规则 |
| `gateway` | 可省略，IPv4 地址 | IPv4 默认路由下一跳；点对点接口通常省略 |
| `gateway6` | 可省略，IPv6 地址 | IPv6 默认路由下一跳；需同时配置 IPv6 `via`。有 `gateway` 时省略，就用主表里经该接口的 IPv6 默认路由的下一跳，运行时跟随 |
| `masquerade` | 默认 `false` | 对该出口的匹配流量启用 NAT，包括已配置的 IPv6 家族 |
| `dns_direct` | 默认 `false` | 该规则的 `dns` 上游不走出口而走主路由表；上游不在出口后方（如 LAN 解析器）时必须开启 |
| `block_input` | 默认 `false` | 丢弃从该接口主动访问 Linux 本机的流量；开启前确认不依赖它做远程管理或隧道监听 |

Gate 为每个配置家族维护专用表中的出口默认路由和不可达后备路由，以及同一优先级的两条
`fwmark` 策略规则：一条限制入接口为该出口的设备，一条 `iif lo` 供 Gate 自身的 DNS 查询使用。出口失效时不可达后备路由防止流量回落到主路由表。
以太网出口需要下一跳时，显式填写 `gateway` / `gateway6`；下一跳按 on-link 安装。

Gate 独占 `inet egress_gate_linux` 表，按入接口设置出口 mark；已配置的地址族才打标，其他地址族清除 mark。
forward 链只放行已分类的对应出口流量，丢弃从该设备进入的其他转发流量。VPP 路由到某个设备的流量都走它的出口，
因此不要把其他路由指向这个设备：一个 VPP 接口上有其他规则时，配置会被拒绝。
从出口接口进入的转发流量只放行 established/related 回包和 DNAT 连接，其他一律丢弃，
包括发往其他接口的流量；依赖该接口主动转入的部署（如站点互联）须调整。DNAT 目标不能位于
出口设备后方，其回包没有分类 mark，会被丢弃。可选 NAT 仅作用于对应入接口、出接口和 mark。
不要在这些设备上依赖其他 packet mark；Gate 不为这些出口写 conntrack mark。
TCP MSS 在 forward 链按出口钳制：去向使用路由 MTU，回向使用接口 MTU（每次后台协调时读取，IPv4
减 40、IPv6 减 60）。UDP（含 QUIC）仍依赖路径 MTU 发现。
如果系统另外运行 `nftables.service` 且配置含 `flush ruleset`，每次重载都会删除这些规则：Gate 的表由下一次后台协调
（默认最多 60 秒）重建，固定规则则要等下一次开机或设备同步，因此须把 `/var/lib/vpp-egress-gate/fixed.nft` include 到该配置中，
否则重建完成前流量可能经主路由表泄漏；包含后这段时间流量被丢弃。
系统其他防火墙链仍须允许这些流量，专有表中的 accept 无法覆盖其他链的 drop。

规则配置了专用 `dns` / `dns_upstream` 时，Gate 用该出口的 mark 发出 TCP/UDP 查询（需要 root 或 `CAP_NET_ADMIN`），
查询与业务流量走同一出口，来源地址是出口接口的地址。出口不通或无法设置 mark 时返回 SERVFAIL，不回落到主路由表；
forward 之外还有 output 规则，防止带 mark 的查询从其他接口发出。上游须能经出口到达（WireGuard 的 AllowedIPs
须包含它），且出口须有同地址族的 `via`，否则配置被拒绝。未配置专用 `dns` 的规则使用全局 `upstream`，走主路由表。
`127.0.0.1` 这类本机转发器由其自身决定上游路径，Gate 的 mark 管不到。

出口接口不存在或未启动时，Gate 正常启动，其他出口不受影响：该出口仍安装不可达路由和策略规则，
流量被拒绝。未配置专用 `dns` 的规则，DNS 应答照常返回。

Gate 通过 netlink 监听出口接口和出口设备的链路、地址变化，变化后约 0.5 秒内协调一次：恢复默认路由，
并更新隧道端点、`rp_filter` 和 MSS。其他接口的变化不触发协调。监听不可用时记录日志，退回周期协调
（默认最多 60 秒）。WireGuard 换端点、路由或策略规则被外部删除时没有链路事件，仍等周期协调。
配置错误（表或优先级被占用）在启动时报错退出；运行期间出现时记录日志，不影响其他出口。

Gate 启动时及每次后台协调时读取出口的隧道端点（WireGuard 需要 PATH 中有 `wg`，GRE、IPIP、
VXLAN 等读取 `remote`），将其加入排除前缀，并撤销已安装的相应路由，防止隧道封装后又进入自身。
命中这些地址的 DNS 应答按排除前缀处理，返回 SERVFAIL。接口缺失或读取失败时沿用上次结果。
PPTP、L2TP、OpenVPN 等无法自动识别的隧道，须把服务器地址写入 `exclude_prefixes`。

Gate 第一次安装路由前完成自己的 Linux 规则配置，失败时扣留应答，后续查询会重试。此后新目的地址只提交 VPP 路由，
DNS 应答不等待 nftables，也不受它失败影响。后台协调恢复规则。
不能将 `linux_exit` 与同一规则中的 Fake-IP / TPROXY 选项混用。

规则归属保存在 `state_file` 后附加 `.linux-exits.json` 的文件中。修改或删除出口后重启
Gate，会清理已记录的旧策略规则和专用默认路由；删除最后一个出口时同时删除专用 nft 表。
退出时保留转发配置，避免影响现有连接；不要删除归属文件，否则无法自动清理旧对象。

## 9. systemd 调用与配置更新

`install.py` 安装两个单元：

```ini
# vpp-egress-gate-links.service（开机运行一次）
ExecStart=/usr/local/bin/vpp-egress-gate --setup-links
# vpp-egress-gate.service
ExecStartPre=-/usr/local/bin/vpp-egress-gate --config /etc/vpp/egress-gate.json --sync-on-start
ExecStart=/usr/local/bin/vpp-egress-gate --config /var/lib/vpp-egress-gate/gate.json
```

查看实际调用、修改配置后重启及读取日志：

```sh
systemctl cat vpp-egress-gate.service
sudo systemctl restart vpp-egress-gate
systemctl is-active vpp-egress-gate.service
sudo journalctl -u vpp-egress-gate-links -u vpp-egress-gate -n 50 --no-pager
```

仅修改 JSON / 列表文件无需 `daemon-reload`；修改 systemd unit 或 drop-in 后，先执行
`sudo systemctl daemon-reload` 再重启。不要同时运行另一个路由同步进程。
常规配置更新无需重启 VPP。

## 10. 验证和排障

先检查入口及引用 JSON 的语法；语法检查不验证接口、下一跳或字段含义：

```sh
python3 -m json.tool /etc/vpp/egress-gate.json > /dev/null
```

查询例子中的地址和域名应替换为实际配置：

```sh
dig @10.61.20.2 -p 1053 example.org A
dig @10.61.20.2 -p 1053 example.org A +tcp
dig @10.61.20.2 -p 1053 example.org AAAA
sudo vppctl -s /run/vpp/cli.sock show ip fib table 0
sudo vppctl -s /run/vpp/cli.sock show ip6 fib table 0
sudo nft list table inet egress_gate   # TPROXY 重定向
sudo nft list table inet egress_gate_linux   # 出口分类、过滤和 NAT
sudo nft list table inet gate_fixed       # 固定防火墙规则
systemctl status vpp-egress-gate-links
sudo journalctl -b -u vpp-egress-gate-links --no-pager
ip tuntap show
sudo vppctl -s /run/vpp/cli.sock show tap
```

| 现象 | 检查项 |
|---|---|
| 启动失败 | JSON 语法、列表文件是否存在、域名/出口是否合法、socket 权限、接口、池冲突及运行日志 |
| 监听失败 | `listen` 地址是否属于本机，端口是否已被占用 |
| SERVFAIL | 查看 `DNS answer withheld` 后的原因；可能为上游失败、VPP API 失败、重启代次变化或本地冲突 |
| AAAA 无记录且 NOERROR | 首个匹配出口是否只有 IPv4；这可能是预期 NODATA 行为 |
| 修改规则不生效 | 重启 Gate，再查日志有没有 `not applied`，有就是配置有错，Gate 还在用上次的同步；开机时不同步，开机后也要重启一次；核对 `/var/lib/vpp-egress-gate/gate.json`，Gate 服务读取的是它 |
| DNS 没有响应，日志停在 `waiting for VPP` | Gate 在等 VPP，冒号后面是原因。VPP 没运行时看它的服务；提示 `VPP route interface does not exist` 时核对接口名和启动 CLI，只要路由要用的接口不存在就会一直等 |
| Gate 未启动，提示依赖失败 | `vpp-egress-gate-links` 失败时 Gate 不启动。查看它的日志，常见原因是 `devices.json` 损坏、接口名或优先级被占用、缺少 `nft` |
| `--sync-devices` 提示 `refusing to take it over` | 已有同名接口且不是持久多队列设备；改名或移除该接口 |
| 设备在但流量不通 | `show tap` 中是否有对应 VPP 接口；`ip link` 显示 `NO-CARRIER` 表示 VPP 没有接上，核对启动 CLI 中的 `exec` 行 |
| 已删除的设备还在 | VPP 仍占用它，重启 VPP 后运行同步，或等下次开机 |
| Fake-IP 有应答但连接失败 | VPP 池路由、Linux 入接口、TPROXY 规则、标记策略路由及代理端口 |

真实地址路由以 API 成功为应答屏障，不先查 FIB，也不在每次成功后读回 FIB。
正常热提交复用接口和 FIB source 缓存，接口重建、API 身份变化或错误时才按既定逻辑刷新。
后台按 DNS 观察账本处理空闲租约，而非按业务流量活跃度处理；配置 `idle_seconds`
时应考虑长连接可能不重新查询 DNS。

内核和转发测试需要 root、`ip`、`nft`、`python3`，默认跳过。它们会改动网络配置，必须在独立网络命名空间中运行，
每个测试单独一个命名空间：

```sh
go test -c -o /tmp/gate.test .
for t in TestLinuxExitKernel TestLinuxExitUnderlayKernel TestLinuxExitPackets TestSyncDevicesKernel; do
  sudo unshare -n env GATE_KERNEL_TEST=1 sh -c "ip link set lo up; /tmp/gate.test -test.run '^$t\$'"
done
```

`TestLinuxExitPackets` 用命名空间模拟 LAN、两个出口和主路由出口，加载设备计划生成的配置和规则，用 veth 代替持久设备，收发真实 TCP/UDP 报文。`TestSyncDevicesKernel` 创建真实的持久设备，覆盖重复同步、开机恢复、更换类型、退役和拒绝接管外来接口；这些测试的配置都不指向真实的 VPP socket。

## 11. 状态和停止行为

普通 DNS 路由与租约运行时保存在内存，正常停止时写入 `state_file`、`lease_file`。
Fake-IP 启动迁移会在接受查询前额外保存一次状态。停止 Gate 不主动批量删除 VPP 路由；
重新启动时会恢复账本，并协调过期或不再属于当前配置的受管理路由。
强杀或断电可能丢失尚未保存的动态观察记录。

要回到 Gate 启动前的状态，先停止 Gate，再用服务读取的配置运行：

```sh
sudo systemctl stop vpp-egress-gate
sudo /usr/local/bin/vpp-egress-gate --config /var/lib/vpp-egress-gate/gate.json --flush
```

它撤销账本记录的 VPP 路由，清空账本，删除 `lease_file`，并清除 Gate 的 Linux 出口路由和策略规则、TPROXY 规则和 DNS 劫持规则。只有路径与账本一致的路由才会被删除，其他路由不受影响。VPP 须处于运行状态；Gate 正在运行时拒绝执行。

以下内容不会被清理：

- 设备：TAP、macvlan、固定防火墙规则和 VPP 静态片段由设备同步管理。
- 系统设置：Gate 关闭的接口 `rp_filter` 和设备同步设置的转发、`rp_filter` 不会恢复，要恢复请用下面的卸载。
- iptables：Gate 在 `FORWARD` 链加的放行规则，下次启动 Gate 还要用，同样由卸载清除。
- 不在账本里的路由：DNS 观察到的路由在正常停止时才写入账本，强杀或断电后留下的这部分路由，要重启 VPP 才能清除。

再次启动 Gate 时，配置里的静态网段和 Fake-IP 地址池路由会重新安装，DNS 观察到的路由要等客户端再次查询。

### 卸载

要完全移除，用 `install.py` 旁边的 `uninstall.py`：

```sh
sudo python3 uninstall.py --dry-run   # 只打印计划
sudo python3 uninstall.py
```

它不重启 VPP，依次完成：

1. 从 VPP 启动 CLI 文件删除 `exec` 那一行。文件自动检测，安装时用过 `--vpp-cli-file` 的这里也要写上；找不到这一行时拒绝执行，因为 VPP 还会去读即将删除的文件。
2. 停止并禁用两个单元。
3. VPP 运行时执行 `--flush` 撤销路由；VPP 未运行时路由本来就不在了。
4. 删除设备的策略规则、路由表、主表路由和 `FORWARD` 放行规则。
5. 让 VPP 放开 TAP，再删除 Linux 端的设备。
6. 删除 nft 表 `egress_gate`、`egress_gate_linux`、`gate_fixed`。
7. 把程序改过的 `sysctl` 恢复原值，记录在 `/var/lib/vpp-egress-gate/host-settings.json`。之后被别人改过的值不动，并给出提示。没有记录的（由未记录原值的旧版本改的）也不动，`net.ipv4.ip_forward` 和 `net.ipv4.conf.all.rp_filter` 请自行确认。
8. 删除安装的单元和网络管理器配置（不是安装脚本写的文件不动）、状态目录和程序。

`/etc/vpp/egress-gate.json` 和 `/etc/vpp/gate/` 是你的规则，不删除，不再需要时手动删除。`.gate-backup` 只在 CLI 文件除 `exec` 行外没有变化时才删除，否则保留并提示。

可以重复运行，中途失败的再运行一次即可。VPP 不肯放开设备时报错退出，并保留继续所需的文件，重启 VPP 后再运行一次。`install.py` 必须和它放在一起。

### 出口接口缺失

规则的 `interface` 在 VPP 里不存在时，Gate 照常启动和应答，只有依赖这个出口的部分受影响：解析到这条规则的查询返回 SERVFAIL，其他规则不受影响。接口出现后几秒内自动补上。有出口缺失时每 2 秒检查一次，否则每 10 秒一次。

规则的每个前缀（静态网段、Fake-IP 地址池、已学到的地址）默认都有一条丢弃路由，用 Gate 自己的低优先级 FIB 来源 `vpp-egress-gate-drop` 安装。出口存在时真实路由优先级更高，流量走隧道；出口缺失时流量被丢弃，不会绕过隧道从默认路由出去。出口来去时丢弃路由本身不变。它们记在账本旁边的 `<state_file>.drops`，规则去掉或 `--flush` 时一并清理。

### 默认出口

规则带 `"default_route": true` 时，没有匹配任何规则、也没有更具体路由的流量都从这条规则的出口出去，包括路由器自己发出的流量。面板路由页 default 行的“切换出口”写的就是这个字段。

- Gate 不改 `0.0.0.0/0` 和 `::/0`，而是在出口上装两半：`0.0.0.0/1`、`128.0.0.0/1`（IPv6 是 `::/1`、`8000::/1`）。原来的默认路由（DHCP、SLAAC 或启动 CLI 写的）留在原处，撤掉这两条就回到原状。
- 有些流量必须继续走原来的默认路由，否则出口会把自己的包再送进自己。Gate 给它们装上指向原默认路由下一跳的路由：VPP 里所有 WireGuard 对端的端点（用作出口的隧道，以及路由器上 WireGuard 服务端的客户端），和 `exclude_prefixes` 里的网段（默认是私网、回环、链路本地，再加上 Linux 出口隧道的端点）。原默认路由的下一跳变了（比如 DHCP 换了网关）会跟着改。
- 出口不能用时回落到原默认路由：VPP 接口不存在或没有 up，`dhcp_gateway` 的接口没有租约，Linux 出口的 Linux 接口不存在或没有 up。出口恢复后自动切回。每 10 秒检查一次，Linux 出口的链路事件会立即触发检查。隧道接口是 up 的、对端却不通，接口看不出来，这种情况不会回落。
- 这些路由用 Gate 自己的 FIB 来源 `vpp-egress-gate-default` 安装，优先级低于 CLI、API、DHCP，同一前缀上别人写的路由优先。它们记在账本旁边的 `<state_file>.default`，去掉 `default_route` 后重启 Gate 或 `--flush` 时撤掉。Gate 被强杀时留在 VPP 里，下次启动接着管理。
- 选了出口而这个出口还要做 NAT 的，NAT 和规则出口一样要配好：WAN 口在面板接口页设为出口，WireGuard 写在接口附加命令里，Linux 出口用 `masquerade`。
- 局限：所有不匹配规则的流量都换了出口，从 WAN 进来的连接（端口转发、IPsec 服务端等）的回包也会从所选出口出去，这些服务在选了出口后不能用。WireGuard 服务端的客户端换了公网地址时，最多 10 秒后才跟上。

没有选出口、也没有要撤掉的路由时，Gate 不为默认出口访问 VPP。

## 12. 管理服务

面板的修改（切换规则出口、调整优先级、编辑域名表和网段表）由独立程序 `gate-admin` 执行，见 [`tools/gate-admin/README.md`](../gate-admin/README.md)。它调用 Gate 的 `--sync-devices --dry-run`、`--sync-devices` 和 `--flush`，配置含义仍以 Gate 为准。
