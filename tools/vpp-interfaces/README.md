# vpp-interfaces

管理面板修改 VPP 接口的执行程序：接口地址（静态、DHCP、SLAAC、DHCPv6）、VLAN 子接口（新建、删除、改 VLAN ID）、桥域和桥成员、up/down 和 MTU。以 root 运行，只在本机 Unix socket 上提供接口，由 `vpp-monitor` 转发（面板的“接口”页面）。

VPP 自己不保存配置，接口来自它启动时执行的 CLI 文件（`startup-config`，安装器生成的是 `/etc/vpp/router.vpp`）。所以每次修改同时做两件事：改这个文件，并在运行中的 VPP 上执行对应的命令。改错地址可能让局域网断开，所以修改后要在 60 秒内确认，否则文件和 VPP 都恢复原样。

## 构建和安装

```sh
make                                   # 生成 dist/vpp-interfaces-linux-{arm64,amd64}
sudo install dist/vpp-interfaces-linux-arm64 /usr/local/bin/vpp-interfaces
sudo install -m 644 vpp-interfaces.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpp-interfaces
```

单元文件里的 `--vpp-unit vpp-router.service` 是安装器装的 VPP 服务，其他部署改成实际的单元名。

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--socket` | `/run/vpp-interfaces/interfaces.sock` | 面板连接的 socket |
| `--cli-file` | 从 `--vpp-config` 里找 | 要修改的 VPP CLI 文件 |
| `--vpp-config` | `/etc/vpp/router.conf` | VPP 启动文件，只用来找 `startup-config` 或 `exec` 指向的 CLI 文件 |
| `--vpp-unit` | 无 | 运行 VPP 的 systemd 单元。修改 VLAN ID 要重启它，不设置时这类修改被拒绝 |
| `--api-socket` | `/run/vpp/api.sock` | VPP API socket |
| `--state-dir` | `/var/lib/vpp-interfaces` | 待确认的改动和修改前的文件 |
| `--confirm` | `1m` | 确认期限 |
| `--system-pending` | `/var/lib/vpp-system/pending.json` | `vpp-system`（面板的“系统”页）待确认的改动。它也改这个 CLI 文件，存在时这里的修改被拒绝；空字符串不检查 |
| `--exits-file` | `/run/vpp-interfaces/exits.json` | 设了静态网关或开了 IPv4 DHCP 的接口，`gate-admin` 据此提供可选出口；空字符串不发布 |
| `--dnsmasq-conf` | 无 | LAN 的 dnsmasq 配置（安装脚本给的是 `/etc/vpp/dnsmasq.conf`），见下文“LAN 的 DHCP”；不设置时没有这部分 |
| `--dnsmasq-unit` | `vpp-router-dnsmasq.service` | LAN 的 dnsmasq 服务：改地址池时重启，改静态分配时 reload |
| `--dhcp-clients` | `/var/lib/vpp-interfaces/dhcp-clients.json` | dhcp-script 记录的客户端 |
| `--devices` | `--state-dir` 下的 `devices.json` | 设备、它们的 MAC 地址和名字 |
| `--meter-state` | `--state-dir` 下的 `meter.json` | 按设备统计流量是否开启，以及它改过什么 |
| `--meter-file` | `/run/vpp-interfaces/meter.json` | 计数规则的顺序，给 `vpp-monitor` 读 |
| `--router-env` | `/etc/vpp/router.env` | 安装脚本的 `router.env`，其中的 `HOST_GW`（Linux 管理口的网关）跟着局域网网关改；空字符串不改 |

## 能改什么

只修改文件里这几种命令，其他行（注释、空行、NAT、路由、DHCP 等）原样保留。可以用 VPP 的缩写，比如 `set int`，新写的行用完整写法。

| 命令 | 面板里的操作 |
|---|---|
| `set interface ip address 接口 地址/长度`、`ip route add 0.0.0.0/0\|::/0 via 网关 接口` | 静态地址和网关（经这个接口的默认路由） |
| `set dhcp client intfc 接口 [hostname 名字]` | IPv4 DHCP |
| `ip6 nd address autoconfig 接口 default-route` | IPv6 SLAAC：按路由器通告生成地址并设置默认路由 |
| `dhcp6 client 接口`（加上一行） | IPv6 DHCPv6 |
| `create sub-interface 父接口 编号 dot1q VLAN [exact-match]` | 新建、删除子接口，改 VLAN ID |
| `create bridge-domain 编号`、`create loopback interface ... instance N` | 新建桥域，可选同时建一个 loopback 作为 BVI |
| `set interface l2 bridge 接口 桥 [bvi]`、`set interface l2 tag-rewrite 接口 pop 1` | 加入、移出、换桥 |
| `set interface state 接口 up/down`、`set interface mtu packet N 接口` | 状态、MTU |
| `nat44 ei add interface address 接口`、`set interface nat44 ei out 接口 output-feature` | 出口（NAT）：从这个口出去的流量转换成它自己的地址 |

- 文件里提到的接口和物理口才能修改。WireGuard、Gate 的 TAP 等由其他程序创建的接口只显示。
- 新的行插在这个接口已有的行后面（也在它所在桥的 `create bridge-domain` 后面），文件里没有这个接口时加在末尾。
- 地址按 IPv4 和 IPv6 分别设置，每个地址族一种方式：IPv4 是不配置、静态或 DHCP，IPv6 是不配置、静态、SLAAC 或 DHCPv6。切换时先撤掉旧方式（释放 DHCP 租约、关闭 SLAAC 或 DHCPv6、删除静态地址和网关），再设置新方式，没变的部分不动。DHCP 和 SLAAC 自己设置默认路由。VPP 的 DHCPv6 客户端只拿地址，所以 DHCPv6 同时接收路由器通告来设置默认路由；路由器通告里允许自动配置的前缀也会生成 SLAAC 地址，和普通主机一样。loopback 没有链路，只能用静态地址。还用着 DHCP、SLAAC 或网关的接口不能加入网桥，也不能删除。
- 静态地址：只替换文件里的地址。运行中有、文件里没有的地址（其他程序加的）不动。在桥上的二层口、由 DHCP 获得地址的接口不能设地址。地址不能和其他接口的重叠。
- 桥：有地址的接口要先删除地址才能加入。只有 loopback 能做 BVI，每个桥只有一个。只带一个 VLAN 标签、exact-match 的子接口加入桥时，自动加上 `tag-rewrite pop 1`，移出时去掉。
- 删除子接口：文件里还有其他命令（NAT、路由等）引用它时拒绝，并指出是哪一行，要先手动删掉。
- 修改 VLAN ID：VPP 不能就地修改，删掉重建又会丢掉其他程序装在接口上的路由和 NAT，所以改文件后重启 VPP。子接口编号不变，接口名也就不变，引用它的命令不用改。VPP 重启后 Gate、vpp-wireguard 会自己恢复。
- 局域网网关在原网段内换地址（去掉 dnsmasq 发的网关地址，加上同一网段的另一个地址）时，dnsmasq 的 `router` 选项（重启 dnsmasq，DHCP 和 DNS 中断约 1 秒）和 `--router-env` 里的 `HOST_GW` 跟着改，`HOST_DEFAULT=1` 时 Linux 管理口的默认路由也立即换过去；新网关在 DHCP 地址池里、是 Linux 管理口的地址或已经静态分配出去时拒绝修改。它们和地址一起走 60 秒确认，没确认时一起恢复。已经连着的设备续租或重新连接后才换到新网关，在那之前上不了网。换到别的网段时，依赖地址的其他配置（dnsmasq 的地址池、Gate、Linux 管理口的地址）不会跟着修改。

## 出口（NAT）

“设为出口”给接口加上安装器给 WAN 写的那种 NAT：NAT44-EI 作为输出特性，地址池是接口自己的地址，DHCP 换了地址也跟着变。文件里还没有 `nat44 ei plugin enable` 时，连同安装器用的会话数和超时一起加上（插件这时才启用）。新的两行放在启用插件那行之后。

- 只做地址转换，不改路由；流量要走这个口，还要在路由页把它选为默认出口或规则的出口。
- 要先有 IPv4 地址（静态或 DHCP）。loopback、网桥的网关、网桥里的二层口不能做出口。用 `set interface nat44 ei in ... out ...` 写的 NAT 不在面板里改。
- 取消时只删这两行，插件保持启用。文件里还有引用这个接口的其他 NAT 命令（静态映射、identity mapping，比如 IPsec 的 500、4500 端口）时拒绝，要先手动删掉。
- 是出口的接口不能加入网桥，子接口不能删除，要先取消。
- 只管 IPv4。IPv6 的 NAT66 不在这里。

## 多个默认路由

每个设了网关的接口都写一条 `ip route add 0.0.0.0/0`（或 `::/0`），每个 DHCP、SLAAC 接口也各自装一条，这里不限制数量。VPP 把同一来源的几条合成等价多路径，按流分到各个口；静态网关（CLI 来源）优先于 DHCP，两者都有时只有静态的生效。要指定走哪个口，在面板路由页的 default 行选默认出口：启动时和每次修改后，这些接口写进 `--exits-file`，静态网关的接口是普通出口，DHCP 接口只能做默认出口（下一跳由 Gate 从租约读取）。选中的口要是出口（NAT），见上一节。

## 确认和恢复

- 一次只能有一个待确认的改动。系统页（`vpp-system`）有待确认的改动时也不能改，反过来也一样：两边都改同一个 CLI 文件，恢复时会把整个文件换回去。
- 在线命令中途失败时，已执行的按相反顺序撤销，文件不改。
- 没确认、或者点“立即恢复”：恢复文件，按相反顺序执行撤销命令。VPP 在这期间重启过（它已经加载了新文件），或者改动本来就要重启，就再重启一次 VPP。
- 要重启的改动在 VPP 恢复应答后才开始倒计时，90 秒内没恢复就立即还原。
- 管理服务重启后接着倒计时，已经过期的立即恢复。

每次修改、确认和恢复都写入服务日志（`journalctl -u vpp-interfaces | grep audit`）。

## 接口

| 路径 | 内容 |
|---|---|
| `GET /interfaces` | 接口、桥域、每项不能修改的原因、待确认的改动和上次结果 |
| `POST /interfaces/ipv4`、`/ipv6` | `{"interface","mode","addresses":[...],"gateway","hostname"}`，`mode` 是 `none`、`static`、`dhcp`（IPv4）、`slaac`、`dhcpv6`（IPv6） |
| `POST /interfaces/address` | `{"interface","addresses":[...]}`，两个地址族的静态地址一起替换，面板用来设置网桥的网关地址 |
| `POST /interfaces/bridge` | `{"interface","bridge","bvi"}`，`bridge` 为 0 表示移出 |
| `POST /interfaces/state`、`/mtu` | `{"interface","up"}`、`{"interface","mtu"}` |
| `POST /interfaces/nat` | `{"interface","nat"}`，`nat` 为 `true` 设为出口，`false` 取消 |
| `POST /interfaces/subif` | `{"parent","vlan","sub_id"}`，`sub_id` 为 0 时同 VLAN ID |
| `POST /interfaces/subif/delete`、`/vlan` | `{"interface"}`、`{"interface","vlan"}` |
| `POST /interfaces/bridge-domain` | `{"bridge","bvi","addresses":[...]}` |
| `POST /interfaces/confirm`、`/rollback` | `{}` |

面板从 `/api/interfaces/*` 转发过来，出错时返回 409 和 `{"error": "原因"}`。

## LAN 的 DHCP

面板“局域网”页的 DHCP 部分也在这里执行，用的是安装脚本的 dnsmasq（`--dnsmasq-conf`）。这些修改不会断开面板，所以没有 60 秒确认，和接口改动互不阻塞。

- **地址池和租期**：只改 `dnsmasq.conf` 里不带标签的 IPv4 `dhcp-range` 那一行，其余行原样保留。地址池要在 LAN 网段内，不能包含网关、DNS（`listen-address`）、网段地址和广播地址；租期写成 `12h`、`30m`、`7d` 或 `infinite`，至少 2 分钟。改完先 `dnsmasq --test`，再重启 dnsmasq，DHCP 和 DNS 中断约 1 秒；启动失败时换回原来的地址池。
- **静态分配**：在 `dhcp-hostsfile` 指向的文件里（安装脚本给的是 `/etc/vpp/dhcp-hosts`），这里只管 `MAC,IP[,名字]` 形式的行，其他写法（标签、client ID、几个 MAC）只显示不修改。地址要在 LAN 网段内，不能是网关和 DNS，不能和别的静态分配重复，也不能是别的设备正在使用的租约。改完 `systemctl reload`，dnsmasq 收到 SIGHUP 重新读取，不中断服务；设备下次续租或重新连接时拿到新地址。
- **租约**：读 `dhcp-leasefile`，只读。
- **设备**：安装脚本把本程序设为 dnsmasq 的 `dhcp-script`（同时开 `script-on-renewal`，dnsmasq 2.86 以后才有）。dnsmasq 每次分配、续租和释放地址时调用 `vpp-interfaces add|old|del MAC IP 主机名`，本程序把客户端发来的主机名、client ID、厂商类别（option 60）和参数请求列表（option 55，不同系统各不相同）记进 `--dhcp-clients`，不经过 socket，服务没运行时也不会漏记。脚本要写别的文件时设 `VPP_INTERFACES_CLIENTS`。
  - 一台设备可以有几个 MAC。新出现的 MAC 是随机地址（第一个字节的第 2 位为 1，手机连 Wi-Fi 的私有地址就是这种），并且主机名在局域网里只有一台设备用、厂商类别和参数请求列表都一样时，自动归入那台设备，标为自动归入；有几台设备用这个主机名时只提示可能是哪几台。不发主机名的设备不会自动归入。
  - 可以给设备命名（最多 32 个字）、合并两台设备、把一个 MAC 拆成单独的设备、忽略合并提示，以及删除不再出现的设备（有静态分配或租约还没过期时不能删除）。
  - 在线状态和流量不在这里，由 `vpp-monitor` 统计。

| 接口 | 内容 |
|---|---|
| `GET /interfaces/dhcp` | 网段、网关、DNS、地址池、静态分配、租约和设备 |
| `POST /interfaces/dhcp/range` | `{"start","end","lease"}`，`lease` 留空不变 |
| `POST /interfaces/dhcp/host` | `{"mac","ip","name"}`，同一个 MAC 已有时替换 |
| `POST /interfaces/dhcp/host/delete` | `{"mac"}` |
| `POST /interfaces/dhcp/device/name` | `{"id","name"}`，空名字表示用主机名 |
| `POST /interfaces/dhcp/device/merge` | `{"id","from"}`，把 `from` 的 MAC 并入 `id` |
| `POST /interfaces/dhcp/device/split` | `{"mac"}` |
| `POST /interfaces/dhcp/device/forget` | `{"id"}` |
| `POST /interfaces/dhcp/device/dismiss` | `{"id"}`，不再提示合并 |
| `GET /interfaces/meter` | 按设备统计流量的状态：是否开启、接口、ACL 编号、计数的地址 |
| `POST /interfaces/meter` | `{"enable": true\|false}` |

### 按设备统计流量

面板“局域网”页的开关，默认关闭。开启后，在局域网网关接口（地址是 dnsmasq 发的网关的那个接口，网桥的 BVI）上挂两张 ACL：入方向按源地址、出方向按目的地址，每个设备地址一条放行规则，最后放行所有 IPv4 和 IPv6，不拦截任何包；并打开 ACL 插件的计数（VPP 全局开关，记下原来的状态，关闭时恢复）。这样无论流量之后走 NAT、Linux 上的代理、隧道还是 IPv6，都按设备计入。VPP 把每条规则的字节数记在统计段（`/acl/<编号>/matches`），`vpp-monitor` 读取时不用 VPP API，也不让 worker 暂停。

- 计数的地址：有效租约和静态分配的 IPv4 地址，加上 VPP 在这个接口上的邻居表里的全局地址（手机自己生成的 IPv6 地址就是这样找到的）。每分钟、修改 DHCP 后各检查一次，地址变了就原地替换规则（计数从零开始，`generation` 跟着变）；VPP 重启后 ACL 没了，或编号被别人占了，就重新建、重新挂。挂载用 `acl_interface_add_del`，不动接口上别人的 ACL。
- 规则顺序写进 `--meter-file`，第 i 条规则统计 `rules[i]`；状态写进 `--meter-state`，本程序重启后照旧。
- 代价：经过网关的每个包多一次 ACL 查找。往局域网发的包（下载）还会从 BVI 以二层方式经过入方向 ACL，所以下载方向查两次。R6S 的 A55 小核用 64 字节小包打满时，上传方向转发能力约降 2.5%（只有规则）到 5%（加计数），下载方向估计约 10%；平时的流量下只是多占一点 CPU。
- VPP 26.06 对 `acl_stats_intf_counters_enable` 回的是 `acl_del_reply`（acl.c 的 `REPLY_MACRO (VL_API_ACL_DEL_REPLY)`），所以按它接收回复，再从 `show acl-plugin tables mask` 读回开关状态确认。

## 测试

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o dist/vpp-interfaces.test .
# 把 dist/vpp-interfaces.test 复制到 Linux 主机上运行
```
