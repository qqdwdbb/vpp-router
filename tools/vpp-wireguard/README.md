# vpp-wireguard

管理 VPP 上的 WireGuard 隧道：配置和节点的增删、启动和停止，以及 VPP 重启后恢复。VPP 不保存任何 WireGuard 配置，它的启动流程也不知道隧道的存在，全部由这个程序下发。以 root 运行，只在本机 Unix socket 上提供接口，由 `vpp-monitor` 转发。

## 构建和安装

```sh
make                                   # 生成 dist/vpp-wireguard-linux-{arm64,amd64}
sudo install dist/vpp-wireguard-linux-arm64 /usr/local/bin/vpp-wireguard
sudo install -m 644 vpp-wireguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpp-wireguard
```

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--socket` | `/run/vpp-wireguard/wireguard.sock` | 面板连接的 socket |
| `--config-dir` | `/etc/vpp/wireguard` | 配置目录（权限 700）：`wireguard.json` 和 `names.json` |
| `--names` | `--config-dir` 下的 `names.json` | 节点名字，面板的 `--vpn-names` 要指向同一个文件 |
| `--api-socket` | `/run/vpp/api.sock` | VPP API socket |
| `--nat-interface` | 无 | NAT44-EI 的外网接口，启动新配置时放行监听端口，否则 VPP 会丢弃发给隧道的 UDP |
| `--exits-file` | `/run/vpp-wireguard/exits.json` | 已启动且声明了下一跳的配置，`gate-admin` 据此提供可选出口 |
| `--vpp-unit` | 无 | 配置 VPP 的 systemd 单元，它变成 active 后立即恢复隧道。不设置时等 VPP socket 存在满 30 秒 |
| `--gate-config` | `/etc/vpp/egress-gate.json` | DNS Gate 入口配置；WireGuard DNS 只使用其中的具体监听地址和 `hijack_interfaces` |

## 配置

配置以结构化数据存在 `wireguard.json`（权限 600，含私钥），VPP 里的接口都由它生成，接口和错误信息不会返回私钥。

- 面板粘贴 wg-quick 格式或导入标准 `.conf` 文件保存，接口号从 `wg100` 起，保存后不自动启动。和 wg-quick 一样，`Address`、`AllowedIPs` 可以分多行写，不带掩码的地址按单个主机算（/32、/128），文件开头的 BOM 和 Windows 换行都可以。
- 源地址应填写 VPP 接口上用于收发隧道包的地址。保存后可在面板中停止配置，再用“修改源地址”更改，无需重新导入私钥和节点；有固定端点时，源地址必须与端点使用同一地址族。
- 停止时先逐个清理接口的节点，再删除接口，避免 VPP 批量删除时遗留节点导致再次启动失败。节点清理失败时保留接口并报告错误。
- `PostUp`、`DNS` 等字段被忽略，其中的命令不会执行。`Endpoint` 里的域名只在添加时解析一次。
- AllowedIPs 可以写 `0.0.0.0/0`，它只决定隧道接受哪些地址。默认只有隧道网段内的 AllowedIPs 才装进主路由表，`0.0.0.0/0` 不会改动路由器自己的路由，其他网段要用规则或附加命令引到接口上。
- `Table = off` 和 wg-quick 一样，完全不装路由，隧道网段内的也不装，流量全部由接口附加命令或规则引入。`Table` 的其他取值没有作用。

**作为规则出口**：添加配置时填“出口下一跳”，每个地址族一个，必须落在某个节点的 AllowedIPs 内。配置启动后，它就出现在路由页的出口列表里，停止后消失。已经选用它的规则不受影响，出口不在时那部分流量被丢弃。局域网流量要经这条隧道出去，通常还需要 NAT，写在接口附加命令里。

**接口附加命令**：属于这个接口的 VPP 命令，接口 up 后执行，停止前撤销，比如接口上的 NAT、ABF 挂载和经它的路由。每行一条，只能是 VPP CLI，不能用 `exec` 和 `unix`。任何一条失败，整个启动撤销。

**恢复**：程序只看 VPP socket 的文件信息来发现 VPP 重启，平时不访问 VPP。恢复失败每 5 秒重试，原因显示在页面上。

**WireGuard 服务器 DNS**：添加配置时勾选 DNS 转发，或之后在停止状态点击“编辑”勾选。目标地址和端口取自 `--gate-config` 中 DNS Gate 的具体 `listen` 地址，Linux 入接口取 `hijack_interfaces`，再从 `show tap` 找到对应的成对 TAP，VPP 出接口是 `show interface address` 中与监听地址同网段的接口：路由模式下是 TAP 自己，TAP 在桥里时是桥的 BVI（桥成员没有地址，无法解析下一跳）；面板不接受这些字段的手工覆盖。客户端 DNS 填对应 WireGuard 接口自身的 IP，无需在 Linux 上绑定这个 IP。只转发普通的 UDP 53 查询，不处理 TCP。启动时自动注册 UDP 53 的 punt（否则 VPP 回 port unreachable，查询到不了 punt redirect），配置该 WireGuard 入接口的 punt redirect 和 nftables DNAT，并在 Linux 上添加 `ip route replace <隧道网段> via <VPP 在该网段的地址> dev <hijack 接口>`，使回答经 VPP 回到隧道（Linux 默认路由不经 VPP 时也成立）；停止时清理，VPP 重启后恢复。Gate 必须已经启用 DNS 劫持并监听一个可由 TAP 到达的具体地址；普通路由转发流量继续经过 VPP，punt redirect 仅处理已进入 punt 路径的流量。

目标 IP 同时用作 VPP 下一跳，须与 VPP 出接口同网段。只为隧道接口自身的网段加回程路由；经节点 AllowedIPs 接入的其他网段需自行在 Linux 上路由回 VPP。防火墙须允许目标 DNS 服务。程序需要 root 和 `nft`，独立管理 `inet vpp_wireguard_dns` 表，每个隧道一条链，优先于旧的 DNS 前端规则；停止后保留空链，重复恢复不会累加规则。共享的 `set punt udp 53` 在停止时保留，以免影响其他隧道或主机服务；此后 VPP 对无人监听的 UDP 53 直接丢弃，而不再回 ICMP。现有手写的相同接口 punt redirect 应从附加命令中移除，交由 DNS 设置统一管理。`POST /wireguard/config` 也接受 `dns` 字段；`POST /wireguard/config/dns` 接收 `interface` 和 `dns`，`dns` 为任意对象即开启（字段一律忽略，启动时自动解析），`dns: null` 关闭功能。wg-quick 的 `DNS=` 仍仅表示客户端解析器配置，不会自动开启服务器转发。

## 从 VPP CLI 文件导入

先停止服务，再导入，接口名和实例号保持不变：

```sh
vpp-wireguard import -name wg0 -file /etc/vpp/wg0.vpp -after-up wg0.up -before-down wg0.down -started
```

导入后会用结构化数据重新生成命令，必须和文件逐条一致，否则拒绝导入。`-started` 表示接口正在运行，VPP 重启后要恢复。导入的配置不会再放行监听端口，因为它们的端口已由其他配置放行。

## 测试

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o dist/vpp-wireguard.test .
# 把 dist/vpp-wireguard.test 复制到 Linux 主机上运行
```
