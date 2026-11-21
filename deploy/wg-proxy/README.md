# wg1 通过专用 TAP 接入 Linux 回环代理

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

## 当前部署与重启恢复

现已部署至 `/usr/local/lib/vpp-vrouter` 和 `/etc/vpp`。VPP endpoint 保持
`10.63.50.2:44441`，经 DNAT 接入 gost 的 `127.0.0.1:44441`。

`cutover/runtime.py` 在加载 wg1 前完成 TAP、route_localnet 和 DNAT 准备，
精确清理源 `10.63.50.1`、目的 `10.63.50.2`、UDP 目的端口 44441 的旧
conntrack，避免握手抢先建立无转换会话。缺少 TAP 会中止启动；`host()` 不再
重复准备该路径，`transport.nft` 本身也支持原子重复加载。

全局防火墙加载也必须在 wg1 之前完成。已安装模式使用持久化
`/etc/nftables.conf`，不会在后续 host 准备中再通过旧 `host.nft` 全局清空。

VPP 重启还会重建 NAT，旧 gost SSH relay 会话可能失效但仍占有 UDP BIND，
导致对端重连不断报 `bind: address already in use`。以下 drop-in 让 gost 在
VPP 停止时关闭旧会话，并在 VPP 和 Linux 网络准备完成后重新启动：

- `gost-vpp-lifecycle.conf` 安装到
  `/etc/systemd/system/gost-tunnel.service.d/vrouter-vpp.conf`。
- `vpp-gost.conf` 安装到 `/etc/systemd/system/vrouter-vpp.service.d/gost.conf`。

安装后执行 `systemctl daemon-reload`。它们不覆盖含认证参数的 gost ExecStart，
也不会在普通 Linux 启动时主动启动 VPP。原有开机接管策略保持不变。

当前 VROUTER 的实验性 RTL8125 PMD 在进程热重启后还可能出现 RX 停止。
`startup/vrouter-vpp-device-prep.py` 通过 VPP 的 ExecStartPre 在进程停止后，
让 r8125 初始化指定 WAN PCI 设备，再交回 uio_pci_generic；不重建 IP/VLAN/路由。
只接受设备配置指定且已分配给 UIO 的 `10ec:8125` 设备，拒绝操作运行中的 VPP。
安装的 drop-in 是 `/etc/systemd/system/vrouter-vpp.service.d/device-prep.conf`。
这是当前 PMD 的设备初始化约束，升级驱动后需重新验证是否仍需要。

检查真实内层回包：`sudo vppctl ping 10.62.30.1 repeat 5`；不能只依据 gost
运行状态、44441 已监听或 conntrack ASSURED 来判断隧道正常。回归测试还需
确认 VPP 实际重启后 gost PID 改变、旧绑定释放、wg1 无需手工干预恢复。

## 历史迁移准备记录

以下 `/opt` 路径及“尚未部署”描述仅保留当时的隔离验证过程，当前部署以
上节标准安装路径为准。

VROUTER 的 Linux wg1 使用 `127.0.0.1:44441`；该端口由运行中的 gost 提供。
VPP 的 loopback 与 Linux 回环是两个独立协议栈，不能原样迁移 endpoint。
不改动 gost、不直接改为公网对端，采用以下路径：

```
VPP wg1 外层源 10.63.50.1
  → tap3901 → Linux vpp-wg-proxy 10.63.50.2:44441
  → 精确 DNAT → 127.0.0.1:44441 → 现有 gost → 上游
```

回包由 conntrack 自动反向转换，呈现为 `10.63.50.2:44441`。
10.63.50.0/30 专供外层传输，wg1 内层仍为原配置的 10.62.30.2/24。
内层地址和外层地址不同；不依赖 WAN DHCP，不添加 WireGuard 定时器。

## 已部署的准备文件

服务器源码目录：`/opt/vpp-vrouter-migration/source/scripts/vrouter/wg-proxy/`。

- `transport.vpp.conf`：创建专用 TAP，Linux .2、VPP .1，interrupt RX。
- `transport.nft`：仅匹配专用 TAP、源 .1、目的 .2、UDP 44441，DNAT 至回环。
- `wg1-egress.vpp.conf`：wg1 的 EI context 101、当前内层地址池 10.62.30.2、
  MTU 1280 对应 MSS 1240，以及设备配置指定的目的路由。
- 服务器私有目录 `private-wireguard/wg1.conf`：由实际 /etc/wireguard/wg1.conf
  转换，仅覆盖外层 src/endpoint，包含原接口密钥及 peer，权限 0600。

以上是迁移准备文件，没有加载到生产转发路径。不要在 Linux wg1 正使用
同一密钥时启动真实 VPP wg1 与上游握手，否则可能导致远端 endpoint 来回漫游。

## 正式切换时的顺序

先确认 transport 网段、TAP 名称和 nft 表名没有冲突；本次只读检查未发现
切换前须核对专用 TAP 的传输网段是否与现有路由重叠。

1. 完成生产整体切换和回滚准备，将 `transport.vpp.conf` 加入 VPP 启动流程。
2. TAP 创建后，仅设置 `net.ipv4.conf.vpp-wg-proxy.route_localnet=1`。
   不设置 all/default，也不在 WAN/LAN 接口启用。
3. 加载专用 nft 表。规则不会开放其他接口访问 Linux 回环服务。
   现有 input/output 过滤策略还必须允许这条精确路径；本机当前策略已通过隔离测试。
4. 停止原 Linux wg1 后，再加载私有 wg1 配置；不运行原文件的 PostUp。
5. 确认主配置已启用 nat44_ei、nat_ei_context、mss_clamp、wg_nat_order 插件，
   EI 已 enable，且普通 WAN 使用 tenant VRF 0 的地址池和 output-chain。
   再加载 `wg1-egress.vpp.conf`。该文件按当前内层地址和 MTU 准备，切换时
   核对其仍与实际 WireGuard 文件一致；不要重复创建已存在的 loop101/表 101。
6. 保留 table 0 的 LAN 连接路由。删除 Linux wg1 后，Linux 控制面到
   10.62.30.0/24 的回程须指向 VPP 的实际 LAN/TAP 地址，不能继续指向已删除接口；
   该地址待生产 LAN 管理地址确定后加入整体启动流程。

这里不导入 AllowedIPs 的默认路由，也不搬运旧策略路由钩子。wg1 的 UDP
外层走专用 TAP，不需要在 WAN 为它添加原先的 UDP identity mapping。

撤销时先停用 VPP wg1，再删除专用 nft 表和 TAP；删除 TAP 后该接口的 sysctl
随接口销毁。现有 gost 保留。生产启动集成和实际上游握手尚未执行。

## 隔离验证

`tests/integration/integration_wireguard_loopback_proxy.py --workers 0|2` 使用临时密钥、
独立 VPP、临时 root TAP/nft 表和 Linux WireGuard 服务端。一个临时 UDP 转发器
仅监听 `127.0.0.1:49342`，模拟 gost 的回环接入面，转发至临时 WG 服务端。
使用 10.253.90.0/30 作为测试外层传输，不连接真实 gost 或上游。

检查 DNAT 命中、真实握手、双向加密 IPv4/IPv6 ping，每个短 burst 要求 5/5。
这证明 VPP/TAP/DNAT/回环代理的接入机制，不等于真实 gost 上游链路或吞吐已验证。
测试结束删除临时 TAP、Linux WG 接口和 nft 表，停止独立 VPP/转发器。
日志：`/opt/vpp-vrouter-migration/logs/wireguard-loopback-proxy-workers0.json`、
`wireguard-loopback-proxy-workers2.json`。

### EI 与目的分流集成检查

同一测试加 `--nat-egress` 会加载 `integration_wireguard_nat_egress.py`：
增加两个内网源地址、普通 WAN 命名空间，以及 VPN 服务端上的两个测试目的网段。
所有测试使用独立地址和临时密钥，不使用生产目的网段发包。

- 默认出口使用 EI context 0，VPN 目的路由使用 wg1/context 101。
- 同一客户端、同一 UDP 源端口跨两个出口时分别使用各自地址池；同一出口
  更换目的地址仍复用映射，且服务端返回的源地址/端口和负载校验均通过。
- 两个内网源分别通过两个出口完成 ICMP 和 64 KiB TCP 响应内容校验。
- 在 VPN 服务端捕获解密后的 TCP SYN，确认其 MSS 为 1240，证明钳制发生在
  WireGuard 加密之前。
- 临时阻断专用 TAP 的入站 UDP：VPN 请求超时，WAN 请求仍成功；解除阻断后
  相同源端口的 VPN 流量恢复，不改路由或切换默认出口。
- 双 worker 模式要求两个 worker 均拥有 NAT 会话。

日志为 `logs/wireguard-nat-egress-workers0.json` 和 `workers2.json`。
这验证的是隔离的 EI/加密/代理转发组合，不是生产 gost、真实目标可达性或吞吐。

生成配置（仅转换，不应用）：

```sh
python3 /opt/vpp-vrouter-migration/source/scripts/vrouter/render-wireguard.py \
  /etc/wireguard/wg1.conf --instance 1 --source-address 10.63.50.1 \
  --endpoint 10.63.50.2:44441 \
  --output /opt/vpp-vrouter-migration/private-wireguard/wg1.conf
```

生成器拒绝覆盖已有输出。更新文件需先在 root 私有目录备份，生成新文件，
校验后替换；密钥不进入项目或日志。
