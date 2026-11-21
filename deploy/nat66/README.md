# wg0 IPv6 NAT66 隔离迁移准备

## NAPT66 动态 WAN 地址

单地址 NAPT66 可用 `tools/napt66-sync.py` 自动更新公网地址。将其安装为
`/usr/local/sbin/napt66-sync`，将本目录 `napt66-sync.service`、
`napt66-sync.timer` 安装到 `/etc/systemd/system/`，按
`napt66-sync.json.example` 创建 `/etc/vpp/napt66-sync.json`，然后执行：

```
sudo systemctl daemon-reload
sudo systemctl enable --now napt66-sync.timer
```

策略包含 `insides` 列表（每项为 `interface` 和 `prefix`）及 `outside`，不保存公网地址。
已有单接口的 `inside`/`prefix` 配置继续可用。服务每十秒
读取 VPP `show interface address`，从 outside 选择 `2000::/3` 地址。
原地址仍存在时继续使用它；移除后切换到接口上的另一个公网地址。
outside 无公网地址或所有 inside 均不存在时关闭 NAPT66，地址/接口恢复后重新启用。
部分 inside 不存在时仅配置其余可用接口，例如 wg100 未创建时 LAN 仍可使用 NAPT66。
有效接口集合变化时整体重配会清空会话，包括其他 inside 的现有会话。
若新旧地址重叠，当前版本不会根据 preferred lifetime 提前切走已弃用的地址。

地址、策略或 VPP 实例改变，以及接口上的 NAPT66 特性丢失时重新配置；
其他检查不重置会话。公网地址变化会使旧连接中断，客户端需重新建立连接。
运行状态记录在 `/run/napt66-sync/state.json`，VPP 实例通过 systemd
`vpp-router.service` 的 InvocationID 标识。

WireGuard 场景应移除该接口 `after_up` 中带固定 `external` 的 NAPT66 命令，
由同步服务在接口创建后恢复。多 inside 时也应移除 `before_down` 中全局的
`napt66 disable`，避免单个 WireGuard 停止时关闭 LAN 的转换。
删除接口及重新同步存在最多约十秒的间隔；本版本不提供逐接口会话保留。
修改 `wireguard.json` 时需协调管理服务的配置写入，避免同时在面板编辑。
检查状态用 `systemctl status napt66-sync.timer`、
`journalctl -u napt66-sync.service` 和 `sudo vppctl show napt66`。

以下为已有静态一对一 NAT66 的迁移记录。

运营商只提供单个公网 IPv6、需要多个 LAN 客户端共享时，使用独立的
[NAPT66 插件](../../plugins/napt66/README.md)。以下静态一对一方案要求为
每个客户端分配不同公网 IPv6，不能用于单地址端口复用。

若运营商只分配一个 IPv6 地址，多个 LAN 客户端共享该地址应使用
[NAPT66 插件](../../plugins/napt66/README.md)。本目录的静态一对一方案
要求每个客户端有独立公网地址。

范围为 `wg0` 上配置的 NAT66 源前缀。
采用 VPP 原生静态一对一 NAT66：每个 peer 的 /128 分配一个公网 IPv6，
不是 NAT44-EI，也不进行端口复用。

## 配置与生命周期

`render-wireguard.py` 新增可选 `--nat66-policy FILE`，与一次性 wg0 安装一起
从 `wg0.conf` 提取配置的 NAT66 源前缀中的 /128 AllowedIPs。它不运行 wg-quick hooks、
不修改 Linux WireGuard、不把密钥写入策略 JSON。服务器实际配置导出 5 个地址，
策略放在 `/opt/vpp-vrouter-migration/private-wireguard/wg0-nat66.json`，权限 0600。
已有私有 VPP WireGuard 配置没有覆盖；本次用临时预览文件提取策略后删除预览。

`ipv6/pd-sync.json` 通过 `nat66_policy_file` 引用该文件。PD 同步程序启动时
读取一次静态 peer 列表，复用 `tools/vpp-egress-nat.py` 的映射核对实现：

- 使用已消费且完成 RA 发布的 PD /64，与 IPsec 地址池选择相同前缀。
- 为 peer 分配稳定编号，映射到 `PD前缀:66::/80`，避开 IPsec `::100–::200`。
  示例 ULA `fd42:1111:2222:90::2` → `2001:db8:4400:1:66::2`。
- PD 改变/撤销/恢复时更新或删除自己管理的映射；保留不归此策略所有的映射。
- 发现目标地址冲突时拒绝覆盖；已有映射丢失时重新添加。
- 不查询 peer 握手、线路状态，不重新导入或重建 WireGuard。
- 映射账本存放 `/run`，内容不变时不改写文件。运行时没有新增 NAT66 定时器或
  独立守护进程，复用 PD 同步程序。

`wg0.vpp.conf.example` 为待安装片段：启用 NAT66，inside 仅为 wg0，outside
为真实 IPv6 WAN。必须先创建 wg0、安装 peer /128 回程路由，再应用该片段。
WireGuard 被手动删除重建后，也要重新应用其 NAT66 inside feature；该模块
不会接管 WireGuard 生命周期。修改 peer 配置后重新导出策略并重启 PD 同步服务。

## 原生插件构建

`build/history/build-nat66.py` 在 `/opt/vpp-vrouter-migration/nat66-build` 生成独立
构建，只编译 stock NAT66 对象并链接已有同版本 VPP 库，不重编整个 VPP，也不
改变原源码、构建或安装目录。当前源码中的 plugin CMake macro 会在未选中的
插件处 return，因此配置时包含 NAT66 之前的 NAT 组件，但不会编译那些组件。
该 checkout 的 API C 引用了 CMake 未生成的 api_json.h，脚本从同版本 API JSON
生成对应字符串头文件，不更改 API schema 或源码。

产物已复制到 `/opt/vpp-vrouter-migration/plugins/nat66_plugin.so`，SHA256：
`c1b08f60f38d8137b153335fdaf44839c1020da82fdabc67ccae7b30454596ef`。
完整启动配置还须显式启用 `nat66_plugin.so`；普通 LAN BVI 不设为 inside。

## 实测

`tests/integration/integration_vrouter_lan_services.py --workers 0|2 --ipv6 --nat66` 在隔离空间
创建带真实握手的 Linux WireGuard 客户端与 VPP wg0，使用新生成的测试密钥。
没有加载生产密钥或让生产 peer 漫游；额外 TAP 仅用于模拟远程 WG 传输链路。

- 两个源 /128 分别验证 IPv6 ICMP、UDP 1024 字节、TCP 64 KiB 数据内容与公网源地址。
- 先后测试两个 PD 前缀，明确撤销 PD 时删除映射，重新获取后恢复收发。
- 同时检查普通 LAN 公网源地址没有被 NAT66 改写，以及不归此模块管理的映射保留。
- 复用既有测试检查同步进程重启、SLAAC 换前缀、RDNSS/DHCPv6、IPv6 DNS 屏障、
  IPv4 DHCP/DNS/EI WAN；可叠加 `--tproxy` 检查共用 DNS TAP 的代理路径。

原有 NAT66 与 EI 池测试继续通过，额外检查静态策略模式只查询 NAT66 映射，
不查询 WireGuard 状态；无变化的 NAT66 账本 mtime 保持不变。

本目录和策略仅处于迁移准备状态。生产 nic0、Linux wg0、dnsmasq、nft、IPsec
没有切换。尚未验证真实运营商/外网客户端、物理吞吐、大报文 PMTU/ICMPv6 错误
处理或完整出口防火墙；PD 撤销只删除映射，不等同于完整的 WAN ULA 源地址过滤。
