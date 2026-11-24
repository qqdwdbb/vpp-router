# VROUTER IPv6 PD、RA 与 VPN 地址池

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

当前生产仍由 Linux dhcpcd 获取 WAN PD、dnsmasq 宣告 LAN 前缀。本目录只部署在
`/opt/vpp-vrouter-migration/source/scripts/vrouter/ipv6/`，没有改变生产 nic0、dhcpcd、
dnsmasq 或 strongSwan。

## 自动同步

`pd-sync.py --config FILE` 读取 VPP `wan-pd` 租约及 LAN BVI 实际消费的 /64，
确认指定 WAN 有 IPv6 默认路由后发布 PIO：

- 获取前缀时先发 L=1/A=0、短 valid lifetime 且 preferred lifetime=0 的 PIO，清除客户端可能缓存的 on-link
  路由；等待超过一次最大 RA 周期后，发布 L=0/A=1 的 SLAAC PIO。
- PIO 有效期/首选期来自租约剩余时间；同前缀续租只刷新变化的到期时间。
- 只发布实际配置到 BVI 的前缀。重叠期保留仍有效的 PIO，VPN 池继续使用当前
  首选且已消费的前缀；旧前缀撤销后切换至新前缀，不根据未消费的新 PD 猜地址。
- 前缀撤销、失效或指定 WAN 默认路由消失时，发送 L=1/A=1 的短 valid lifetime、preferred lifetime=0 PIO，撤销 on-link 路由并废弃旧 SLAAC 首选地址，
  同时撤销 VPN
  IPv6 池，保留原 IPv4 池；清理等待期结束后删除旧 PIO。
- 状态存放 `/run`，只有状态变化才写 RAM 文件。同一 VPP 下重启同步程序会复用
  状态，不重新清除工作中的前缀。CLI socket 更换后重新建立发布状态。
- VPP 读取失败时保留最近状态并重试，不把命令失败当成没有租约。

可选 `ipsec_config` 使用现有 `tools/ipsec/ipsec-prefix-sync.py` 的池计算与
原子写入函数，更新两个 `rightsourceip`，保留 IPv4、认证及其他配置。
证书/`%default` 的 IPv6 范围仍是 `前缀::100–前缀::200`（包含两端），排除已有有效 DHCP 租约。
`eap-mschapv2` 保持唯一本地地址（例如 `fd42:1111:2222:60::/64`），不领取公网 PD。
该 ULA 的互联网出口由 ABF 621 经 `loop10` 送到 VPS `fd42:1111:2222:20::1`。VPS 把 `fd42:1111:2222:60::/64` 与 wg8 `fd42:1111:2222:70::/64` 路由到 `::3`，源地址 mark `0x1` 经 `wg1` FULLCONENAT 出网（与 IPv4 `10.61.50.0/24` 相同），不走 AWS `ens5`。`vrouter_lease_tproxy` 仍对这两段源地址 return，避免偶发送到 `br-mgmt` 的内层进 LAN TPROXY。LAN ULA、LAN PD 与拦截的公共 DNS 仍留在 table-0 FIB。
配置内容不变时不写磁盘。可配置 `ipsec_reload_command` 命令数组；加载失败会
重试，但本次没有设置该项，也没有重载生产 strongSwan。

## VPP 续租标志修复

VPP 26.06 的 `ip6_ra_update_secondary_radv_info` 原来在续租刷新 lifetime 时，
把已配置 PIO 的 L/A/enabled 标志重置为默认值。仅靠定期 CLI 改回 off-link
仍会留下客户端学习 on-link 路由的窗口。

`docs/history/patches/ip6-ra-preserve-pd-flags.patch` 让续租保留已有三项标志。
`build/history/build-ip6-ra.py` 复制单个源码文件、复用原编译参数和其他对象，
只重编该对象并链接隔离 `libvnet`，不修改原源码、构建对象或安装目录。
产物 `/opt/vpp-vrouter-migration/ipv6-pd/lib/libvnet.so.26.06.0`，SHA256：
`d7bf4e00a790b9c679564867a2c547ec143fdf551bcd502de6e237991c03a91b`。

VPP 进程本身必须优先加载该目录；`vpp-runtime.conf` 是待整合的 service drop-in。
只设置同步程序的环境不能修复已运行的 VPP。集成测试读取 VPP `/proc/PID/maps`
确认真正加载了隔离库，并抓取实际 RA 验证反复续租后仍为 L=0/A=1。

## 部署准备

- `native-pd.vpp.conf.example`：VPP WAN SLAAC/RA 默认路由、原生 DHCPv6-PD、
  LAN BVI 前缀消费与 ULA；替换实际 WAN 接口名，不能直接附加到生产网络。
- `pd-sync.json`：将 `WAN_INTERFACE` 替换为真实 VLAN 100 接口名，核对 BVI。
  未替换时程序拒绝启动。默认 LAN RA 最大周期 10 秒，清除等待 12 秒；
  同步程序的 `ra_max_interval_seconds` 必须与 VPP RA 配置一致。
- `vrouter-pd-sync.service`：待整体迁移后安装，与 VPP 生命周期关联。状态使用
  RuntimeDirectory，不添加定时器或持久磁盘状态。
- 生产运行时配置为 `/etc/vpp/ipsec.conf`，由基础部署配置生成，并由 PD 同步器在
  原文件上更新动态公网地址池。测试使用独立临时配置。旧的
  `/opt/vpp-vrouter-migration/private-ipsec/ipsec.conf` 仅作为部署输入，不是运行时读取路径。

## 验证与剩余工作

`tests/integration/integration_vrouter_lan_services.py --workers 0|2 --ipv6` 使用隔离 VPP、
受控 PD/RA 上游和现有 LAN/DNS TAP，自动发布由独立同步进程完成，测试不再
显式写公网 PIO。验证初次获取、重复续租、抓包 L/A 标志、客户端无公网 on-link
路由、前缀变更、零 lifetime 撤销、旧地址不再首选、自动选择源地址、重新获取、
同步进程重启和池文件 mtime。
同时验证客户端公网 IPv6 转发、Linux DNS ULA 可达及既有 IPv4 DHCP/DNS/WAN。
`--tproxy` 可组合验证共享 TAP 的 IPv4/IPv6 TCP/UDP 代理。

`tests/unit/test_vrouter_pd_sync.py` 检查租约过滤、首选期过期、上游默认路由消失、读取
失败保留状态、配置稳定及进程恢复；原 IPsec 池单元测试继续复用。

IPv6 DNS 的 RDNSS/DHCPv6 公布与 gate IPv6 监听已完成隔离验证，配置见
`../lan-services/` 与 `../dns-route-gate/`：Linux 仅持固定 ULA、关闭 RA 接收
和自动配置，辅助 RA 不发布默认路由或公网前缀。WireGuard wg0 NAT66 已接入同一 PD 同步进程，详见 `../nat66/README.md`。
仍需整合完整防火墙，以及 VPP IPsec SA/回程路由和 strongSwan 控制面。更新池文件不等于
已经建立 IPsec 数据路径。本轮未连接实际运营商 PD，也未切换生产网络；
正式切换还须停用原 Linux PD 客户端并决定是否保留 DUID/IAID。

IPsec 接入联测增加 `ipsec_pool_routes`：池与 LAN 共用 /64 时，自动安装池范围
的更具体路由到 WAN 默认网关，使回包命中 WAN SPD。记录位于同一 `/run` 状态，
前缀撤销/网关变化清理旧路径，VPP socket 变化重建。实际 PD/EAP/重连验证和
非重启式 starter 重载边界见 `../ipsec/README.md`；生产 reload 命令仍未配置。

Linux 透明代理也需要池范围的更具体回程路由，否则重启后学习到的 LAN /64
直连路由可能使代理回复尝试对 VPN 客户端进行邻居发现。启用 `ipsec_pool_routes`
时，可另设 `host_interface` 和 `ipsec_host_gateway`，分别指定 Linux 到 VPP 的
接口及固定 IPv6 下一跳（例如 `vpp-host` 和设备的 VPP ULA 网关）。同步器会将
同一公网地址池的范围安装到 Linux，使用 metric 100；随前缀变化先添加新路径再
删除旧路径，撤销时清理，并在同步服务重启后重新应用。状态记录为
`ipsec_host_routes`。此配置使用固定 ULA 下一跳，不把动态公网前缀写死在启动单元中。
未设置 `ipsec_host_gateway` 时不管理 Linux 地址池路由。
