# VROUTER DNS/nftset → VPP 动态分流准备

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

LAN DNS 前端同时匹配 `br-mgmt`、实际 LAN 端口 `nic1`、VPP TAP 对端
`vpp-lan` 和历史接口名 `lan`。这样经过现有二层桥接的客户端仍会进入
DNS Route Gate，解析出的 `proxylist/proxylist6` 地址才会先完成 VPP 路由屏障。

生产 dnsmasq 继续运行于 Linux，仍可为传统防火墙写入 nftset；DNS Gate 的
VPP 路由不读取这些集合。当前出口映射：

- `inet/mangle/altroute → table 0 → 10.62.30.1 wg1`
- `inet/mangle/vpn → table 0 → 10.61.50.1 loop10`（br0 远端网关）
- `inet/mangle/vpn6 → table 0 → fd42:1111:2222:20::1 loop10`

`proxylist/proxylist6` are enabled through the shared LAN TAP to Linux; see the ordered-overlap policy below.
当前部署的域名出口配置包含 `uk`；其静态 set 成员也按相同映射安装路由。
已有 `/etc/dnsmasq.d` 不复制覆盖、不重启生产 dnsmasq、不修改现有 nft 表。
已离线验证 altroute 域名规则的解析，示例域名为 example.net。现有
dnsmasq 配置与本目录 nft 准备文件均通过语法检查。

## 运行方式

复用项目 `tools/dns-route-gate.py` 和 `nftset-route-sync.py` 的 VPP 路由
提交代码，不读取或监听 dnsmasq nftset。新增 IP 通过持久 Binary API 直接
提交；真实 DNS 每次应答前重新提交选定路由，等待 API 成功后才返回客户端，
不查询 FIB 判断路由是否存在。后台从观察账本恢复路由并处理配置变更和租约过期，
不自动审计 FIB，也不检查 WireGuard 线路/握手。
配置、出口不变且有效前缀没有撤回时跳过全量路由规划，仍校准租约接管集合，
以便在 nftables 重载后恢复接管。续租和已成功添加的新 DNS 路由均不触发全量规划；
添加失败、策略变更或租约过期撤回前缀时才重新规划。

Fake-IP 出口在域名配置中指定 `fakeip_range`，例如 IPv4 的 `198.18.0.0/15`
及 IPv6 的 `2001:2::/48`。同一地址池合并为一条固定路由，启动时安装成功后
才接受 DNS 查询。匹配该域名策略后直接返回 Fake-IP DNS 的应答，跳过主机路由
及租约写入，不逐地址检查范围。文档顶层 `fakeip_ttl` 默认 `604800`（7 天），
仅覆盖 Fake-IP 应答的 A/AAAA/CNAME TTL。旧 Fake-IP 主机路由和租约在启动迁移时清理。

`static_nftables_file` 指向 `/etc/nftables.conf` 时，Gate 还读取其中
`table inet mangle` 各出口 set 的内联 `elements` 和 `add element` 声明。
静态 IP、CIDR 和地址范围按 `/etc/vpp/dns-route-domains.json` 的出口顺序
分配 VPP 路由；重叠时前面的出口优先。只读取配置文件里的静态成员，
不导入 dnsmasq 运行时写入的 nft set 成员。修改 nftables.conf 后需重启 Gate
更新路由；服务或 VPP 重启时也会从该文件恢复。

需要为某个出口维护专用 IP/CIDR 列表时，可在同一个 route 中使用
`ip_range_files`。Fake-IP 的两个固定文件同时包含 Fake-IP 地址池和需要走该出口的
真实地址范围；文件每行一个 CIDR，也支持 `first-last` 地址范围。相对路径以 JSON
文件所在目录为基准，地址族必须与 `via` 一致，不能写默认路由。例如：

```json
{
  "name": "proxylist",
  "interface": "tap2490",
  "via": "10.63.30.2",
  "domain_files": ["tproxy.domains"],
  "ip_range_files": ["fakeip.ipv4"],
  "dns_upstream": ["127.0.0.1", 5354],
  "fakeip_range": "198.18.0.0/15"
}
```

Gate 会把这些文件中的网段与该出口的域名路由一起安装到 VPP；修改文件后重启
`vrouter-dns-route-gate.service` 生效。当前 Fake-IP 文件为
`/etc/vpp/fakeip.ipv4` 和 `/etc/vpp/fakeip.ipv6`，其中包含两个 Fake-IP 池和
Svc-a 的 ASN 网段，不再依赖 Svc-a 专用 nftables set 或安装脚本。

用户在 `/etc/vpp/dns-route-domains.json` 指定出口，并为每个出口引用一个或多个
域名列表文件：

TPROXY 的 `proxylist` 和 `proxylist6` 共用 `tproxy.domains`，分别指定 IPv4、IPv6
下一跳；从 dnsmasq 导出时合并两组域名并去重，只生成这一份列表。

```json
{
  "routes": [
    {
      "name": "altroute",
      "interface": "wg1",
      "via": "10.62.30.1",
      "fib_table": 0,
      "domain_files": ["altroute.domains"]
    },
    {
      "name": "vpn6",
      "interface": "loop10",
      "via": "fd42:1111:2222:20::1",
      "domain_files": ["vpn6.domains"]
    }
  ]
}
```

`/etc/vpp/altroute.domains` 等文件每行一个域名，空行和 `#` 注释可用：

```text
# Research sites
example.net
example.org
```

相对路径以 JSON 文件所在目录为基准，也支持绝对路径。`domains` 数组仍可与
`domain_files` 并用，适合少量临时域名；日常维护直接编辑列表文件。
列表文件缺失、为空且没有内联域名，或包含无效域名时，Gate 拒绝该配置。

需要按关键字匹配任意位置的域名时，可使用 `domain_keywords`；匹配到该规则后，
如果设置了 `dns_upstream`，该查询会转发到指定的 DNS，同时解析出的地址会按
同一条 route 的 `interface`/`via` 安装 VPP 路由。例如：

```json
{
  "name": "sample-edge",
  "interface": "tap2490",
  "via": "10.63.30.2",
  "domain_keywords": ["demo-edge-node", "dualstack.demo-edge"],
  "dns_upstream": ["127.0.0.1", 5354],
  "fakeip_range": "198.18.0.0/15"
}
```

`sample-edge6` 使用相同的示例关键字和 `2001:2::/48` Fake-IP 池，出口为
`tap2490`/`fd42:1111:2222:30::2`。命中后 Gate 返回固定池中的 Fake-IP，跳过
动态主机路由写入。

`dns_upstream` 只接受 IP 地址和端口，未匹配专用上游的查询继续使用 gate
配置中的全局 `upstream`。

域名匹配自身和子域名。`via` 的地址族决定该出口安装 A 还是 AAAA 路由；
同一域名可分别放进 IPv4 和 IPv6 出口。服务启动时读取配置和域名文件，
运行期间不检查文件变动。修改后手动重启 `vrouter-dns-route-gate.service` 生效，
撤销已移除域名的路由，并将仍匹配的已观察地址切换到新出口。
配置错误时启动失败。首次迁移可运行
`vpp-dns-route-gate --config /etc/vpp/dns-route-gate.json --export-domain-routes /etc/vpp/dns-route-domains.json`
从现有 dnsmasq 规则生成可编辑的初始列表，核对后启动 Gate。以后只修改这份
JSON 中的出口或对应的 `.domains` 列表；dnsmasq 的 nftset 规则可以独立维护。
导出命令会同时生成 JSON 和每个出口的 `.domains` 文件，遇到已有文件会拒绝覆盖。
首次切换时，旧观察账本中无法反推域名的地址会作为过渡路由保留到原有空闲
期限；它们不再由 nftset 更新。修改某个出口或其域名文件后，该出口的过渡
路由立即失效，其他出口不受影响；之后只按新规则和已观察到的域名维护。

官方 Python API 来自 VROUTER 同一 VPP 源码，隔离复制到服务器
`/opt/vpp-vrouter-migration/runtime/python/vpp_papi`，没有替换系统 Python 包。
API schemas 使用当前安装树 `/opt/vpp-nic1-test/vpp/share/vpp/api`。
`runtime.env` 指定 Python/API/库/命令路径，后续服务需通过 EnvironmentFile 加载。
这不是额外后台进程，也不需要编译 Python 扩展。

运行时路由和 DNS 观察账本保存在内存中，正常停止时落盘。
配置 Fake-IP 固定路由后，启动同步完成也会保存迁移结果，避免异常退出后
重新读取已删除的主机路由记录。复用原服务的
`After=vpp.service` 与 `PartOf=vpp.service`，VPP 停止前先停止 gate、保存状态；
不得另加每秒保存任务。强杀/断电不再依赖 dnsmasq nftset 恢复。

## 准备文件与未完成的前端

本目录部署在服务器 `/opt/vpp-vrouter-migration/source/scripts/vrouter/dns-route-gate/`，
尚未安装到 /etc/vpp 或启用 service。

- `nftset-route-sync.json`：altroute、vpn、vpn6 映射及固定排除，保护 WG
  代理传输网段、LAN 和 br0 `10.61.50.0/24` / `fd42:1111:2222:20::/64`。
- `dns-route-gate.json`：在 Linux `10.61.20.2` 和 `fd42:1111:2222:10::2` 监听 1053，
  上游为该地址上 dnsmasq 的 53，读取独立域名列表 JSON。
- `dns-route-gate.nft`：LAN 客户端 TCP/UDP 53 由 VPP ACL/ABF 按端口送至 Linux，再由 nftables DNAT 到 Gate。覆盖 IPv4/IPv6，不依赖公共 DNS 地址名单，仅匹配 LAN 源地址；VPN 保留原 DNS 配置，不附加 DNS 引流策略。Linux 本机上游查询在 VPP ACL 中豁免；详见 `../dns-intercept/README.md`。
  gate 到 dnsmasq 的本机请求不经 prerouting，不会递归。
- `runtime.env`：同版本官方 API 的环境配置。
- `vrouter-runtime.conf`：供现有 `vpp-dns-route-gate.service` 的 drop-in 使用，
  将 ExecStart 指向迁移源码并加载上述环境；现有依赖和停止保存顺序保持不变。
  待整体启动集成时安装，当前未写入 /etc/systemd/system。

正式启用前必须先完成 br-mgmt/.2、dnsmasq 监听地址和服务启动顺序。
示例中 DHCP 直接公布 Linux DNS 10.61.20.2，网关仍为 VPP 10.61.20.1。
不需要网关 .1 的 DNS 转送或 ABF。二层 TAP 与 DHCP 方案见
`../lan-services/README.md`；IPv6 DNS 通过固定 ULA 的 RDNSS/DHCPv6 公布，
辅助 Linux RA 的 router lifetime 为 0，不取代 VPP 默认路由。
Linux br-mgmt 关闭 accept_ra/autoconf，防止 dnsmasq constructor 误宣告公网前缀。
vpn6 的 AAAA 经 VLAN 10 BVI `loop10` 指向 br0 网关，见 `../vps-bridge/`。
配置已写入本目录 JSON，尚未安装到 /etc/vpp 或启用服务。

WireGuard 手动重建必须沿用接口锁与内存账本：重建前移除旧索引的已管理路径，
创建新接口后更新锁时间。此模块仅刷新 API 索引并恢复期望路由，不管理 WireGuard。

## 隔离验证入口

`tests/integration/integration_vrouter_dns_route_gate.py` 启动独立 VPP systemd 单元、临时 dnsmasq、
模拟 DNS 上游、临时 nft 表与实际 gate 主进程，不绑定物理网卡。

检查 DNS 应答屏障（排他锁暂时阻止路由安装时不得提前应答）、TCP DNS、
未匹配域名不装路由、直接 nft 新增事件、monitor 断线恢复、受控 WireGuard
接口重建后的索引刷新、VPP 重启恢复、API 失败返回不含地址的 SERVFAIL，
以及运行时不写账本、正常停止才保存。后台每 60 秒校准配置和租约，
接口重建后由下一次 DNS 查询重新提交路由，不依赖周期性 FIB 审计。

真实 API、dnsmasq 和 nft 均参与；WireGuard 接口只供路由指向，业务数据转发
已在上一阶段的 EI/加密/代理集成测试验证，本测试不冒充真实网站或上游可达性检查。

`vpn`/`vpn6` 经 VLAN 10 BVI 的隔离转发见 `tests/integration/integration_vrouter_vpn_br0.py`：
临时 nft 表写入样例地址，Binary API 安装经 `loop10` 指向 `10.61.50.1` /
`fd42:1111:2222:20::1` 的路由，并从模拟 LAN  ping 通远端；不改生产
`inet mangle vpn/vpn6`，不绑 nic0。


IPv6 前端验证使用 `tests/integration/integration_vrouter_lan_services.py --ipv6`，由原 gate
同时处理 IPv4/IPv6 UDP/TCP；AAAA 应答的目标 /128 通过 Binary API 安装，
IPv6 监听也必须遵守路由屏障。测试使用受控域名与临时 set，不启用生产 proxylist6。
停止 gate 后，两种 IP 传输的查询都不能直接绕过重定向访问 dnsmasq。

## VPP outage and joint PD recovery

`tests/integration/integration_vrouter_lan_services.py --workers 2 --ipv6 --recovery` keeps the
PD publisher, DNS gate and dnsmasq running while stopping and rebuilding the
private VPP instance. It checks that an API outage preserves the pool and blocks
DNS answers requiring unavailable routes, then reacquires PD/SLAAC and restores
both families of DNS routes and UDP/TCP queries. Test-only upstream DHCPv6 and RA
capture processes are rebound to the recreated TAPs; they are not the services
whose uninterrupted recovery is being measured.

The first run exposed stale generation caching: a leftover CLI socket could
retain the old InvocationID after VPP stopped. `Backend.generation()` now checks
its cached process PID and `/proc/PID/stat` start time before returning the cached
invocation. Dead processes and PID reuse fail the DNS barrier; active queries
retain the cached systemd lookup. A new invocation must belong to an active unit.
The change remains in migration source; no production daemon was restarted.

## Ordered overlaps (production, 2026-10-18)

The explicit `overlap_policy: "first"` follows mappings order:
uk, altroute, vpn/vpn6, then proxylist/proxylist6. Earlier observed DNS claims win.
Lower-priority ranges are split around earlier ranges/hosts, preserving
the configured priority despite VPP longest-prefix routing. Other configurations
still reject conflicting prefixes unless they explicitly select this policy.

DNS answers and ledger-based background reconciliation share this ordering.
The controller serializes ordered updates; owned next-hop replacements use
delete then add, never ECMP. Every DNS answer re-submits its selected paths and
waits for Binary API success, including repeated answers whose paths may have
been removed externally. The request path neither queries FIB nor runs a full
reconcile. Background reconciliation does not automatically audit FIB; an
explicit controller `force_audit=True` remains available for diagnostics.
Host overlap checks use prefix indexes rather than comparing every host in a
later policy with every earlier host.

Private/local and carrier IPv6 exclusions match the existing nft early returns.
The current proxy upstream addresses are also excluded to avoid recursive proxy
routing; update those exclusions if the upstream addresses change.
`tests/integration/integration_vrouter_route_overlap.py` uses a separate VPP instance and a
hook-free temporary nft table for real Binary API and DNS barrier validation.

### Stage dnsmasq domain includes

The migration unit invokes dnsmasq directly. During bundle preparation it copies
regular files from `/etc/dnsmasq.d` into the bundle's private `config/dnsmasq.d`
directory and removes every `nftset=` directive. The generated configuration
points only to that staged directory, so vrouter-dnsmasq keeps domain-specific
upstreams and cache rules without depending on nftables sets. The original
`/etc/dnsmasq.d` files are never included directly at runtime.

### 路由租约与 TPROXY 接管

`proxylist`/`proxylist6` 的 DNS 元素可以按原超时消失，但仍有效的 VPP 路由不能依赖它们接管流量。对应映射的 `tproxy_set` 指向同步器独占的 `inet/mangle/vrouter_lease4`、`vrouter_lease6`，集合无 timeout，不由 dnsmasq 写入。同步器在安装路由前，以原 owner 与新目标的并集原子更新集合；VPP 撤销路径并验证后，再按剩余 owner/pending 更新集合。nft 更新失败时不安装新路由，VPP 撤销失败时保留接管元素。

`dns-route-gate.nft` 同时持久化租约接管链和独立的防环链。接管沿用生产的 mark 1 和端口 2080；防环在 forward 优先级 -1 丢弃 `br-mgmt → br-mgmt` 的路由转发，不依赖任何域名集合。本机 socket 回包不走 forward。部署要求管理桥承担主机服务和透明代理，不应把 Linux 用作该接口到同接口的普通三层中转。

全量 `nft -f /etc/nftables.conf` 重建后，租约集合暂时为空，防环链立即生效；同步器在下次全量同步（当前最多 60 秒）重建集合。这期间连接可能被丢弃，但不会产生回送环路。需要立即恢复可重启 `vrouter-dns-route-gate.service`，无需重启 VPP。
