# Linux 主机服务入口（IPv4）

## Linux 客户端回程路由优先级

`host-links.py` 的 JSON 配置中，`routes` 条目支持可选的整数 `metric`
（0–4294967295）；省略时保留 iproute2 的默认行为。例如：

```json
{
  "prefix": "fd42:1111:2222:90::/64",
  "via": "fd42:1111:2222::1",
  "interface": "vpp-host",
  "metric": 100
}
```

当客户端隧道运行在 VPP 中，而 Linux 同时存在同网段的 WireGuard 接口时，
透明代理的回复必须经 `vpp-host` 返回 VPP。Linux IPv6 直连路由通常使用
metric 256，未指定 metric 的 IPv6 静态路由通常为 1024；此时为该客户端网段的
VPP 回程路由显式设置 metric 100。地址及下一跳按设备配置，不修改所有路由的默认值。
应用后用 `ip -6 route get CLIENT_IPV6` 确认经过 VPP，并从客户端验证代理访问。
已存在的旧 metric 路由不会因添加新 metric 自动删除，应核对后按完整路由精确清理。

现场曾出现 WireGuard 客户端 IPv6 直连访问正常，但 Google IPv6 测试经透明代理
退回 IPv4：Linux 误选自身无活动握手的 `wg0` 作为代理回程接口。显式设置上述
回程优先级后，客户端重新测试通过。仅对确认存在冲突的网段配置该优先级。

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

LAN 与 Linux 主机共用 WAN 动态 NAT 地址 `10.61.10.2`，与上级光猫的 DMZ
目标一致。Linux 主机 `10.61.20.2` 是普通 NAT 客户端；在启用 outside 动态分配前，
仅为 `services.json` 明确声明的 WAN 固定端口建立优先映射。没有整地址主机映射，
不再使用 `.0.4` 客户端池或 VRF4094 保留池。

## 流量路径

- LAN 网关的未知 TCP/UDP 经 VPP punt 到 `br-mgmt`，可信来源访问
  `10.61.20.1` 时 DNAT 到主机 `.2.2`。TCP/UDP53 必须在通用 DNAT 前直接
  转到 `.2.2:1053` 的 DNS Route Gate，避免首次 NAT 后跳过后续 DNS NAT 链。
  VPN 网关 `10.62.10.1:53` 同样转到 `.2.2:1053`。
- IPsec 解密后的入口为 `tap4061`，需要单独配置
  `ip punt redirect rx tap4061 via 10.61.20.2 loop200`，才能访问网关
  `10.61.20.1` 的主机服务。该规则由 `cutover/runtime.py` 安装，
  与 WAN 上的 IKE punt 转交规则分别配置。
- 普通主机服务的固定 WAN 端口直接由 VPP 映射到 `10.61.20.2`，回包经
  `br-mgmt` 返回。gost 的 TCP 端口由设备配置声明，需另行确认服务已监听。
- **Nebula 不建立静态端口映射**。监听端口无论如何变化，都交给 VPP 动态 NAT，
  使用 `.0.2` 出口。`service-ports.py` 的监听发现仅提供清单，不参与启动端口预留。
  不为当前观察到的 `36145/UDP` 或其他 Nebula 端口生成固定规则。
- coturn 是专用路径：TCP/UDP42004、42005，以及 UDP49152–50151（1000 个端口），预留到
  `10.63.20.2`，经 `tap2480 / vpp-hostsvc` 进入 Linux，再 DNAT 到 `.2.2`。
  入站连接保存 ct mark `0x01000000`，回包经表2480返回专用 TAP。
  主动 coturn TCP/UDP 按服务 cgroup 识别，保存 `0x02000000`；主路由表具体
  内网路由优先，公网默认路由使用专用 TAP，并 SNAT 到 `10.63.20.2`。
  VPP 固定端口再转换到 `.0.2`，其余临时端口由同一 `.0.2` 动态池处理。
- coturn UDP 入站及主动 SNAT 的 reply 方向逐包核对 socket 所属
  `system.slice/vrouter-coturn.service`，同 UID 其他进程不能借旧 conntrack 接管端口。
  TCP 控制端口按固定端口准入。专用 TAP 默认丢弃未准入流量。
- LAN 客户端可以使用与固定服务相同的本地源端口；VPP 为其分配其他外部端口，
  避开固定端口和 coturn 中继范围。WAN ACL 保留反欺骗，允许发往 `.0.2` 的
  TCP/UDP 进入 NAT 查表，以便已有 EI 动态映射接收其他远端的新报文。
  没有映射的报文不会因整地址 fallback 进入 Linux 主机。
- VPP 原生 UDP identity 端口唯一来源为 `cutover/profile.json` 的
  `wan_identity_udp_ports`；已有的固定 UDP 转发仍保留。wg1 的 VRF101 和
  `10.62.30.2` 出口保持独立。

## 生命周期与边界

`runtime.reserve_host_ports` 在第一次启用 WAN outside 动态 NAT 前批量装入固定
映射。`host-fixed-mappings.vpp/json` 是运行时生成记录，不是不可变部署配置。
EI outside 接口全部配置后，用 `nat44 ei pool receive 10.61.10.2 nic0-dpdk.100`
固定池地址接收接口。候选插件只要求 `pool-receive-v1` 能力；共享池插件来自 `shared-port-candidate`，叠加
`docs/history/patches/nat44-ei-static-port-byte-order.patch`：静态映射参数为网络字节序，
端口占用 bitmap 必须使用主机字节序，添加/删除均需转换，防止动态分配占用 TURN 端口。

`host-path.py --watch` 每两秒原子刷新自己的 nft 表，以跟踪 coturn cgroup；
不修改 VPP NAT，也不需要跟踪 Nebula 端口变化。coturn 特权 ExecStartPre 在主进程
启动前加载规则，和 watcher 共用锁，避免旧快照覆盖启动策略。保留其他 mark 位。
路由规则优先级90–92、表2480和上述 mark 位由该路径独占；安装检查冲突，
写入所有权记录，回退只清理自身规则。专用表的 unreachable default 防止路由丢失
后意外回落。不能清空全局 conntrack 来迁移某个服务的旧 NAT 绑定。

`internal_services` 中的回环2080仅记录 TPROXY 内部用途，不生成 WAN 映射；
LAN 全端口 DNAT 的实际可用性仍取决于 INPUT 策略与 socket 监听地址。
IPv6 主机服务入口未扩展。UPnP 控制协议及动态端口映射后端不在本次修改范围。
共用 DMZ 地址不代表所有公网对端和应用的 NAT 类型均已验收。

## 验证和现场记录

隔离 VPP 回归：

```sh
python3 tests/integration/integration_nat44_ei.py --workers 2 --wan-identity ports \
  --shared-host-pool --reinit-nat \
  --host-policy-source deploy/host-services --plugin-path PLUGIN_DIRECTORY
```

检查普通固定入口、完整 TURN 范围、普通主机多个动态源端口、LAN 本地端口冲突、
其他远端访问已有动态映射、WAN/wg1 双出口 TCP/UDP/ICMP，以及 NAT 热重建。
`integration_vrouter_host_egress.py` 检查 Linux 双接口、DNS gate 与策略路由清理；
`integration_vrouter_turn_admission.py` 检查 cgroup 生命周期及同 UID 接管阻断。
这些使用隔离 namespace 和模拟服务，不等同于真实公网 TURN 分配/中继验收。

2026-10-18 现场最终包为
`/opt/vpp-vrouter-migration/shared-wan-release-20261018-v2`，源码为
`/opt/vpp-vrouter-migration/shared-wan-source-20261018`。旧 `.4` 分池部署已撤回。
该包从 Linux 基线重新 prepare/validate，包含不预留 Nebula 监听端口的生成器和
静态端口字节序修正插件；旧包及其 manifest 保留原样。未更改开机启动方式，
未进行整机重启或真实公网 TURN 中继验收。现有 PD 同步在启用后更新私有
`config/ipsec.conf` 地址池，manifest 保留原值；下一次从 Linux 试切前须重新
prepare/validate 新包，不用运行后的旧包绕过完整性检查。

最终记录见 shared-wan-deployed-20261018.json（`artifacts/vrouter/shared-wan-deployed-20261018.json`，未入库）。

### 后续固定目录安装

同日服务已迁至 `/usr/local/lib/vpp-vrouter`，配置迁至 `/etc/vpp`，运行状态、生成的
IPsec 池配置和回退快照迁至 `/var/lib/vpp-vrouter`，服务单元永久安装到
`/etc/systemd/system`。上文 release/source 路径为前一阶段历史记录。
主机与 LAN 共享 `.0.2`、Nebula 动态 NAT、coturn 专用路径的行为保持不变。
详见 [安装说明](../install/README.md) 和
现场安装记录（`artifacts/vrouter/fhs-deployed-20261018.json`，未入库）。
# 当前 LAN DNS 前端

网关 DNS 的首条 DNAT 与普通主机服务规则统一匹配
`br-mgmt`、`nic1`、`vpp-lan` 和 `lan`。LAN 保持现有二层桥接时，报文可能
从桥端口或 VPP TAP 对端进入，不能只依赖 `br-mgmt` 这个逻辑接口名。

## LibreSpeed 主机测速

通过 VCL/LDP 让独立 nginx 直接监听 VPP 地址的步骤、eventfd 配置及性能实测，
见 [nginx Host Stack 部署说明](nginx-hoststack.md)。

当前正式部署使用仓库中的
`nginx-hoststack.conf`、`nginx-hoststack.vcl`、`nginx-hoststack.service`、
`rk3588-vpp-nginx-hoststack.conf`、`librespeed-go.service`、
`librespeed-go.socket` 和 `librespeed-go.settings.toml`。HostStack nginx
监听 VPP 地址 `10.61.20.1:80`；测速 `/backend/`、`/results/` 反代到
`unix:/run/librespeed-go/http.sock` 上的 librespeed-go v1.1.6。页面是
LibreSpeed 6.3.1 静态前端，PHP 测速脚本未部署。Linux nginx 的
LibreSpeed server 配置不再加载。Go 走原始 syscall，不能 LDP 进 Host Stack。

`librespeed-backend.nginx.conf` 可 include 到已有 LibreSpeed 的 Nginx server
块内，把 PHP 兼容路径反代到同一 Go Unix socket。`^~ /backend/` 覆盖原 PHP
路径；`/backend/empty.php` 上传允许 128 MiB，并关闭请求缓冲。
Host Stack 路径上 `client_body_buffer_size` 与 VCL rx-fifo 对齐，并用
upstream keepalive。安装前备份原配置。

2026-10-30 现场发现 20 MiB 上传被拒绝为 HTTP 413，下载频繁写临时文件。
在 `/etc/nginx/conf.d/speedtest.conf` 加入同等配置后，2/20 MiB 上传均返回
200 且响应正文为空，20 MiB 下载长度正确。此为主机端接口验证，不代表
WireGuard/IPsec 实际吞吐验收；通过公网域名接入时仍需核对外层路径。
备份：`/var/lib/vpp-vrouter/history/<backup-id>/speedtest.conf`。

