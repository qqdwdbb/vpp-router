# VROUTER 启动与恢复整合准备

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

此目录记录整体整合前的核对结果；尚无可直接安装的生产启动单元。
真实客户端接入已通过证书和 EAP 业务验证，物理 WAN/LAN 仍由 Linux 提供。
不要把临时公网联测单元设为开机服务，也不要直接安装通用 IPsec 单元。

## 现有组件与待适配项

| 组件 | 现有入口 | 整合约束 |
| --- | --- | --- |
| VPP | VROUTER 隔离测试生成的启动配置 | 最终物理拓扑、VLAN 和管理 TAP 尚需统一；先准备 namespace，再创建依赖它的 TAP |
| IPsec | `../ipsec/real-client-lab.py` | 有界公网测试专用，包含停原服务与到期回退，不能直接作为生产 daemon |
| 通用 IPsec | `../../ipsec/strongswan-vpp.service`、`../../ipsec/ipsec-prepare.py` | prepare 带有独立的接口名与 LAN 地址默认值，部署前需核对并调整 |
| PD / VPN 池 | `../ipv6/vrouter-pd-sync.service`、`../ipv6/pd-sync.json` | 替换 `WAN_INTERFACE`，确认最终池文件和迁移实例的 reload 命令；当前未设置 reload |
| DNS gate | `../../vpp-dns-route-gate.service`、`../dns-route-gate/vrouter-runtime.conf` | 等待 VPP、dnsmasq、nftsets；保留 API 环境和停止保存顺序 |
| 透明代理 | `../tproxy/setup-shared.py` | 等待共享管理 TAP、地址、集合与现有 SOCKS 后端；不重复启动生产监听器 |
| WireGuard | `../wg-proxy/README.md` | 复用准备的配置生成与回环 TAP；正式接入前处理旧实例和远端 endpoint 漫游 |
| 物理恢复 | `../restore-nic0.sh` | 尚未完成控制台回滚演练，不作为已验证的切换保障 |

## 启动阶段及就绪条件

1. 网络准备：建立控制面 namespace，核对独立恢复通道与最终接口清单。
2. VPP 启动：加载 VROUTER 修补库和插件；建立 VLAN、BD/BVI、管理和控制 TAP。
   API 可连接只是第一项检查，还需确认预期接口、地址与路由。
3. Linux 控制面：配置共享管理 bridge 的 `.2`/ULA、DNS/DHCP、TPROXY 与
   必要转发规则；恢复各 Linux 控制流量的回程，避免接口准备前启动依赖服务。
4. 隧道：加载 WireGuard，再启动 mandatory `kernel-vpp!` 的私有 strongSwan。
   检查两种认证 profile、VPP API 连接；生产旧实例的退出只能在切换窗口内执行。
5. PD 同步：在 IPsec 配置及 reload 目标就绪后启动；仅更新迁移实例。
   校验 PD/RA、池路由、撤销与重载重试，不将读取失败当作前缀撤销。
6. DNS gate：集合和出口接口可用后放行业务；检查 VPP 重启后接口索引重建。
   代理故障仍应保持原有防绕过规则。

systemd 的 After 仅表示启动顺序，不代表接口或 API 已就绪。后续实现应复用
已有就绪检查，先在隔离 namespace 中验证整个依赖链，再生成待安装文件。

## 策略与恢复验收

公网联测发现提前对 IPsec 客户端做 VPP SNAT 会遮蔽 Linux 源地址策略。
当前实验已保留客户端源地址，让 `10.62.20.0/24` 命中既有 mark 2 / vpn 表，
经 `10.61.50.1` 出口；用户重连复验正常。完整迁移后必须明确策略所在层，
在执行 NAT 之前分类，不能将本次依赖 Linux 的结果视为 VPP 策略已迁移。

隔离整合至少覆盖：正常启动、依赖延迟、VPP 重启、charon 故障、PD 读取失败/
撤销、DNS gate 重建、代理失败及停止清理。核对已有 SA/路由和规则重建结果，
仅清理实例拥有的资源，不清空全局规则，也不输出凭据或 SA 密钥。

生产切换前还需完成完整防火墙、真实吞吐、独立恢复通道和控制台物理回滚演练。

## 已完成：IPsec 私有 systemd 生命周期（2026-10-17）

复用 `tests/integration/integration_vrouter_ipsec.py` 的临时证书/EAP 和双栈业务，新增
`--lifecycle`，由 `integration_vrouter_ipsec_lifecycle.py` 管理私有瞬态 VPP/
strongSwan 单元。只在本用例中启用，不安装或替换生产单元。

```sh
python3 tests/integration/integration_vrouter_ipsec.py --workers 2 --eap --outer6 --lifecycle \
  --vnet-library-dir /opt/vpp-vrouter-migration/ipsec-ip6-udp/lib
```

就绪检查放在测试控制面的 ExecStartPost：确认该单元 MainPID 对应的私有
mount/network namespace 中已加载 kernel-vpp 和 lab profile，并已连接该
VPP 实例的 API。测试单元采用 Requires/After/PartOf 绑定、KillMode=control-group、
Restart=on-failure 和运行超时；输出与状态不包含 SA 密钥。

双 worker / IPv6 NAT-T 实测通过：

- starter 正常 restart 后更换 starter/charon PID，旧 VPP SA 清空；客户端
  重连，两族各 64 KiB 随机 TCP 内容校验通过。
- systemctl reload 向测试 starter 发送 HUP，不替换 starter 或客户端 IKE；
  再次验证双栈 TCP。
- 强制 SIGKILL 测试 starter，systemd 自动重启（NRestarts 增加），清理旧 SA；
  客户端重新认证并通过双栈 TCP。
- 停止测试 VPP，控制面按依赖顺序停止。结束后无测试 namespace/单元残留，
  原 strongSwan active，nic0 UP/r8125。

证据：`artifacts/vrouter/ipsec-control-lifecycle-20261017.json`。
现有默认集成入口仍按原方式运行；生命周期场景的回显服务接受五轮连接，
分别验证初始、正常重启、reload、starter 故障恢复和 VPP 重启重建后的内容。

这不覆盖单独 SIGKILL charon 子进程、VPP 崩溃后的自动恢复，或 PD/DNS gate/
TPROXY/WireGuard 的联合恢复。下一步应逐项接入这些依赖，不能将本轮标记为
完整生产启动或整体故障恢复通过。

## 已补齐：VPP restart 后的接口重建

生命周期场景保存初始 VPP 配置命令和私有 Linux namespace 的地址/路由恢复
清单，为其唯一测试 VPP 单元添加 `/run/systemd/system` 下的临时 ExecStartPost。
VPP 重启时先恢复 TAP/地址/路由/punt，再恢复 Linux 别名、桥成员和控制下一跳
邻居；依赖控制面通过 After/Requires/PartOf 等待 VPP 重建完成后重新就绪。
临时 drop-in 随测试清理，不安装生产配置，不扫描或修改其他实例。

首轮验证暴露了随机 TAP MAC 导致旧邻居缓存失效的问题。生命周期场景现在
为三个测试 TAP 指定固定 MAC，重启后核对 MAC 保持、控制 TAP ifindex 改变，
并验证新 VPP 无旧 SA，客户端重新认证后双栈各 64 KiB TCP 内容一致。
IPv6 外层抓包使用稳定的 veth 桥端口，重建 TAP 后继续观察真实封装流量。
默认非生命周期场景保留原 TAP 行为。

这仍是测试拓扑的重建机制，不能直接用于物理 DPDK/VLAN、生产 LAN 桥、
完整防火墙或真实 WireGuard 的重建。后续继续 PD/DNS gate 等依赖的联合恢复。

双 worker 的 IPv4 和 IPv6 NAT-T 外层两种场景均已通过本重建验证；证据见
`artifacts/vrouter/ipsec-vpp-rebuild-20261017.json`。结束核查无私有 namespace、
瞬态生命周期单元或临时 drop-in 残留，原 strongSwan active、nic0 UP/r8125。

## 验收重点调整

全面迁移后 VPP 是基础转发服务，停机导致路由器业务不可用属于预期；不把
“停机期间业务仍然可用”设为验收目标。主要门槛是 VPP 重新就绪后接口、
PD/默认路由、DNS 分流和隧道能否自动收敛，且不改变正常出口策略。
停机时 DNS 缓存的防御检查只保留窄回归，不扩展为完整高可用专项。

联合恢复用例使用 `--ipv6 --recovery`，只建立一次 PD/SLAAC 和 DNS 基线后进入
restart，不重复普通 `--ipv6` 用例中的完整换前缀/撤销流程；原普通用例保留。
PD/DNS gate/dnsmasq 保持运行，虚拟 DHCPv6 上游和 RA 抓包器需因 TAP ifindex
变化重新绑定。原生 PD 重新获取与业务回程才是恢复成功的判断依据。

## 已完成：独立 charon 子进程 SIGKILL 恢复已验证（2026-10-17）

在 IPsec 生命周期场景中补充了对 charon 子进程的单独 SIGKILL 故障注入：
- 模拟 charon 进程崩溃后，私有 starter 自动察觉并拉起新 charon 子进程。
- 客户端在服务端崩溃后，采用非阻塞 `stroke down-nb lab` 清理本地旧 IKE_SA 状态，避免因向无旧会话状态的新服务端发送 Informational DELETE 而阻塞超时。
- 随后执行 `stroke up lab` 完成重新认证并建立新隧道，两族各 64 KiB TCP 数据传输校验通过。
- 全部 14 项 lifecycle 断言全部通过：
  `systemd_readiness`、`graceful_starter_restart`、`old_sas_removed`、`client_reconnect`、
  `dual_stack_tcp_after_restart_and_reload`、`reload_preserves_starter_and_ike`、
  `starter_sigkill_systemd_recovery`、`charon_sigkill_starter_recovery`、
  `dual_stack_tcp_after_starter_failure`、`vpp_restart_rebuild`、`control_tap_recreated`、
  `tap_macs_preserved`、`dependent_control_restarted`、`dual_stack_tcp_after_vpp_restart`、
  `vpp_stop_stops_control`。

证据：`artifacts/vrouter/ipsec-lifecycle-charon-kill-20261017.json`。

## 已完成：全链路启动编排与级联故障恢复（2026-10-17）

在 `deploy/startup/` 下规范化了统一的 systemd 依赖链体系：
```
vrouter-vpp.service (核心转发表与 API 就绪检查)
  │  Requires/After/PartOf
  ├─► vrouter-network-prep.service (Oneshot: br-mgmt、TAP MAC固定、默认路由、静态ARP/ND)
  │     │  Requires/After/PartOf
  │     ├─► vrouter-dns-route-gate.service (Binary API 路由屏障、nftset 监听)
  │     └─► vrouter-strongswan.service (IKE 控制面、kernel-vpp、VPP API 绑定)
  │           │  Requires/After/PartOf
  │           └─► vrouter-pd-sync.service (IPv6 PD 同步、LAN PIO、IPsec VPN 池更新)
```

配合脚本与就绪探针：
- `vrouter-vpp-ready.py`：VPP API socket 存活与 `show version` 就绪门禁。
- `vrouter-strongswan-ready.py`：校验 `kernel-vpp` 插件加载、VPP Binary API 客户端绑定与 IKE 配置。
- `vrouter-network-prep.py`：管理桥接 `br-mgmt`（.2/ULA）、对齐 TAP MAC、双栈默认路由及对齐 BVI 静态邻居。

自动化隔离集成测试 `tests/integration/integration_vrouter_startup_orchestration.py` 在 VROUTER 实测通过：
1. **有序冷启动（Ordered Cold Boot）**：所有单元基于拓扑依赖严格按顺序启动，就绪探针阻止依赖项过早执行，各服务顺利进入 active (running)。
2. **稳态并发与功能校验（Steady-State Concurrency）**：
   - Linux host `br-mgmt` 顺利连通 VPP `loop200` 网关，ICMP 0% loss。
   - DNS route gate 成功通过 Binary API 在 VPP 安装 FIB 分流路由。
   - PD sync 成功与 VPP 握手并跟踪 generation。
3. **级联故障恢复（Cascading Auto-Recovery）**：
   - 对根单元 `vrouter-vpp` 触发 restart。
   - `PartOf=` 机制级联触发所有依赖单元安全停止并重新按序启动。
   - network-prep 重新绑定 TAP 并恢复静态邻居；DNS gate 与 PD sync 自动识别新 VPP PID 与 socket generation，重新建链并同步 FIB 路由与 VPN 池状态。
   - 重启后 host 到 VPP 网关通信与 FIB 分流路由全部自动收敛恢复。
4. **有序下线（Orderly Teardown）**：
   - 停止 `vrouter-vpp` 后，所有级联依赖项均被 systemd 完整干净地停止，无残留僵尸进程或游离 TAP。

证据：`artifacts/vrouter/startup-orchestration-20261017.json`。
本地 162 项单元测试全部通过。
路由器现场检查：nic0 UP/r8125 未切换，生产 strongSwan active，无残留测试 namespace 与 systemd 单元。


## 真实 strongSwan 联合启动验收入口

使用匹配的独立候选插件目录（NAT44-EI、nat-ei-context、IPsec punt 三者一起），
复用临时证书/EAP 客户端与真实 VPP/charon：

```sh
python3 tests/integration/integration_vrouter_ipsec.py --workers 0 --eap --startup-chain \
  --plugin-path /opt/vpp-vrouter-migration/nat44-ei-acl-order/plugins \
  --vnet-library-dir /opt/vpp-vrouter-migration/ipsec-ip6-udp/lib
python3 tests/integration/integration_vrouter_ipsec.py --workers 2 --eap --outer6 --startup-chain \
  --plugin-path /opt/vpp-vrouter-migration/nat44-ei-acl-order/plugins \
  --vnet-library-dir /opt/vpp-vrouter-migration/ipsec-ip6-udp/lib
```

`integration_vrouter_ipsec_startup.py` 从本目录的 network-prep/firewall/strongSwan/
DNS gate/PD service 模板派生私有测试单元，仅替换实例名、namespace、路径和测试配置。
实际启动 starter/charon、mandatory kernel-vpp、统一防火墙、DNS gate 与 PD poller。
通过 systemd 单调时钟验证依赖就绪顺序；正常 VPP restart 后必须重建 TAP、重启依赖、
恢复 DNS FIB 路由和 PD 代际状态，再重新认证并验证双栈 TCP 内容。
停止测试 VPP 后检查依赖停止，随后清理测试单元及 namespace。
旧 `integration_vrouter_startup_orchestration.py` 仅为 VPP/network/DNS/PD 子集测试，
不能代替此入口。

生产模板中的 strongSwan 现在使用独立 network/mount namespace、私有 `/run`、
明确的 `/etc/vpp/ipsec.conf` 和插件目录。ExecStartPost 用 systemd 的 `$MAINPID`
定位目标，避免在私有 `/run` 内访问不到 systemd bus；只读绑定 `/run/vpp` 保留 CLI 可见性。
reload 向本单元 starter 发 HUP，不触及原 strongSwan。尚未准备命名空间、配置、
插件、证书挂载、控制 TAP 前，不应直接安装模板。

即使 IKE 仅走 IPv4，VPP 启动配置也必须在 `ipsec cleartext ingress CONTROL_TAP`
之前执行 `enable ip6 interface CONTROL_TAP`，或已经为该 TAP 配好 IPv6 transit 地址。
解密插件现在分别接入 IPv4/IPv6 明文节点，避免 VPP 按目标节点复用 next-slot 导致
IPv6 绕过逻辑入口；WAN 默认拒绝规则保留。IPv4/IPv6 的输出 SPD 均先于 WAN ACL。

范围：验证目标服务链在隔离 namespace/TAP 中的启动、业务与正常重启收敛；
PD 在链中验证真实进程与 VPP 代际同步，地址池换代仍由独立 PD/IPsec 用例负责。
这不替代公网手机复验、物理 nic0 切换、物理吞吐或独立恢复通道演练。

本轮 VROUTER 重放副本位于 `/opt/vpp-vrouter-migration/nat44-ei-acl-order/source`；
在该目录执行以上集成命令。完整 186 项单测是在本地完整工作区运行。

## 2026-10-18：固定目录本地安装

现场服务已迁入 `/etc/systemd/system`，配置位于 `/etc/vpp`，运行程序及私有库位于
`/usr/local/lib/vpp-vrouter`，状态及回退快照位于 `/var/lib/vpp-vrouter`。
`sudo vppctl show version` 可直接调用；不再依靠 shell 临时 PATH。
前文 `/opt` 路径保留为试部署和构建历史。DPDK 的固定搜索路径通过仅 VPP 服务
可见的只读挂载映射承接，实际库来自新安装树。安装、确认和恢复步骤见
[本地安装说明](../install/README.md)。本次没有启用开机接管，尚未整机重启验收。
