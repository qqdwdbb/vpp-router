# NAT44-EI 双出口部署

服务器 `10.61.10.3`，VPP `26.06-release`。NAT44-ED 的 `nat_plugin.so`
已停用，IPv4 两个出口均使用 `nat44_ei_plugin.so`。

| 出口 | EI 内侧上下文 | 地址池 | 实际转发路由表 |
| --- | --- | --- | --- |
| host-vpp-wan | VRF 0 | 10.61.10.4 | 0 |
| wg1 | VRF 101（loop101） | 10.62.30.2 | 0 |

EI 的内侧会话键包含源地址、源端口、协议和内侧 FIB，不能直接按出口挑选
同一 VRF 中的两个地址池。`nat_ei_context_plugin.so` 在 wg1 的 IPv4 输出
阶段保存 RX 接口，临时使用 loop101 选择 EI 映射域，再恢复原 RX 接口。
VRF 101 的默认路由查表 0，使反向 NAT 后的流量回到原有路由体系。
`altroute → 10.62.30.1 wg1`、LAN 地址与网关均保持原配置。

## 输出链与 IPsec

原生 EI 输出节点会直接送到 interface-output，跳过后续输出功能。附加
插件将 EI 快速、慢速和 hairpin 完成节点的成功边接回输出功能链，继续
MSS 和 WireGuard 加密。WAN 通过 `nat44 ei output-chain host-vpp-wan`
启用链恢复，wg1 通过 `nat44 ei context wg1 loop101` 同时启用上下文与链
恢复。所有受管 EI 输出接口都必须启用相应配置。

IPsec 顺序插件保证 IPv4 入站先执行 IPsec 策略检查，再执行 EI out2in，
避免 EI 的直接查表跳过 ESP 解密。出站先做 IPsec 策略保护，再做 EI。
`wg_nat_order_plugin.so` 保证 EI、上下文恢复及 MSS 先于 WireGuard 加密。

## 配置与代码

- `/etc/vpp/startup.conf`：加载 EI、上下文及输出顺序插件，不加载 ED。
- `/etc/vpp/nat.conf`：启用 EI、WAN output-feature；在 WireGuard 配置前
  执行 `/etc/vpp/nat44-ei-context.conf`。
- `/etc/vpp/wireguard/wg1.conf`：EI output-feature、VRF 101 池、上下文。
- `/usr/local/sbin/vpp-egress-nat`：按出口维护地址池；根据静态配置声明的
  UDP 端口，把身份映射绑定到 DHCP 获得的 WAN 地址。EI 原生接口地址回调
  未注册自动地址池时不会解析待处理身份映射，因此这里显式处理，避免
  WireGuard/IKE 的本机 UDP 端口被丢弃或改写。
- `plugins/nat-ei-context/`：上下文与输出链插件源码和构建说明。
- `plugins/wg-nat-order/`、`plugins/ipsec-ike-punt/`：更新后的顺序插件。
- `tools/import-wireguard*.py`、`tools/vpp-wireguard-static.py`：生成、
  加载和重建 EI WireGuard 配置；重建 wg1 前解除上下文并清理受管路由。

编译依赖当前安装版本的 vpp-dev/libvppinfra-dev。插件操作 VPP 26.06 的
输出图及 buffer 元数据；升级 VPP 需要重新编译和验证。目前按现网的单
main 线程验证，多 worker/handoff 未进行负载验证。

## 已验证

### 动态端口分配失败回滚（2026-10-19）

`docs/history/patches/nat44-ei-port-allocation-rollback.patch` 修复 EI 慢路径：动态端口分配成功后，
若创建 NAT 用户或会话失败，立即归还该端口；静态映射不释放端口。
这避免用户表满时每个被丢弃的新连接继续占用端口。已泄漏的端口需要重启 VPP
以重建端口池。隔离复现用 `tests/integration/integration_nat44_ei.py --port-rollback-check`：
旧插件在 32 次用户创建失败后 UDP 占用端口从 1 增至 33，修补版保持为 1。

- `python3 -m unittest discover -s tests`：113 项通过。
- `tests/integration/integration_nat44_ei.py`：独立 VPP、三个命名空间，验证双出口
  TCP/UDP/ICMP、回程、相同源 UDP 端口及各自的 endpoint-independent 映射。
- `tests/integration/integration_nat44_ei_live.py`：现网 LAN 模拟客户端、临时 wg1
  Linux 对端，验证 nftset → 主表路由 → EI → WireGuard 加密 → 对端。
  同一 UDP 源端口在 WAN 映射为 10.61.10.4，在 wg1 映射为 10.62.30.2；
  两个出口的 HTTP 与 wg1 ICMP 均通过。真实 wg1 对端 10.64.20.3 仍
  不可达，此测试没有把临时对端结果当作真实线路已经恢复。
- LAN：公网 IPv4 ping、HTTPS 200、DNS。
- wg0：IPv4 公网 ping、IPv6 NAT66 公网 ping/HTTPS 200/DNS。
- IPsec：EAP 认证、VPP SA、IPv4/IPv6 公网 ping 与 HTTPS 200；Linux
  XFRM SA 为 0，ESP 由 VPP 处理。
- wg1 真实删除重建后，保留的 nft 路由约 0.38 秒恢复。

测试用命名空间、peer、地址、路由和账本记录均清理。NAT66、IPv6 PD、
DNS 路由屏障及停止时持久化的策略保留。

迁移前完整备份：`/root/vpp-nat-backup/<backup-id>/`。
服务器部署副本与源码位于 `/usr/local/share/vpp-nat44-ei/`。

## VROUTER 会话过期回收修复（2026-10-22）

VROUTER 的 EI 原实现只有按需回收；会话槽位达到 65536 后，新连接先触发
上限检查，空闲的旧会话仍可能长期占位。`build/history/nat44-ei-cleaner.c`
增加每秒触发的 worker 输入节点，每次最多扫描 4096 个槽位，在会话所属
线程调用原生释放函数，同时释放查找键、动态端口和用户链表。65536 槽位
约 16 秒扫描一轮；过期时刻之后还可能等待一轮扫描。静态映射配置保留。

同时修正 `nat44 ei del user` 使用错误线程索引以及最后一条会话释放后
继续访问用户链表头的问题，并修正 CLI 成功/失败判断反向的问题。
2026-10-22 08:27:35 的操作触发了 SIGSEGV 和 systemd 自动重启，
此前全表清空来自这次崩溃，并非正常的定向删除或过期回收。

构建入口 `build/history/build-nat44-ei-expiry.py` 使用现网
`/opt/vpp-vrouter-migration/nat-resource-fix-20261019` 的主源文件和慢路径对象，
以及 handoff 源目录中的 CLI 源文件，保留地址池接收、本机回程和动态
端口分配失败回滚。输出到 `/opt/vpp-vrouter-migration/nat44-ei-expiry/`。
该工具只构建；安装时必须原子替换 `.so`，再受控重启 VPP 才会加载。
安装前插件备份为同目录的 `nat44_ei_plugin.so.before-install`。

隔离验证（在路由器上以 root 运行，不使用生产物理网卡）：

```sh
python3 /opt/vpp-vrouter-migration/expiry-tools/integration_nat44_ei_expiry.py \
  --plugin /opt/vpp-vrouter-migration/nat44-ei-expiry/nat44_ei_plugin.so
# 双 worker 回归：追加 --workers 1-2
```

测试覆盖表满后的回收、UDP/ICMP/空闲 TCP 过期、活动 UDP/TCP 保留、
静态映射保留，以及定向删除不影响其他客户端。生产超时为 UDP 300 秒、
TCP established 1800 秒、TCP transitory 120 秒、ICMP 60 秒。
64 槽位分别通过单、双 worker 测试；8192 槽位通过跨批次扫描测试。
已于 08:46:30 受控重启加载，依赖服务恢复。现网检查中，空闲 UDP 会话
第 294 秒仍存在、第 315 秒已释放；持续每 10 秒发送数据的 UDP 会话保留，
ICMP 探测会话在 60 秒超时后释放。观察期间 VPP PID 不变、自动重启计数为 0。
记录保存在上述构建目录的 `BUILD.json`、`live-observations.jsonl` 和
`LIVE-VALIDATION.json`。
可用以下命令查看扫描和回收计数（`show errors` 同时包含普通统计）：

```sh
vppctl show errors | grep nat44-ei-expire-worker
vppctl show nat44 ei sessions
```

## 单 worker 本地发包崩溃修复（2026-10-22）

`vppctl ping` 可在主线程创建输出 NAT 会话。原实现仅在 worker 数量
大于 1 时启用 handoff；配置单 worker 时，回包直接在 worker 上读取
同索引的会话池。16:09:08 的 core 显示 ICMP 会话属于 thread 0，
thread 1 却读取了同索引的一条旧 TCP 会话，最终在
`nat44_ei_session_update_lru` → `clib_dlist_remove` 访问无效指针。
这也会造成回包被错误转换，表现为本地 ping 丢包。

`build/history/build-nat44-ei-single-worker.py` 从已部署的 expiry 修复
构建候选，保留端口回滚、过期回收及定向删除逻辑。只要存在 worker，
就初始化 worker 选择、帧队列和输入/输出 handoff，并同步静态映射
的 worker 记录。零 worker 仍走直接处理路径。
`plugins/nat-ei-context/nat_ei_context.c` 相应调整输出链游标处理，
两个插件必须配套更新并重启 VPP。

构建和隔离回归入口：

```sh
python3 build/history/build-nat44-ei-single-worker.py \
  --context-source /absolute/path/to/nat_ei_context.c
python3 tests/integration/integration_nat44_ei_local_ping.py \
  --plugins /opt/vpp-vrouter-migration/nat44-ei-single-worker --workers 1
# 零 worker 和双 worker：分别使用 --workers 0 与 --workers 1,2。
```

隔离回归使用 TAP 和临时命名空间，检查默认/显式源接口的本地 ICMP、
输出 NAT 的独立 VRF 上下文及删除接口。旧插件在同一测试中把回包
转换到 `0.0.0.0` 并丢弃；候选在零、单、双 worker 下全部通过。
既有 expiry 回归也通过单 worker 的容量、活跃 TCP/UDP、ICMP/UDP/TCP
过期、静态映射保留和定向用户删除检查。

现场插件备份：`/var/lib/vpp-vrouter/debug/before-single-worker-20261022/`。
原始 core 和对应旧二进制快照继续保留，不要用新插件解释旧 core。

## Worker 配置、HA 和管理面修复（2026-10-22）

`build/history/build-nat44-ei-thread-control.py` 在上述单 worker 修复之上
重建主文件、CLI、API 和 HA 对象，保留已部署的 in2out 端口回滚对象及
其他原始对象。构建结果位于 `/opt/vpp-vrouter-migration/nat44-ei-thread-control/`。
现有配套 `nat_ei_context_plugin.so` 保持不变。

- 重复应用相同 worker 集合直接成功，不重置会话或端口范围。
- **改变 worker 集合必须先禁用 NAT。** 启用期间，即使当前没有会话，
  也可能存在排队包，拒绝变更并返回 `VNET_API_ERROR_INSTANCE_IN_USE`（-147）。
  非空会话或静态映射也受保护。CLI 明确提示先禁用 NAT；该操作会中断
  连接并需要重建配置，应在维护期间执行，不要在生产中直接清空会话试探。
- HA 配置一个 worker 时也使用 handoff；刷新/删除会话前检查全局哈希的
  owner。消息中的越界线程号不会用于索引交接队列，进入 checked drop，
  `show errors` 可看到 `nat44-ei-ha` 的 `bad-thread-index`。
- CLI 正确显示单 worker，API 支持设置单 worker；零 worker 仍拒绝配置
  worker 集合。API/CLI 对实际集合变更返回一致错误。

隔离回归入口增加 `--thread-control`：

```sh
python3 benchmarks/diagnostics/run-nat-thread-audit.py \
  --plugins /opt/vpp-vrouter-migration/nat44-ei-thread-control \
  --thread-control --output /absolute/path/to/a-new-result-directory
```

零、单、双 worker × 输入/输出 NAT 的 90 项检查通过。其中涉及真正改变
worker 集合的用例在双 worker 下执行，验证启用期间拒绝、重复设置幂等，
以及禁用后改变并恢复集合。HA 用隔离 Linux UDP 对端发送 ADD/REFRESH/DEL，
验证主线程和各 worker 的归属、错误 owner 不改动会话、越界线程号拒绝。
这些是 HA 协议事件验证，不是双机故障切换验收。生产 HA 保持关闭。

双 worker 的容量、活动连接、会话过期和定向删除回归继续通过。候选详细
记录位于 `artifacts/vrouter/thread-control-20261022/`。

## out2in 的 DHCP 分支（2026-11-03）

特性链字符串以 `end_node_index` 结尾，它是全局节点号，不是 next 索引。走 worker handoff 时 `out2in` 不在链上，游标已被 handoff 用完，DHCP 分支再调用 `vnet_feature_next` 会把结束节点号当成 next 索引。在单 worker 且 handoff 位于链尾的配置下，一个发往 NAT 地址 UDP 68 端口且没有会话和静态映射的包就能让 worker 段错误。补丁 0011 改为在有 worker 时直接送 `ip4-lookup`。

