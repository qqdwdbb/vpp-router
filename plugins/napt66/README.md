# NAPT66：多个 LAN 客户端共享一个 WAN IPv6

独立树外插件，面向 VPP 26.06。LAN 使用 ULA，出站 TCP/UDP 源端口及
ICMPv6 Echo ID 被转换到单个公网 IPv6，回包根据会话返回原客户端。
映射以本地地址、端口、远端地址、端口及协议区分，回包必须匹配远端。
原有静态 `nat66` 插件不需要修改。

## 构建

在 Linux 上将本目录复制到匹配运行版本的 VPP 源码树 `src/plugins/napt66`，
通过 VPP CMake 构建；若设置了 `VPP_PLUGINS` 白名单，将 `napt66` 加入列表。
安装生成的 `napt66_plugin.so` 到该 VPP 的插件搜索目录，并在 startup.conf 中启用：

```
plugins {
  plugin napt66_plugin.so { enable }
}
```

本仓库安装器尚未自动集成此插件。需使用相同 VPP ABI；核心 C 单元测试
可以在 macOS/Linux 运行，不能代替 Linux 上的插件构建及实机转发测试。

```
python3 -m unittest discover -s tests/unit -p test_napt66.py -v
```

测试直接编译生产核心，覆盖端口冲突、协议回程、校验和、PTB 引用、
超时、端口耗尽和回收，并用 ASan/UBSan 检查 10 万个畸形输入。

## 配置示例

假设运营商仅分配 `2001:db8:1::2`（示例地址，实际使用必须替换）。
先完成 WAN IPv6 地址、默认路由及邻居发现配置；公网地址必须由 VPP 持有，
可以是 /128，但仍须有可达的运营商网关路由。插件不申请地址、不执行 DHCPv6。

```
set interface ip address lan0 fd66::1/64
set interface state lan0 up
set interface state wan0 up
napt66 inside lan0 outside wan0 prefix fd66::/64 external 2001:db8:1::2
show napt66
```

LAN 与 WireGuard 共用一个 WAN IPv6 时，可一次配置多个 inside：

```
napt66 inside loop0 prefix fd8b:d364:9a4c::/64 inside wg100 prefix fd42:1111:2222:90::/64 outside port0.100 external 2001:db8:1::2
```

最多 16 个 inside，每个接口一个 ULA 源前缀，接口不可重复、前缀不可重叠。
只匹配收到报文的 inside 所绑定的源前缀；所有 inside 共用端口池及会话表。
回程恢复客户端目的地址后，由 table 0 路由决定出口，需保留 LAN 直连路由
和 WireGuard peer /128 回程路由。重复执行命令整体替换所有绑定并清空会话。
inside 删除时自动移除绑定并清空共享会话，其他 inside 保持启用；outside
删除时关闭全部绑定。可使用 `tests/integration/integration_napt66_cli.py`
在无网卡的隔离实例验证配置、冲突拒绝、删除接口和关闭清理。

LAN 的 RA/SLAAC 或静态配置应给客户端提供 `fd66::/64` 地址、VPP 的
默认路由及可用 DNS。ULA 不需要运营商委派前缀。客户端可能按自身地址选择
策略优先访问 IPv4；用 `curl -6` 或 `ping -6` 检查 IPv6 路径。

重复执行配置命令会清空会话；WAN 地址变化后用新地址重新配置。
动态 WAN 地址可使用 [napt66-sync](../../deploy/nat66/README.md#napt66-动态-wan-地址)。
删除或重建接口前先关闭插件，再使用新接口重新配置。
`napt66 disable` 关闭两个接口上的特性并清空会话。
`show napt66` 回收过期会话并显示数量；`show errors` 显示转换和丢包计数。

## 范围与限制

- 多个 inside、单个 outside，部署时应位于 IPv6 table 0。inside 可为承载所有 LAN
  客户端流量的 BVI。不要在同一接口同时启用静态 NAT66。
- inside 输入特性只转换指定 ULA 源前缀发往 `2000::/3` 的流量，ULA、
  链路本地及组播目的地址直接通过。该部署要求这些全球单播目的地址均走 WAN；
  多出口、内网全球单播路由和 hairpin 不在本版范围内。
- TCP、UDP、Echo 请求/应答及入站 ICMPv6 错误类型 1–4（含 PTB）受支持，
  ICMP 引用中的地址、端口及可见传输层校验和也会还原。路由器自身的 Echo
  请求应答及 ND/MLD 控制消息不分配会话。
- IPv6 扩展头、分片、jumbogram、VPP 链式 buffer、其他传输协议和客户端
  发出的 ICMPv6 错误不支持；需要转换的此类流量丢弃。请先以普通 MTU
  的 TCP/UDP/Echo 验证；不能据此宣称任意 IPv6 应用均可使用。
- 公网端口/ID `49152–65535` 专用于 NAPT，共 16384 个会话（协议间共用容量）。
  路由器本地服务及主动连接必须避开这个范围；插件不接管本地端口分配器。
  低端口回包可继续交给本地协议栈，高端口无会话或远端不匹配则丢弃。
- 空闲超时：TCP 7440 秒、UDP 300 秒、Echo 60 秒；TCP 未细分握手、FIN/RST
  状态。每包增量回收，并在分配端口时回收过期项；无独立定时器。
- worker 共享会话表，由自旋锁保护。首先保证正确性，尚未进行吞吐或多 worker
  压测，不应据此宣称线速性能。
- 不提供端口转发或入站连接。NAPT 不是完整防火墙，仍需配置 IPv6 ACL，
  并允许必要的 ICMPv6 控制消息。未配置源前缀中的地址不受此插件转换。

## 验证

```
python3 -m unittest discover -s tests/unit -p test_napt66.py -v
```

测试直接编译生产数据面核心，验证相同源端口的客户端隔离、双向转换、
校验和、远端过滤、超时、满表回收、PTB 引用恢复和截断/不支持头部。
上线前还须在隔离 Linux/VPP 实例检查插件构建加载、LAN RA、WAN 邻居发现、
默认路由、双客户端 TCP/UDP/Echo、PMTU、多 worker 和地址变化重配。
