# DNS Gate 的 VPP 路由后端

当前入口是 `dns-route-gate.py`，配置和域名列表格式见
[deploy/dns-route-gate/README.md](../deploy/dns-route-gate/README.md)。

`nftset-route-sync.py` 仅作为公共模块，供 DNS Gate 和 WireGuard 接口导入器
复用。旧的独立同步入口、nft monitor 和元素事件解析器已移除。
它不再提供独立服务或 `--once`、`--dry-run`、`--withdraw` 命令。

DNS Gate 根据 DNS 应答匹配域名规则，通过持久 VPP Binary API 连接调用
`ip_route_add_del_v2`，检查每次返回的 `retval`。添加成功后才返回 DNS。
重复路径由 VPP 处理，查询路径不查询或确认 FIB，也不检查 WireGuard 握手。
后台协调用于恢复、过期清理和 FIB 审计，不读取或监听 dnsmasq 动态 nftset。
静态前缀可从配置的 `static_nftables_file` 中读取，DNS 拦截规则仍由 nftables 提供。

主机路由使用按 `(table, prefix)` 索引的内存字典，优先级计算只查找
受影响地址的祖先前缀。查询路径增量更新租约，完整账本只在后台快照、
接口导入器读取和正常停止时生成。账本和租约只在正常停止或重启时落盘；
强杀或断电可能丢失尚未保存的记录。

WireGuard 接口导入器通过只读 Unix socket
`/run/vpp-nft-route-sync/state.sock` 获取当前内存账本，接口重建前撤销
已管理的路径。保留该 socket 和账本文件名，以供现有导入器使用。

实机基准程序为 `benchmarks/benchmark_route_latency.py`，通过临时账本及保留
测试地址测量 DNS 首次添加至 VPP ACK 的时长，不包含上游 DNS RTT。
该程序需要 root，并使用现有 wg1 出口；结束后清理测试路由。
