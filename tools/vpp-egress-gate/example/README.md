# vpp-egress-gate 用户配置

正式的命令行用法、配置字段、单文件/拆分配置、systemd 调用及排障说明见
[VPP Egress Gate 使用手册](../README.md)。本页保留常用出口配置示例。

一份 JSON 即可：监听地址、VPP 运行参数、以及域名出口。

## 真实 DNS 出口

域名文件里的名字（含子域）走指定下一跳；未写 `dns` 时用全局 `upstream`。一条出口同时覆盖 A / AAAA，默认 v4 和 v6 从同一张网卡出去。

```json
{
  "name": "vpn",
  "interface": "loop10",
  "via": ["10.61.50.1", "fd42:1111:2222:20::1"],
  "domain_files": ["vpn.domains"]
}
```

只写 IPv4 下一跳时，AAAA 直接返回空应答（NODATA），不查上游、不装 v6 策略路由，也不会掉到后面的出口：

```json
{
  "name": "altroute",
  "interface": "wg1",
  "via": "10.62.30.1",
  "domain_files": ["altroute.domains"],
  "dns": ["8.8.8.8", 53]
}
```

`domain_files`、`ip_range_files` 可以是字符串或数组，写绝对路径或文件名，只写文件名时在 `/etc/vpp/gate` 下查找，所以本目录的 `.domains` 文件要放到那里。也可用 `domains` 内联列表、`domain_keywords` 子串匹配、`ip_range_files` 静态网段。

## Fake DNS + TPROXY

命中后把查询交给本地 Fake-IP DNS，VPP 只装地址池路由，流量由指定端口的 TPROXY 程序接管。

```json
{
  "name": "proxy",
  "interface": "tap2490",
  "via": ["10.63.30.2", "fd42:1111:2222:30::2"],
  "domain_files": ["proxy.domains"],
  "fake_dns": ["127.0.0.1", 5354],
  "fakeip_range": ["198.18.0.0/15", "2001:2::/48"],
  "tproxy_port": 2082,
  "tproxy_interface": "vpp-tproxy"
}
```

`via` 和 `fakeip_range` 可以各写一个 IPv4 和一个 IPv6；A / AAAA 由 Gate 按地址族选下一跳。`fake_dns` 和 `tproxy_port` 只写一份。TPROXY 只绑 `tproxy_interface` 这一张网卡。

## 劫持客户端自定义 DNS

`hijack_dns` 默认关闭。打开后，启动时在指定网卡上把 TCP/UDP 53（含 8.8.8.8 等内置 DNS）重定向到 Gate 监听端口；进程退出时撤掉。不要和另一套 dstnat 53 规则叠两份。

```json
{
  "hijack_dns": true,
  "hijack_interfaces": ["br-mgmt"]
}
```

`hijack_interfaces` 可以是字符串或数组。所有 `listen` 地址必须用同一个端口。

## 生效

配置仅在启动时读取，运行期间复用内存缓存。修改主 JSON、`.domains`、`ip_range_files`、`listen` 或全局 `upstream` 后，需要重启 Gate 进程生效。

## 动态路由生命周期

普通 DNS 答复命中域名策略后，Gate 先向 VPP 提交对应的动态路由，成功后才返回答复。Gate 按最后一次观察到该域名和地址的时间维护租约；`idle_seconds` 默认为 604800 秒（7 天），与 DNS 答复的 TTL 无关，也不表示实际网络流量的空闲时间。后台协调会撤销不再被有效租约或静态配置需要的受管理路由。

运行中的租约和路由账本保存在内存，正常停止时落盘；停止 Gate 不会主动批量删除 VPP 路由。启动时 Gate 恢复账本并协调路由，因此已过期或不再符合当前配置的受管理路由仍可能在启动时撤销。Fake-IP 使用配置的固定地址池，不为每个 Fake-IP 建立动态主机路由和租约。
