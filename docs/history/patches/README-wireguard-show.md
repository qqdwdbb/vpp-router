# VPP WireGuard `wg show`

补丁：`wireguard-show.patch`，基于 VPP stable/2606 的原生 WireGuard 插件。

它新增 Linux 风格的 CLI：

```text
wg show
wg show wg0
```

输出每个 WireGuard 接口的公钥和监听端口，以及每个 peer 的公钥、endpoint、
allowed IP、persistent keepalive、最近一次完成握手距今的时间和收发字节数。
握手时间按秒、分钟、`h` 和 `day` 分段显示；收发量会自动使用 B、KB、MB 或 GB。
每个 peer 之间以及不同接口之间输出空行。Peer 按最近握手时间从近到远排列，未握手
的 peer 排在后面，并按第一个 allowed IP 排列。

收发字节数在 WireGuard 数据路径中按 peer 统计，口径是解密后的入站业务数据和
加密前的出站业务数据，与 Linux `wg show` 的 transfer 字段一致。握手时间使用
Unix 时间戳记录；未完成过握手的 peer 输出 `never`。

## 构建

在 VPP 2606 源码树根目录应用补丁，然后重新编译 WireGuard 插件：

```sh
patch -p1 --batch -i /path/to/wireguard-show.patch
ninja -C build-root/build-vpp-native/vpp wireguard_plugin.so
```

实际构建目录和目标路径按本机的 VPP 构建配置调整。补丁修改了 WireGuard 的
CLI、peer 状态和收发路径，需要和现有 WireGuard 源码一起重新编译，不能只替换
CLI 目标文件。

## 验证

加载插件后执行：

```text
vpp# wg show
vpp# wg show wg0
```

然后用已有 WireGuard 流量触发握手和数据包，检查 `latest handshake`、`received`
和 `sent` 是否增长。VPP 重启后这些运行时统计会从零开始。
