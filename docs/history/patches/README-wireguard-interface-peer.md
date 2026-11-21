# WireGuard 跨接口复用 peer 公钥

补丁：`wireguard-interface-peer.patch`，基于 VROUTER 的 VPP stable/2606 源码。

原插件在全局 peer 池中检查公钥重复，握手 initiation 解密出客户端公钥后，
也在全局池中取第一个同公钥 peer。只放开添加检查会让握手选错接口。

本补丁同时修改：

- peer 添加的唯一性为 `(tun_sw_if_index, public_key)`；同接口仍拒绝重复。
- Noise 的 remote lookup 回调传入正在处理握手的 `noise_local_t`，查找条件
  增加 `r_local_idx`。不同接口即使本机私钥也相同，仍以独立 local 实例区分。

不修改 CLI/Binary API，不改变 peer index、会话 receiver index 或数据包加密
格式。回调为插件内部接口；构建时重新编译整个 WireGuard 插件，避免混用
修改前后的内部函数签名。

## VROUTER 构建

将补丁放入 `/opt/vpp-vrouter-migration/source/plugins/`，运行
`source/scripts/vrouter/build-wireguard-interface-peer.py`。
脚本复制 WireGuard 源码并应用补丁，复用原 Ninja 的编译/链接参数，头文件
优先读取复制目录。已有复制目录必须通过补丁反向 dry-run 检查。
原源码、构建对象和安装目录不修改。

产物：`/opt/vpp-vrouter-migration/wireguard-interface-peer/wireguard_plugin.so`。
验证后复制到迁移用的 `/opt/vpp-vrouter-migration/plugins/`；原版本先备份到
`baseline/wireguard_plugin-before-interface-peer.so`。

## 验证

`tests/integration/integration_wireguard_interface_peer.py --workers 0|2` 在独立 VPP 与
Linux netns 中生成临时密钥，不接管物理网卡，不读取生产密钥。

同一个 Linux 客户端私钥在两个接口复用，分别覆盖 VPP 本机密钥不同和相同
两种情况。检查真实握手、双向加密 IPv4/IPv6 ping、同接口重复拒绝、删除一个
peer 后另一个隧道继续通信、删除后的接口不误用另一接口 peer，以及重建后的
全新握手。冷握手先预热，每个已建隧道的短 ping 检查要求 5/5 回复。

生产配置仅在服务器本地的 `check-wireguard.py --interface all` 中加载，
核对 wg0 的 28 个和 wg8（sg）的 4 个 peer；不把配置加载等同于生产端握手。
测试不是吞吐或长期稳定性验证。
