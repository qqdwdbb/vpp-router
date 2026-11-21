# IPv4 内层 / IPv6 UDP ESP 校验和修复候选

真实 Android IPv6 公网接入可完成 IKE/CHILD，但 DNS 和多网站失败。实验 TAP
观察到部分 VPP UDP6 回包校验和错误，而公网入站正常；仅对实验 TAP 的
IPv6 源地址与 UDP 源端口 4500 加 tc csum udp 后，用户确认业务恢复。

`ipsec-ip6-udp-family-flags.patch` 修正 VPP 26.06 `esp_encrypt.c`：
`set_ip6_udp_cksum_offload()` 标记 IPv6 外层时清除旧 IS_IP4，并在 ESP 加密
完成后由 IPsec 路径计算外层 IPv6 UDP checksum、清除该包的 UDP offload 标志。
这样只对 IPv6 UDP/4500 ESP 包走软件校验和，其他流量仍保留 DPDK 硬件 offload。

在 VROUTER 执行 `build/history/build-ipsec-ip6-udp.py`，复用现有 ninja 编译参数，
仅重编 ESP 对象，并保留已构建的 PD/RA 对象，链接独立 libvnet 到
`/opt/vpp-vrouter-migration/ipsec-ip6-udp/lib/`；不覆盖原构建或安装树。
候选库 SHA256：`28e6afa53304e849802104fe1966fdb9ed99b562f90582466a46f9d3a62fc801`。

隔离集成入口支持显式选择候选库并检查进程实际映射：

```sh
python3 tests/integration/integration_vrouter_ipsec.py --workers 2 --eap --outer6 \
  --vnet-library-dir /opt/vpp-vrouter-migration/ipsec-ip6-udp/lib
```

候选库通过双栈 ping、双族 64 KiB TCP、重连、rekey、断线 SA 清理；没有
使用 tc 校验和补偿。旧库在该隔离拓扑也通过，不能用该测试宣称复现了现场
故障。真实客户端候选库验证须单独记录，不将 tc 恢复等同核心补丁通过。

公网实验 `real-client-lab.py --serve` 同样支持 `--vnet-library-dir`，只在
有界临时单元中选择，不安装生产库。恢复时删除实验 TAP，原诊断 tc 规则
随接口删除；后续新建的复验 TAP 不含 tc csum 规则。物理 nic0 未修改。

候选公网窗口首次反馈无法连接：服务端收到重复 IPv6 IKE 初始请求并尝试发送
响应，未进入 CHILD 建立，需继续核对初始响应路径。候选真实接入未通过。

后续定位了独立的控制面邻居解析问题：namespace 以 WAN /128 别名发送时，
默认下一跳邻居可保持 INCOMPLETE。固定私有控制下一跳的实际 VPP MAC 后，
候选库真实 Android IPv6 外层接入、DNS/网页经用户确认正常，无 tc 补偿。
采样 VPP 回包与 WAN 发包均为有效 UDP6 校验和。候选库已通过本轮真实
路径复验；当时尚未安装为永久生产库。后续现场生产部署见下节。证据见
`artifacts/vrouter/ipsec-ike-response-path-20261017.json`。

## VROUTER 现场生产修复（2026-10-24）

现场复测发现，IPv6 NAT-T ESP 的服务端回程 UDP/4500 包在 WAN 上出现
`UDP checksum 0x0000`；入站校验和正常。根因不是 MTU、PMTU 或认证，而是
ESP 加密完成后的软件校验和修复使用了错误的 VPP buffer 基准。VPP 的报头偏移
相对 `b->data`，不能加到 `vlib_buffer_get_current(b)` 上。

最终补丁改为使用 `b->data + l3_hdr_offset/l4_hdr_offset` 写入并计算真实的
IPv6 UDP 头，然后清除 UDP checksum offload 标志，并清除残留的 IPv4 buffer
标志。最终生产候选库 SHA256 为
`f88c49facf7f665ce9bc3767dfb523667d60bada29ab4b58a74c9e069fb64cc9`，已通过
VROUTER VPP 重启加载。真实 IPv6 证书客户端重连后 SA 计数增长，用户确认测速正常。

本修复只针对 IPv6 UDP/4500 ESP；没有关闭全局 DPDK checksum offload，也没有
改变 WAN `tap4061`。LAN 侧另行将 `tap2000/vpp-lan` 创建参数恢复为 `gso`：
VPP `gso-enabled=1`，Linux GSO/GRO 开启，TAP 驱动的 TSO 仍为 off。

回归抓包应确认服务器到客户端的 UDP/4500 ESP 不再出现 `bad udp cksum`，并且
IPv4、原生 ESP、非 IPsec UDP/TCP 仍使用原有 offload 路径。生产库和拓扑备份
位置记录在 `docs/internal/HANDOFF.md` 的同日期章节中。
