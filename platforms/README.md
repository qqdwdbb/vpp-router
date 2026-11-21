# 平台相关内容

部署和 VPP 补丁不依赖这里的内容。只在硬件匹配时使用。

| 目录 | 适用 | 内容 |
|---|---|---|
| `rtl8125-noncoherent` | RTL8125 + 非一致性 DMA 的 ARM64 平台 | DPDK r8169 PMD 补丁（多队列、缓存维护、批处理、计数修复；RSS 配置与 `l3-src-only`），另外需要 VPP 补丁 0001 |
| `rk3588` | RK3588 + Rockchip vendor 内核 | 固定 DDR 最低频率的 systemd 服务 |
| `n1-dwmac` | Phicomm N1（Amlogic S905D）的 DWMAC 平台网卡 | 原生 vdev PMD、独占 DMA 的内核 helper、VPP 驱动注册补丁，见 [n1-dwmac/README.md](n1-dwmac/README.md) |

带 `vpp-router.conf` 的目录是平台网卡描述，`deploy/install/vpp-router-install.sh` 用它识别非 PCI 网卡并编译对应的 PMD 和内核模块。

一致性 DMA 的平台或其他网卡不需要这些补丁。

## RTL8125 RSS（dpdk-patches 0002）

原 PMD 启动时固定开启全部哈希类型，并且每次启动都随机生成密钥，`rte_eth_dev_configure` 传入的 `rss_hf` 和密钥都不生效。0002 改为：

- 配置时传入的哈希类型和 40 字节密钥在端口启动时写入网卡；没有指定类型时仍开启全部类型。密钥在停止、启动后保持不变。
- 新增 `RTE_ETH_RSS_L3_SRC_ONLY`：只按源地址选队列。PMD 清零密钥第 61–93 位和第 157–285 位，使目的地址不影响哈希结果的第 1、2 位，并让队列表只取这两位。为了让同一 /24 内的主机能分到不同队列，密钥第 60 位固定为 1。
- `l3-src-only` 需要同时开启 `ipv4` 或 `ipv6`，RX 队列数只能是 1、2 或 4；配置不符合时 `rte_eth_dev_configure` 返回 `-EINVAL`。TCP、UDP 类型在这一模式下不参与哈希。
- 查询哈希配置时返回网卡实际使用的密钥（即清零后的密钥）。

VPP 不需要改动，写法如下：

```
dev 0003:31:00.0 { name eth2-dpdk num-rx-queues 2 rss { ipv4 ipv6 l3-src-only } }
```

单靠这项配置得不到多 worker 的收益：NAT44-EI 仍按自己的哈希选 worker，跨核转交的包数不会减少。

**验证情况（2026-11-06，RK3588 开发板的 RTL8125B rev 05）：** 共 10 组测试。发包机发送约 9600 帧，覆盖 452 个源地址；每帧的硬件哈希都与软件 Toeplitz 一致，队列也都与队列表一致。`l3-src-only` 下同一源地址始终落在同一队列。指定密钥、中途停止再启动、配置不合法时拒绝，这几项都通过。VLAN 100 和 VLAN 10 的帧也会被正确哈希。带扩展头的 IPv6 包（如 MLD）不做哈希，固定进队列 0。

**未验证：** 运行时调用 `rss_hash_update` 切换到 `l3-src-only` 的路径。测试中发现这条路径没有重算队列表，修复后没有再上硬件测试；VPP 不走这条路径。RTL8125A 和一致性 DMA 平台也没有测试。
