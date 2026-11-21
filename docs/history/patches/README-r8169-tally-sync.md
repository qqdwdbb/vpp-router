# RTL8125 tally DMA 统计修复

2026-10-30，叠加在现有 DMA/TX-reclaim PMD 上；不改队列、descriptor 或 NAT。

## 修复

`r8169-tally-dma-sync.patch` 在 tally DMA 前后使用既有非一致性缓存同步，
超时返回错误而不发布旧快照，修正 16/32 位字段转换，并将 RTL8125 tally
缓冲扩为 192 字节。增加 15 项诊断 xstats；标准 `imissed` 仍使用原 16 位
`rx_missed`，没有改用 `rx_mac_missed`。

现场已验证主要 RX/TX 包计数恢复更新，与软件计数吻合。扩展区包括 octets
仍为零，尚未证明这些扩展项在当前硬件上有效；不能用零值排除 NIC 丢包。
结构参考 Linux r8169_main.c；曾提出替换标准 missed 的补丁被作者撤回，
因此保持标准计数语义。

## 验证与构建

`tests/integration/integration_r8169_tally_dma.py --source PATH/r8169_hw.c` 编译实际读取函数，
模拟分离的 CPU 缓存和 DMA 快照，检查更新、超时、位宽、布局与 xstats。
`tests/integration/integration_r8169_tx_reclaim.py --source PATH/r8169_rxtx.c` 检查既有 TX 行为。

在 VROUTER 使用 `build/history/build-r8169-tally-sync.py --assets DIRECTORY`。
assets 包含此补丁及上述两项测试。它使用 `maintenance/tx-reclaim/source` 和
保留的编译命令，不安装或重启。已有新版运行时须用 `--expected-installed`
指定当前库，并用 `--output` 指定新的空候选目录。安装使用既有升级工具的
`--candidate` 与 `--result` 参数，保留健康检查和失败回退。

当前接受库 SHA256：
`7b485442401538a53c157daa8f581e59c346070f897d5a38ec54eacbcf7b77d3`。
最终源码与维护资料位于 `/usr/local/src/vpp-vrouter/maintenance/tally-verified`。
安装输入 `migration/dma-pmd` 与恢复基准同步为该版本。

复测见 `artifacts/vrouter/rtl8125-tally-fix-and-retest-20261030.md`。
