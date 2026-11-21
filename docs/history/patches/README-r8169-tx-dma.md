# RTL8125 TX DMA 批处理

叠加于 `maintenance/rx-dma-batch/source`，保留已验证的 RX 同步优化、tally
修复和 TX 回收/整批 2 ms 背压。不改队列、ring、worker、NAT 或配置。

## 同步机制

优化仅用于 `R8169_DMA_NONCOHERENT=1` 且 `EnableTxNoClose=1` 的路径。
no-close 通过 MMIO 的软件尾指针发布新描述符，完成状态通过硬件关闭指针读取；
NIC 不将完成状态写回描述符内存。保留的 Realtek vendor 源码亦使用该尾指针
doorbell，并允许在 `netdev_xmit_more()` 时推迟发布。

此前每个报文段执行数据 clean + `dsb sy`、描述符 clean + `dsb sy`，并在每个
描述符 OWN 写入前执行写屏障。现在：

1. TSO/checksum/PTP 等准备之后，发出每段完整实际数据范围的 `dc cvac`。
2. 准备整批描述符，发布前按连续范围 clean 描述符，跨环时拆成两段。
3. 保留 burst 末尾的写屏障，使用一次 `dsb sy` 完成所有数据和描述符 clean，
   再写 MMIO 软件尾指针。即使脏描述符行提前逐出，NIC 也尚未获准消费新项。

数据 clean 范围、`dc cvac`、完成屏障的 `sy` 域均保留。其余 coherent/close
路径保持既有操作。描述符可共享一行的依据限于 no-close 的内存所有权规则，
不可套用到会被 NIC 写回状态的 RX 或普通 close 模式。

在 64 字节 cache line、16 字节 TX 描述符、对齐的 8 个单段 60 字节包模型中：

| 项目 | RX 优化版基线 | TX 批处理候选 |
|---|---:|---:|
| 完成屏障 `dsb sy` | 16 | 1 |
| 描述符行 clean | 8 | 2 |
| 数据行 clean | 8 | 8 |
| 写屏障 | 9 | 1 |

这只是操作数，不是硬件周期或吞吐比例。跨环的大批次可能在两段范围中重复
clean 同一缓存行，不影响顺序；没有为这一少见情况增加额外状态。

## 回归与构建

`tests/integration/integration_r8169_tx_dma.py --source PATH/r8169_rxtx.c` 提取实际 TX
packet/burst、同步帮助函数编译测试，`--baseline` 可验证 RX 优化版。
模型将缓存 clean 延迟至屏障完成，并覆盖描述符提前逐出、逆序完成、32/64/128
字节 cache line、任意环内起点、多次环绕、32 位尾指针溢出、多段/MTU/非对齐
数据、TSO/checksum/PTP 元数据准备、部分发送、超时、空调用和 coherent/close。
移除末尾完成屏障的故障注入会在 doorbell 前被断言拒绝。

本机 ASan/UBSan、TX DMA/RX DMA、既有 TX 回收和 tally 回归通过；VROUTER 原生构建
与四组回归通过。模型不能替代真实 ARM cache、PCIe 和 NIC 时序验证。

复用已有构建器，增加 `--tx-dma` 选择此阶段：

```sh
python3 build/history/build-r8169-rx-dma.py --tx-dma --assets /absolute/assets
```

assets 放此补丁及四个 `integration_r8169_*.py` 回归脚本。构建器确认当前库与
保留的 RX 阶段基线一致，在新的空目录中应用补丁、回归、编译与链接，不会安装
或重启。默认输出为 `/usr/local/src/vpp-vrouter/maintenance/tx-dma-batch`。

- 本轮基线 SHA256：`0633b93dbbf6e118e427f9cc9c47af99eb43a677da98c5d4f8e1f368b38f8cf5`
- TX 候选 SHA256：`da6016a1c52c28ba2b80f549f425bded9c3bd449b74ad6a9a1ca602d1acd4d0a`

2026-10-30 已试装运行并完成 A/B：本轮 1 MPPS 的两次 10 秒基线平均实收
954,814.7 PPS，候选为 999,997.4 PPS。候选 850 kPPS / 30 秒与
1 MPPS / 30 秒均收齐，全部候选批次未采到 RDU；但其中一次 10 秒测试存在
NAT 已计满而 Mac 少 52 包的未定位差异，因此不能宣称长期端到端无损。
13 个服务和网关/DNS/HTTPS 健康检查通过。旧库和唯一恢复快照保留。

现场 A/B、当前状态和验收边界记录于
`artifacts/vrouter/rtl8125-tx-dma-optimization-20261030.md`。
