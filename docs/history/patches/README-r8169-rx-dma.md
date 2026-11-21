# RTL8125 RX DMA 同步合并

此补丁叠加于 `maintenance/tally-verified/source`，保留 tally 修复、TX 回收及
2 ms 有界背压。只修改 `r8169_rxtx.c` 的 RX 同步路径，不改队列、ring 大小或 NAT。

## 实现与约束

- 将缓存指令发出与 `dsb sy` 完成拆开；既有 `rtl_nc_sync()` 仍同步完成，
  tally、TX、初始化调用的语义不变。
- 同一次 RX burst 内，同一 cache line 的描述符只同步一次。遇到缓存中的 OWN
  就返回，下次调用重新同步；不会跨 burst 缓存 NIC 所有权状态。
- 回填依旧以整条 cache line 为单位，完整 RX buffer 的 `dc civac` 全部保留。
  先发出该行所有新 buffer 的维护，再统一完成，之后才能写描述符 OWN，最后
  clean 描述符行并等待完成。不能把 buffer 完成屏障移到 OWN 写入之后，因为
  描述符的脏缓存行可能提前被逐出。
- 已接收报文的缓存维护依旧覆盖实际包长，完成屏障合并到 burst 返回前。
  RX 循环后半段只读写 mbuf 元数据，不读取报文字节；以后若增加报文解析，
  必须重新检查这一前提。所有提前结束路径都经过完成屏障。

未减少完整回填 buffer 的维护范围，未替换缓存指令、缩小屏障域或关闭
`R8169_DMA_NONCOHERENT=1`。低速下仍可能等同一缓存行的邻居完成后才发布回填，
这是既有行为。快照中的 OWN 可能让刚完成的邻居延后一个轮询调用。

## 验证和使用

`tests/integration/integration_r8169_rx_dma.py --source PATH/r8169_rxtx.c` 编译实际 RX 函数、
回填函数及同步函数，以延迟到屏障才完成的缓存模型检查数据可见性和交还顺序。
支持 `--baseline` 检查旧版本。覆盖分配失败、错误包、半行跨 burst、晚到完成、
重复环绕、VLAN/RSS、空轮询、coherent 路径及 32/64/128 字节缓存行。

在 64 字节缓存行、32 字节 type-3 描述符、256 字节 RX buffer、8 包完整
burst 模型中：

| 项目 | 旧版本 | 候选 |
|---|---:|---:|
| `dsb sy` 完成次数 | 28 | 13 |
| RX 描述符行同步次数 | 8 | 4 |
| 数据缓存行维护次数 | 40 | 40 |

此表是操作次数，不能解读为吞吐提升 53.6%。模型不模拟真实 ARM cache、
DMA 事务、脏行写回或 NIC 时序；需要线上序号包及 RDU/worker 采样复验。

在 VROUTER 上构建：

```sh
python3 build/history/build-r8169-rx-dma.py --assets /absolute/assets
```

assets 放入此补丁、`integration_r8169_rx_dma.py`、
`integration_r8169_tx_reclaim.py` 和 `integration_r8169_tally_dma.py`。
脚本检查已安装 PMD 与保留基线一致，在新的候选目录中应用补丁、运行三组回归、
重新编译 RX/TX、hw、ethdev 并链接；不会安装或重启。

2026-10-30 已在 VROUTER 完成构建和上述回归：

- 基线 SHA256：`7b485442401538a53c157daa8f581e59c346070f897d5a38ec54eacbcf7b77d3`
- 候选 SHA256：`0633b93dbbf6e118e427f9cc9c47af99eb43a677da98c5d4f8e1f368b38f8cf5`
- 候选库：`/usr/local/src/vpp-vrouter/maintenance/rx-dma-batch/librte_net_r8169.so.26.1`

同日经用户授权，已使用 `install/tx-reclaim-upgrade.py` 的 `--candidate`、
`--result` 试装并完成现场 A/B，当前运行此候选。原队列、worker、ring、NAT
和 startup.conf 不变。1 MPPS 两轮 10 秒测试的平均接收从 866,547 PPS
提高到 962,167 PPS（+11.0%），缺包率从 13.35% 降至 3.78%。候选 850 kPPS
连续 30 秒收齐 25,500,000 包；1 MPPS 连续 30 秒收 28,997,178/30,000,000。
全部批次 NAT/Mac 一致，无 BPF 丢包、重复或乱序。

1 MPPS 仍频繁出现 RDU，没有达到百万 PPS 无损。当前为顺序 A/B、有限时长
验证；不能推广为长期稳定性或最大无损速率结论。13 个服务及网关/DNS/HTTPS
检查通过，试装超时回退 timer 已取消，旧版恢复点与安装输入保持原版本。
构建脚本会拒绝在已换版的生产库上重复构建，以免混用基线。

详细数据、验证边界和后续维护说明见
`artifacts/vrouter/rtl8125-rx-dma-optimization-20261030.md`。
