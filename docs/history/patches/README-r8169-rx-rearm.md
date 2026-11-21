# RTL8125 跨缓存行 RX 回填

补丁 `r8169-rx-rearm-batch.patch` 叠加在 `maintenance/tx-dma-batch/source`。
仅修改非一致性 DMA RX 回填，保留 RX 描述符轮询、完整 buffer 缓存维护、
`dc civac`/`dc cvac`、`dsb sy`、逐描述符写入顺序、TX 和 tally 行为。

每次 RX 调用收集最多四个已完全消费的描述符缓存行。先对全部替换 buffer
发出维护，一次完成后才填写任何 OWN；再 clean 全部描述符行并统一完成。
达到四行、走到 ring 末尾或函数退出时发布完整行；批次不跨环、不跨调用。
未完整消费的缓存行沿用原来的保留方式，避免覆盖 NIC 持有的邻居状态。
错误包复用原 buffer，错误包路径、分配失败以及返回零包时也必须排空完整行。

64 字节缓存行、32 字节描述符、对齐八包模型：回填部分完成屏障 8→2，
整个 RX 调用完成屏障 13→7；描述符行读取四次、回写四行、数据行维护四十次
均不变。完整 buffer 维护仍占用带宽；屏障数下降不能直接换算成 PPS 增益。
四行批次会稍晚归还最早的描述符，必须通过真实流量观察 RDU 和转发结果。

构建：

```sh
python3 build-r8169-rx-dma.py --assets /absolute/assets --rx-rearm
```

assets 包含此补丁、构建器和 `integration_r8169_{rx_dma,tx_dma,tx_reclaim,tally_dma}.py`。
构建器要求已部署库等于 TX-batched 基线，拒绝覆盖既有输出，不自动安装。

RX 回归提取实际帮助函数与接收循环，覆盖 32/64/128 字节缓存行、所有起点与
burst 长度、跨调用半行、环绕、错误包、全错误 ring、分配失败、晚到 OWN、
VLAN/RSS、空调用及 coherent 路径；支持逆序完成缓存操作和 `--sanitize`。
可用 `--ring-size 16` 覆盖 128 字节行下四行批次；默认八描述符环。
新旧源码均运行同样正确性用例，按源码识别新分组实现并检查操作数。
模型不能证明真实 ARM/PCIe/NIC 的所有时序。

现场结果和最终部署状态见 `artifacts/vrouter/rtl8125-rx-group-optimization-20261030.md`。
