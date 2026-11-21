# VROUTER RX 同步与批次对照

构建工具：`build/history/build-r8169-rx-batches.py`，基于已接受的rx-alloc-bulk源。
只在新的maintenance目录构建，不覆盖原源码和安装输入。包含：

| 组 | 描述符读取 | 每次PMD请求 | 回填完整cache line |
|---|---|---:|---:|
| baseline | 原逐行完成 | 32 | 4 |
| read | 有界窗口合并完成 | 32 | 4 |
| call64 | 有界窗口合并完成 | 64 | 4 |
| rearm2 | 有界窗口合并完成 | 64 | 2 |
| rearm8 | 有界窗口合并完成 | 64 | 8 |
| rearm8-32 | 有界窗口合并完成 | 32 | 8 |

各增量只和直接对照比较：read对baseline，call64对read，rearm2/8对call64。
八行组初步改善后追加rearm8-32，比较相同八行回填下32/64调用。
不是完整析因实验，不能推断所有因素在其他组合下的独立作用。

读取合批只作用于既有8描述符前瞻：调用者已同步首行，后续有界范围一次维护并完成。
不跨ring，不写OWN，不减缓存范围，不替换dc civac/dc cvac或dsb sy，不移除OWN后的rte_rmb。
为少包/空轮询保留首行探测。前瞻和消费仅在本次调用共享快照。

调用上限64需要改VPP DPDK插件node.c中n_to_rx上限；外层VLIB_FRAME_SIZE预算不变。
工具仅重编node对象并链接现有其他对象，另构建32包控制验证机器码与线上.text一致。
编译保留原宏文件路径和链接时RPATH字符串布局，最后设置实际部署RUNPATH。

构建资产包含build-r8169-rx-dma.py和integration_r8169_{rx_dma,tx_dma,tx_reclaim,tally_dma}.py。
VROUTER上执行：

```sh
python3 /tmp/build-r8169-rx-batches.py --assets /tmp \
  --output /usr/local/src/vpp-vrouter/maintenance/rx-batch-experiment
```

RX回归保留全部数据可见性、发布顺序、错误/分配失败、部分行/跨调用、晚到OWN和环绕断言。
新计数断言按读取方式及回填行数区分。支持8/12/16/32/64环；64包用例扩大模型buffer池。
模型不能证明真实ARM/PCIe/NIC全部时序。

试装工具：`vrouter_rx_batch_trial.py`，复用`vrouter_rx_ring_trial.py`的就绪检查。
两文件安装到root拥有的/run目录；严格核对当前库与构建manifest，私有备份两个原库。
只原子替换PMD和DPDK插件，不改startup.conf、RX/TX ring、worker或buffer池。
每次apply先启用9分钟独立恢复timer，再切库和重启，核对加载inode/哈希与健康。
如切换失败则恢复；拒绝覆盖试验范围外的库。root私有状态为/var/lib/vpp-vrouter/rx-batch-trial。

```sh
python3 /run/vrouter_rx_batch_trial.py prepare
systemd-run --unit=vrouter-rx-batch-read --property=RuntimeMaxSec=400 \
  /usr/bin/python3 /run/vrouter_rx_batch_trial.py apply --arm read
# 查journal/status，确认active后再运行流量；每次单元名称更换。
python3 /run/vrouter_rx_batch_trial.py status
python3 /run/vrouter_rx_batch_trial.py restore
```

测试仍固定RX1024/TX1024和原8192 buffer配置，使用Linux DPDK序号接收。
各组同样1000PPS功能检查、1.5/1.6MPPS各两次15秒、CPU0只读RDU采样；单UDP流64B源帧含FCS。
开始和结束均测原版。每个接收进程最多32个run；基本矩阵六组各5个共30个。
读取合批已收齐1.6MPPS，因此追加各候选及末尾基线2MPPS过载两轮，每轮15秒/3000万包。
另追加rearm8-32五个基本阶段及两轮过载，总计47个run。
前26个使用首个接收进程，其余21个使用新进程；保存前者终态后改用新的JSON路径。
如追加组，需先保存抓包终态并启动新的JSON/接收进程。不要在同一个run-base上重发。

```sh
python3 benchmarks/vrouter_trex_sequence_benchmark.py --linux-dpdk \
  --receiver-ip 10.61.20.198 --linux-rx-namespace vrouter-nat-rx \
  --capture-json /tmp/vrouter-rx-batch-dpdk.json \
  --rates 1000,1500000,1600000,1500000,1600000 --seconds 15 \
  --run-base 371000 --sample-rx-status --output artifacts/vrouter/rx-batch-stage.json
```

最终恢复PMD和插件原字节、核对startup和664文件恢复基线，停止DPDK/TRex及临时NAT/timer。
候选和补丁保留用于审查，不自动提升安装或恢复基线。
