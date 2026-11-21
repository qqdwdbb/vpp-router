# RTL8125 RX 标量成本与 raw 批量分配

两层补丁叠加在 `maintenance/rx-rearm-batch/source`，沿用四个完整缓存行回填、
DMA 数据维护范围和完整同步顺序，保留 TX/tally 路径。

## 第一阶段：标量成本

`r8169-rx-scalar-cost.patch`：

- tail 用递增和 ring 末尾比较推进，直接保留刚消费的索引，不再反向取模。
- 每次 burst 计算一次每行描述符数。非一致性初始化已限定 type-3、二次幂
  描述符 stride 整除 CTR 二次幂行长，因此行边界用 mask，仍不要求 ring 长度
  为二次幂。错误包路径沿用同一判断。
- 使用 raw mbuf 分配契约提供的 `nb_segs=1`、`next=NULL`，不重复重写。
  仅作用于单段 RX 函数，scatter 函数不变；VPP 的后续使用仍得到有效字段。
- 正常包 bytes 在本地累加，packets 使用 `nb_rx`，在退出时加回。零包退出不
  写回这些计数；错误计数保持原行为。DMA 地址计算方式不变。

## 第二阶段：有界 raw 分配

`r8169-rx-alloc-bulk.patch` 叠加在第一阶段上：

- 在需要新 buffer 时，向前扫描最多八个描述符，止于 OWN、ring 末尾或本次
  正常包配额。按实际 ready 正常包数申请，错误包继续复用原 buffer。
- 扫描同步过的描述符快照供主循环使用，避免扫描和消费各做一次 DMA 同步。
  快照只保留在本次调用；主循环仍在 OWN 检查后执行原读取屏障才读其他字段。
  扫描只读取 opts1，错误分类位与 OWN 位同处该字段。
- 两个以上 ready 正常包使用 `rte_mbuf_raw_alloc_bulk()`；一个包仍逐个分配。
  不引入完整 mbuf reset，也不建立跨调用的私有备用池。
- bulk 全有或全无。失败后在本次调用内沿原逐包分配路径推进，直到实际分配
  失败。bulk 失败自身不增加 `rx_mbuf_alloc_failed`，保持部分成功语义。
- 退出时归还任何未消费的新对象；错误包、分配失败和零返回时继续排空完整行。

有界前置扫描新增状态读取和栈数组成本，需要单独现场对照，不能从模型 API
次数直接推断实际加速。VPP 正常 mempool 已有 512 项 cache 和批量模板初始化。

## 构建与回归

```sh
python3 build-r8169-rx-dma.py --assets /absolute/assets --rx-scalar
python3 build-r8169-rx-dma.py --assets /absolute/assets --rx-alloc
```

两个命令都以仍部署的四行回填版为基线，在独立目录构建。第二个在该基线上
依次应用两层补丁，每层之后运行回归。默认输出分别为 `maintenance/rx-scalar-cost`
和 `maintenance/rx-alloc-bulk`。不覆盖旧输出，不自动安装或重启。
assets 包含两层补丁、构建器和四组 r8169 回归脚本。

RX 模型覆盖 8/12/16 描述符环、32/64/128 字节缓存行、所有起点和 burst 长度、
半行跨调用、环绕、错误包/全错误 ring、晚到 OWN、RSS/VLAN、空调用和 coherent。
12 描述符环验证非二次幂索引。raw 分配 mock 提供文档保证的单段/next 初值。
另检查 0～7 个可用 buffer 时 bulk 失败后的部分成功、bulk 拒绝但 scalar 可用、
错误包不消耗新 buffer、单包不批分配、coherent 满 burst，以及故障注入提前
退出时归还剩余对象。数据可见性模型和逆序完成检查保留，支持 ASan/UBSan。

八个 ready 正常包模型从八次 scalar get 变为一次 bulk get；完成屏障仍七次，
描述符行读取四次，数据缓存行维护四十次。16 包模型为两次 bulk get、十三次
完成屏障。真实 ARM/PCIe/NIC 时序及每包周期仍需现场验证。

现场结果与最终运行版本见 `artifacts/vrouter/rtl8125-rx-allocation-optimization-20261030.md`。

2026-10-30 已完成两层分别构建、试装与对照，当前保留两层共同生效的叠加版：
库 SHA256 为 `f89a9e9d5210046d5b8a5dc7960e2b0ec3bd0f6bc99cf1cf787d4ffcd8da97a8`。
1.4 MPPS/20 秒收齐 2800 万；1.5 MPPS/20 秒两轮 NAT 前少 433/0 包，后一轮
Mac 仍少 4 包。叠加版相对第一阶段总 CPU 周期改善尚未证明；本轮高负载
NAT 前缺失表现较好，仍有 USB 接收端、有限时长及顺序对照限制。
13 服务与网络健康检查通过，临时测试已清理，旧库和唯一恢复点保留。


同日经用户接受，已将本叠加版同步为安装输入和当前恢复基准，三处 PMD 哈希
一致。旧基线已单独归档，详见
`artifacts/vrouter/rtl8125-baseline-promoted-20261030.md`；此前“未提升恢复基准”的
记载属于试装验收阶段的历史状态。
