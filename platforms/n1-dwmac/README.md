# Phicomm N1 DWMAC 原生 PMD

Phicomm N1（Amlogic S905D）的以太网是 Synopsys DWMAC1000 3.70a 平台设备，不在 PCI 上，DPDK 也没有对应的驱动。本目录是为它写的原生 PMD：数据面直接操作 MAC、DMA 寄存器和描述符，不经过 AF_PACKET、AF_XDP、TAP 或 Linux 套接字。

| 内容 | 说明 |
|---|---|
| `kmod/` | `n1_dma.ko` helper（GPL-2.0）。独占 `/dev/n1-dwmac`，打开时关闭 Linux eth0 的收发，提供 MMIO 和 32 位地址以下的一致性描述符区，把 VPP/mbuf 页面映射给 DMA，并将收包 IRQ 转发到 eventfd；最后一个引用释放时复位 DMA 并把 eth0 还给 Linux。板级电源、时钟和 PHY 初始化仍由 Linux 负责。模块 ABI 为 3，需与 PMD 一起更新 |
| `dpdk/` | `net_n1_dwmac` vdev PMD（BSD-3-Clause），作为 DPDK 的 `drivers/net/n1_dwmac` 编译 |
| `vpp-patches/` | 叠加在 `patches/vpp` 之后：0001 在 VPP dpdk 插件里注册驱动（单队列、256 描述符、不分散接收）；0002 只信任显式 GOOD 的 IPv4 头校验和，UNKNOWN 走软件校验 |
| `vpp-router.conf` | `deploy/install/vpp-router-install.sh` 读取的平台描述 |

## 限制

- helper 只接受设备树为 `phicomm,n1`、设备为 `snps,dwmac-3.70a`、名字为 `eth0` 的网卡，只在 Linux 6.1.129-ophub 上运行过。换内核要重新编译模块，安装脚本会针对当前内核编译。
- 为了在新内核上编译，`kmod/n1_dma.c` 按内核版本条件编译了两处：6.3 起用 `vm_flags_set()`，6.12 起不再设置已删除的 `no_llseek`（不设置 `llseek` 时 `lseek` 同样返回 `-ESPIPE`）。6.1 上编译出的代码不变。2026-11-12 在 6.18.59-ophub 上用 gcc-14 编译通过，该内核由 GCC 15 编译，系统 gcc 13 不认识它的构建参数，安装脚本会自动选择更新的 gcc。
- 单 RX/单 TX 队列，各 256 描述符，只支持千兆全双工，最大帧 1522 字节（不含 FCS）。
- 支持单 RX 队列的 interrupt 和 adaptive 模式；IRQ 一次触发后屏蔽，由 VPP 重新启用。2026-11-14 在 6.18.59-ophub 上验证了模式切换、中断计数及到网关的少量 ICMP 收发；尚未验证长时间运行和高负载。
- 只能单线程运行。`stats_get` 无锁调用 `tx_clean`，开启 worker 后会与 worker 的发送路径竞争，2026-11-03 实际发生过 SIGSEGV；候选修复没有上线。
- DMA 复位超时时 helper 会保守地固定资源，直到重启。
- 不支持热拔插、挂起和网络命名空间迁移。

## 来源

从私有实验目录复制，是 2026-11-02 起生产运行的版本（插件 SHA-256 `4634f436…`，含 2KiB XOFF 提前流控），不是之后被拒绝的 rx-reserve 候选。

| 文件 | SHA-256 前缀 |
|---|---|
| `dpdk/n1_pmd.c` | `51976fac7bfc8fe8` |
| `dpdk/n1_direct.h` | `e4584c69fa4ad3f6` |
| `dpdk/n1_stats.h` | `7fb1809847577d19` |
| `dpdk/n1_checksum.h` | `dcdaa9b6e0ff9ef6` |
| `kmod/n1_dma.c` | `df7796380fbaee6f`（复制时；之后加了上面两处内核版本兼容） |
| `kmod/n1_dma.h` | `8268bc3590ebd048` |

原先的构建方式是 DPDK 26.03 共享库加单独编译的 dpdk 插件；安装脚本改为把 PMD 编进静态 DPDK，和其他网卡共用一个 dpdk 插件。这种构建方式还没有在 N1 上运行过。
