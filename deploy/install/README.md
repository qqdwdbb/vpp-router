# VROUTER 本地安装布局

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

这是自编译软件的本地安装，使用 Debian/Ubuntu 的 `/usr/local` 层级，不覆盖发行版
包管理器管理的 `/usr/bin` 和 `/usr/lib` 文件。安装入口为 `install.py`，将已经确认
的 VROUTER 部署迁入固定位置；默认拒绝覆盖已有安装及管理员配置。

当前二进制基线为 `baseline.json` 中的 `vrouter-rx-checksum-batch64-rearm8-acl-cache-v3-20261101-fib-path-copy-nat-fix-batch-context-next-guard-context-cursor`：
ACL `9c126c01…`、DPDK插件 `e3a395a7…`、RTL8125 PMD `dcb194e5…`、libvnet `ec688225…`、
NAT44-EI `259a6fe9…`、nat_ei_context `7aaec95a…`（含下一跳和特性链游标校验）。
`startup.conf` 的 `dpdk` 段启用 `enable-tcp-udp-checksum`；必须配合这两个已修复
GOOD/BAD/UNKNOWN 状态传递的二进制，不能只在旧插件上打开配置。
独立对端验证涵盖 IPv6 TCP/UDP、扩展头、分片及 native VLAN 1、VLAN 10/100，
39 组共 195 帧全部通过。报告：`artifacts/vrouter/rx-checksum-20261101.md`。
安装器在写入前校验bundle内两个插件和dma-pmd输入，ELF重定位后再次校验安装产物；
回退工具在停止服务前校验恢复清单中这三个二进制的版本。
旧版本或缺少这些文件会被拒绝，即使旧快照自身的完整性校验通过。
`baseline.json` 随安装脚本部署并纳入恢复快照；后续接受新二进制版本时须同步更新此清单。
`activate.py rollback` 继续委托当前 `recovery.py restore`，不使用实验控制器的旧备份。
当前恢复代次以目标机 `/var/lib/vpp-vrouter/recovery/current` 为准，以下代次记录属于历史。

| 内容 | 位置 |
| --- | --- |
| CLI | `/usr/local/bin/vppctl` |
| VPP 命令入口 | `/usr/local/sbin/vpp` |
| 程序、私有库、VPP/strongSwan 插件及辅助脚本 | `/usr/local/lib/vpp-vrouter/` |
| DPDK 运行库和 PMD | `/usr/local/lib/aarch64-linux-gnu/` |
| VPP API 描述 | `/usr/local/share/vpp-vrouter/api/` |
| 配置与私有凭据 | `/etc/vpp/` |
| 状态、验证记录及回退快照 | `/var/lib/vpp-vrouter/` |
| 管理员服务单元 | `/etc/systemd/system/vrouter-*.service` |
| socket、临时状态 | `/run/vpp/`、`/run/vrouter-*` |
| UIO 内核模块 | `/lib/modules/$(uname -r)/updates/vpp/` |
| 服务日志 | systemd journal |
| 源码、构建输入及维护构建资料 | `/usr/local/src/vpp-vrouter/` |
| Python 编译缓存 | `/var/cache/vpp-vrouter/python/` |
| core dump | `/var/lib/systemd/coredump/`，用 `coredumpctl` 查询 |
| 已移出加载目录的旧插件副本 | `/var/lib/vpp-vrouter/history/` |

CLI 入口设置私有动态库路径，不改动系统全局动态库配置。`vppctl` 的参数直接传给
真实程序；访问管理 socket 通常使用 `sudo vppctl`。VPP 应通过 systemd 管理，
不要另外手动启动第二个 VPP 进程。

DPDK 库和 PMD 保留原有相对目录与 SONAME 软链接，安装器检查所有链接均有效且
指向本地安装的多架构库目录。`DPDK_PLUGIN_PATH` 显式指向
`/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1`，因此 VPP 直接从标准本地
多架构目录加载 DPDK PMD，不依赖旧构建目录，也不需要 systemd 的兼容挂载或
宿主机兼容软链接。

安装器要求 `patchelf` 和 `systemd-coredump`。安装后的 ELF 使用固定本地库路径或
`$ORIGIN`，不保留构建树 RUNPATH，也不保留表示当前目录的空路径项。修正时先修改
临时副本，校验 `.text` 代码段哈希，再原子替换文件，避免改写正在使用的映射。
strongSwan 插件处于私有挂载空间，使用绝对的已安装私有库路径，不能按主机上的
插件目录直接推导 `$ORIGIN`。

VROUTER 的 RTL8125 使用带缓存同步的 PMD，不能用普通 DPDK 构建中的同名库替换。
安装器从 `dma-pmd` 构建产物复制该库到上述 PMD 目录，并设置
`R8169_DMA_NONCOHERENT=1`。对应源码补丁为
[`r8169-noncoherent-dma-experimental.patch`](../../docs/history/patches/r8169-noncoherent-dma-experimental.patch)。
2026-10-29 现场验证：普通库无法收到网关回包；恢复带补丁的库后网关 ping、
主机 DNS 和 HTTPS 恢复。缓存同步存在额外开销，此次未测试吞吐上限。

静态配置和 PD 同步生成的 IPsec 地址池文件都放在 `/etc/vpp`，其中
`/etc/vpp/ipsec.conf` 是 strongSwan 实际读取的运行时配置。状态及回退快照放在
`/var/lib/vpp-vrouter`。配置及快照保留 root 私有权限，源码与库不含凭据。服务专用环境
变量仍保留，例如 strongSwan 的 `STRONGSWAN_CONF`。
namespace 创建服务必须在主机挂载空间发布 namespace，不增加挂载隔离属性。

`LD_LIBRARY_PATH` 只包含 `/usr/local` 下的正式库目录。2026-10-29 已将实际运行的
补丁版 libvnet 迁入私有库目录；同名库不能仅凭文件名互换。Python 服务通过
`PYTHONPYCACHEPREFIX` 将编译缓存写入 `/var/cache`，不在 `/etc/vpp` 生成缓存。

core dump 由发行版 `systemd-coredump` 处理，配置为压缩外部存储、`MaxUse=512M`、
`KeepFree=1G`、处理及单文件上限 `2G`。这些是 systemd 的回收策略，处理期间可以
暂时超过占用目标。旧的原始 VPP core 和分析文本迁入 `legacy-vpp/router/`，由
tmpfiles 按 7 天保留期清理；历史文件没有新的 journal 元数据，不能用
`coredumpctl` 查询。系统新生成 core 的时间清理由发行版 tmpfiles 规则管理。

## 当前版本恢复

恢复基准位于 `/var/lib/vpp-vrouter/recovery/current`。它指向唯一保留的健康版本，
包含当前 VPP 程序、私有库、RTL8125 PMD、API、sing-box/gost/smartdns 本地程序、
`/etc/vpp`、路由与 DNS 配置、相关证书凭据、当前 systemd 单元及 drop-in、UIO 模块。
目录和元数据仅 root 可访问；文件内容、类型、权限、属主和软链接均记录在 manifest。
恢复副本是部署文件的恢复点，不是系统磁盘镜像；发行版软件由原系统提供。

在独立 `mgmt0 / 10.61.60.1` 管理口执行：

```sh
# 只校验恢复副本，文件损坏时拒绝进入恢复流程。
sudo python3 /usr/local/lib/vpp-vrouter/install/recovery.py verify

# 用独立作业恢复当前接受的版本；包括清除受管配置目录中的后加文件。
sudo systemd-run --unit=vrouter-recover-current --no-block --service-type=oneshot \
  --property=TimeoutStartSec=300 /usr/bin/python3 \
  /usr/local/lib/vpp-vrouter/install/recovery.py restore
sudo journalctl -u vrouter-recover-current -f
```

恢复前验证全部文件和内核/架构，并确认独立管理路由；随后停止受管服务、原子恢复
程序和配置、重新加载服务并启动，检查服务状态、网关真实回包、本机 DNS 与 HTTPS。
不会用旧 Linux 网络快照覆盖当前部署。连接及 NAT/IPsec 会话等运行状态重新建立，
动态公网 IPv6 前缀继续由 PD 同步服务获取。恢复失败则调用当前 Linux IPv4 应急接管。
在 Linux 接管模式下也可执行同一个 `restore`，文件修复后会释放 Linux 网卡并返回 VPP。

只有明确接受一套新的运行版本时，才更新恢复基准：

```sh
sudo python3 /usr/local/lib/vpp-vrouter/install/recovery.py snapshot
```

创建前后都检查运行健康度；失败不会替换上一份有效基准。发布前核对所有文件，
发布后删除上一代，只保留一份当前接受的版本。不会在开机或故障时自动覆盖恢复点。
Linux 接管状态不能被保存成 VPP 恢复基准。

`activate.py` 的 `rollback` 现在调用这个当前版本恢复工具；`linux` 调用现有 Linux
应急接管，均不再依赖 `pre-fhs`、`previous_bundle` 或旧 Linux baseline。
阶段性 `apply` 需要事先存在有效恢复点，设置 300 秒回退计时器；`confirm` 完成健康
检查后停止计时器，才将已接受版本设为新基准。首次文件准备的 `install.py` 不替代
现有部署的恢复工具。

```sh
sudo python3 /usr/local/lib/vpp-vrouter/install/recovery.py linux
# 仅切换回已安装程序，不修复文件：
sudo python3 /usr/local/lib/vpp-vrouter/scripts/vrouter/startup/vrouter-linux-fallback.py resume
```

旧 `pre-fhs` 恢复包和旧系统单元备份已在新恢复点实际验证后删除。
`baseline/linux-state.json` 仅保留当前运行需要的 br0 MAC 与 Nebula 静态路由，
不再充当迁移前 Linux 网络的还原快照。

## 构建输入

构建输入默认位于 `/usr/local/src/vpp-vrouter/`，其下 `nic1-test/` 保存 VPP、DPDK 和
UIO 构建输入，`migration/` 保存已验证的补丁产物及 Python API。文件准备工具的
`--artifacts DIRECTORY` 可以指定另一份完整构建输入；这些目录不是运行时搜索路径。
旧构建树搬迁后，重新编译前须重新生成 Meson/CMake 构建配置。旧试部署控制器及
实验包不再用于恢复当前路由器。

RTL8125 当前 PMD 同时包含非一致性 DMA 缓存同步和 TX 提前回收/有界背压补丁。
`migration/dma-pmd/librte_net_r8169.so.26.1` 同步为已验收版本，不能再以 stock PMD
替换。重建方法见 `docs/history/patches/README-r8169-tx-reclaim.md`；维护目录
`maintenance/tx-reclaim` 保留最终候选源码、补丁、回归测试和构建命令。

2026-10-29 已验证当前 VPP 开机接管及目录迁移后的网络恢复。早期部署包的
manifest/validation 保留历史内容，不将它们改写为新的安装证明。真实公网 TURN
中继和吞吐上限不属于本次目录迁移验收。早期安装记录见
`artifacts/vrouter/fhs-deployed-20261018.json`，本次记录见
`artifacts/vrouter/deployment-layout-fixed-20261029.json`。

## 2026-10-30 tally 计数修复

当前 PMD 还须叠加 `docs/history/patches/r8169-tally-dma-sync.patch`，修复非一致性 DMA
统计读取。最终维护目录为 `maintenance/tally-verified`；安装输入及恢复点
同步为 SHA256 `7b485442401538a53c157daa8f581e59c346070f897d5a38ec54eacbcf7b77d3`。
原 `maintenance/tx-reclaim` 仅保留为重建基线，不能覆盖当前运行库。
详见 `docs/history/patches/README-r8169-tally-sync.md` 和计数修复复测报告。


## 2026-10-30 接受当前 RX 优化部署为安装与恢复基线

安装输入 `migration/dma-pmd/librte_net_r8169.so.26.1` 与
`recovery/current` 中的 RTL8125 PMD 均已同步为 RX 成本优化＋有界 raw 批量分配
叠加版，保留此前 DMA、TX 回收、tally 及四行回填修复。

- PMD SHA256：`f89a9e9d5210046d5b8a5dc7960e2b0ec3bd0f6bc99cf1cf787d4ffcd8da97a8`。
- 当前维护目录：`maintenance/rx-alloc-bulk`，两层构建参数及补丁见
  `docs/history/patches/README-r8169-rx-allocation.md`。
- `migration/dma-pmd/accepted-baseline.json` 记录维护源码、接受时间、恢复代
  和旧基线归档位置；该目录的 rxtx 对象与依赖同步为对应构建产物。
- 恢复 current 指向 `generations/<generation-id>`，664 项清单及标准
  `recovery.py verify` 通过。新恢复点使用当前部署的程序与配置。
- 旧恢复代和旧安装输入已在设备上归档到
  `/var/lib/vpp-vrouter/history/<backup-id>`，
  保持 root 私有权限并按原 manifest 校验；它是历史归档，不是第二个活动恢复点。
- 更新未重启 VPP；PID、启动时间和启动配置未变，13 服务与网络健康通过。
  本次没有执行实际恢复演练。

上述 tally/tx-reclaim 版本描述为历史阶段，不应再把其库复制回当前安装输入。
完整记录见 `artifacts/vrouter/rtl8125-baseline-promoted-20261030.md`。


## 2026-10-30 接受描述符读取合批、64包调用及八行回填

现部署已接受上一轮rearm8＋plugin64组合：PMD `8881ceab...`、DPDK插件 `7b3210e6...`。
RX/TX ring仍1024，startup.conf未改。迁移安装输入中PMD及其rxtx对象/依赖、
`migration/plugins/dpdk_plugin.so`均同步；安装器使用的入口已经核对。
恢复current指向`generations/<generation-id>`，664项标准校验及13服务健康检查通过。
旧恢复代及安装输入归档于设备私有目录
`/var/lib/vpp-vrouter/history/<backup-id>`，清单核对通过。
原试装timer已取消，trial状态标记accepted；不再使用旧trial restore作为当前恢复方式。
使用上述标准recovery.py恢复当前接受版本。本次没有执行实际恢复演练。
记录：`artifacts/vrouter/rx-batches-accepted-20261030.md`。

## 2026-11-09 RK3588 开发板 TAP offload 与 DNS 故障修复

RK3588 开发板部署普通 TAP 的 VPP GSO 后，曾同时打开 Linux TAP 的 TX checksum offload。
这会使 dnsmasq 发往 `vpp-lan` 的 UDP DNS 回复带着未完成的校验和，抓包出现
`bad udp cksum`；此时 `vpp-egress-gate.service` 仍可能显示 `active (running)`，
但它的本地 DNS 查询已经报 `i/o timeout`，所以服务状态不能代替 DNS 健康检查。

当前配置按用途分离：

- 普通 TAP：`tap2000`、`tap2010`、`tap2480`、`tap2490`、`tap3901`。VPP 侧
  `gso-enabled=1`、`csum-enabled=1`；Linux 侧 `tx-checksumming=off`、
  `generic-segmentation-offload=on`、`generic-receive-offload=on`、
  `tcp-segmentation-offload=off`。
- IPsec 专用 TAP：`tap4061`。VPP 侧 GSO/CSUM 均关闭；RK3588 开发板 namespace 对端
  `rk3588-ipsec/eth2-dpdk.100` 的 `tx/gso/gro/tso` 全部关闭。

修复时在线关闭普通 TAP 的 TX checksum offload，并同步 `runtime.py` 的启动配置，
无需再次重启 VPP。验证应同时覆盖 Linux offload、VPP TAP 状态和真实 DNS 查询：

```sh
sudo ethtool -k vpp-lan
sudo ip netns exec rk3588-ipsec ethtool -k eth2-dpdk.100
sudo vppctl show tap
dig +short @10.61.20.2 example.com
sudo journalctl -u vpp-egress-gate.service --since '30 seconds ago'
```

从路由器本机直接查询 `@10.61.20.1` 不经过 LAN 入站 DNAT，不能作为客户端 DNS
路径测试；应从 LAN 客户端测试，或在路由器上直接查询 `10.61.20.2`。两份现场备份均位于设备的 `/var/lib/vpp-rk3588/history/` 下。

## 从源码全新安装：vpp-router-install.sh

`vpp-router-install.sh` 与上面的迁移安装无关，用于在一台新机器上从头装一台基本路由：

```sh
sudo deploy/install/vpp-router-install.sh                # 检测、选网卡、编译、安装、配置
sudo deploy/install/vpp-router-install.sh --config-only  # 不编译，重新选网卡和地址
sudo deploy/install/vpp-router-install.sh --restore      # 停止 VPP，网卡还给原内核驱动
sudo deploy/install/vpp-router-install.sh --uninstall    # 还原网卡，删除程序和服务，保留 /etc/vpp
```

- 检测架构（x86_64、aarch64）、CPU、内存、大页、IOMMU 和全部物理网卡。DPDK 原生支持的网卡排在前面并标为推荐；装好后按 DPDK 构建产物的 PCI ID 表精确判断。DPDK 不支持的网卡用 AF_PACKET 接入。
- RTL8111/8168（10ec:8168）按芯片版本判断：读 BAR2 的 TxConfig，读不到时用内核日志里的 XID。DPDK 26.03 的 r8169 只支持 8168G/GU/EP/H/FP/M/KB，8111B–F（含常见的 8111E/F）和 8411/8411B 会改用 AF_PACKET。
- mlx4（ConnectX-3）的 PMD 在端口启动时用 ibverbs 装收包流规则，要求 `mlx4_core` 以 `log_num_mgm_entry_size=-1`（设备管理的流表）加载；默认的 -10 下规则被拒（`cannot attach flow rules (code 95, "Operation not supported")`），端口启动失败。选了 mlx4 网卡且参数不是 -1 时，脚本写入 `/etc/modprobe.d/vpp-router-mlx4.conf`（mlx4_core 在 initramfs 中时同时重建 initramfs），并询问是否在安装时重新加载 mlx4 驱动（会短暂断开本机所有 mlx4 网口）。当前 SSH 经过 mlx4 网口、拒绝重新加载或驱动卸载不掉时，不启动 VPP，设为开机启动并提示重启。其他 modprobe 配置把该参数设成别的值，或 mlx4_core 编进了内核时，停止安装并说明。`vpp-router-ctl prep` 每次启动前加载 `mlx4_ib`/`mlx5_ib` 和 `ib_uverbs`，并检查该参数，不是 -1 时直接报错，不再让 VPP 端口启动失败。卸载时删除这个 modprobe 文件。
- 选了 mlx4 网卡时 DPDK 配置加 `no-multi-seg`：RX scatter 打开时每个接收描述符带多个分段，网卡本身收不过来（`ethtool -S` 的 `rx_fifo_errors` 增长、发出 PAUSE）。ConnectX-3（i5-9300H，2 worker／2 队列，64 字节 VLAN 小包，8 个源地址，NAT44-EI）实测上限从 5.2 Mpps 升到 7.1 Mpps，与 testpmd 单队列纯收发相同。路由器各接口 MTU 都是 1500，用不到多段 buffer。
- mlx4/mlx5 网卡保留内核网卡，`vpp-router-ctl prep` 用 `ethtool -A` 关闭其以太网流控（PAUSE），原设置记在 `/run/vpp-router/pause-<网卡>`，`release` 时恢复。流控开着时，网卡收不过来就让交换机暂停发送，超载时吞吐反而跌到 4.6 Mpps；关闭后超载时保持在 7.4–7.9 Mpps。同一台机器上 4 个 RX 队列分给 2 个 worker 反而降到 5.7 Mpps（在途 buffer 超出 8 MB L3），所以队列数仍跟 worker 数一致。
- 非 PCI 网卡按 `platforms/*/vpp-router.conf` 匹配原生 PMD。目前有 Phicomm N1（`platforms/n1-dwmac`）：PMD 编进 DPDK，`n1_dma.ko` 针对当前内核编译，VPP 单线程、不用大页。其他开发板的平台网卡用 AF_PACKET。
- 选了 PCI、AF_PACKET 或支持中断的平台网卡（包括 N1）时询问收包方式，默认轮询：每个 VPP 线程占满一个 CPU，一直全速运行。选择中断时使用 VPP 的 adaptive 模式：流量小时线程可休眠、由网卡中断唤醒，流量大时自动转为轮询；实际休眠还取决于其他 VPP 节点。PCI 收包中断需要 MSI-X，因此会把 `uio_pci_generic` 换成 `vfio-pci`（没有 IOMMU 时用 no-IOMMU 模式）。同时在 VPP 启动配置中写入 `session { use-private-rx-mqs }`，让 Host Stack 消息队列也能自适应进入中断等待。`vpp-router-ctl post` 在 VPP 启动后逐个设置 `rx-mode adaptive`，再从 `show interface rx-placement` 核对，PMD 不支持的网卡保持轮询并写入日志。RTL8125 等 r8169 网卡的收包中断来自 `patches/dpdk` 的补丁，支持最多 4 个 RX 队列，已在 RK3588 开发板 RTL8125 上完成四队列逐队列中断与轻载测试，其他型号及高负载尚未验证。N1 的中断验证范围见其平台 README。mlx4（ConnectX-3）的收包中断来自 VPP 0030，已在 ConnectX-3 主机（i5-9300H）上验证空闲休眠、低速唤醒不丢包和满载吞吐；mlx5 尚未打开。
- 编译并行数按每进程 800 MB（内存加 swap）计算。内存不够用满全部 CPU 时，编译期间临时启用与内存同样大小的 zram swap，编完或脚本退出时撤除；用 `--jobs N` 指定并行数时不启用。Phicomm N1（1.8 GB 内存）因此用 4 个进程编译，完整安装约 67 分钟。
- 内存小于 3 GB 时只编译所选网卡需要的 PMD。aarch64 只编通用版本，不编 VPP 针对服务器 CPU 的变体（`neoversev2` 等，变体列表从源码的 `cpu.cmake` 读取）。
- 只安装运行需要的 CMake 组件（`vpp`、`vpp-plugin-core`、`vpp-plugin-dpdk`、`vpp-crypto-engines`、`libvppinfra`），不需要 pip；纯 Python 的 `vpp_papi` 从源码复制到系统 Python 的本地包目录（Debian/Ubuntu 上是 `/usr/local/lib/python3.X/dist-packages/`），可以直接 `import vpp_papi`。VPP 自带的 `etc` 模板、`elog_dump` 和 VAT 测试插件不安装。
- 编译并启用的插件：dpdk（有 PCI 或平台网卡时启用）、af_packet、tap、nat44_ei 或 nat（NAT44-ED，两个都编译，只启用所选模式的那个）、wireguard、acl、abf、dhcp、mss_clamp、ping、vxlan、gre，选 IPsec 时加 ipsec_ike_punt。acl、abf 总是启用，供 Gate 将客户端发往公网 DNS 的查询送到 Linux，之后再装 Gate 也可使用；插件加载本身不会启用 DNS 接管。af_packet、vxlan、gre 总是启用，面板接口页可以新建 AF_PACKET、VXLAN、GRE 接口；以前的安装重新运行时会因此重新编译 VPP。
- 多网卡：选一个 WAN，其余 LAN 桥接到桥域 1，网关为 BVI `loop0`。
- 多网卡也可显式选择 WAN trunk：WAN VLAN 与该口上的 LAN VLAN 分离，其他 LAN 口加入同一 LAN 桥。物理口仍按 `wan0`、`lan0` 等命名，子接口为 `wan0.<VLAN>`；默认仍是独立 WAN。
- 自定义业务配置独立保存：`router.vpp` 中追加的 `exec` 行在重配时保留；`dnsmasq.conf` 里自己加的行也保留。安装器不默认安装任何站点的 VLAN、分流名单或 Linux 服务策略。
- 可用 `VPP_EXTRA_PLUGINS=dslite,nat66,nat_ei_context,wg_nat_order,dns_intercept` 显式追加插件。项目插件从对应连字符目录复制并一起编译，附加插件同时写入启动配置；默认安装集合不变。VPP 26.06 的 NAT CMake 会在首个未选组件处返回，因此选择 nat66 时也须包含其前面的 dslite。
- 单网卡：WAN 和 LAN 用 VLAN 区分，WAN 默认 100，LAN 默认 1（不打标签）。
- WAN 用 DHCP 或静态地址，出口做 NAT44（output-feature），安装时选 EI（默认，全锥形）或 ED（端口复用、端口受限锥形，运营商限制可用端口数时用），重新运行时默认沿用启动文件加载的插件，以后可以在面板系统页切换。重新运行时换了模式，`router.vpp` 按新模式重新生成，它保留的 `exec` 行所执行的文件（比如多出口用的 `router-local.vpp`）由 `vpp-system nat-mode` 按系统页切换的同一套规则改写，改写前的文件存在 `/var/lib/vpp-router/nat-mode/`；改不了（规则见 `tools/vpp-system` 的 README），或者没有带这个子命令的 vpp-system（没装面板）而这些文件里有 NAT44 命令时，保持原来的模式并说明原因。TCP 会话空闲回收时间和 RK3588 开发板一样：已建立 1800 秒、握手和关闭中 120 秒（VPP 默认是 7440 秒和 240 秒），UDP 300 秒、ICMP 60 秒保持默认。可选 `vpp-host` TAP 给 Linux 管理用，并可在其上运行 dnsmasq 提供 LAN DHCP/DNS。
- LAN 只运行一个 dnsmasq：`vpp-host` 上的 `vpp-router-dnsmasq.service`，配置在 `/etc/vpp/dnsmasq.conf`，静态分配在 `/etc/vpp/dhcp-hosts`（`dhcp-hostsfile`，改完 `systemctl reload vpp-router-dnsmasq` 生效，不中断 DHCP 和 DNS），租约在 `/var/lib/vpp-router/dnsmasq.leases`。`dnsmasq.conf` 不再整个重新生成：安装脚本和面板只就地修改它管理的几行（`interface`、`bind-interfaces`、`except-interface`、`listen-address`、`dhcp-authoritative`、IPv4 的 `dhcp-range`、不带标签的 `router` 和 `dns-server` 选项、`dhcp-leasefile`、`dhcp-hostsfile`），其余行原样保留，自定义配置直接写在这个文件里。重新运行时地址池和租期以文件里的为默认值。装了面板时，`dhcp-script` 设为 `vpp-interfaces`（dnsmasq 支持时同时加 `script-on-renewal`），面板“局域网”页用它记录的客户端识别设备，地址池和静态分配也在那里修改，见 `tools/vpp-interfaces/README.md`。
- 系统 dnsmasq（`dnsmasq.service` 已启用或正在运行）会和它争用 53、67 端口，不能同时运行。安装脚本用 `dnsmasq-lan.py` 从运行中的进程找出它实际读取的配置（`-C`、`-7`、`conf-file`、`conf-dir`，也可以用 `DNSMASQ_CONF`、`DNSMASQ_CONF_DIR` 指定），列出能导入和不导入的内容，同意后导入，然后停用并屏蔽系统 dnsmasq：`dhcp-host` 和 `dhcp-hostsfile` 里 LAN 网段内的静态分配进 `dhcp-hosts`；LAN 网段内的 IPv4 地址池作为默认值；监听、端口、租约文件、RA、服务相关的选项以及网关和 DNS 选项由 VPP 的拓扑决定，不导入；其余配置追加到 `dnsmasq.conf`，未通过 `dnsmasq --test` 时改成注释；LAN 网段内的现有租约复制过来，设备续租时拿到原来的地址。不同意时保留系统 dnsmasq，LAN 上不运行 dnsmasq。系统 dnsmasq 原来的状态记在 `/var/lib/vpp-router/system-dnsmasq`，`--restore`、`--uninstall` 和自动回退时恢复。2026-11 以前按系统 dnsmasq 方式安装的机器，重新运行时先还原当时对系统配置的修改，再按上面的方式导入。
- 不写 `/etc/vpp/startup.conf`：它属于发行版的 vpp 软件包（deb conffile、rpm `%config`），包升级会提示换成包里的版本，`apt purge` 会删除，rpm 卸载会改名为 `.rpmsave`。VPP 启动参数写在 `/etc/vpp/router.conf`。以前版本生成的 `startup.conf` 在重新安装或 `--config-only` 时移到 `/var/lib/vpp-router/startup.conf.bak`，当时另存的原文件（`startup.conf.orig`）放回原处。
- 检测到发行版的 `vpp.service`（已安装且未屏蔽）时询问是否停止并 `mask`：它开机时会占用 `/run/vpp/cli.sock`，dpdk 插件还会接管所有绑定到 vfio-pci 的网卡。拒绝时，若它已启用或正在运行则停止安装。编译完成后才停止它；屏蔽前的状态记在 `/var/lib/vpp-router/distro-vpp-masked`，`--uninstall` 解除屏蔽，原来开机启动的重新启用，但不立即启动。
- 承载当前 SSH 的网卡交给 VPP 时，可启用 10 分钟自动回退：到时没有执行 `vpp-router-ctl confirm` 就停止 VPP 并还原网卡，不会重新启动 VPP。
- 同时编译本仓库的 VPP 插件 `ipsec_ike_punt`（`plugins/ipsec-ike-punt`），供下面的 IPsec 服务器选项使用；不选该项时插件只装进 `vpp_plugins/`，`router.conf` 不启用它。插件一旦加载，就会接管发给 VPP 的 ICMPv6 Packet Too Big，并在 IPsec 加密前插入 PMTU 检查。
- 询问是否用作 IPsec 服务器（默认否，以前选过则默认是）。这一项只配置 VPP 一侧，strongSwan 及其 `kernel-vpp` 后端要另外安装（参考 `plugins/strongswan-vpp/` 和 `tools/ipsec/`）：
  - `router.conf` 启用 `ipsec_ike_punt`；`vpp-router-ctl prep` 在 VPP 启动前建网络命名空间 `vpp-ipsec`。
  - `router.vpp` 建 `tap2082`，Linux 一端在 `vpp-ipsec` 里，名字与 VPP 的 WAN 接口相同（`kernel-vpp` 按 Linux 接口名找 VPP 接口，所以 WAN 名超过 15 个字符时不能启用），两端地址 `10.63.40.1/30`↔`.2`、`fd42:1111:2222:40::1/64`↔`::2`。
  - WAN 上 UDP 500 和 UDP 4500 中以 4 个 0 开头的 IKE 报文转进命名空间，ESP 留在 VPP 加解密；这两个端口在 NAT44 中做身份映射；解密后的流量以 `tap2082` 为接收接口进入 VPP（`ipsec cleartext ingress`），再走路由和出口 NAT。
  - `vpp-router-ctl post` 把 VPP 的 WAN IPv4 地址（/32）和一个全局 IPv6 地址（/128）配到命名空间里的同名接口上，默认路由经 `tap2082` 回到 VPP。WAN 用 DHCP 且地址后来变了，执行 `vpp-router-ctl ipsec` 重新设置。
  - charon 在命名空间里运行（`ip netns exec vpp-ipsec ipsec start`），绑定上面的 WAN 地址；需要 DNS 时写 `/etc/netns/vpp-ipsec/resolv.conf`。VPN 地址池不要和 LAN 重叠，回程按默认路由经 WAN 出去，才会被加密。
- 同时编译并安装管理面板 `vpp-monitor` 和它转发的 `vpp-interfaces`（接口）、`vpp-wireguard`（WireGuard）、`vpp-firewall`（防火墙）、`vpp-system`（线程、收包方式、NAT 参数、CPU 调速器），各自一个同名服务，详见它们在 `tools/` 下的 README。Go 工具链（1.25.11）按校验和从 go.dev 下载到构建目录，不装进系统；下载不了时用 `GO_URL` 换镜像，Go 模块用 `GOPROXY` 换代理。面板只监听 `vpp-host` 的地址（局域网打开 `https://<vpp-host 地址>:9480/`，端口可改，见下文），没有 `vpp-host` 时只监听 `127.0.0.1`。第一次安装时输入面板用户 `admin` 的密码，以后保留。
- 可选安装 Gate（默认不装，路由页面用它）：VPP 启动后运行 `tools/vpp-egress-gate/install.py`，回答它的问题，再装上 `gate-admin` 并询问是否启动 Gate。已经装了 Gate 的机器重新安装时自动装上 `gate-admin`。重新生成 `router.vpp` 时保留其他程序追加的 `exec` 行（例如 Gate 的设备配置）；面板对接口的修改不保留，`--config-only` 按这次的回答重新生成。
- 可选安装 sing-box 作为局域网的代理入口（默认不装，版本 1.14.3，和 RK3588 开发板相同，按校验和从 GitHub 下载，`SINGBOX_URL` 可换镜像），和 RK3588 开发板一样提供：局域网 SOCKS5 `vpp-host 地址:1080`（不认证），以及给 Gate 代理规则用的 TPROXY（2082）和 Fake-IP DNS（127.0.0.1:5354），端口都可以改。真实地址和 Fake-IP 地址进同一个 TPROXY 入站：规则的 DNS 用 Fake-IP DNS 时域名解析成地址池里的地址，用其他 DNS 时解析成真实 IP，网段总是真实 IP。TPROXY 的端口和地址池与 Gate 一致：Gate 已装时从它的配置读取，新装 Gate 时把同样的值传给它的安装程序。代理程序收到的是 Fake-IP 地址，要用自己发出的映射查回域名再交给上游，所以只转发目的 IP 的程序（比如 ipt2socks）不能替代它。
  - 配置在 `/etc/vpp/sing-box/`（只有 root 可读），sing-box 用 `-C` 合并加载：`entry.json` 是入口，每次运行本脚本都重新生成；`upstream.json` 是上游，只在第一次写，之后归你管理，本脚本不再改动。
  - 上游是 `upstream.json` 里标签为 `proxy` 的出站或 endpoint，sing-box 支持的任何协议都行（SOCKS5、Trojan、Shadowsocks、VLESS、WireGuard 等）。安装时可以按提示填 SOCKS5 或 Trojan，或者导入一个 sing-box 出站或 endpoint 的 JSON 文件（一个对象、它们的列表，或带 `outbounds`/`endpoints` 的片段；只有一个时自动设成 `proxy`，WireGuard 自动放进 `endpoints`），也可以稍后配置。还没有上游时，占位配置拒绝所有代理流量，不会不经代理就连出去。
  - 换上游：在面板的“代理”页面用向导设置，或从 sing-box 配置、分享链接、订阅导入（由一起安装的 `vpp-proxy` 执行，见 `tools/vpp-proxy/README.md`）；也可以直接编辑 `upstream.json` 再 `systemctl restart vpp-router-sing-box`，启动前会先用 `sing-box check` 检查。服务是 `vpp-router-sing-box.service` 和 `vpp-proxy.service`。UDP 要上游协议支持（SOCKS5 要支持 UDP ASSOCIATE）。
- 端口可以自定义：面板（默认 9480）、Gate 的 DNS（1053）、sing-box 的 SOCKS5（1080）、TPROXY（2082）和 Fake-IP DNS（5354）。回答完 sing-box 的问题后，脚本列出这次会用到的端口并询问是否修改；也可以用环境变量 `VPP_PANEL_PORT`、`VPP_GATE_DNS_PORT`、`VPP_SOCKS_PORT`、`VPP_TPROXY_PORT`、`VPP_FAKEDNS_PORT` 指定。端口要在 1 到 65535 之间、互不相同，不能是 53 和 67（客户端的 DNS 和 DHCP 用的是这两个固定端口，Gate 通过重定向接收 53 端口的查询）。选定的值记在 `/var/lib/vpp-router/ports`，重新运行和 `--config-only` 时沿用。Gate 的 DNS、TPROXY 和 Fake-IP DNS 只在第一次生成 Gate 配置时使用，之后以 `/etc/vpp/egress-gate.json` 为准，要改时改那里（或在面板的路由页面改代理规则）。
- 升级或 `--config-only` 会在覆盖旧配置和程序前，使用旧控制脚本停止 VPP、释放原网卡；释放失败则停止操作。当前 SSH 的本地地址或回程接口属于旧 VPP 管理网络时，拒绝停服，须改用控制台或独立管理口执行：Linux 网卡回退不能恢复原来的 VPP TAP 管理通道。

| 内容 | 位置 |
| --- | --- |
| 程序 | `/usr/local/bin/vpp`、`/usr/local/bin/vppctl`（在 PATH 里，`sudo vppctl` 直接可用），面板和管理服务 `/usr/local/bin/{vpp-monitor,vpp-interfaces,vpp-wireguard,vpp-firewall,vpp-system,gate-admin}`，可选的 `/usr/local/bin/sing-box` 和 `vpp-proxy`（配置在 `/etc/vpp/sing-box/`、`/etc/vpp/proxy/`），控制脚本 `/usr/local/sbin/vpp-router-ctl`，辅助脚本 `/usr/local/libexec/vpp-router/` |
| 库和插件 | `/usr/local/lib/vpp-router/`（私有库、`vpp_plugins/`、`vpp_crypto_engines/`），RPATH 指向这里，不改 `ld.so.conf` |
| 数据 | `/usr/local/share/vpp/api/`（API 定义），`/usr/local/share/vpp-router/`（DPDK PCI ID 表、仓库版本） |
| 平台内核模块 | `/lib/modules/<内核版本>/updates/vpp-router/`；没有设备匹配表，不会被自动加载，只由 `vpp-router-ctl` 加载 |
| 安装清单 | `/var/lib/vpp-router/installed-files`：装到系统目录的每个文件。升级时删除新版本没有的旧文件，`--uninstall` 按它删除；已存在且不在清单里的文件（例如手工部署的 VPP）不会被覆盖，安装会停止并提示用 `--prefix /opt/<名字>` |
| 配置 | `/etc/vpp/`，VPP 系统的 `/etc`：`router.conf`（VPP 启动参数）、`router.vpp`、`router.env`、`dnsmasq.conf`（dnsmasq 的 LAN 配置，相当于普通系统的 `/etc/dnsmasq.conf`） |
| 状态 | `/var/lib/vpp-router/`（原驱动记录 `nics.orig`、配置备份、DHCP 租约） |
| 服务 | `vpp-router.service`、`vpp-router-dnsmasq.service`，面板 `vpp-monitor.service`、`vpp-interfaces.service`、`vpp-wireguard.service`、`vpp-firewall.service`、`vpp-system.service`，装了 Gate 时 `gate-admin.service`，可选的 `vpp-router-sing-box.service` 和 `vpp-proxy.service`（Gate 自己的服务由它的 install.py 安装，`--uninstall` 不删） |
| 面板状态 | `/var/lib/vpp-monitor/`（密码哈希、证书），`/var/lib/vpp-interfaces/`、`/var/lib/vpp-system/`（待确认的改动），WireGuard 配置 `/etc/vpp/wireguard/`，系统页的收包设置和调速器 `/etc/vpp/system.json` |
| 源码和构建目录 | `/usr/local/src/vpp-router/` |

按本机编译的软件使用 `/usr/local`，私有库目录为 `vpp-router`。2026-11 以前的版本装在 `/opt/vpp-router/`，重新安装或 `--uninstall` 时整个删除。

可选启用 IPv6-PD：VPP 在 WAN 通过 DHCPv6-PD 获取前缀和通过 RA 学习默认路由，
在 LAN 的 `loop0` 消费一个 /64，由 `vpp-router-pd-sync.service` 根据租约的有效期
通过 RA/SLAAC 向 LAN 发布及撤销前缀。`/etc/vpp/router-pd-sync.json` 随配置生成；
重新配置会备份旧文件。需要上游提供 PD 和 RA 默认路由，不能同时在同一个 WAN 上
运行其他 PD 客户端。此功能不配置 IPv6 DNS 或 IPv6 防火墙，也不提供下级路由器的
DHCPv6-PD 委派服务；仅有一个 /64 时也无法再分出独立 /64 给下级路由器。

LAN 默认还有一个固定的 IPv6 ULA 网段（安装时问，默认启用）：按 RFC 4193 随机生成一个
`fdxx:xxxx:xxxx::/64`，`loop0` 用其中的 `::1`，并通过 RA 宣告（VPP 不会自动宣告接口地址的网段），
不依赖上游 IPv6，也不随委派前缀变化。重新安装时从 `router.vpp` 读回，网段不变；记在
`router.env` 的 `LAN_ULA`。装了 Gate 时，ULA 写进 Gate 的 `lan_prefixes`，`loop0` 写进
`lan_interfaces`（Gate 跟随其上的委派前缀），已有的 Gate 配置会补上这两项并重启 Gate；
sing-box 的 Fake-IP 同时分配 IPv6 地址池 `2001:2::/48`。

除默认的 `ipsec-ike-punt` 外，`plugins/` 下的插件须用 `VPP_EXTRA_PLUGINS` 显式选择；插件目录必须提供 `CMakeLists.txt`。PPPoE 不由本脚本配置。

源码按 `patches/README.md` 中的地址下载并校验 SHA-256，从源码包重新解开再打补丁。编译完成后在 `/usr/local/src/vpp-router/build.key` 记下编译指纹（源码版本和校验和、补丁和平台文件、所选 PMD、编译器版本、编译步骤本身）；再次运行安装时指纹不变且构建目录完整，就复用上次的编译结果，例如编译后安装或配置失败时，重跑约 1 分钟。`--rebuild` 强制重新编译。

构建依赖包含 `libunwind-dev`（Debian/Ubuntu）或 `libunwind-devel`（RPM 系统），用于调用栈和内存分配追踪。配置阶段未找到该开发库时安装器会停止，避免出现 `memory-trace` 已开启却无法记录分配调用栈的构建。
