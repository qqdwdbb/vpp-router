# vpp-system

管理面板“系统”页面的执行程序：VPP 的线程布局（主线程和 worker 所在的 CPU、调度策略）和 DPDK 网卡的收包队列数，把还没接入的 PCI 网卡经 DPDK 加进 VPP 或让接入的网卡退出，每个接口的收包方式和每个队列由哪个线程处理，NAT44 的模式（EI 或 ED）、会话超时和会话表大小，以及 Linux 的 cpufreq 调速器。以 root 运行，只在本机 Unix socket 上提供接口，由 `vpp-monitor` 转发。

## 构建和安装

```sh
make                                   # 生成 dist/vpp-system-linux-{arm64,amd64}
sudo install dist/vpp-system-linux-arm64 /usr/local/bin/vpp-system
sudo install -m 644 vpp-system.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpp-system
```

安装器生成的单元带 `--vpp-config /etc/vpp/router.conf --vpp-unit vpp-router.service` 和加网卡用的 `--router-env`、`--nics-orig`、`--pci-ids`、`--unit-dir`，平台限制 worker 数时（`platforms/*/vpp-router.conf` 的 `PLAT_MAX_WORKERS`，比如 N1 是 0）再加 `--max-workers`。其他部署按实际的启动文件和单元名改。

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--socket` | `/run/vpp-system/system.sock` | 面板连接的 socket |
| `--vpp-config` | `/etc/vpp/router.conf` | VPP 启动文件，改其中的 `cpu` 段、`dpdk` 里的 `num-rx-queues` 和 NAT 插件的 `plugin` 行 |
| `--cli-file` | 从 `--vpp-config` 里找 | VPP 启动时执行的 CLI 文件，改其中 NAT44 的启用和超时两行，切换模式时改全部 NAT44 命令 |
| `--wireguard-store` | `/etc/vpp/wireguard/wireguard.json` | vpp-wireguard 的配置，切换 NAT 模式时检查其中命令；为空不检查 |
| `--config` | `/etc/vpp/system.json` | 收包方式、收包线程和调速器 |
| `--vpp-unit` | 无 | 运行 VPP 的 systemd 单元。改线程和会话表时重启它，它变成 active 后装回收包设置。不设置时这两类修改被拒绝，收包设置在 VPP socket 出现 30 秒后装回 |
| `--api-socket` | `/run/vpp/api.sock` | VPP API socket |
| `--state-dir` | `/var/lib/vpp-system` | 待确认的改动和修改前的文件 |
| `--confirm` | `1m` | 确认期限 |
| `--max-workers` | `-1` | 平台最多能跑的 worker 数，`-1` 不限 |
| `--interfaces-pending` | `/var/lib/vpp-interfaces/pending.json` | `vpp-interfaces` 待确认的改动，存在时线程和 NAT 的修改被拒绝；空字符串不检查 |
| `--sysfs` | `/sys` | sysfs 的位置 |
| `--router-env` | `/etc/vpp/router.env` | 安装器的 `router.env`，加的网卡写进其中的 `NICS`。空字符串关闭加网卡 |
| `--cpu-affinity-file` | `/etc/systemd/system.conf.d/90-vpp-router-cpu.conf` | 安装器管理的系统默认 CPU 亲和性；`router.env` 有 `SYSTEM_CPUS` 时随线程布局同步更新 |
| `--nics-orig` | `/var/lib/vpp-router/nics.orig` | 安装器记录每块网卡原驱动的文件，加网卡时补上一行；空字符串不写 |
| `--pci-ids` | `/usr/local/share/vpp-router/dpdk-pci-ids` | 安装器从 DPDK 构建产物生成的 PCI ID 表，判断这次编译的 PMD 支持哪些网卡 |
| `--dpdk-plugin` | 从启动文件找 | VPP 的 `dpdk_plugin.so`，判断能否给同一 PCI 设备的几个口分别命名 |
| `--unit-dir` | `/etc/systemd/system` | `--vpp-unit` 的单元文件所在目录，用来判断平台是否要在启动前初始化 RTL8125；维护页列出这里安装的服务 |
| `--units` | 无 | 维护页在 `--unit-dir` 之外还要列出的单元，逗号分隔 |
| `--backup` | `/etc/vpp,/var/lib/vpp-interfaces/devices.json,/var/lib/vpp-router/nics.orig` | 配置备份里的文件和目录，逗号分隔，另外总是加上路由器服务的单元文件 |

## 各项设置存在哪里、怎么生效

| 设置 | 存放 | 生效 | 确认 |
|---|---|---|---|
| 主线程 CPU、worker 的 CPU、调度策略和优先级 | 启动文件的 `cpu { }` | 重启 VPP | 60 秒内确认，否则恢复 |
| DPDK 网卡的收包队列数 | 启动文件 `dpdk { dev 地址 { num-rx-queues N } }` | 和线程一起重启 | 同上 |
| 加入、退出 DPDK 网卡 | 启动文件 `dpdk` 段的 `dev` 块、`router.env` 的 `NICS` | 重启 VPP | 同上；加入的恢复时网卡交还原驱动，退出的恢复时重新绑定 |
| NAT44 模式（EI 或 ED） | 启动文件 `plugins` 段的 NAT 插件、CLI 文件里的全部 NAT44 命令 | 重启 VPP | 同上 |
| NAT44 会话表（每线程会话数；EI 另有用户数、每个用户的会话数） | CLI 文件的 `nat44 ei plugin enable` 或 `nat44 plugin enable` 行 | 重启 VPP | 同上 |
| NAT44 超时（TCP 已建立、握手和关闭、UDP、ICMP） | CLI 文件的 `set nat44 ei timeout` 或 `set nat timeout` 行 | 立即（API） | 不需要 |
| 接口的收包方式（轮询、中断、自适应） | `system.json` | 立即，VPP 每次启动后装回 | 不需要 |
| 队列由哪个线程处理 | `system.json` | 立即，VPP 每次启动后装回 | 不需要 |
| cpufreq 调速器 | `system.json` | 立即，本服务启动时（开机）再设一次 | 不需要 |

### 启动文件

只改顶层的 `cpu` 段，写成一行；段里本程序不管的参数（`relative`、`skip-cores` 等）保留。原来是 `workers N` 或 `coremask-workers` 的，保存后换成 `corelist-workers`。没有 `cpu` 段时加在文件末尾。`dpdk` 里只改 PCI 地址的 `dev` 块的 `num-rx-queues`，没有就加上；`dev default` 和平台 vdev 只显示。文件的其他字节不动，注释、缩进、多行写法都保留。

安装器启用 worker CPU 隔离（`router.env` 包含 `SYSTEM_CPUS`）时，保存线程布局还会同步修改 `SYSTEM_CPUS`、
systemd 默认 CPU 亲和性和 VPP 单元的 `CPUAffinity`。系统使用在线 CPU 中除 worker 以外的 CPU，包含主线程的 CPU；
VPP 单元仍可使用全部在线 CPU。没有 worker 时释放全部 CPU。四份文件一起备份并等待确认，超时、手动撤销、
启动验证失败或管理服务重启后发现过期改动时一起恢复；原先不存在的 systemd 配置文件会在回退时删除。
应用和恢复时都重新加载 systemd 的默认亲和性，再重启 VPP。`vpp-router-ctl post` 迁移允许使用全部 CPU 或上次
系统 CPU 范围的用户线程，保留其他自定义亲和性和内核线程；迁移范围保存在 `/run/vpp-router/system-cpus`，
即使迁移中途失败，回退仍能识别已经迁移过的线程。该联动需要安装新版控制脚本。

检查：CPU 要在线，主线程不能和 worker 同一个 CPU，worker 数不超过 `--max-workers`，队列数不超过网卡的上限（`show hardware-interfaces` 的 `rx: queues N (max M)`，读不到时 16），优先级（1–99）只用于 `fifo`、`rr`。

### NAT44 模式

VPP 运行两种 NAT44 插件之一，启动文件加载哪个就是哪种：

- EI（`nat44_ei_plugin.so`）：一个内网地址和端口连所有目的地都用同一个外部端口，谁都能发进来（全锥形）；每条连接独占一个外部端口。
- ED（`nat_plugin.so`）：先试内网端口，同一个外部端口可以复用给不同的目的地，只放行回应已有连接的包（端口受限锥形）。运营商限制可用端口数时能容纳多得多的连接；137（i5-9300H，2 个 worker）上 64 字节 UDP 峰值约 6.8 Mpps，EI 约 7.1 Mpps。依赖补丁 0033（多 worker 时保持映射不变）和 0034（多个出口时用出口自己的地址）。

切换时把启动文件里旧插件的 `plugin` 行换成新插件（两个都写着时互换 enable 和 disable，插件默认全部加载时另写一行禁用旧的），CLI 文件和它 `exec` 的文件（逐层往下，比如多出口用的 `router-local.vpp`）里的 NAT44 命令改成另一种写法，改到的文件一起备份、一起回滚：`nat44 ei ...` 与 `nat44 ...`、`set interface nat44 ei ...` 与 `set interface nat44 ...`、`set nat44 ei timeout` 与 `set nat timeout`。EI 的启用行改成 ED 时去掉用户数，反过来加上安装器的用户数 4096、每个用户 16384 个会话（不超过会话数）。另一种插件没有对应写法的命令（EI 的 `static-mapping-only`，ED 的 twice-nat、`out2in-only` 等），无论在哪个文件里，都使切换被拒绝，页面显示原因和所在文件。

离线改写：`vpp-system nat-mode -mode ei|ed [-check] [-vpp-config F] [-cli-file F] [-wireguard-store F] [-backup-dir D]` 不碰启动文件和 VPP，只把 CLI 文件和它 exec 的文件里的 NAT44 命令按上面的规则改成所选插件的写法，已经是这种写法的不动；`-check` 只检查。不能改时和系统页一样拒绝，什么都不改。安装器重新运行时换了 NAT 模式就用它改写保留下来的 exec 文件。

多出口：EI 按内侧路由表而不是按出口选地址池，所以本项目的多出口配置用 `nat_ei_context` 插件给每个出口一个自己的池：`nat44 ei context 出口 loopN` 让从出口出去的流量算作 loopN 所在路由表 N 的，池地址写成 `nat44 ei add address A tenant-vrf N`；`nat44 ei output-chain 出口` 让 EI 之后继续走输出功能链；`nat44 ei pool receive A 出口`（补丁 0008）把 A 的接收路由固定在出口上。ED 都不需要：它按出口选绑定在该出口上的地址（补丁 0034），NAT 之后本来就继续走输出功能链，各出口自己的地址由接口接收。切到 ED 时这几行改成 `#ei-only: 原命令` 的注释留在原处，路由表 N 的池地址在注释下面另起一行不带 tenant-vrf 的 ED 写法；切回 EI 时注释恢复成原命令，紧跟的那行 ED 写法删掉，所以 EI 到 ED 再到 EI 后文件逐字节不变（那行 ED 写法被手工改过则保留，改成 EI 写法）。前提是每个出口的池地址就是出口接口自己的地址（`set interface ip address` 或 WireGuard 配置的地址；`pool receive` 的出口也可以用 `add interface address` 取地址），切换前检查，不满足、或找不到 loopN 的路由表（`set interface ip table`）时拒绝。在 137 上按 R6S 的布局（WAN、桥接的 loop10、WireGuard 出口）测过：每个客户端经每个出口用的都是该出口的地址，MSS 钳制相同，WireGuard 出口重启后也一样。ED 还需要补丁 0036，否则 VPP 自己从出口地址发出的 ICMP（比如别人 ping 路由器出口地址时的回复）会被转换，对方收不到。WireGuard 配置的附加命令和停止前命令（`--wireguard-store`，默认 `/etc/vpp/wireguard/wireguard.json`）不改：vpp-wireguard 执行时自己换成 VPP 运行的插件的写法，这里只按上面同样的规则检查，有不能换的就拒绝，页面只指出是哪个 VPN 的第几条（文件里有私钥，不引用命令）。备份按文件名存放，两个要改的文件同名时也拒绝。重启后所有 NAT 会话重建；端口转发、本机端口和 WireGuard 的监听端口由各自的服务按 VPP 运行的插件装回。

### 加入 DPDK 网卡

安装器只在安装或 `--config-only` 时选网卡，`--config-only` 会重新生成 `router.vpp`，面板对接口做的修改会丢。这里加一块网卡，只改两个文件，`router.vpp` 不动：

- 启动文件 `dpdk` 段末尾加 `dev 地址 { name 接口名 num-rx-queues N }`。N 是 worker 数（没有 worker 时 1），不超过 `ethtool -l` 报的网卡上限。加的是 mlx4 网卡、段里还没有 `no-multi-seg` 时一起加上，和安装器一样。
- `router.env` 的 `NICS` 末尾加 `"lan 地址 Linux网卡名 dpdk|mlx 接口名"`。VPP 启动前 `vpp-router-ctl prep` 按它把网卡绑定到 `UIO` 驱动（mlx 网卡保留内核驱动，关闭流控）。
- `nics.orig` 里还没有这块网卡时加一行 `地址 当前驱动 Linux网卡名`，安装器的 `--restore` 据此交还网卡。这个文件不随撤销恢复，和安装器一样只记第一次见到的驱动。

页面列出 sysfs 里 class 为网卡（0x02）、还不在 `dpdk` 段和 `NICS` 里的 PCI 设备，无线网卡不列。Mellanox 网卡按口列出：mlx4 经一个 PCI 功能驱动 ConnectX-3 的两个口，每个 Linux 网卡是一个口，按 `dev_port` 排序，没接入的口单独列出（“口 1，和 port0 同一块卡”）。一个 PCI 设备只能有一个 `dev` 块，所以加这样的口时改的是已有块的 `name`：`name port0` 变成 `name port0,lan0`，按口的顺序列出，空位表示不接入的口；块里的队列数、描述符数等对所有口生效。这要 VPP 的 dpdk 插件带补丁 0031（`patches/vpp/0031-dpdk-name-ports-of-multi-port-device.patch`），本程序在插件文件里找补丁加的 notice 文字，没有就不允许加；插件位置取 `--dpdk-plugin`，没设置时从启动文件 `plugins { path … }` 里找。新卡只加第二个口时写 `name ,lan0`。下面这些情况不能加，页面写明原因：

- 不在 PCI ID 表里，也就是这次编译的 DPDK 没有它的 PMD。内存小于 3 GB 时安装器只编译所选网卡的 PMD，换别的芯片要重新完整安装。
- 属于网桥或 bond，或者 Linux 的默认路由（IPv4 或 IPv6）经过它。
- 用 vfio-pci 时，IOMMU 组里还有内核驱动在用的其他设备（桥除外）；或者网卡没有 IOMMU 组，而安装时没有选无 IOMMU 模式。
- mlx4 网卡的 `mlx4_core log_num_mgm_entry_size` 不是 -1；Mellanox 网卡没有 Linux 网卡。
- 平台在 VPP 启动前初始化 RTL8125（单元里有 `rtl8125-init`，比如 RK3588 开发板）时的 r8169 网卡。
- 部署本身不行时整节不可用：没有 `router.env` 或其中没有 `NICS`，启动文件没有 `dpdk` 段或是 `no-pci`（安装时没有选 PCI 网卡，dpdk 插件没有启用），没有 PCI ID 表，没有 `--vpp-unit`。这些情况用安装器的 `--config-only`。

Linux 在网卡上有地址时要用户确认（请求带 `"accept": true`）：接入后这些地址和经过它的连接都没有了。撤销时网卡交还原驱动，地址要由系统的网络配置（NetworkManager、networkd 等）重新设置。RTL8111/8168 只有 8168G 及以后的芯片受支持，也要确认。

接口名以字母开头，只用字母、数字、`-`、`_`，不能和 VPP 现有接口、启动文件和 `NICS` 里的名字重复，也不能用接口页当作虚拟接口的前缀（`tap`、`loop`、`wg`、`host-` 等）。页面建议第一个空闲的 `lanN`。

VPP 重启后 `show hardware-interfaces` 里出现这个名字和 PCI 地址才算成功，否则自动恢复。恢复（撤销、过期或失败）时先用新文件停止 VPP，让 `vpp-router-ctl release` 撤掉 prep 对网卡做的设置，再恢复文件，清除 `driver_override`，把网卡从 UIO 驱动解绑后绑回原驱动，最后启动 VPP。接入后网卡在接口页显示为物理口，地址、桥和出口在那里配置。

### 退出 DPDK 网卡

列出 `router.env` 的 `NICS` 里接入方式是 `dpdk` 或 `mlx` 的口。下面这些情况不能退出：安装时选的 WAN 口（角色 `wan`，PD 同步、IPsec 等配置也用它）；CLI 文件里还有命令用到它或它的子接口（`接口名.N`），页面列出前三行和总行数，要先在接口页删掉地址、子接口、桥和出口；它是 `dpdk` 段最后一块 PCI 网卡（没有 `dev` 时 dpdk 插件会接管所有处于 down 状态的网卡）。

退出时先停止 VPP，让 `vpp-router-ctl release` 按原来的文件收尾（比如恢复 mlx 网卡的流控），再改文件：`dev` 块整个删掉（自成一行时删掉那一行），同一 PCI 设备还有别的口在 VPP 时只把 `name` 列表里这个口换成空位（`port0,lan0` 退出 `lan0` 变成 `port0`，退出 `port0` 变成 `,lan0`）；`router.env` 删掉这一行。然后把网卡交还 `nics.orig` 记的驱动（没有记录时由内核选择），Mellanox 网卡和别的口还在 VPP 的网卡不动驱动，再启动 VPP。VPP 里没有这个接口、同卡其他口都还在才算成功。

撤销时恢复两个文件并重启 VPP，`vpp-router-ctl prep` 重新绑定网卡。确认时从 `system.json` 删掉这个接口的收包方式和收包线程设置。`nics.orig` 不改。

### 重启和确认

和 `vpp-interfaces` 一样：先把要改的文件备份到 `--state-dir`，写入新文件，重启 VPP，等单元 active、API socket 换成新的并且应答，再等最多 30 秒，直到 VPP 按新设置运行（线程在指定的 CPU 上，或 NAT 的会话表是新的大小）。没有做到就恢复文件并再重启一次，返回错误。做到了就开始 60 秒倒计时，期间可以“确认保留”或“立即恢复”（恢复也要重启）。管理服务重启后接着倒计时，过期的立即恢复。

NAT 会话表太大、主堆内存不够时插件启用失败，VPP 照常启动但没有 NAT，会自动恢复。

`vpp-interfaces` 也改同一个 CLI 文件，恢复时整个文件换回去，所以一边有待确认的改动时另一边拒绝修改（本程序看 `--interfaces-pending`，它看 `--system-pending`）。

### 收包方式

`sw_interface_set_rx_mode` 设置接口所有队列。设置后读回，VPP 拒绝或仍显示原来的方式（网卡不支持收包中断）时恢复原来的方式并报错。“缺省”从 `system.json` 删掉这个接口，现在的方式不变，下次 VPP 启动时按安装器的设置（`router.env` 的 `RX_MODE`、`router.vpp` 里 TAP 的 `rx-mode interrupt`）。

本程序在 VPP 单元变成 active 之后（`vpp-router-ctl post` 之后）才装回，所以面板的设置覆盖 `RX_MODE=interrupt` 时 ctl 设的 adaptive。

用中断或自适应时，如果 VPP 开着主机协议栈（session 层，比如 LDP 跑的 nginx），启动文件里还要有 `session { use-private-rx-mqs }`，否则 session 队列一直轮询，worker 不能休眠。安装器选了“中断”时会写这一行；之后在面板上改的不会自动加。

### 收包线程

`sw_interface_set_rx_placement` 把一个队列交给主线程或某个 worker。线程按 VPP 的线程号：0 是主线程，n 是 worker n-1。VPP 启动后装回；worker 少了以后放不下的队列跳过，由 VPP 自己分配，并在页面上提示。“VPP 分配”删掉这一项，现在的线程不变。

### 调速器

写 `/sys/devices/system/cpu/cpufreq/policyN/scaling_governor`，只接受该策略 `scaling_available_governors` 里的值，写后读回。本服务启动时把 `system.json` 里的设置都写一次；别的程序（比如 rc.local）之后再改的，页面上显示“设置的是 X”。没有 cpufreq 的机器（虚拟机、固定频率）这一节为空。

## 维护

面板“维护”页面的后端。

### 服务

列出 `--unit-dir` 里管理员安装的服务（普通文件，不含模板 `@.service` 和指向 `/dev/null` 的屏蔽链接）、`--vpp-unit` 和 `--units`，用 `systemctl show` 读状态。下面这些算路由器的服务，排在前面，其余折叠在“其他服务”里：VPP 的单元，`After`、`Requires`、`Wants`、`BindsTo`、`PartOf`、`Requisite` 里有 VPP 单元的，单元文件里出现 `vpp`（不区分大小写）或运行 `gate-admin` 的。

启动、停止、重启用 `systemctl … --no-block`，不等待完成，页面接着刷新状态。限制：

- VPP 的单元、面板（连到 socket 的进程所在的单元，按 `SO_PEERCRED` 和 cgroup 找）和本程序只能重启：停止后面板无法再启动它们。
- 重启面板和本程序用 `systemd-run --on-active=2s` 延迟执行，先回复请求。重启主机也一样。
- 本程序或 `vpp-interfaces` 有改动等待确认时，不能重启 VPP 或主机：重启会让确认流程失去意义。

### 日志

`journalctl -o json`，单元必须是列出的服务，`kernel` 读内核日志（`--dmesg`），空的读全部。关键词不区分大小写，在本程序里过滤（不依赖 journalctl 的 `--grep`，它要 PCRE2），有关键词时先读最后 2 万行再挑。每次最多返回 2000 行，带 journal 游标，页面用 `after` 从游标继续，做实时跟踪。`vpp:logging` 是 VPP 的 `show logging`。下载用 `-o short-iso`，最多 5 万行。

### 网络测试

| 测试 | 做法 |
|---|---|
| ping | Linux：`ping -n -c N -i 0.5 -W 2 [-4/-6] [-I 接口]`。VPP：`ping 地址 repeat N interval 0.5 [source 接口]`，域名先用主机的 DNS 解析 |
| 路由跟踪 | Linux 的 traceroute（或 busybox）：`traceroute -n -w 2 -q 1 -m 20 [-4/-6] [-i 接口]`。GNU inetutils 的 traceroute 没有 `-n`、不能指定接口、只支持 IPv4：`traceroute -w 2 -q 1 -m 20`，IPv6 改用 tracepath。没有 traceroute 时用 `tracepath -n -m 20 [-4/-6]`（不能指定接口）。有 `stdbuf` 时按行输出，35 秒到时停止也能看到已经走过的跳 |
| DNS | Go 的解析器，A、AAAA、CNAME、MX、TXT、NS。不填服务器时用主机的设置；填了直接问它，可以绑定接口 |
| HTTP | GET，不跟随跳转，读最多 1 MiB，报告解析、连接、TLS、第一个字节和完成的时间、状态码和证书。可以绑定接口（`SO_BINDTODEVICE`） |

目标只接受 IP 地址和域名（HTTP 是网址），不会被命令当成选项。同一时间只跑一个测试，最长 40 秒。

可选的接口只列能发出测试的。Linux：`ip -o -4/-6 route show table all` 里有路由经过的设备，不算 local 表、`local`/`broadcast`/`multicast`/`anycast`/`unreachable` 等类型、`linkdown` 的路由和每个 IPv6 设备都有的 `fe80::/64`，也不列 loopback；读不到路由时列出全部设备。VPP：`show interface address` 里状态 up、有 L3 地址（自己的或 unnumbered 借来的，不算 `fe80::`）的接口，桥成员和没有地址的口不列；这条命令失败时退回 `show interface` 的全部接口。

### 配置备份

把 `--backup` 的文件和目录，以及路由器服务的单元文件和 drop-in 目录，按原路径打包成 `.tar.gz`，加一个 `MANIFEST.txt`。符号链接按链接保存，大于 16 MiB 的文件跳过并记在清单里。不含面板的账号和证书（`/var/lib/vpp-monitor`）。

### 接口

| 路径 | 内容 |
|---|---|
| `GET /system/maint/units` | 服务、VPP 单元名、不能重启 VPP 的原因、开机时间、备份的路径 |
| `POST /system/maint/units` | `{"unit","action"}`，`action` 是 `start`、`stop`、`restart`，或 `reboot`（不需要 `unit`）；返回新的服务列表 |
| `GET /system/maint/logs` | 参数 `unit`、`lines`、`since`（Unix 秒）、`boot=1`、`priority`（0–7）、`grep`、`after`（游标） |
| `GET /system/maint/logs.txt` | 同上，下载文本 |
| `GET /system/maint/sources` | 测试可用的 Linux 接口、VPP 接口和路由跟踪工具 |
| `POST /system/maint/test` | `{"kind","target","from","interface","family","count","server","type"}` |
| `GET /system/maint/backup` | 下载配置备份 |

每个操作都写入服务日志（`audit:`）。

## 配置文件

```json
{
  "rx_modes": {"port0": "adaptive"},
  "rx_placement": {"port0": {"1": 2}},
  "governors": {"policy4": "ondemand"}
}
```

直接改文件后重启服务生效。每次修改都写入服务日志（`journalctl -u vpp-system | grep audit`）。

## 接口

| 路径 | 内容 |
|---|---|
| `GET /system` | CPU 和调速器、VPP 的线程和启动文件里的 `cpu` 段、DPDK 网卡、可以加入的 PCI 网卡（`nics`）、每个接口的收包队列（方式、线程、设置）、NAT44（启动文件加载的模式、CLI 文件的模式、不能切换的原因、运行中的值和文件里的值）、待确认的改动和上次结果、错误 |
| `POST /system/nat/timeouts` | `{"tcp_established","tcp_transitory","udp","icmp"}`，各 10–604800 秒 |
| `POST /system/nat/size` | `{"sessions","users","user_sessions"}`（ED 只用 `sessions`），重启 VPP |
| `POST /system/nat/mode` | `{"mode"}`，`ei` 或 `ed`，重启 VPP |
| `POST /system/threads` | `{"main_core","workers":[...],"scheduler_policy","scheduler_priority","rx_queues":{"PCI 地址":N}}`，重启 VPP |
| `POST /system/rx-mode` | `{"interface","mode"}`，`mode` 是 `polling`、`interrupt`、`adaptive` 或 `default`（缺省：不再设置，回到安装器的设置） |
| `POST /system/rx-placement` | `{"interface","queue","thread"}`，`thread` 为 -1 时交给 VPP 分配 |
| `POST /system/nics/add` | `{"address","port","name","accept"}`，`port` 是同一 PCI 设备上的口（`dev_port`，一般是 0），`accept` 表示已确认页面上的提示，重启 VPP |
| `POST /system/nics/retire` | `{"name"}`，VPP 接口名，重启 VPP |
| `POST /system/governor` | `{"policy","governor"}`，`governor` 为空时是缺省：不再设置，回到系统的设置 |
| `POST /system/confirm`、`/rollback` | `{}` |

面板从 `/api/system/*` 转发过来，出错时返回 409 和 `{"error": "原因"}`。

## 测试

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o dist/vpp-system.test .
# 把 dist/vpp-system.test 复制到 Linux 主机上运行
```
