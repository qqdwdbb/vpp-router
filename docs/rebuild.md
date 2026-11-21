# 从原始源码重现

## 状态

2026-11-14 逐个比对了参考设备（RK3588 开发板）上 VPP 进程加载的全部 VPP/DPDK 文件：用本仓库源码（原版
VPP 26.06、DPDK 26.03 加 `patches/vpp`、`platforms/rtl8125-noncoherent` 的 0001 和 `plugins/`）
按参考设备当时的编译参数重编，比较 .text、.rodata、.data、.data.rel.ro、.init_array、.fini_array。
除 acl_plugin 外全部相同。

| 组件 | 状态 |
|---|---|
| RTL8125 PMD | 整个文件逐字节相同（原版 DPDK 26.03 加平台补丁 0001；不含平台补丁 0002） |
| 其他 DPDK 库（eal、ethdev、bus_pci、mempool_ring 等） | 相同，源码为原版 DPDK 26.03 |
| dpdk 插件 | 整个文件逐字节相同。`.enable_rxq_int`（`b081224`）是之后加的，参考设备上还没有 |
| vpp、libvppinfra、libvlib、libvlibapi、libvlibmemory、libsvm、libnat、native/openssl 加密引擎 | 相同（含补丁 0014；0013 只加 `const`，不改变生成的代码） |
| libvnet、tap、nat44_ei、wireguard、dhcp、mss_clamp、ping | 相同（libvnet 含 0006、0007、0009、0015，nat44_ei 含 0008、0010–0012） |
| abf、nat66 | 相同，用同一份源码在单独的构建目录编译（`build/history/build-abf.py`、`build-nat66.py`） |
| dns_intercept、nat_ei_context | 相同，参数与当时的 VPP 插件编译参数一致 |
| wg_nat_order | 相同，按插件 README 的 `cc -shared -fPIC -O2` 编译 |
| ipsec_ike_punt | 相同。参考设备上的版本是关掉 `-Werror` 编译的：`ipsec_hidden_symbol()` 把 `u8 *` 传给 `strcmp`，触发指针符号警告。2026-11-14 源码加了 `(const char *)` 转换，现在带 `-Werror` 也能编译，生成的代码不变 |
| acl_plugin | 参考设备上的版本另含面板用的会话计数补丁（每个会话的字节和包数，`show acl-plugin session-list`），用于统计 IPv6 NAT 会话；现在不需要，没有收入本仓库。从本仓库重编部署时这部分会去掉 |

除 PMD 和 dpdk 插件外，文件整体哈希不同：调试信息里的路径不同，参考设备上的版本还用 patchelf 改过 RUNPATH。因此比较应针对代码和数据段。

## 工具链

参考设备上的版本在 Debian 12 arm64 上原生编译，GCC 12.2.0-14+deb12u1。

Debian 12 的交叉编译器 `gcc-12-aarch64-linux-gnu` 12.2.0-14cross1 没有 CVE-2023-4039（AArch64 栈保护）修复，产物和参考设备上的版本不一致，不能用于发布。应使用原生 arm64 环境。

## 构建参数

`deploy/install/vpp-router-install.sh` 用下面的参数自动完成下载、打补丁和编译，DPDK 改为只编译常见网卡的 PMD，并按 VPP 内置 DPDK 的方式 whole-archive 链接。

VPP（CMake，Ninja，Release）：

```
-DVPP_PLUGINS=dpdk,tap,nat,nat44_ei,wireguard,acl,dhcp,mss_clamp,ping
-DVPP_DRIVERS=none -DVPP_CRYPTO_ENGINES=native,openssl -DVPP_USE_SYSTEM_DPDK=ON
-DVPP_USE_LTO=OFF -DVPP_TESTS=none -DVPP_TOOLS=vppctl
-DVPP_MARCH_VARIANT_CORTEXA72=OFF -DVPP_MARCH_VARIANT_NEOVERSEN1=OFF
-DVPP_MARCH_VARIANT_NEOVERSEN2=OFF -DVPP_MARCH_VARIANT_OCTEONTX2=OFF
-DVPP_MARCH_VARIANT_QDF24XX=OFF -DVPP_MARCH_VARIANT_THUNDERX2T99=OFF
```

版本字符串写在 `src/scripts/.version`：`v26.06-1-geth1test`。这个源码包在 v26.06 之上还带有
时钟速率修正、IPv6 ND 学习顺序和 tlsopenssl 的改动，已作为 `patches/vpp` 的 0014–0016 收入。

DPDK（Meson，release）：

```
--default-library=static -Dplatform=generic -Dtests=false -Dmax_lcores=16
-Denable_driver_sdk=true -Ddisable_libs=graph,node
-Denable_drivers=net/r8169,bus/pci,bus/vdev,bus/vmbus,mempool/ring
```

abf 和 nat66 用单独的构建目录（`VPP_BUILD_NATIVE_ONLY=ON`），见 `build/history/build-abf.py` 和 `build-nat66.py`。这些脚本和 `build/history/rebuild/` 依赖原设备上的目录，不能直接在其他机器运行。

## 内核依赖

只在 Rockchip vendor 内核 6.1.57 上运行过。换内核需要处理：

| 依赖 | 说明 |
|---|---|
| uio_pci_generic | 原内核没有，需要编译模块。启用 IOMMU 后可能不可用 |
| vhost_net | 按内核编译或打开配置 |
| r8125 | 第三方模块，只用于 Linux 驱动回退 |
| 用户态缓存维护 | PMD 在 EL0 执行 `dc civac`，依赖内核允许 |
| `/sys/class/devfreq/dmc` | vendor 内核的节点，`vrouter-dmc-fixed.service` 依赖它 |
| nftables、TPROXY、TUN | 防火墙和分流需要 |
