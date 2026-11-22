#!/usr/bin/env bash
# 从源码编译并安装 VPP 软路由：VPP 26.06 + DPDK 26.03 + patches/vpp、patches/dpdk。
#
# 流程：检测架构和网卡 → 选择交给 VPP 的网卡并分配 WAN/LAN → 安装依赖、
# 下载并打补丁、编译 DPDK 和 VPP，编译管理面板和它的服务 → 生成配置和 systemd 单元 → 可选启动，
# 可选安装 Gate。
# 非 PCI 网卡按 platforms/*/vpp-router.conf 匹配原生 PMD（例如 Phicomm N1），
# 没有匹配的平台时用 AF_PACKET 接入。
#
#   sudo deploy/install/vpp-router-install.sh                # 完整安装
#   sudo deploy/install/vpp-router-install.sh --config-only  # 不编译，只重新配置网卡
#   sudo deploy/install/vpp-router-install.sh --restore      # 停止 VPP，网卡还给内核驱动
#   sudo deploy/install/vpp-router-install.sh --uninstall    # 还原网卡并删除程序，保留 /etc/vpp
#
# 安装位置：本机编译的程序放 /usr/local（vpp、vppctl 在 bin，私有库和插件在 lib/vpp-router），
# 配置 /etc/vpp，状态 /var/lib/vpp-router，服务 vpp-router.service（可选 vpp-router-dnsmasq.service）。
# 管理面板 vpp-monitor 和它转发的 vpp-interfaces、vpp-wireguard、vpp-firewall、vpp-system（装了 Gate 时还有 gate-admin）也在 bin，
# 各自一个同名服务。
set -Eeuo pipefail

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
	echo "需要 bash 4 或更新版本" >&2; exit 1
fi

SCRIPT=$(readlink -f "${BASH_SOURCE[0]}")
REPO=$(cd "$(dirname "$SCRIPT")/../.." && pwd)

VPP_TAG=v26.06
VPP_URL=${VPP_URL:-https://github.com/FDio/vpp/archive/refs/tags/$VPP_TAG.tar.gz}
VPP_SHA256=${VPP_SHA256:-9541cb9fc889b963f537117907e16b8e37339d3446bad71cdf9e7d05622db990}
DPDK_VERSION=26.03
DPDK_URL=${DPDK_URL:-https://fast.dpdk.org/rel/dpdk-$DPDK_VERSION.tar.xz}
DPDK_SHA256=${DPDK_SHA256:-84989202bbe0fbaeeb62f8fdc63f691880ac0b66cd0dc64c167843c59db29d2c}
# 编译面板和管理服务的 Go 工具链。发行版的 Go 常常太旧（需要 1.24 以上），所以下载官方版本，只放在 $SRC 里
GO_VERSION=1.25.11
GO_SHA256_amd64=34f14304e856893f4ba30c2cacfe93906e9de7915c5f6aaaf3a81cdccd7ba30b
GO_SHA256_arm64=c30bf9e156a54ea4e31fbbbf31a712b32734b58cc9a22426fa5ee632d0885124
# 可选的 sing-box：局域网的代理入口（TPROXY、Fake-IP DNS、SOCKS5），上游任意，和 RK3588 开发板用的版本相同
SINGBOX_VERSION=1.14.3
SINGBOX_SHA256_amd64=e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee
SINGBOX_SHA256_arm64=29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e

PREFIX=/usr/local
# 2026-11 以前的安装位置，安装时迁移并删除
OLD_PREFIX=/opt/vpp-router
SRC=/usr/local/src/vpp-router
CONF=/etc/vpp
# VPP 启动参数。不用 startup.conf：那是发行版 vpp 软件包的配置文件（deb conffile、rpm %config），
# 包升级会提示换成包里的版本，purge 会删除，rpm 卸载会改名为 .rpmsave
STARTUP=$CONF/router.conf
STATE=/var/lib/vpp-router
# IPv6-PD 时让 Linux 的 vpp-host 即使开启转发也能接受 VPP 发出的 RA。
SYSCTL_IPV6=/etc/sysctl.d/99-vpp-router-ipv6.conf
UNIT_DIR=/etc/systemd/system
SERVICE=vpp-router
# 发行版 vpp 软件包的服务：会用 /run/vpp/cli.sock，dpdk 插件还会接管所有绑定到 vfio-pci 的网卡
DISTRO_SERVICE=vpp.service
# 本脚本屏蔽了发行版服务的记录，内容是屏蔽前 is-enabled 的结果；--uninstall 据此还原
DISTRO_MASKED=$STATE/distro-vpp-masked
DNS_SERVICE=vpp-router-dnsmasq
PD_SERVICE=vpp-router-pd-sync
IPV6_PD=0
# LAN 的固定 IPv6 ULA 网段（/64），空表示不用；重装时沿用 router.vpp 里的，不会变
LAN_ULA=
# LAN 的 dnsmasq 配置：生成和就地更新 $CONF/dnsmasq.conf，导入系统 dnsmasq 的配置
LANTOOL=$REPO/deploy/install/dnsmasq-lan.py
# 安装时停用的系统 dnsmasq.service 原来的状态（is-enabled is-active），--restore、--uninstall 据此恢复
SYSTEM_DNSMASQ=$STATE/system-dnsmasq
IMPORT_DNSMASQ=0 IMPORT_RANGE= DHCP_LEASE=12h
HOST_TAP=vpp-host
# 和 VPP 一起编译的本仓库插件（plugins/ 下的目录）。ipsec-ike-punt 是 strongSwan + VPP 做 IPsec 服务器时
# 用的：把 UDP 4500 上的 IKE 报文交给 Linux、解密后的流量换接收接口再走 NAT、处理隧道 PMTU。
# 装上但默认不启用，加载它就会接管发给 VPP 的 ICMPv6 Packet Too Big
REPO_PLUGINS="ipsec-ike-punt"
# 可选的额外插件，逗号分隔；项目插件目录使用连字符，VPP 名称使用下划线。
EXTRA_PLUGINS=${VPP_EXTRA_PLUGINS:-}
if [ -z "${VPP_EXTRA_PLUGINS+x}" ] && [ -r "$STATE/extra-plugins" ]; then
	EXTRA_PLUGINS=$(<"$STATE/extra-plugins")
fi
for extra in ${EXTRA_PLUGINS//,/ }; do
	[[ "$extra" =~ ^[a-z][a-z0-9_]*$ ]] || { echo "无效的额外插件名: $extra" >&2; exit 2; }
	if [ -d "$REPO/plugins/${extra//_/-}" ]; then REPO_PLUGINS+=" ${extra//_/-}"; fi
done
IPSEC=0
# IPsec 服务器选项：charon 所在的命名空间，以及 VPP 与它之间的 TAP（与 tools/ipsec/ipsec-vpp.conf 相同）
IPSEC_NS=vpp-ipsec
IPSEC_TAP_ID=2082
# 管理面板和它转发的服务，都在 tools/ 下，各自一个同名的 systemd 服务
PANEL_TOOLS=(vpp-monitor vpp-interfaces vpp-wireguard vpp-firewall vpp-system)
PANEL_STATE=/var/lib/vpp-monitor
# 面板、Gate 和 sing-box 监听的端口，可以自定义。环境变量 VPP_PANEL_PORT 等优先，其次是上次记在
# $STATE/ports 的值，安装时还可以再改。Gate 的 DNS、TPROXY 和 Fake-IP DNS 只在第一次生成 Gate 配置时用，
# 之后以 Gate 的配置为准；客户端用的 DNS 53 和 DHCP 67 是协议规定的端口，不在其中
PORT_VARS=(PANEL_PORT GATE_DNS_PORT SOCKS_PORT TPROXY_PORT FAKEDNS_PORT)
PANEL_PORT=9480 GATE_DNS_PORT=1053 SOCKS_PORT=1080 TPROXY_PORT=2082 FAKEDNS_PORT=5354
# Gate 由它自己的 install.py 安装，程序和单元的位置是固定的
GATE_CONFIG=$CONF/egress-gate.json
GATE_UNIT=vpp-egress-gate.service
WANT_GATE=0
PANEL_PW=
# entry.json 由本脚本每次生成，upstream.json 只在第一次写，之后归用户
SINGBOX_DIR=$CONF/sing-box
SINGBOX_UNIT=vpp-router-sing-box
SINGBOX_GEN=$REPO/deploy/install/singbox-config.py
WANT_SINGBOX=0
SB_TYPE= SB_SERVER= SB_PORT= SB_USER= SB_PASS= SB_SNI= SB_FILE=
JOBS=
REBUILD=0
MODE=install

usage() {
	sed -n '2,14p' "$SCRIPT" | sed 's/^# \{0,1\}//'
	cat <<EOF

选项：
  --config-only   跳过依赖安装和编译，只重新选择网卡并生成配置
  --restore       停止并禁用服务，把网卡还给安装前的内核驱动
  --uninstall     还原网卡，删除本脚本安装的程序、内核模块和服务；保留 /etc/vpp 和 /var/lib/vpp-router
  --prefix DIR    安装前缀（默认 ${PREFIX}）：程序在 bin、sbin，VPP 的库和插件在 lib/vpp-router
  --src DIR       源码和构建目录（默认 ${SRC}）
  --jobs N        编译并行数（默认按 CPU 数和内存，每个编译进程约 800 MB 内存加 swap；
                  内存不够时编译期间临时启用 zram）
  --rebuild       即使源码、补丁和编译选项都没变，也重新编译 DPDK 和 VPP
  -h, --help      显示本帮助

环境变量：VPP_URL VPP_SHA256 DPDK_URL DPDK_SHA256 UIO_DRIVER（vfio-pci 或 uio_pci_generic）
          VPP_EXTRA_PLUGINS（逗号分隔的额外 VPP 插件，项目插件须含 CMakeLists.txt）
          DNSMASQ_CONF DNSMASQ_CONF_DIR（导入时读取的系统 dnsmasq 主配置和配置目录，默认从运行中的进程读取）
          GO_URL（Go 工具链的下载地址，默认 go.dev，可以换成镜像，校验和不变）
          SINGBOX_URL（sing-box 发布包的下载地址，默认 GitHub，可以换成镜像，校验和不变）
          GOPROXY（编译面板时下载 Go 模块的代理，默认 proxy.golang.org，比如 https://goproxy.cn）
          VPP_PANEL_PORT（面板，默认 9480） VPP_GATE_DNS_PORT（Gate 的 DNS，默认 1053）
          VPP_SOCKS_PORT VPP_TPROXY_PORT VPP_FAKEDNS_PORT（sing-box 的 SOCKS5、TPROXY、Fake-IP DNS，
          默认 1080、2082、5354）；不设时沿用上次安装的值，安装过程中也可以修改
EOF
}

while [ $# -gt 0 ]; do
	case $1 in
	--config-only) MODE=config ;;
	--restore) MODE=restore ;;
	--uninstall) MODE=uninstall ;;
	--prefix) PREFIX=${2:?}; shift ;;
	--src) SRC=${2:?}; shift ;;
	--jobs) JOBS=${2:?}; shift ;;
	--rebuild) REBUILD=1 ;;
	-h|--help) usage; exit 0 ;;
	*) echo "未知选项: $1" >&2; usage >&2; exit 2 ;;
	esac
	shift
done

DEPS=$SRC/deps
PREFIX=${PREFIX%/}
# VPP 的私有库目录。编译时写入 VPP（CLIB_LIB_DIR），运行时按 bin/vpp 的位置找 ../lib/vpp-router 下的
# vpp_plugins 和 vpp_crypto_engines；RPATH 也指向这里，不需要 ld.so.conf 或 LD_LIBRARY_PATH
VPP_LIBDIR_REL=lib/vpp-router
LIBDIR=$PREFIX/$VPP_LIBDIR_REL
LIBEXEC=$PREFIX/libexec/vpp-router
DATADIR=$PREFIX/share/vpp-router
CTL=$PREFIX/sbin/vpp-router-ctl
VPPCTL_BIN=$PREFIX/bin/vppctl
# 本脚本装到系统目录的每个文件，升级和卸载只按它删除
MANIFEST=$STATE/installed-files
KMOD_DIR=/lib/modules/$(uname -r)/updates/vpp-router

# ---------- 输出与输入 ----------

if [ -t 1 ]; then B=$'\033[1m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'
else B= R= G= Y= C= N=; fi
info() { printf '%s==>%s %s\n' "$C$B" "$N" "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '%s警告:%s %s\n' "$Y$B" "$N" "$*" >&2; }
die() { printf '%s错误:%s %s\n' "$R$B" "$N" "$*" >&2; exit 1; }
trap 'die "第 $LINENO 行命令失败: $BASH_COMMAND"' ERR

# ask 变量名 提示 默认值
ask() {
	local __ans
	read -r -p "$2 [$3]: " __ans </dev/tty || __ans=
	printf -v "$1" '%s' "${__ans:-$3}"
}

# ask_yn 提示 y|n，回答“是”时返回 0
ask_yn() {
	local reply hint=y/N
	[ "$2" = y ] && hint=Y/n
	while :; do
		read -r -p "$1 [$hint]: " reply </dev/tty || reply=
		reply=${reply:-$2}
		case ${reply,,} in
		y|yes|是) return 0 ;;
		n|no|否) return 1 ;;
		esac
	done
}

# IPv4 地址计算，避免依赖 ipcalc
ipv4() {
	python3 -I - "$@" <<'EOF'
import ipaddress, sys
op, args = sys.argv[1], sys.argv[2:]
def iface(text):
    if '/' not in text:
        raise ValueError
    i = ipaddress.IPv4Interface(text)
    if i.network.prefixlen > 30 or i.ip in (i.network.network_address, i.network.broadcast_address):
        raise ValueError
    return i
try:
    if op == 'cidr':
        iface(args[0])
    elif op == 'ip':
        ipaddress.IPv4Address(args[0])
    elif op == 'in':            # cidr ip：ip 在 cidr 网段内且不是本机地址
        i, a = iface(args[0]), ipaddress.IPv4Address(args[1])
        sys.exit(0 if a in i.network and a != i.ip and a not in (i.network.network_address, i.network.broadcast_address) else 1)
    elif op == 'overlap':       # cidr cidr...：第一个网段与其余任一重叠
        net = ipaddress.ip_interface(args[0]).network
        sys.exit(0 if any(net.overlaps(ipaddress.ip_interface(o).network) for o in args[1:]
                          if ipaddress.ip_interface(o).version == 4) else 1)
    elif op == 'peer':          # cidr：网段内另一个地址，保留前缀
        i = iface(args[0])
        print(next(f'{h}/{i.network.prefixlen}' for h in i.network.hosts() if h != i.ip))
    elif op == 'range':         # gateway-cidr host-ip：DHCP 地址池
        i, used = iface(args[0]), {iface(args[0]).ip, ipaddress.IPv4Address(args[1])}
        hosts = [h for h in i.network.hosts() if h not in used]
        if i.network.prefixlen == 24:
            pool = [h for h in hosts if 100 <= int(h) & 255 <= 199]
        else:
            pool = hosts[len(hosts) // 4: len(hosts) * 3 // 4] or hosts
        print(pool[0], pool[-1], i.network.netmask)
    elif op == 'addr':
        print(iface(args[0]).ip)
    else:
        sys.exit(2)
except (ValueError, StopIteration, IndexError):
    sys.exit(1)
EOF
}

# 从 /etc/machine-id 派生固定的本地管理 MAC
stable_mac() {
	local h
	h=$(printf '%s:%s' "$1" "$(cat /etc/machine-id 2>/dev/null || hostname)" | sha256sum | cut -c1-10)
	printf '02:%s:%s:%s:%s:%s\n' "${h:0:2}" "${h:2:2}" "${h:4:2}" "${h:6:2}" "${h:8:2}"
}

# ---------- 平台检测 ----------

detect_platform() {
	[ "$(uname -s)" = Linux ] || die "只支持 Linux"
	[ "$(id -u)" = 0 ] || die "请用 root 运行（sudo $0）"
	[ -r /dev/tty ] || die "需要交互终端"
	command -v python3 >/dev/null || die "需要 python3"
	command -v ip >/dev/null || die "需要 iproute2"

	ARCH=$(uname -m)
	case $ARCH in
	x86_64|aarch64) ;;
	*) die "不支持的架构 ${ARCH}（只支持 x86_64 和 aarch64）" ;;
	esac
	CPUS=$(nproc)
	MEM_MB=$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)
	HUGE_KB=$(awk '/^Hugepagesize:/ {print $2}' /proc/meminfo)
	HUGE_KB=${HUGE_KB:-0}
	OS_ID=unknown OS_NAME=Linux
	if [ -r /etc/os-release ]; then
		# shellcheck disable=SC1091
		OS_ID=$(. /etc/os-release; echo "${ID:-unknown} ${ID_LIKE:-}")
		OS_NAME=$(. /etc/os-release; echo "${PRETTY_NAME:-Linux}")
	fi
	if command -v apt-get >/dev/null; then PKG=apt
	elif command -v dnf >/dev/null; then PKG=dnf
	else PKG=none; fi

	BOARD=
	[ -r /proc/device-tree/compatible ] && BOARD=$(tr '\0' ' ' </proc/device-tree/compatible)

	if [ -n "$(ls -A /sys/kernel/iommu_groups 2>/dev/null)" ]; then IOMMU=1; else IOMMU=0; fi
	if [ -z "$JOBS" ]; then JOBS_AUTO=1; plan_jobs; else JOBS_AUTO=0; fi

	info "主机：${OS_NAME}，${ARCH}，内核 $(uname -r)，$CPUS 个 CPU，内存 ${MEM_MB} MB，大页 $([ "$HUGE_KB" = 0 ] && echo 无 || echo "${HUGE_KB} kB")，IOMMU $([ $IOMMU = 1 ] && echo 开启 || echo 未开启)"
	[ -n "$BOARD" ] && note "设备树：$BOARD"
	if [ "$MODE" = install ] && [ "$JOBS_AUTO" = 1 ] && [ "$JOBS" -lt "$CPUS" ]; then
		if zram_usable; then
			note "内存较小，编译期间会临时启用 ${MEM_MB} MB 的 zram swap，用满 $CPUS 个 CPU 编译。"
		else
			note "内存较小且没有 zram，编译并行数为 ${JOBS}，VPP 和 DPDK 的编译可能要数小时；建议先开启 swap。"
		fi
	fi
	[ "$PKG" != none ] || [ "$MODE" != install ] || die "没有 apt-get 或 dnf，无法自动安装依赖"
}

# 发行版 vpp.service 开机先于本服务启动时，会占用 /run/vpp/cli.sock 并接管 vfio-pci 网卡。
# 这里只做决定，真正停止在编译之后（mask_distro_vpp），编译期间不打断它。
ask_distro_vpp() {
	MASK_DISTRO=0
	local state
	state=$(systemctl is-enabled "$DISTRO_SERVICE" 2>/dev/null) || true
	case $state in
	''|masked|not-found) return 0 ;;
	esac
	warn "检测到发行版的 ${DISTRO_SERVICE}（${state}$(systemctl is-active --quiet "$DISTRO_SERVICE" && echo '，正在运行')），会与 $SERVICE 争用网卡和 /run/vpp"
	if ask_yn "停止并屏蔽（mask）${DISTRO_SERVICE}？--uninstall 时恢复" y; then
		MASK_DISTRO=1
	elif [ "$state" = enabled ] || systemctl is-active --quiet "$DISTRO_SERVICE"; then
		die "${DISTRO_SERVICE} 已启用或正在运行，不能与 $SERVICE 同时使用；可手动 systemctl disable --now $DISTRO_SERVICE 后重试"
	fi
}

mask_distro_vpp() {
	[ "${MASK_DISTRO:-0}" = 1 ] || return 0
	local state
	state=$(systemctl is-enabled "$DISTRO_SERVICE" 2>/dev/null) || true
	mkdir -p "$STATE"
	# 只记第一次：重复运行时服务已被屏蔽，不能把 masked 记成原状态
	[ -e "$DISTRO_MASKED" ] || echo "${state:-disabled}" >"$DISTRO_MASKED"
	systemctl disable --now "$DISTRO_SERVICE" >/dev/null 2>&1 || true
	if systemctl mask "$DISTRO_SERVICE" >/dev/null 2>&1; then
		info "已停止并屏蔽 $DISTRO_SERVICE"
	else
		# 单元文件本身在 /etc/systemd/system 时无法 mask
		warn "无法屏蔽 ${DISTRO_SERVICE}，已停止并禁用"
	fi
}

unmask_distro_vpp() {
	[ -e "$DISTRO_MASKED" ] || return 0
	local state
	state=$(cat "$DISTRO_MASKED")
	systemctl unmask "$DISTRO_SERVICE" >/dev/null 2>&1 || true
	# 只恢复开机启动，不立即启动：卸载后网卡刚还给内核驱动
	if [ "$state" = enabled ]; then
		systemctl enable "$DISTRO_SERVICE" >/dev/null 2>&1 || warn "无法重新启用 $DISTRO_SERVICE"
	fi
	rm -f "$DISTRO_MASKED"
	info "已解除对 $DISTRO_SERVICE 的屏蔽（原状态 ${state}，未启动）"
}

# ---------- 网卡检测 ----------

IDS_FILE=$DATADIR/dpdk-pci-ids

# 按 DPDK 构建产物中的 PCI ID 表精确查找；没有表时按内核驱动推断
# 输出 PMD 名；不确定的型号后缀 ?
pmd_for() {
	local drv=$1 vd=$2 v d
	if [ -s "$IDS_FILE" ]; then
		v=${vd%%:*} d=${vd##*:}
		awk -v v="$v" -v d="$d" '$1 == v && ($2 == d || $2 == "ffff") {print $3; exit}' "$IDS_FILE"
		return
	fi
	case $drv in
	ixgbe|ixgbevf) echo ixgbe ;;
	i40e) echo i40e ;;
	iavf|i40evf) echo iavf ;;
	ice) echo ice ;;
	igc) echo igc ;;
	igb|igbvf|e1000) echo e1000 ;;
	e1000e) echo 'e1000?' ;;
	idpf) echo idpf ;;
	virtio_net|virtio-pci) echo virtio ;;
	vmxnet3) echo vmxnet3 ;;
	ena) echo ena ;;
	gve) echo gve ;;
	mlx5_core) echo mlx5 ;;
	mlx4_core|mlx4_en) echo mlx4 ;;
	bnxt_en) echo bnxt ;;
	enic) echo enic ;;
	hns3) echo hns3 ;;
	nfp) echo nfp ;;
	cxgb4) echo cxgbe ;;
	txgbe) echo txgbe ;;
	ngbe) echo ngbe ;;
	atlantic) echo atlantic ;;
	ionic) echo ionic ;;
	r8169|r8125|r8126|r8127)
		# DPDK r8169 PMD 只支持 RTL8125/8126/8127 系列，不支持 RTL8111/8168
		case $vd in 10ec:8125|10ec:8126|10ec:8127|10ec:8162|10ec:3000|10ec:5000) echo r8169 ;; esac ;;
	esac
}

sysdrv() { if [ -e "$1/driver" ]; then basename "$(readlink -f "$1/driver")"; else echo none; fi; }

orig_ifname() {
	[ -r "$STATE/nics.orig" ] || return 0
	awk -v p="$1" '$1 == p {print $3; exit}' "$STATE/nics.orig"
}

# 按 platforms/*/vpp-router.conf 匹配非 PCI 网卡，输出平台目录名
match_platform() {
	local ifc=$1 dev=$2 f compat
	compat=$(tr '\0' ' ' <"$dev/of_node/compatible" 2>/dev/null || true)
	[ -n "$compat" ] || return 0
	for f in "$REPO"/platforms/*/vpp-router.conf; do
		[ -r "$f" ] || continue
		if (
			# shellcheck disable=SC1090
			. "$f"
			[ "$ARCH" = "$PLAT_ARCH" ] && [ "$ifc" = "$PLAT_IFNAME" ] &&
				[[ " $BOARD " == *" $PLAT_MACHINE "* ]] && [[ " $compat " == *" $PLAT_DEVICE "* ]]
		); then
			basename "$(dirname "$f")"
			return 0
		fi
	done
	return 0
}

# plat_var 平台 变量名：读取平台描述中的一个标量
plat_var() {
	# shellcheck disable=SC1090
	(. "$REPO/platforms/$1/vpp-router.conf"; printf '%s' "${!2:-}")
}

# RTL8111/8168（10ec:8168）的芯片版本。DPDK r8169 只支持 8168G 及之后的型号，
# 依据 TxConfig 寄存器（BAR2 + 0x40）判断，规则与 DPDK 的 rtl_get_mac_version、
# rtl_set_hw_ops 相同。读不到寄存器时（网卡休眠或内核 lockdown）改用内核日志
# 里 r8169 打印的 XID。输出：ok|no|unknown 型号
rtl_chip() {
	python3 -I - "$1" <<'EOF' || echo "unknown -"
import mmap, os, re, subprocess, sys
pci = sys.argv[1]
base = f'/sys/bus/pci/devices/{pci}'
value = None
try:
    status = 'active'
    if os.path.exists(f'{base}/power/runtime_status'):
        status = open(f'{base}/power/runtime_status').read().strip()
    if status == 'active':
        size = min(os.path.getsize(f'{base}/resource2'), mmap.PAGESIZE)
        fd = os.open(f'{base}/resource2', os.O_RDWR | os.O_SYNC)
        try:
            m = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ)
            view = memoryview(m).cast('I')
            v = view[0x40 // 4]
            view.release()
            m.close()
            if v not in (0, 0xffffffff):
                value = v
        finally:
            os.close(fd)
except (OSError, ValueError):
    pass
if value is None:
    log = ''
    for cmd in (['dmesg'], ['journalctl', '-k', '-b', '--no-pager', '-q']):
        try:
            log = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if log:
            break
    xids = [m.group(1) for line in log.splitlines() if pci in line
            for m in [re.search(r'XID ([0-9a-fA-F]+)', line)] if m]
    if xids:
        # Linux 打印的 XID 是 (TxConfig >> 20) & 0xfcf
        value = (int(xids[-1], 16) & 0xfcf) << 20
if value is None:
    print('unknown -')
    sys.exit()
reg, ic = value & 0x7c800000, (value & 0x00700000) >> 20
supported = {0x4C000000: ('G', {0, 1}), 0x50000000: ('EP', {0, 1, 2}), 0x50800000: ('GU', {0, 1}),
             0x54000000: ('H', {0, 1}), 0x54800000: ('FP', {1, 2, 3, 4}), 0x6C000000: ('M', {0}),
             0x7C800000: ('KB/KD', None)}
unsupported = {0x30000000: 'B', 0x38000000: 'B', 0x3C000000: 'C', 0x3C800000: 'CP', 0x28000000: 'D',
               0x28800000: 'DP', 0x2C000000: 'E', 0x2C800000: 'E-VL', 0x48000000: 'F',
               0x48800000: '8411', 0x5C800000: '8411B'}
if reg in supported:
    name, ics = supported[reg]
    print('ok' if ics is None or ic in ics else 'unknown', f'RTL8168{name}/8111{name}')
elif reg in unsupported:
    name = unsupported[reg]
    print('no', f'RTL{name}' if name.startswith('84') else f'RTL8168{name}/8111{name}')
else:
    print('unknown', f'TxConfig={value:#010x}')
EOF
}

add_nic() {
	# 下标 ifc pci pcidrv drv vd kind pmd rec flags
	local i=$NIC_N
	N_IF[i]=$1 N_PCI[i]=$2 N_PCIDRV[i]=$3 N_DRV[i]=$4 N_VD[i]=$5
	N_KIND[i]=$6 N_PMD[i]=$7 N_REC[i]=$8 N_FLAGS[i]=$9
	N_DESC[i]=- N_MAC[i]=- N_LINK[i]=- N_ADDR[i]= N_MAXQ[i]=0 N_SSH[i]=0 N_DEF[i]=0 N_PLAT[i]=
	NIC_N=$((NIC_N + 1))
}

detect_nics() {
	NIC_N=0
	N_IF=() N_PCI=() N_PCIDRV=() N_DRV=() N_VD=() N_KIND=() N_PMD=() N_REC=() N_FLAGS=()
	N_DESC=() N_MAC=() N_LINK=() N_ADDR=() N_MAXQ=() N_SSH=() N_DEF=() N_PLAT=()

	local ssh_ip ssh_if= def_ifs p ifc dev sub drv pcidrv pci vd pmd kind rec flags master d i plat st chip
	ssh_ip=$(awk '{print $3}' <<<"${SSH_CONNECTION:-}")
	if [ -n "$ssh_ip" ]; then
		ssh_if=$(ip -o addr show | awk -v ip="$ssh_ip" '{split($4, a, "/"); if (a[1] == ip) {print $2; exit}}')
	fi
	def_ifs=" $( { ip -4 route show default; ip -6 route show default; } 2>/dev/null |
		awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' | sort -u | tr '\n' ' ')"

	for p in /sys/class/net/*; do
		ifc=${p##*/}
		[ -e "$p/device" ] || continue
		[ -d "$p/wireless" ] || [ -e "$p/phy80211" ] && continue
		dev=$(readlink -f "$p/device")
		drv=$(sysdrv "$dev")
		sub=$(basename "$(readlink -f "$dev/subsystem")")
		if [ "$sub" = virtio ]; then
			dev=$(dirname "$dev")
			sub=$(basename "$(readlink -f "$dev/subsystem")")
		fi
		flags= pci=- vd=- pcidrv=- plat=
		if [ "$sub" = pci ]; then
			pci=${dev##*/}
			pcidrv=$(sysdrv "$dev")
			vd=$(printf '%04x:%04x' "$(cat "$dev/vendor")" "$(cat "$dev/device")")
			pmd=$(pmd_for "$drv" "$vd")
			if [ "$pmd" = r8169 ] && [ "$vd" = 10ec:8168 ]; then
				read -r st chip <<<"$(rtl_chip "$pci")"
				case $st in
				ok) flags+="[$chip] " ;;
				no) pmd= flags+="[${chip}，DPDK 不支持] " ;;
				*) pmd='r8169?'
					if [ "$chip" = - ]; then flags+="[读不到芯片版本] "; else flags+="[$chip 小版本未知] "; fi ;;
				esac
			fi
		else
			pmd=
			plat=$(match_platform "$ifc" "$dev")
			if [ -n "$plat" ]; then
				pmd=$(plat_var "$plat" PLAT_PMD)
				flags+="[$(plat_var "$plat" PLAT_TITLE)] "
			else
				flags+="[$sub 设备] "
			fi
		fi
		case $pmd in
		mlx4|mlx5) kind=mlx rec=1 ;;
		*\?) kind=dpdk rec=0; [[ $flags == *'[读不到'* || $flags == *小版本未知* ]] || flags+="[部分型号支持] " ;;
		?*) kind=dpdk rec=1 ;;
		*) kind=afp rec=0 ;;
		esac
		[ -n "$plat" ] && kind=plat
		master=
		[ -e "$p/master" ] && master=$(basename "$(readlink -f "$p/master")")
		[ -n "$master" ] && flags+="[属于 $master] "
		add_nic "$ifc" "$pci" "$pcidrv" "$drv" "$vd" "$kind" "${pmd%\?}" "$rec" "$flags"
		i=$((NIC_N - 1))
		N_PLAT[i]=$plat
		if [ -n "$ssh_if" ] && { [ "$ifc" = "$ssh_if" ] || [ "$master" = "$ssh_if" ]; }; then
			N_SSH[i]=1; N_FLAGS[i]+="${R}[当前 SSH]${N} "
		fi
		if [[ $def_ifs == *" $ifc "* || ( -n $master && $def_ifs == *" $master "* ) ]]; then
			N_DEF[i]=1; N_FLAGS[i]+="[默认路由] "
		fi
		N_MAC[i]=$(cat "$p/address" 2>/dev/null || echo -)
		if [ "$(cat "$p/carrier" 2>/dev/null)" = 1 ]; then
			d=$(cat "$p/speed" 2>/dev/null || echo -1)
			if [ "${d:--1}" -gt 0 ] 2>/dev/null; then N_LINK[i]="up/${d}M"; else N_LINK[i]=up; fi
		else
			N_LINK[i]=down
		fi
		N_ADDR[i]=$(ip -o -4 addr show dev "$ifc" 2>/dev/null | awk '{print $4}' | paste -sd, - || true)
		if [ "$pci" != - ] && command -v lspci >/dev/null; then
			N_DESC[i]=$(lspci -s "$pci" 2>/dev/null | sed 's/^[^:]*: //; s/^[^:]*: //' | cut -c1-48 || true)
		fi
		if command -v ethtool >/dev/null; then
			N_MAXQ[i]=$( (ethtool -l "$ifc" 2>/dev/null || true) | awk '/^Pre-set/ {s = 1} s && /^(Combined|RX):/ {if ($2 + 0 > m) m = $2 + 0} /^Current/ {s = 0} END {print m + 0}')
		fi
	done

	# 已经绑定到 DPDK 用户态驱动、没有内核网卡名的设备（例如上次安装留下的）
	for d in /sys/bus/pci/devices/*; do
		[ -e "$d/class" ] || continue
		[[ $(cat "$d/class") == 0x02* ]] || continue
		drv=$(sysdrv "$d")
		case $drv in vfio-pci|uio_pci_generic|igb_uio) ;; *) continue ;; esac
		pci=${d##*/}
		vd=$(printf '%04x:%04x' "$(cat "$d/vendor")" "$(cat "$d/device")")
		pmd=$(pmd_for - "$vd")
		ifc=$(orig_ifname "$pci")
		add_nic "${ifc:--}" "$pci" "$drv" "$drv" "$vd" dpdk "${pmd:-?}" 1 "[已绑定 $drv] "
		i=$((NIC_N - 1))
		if command -v lspci >/dev/null; then
			N_DESC[i]=$(lspci -s "$pci" 2>/dev/null | sed 's/^[^:]*: //; s/^[^:]*: //' | cut -c1-48 || true)
		fi
	done
	[ "$NIC_N" -gt 0 ] || die "没有找到物理网卡"
}

show_nics() {
	local k i pmd
	ORDER=()
	for i in $(seq 0 $((NIC_N - 1))); do [ "${N_REC[i]}" = 1 ] && ORDER+=("$i"); done
	for i in $(seq 0 $((NIC_N - 1))); do [ "${N_REC[i]}" = 1 ] || ORDER+=("$i"); done
	echo
	# 中文表头每个字占两列，printf 按字节补齐会错位，直接写出对齐好的表头
	printf '%s #   接口             PCI           驱动            DPDK       链路       IPv4%s\n' "$B" "$N"
	local label color
	for k in "${!ORDER[@]}"; do
		i=${ORDER[k]}
		case ${N_KIND[i]} in
		mlx) label="${N_PMD[i]}*" color=$G ;;
		plat) label="${N_PMD[i]}#" color=$G ;;
		dpdk) if [ "${N_REC[i]}" = 1 ]; then label=${N_PMD[i]} color=$G; else label="${N_PMD[i]}?" color=$Y; fi ;;
		*) label=- color= ;;
		esac
		# 先按纯文本补齐宽度，再加颜色
		printf ' %-3s %-16s %-13s %-15s %s%-10s%s %-10s %-18s%s\n' "$((k + 1))" "${N_IF[i]}" "${N_PCI[i]}" \
			"${N_DRV[i]}" "$color" "$label" "$N" "${N_LINK[i]}" "${N_ADDR[i]:--}" "${N_FLAGS[i]}"
		if [ "${N_DESC[i]}" != - ]; then printf '     %s%s  %s%s\n' "$C" "${N_VD[i]}" "${N_DESC[i]}" "$N"; fi
	done
	echo
	note "DPDK 列为绿色：DPDK 原生支持，推荐交给 VPP；* 为 Mellanox 分叉驱动，无需解绑内核驱动；"
	note "# 为非 PCI 平台网卡的原生 PMD（platforms/*/vpp-router.conf）。"
	note "RTL8111/8168 只有 8168G 及之后的型号受 DPDK 支持，表中按芯片版本标出。"
	note "黄色 ?：只有部分型号支持，编译后按 DPDK 的 PCI ID 表复核，不支持时改用 AF_PACKET。"
	note "- ：DPDK 不支持，可以用 AF_PACKET 接入 VPP，性能明显低于 DPDK。"
	[ -s "$IDS_FILE" ] && note "支持情况来自已安装的 DPDK PCI ID 表 ${IDS_FILE}。"
	return 0
}

# ---------- 交互配置 ----------

choose_nics() {
	local default= k i reply n bad
	for k in "${!ORDER[@]}"; do
		i=${ORDER[k]}
		[ "${N_REC[i]}" = 1 ] && [ "${N_SSH[i]}" = 0 ] && default+="$((k + 1)) "
	done
	default=${default% }
	while :; do
		ask reply "选择要交给 VPP 的网卡编号（空格或逗号分隔）" "${default:-1}"
		SEL=() bad=
		for n in ${reply//,/ }; do
			if ! [[ $n =~ ^[0-9]+$ ]] || [ "$n" -lt 1 ] || [ "$n" -gt "$NIC_N" ]; then bad=1; break; fi
			i=${ORDER[n - 1]}
			[[ " ${SEL[*]} " == *" $i "* ]] || SEL+=("$i")
		done
		[ -z "$bad" ] && [ ${#SEL[@]} -gt 0 ] && break
		warn "无效的选择：$reply"
	done

	for i in "${SEL[@]}"; do
		if [ "${N_SSH[i]}" = 1 ]; then
			warn "${N_IF[i]} 承载当前 SSH 连接。VPP 接管后这台机器的 Linux 网络会断开，"
			note "直到经 VPP 的 LAN 管理接口 $HOST_TAP 重新连接。请准备好控制台。"
			ask_yn "仍然把 ${N_IF[i]} 交给 VPP？" n || { choose_nics; return; }
		fi
		[ "${N_KIND[i]}" = afp ] && note "${N_IF[i]} 将以 AF_PACKET 方式接入（DPDK 不支持该网卡）。"
		if [ "${N_KIND[i]}" != dpdk ] && [ "${N_IF[i]}" != - ] &&
			grep -qsE "^[[:space:]]*(auto|allow-hotplug)[[:space:]].*\<${N_IF[i]}\>" /etc/network/interfaces /etc/network/interfaces.d/*; then
			warn "${N_IF[i]} 在 /etc/network/interfaces 中开机自动启用，ifupdown 可能与 VPP 争用；请自行改为 manual。"
		fi
		if [ "${N_PCI[i]}" != - ] && [ "${N_KIND[i]}" = dpdk ]; then
			local other
			for other in "${SEL[@]}"; do
				[ "$other" != "$i" ] && [ "${N_PCI[other]}" = "${N_PCI[i]}" ] && die "${N_IF[i]} 和 ${N_IF[other]} 是同一个 PCI 设备"
			done
		fi
	done
	return 0
}

ask_vlan() {
	local v
	while :; do
		ask v "$2" "$3"
		[[ $v =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 4094 ] && break
		warn "VLAN 范围是 1–4094（1 表示不打标签）"
	done
	printf -v "$1" '%s' "$v"
}

configure_roles() {
	local k i default=1 reply trunk_default=n
	grep -qx 'WAN_TRUNK=1' "$CONF/router.env" 2>/dev/null && trunk_default=y
	LAN=() WAN_VLAN=1 LAN_VLAN=1 WAN_TRUNK=0
	if [ ${#SEL[@]} -ge 2 ]; then
		SINGLE=0
		echo
		info "多网卡：选择一个作为 WAN，其余作为 LAN 并桥接在一起"
		for k in "${!SEL[@]}"; do
			i=${SEL[k]}
			printf '  %s) %-16s %-13s %s %s\n' "$((k + 1))" "${N_IF[i]}" "${N_PCI[i]}" "${N_LINK[i]}" "${N_ADDR[i]}"
		done
		# 默认：现在承载默认路由的网卡，其次是第一个有链路的网卡
		default=
		for k in "${!SEL[@]}"; do
			if [ "${N_DEF[${SEL[k]}]}" = 1 ]; then default=$((k + 1)); break; fi
		done
		if [ -z "$default" ]; then
			for k in "${!SEL[@]}"; do
				if [[ ${N_LINK[${SEL[k]}]} == up* ]]; then default=$((k + 1)); break; fi
			done
		fi
		default=${default:-1}
		while :; do
			ask reply "WAN 网卡" "$default"
			[[ $reply =~ ^[0-9]+$ ]] && [ "$reply" -ge 1 ] && [ "$reply" -le ${#SEL[@]} ] && break
		done
		WAN_NIC=${SEL[reply - 1]}
		for i in "${SEL[@]}"; do
			if [ "$i" != "$WAN_NIC" ]; then LAN+=("$i"); fi
		done
		if ask_yn "WAN 网卡同时用 VLAN trunk 承载 LAN？" "$trunk_default"; then
			WAN_TRUNK=1
			while :; do
				ask_vlan WAN_VLAN "WAN VLAN" 100
				ask_vlan LAN_VLAN "该网卡上的 LAN VLAN（1 表示不打标签）" 1
				[ "$WAN_VLAN" != "$LAN_VLAN" ] && break
				warn "WAN 和 LAN 不能使用同一个 VLAN"
			done
		fi
	else
		SINGLE=1
		WAN_NIC=${SEL[0]}
		echo
		info "单网卡：WAN 和 LAN 用 VLAN 区分，交换机端口需要配置成对应的 trunk"
		note "VLAN 1 表示不打标签（untagged）。两者不能相同。"
		while :; do
			ask_vlan WAN_VLAN "WAN VLAN" 100
			ask_vlan LAN_VLAN "LAN VLAN" 1
			[ "$WAN_VLAN" != "$LAN_VLAN" ] && break
			warn "WAN 和 LAN 不能使用同一个 VLAN"
		done
	fi
	return 0
}

# 运营商委派的前缀会变，ULA 不会：局域网内部和 Gate 的回程路由可以一直用它。
# 网段按 RFC 4193 随机生成一次，之后从 router.vpp 读回
ask_lan_ula() {
	local prev
	prev=$(awk '$1 == "set" && $3 == "ip" && $4 == "address" && $5 == "loop0" && tolower($6) ~ /^fd[0-9a-f][0-9a-f]:/ {print $6; exit}' "$CONF/router.vpp" 2>/dev/null || true)
	LAN_ULA=
	if ask_yn "LAN 加一个固定的 IPv6 ULA 网段？（本地地址，不随运营商变化；Gate 的代理和出口用它走 IPv6）" y; then
		if [ -n "$prev" ]; then
			LAN_ULA=$(python3 -I -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$prev")
		else
			LAN_ULA=$(python3 -I -c 'import ipaddress,os; print(ipaddress.ip_network((0xfd << 120 | int.from_bytes(os.urandom(5), "big") << 80, 64)))')
		fi
	fi
}

ask_network() {
	local reply cand existing
	echo
	info "WAN 地址"
	while :; do
		ask reply "1) DHCP  2) 静态地址" 1
		case $reply in 1|2) break ;; esac
	done
	WAN_MODE=dhcp WAN_CIDR= WAN_GW=
	if [ "$reply" = 2 ]; then
		WAN_MODE=static
		while :; do ask WAN_CIDR "WAN 地址/前缀，例如 203.0.113.10/24" ""; ipv4 cidr "$WAN_CIDR" && break; warn "地址无效"; done
		while :; do ask WAN_GW "WAN 网关" ""; ipv4 in "$WAN_CIDR" "$WAN_GW" && break; warn "网关必须在 $WAN_CIDR 网段内"; done
	fi
	note "PPPoE 不在本脚本范围内。IPv6-PD 需要运营商提供前缀及 IPv6 RA 默认路由。"
	if ask_yn "启用 IPv6-PD，并通过 SLAAC 向 LAN 宣告前缀？" n; then IPV6_PD=1; fi
	ask_lan_ula

	echo
	info "LAN 网关"
	# 默认网段避开本机现有的所有 IPv4 网段（包括 WAN 上游）。上次安装的 $HOST_TAP 是本脚本自己的，
	# 重装时会重建，不算占用
	existing=$(ip -o -4 addr show | awk -v tap="$HOST_TAP" '$2 != tap && $4 !~ /^127\./ {print $4}' | tr '\n' ' ')
	[ -n "$WAN_CIDR" ] && existing+=" $WAN_CIDR"
	# 重装时优先沿用上次的 LAN；否则默认 10.61.30.0/24，与本机现有网段重叠时依次换用后面的候选
	local prev
	prev=$(awk '$1 == "set" && $3 == "ip" && $5 == "loop0" {print $6; exit}' "$CONF/router.vpp" 2>/dev/null || true)
	ipv4 cidr "$prev" 2>/dev/null || prev=
	LAN_CIDR=10.61.30.1/24
	for cand in $prev 10.61.30.1/24 10.61.60.1/24 10.64.30.1/24 192.168.88.1/24 10.10.0.1/24 172.20.0.1/24; do
		# shellcheck disable=SC2086
		if [ -z "${existing// }" ] || ! ipv4 overlap "$cand" $existing; then LAN_CIDR=$cand; break; fi
	done
	while :; do
		ask LAN_CIDR "VPP 的 LAN 网关地址/前缀" "$LAN_CIDR"
		ipv4 cidr "$LAN_CIDR" || { warn "地址无效"; continue; }
		if [ -n "$WAN_CIDR" ] && ipv4 overlap "$LAN_CIDR" "$WAN_CIDR"; then warn "LAN 与 WAN 网段重叠"; continue; fi
		break
	done
	LAN_GW=$(ipv4 addr "$LAN_CIDR")

	echo
	info "Linux 管理接口"
	note "VPP 在 LAN 网桥上创建 TAP，Linux 侧名为 ${HOST_TAP}，用于管理本机和运行 DHCP/DNS。"
	local need_tap=0 i
	for i in "${SEL[@]}"; do [ "${N_SSH[i]}" = 1 ] && need_tap=1; done
	[ "$SINGLE" = 1 ] && need_tap=1
	HOST_CIDR= HOST_DEFAULT=0 DNSMASQ=0 IMPORT_DNSMASQ=0 DNS_LISTEN=
	if ask_yn "创建 ${HOST_TAP}？$([ $need_tap = 1 ] && echo '（单网卡或 SSH 网卡交给 VPP 时强烈建议）')" y; then
		HOST_CIDR=$(ipv4 peer "$LAN_CIDR")
		while :; do
			ask HOST_CIDR "$HOST_TAP 的地址/前缀" "$HOST_CIDR"
			ipv4 cidr "$HOST_CIDR" && ipv4 in "$LAN_CIDR" "$(ipv4 addr "$HOST_CIDR")" && break
			warn "必须是 $LAN_CIDR 网段内的另一个地址"
		done
		# Linux 还有不经过 VPP 网卡的默认路由（例如 Wi-Fi，它不在网卡列表里）时默认保留
		local keep_default=0 def=n dev gone=" "
		for i in "${SEL[@]}"; do
			[ "${N_IF[i]}" != - ] || continue
			gone+="${N_IF[i]} "
			[ -e "/sys/class/net/${N_IF[i]}/master" ] && gone+="$(basename "$(readlink -f "/sys/class/net/${N_IF[i]}/master")") "
		done
		for dev in $(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}'); do
			[[ $gone == *" $dev "* ]] || keep_default=1
		done
		[ $keep_default = 0 ] && def=y
		ask_yn "Linux 的默认路由改走 VPP（经 $HOST_TAP 到 ${LAN_GW}）？" $def && HOST_DEFAULT=1
		DNS_LISTEN=$(ipv4 addr "$HOST_CIDR")
		if ask_yn "用 dnsmasq 在 $HOST_TAP 上为 LAN 提供 DHCP 和 DNS？" y && ask_system_dnsmasq; then
			DNSMASQ=1
			ask_dhcp_range
		fi
	elif system_dnsmasq; then
		warn "系统 dnsmasq 在运行，但没有 ${HOST_TAP}，无法让它服务 LAN；它原来绑定的网卡交给 VPP 后会失效。"
	fi
	return 0
}

# 系统的 dnsmasq.service 已启用或正在运行
system_dnsmasq() {
	command -v dnsmasq >/dev/null || return 1
	systemctl is-active --quiet dnsmasq.service 2>/dev/null || systemctl is-enabled --quiet dnsmasq.service 2>/dev/null
}

# dnsmasq-lan.py scan/import 的公共参数
scan_args() {
	local a
	SCAN_ARGS=(--lan "$LAN_CIDR" --conf "$CONF/dnsmasq.conf")
	# 默认从运行中的 dnsmasq 进程读取配置文件；不常见的部署可以手工指定
	[ -n "${DNSMASQ_CONF:-}" ] && SCAN_ARGS+=(--system-conf "$DNSMASQ_CONF")
	for a in ${DNSMASQ_CONF_DIR:-}; do SCAN_ARGS+=(--system-conf-dir "$a"); done
	return 0
}

# 地址池的默认值：已有的 $CONF/dnsmasq.conf，其次是导入的系统配置，再次按 LAN 网段计算
ask_dhcp_range() {
	local start= end= mask= lease= cur
	cur=$(python3 -I "$LANTOOL" range --conf "$CONF/dnsmasq.conf" 2>/dev/null) || cur=
	[ -n "$cur" ] || cur=$IMPORT_RANGE
	read -r start end mask lease <<<"$cur"
	if [ -n "$start" ] && ! { ipv4 in "$LAN_CIDR" "$start" && ipv4 in "$LAN_CIDR" "$end"; }; then start= end=; fi
	DHCP_LEASE=${lease:-12h}
	read -r DHCP_START DHCP_END DHCP_MASK <<<"$(ipv4 range "$LAN_CIDR" "$DNS_LISTEN")"
	ask DHCP_START "DHCP 起始地址" "${start:-$DHCP_START}"
	ask DHCP_END "DHCP 结束地址" "${end:-$DHCP_END}"
	ipv4 in "$LAN_CIDR" "$DHCP_START" && ipv4 in "$LAN_CIDR" "$DHCP_END" || die "DHCP 地址池不在 $LAN_CIDR 内"
}

# LAN 只运行一个 dnsmasq（$DNS_SERVICE）。系统的 dnsmasq.service 会和它争用 53、67 端口，所以导入它能沿用的
# 配置后停用并屏蔽它；不同意时 LAN 上不运行 dnsmasq。返回 1 表示不运行
ask_system_dnsmasq() {
	IMPORT_DNSMASQ=0 IMPORT_RANGE=
	system_dnsmasq || [ -e "$STATE/dnsmasq-orig/manifest.json" ] || return 0
	local report
	echo
	info "系统 dnsmasq"
	note "dnsmasq.service 已启用，它和 LAN 的 dnsmasq 会争用 53、67 端口，不能同时运行。"
	note "可以把它能沿用的配置导入 $CONF/dnsmasq.conf：静态分配、地址池、自定义选项和 LAN 网段内的租约，"
	note "然后停用并屏蔽它（--restore、--uninstall 时恢复原来的状态）。"
	scan_args
	report=$(python3 -I "$LANTOOL" scan "${SCAN_ARGS[@]}") || die "无法读取系统 dnsmasq 的配置"
	if [ -n "$report" ]; then printf '%s\n' "$report" | sed 's/^/    /'; else note "没有可以导入的配置。"; fi
	if ! ask_yn "导入这些配置，并停用系统 dnsmasq？" y; then
		warn "保留系统 dnsmasq。LAN 上不运行 dnsmasq，没有 DHCP。"
		return 1
	fi
	IMPORT_DNSMASQ=1
	IMPORT_RANGE=$(python3 -I "$LANTOOL" scan --range-only "${SCAN_ARGS[@]}") || IMPORT_RANGE=
	return 0
}

ask_cpu() {
	local def max
	echo
	info "CPU"
	if [ "$CPUS" -le 1 ]; then
		WORKERS=0 MAIN_CORE=0
		warn "只有 1 个 CPU，VPP 主线程会占满它"
		return
	fi
	MAIN_CORE=1
	max=$((CPUS - 2))
	if [ -n "${PLAT:-}" ] && [ -n "${PLAT_MAX_WORKERS:-}" ] && [ "$PLAT_MAX_WORKERS" -lt "$max" ]; then
		max=$PLAT_MAX_WORKERS
		if [ "$max" = 0 ]; then
			WORKERS=0
			note "$PLAT_TITLE 只能单线程运行，主线程固定在 CPU ${MAIN_CORE}，不开 worker。"
			return 0
		fi
	fi
	if [ "$CPUS" -le 2 ]; then def=0; elif [ "$CPUS" -le 4 ]; then def=$max; else def=$((max < 4 ? max : 4)); fi
	note "主线程固定在 CPU ${MAIN_CORE}，worker 依次使用 CPU 2 起。轮询模式下每个线程占满一个 CPU。"
	while :; do
		ask WORKERS "worker 线程数（0–${max}，0 表示只用主线程）" "$def"
		[[ $WORKERS =~ ^[0-9]+$ ]] && [ "$WORKERS" -le "$max" ] && break
	done
}

# 收包方式。轮询时 VPP 线程不停查询网卡；中断（VPP 的 adaptive 模式）时包间隔大就休眠，由网卡中断唤醒，
# 流量大时自动转为轮询。RX_MODE 的值仍叫 interrupt，与已有的 router.env 兼容
# 不分架构：aarch64 上的 RTL8125 和支持中断的平台 PMD 也可以选择。
ask_rx_mode() {
	RX_MODE=polling
	has_kind dpdk mlx afp || { has_kind plat && [ "${PLAT_RX_INTERRUPTS:-0}" = 1 ]; } || return 0
	local reply
	echo
	info "DPDK 收包方式"
	note "轮询（默认）：VPP 的每个线程不停查询网卡，所在 CPU 始终占满 100%，并一直以最高频率全速运行；"
	note "              延迟最低、吞吐最高，没有流量时功耗也不会下降。"
	note "中断：流量小时线程休眠，由网卡中断唤醒，CPU 可以降频和进入空闲状态；流量大时自动转为轮询"
	note "      （VPP 的 adaptive 模式）。功耗和温度明显更低，代价是休眠后第一个包的延迟略高。"
	note "      希望降低功耗请选择中断。"
	while :; do
		ask reply "1) 轮询  2) 中断" 1
		case $reply in 1|2) break ;; esac
	done
	[ "$reply" = 2 ] || return 0
	RX_MODE=interrupt
	note "不支持收包中断的网卡在启动后会自动保持轮询，并记录到 journalctl -u ${SERVICE}。"
	# 收包中断需要 MSI-X，uio_pci_generic 只有 INTx
	if has_kind dpdk && [ "$UIO" = uio_pci_generic ]; then
		if modinfo vfio-pci >/dev/null 2>&1; then
			UIO=vfio-pci
			[ "$IOMMU" = 1 ] && NOIOMMU=0 || NOIOMMU=1
			note "uio_pci_generic 不支持收包中断，改用 vfio-pci$([ "$NOIOMMU" = 1 ] && echo '（无 IOMMU 模式）')。"
		else
			warn "uio_pci_generic 不支持收包中断，且没有 vfio-pci 模块，DPDK 网卡只能轮询"
		fi
	fi
	return 0
}

# Gate 已经装过：有它的配置和单元。此时只要装上管理它的 gate-admin
gate_present() { [ -e "$GATE_CONFIG" ] && [ -e "$UNIT_DIR/$GATE_UNIT" ]; }

# 这次装面板：完整安装总是装，--config-only 时只在以前装过时更新它的服务
panel_wanted() { [ "$MODE" = install ] || manifest_has "$PREFIX/bin/vpp-monitor"; }

# 要编译的 Go 程序
panel_tools() {
	printf '%s\n' "${PANEL_TOOLS[@]}"
	if gate_present || [ "$WANT_GATE" = 1 ]; then echo gate-admin; fi
	if [ "$WANT_GATE" = 1 ]; then echo vpp-egress-gate; fi
	# 面板“代理”页的执行程序，和 sing-box 一起装
	if [ "$WANT_SINGBOX" = 1 ]; then echo vpp-proxy; fi
	return 0
}

# 面板只监听 Linux 管理口的地址，局域网从这里访问；没有管理口时只能 SSH 转发
panel_listen() {
	if [ -n "$HOST_CIDR" ]; then ipv4 addr "$HOST_CIDR"; else echo 127.0.0.1; fi
}

port_label() {
	case $1 in
	PANEL_PORT) echo 面板 ;;
	GATE_DNS_PORT) echo 'Gate 的 DNS' ;;
	SOCKS_PORT) echo 'sing-box SOCKS5' ;;
	TPROXY_PORT) echo 'sing-box TPROXY' ;;
	FAKEDNS_PORT) echo 'sing-box Fake-IP DNS' ;;
	esac
}

# 1 到 65535，不能是客户端的 DNS 53 和 DHCP 67
valid_port() {
	[[ $1 =~ ^[0-9]{1,5}$ ]] || return 1
	local n=$((10#$1))
	[ "$n" -ge 1 ] && [ "$n" -le 65535 ] && [ "$n" != 53 ] && [ "$n" != 67 ]
}

# 已经给了别的服务的端口，打印那个变量名
port_owner() {
	local other
	for other in "${PORT_VARS[@]}"; do
		if [ "$other" != "$1" ] && [ "${!other}" = "$2" ]; then echo "$other"; return 0; fi
	done
	return 1
}

load_ports() {
	local name value env
	if [ -r "$STATE/ports" ]; then
		while IFS='=' read -r name value; do
			if [[ " ${PORT_VARS[*]} " == *" $name "* ]] && valid_port "$value"; then
				printf -v "$name" '%s' "$((10#$value))"
			fi
		done <"$STATE/ports"
	fi
	for name in "${PORT_VARS[@]}"; do
		env=VPP_$name
		[ -n "${!env:-}" ] || continue
		valid_port "${!env}" || die "$env=${!env} 不是可用的端口：要 1 到 65535，不能是 53 或 67"
		printf -v "$name" '%s' "$((10#${!env}))"
	done
	for name in "${PORT_VARS[@]}"; do
		if value=$(port_owner "$name" "${!name}"); then
			die "$(port_label "$name")和$(port_label "$value")都用了端口 ${!name}"
		fi
	done
	return 0
}

save_ports() {
	local name
	for name in "${PORT_VARS[@]}"; do printf '%s=%s\n' "$name" "${!name}"; done >"$STATE/ports"
}

# 只列出这次会用上的端口：Gate 已经有配置时，它的 DNS、TPROXY 和 Fake-IP DNS 以配置为准
ask_ports() {
	local names=() name value owner
	panel_wanted && names+=(PANEL_PORT)
	if [ "$WANT_GATE" = 1 ] && [ ! -e "$GATE_CONFIG" ]; then names+=(GATE_DNS_PORT); fi
	if [ "$WANT_SINGBOX" = 1 ]; then
		names+=(SOCKS_PORT)
		[ -e "$GATE_CONFIG" ] || names+=(TPROXY_PORT FAKEDNS_PORT)
	fi
	[ ${#names[@]} -gt 0 ] || return 0
	echo
	info "端口"
	for name in "${names[@]}"; do note "$(port_label "$name")：${!name}"; done
	[ -e "$GATE_CONFIG" ] && note "Gate 的 DNS、TPROXY 和 Fake-IP DNS 端口以 $GATE_CONFIG 为准，要改时改那里。"
	ask_yn "修改这些端口？" n || return 0
	for name in "${names[@]}"; do
		while :; do
			ask value "$(port_label "$name")的端口" "${!name}"
			if ! valid_port "$value"; then warn "要 1 到 65535 之间的数字，不能是 53 或 67"; continue; fi
			value=$((10#$value))
			if owner=$(port_owner "$name" "$value"); then warn "端口 $value 已经给了$(port_label "$owner")"; continue; fi
			printf -v "$name" '%s' "$value"
			break
		done
	done
	return 0
}

ask_panel() {
	panel_wanted || return 0
	echo
	info "管理面板"
	note "面板 vpp-monitor 显示流量，修改接口、WireGuard 和路由规则，地址 https://$(panel_listen):$PANEL_PORT/"
	[ -n "$HOST_CIDR" ] || note "没有 Linux 管理口，面板只监听 127.0.0.1，要用 ssh -L $PANEL_PORT:127.0.0.1:$PANEL_PORT 访问。"
	if [ "$MODE" = install ] && ! gate_present; then
		note "Gate 按域名把流量分到不同出口，路由页面用它。它会接管局域网 DNS，安装时要回答出口和局域网的问题。"
		if ask_yn "同时安装 Gate？（VPP 启动后进行）" n; then WANT_GATE=1; fi
	fi
	if [ -s "$PANEL_STATE/auth.json" ]; then
		note "面板密码已经设置过，保留不变。"
		return 0
	fi
	local again
	while :; do
		read -r -s -p "面板用户 admin 的密码（至少 8 位）: " PANEL_PW </dev/tty || PANEL_PW=
		echo
		if [ ${#PANEL_PW} -lt 8 ]; then warn "至少 8 位"; continue; fi
		read -r -s -p "再输入一次: " again </dev/tty || again=
		echo
		[ "$PANEL_PW" = "$again" ] && break
		warn "两次输入不同"
	done
	return 0
}

# VPP 里的 WAN 接口名，与 assign_names、gen_router_vpp 的规则相同（此时 V_NAME 可能还没分配）
ipsec_wan_name() {
	local base
	if [ "${N_KIND[WAN_NIC]}" = afp ]; then base=host-${N_IF[WAN_NIC]}
	elif [ "$SINGLE" = 1 ]; then base=port0
	else base=wan0; fi
	if { [ "$SINGLE" = 1 ] || [ "${WAN_TRUNK:-0}" = 1 ]; } && [ "$WAN_VLAN" != 1 ]; then echo "$base.$WAN_VLAN"; else echo "$base"; fi
}

# IPsec 服务器（VPP 侧）。strongSwan 的 charon 在命名空间 $IPSEC_NS 里协商 IKE，用 kernel-vpp 后端
# 把 SA 和策略下发给 VPP；VPP 把 IKE 报文转进命名空间，ESP 自己加解密
ask_ipsec() {
	local def=n wan
	IPSEC=0
	[ -r "$CONF/router.env" ] && grep -qx 'IPSEC=1' "$CONF/router.env" && def=y
	echo
	info "IPsec 服务器"
	note "用 strongSwan + VPP 做 IPsec VPN 服务器时选是：启用 ipsec_ike_punt 插件，建命名空间 $IPSEC_NS 和通往它的 TAP，"
	note "把 WAN 上 UDP 500/4500 的 IKE 报文转给命名空间里的 charon，ESP 留在 VPP 加解密。"
	note "strongSwan 及其 kernel-vpp 后端不由本脚本安装，见 deploy/install/README.md。"
	ask_yn "用作 IPsec 服务器？" "$def" || return 0
	wan=$(ipsec_wan_name)
	# kernel-vpp 按 Linux 接口名找 VPP 接口，所以命名空间里的接口与 VPP 的 WAN 同名，受 Linux 15 字符限制
	if [ ${#wan} -gt 15 ]; then
		warn "WAN 接口名 $wan 超过 15 个字符，Linux 里不能有同名接口，不启用 IPsec 服务器"
		return 0
	fi
	IPSEC=1
	return 0
}

# sing-box 是局域网的代理入口，和 RK3588 开发板一样：给 Gate 的 Fake-IP DNS 和 TPROXY、真实地址的 TPROXY、
# 局域网的 SOCKS5。上游是 $SINGBOX_DIR/upstream.json 里标签为 proxy 的出站或 endpoint，任何类型都行；
# 已经装过时保留上游，只重新生成入口
ask_singbox() {
	if [ -e "$SINGBOX_DIR/entry.json" ]; then
		WANT_SINGBOX=1
		note "sing-box 已经装过，上游 $SINGBOX_DIR/upstream.json 保留不变，入口按这次的配置重新生成。"
		return 0
	fi
	[ "$MODE" = install ] || return 0
	echo
	info "代理入口 sing-box"
	note "和 RK3588 开发板一样，sing-box 向局域网提供代理入口：SOCKS5 $(panel_listen):$SOCKS_PORT（不认证），以及给 Gate 代理规则用的"
	note "TPROXY $TPROXY_PORT 和 Fake-IP DNS $FAKEDNS_PORT：真实地址和 Fake-IP 地址都进 TPROXY。流量经上游出去，上游可以是 sing-box 支持的任何协议。"
	ask_yn "安装 sing-box？" n || return 0
	WANT_SINGBOX=1
	local reply text port host again
	note "上游写在 $SINGBOX_DIR/upstream.json，以后可以换成任何 sing-box 出站或 endpoint（标签为 proxy）。"
	while :; do
		ask reply "上游：1) SOCKS5  2) Trojan  3) 导入 sing-box 出站/endpoint 的 JSON 文件（任意类型，包括 WireGuard）  4) 稍后配置" 4
		case $reply in 1|2|3|4) break ;; esac
	done
	case $reply in
	4) SB_TYPE=none; return 0 ;;
	3)
		SB_TYPE=file
		while :; do
			ask SB_FILE "JSON 文件路径" ""
			SB_FILE=$(readlink -f -- "$SB_FILE" 2>/dev/null || true)
			[ -n "$SB_FILE" ] && [ -f "$SB_FILE" ] && python3 -I "$SINGBOX_GEN" check-file "$SB_FILE" && break
			warn "要一个存在的 JSON 文件：一个出站或 endpoint 对象，或者它们的列表，或带 outbounds/endpoints 的片段"
		done
		return 0 ;;
	1) SB_TYPE=socks ;;
	2) SB_TYPE=trojan ;;
	esac
	while :; do
		ask text "服务器，地址:端口（IPv6 写成 [地址]:端口）" ""
		port=${text##*:} host=${text%:*}
		host=${host#[} host=${host%]}
		if [ -n "$host" ] && [ "$host" != "$text" ] && [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && [[ $host != *[[:space:]]* ]]; then
			break
		fi
		warn "写成 1.2.3.4:1080、proxy.example.com:443 或 [2001:db8::1]:1080"
	done
	SB_SERVER=$host SB_PORT=$port
	if [ "$SB_TYPE" = socks ]; then
		ask SB_USER "用户名（没有认证直接回车）" ""
		[ -n "$SB_USER" ] || return 0
	else
		ask SB_SNI "TLS 服务器名（SNI）" "$SB_SERVER"
	fi
	while :; do
		read -r -s -p "密码: " SB_PASS </dev/tty || SB_PASS=
		echo
		[ -n "$SB_PASS" ] || { warn "密码不能为空"; continue; }
		read -r -s -p "再输入一次: " again </dev/tty || again=
		echo
		[ "$SB_PASS" = "$again" ] && break
		warn "两次输入不同"
	done
	return 0
}

choose_uio() {
	UIO=${UIO_DRIVER:-}
	NOIOMMU=0
	if [ -z "$UIO" ]; then
		if [ "$IOMMU" = 1 ]; then UIO=vfio-pci
		elif [ "${RTL_PLATFORM:-0}" = 1 ] && modinfo uio_pci_generic >/dev/null 2>&1; then UIO=uio_pci_generic
		elif modinfo vfio-pci >/dev/null 2>&1; then UIO=vfio-pci
		elif modinfo uio_pci_generic >/dev/null 2>&1; then UIO=uio_pci_generic
		else UIO=vfio-pci; fi
	fi
	[ "$UIO" = vfio-pci ] && [ "$IOMMU" = 0 ] && NOIOMMU=1
	return 0
}

ask_platform() {
	local i need_mlx=0 rtl=0 def=n
	NEED_MLX=0 RTL_PLATFORM=0 PLAT= PLAT_NIC= PLAT_RX_INTERRUPTS=0
	for i in "${SEL[@]}"; do
		[ "${N_KIND[i]}" = mlx ] && need_mlx=1
		[ "${N_PMD[i]}" = r8169 ] && rtl=1
		if [ "${N_KIND[i]}" = plat ]; then
			[ -z "$PLAT_NIC" ] || die "只支持一块平台网卡（${N_IF[PLAT_NIC]} 和 ${N_IF[i]}）"
			PLAT_NIC=$i PLAT=${N_PLAT[i]}
		fi
	done
	NEED_MLX=$need_mlx
	if [ -n "$PLAT" ]; then
		# shellcheck disable=SC1090
		. "$REPO/platforms/$PLAT/vpp-router.conf"
		echo
		info "平台网卡：${PLAT_TITLE}（platforms/${PLAT}）"
		note "${N_IF[PLAT_NIC]} 由 $PLAT_KMOD.ko 和 $PLAT_VDEV 接管，详见 platforms/$PLAT/README.md。"
	fi
	if [ "$ARCH" = aarch64 ] && [ $rtl = 1 ]; then
		[[ $BOARD == *rk3588* ]] && def=y
		echo
		info "Realtek DMA 非一致性补丁"
		note "platforms/rtl8125-noncoherent 用于 DMA 非一致性的 ARM64 平台（例如 RK3588）。"
		note "补丁改的是整个 r8169 PMD，但只在 RTL8125B 上验证过。"
		ask_yn "这台设备是 DMA 非一致性平台，需要应用该补丁？" $def && RTL_PLATFORM=1
	fi
	choose_uio
}

# has_kind 接入方式...：所选网卡中是否有这些方式
# ---------- mlx4（ConnectX-3）----------
# mlx4 PMD 启动端口时用 ibv_create_flow 装 MAC、广播、混杂等收包规则，要求 mlx4_core
# 工作在设备管理的流表模式（log_num_mgm_entry_size=-1）；默认的 -10 下内核返回 EOPNOTSUPP，
# 端口启动失败。参数只在加载模块时生效，所以写入 modprobe.d 后要重新加载驱动或重启。
MLX4_CONF=/etc/modprobe.d/vpp-router-mlx4.conf
MLX4_OPT='options mlx4_core log_num_mgm_entry_size=-1'
# 本脚本写的文件第一行；同名但没有这一行的文件是别人写的，不收进清单、不删除
MLX4_MARK='# vpp-router：mlx4 PMD 需要设备管理的流表'

mlx4_selected() {
	local i
	for i in "${SEL[@]}"; do [ "${N_PCIDRV[i]}" = mlx4_core ] && return 0; done
	return 1
}

mlx4_current() { cat /sys/module/mlx4_core/parameters/log_num_mgm_entry_size 2>/dev/null || echo -; }

# modprobe 配置里 log_num_mgm_entry_size 的最终值（同一参数多次出现时以最后一次为准），没有时为空
mlx4_configured() {
	modprobe -c 2>/dev/null | awk '$1 == "options" && $2 == "mlx4_core" {
		for (i = 3; i <= NF; i++) if ($i ~ /^log_num_mgm_entry_size=/) { sub(/^[^=]*=/, "", $i); v = $i } }
		END { print v }'
}

# 询问放在编译之前；结果在 setup_mlx4 中执行
ask_mlx4() {
	MLX4_RELOAD=0 MLX4_REBOOT=0
	mlx4_selected || return 0
	local cur cfg i other=
	cur=$(mlx4_current) cfg=$(mlx4_configured)
	if [ -n "$cfg" ] && [ "$cfg" != -1 ]; then
		other=$(grep -lE '^[[:space:]]*options[[:space:]]+mlx4_core[[:space:]].*log_num_mgm_entry_size=' \
			/etc/modprobe.d/*.conf /run/modprobe.d/*.conf /usr/lib/modprobe.d/*.conf /lib/modprobe.d/*.conf 2>/dev/null |
			grep -vxF "$MLX4_CONF" | paste -sd' ' - || true)
		die "modprobe 配置把 mlx4_core 的 log_num_mgm_entry_size 设为 ${cfg}（${other:-来源未知}），mlx4 PMD 需要 -1；请先改掉"
	fi
	[ "$cur" = -1 ] && return 0
	# 没有 initstate 说明 mlx4_core 编进了内核，modprobe.d 不起作用
	if [ -e /sys/module/mlx4_core ] && [ ! -e /sys/module/mlx4_core/initstate ]; then
		die "mlx4_core 编进了内核，请在内核命令行加 mlx4_core.log_num_mgm_entry_size=-1 并重启后再安装"
	fi
	echo
	info "mlx4（ConnectX-3）"
	note "mlx4_core 当前 log_num_mgm_entry_size=${cur}，mlx4 PMD 需要 -1，否则端口启动时流规则被拒（EOPNOTSUPP）。"
	note "将写入 $MLX4_CONF；参数在重新加载 mlx4 驱动后生效，会断开本机所有 mlx4 网口片刻。"
	for i in $(seq 0 $((NIC_N - 1))); do
		if [ "${N_PCIDRV[i]}" = mlx4_core ] && [ "${N_SSH[i]}" = 1 ]; then
			warn "当前 SSH 经过 mlx4 网口 ${N_IF[i]}，不能现在重新加载驱动；安装完成后需要重启"
			MLX4_REBOOT=1
			return 0
		fi
	done
	if ask_yn "安装时重新加载 mlx4 驱动？（否则安装后需要重启）" y; then MLX4_RELOAD=1; else MLX4_REBOOT=1; fi
}

# 内核模块在 initramfs 里时，modprobe.d 也要进 initramfs，否则开机时仍按旧参数加载
mlx4_initramfs() {
	local kver img
	kver=$(uname -r)
	if command -v update-initramfs >/dev/null && command -v lsinitramfs >/dev/null; then
		img=/boot/initrd.img-$kver
		# 不用 grep -q：pipefail 下提前退出会让 lsinitramfs 收到 SIGPIPE
		[ -e "$img" ] && [ "$(lsinitramfs "$img" 2>/dev/null | grep -c '/mlx4_core\.ko')" -gt 0 ] || return 0
		note "mlx4_core 在 initramfs 中，重建 $img"
		update-initramfs -u -k "$kver" >/dev/null || warn "update-initramfs 失败，开机时 mlx4_core 可能仍用旧参数"
	elif command -v dracut >/dev/null && command -v lsinitrd >/dev/null; then
		[ "$(lsinitrd 2>/dev/null | grep -c '/mlx4_core\.ko')" -gt 0 ] || return 0
		note "mlx4_core 在 initramfs 中，用 dracut 重建"
		dracut -f >/dev/null 2>&1 || warn "dracut 失败，开机时 mlx4_core 可能仍用旧参数"
	fi
	return 0
}

setup_mlx4() {
	mlx4_selected || return 0
	local cfg i t
	cfg=$(mlx4_configured)
	if [ "$cfg" != -1 ]; then
		if [ -e "$MLX4_CONF" ] && [ "$(head -n 1 "$MLX4_CONF")" != "$MLX4_MARK" ]; then
			die "$MLX4_CONF 已存在且不是本脚本写的"
		fi
		printf '%s\n%s\n' "$MLX4_MARK" "$MLX4_OPT" >"$MLX4_CONF"
		manifest_add "$MLX4_CONF"
		note "$MLX4_CONF"
		mlx4_initramfs
	elif [ -e "$MLX4_CONF" ] && [ "$(head -n 1 "$MLX4_CONF")" = "$MLX4_MARK" ]; then
		# 重新安装时 install_vpp 会重写清单，这里补回
		manifest_add "$MLX4_CONF"
	fi
	[ "$(mlx4_current)" = -1 ] && return 0
	[ "${MLX4_RELOAD:-0}" = 1 ] || { MLX4_REBOOT=1; return 0; }
	info "重新加载 mlx4 驱动"
	if ! modprobe -r mlx4_ib mlx4_en mlx4_core 2>/dev/null; then
		warn "无法卸载 mlx4 驱动（可能被 RDMA 或其他模块占用），需要重启后生效"
		modprobe mlx4_core 2>/dev/null || true
		modprobe mlx4_en 2>/dev/null || true
		modprobe mlx4_ib 2>/dev/null || true
		MLX4_REBOOT=1
		return 0
	fi
	modprobe mlx4_core && modprobe mlx4_en && modprobe mlx4_ib || die "重新加载 mlx4 驱动失败"
	modprobe ib_uverbs 2>/dev/null || true
	command -v udevadm >/dev/null && udevadm settle --timeout=30 2>/dev/null || true
	[ "$(mlx4_current)" = -1 ] || die "重新加载后 log_num_mgm_entry_size 仍为 $(mlx4_current)"
	# 网卡名要和配置一致；等 udev 改名完成
	for i in "${SEL[@]}"; do
		[ "${N_PCIDRV[i]}" = mlx4_core ] || continue
		for t in $(seq 1 30); do
			[ -e "/sys/bus/pci/devices/${N_PCI[i]}/net/${N_IF[i]}" ] && break
			sleep 1
		done
		[ -e "/sys/bus/pci/devices/${N_PCI[i]}/net/${N_IF[i]}" ] ||
			die "重新加载后 ${N_PCI[i]} 上没有网卡 ${N_IF[i]}（现在是 $(ls "/sys/bus/pci/devices/${N_PCI[i]}/net" 2>/dev/null | paste -sd' ' -)）"
	done
	MLX4_REBOOT=0
	return 0
}

has_kind() {
	local i k
	for i in "${SEL[@]}"; do
		for k in "$@"; do [ "${N_KIND[i]}" = "$k" ] && return 0; done
	done
	return 1
}

# VFIO 要求同组中非桥设备全部交给 VFIO 或解绑；不能自动解绑其他设备。
check_vfio_groups() {
	[ "$UIO" = vfio-pci ] || return 0
	local i j d pci class drv selected busy
	for i in "${SEL[@]}"; do
		[ "${N_KIND[i]}" = dpdk ] || continue
		[ -d "/sys/bus/pci/devices/${N_PCI[i]}/iommu_group/devices" ] || continue
		busy=
		for d in /sys/bus/pci/devices/"${N_PCI[i]}"/iommu_group/devices/*; do
			[ -e "$d" ] || continue
			pci=${d##*/}
			class=$(cat "$d/class")
			[[ $class == 0x06* ]] && continue
			drv=$(sysdrv "$d")
			case $drv in none|vfio-pci) continue ;; esac
			selected=0
			for j in "${SEL[@]}"; do
				[ "${N_KIND[j]}" = dpdk ] && [ "${N_PCI[j]}" = "$pci" ] && selected=1
			done
			[ "$selected" = 1 ] || busy+="$pci ($drv) "
		done
		[ -n "$busy" ] || continue
		warn "${N_PCI[i]} 的 IOMMU 组包含其他正在使用的设备：$busy"
		if [ "${N_IF[i]}" != - ] && ask_yn "改用 AF_PACKET 接入 ${N_IF[i]}（保留内核驱动）？" y; then
			N_KIND[i]=afp
		else
			die "VFIO 无法安全接管该 IOMMU 组；请使用独立 IOMMU 组或选择其他网卡"
		fi
	done
}

summary() {
	local i
	echo
	info "确认配置"
	if [ "$SINGLE" = 1 ]; then
		note "网卡     ${N_IF[WAN_NIC]} (${N_PCI[WAN_NIC]})，单臂"
		note "WAN      VLAN $WAN_VLAN$([ "$WAN_VLAN" = 1 ] && echo '（不打标签）')"
		note "LAN      VLAN $LAN_VLAN$([ "$LAN_VLAN" = 1 ] && echo '（不打标签）')"
	else
		note "WAN      ${N_IF[WAN_NIC]} (${N_PCI[WAN_NIC]})"
		for i in "${LAN[@]}"; do note "LAN      ${N_IF[i]} (${N_PCI[i]})"; done
	fi
	note "WAN 地址 $([ "$WAN_MODE" = dhcp ] && echo DHCP || echo "$WAN_CIDR 网关 $WAN_GW")，NAT44-EI"
	note "LAN 网关 $LAN_CIDR"
	[ "$IPV6_PD" = 1 ] && note "IPv6     WAN DHCPv6-PD，LAN RA/SLAAC"
	[ -n "$LAN_ULA" ] && note "IPv6     LAN 固定 ULA $LAN_ULA（RA/SLAAC）"
	if [ -n "$HOST_CIDR" ]; then
		note "Linux    $HOST_TAP $HOST_CIDR$([ "$HOST_DEFAULT" = 1 ] && echo "，默认路由经 $LAN_GW")"
		[ "$DNSMASQ" = 1 ] && note "DHCP     $DHCP_START – ${DHCP_END}，租期 ${DHCP_LEASE}（dnsmasq，监听 ${DNS_LISTEN}）"
		[ "$IMPORT_DNSMASQ" = 1 ] && note "dnsmasq  导入系统 dnsmasq 的配置，然后停用并屏蔽它"
	fi
	note "CPU      主线程 ${MAIN_CORE}，worker $WORKERS 个"
	if [ "${RX_MODE:-polling}" = interrupt ]; then
		note "收包     中断（adaptive：流量小时线程休眠，流量大时轮询）"
	else
		note "收包     轮询（每个 VPP 线程占满一个 CPU，全速运行）"
	fi
	has_kind dpdk && note "驱动     $UIO$([ "$NOIOMMU" = 1 ] && echo '（无 IOMMU 模式）')"
	[ "$IPSEC" = 1 ] && note "IPsec    服务器的 VPP 侧：IKE 转给命名空间 $IPSEC_NS 的 $(ipsec_wan_name)（strongSwan 另装）"
	if panel_wanted; then
		note "面板     https://$(panel_listen):${PANEL_PORT}/，服务 $(panel_tools | grep -vx vpp-egress-gate | paste -sd' ')"
		[ "$WANT_GATE" = 1 ] && note "Gate     VPP 启动后运行 Gate 的安装程序"
	fi
	if [ "$WANT_SINGBOX" = 1 ]; then
		local upstream
		case $SB_TYPE in
		socks) upstream="SOCKS5 $SB_SERVER:$SB_PORT$([ -n "$SB_USER" ] && echo "，用户 $SB_USER")" ;;
		trojan) upstream="Trojan $SB_SERVER:$SB_PORT，SNI $SB_SNI" ;;
		file) upstream="导入 $SB_FILE" ;;
		none) upstream="稍后配置（之前拒绝代理流量）" ;;
		*) upstream="保留现有的 upstream.json" ;;
		esac
		if [ -e "$GATE_CONFIG" ]; then
			note "代理入口 sing-box $SINGBOX_VERSION：SOCKS5 $(panel_listen):$SOCKS_PORT，TPROXY 和 Fake-IP DNS 按 Gate 的代理规则；上游 $upstream"
		else
			note "代理入口 sing-box $SINGBOX_VERSION：SOCKS5 $(panel_listen):$SOCKS_PORT、TPROXY $TPROXY_PORT、Fake-IP DNS 127.0.0.1:$FAKEDNS_PORT；上游 $upstream"
		fi
		[ "$WANT_GATE" = 1 ] && [ ! -e "$GATE_CONFIG" ] && note "Gate     DNS 端口 $GATE_DNS_PORT"

	fi
	[ "$RTL_PLATFORM" = 1 ] && note "补丁     另加 platforms/rtl8125-noncoherent"
	if [ "${MLX4_RELOAD:-0}" = 1 ]; then note "mlx4     写入 ${MLX4_CONF}，安装时重新加载 mlx4 驱动"
	elif [ "${MLX4_REBOOT:-0}" = 1 ]; then note "mlx4     写入 ${MLX4_CONF}，安装后需要重启"; fi
	[ -n "$PLAT" ] && note "平台     platforms/${PLAT}：${N_IF[PLAT_NIC]} 用 ${PLAT_VDEV}，内核模块 $PLAT_KMOD.ko（针对 $(uname -r) 编译）"
	[ "$MODE" = install ] && note "编译     VPP $VPP_TAG + DPDK ${DPDK_VERSION}，源码 ${SRC}，安装到 $PREFIX"
	echo
	ask_yn "开始？" y || die "已取消"
}

# ---------- 依赖、源码、编译 ----------

install_deps() {
	info "安装编译依赖"
	local pkgs
	case $PKG in
	apt)
		pkgs="build-essential git curl ca-certificates xz-utils patch python3 python3-ply python3-pyelftools
			meson ninja-build cmake pkg-config libnuma-dev libssl-dev libsystemd-dev libunwind-dev uuid-dev pciutils ethtool kmod iproute2"
		[ "$NEED_MLX" = 1 ] && pkgs+=" rdma-core libibverbs-dev libmnl-dev"
		# dnsmasq-base 只有程序，不会启动占用 53 端口的系统服务
		[ "$DNSMASQ" = 1 ] && pkgs+=" dnsmasq-base"
		# Gate 用 nft 管理转发规则；只要程序，nftables.service 不启用
		[ "$WANT_GATE" = 1 ] && pkgs+=" nftables"
		DEBIAN_FRONTEND=noninteractive apt-get update
		# shellcheck disable=SC2086
		DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $pkgs
		if [ -n "${PLAT_KMOD:-}" ] && [ ! -e "/lib/modules/$(uname -r)/build/Makefile" ]; then
			DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "linux-headers-$(uname -r)" ||
				warn "没有找到 linux-headers-$(uname -r) 软件包"
		fi ;;
	dnf)
		pkgs="gcc gcc-c++ make git curl xz patch python3 python3-ply python3-pyelftools meson ninja-build
			cmake pkgconf-pkg-config numactl-devel openssl-devel systemd-devel libunwind-devel libuuid-devel pciutils ethtool kmod iproute"
		[ "$NEED_MLX" = 1 ] && pkgs+=" rdma-core-devel libmnl-devel"
		[ "$DNSMASQ" = 1 ] && pkgs+=" dnsmasq"
		[ "$WANT_GATE" = 1 ] && pkgs+=" nftables"
		# shellcheck disable=SC2086
		dnf install -y $pkgs
		if [ -n "${PLAT_KMOD:-}" ] && [ ! -e "/lib/modules/$(uname -r)/build/Makefile" ]; then
			dnf install -y "kernel-devel-$(uname -r)" || warn "没有找到 kernel-devel-$(uname -r) 软件包"
		fi ;;
	esac
}

# fetch URL SHA256 目标文件
fetch() {
	local sum
	if [ ! -s "$3" ]; then
		curl -fL --retry 3 -o "$3.part" "$1"
		mv "$3.part" "$3"
	fi
	sum=$(sha256sum "$3" | cut -d' ' -f1)
	if [ "$sum" != "$2" ]; then
		rm -f "$3"
		die "$(basename "$3") 的 SHA-256 不符：得到 ${sum}，期望 $2"
	fi
}

fetch_sources() {
	info "获取源码到 $SRC"
	mkdir -p "$SRC"
	fetch "$DPDK_URL" "$DPDK_SHA256" "$SRC/dpdk-$DPDK_VERSION.tar.xz"
	fetch "$VPP_URL" "$VPP_SHA256" "$SRC/vpp-$VPP_TAG.tar.gz"
	# 每次都从源码包重新解开，补丁总是打在干净的树上
	rm -rf "$SRC/dpdk" "$SRC/vpp"
	mkdir -p "$SRC/dpdk" "$SRC/vpp"
	tar -xJf "$SRC/dpdk-$DPDK_VERSION.tar.xz" -C "$SRC/dpdk" --strip-components=1
	tar -xzf "$SRC/vpp-$VPP_TAG.tar.gz" -C "$SRC/vpp" --strip-components=1
}

# 编译面板和管理服务到 $SRC/tools-bin。go 自己判断要重编什么，模块和编译缓存放在 $SRC，不碰 root 的家目录
build_tools() {
	local goarch sum go tool pkg
	case $ARCH in x86_64) goarch=amd64 ;; aarch64) goarch=arm64 ;; esac
	sum=GO_SHA256_$goarch
	info "编译管理面板和服务（Go $GO_VERSION）"
	mkdir -p "$SRC"
	fetch "${GO_URL:-https://go.dev/dl/go$GO_VERSION.linux-$goarch.tar.gz}" "${!sum}" "$SRC/go$GO_VERSION.linux-$goarch.tar.gz"
	go=$SRC/go-$GO_VERSION/bin/go
	if [ ! -x "$go" ]; then
		rm -rf "$SRC/go-$GO_VERSION"
		mkdir -p "$SRC/go-$GO_VERSION"
		tar -xzf "$SRC/go$GO_VERSION.linux-$goarch.tar.gz" -C "$SRC/go-$GO_VERSION" --strip-components=1
	fi
	mkdir -p "$SRC/tools-bin"
	: >"$SRC/tools-build.log"
	for tool in $(panel_tools); do
		pkg=.
		[ "$tool" = vpp-egress-gate ] && pkg=./cmd/vpp-egress-gate
		note "$tool"
		(cd "$REPO/tools/$tool" && env GOTOOLCHAIN=local GOPATH="$SRC/go-path" GOCACHE="$SRC/go-cache" GOFLAGS=-mod=readonly \
			CGO_ENABLED=0 "$go" build -trimpath -o "$SRC/tools-bin/$tool" "$pkg") >>"$SRC/tools-build.log" 2>&1 ||
			die "编译 $tool 失败，见 $SRC/tools-build.log（下载模块失败时可以设置 GOPROXY）"
	done
	if [ "$WANT_SINGBOX" = 1 ]; then
		local name=sing-box-$SINGBOX_VERSION-linux-$goarch
		sum=SINGBOX_SHA256_$goarch
		note "sing-box $SINGBOX_VERSION"
		fetch "${SINGBOX_URL:-https://github.com/SagerNet/sing-box/releases/download/v$SINGBOX_VERSION/$name.tar.gz}" "${!sum}" "$SRC/$name.tar.gz"
		tar -xzf "$SRC/$name.tar.gz" -C "$SRC/tools-bin" --strip-components=1 "$name/sing-box"
	fi
}

apply_series() {
	local dir=$1 series=$2 p
	while read -r p; do
		p=${p%%#*}; p=${p//[[:space:]]/}
		[ -n "$p" ] || continue
		note "补丁 $p"
		patch -d "$dir" -p1 --forward --batch --silent <"$(dirname "$series")/$p" || die "补丁 $p 无法应用"
	done <"$series"
}

apply_patches() {
	info "应用补丁"
	apply_series "$SRC/vpp" "$REPO/patches/vpp/series"
	if [ "$RTL_PLATFORM" = 1 ]; then
		apply_series "$SRC/dpdk" "$REPO/platforms/rtl8125-noncoherent/dpdk-patches/series"
	fi
	# 通用 DPDK 补丁排在平台补丁之后，两种情况下都能应用
	apply_series "$SRC/dpdk" "$REPO/patches/dpdk/series"
	if [ -n "$PLAT" ]; then
		local pdir=$REPO/platforms/$PLAT ddir=$SRC/dpdk/drivers/net/$PLAT_PMD list=$SRC/dpdk/drivers/net/meson.build
		[ -n "${PLAT_VPP_SERIES:-}" ] && apply_series "$SRC/vpp" "$pdir/$PLAT_VPP_SERIES"
		# 平台 PMD 作为 DPDK 的 drivers/net/$PLAT_PMD 编译，并加入 net 驱动列表
		mkdir -p "$ddir"
		cp "$pdir"/dpdk/* "$ddir/"
		[ -d "$pdir/kmod" ] && cp "$pdir"/kmod/*.h "$ddir/"
		sed -i "0,/^drivers = \[\$/s//drivers = [\n        '$PLAT_PMD',/" "$list"
		grep -q "'$PLAT_PMD'," "$list" || die "无法把 $PLAT_PMD 加入 $list"
		note "DPDK 驱动 net/$PLAT_PMD"
	fi
	# 本仓库的 VPP 插件放进源码树，和自带插件一起编译（VPP_PLUGINS 里按 add_vpp_plugin 的名字选）
	local p
	for p in $REPO_PLUGINS; do
		cp -r "$REPO/plugins/$p" "$SRC/vpp/src/plugins/$p"
	done
	echo "${VPP_TAG}-router" >"$SRC/vpp/src/scripts/.version"
}

# 编译并行数：每个编译进程按内存加 swap 共 800 MB 估算。
# 实测 N1（1.8 GB 内存）4 个进程同时编 vnet 最大的几个文件时，占用约 1.7 GB 内存和 1.2 GB swap
JOB_MB=800
plan_jobs() {
	local swap_mb
	swap_mb=$(awk 'NR > 1 { s += $3 } END { print int(s / 1024) }' /proc/swaps 2>/dev/null || echo 0)
	JOBS=$(((MEM_MB + ${swap_mb:-0}) / JOB_MB))
	[ "$JOBS" -ge 1 ] || JOBS=1
	[ "$JOBS" -le "$CPUS" ] || JOBS=$CPUS
	return 0
}

zram_usable() {
	command -v zramctl >/dev/null && command -v mkswap >/dev/null && modinfo zram >/dev/null 2>&1
}

# 内存不够用满所有 CPU 时，编译期间临时启用与内存同样大小的 zram swap（编译器内存压缩率约 3:1），
# 编译结束或脚本退出时撤除
BUILD_ZRAM=
build_swap_on() {
	[ "$JOBS_AUTO" = 1 ] && [ "$JOBS" -lt "$CPUS" ] || return 0
	zram_usable || return 0
	local size alg=lzo-rle
	size=$((MEM_MB < 4096 ? MEM_MB : 4096))
	modprobe zram 2>/dev/null || return 0
	# 先分配设备再读它支持的算法：没有空闲设备时 /sys/block/zram* 可能还不存在
	BUILD_ZRAM=$(zramctl --find 2>/dev/null) || BUILD_ZRAM=
	[ -n "$BUILD_ZRAM" ] || { warn "无法创建 zram，编译并行数保持 $JOBS"; return 0; }
	trap build_swap_off EXIT
	grep -qsw zstd "/sys/block/${BUILD_ZRAM##*/}/comp_algorithm" && alg=zstd
	if ! zramctl --size "${size}M" --algorithm "$alg" "$BUILD_ZRAM" >/dev/null ||
		! mkswap -q "$BUILD_ZRAM" >/dev/null || ! swapon -p 100 "$BUILD_ZRAM"; then
		build_swap_off
		warn "无法启用 zram swap，编译并行数保持 $JOBS"
		return 0
	fi
	plan_jobs
	note "临时启用 ${size} MB zram swap（$BUILD_ZRAM，$alg），编译并行数 $JOBS"
}

build_swap_off() {
	[ -n "$BUILD_ZRAM" ] || return 0
	swapoff "$BUILD_ZRAM" 2>/dev/null || true
	zramctl --reset "$BUILD_ZRAM" 2>/dev/null || true
	BUILD_ZRAM=
}

# 编译指纹：源码、补丁、平台文件、所选 PMD、编译器和编译步骤本身。
# 指纹不变时复用上次的编译结果，例如编译完成后安装或配置失败、重新运行安装时
build_key() {
	local i p files=("$REPO/patches/vpp" "$REPO/patches/dpdk")
	for p in $REPO_PLUGINS; do files+=("$REPO/plugins/$p"); done
	[ "$RTL_PLATFORM" = 1 ] && files+=("$REPO/platforms/rtl8125-noncoherent/dpdk-patches")
	[ -n "$PLAT" ] && files+=("$REPO/platforms/$PLAT")
	{
		echo "$ARCH $PREFIX $VPP_LIBDIR_REL $VPP_URL $VPP_SHA256 $DPDK_URL $DPDK_SHA256 ${PLAT:-} ${PLAT_PMD:-} $RTL_PLATFORM ${NEED_MLX:-0} ${EXTRA_PLUGINS:-}"
		if [ "$MEM_MB" -lt 3000 ]; then
			for i in "${SEL[@]}"; do
				if [ "${N_KIND[i]}" = dpdk ]; then echo "pmd ${N_PMD[i]}"; fi
			done
		fi
		gcc --version | head -n 1
		declare -f fetch_sources apply_series apply_patches driver_path configure_dpdk build_dpdk build_vpp
		find "${files[@]}" -type f -print0 | sort -z | xargs -0 sha256sum | sed "s|$REPO/||"
	} | sha256sum | cut -d' ' -f1
}

reuse_build() {
	[ "$REBUILD" = 0 ] && [ -s "$SRC/build.key" ] && [ -x "$SRC/build-vpp/bin/vpp" ] || return 1
	[ "$(cat "$SRC/build.key")" = "$(build_key)" ] || return 1
	info "源码、补丁和编译选项与上次相同，复用 $SRC 中的编译结果（--rebuild 强制重新编译）"
	return 0
}

# DPDK 驱动路径在不同版本间移动过（例如 Intel 驱动移到 net/intel/），按目录名查找
driver_path() {
	[ -d "$SRC/dpdk/drivers/$1" ] || return 0
	(cd "$SRC/dpdk/drivers" && find "$1" -mindepth 1 -maxdepth 2 -type d -name "$2" -exec test -f {}/meson.build \; -print -quit)
}

configure_dpdk() {
	local round missing dep class name path added status
	for round in 1 2 3 4; do
		rm -rf "$SRC/build-dpdk"
		status=0
		meson setup "$SRC/build-dpdk" "$SRC/dpdk" "${opts[@]}" \
			-Denable_drivers="$(IFS=,; echo "${drivers[*]}")" >"$log" 2>&1 || status=$?
		missing=$(grep -oE 'missing internal dependency,? "[a-z0-9_]+"' "$log" | grep -oE '"[a-z0-9_]+"' | tr -d '"' | sort -u || true)
		added=0
		for dep in $missing; do
			class=${dep%%_*} name=${dep#*_}
			path=$(driver_path "$class" "$name" 2>/dev/null || true)
			if [ -n "$path" ] && [[ " ${drivers[*]} " != *" $path "* ]]; then drivers+=("$path"); added=1; fi
		done
		[ "$status" = 0 ] && [ "$added" = 0 ] && return 0
		[ "$added" = 1 ] && [ "$round" -lt 4 ] && continue
		tail -n 30 "$log"
		die "DPDK 配置失败，日志 $log"
	done
}

build_dpdk() {
	info "编译 DPDK $DPDK_VERSION"
	local want=(ixgbe i40e iavf ice igc e1000 idpf virtio vmxnet3 ena gve bnxt enic hns3 nfp cxgbe
		txgbe ngbe atlantic r8169 ionic)
	# VPP 的 dpdk 插件在 Linux 上总会引用 bus/vmbus 的头文件和符号
	local drivers=(bus/pci bus/vdev bus/vmbus mempool/ring) d path missing log opts round
	# 小内存开发板只编译所选网卡需要的 PMD，其余驱动要编译数小时
	if [ "$MEM_MB" -lt 3000 ]; then
		local i
		want=()
		for i in "${SEL[@]}"; do
			if [ "${N_KIND[i]}" = dpdk ] && [[ " ${want[*]} " != *" ${N_PMD[i]} "* ]]; then want+=("${N_PMD[i]}"); fi
		done
		note "内存较小，只编译所选网卡的 PMD：${want[*]:-无}${PLAT:+ $PLAT_PMD}"
	fi
	[ "$NEED_MLX" = 1 ] && want+=(mlx4 mlx5) && drivers+=(bus/auxiliary)
	[ -n "$PLAT" ] && drivers+=("net/$PLAT_PMD")
	for d in "${want[@]}"; do
		path=$(driver_path net "$d")
		[ -n "$path" ] && drivers+=("$path")
	done
	# max_lcores 按本机 CPU 数：arm64 generic 默认 256，DPDK 的 lcore 变量区
	# （每个 lcore 128 KiB）因此在 VPP 主堆里占 32 MiB；本机编译，CPU 数就是上限
	opts=(--prefix="$DEPS" --libdir=lib --buildtype=release --default-library=static
		-Dplatform=generic -Dmax_lcores=detect -Dtests=false -Denable_docs=false -Ddisable_libs=graph,node -Ddisable_apps='*'
		-Denable_driver_sdk=true)
	[ "$NEED_MLX" = 1 ] && opts+=(-Dibverbs_link=dlopen)
	log=$SRC/dpdk-configure.log
	# Meson 遇到显式启用的驱动缺依赖时会失败，仍需先读取日志并重试。
	configure_dpdk
	sed -n '/Drivers Enabled/,/Content Skipped/p' "$log" | sed 's/^/    /' | head -n 20 || true
	ninja -C "$SRC/build-dpdk" -j "$JOBS"
	rm -rf "$DEPS"
	meson install -C "$SRC/build-dpdk" --quiet
	if [ -n "$PLAT" ] && [ ! -f "$DEPS/lib/librte_net_$PLAT_PMD.a" ]; then
		grep -i "$PLAT_PMD" "$log" | sed 's/^/    /' || true
		die "平台 PMD net/$PLAT_PMD 没有编译，见 $log"
	fi

	# VPP 内置 DPDK 的链接方式：把 libdpdk.a 整体 whole-archive 链进 dpdk 插件，
	# 否则静态库中 PMD 的注册构造函数会被丢弃。libdpdk.a 写成链接脚本，
	# 再带上 DPDK 依赖的外部库（libnuma、libarchive 等）。
	local libs ext
	libs=$(find "$DEPS/lib" -maxdepth 1 -name 'librte_*.a' | sort | tr '\n' ' ')
	ext=$(PKG_CONFIG_PATH=$DEPS/lib/pkgconfig pkg-config --static --libs-only-l libdpdk |
		tr ' ' '\n' | awk '/^-l/ && !/^-l(:lib)?rte_/ && !seen[$0]++' | tr '\n' ' ')
	{
		echo "GROUP ( $libs)"
		[ -n "${ext// }" ] && echo "INPUT ( $ext)"
	} >"$DEPS/lib/libdpdk.a"
	note "外部依赖：${ext:-无}"

	# 每个 PMD 的 PCI ID 表（pmdinfogen 生成的 *.pmd.c），用于精确判断网卡是否受支持
	python3 -I - "$SRC/build-dpdk" >"$SRC/dpdk-pci-ids" <<'EOF'
import json, pathlib, re, sys
for f in sorted(pathlib.Path(sys.argv[1]).rglob('*.pmd.c')):
    for m in re.finditer(r'PMD_INFO_STRING=\s*((?:[^"\\]|\\.)*)"', f.read_text(errors='replace')):
        try:
            info = json.loads(m.group(1).encode().decode('unicode_escape'))
        except ValueError:
            continue
        name = info.get('name', '?').removeprefix('net_')
        for e in info.get('pci_ids', []):
            v, d = (e[0], e[1]) if isinstance(e, list) else (e.get('vendor'), e.get('device'))
            if v is not None and d is not None:
                print(f'{v:04x} {d:04x} {name}')
EOF
	# 只编译了平台 PMD（vdev）时没有 PCI ID 表
	if [ ! -s "$SRC/dpdk-pci-ids" ] && has_kind dpdk; then
		warn "没有读到 DPDK 的 PCI ID 表，无法复核网卡支持情况"
	fi
}

build_vpp() {
	info "编译 VPP $VPP_TAG"
	local args
	args=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX"
		-DCMAKE_INSTALL_LIBDIR="$VPP_LIBDIR_REL" -DCMAKE_PREFIX_PATH="$DEPS" -DCMAKE_INSTALL_RPATH="$LIBDIR"
		-DVPP_PLUGINS=dpdk,af_packet,tap,nat,nat44_ei,wireguard,acl,abf,dhcp,mss_clamp,ping,ipsec_ike_punt,vxlan,gre${EXTRA_PLUGINS:+,$EXTRA_PLUGINS}
		-DVPP_DRIVERS=none -DVPP_CRYPTO_ENGINES=native,openssl -DVPP_USE_SYSTEM_DPDK=OFF
		-DVPP_USE_LTO=OFF -DVPP_TESTS=none -DVPP_TOOLS=vppctl)
	# arm64 只编通用版本：每个 CPU 变体都要把 vnet 和插件的热点代码再编一遍（N1 上占四分之一时间），
	# 而开发板上的 Cortex-A5x/A7x 用不上这些服务器 CPU 的变体。变体列表从源码读取，新版本增加的也会关掉
	if [ "$ARCH" = aarch64 ]; then
		local v
		for v in $(grep -oE 'add_vpp_march_variant\([a-z0-9_]+' "$SRC/vpp/src/cmake/cpu.cmake" | cut -d'(' -f2 | sort -u); do
			[ "$v" = scalar ] || args+=("-DVPP_MARCH_VARIANT_${v^^}=OFF")
		done
	fi
	rm -rf "$SRC/build-vpp"
	cmake -S "$SRC/vpp/src" -B "$SRC/build-vpp" "${args[@]}" >"$SRC/vpp-configure.log" 2>&1 ||
		{ tail -n 40 "$SRC/vpp-configure.log"; die "VPP 配置失败，日志 $SRC/vpp-configure.log"; }
	if [ -f "$SRC/build-vpp/CMakeCache.txt" ] &&
		grep -Eq '^LIBUNWIND_(LIB|INCLUDE_DIR):[^=]+=[^[:space:]]*-NOTFOUND$' "$SRC/build-vpp/CMakeCache.txt"; then
		die "VPP 未找到 libunwind 开发库，无法采集内存分配调用栈；请检查构建依赖"
	fi
	grep -iE 'dpdk|plugins' "$SRC/vpp-configure.log" | sed 's/^/    /' | head -n 10 || true
	ninja -C "$SRC/build-vpp" -j "$JOBS"
}

# 安装前缀可以是 /usr/local 这样的公共目录，因此不整体替换：每个文件记在 $MANIFEST，
# 已存在但不在清单里的文件（例如手工部署的 VPP）一律不覆盖
check_prefix() {
	case $PREFIX in
	/*) ;;
	*) die "PREFIX 必须是绝对路径" ;;
	esac
	case $PREFIX in
	''|/usr|/etc|/var|/bin|/sbin|/lib|/lib64|/boot|/proc|/sys|/dev|/run) die "PREFIX=$PREFIX 是发行版的系统目录，请用 /usr/local 或 /opt/<名字>" ;;
	esac
}

# 清单里的路径，每行一个
manifest_has() { [ -s "$MANIFEST" ] && grep -qxF -- "$1" "$MANIFEST"; }

manifest_add() {
	mkdir -p "$STATE"
	printf '%s\n' "$@" >>"$MANIFEST"
	sort -u -o "$MANIFEST" "$MANIFEST"
}

# 删除空的私有目录；公共目录（bin、sbin、lib、share）本身不动
prune_private_dirs() {
	local d
	PYDIR=${PYDIR:-$(python_dir)}
	for d in "$LIBDIR" "$LIBEXEC" "$DATADIR" "$PREFIX/share/vpp" "$PYDIR/vpp_papi" "$KMOD_DIR"; do
		[ -d "$d" ] && find "$d" -depth -type d -empty -delete 2>/dev/null
	done
	return 0
}

# Python 包目录：前缀是系统 Python 的本地目录（Debian 上 /usr/local/lib/python3.X/dist-packages）时直接可导入
python_dir() {
	local sys
	sys=$(python3 -I -c 'import sysconfig; print(sysconfig.get_path("purelib"))' 2>/dev/null || true)
	case $sys in "$PREFIX"/*) echo "$sys"; return 0 ;; esac
	echo "$PREFIX/lib/python3/site-packages"
}

# 2026-11 以前装在 /opt/vpp-router（整个目录由本脚本创建，没有清单）；迁移到新布局时删除
remove_old_prefix() {
	[ -d "$OLD_PREFIX/share/vpp-router" ] && ! manifest_has "$OLD_PREFIX/bin/vpp" || return 0
	rm -rf "$OLD_PREFIX"
	if grep -qs "^$OLD_PREFIX/" /etc/ld.so.conf.d/vpp-router.conf; then
		rm -f /etc/ld.so.conf.d/vpp-router.conf
		ldconfig
	fi
	note "已删除旧的安装目录 $OLD_PREFIX"
}

install_vpp() {
	info "安装到 $PREFIX"
	check_prefix
	mkdir -p "$STATE"
	local stage=$SRC/stage root comp new old conflicts=() f
	rm -rf "$stage"
	root=$stage$PREFIX
	# 只装运行需要的组件。vpp-api-python 组件要用 pip 构建（还会联网取 setuptools），
	# vpp_papi 是纯 Python 包，直接复制源码；vpp-dev 的头文件路由器用不上
	for comp in vpp vpp-plugin-core vpp-plugin-dpdk vpp-crypto-engines libvppinfra; do
		DESTDIR=$stage cmake --install "$SRC/build-vpp" --component "$comp" >/dev/null
	done
	# VPP 自带的 etc 模板（startup.conf、sysctl.d）不用，配置只在 /etc/vpp；VAT 测试插件和 elog_dump 用不上
	rm -rf "$root/etc" "$root/bin/elog_dump" "$stage$LIBDIR/vat2_plugins" "$stage$LIBDIR/vpp_api_test_plugins"
	[ -x "$root/bin/vpp" ] && [ -x "$root/bin/vppctl" ] || die "安装结果里没有 bin/vpp 或 bin/vppctl"
	[ -f "$stage$LIBDIR/vpp_plugins/dpdk_plugin.so" ] ||
		die "没有生成 $LIBDIR/vpp_plugins/dpdk_plugin.so，见 $SRC/vpp-configure.log 中的 DPDK 部分"
	PYDIR=$(python_dir)
	mkdir -p "$stage$PYDIR"
	cp -r "$SRC/vpp/src/vpp-api/python/vpp_papi" "$stage$PYDIR/"
	rm -rf "$stage$PYDIR/vpp_papi/tests"
	find "$stage$PYDIR" -name __pycache__ -prune -exec rm -rf {} +
	mkdir -p "$stage$DATADIR"
	[ -s "$SRC/dpdk-pci-ids" ] && cp "$SRC/dpdk-pci-ids" "$stage$IDS_FILE"
	git -C "$REPO" rev-parse HEAD >"$stage$DATADIR/repo-commit" 2>/dev/null || true
	if [ "$NEED_MLX" = 1 ]; then
		local glue
		glue=$(find "$DEPS/lib" -type d -name 'pmds-*-glue' -print -quit)
		[ -n "$glue" ] && cp -a "$glue" "$stage$LIBDIR/dpdk-glue"
	fi
	write_ctl "$stage"
	# Gate 的程序由它的 install.py 装到固定位置，不在这里
	local tool
	for tool in $(panel_tools | grep -vx vpp-egress-gate); do
		install -m 755 "$SRC/tools-bin/$tool" "$root/bin/$tool"
	done
	[ "$WANT_SINGBOX" = 1 ] && install -m 755 "$SRC/tools-bin/sing-box" "$root/bin/sing-box"

	new=$SRC/installed-files.new
	(cd "$stage" && find . ! -type d | sed 's|^\.||' | LC_ALL=C sort) >"$new"
	while read -r f; do
		{ [ -e "$f" ] || [ -L "$f" ]; } || continue
		manifest_has "$f" && continue
		# 旧布局（/opt/vpp-router）没有清单，那里的文件会整体删除
		case $f in "$OLD_PREFIX"/*) [ -d "$OLD_PREFIX/share/vpp-router" ] && ! manifest_has "$OLD_PREFIX/bin/vpp" && continue ;; esac
		conflicts+=("$f")
	done <"$new"
	if [ ${#conflicts[@]} -gt 0 ]; then
		printf '    %s\n' "${conflicts[@]:0:10}" >&2
		die "以上 ${#conflicts[@]} 个文件已存在且不是本脚本安装的，不会覆盖；请先移走，或用 --prefix /opt/<名字> 装到别处"
	fi

	prepare_reconfigure
	remove_old_prefix
	# 解到系统目录；--no-overwrite-dir 保留已有目录（/usr/local/bin 等）的权限和属主
	tar -C "$stage" -cf - . | tar -C / -xf - --no-overwrite-dir --no-same-owner
	# 新版本里没有的旧文件删除；其他内核版本的模块留着，换回旧内核时还能用
	old=$SRC/installed-files.old
	if [ -s "$MANIFEST" ]; then LC_ALL=C sort -u "$MANIFEST" >"$old"; else : >"$old"; fi
	LC_ALL=C comm -23 "$old" "$new" | { grep -v '^/lib/modules/' || true; } | while read -r f; do rm -f -- "$f"; done
	prune_private_dirs
	{ grep '^/lib/modules/' "$old" || true; cat "$new"; } | LC_ALL=C sort -u >"$MANIFEST"
	rm -f "$old" "$new"
	rm -rf "$stage"

	if ldd "$PREFIX/bin/vpp" | grep -q 'not found'; then
		echo "$LIBDIR" >/etc/ld.so.conf.d/vpp-router.conf
		ldconfig
		manifest_add /etc/ld.so.conf.d/vpp-router.conf
		warn "RPATH 不完整，已加入 /etc/ld.so.conf.d/vpp-router.conf"
	fi
	local undefined
	undefined=$(ldd -r "$LIBDIR/vpp_plugins/dpdk_plugin.so" 2>&1 |
		grep -E 'undefined symbol: (rte_|ibv|mlx|archive_|numa_|elf_|pcap_|strlcpy)' | head -n 5 || true)
	[ -z "$undefined" ] || warn "dpdk 插件有未解析的符号，可能无法加载：
$undefined"
	note "vpp、vppctl 在 $PREFIX/bin，私有库和插件在 $LIBDIR，vpp_papi 在 $PYDIR"
	return 0
}

# 平台内核模块：针对当前运行的内核编译，装到 /lib/modules/<内核版本>/updates/vpp-router/
# 内核模块要用与编译内核相同或更新的 gcc：内核的构建参数可能包含旧 gcc 不认识的选项
# （例如 GCC 14 起才有的 -fmin-function-alignment）。输出 make 的编译器参数
kmod_cc() {
	local conf=$1/include/generated/autoconf.h want have n
	if grep -q '^#define CONFIG_CC_IS_CLANG 1' "$conf" 2>/dev/null; then
		echo LLVM=1
		return 0
	fi
	want=$(awk '$2 == "CONFIG_GCC_VERSION" {print int($3 / 10000)}' "$conf" 2>/dev/null || true)
	have=$(gcc -dumpversion 2>/dev/null | cut -d. -f1)
	if [ -z "$want" ] || [ -z "$have" ] || [ "$have" -ge "$want" ]; then
		echo CC=gcc
		return 0
	fi
	for n in $(seq "$want" -1 $((have + 1))); do
		command -v "gcc-$n" >/dev/null && { echo "CC=gcc-$n"; return 0; }
	done
	for n in $(seq "$want" -1 $((have + 1))); do
		case $PKG in
		apt) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "gcc-$n" >&2 || continue ;;
		dnf) dnf install -y "gcc-toolset-$n-gcc" >&2 && [ -x "/opt/rh/gcc-toolset-$n/root/usr/bin/gcc" ] &&
			{ echo "CC=/opt/rh/gcc-toolset-$n/root/usr/bin/gcc"; return 0; }; continue ;;
		*) continue ;;
		esac
		command -v "gcc-$n" >/dev/null && { echo "CC=gcc-$n"; return 0; }
	done
	warn "内核由 GCC $want 编译，系统只有 GCC ${have}，模块可能无法编译" >&2
	echo CC=gcc
}

# 平台内核模块：针对当前运行的内核编译到 $SRC/kmod-<名字>/，install_kmod 再装进 /lib/modules
build_kmod() {
	[ -n "${PLAT:-}" ] && [ -n "${PLAT_KMOD:-}" ] || return 0
	local kver kdir b abi cc
	kver=$(uname -r)
	kdir=/lib/modules/$kver/build
	b=$SRC/kmod-$PLAT_KMOD
	info "编译 $PLAT_KMOD.ko（内核 ${kver}）"
	[ -e "$kdir/Makefile" ] || die "没有当前内核 $kver 的头文件（${kdir}），请先安装与内核匹配的 headers"
	cc=$(kmod_cc "$kdir")
	rm -rf "$b"
	mkdir -p "$b"
	cp "$REPO/platforms/$PLAT"/kmod/* "$b/"
	echo "obj-m += $PLAT_KMOD.o" >"$b/Kbuild"
	note "编译器 ${cc#*=}"
	make -C "$kdir" M="$b" "$cc" modules -j "$JOBS" >"$b/build.log" 2>&1 ||
		{ tail -n 30 "$b/build.log"; die "$PLAT_KMOD.ko 编译失败，日志 $b/build.log"; }
	if [ -n "${PLAT_KMOD_ABI:-}" ]; then
		abi=$(modinfo -F "${PLAT_KMOD}_abi" "$b/$PLAT_KMOD.ko" 2>/dev/null || true)
		[ "$abi" = "$PLAT_KMOD_ABI" ] || die "$PLAT_KMOD.ko 的 ABI 是 '${abi:-无}'，需要 $PLAT_KMOD_ABI"
	fi
	return 0
}

# 装到 /lib/modules/<内核版本>/updates/vpp-router/。模块没有设备匹配表，不会被 udev 自动加载，
# 只由 vpp-router-ctl 按路径 insmod
install_kmod() {
	[ -n "${PLAT:-}" ] && [ -n "${PLAT_KMOD:-}" ] || return 0
	local ko=$KMOD_DIR/$PLAT_KMOD.ko
	if [ -e "$ko" ] && ! manifest_has "$ko"; then die "$ko 已存在且不是本脚本安装的"; fi
	install -D -m 0644 "$SRC/kmod-$PLAT_KMOD/$PLAT_KMOD.ko" "$ko"
	depmod -a "$(uname -r)" 2>/dev/null || true
	manifest_add "$ko"
	note "$ko"
}

# ---------- 安装后复核与配置 ----------

verify_nics() {
	[ -s "$IDS_FILE" ] || return 0
	local i pmd
	for i in "${SEL[@]}"; do
		[ "${N_KIND[i]}" = afp ] && continue
		[ "${N_VD[i]}" = - ] && continue
		pmd=$(pmd_for - "${N_VD[i]}")
		if [ -z "$pmd" ]; then
			if [ "${N_IF[i]}" = - ]; then
				die "${N_PCI[i]}（${N_VD[i]}）不在 DPDK 的 PCI ID 表中，且没有内核网卡名，无法改用 AF_PACKET"
			fi
			warn "${N_IF[i]}（${N_VD[i]}）不在本次编译的 DPDK PCI ID 表中，改用 AF_PACKET"
			N_KIND[i]=afp
		else
			N_PMD[i]=$pmd
		fi
	done
	return 0
}

# VPP 里的接口名
assign_names() {
	local i k=0
	for i in "${SEL[@]}"; do
		if [ "$SINGLE" = 1 ]; then V_NAME[i]=port0
		elif [ "$i" = "$WAN_NIC" ]; then V_NAME[i]=wan0
		else V_NAME[i]=lan$k; k=$((k + 1)); fi
		[ "${N_KIND[i]}" = afp ] && V_NAME[i]=host-${N_IF[i]}
	done
	return 0
}

record_orig() {
	mkdir -p "$STATE"
	touch "$STATE/nics.orig"
	local i
	for i in "${SEL[@]}"; do
		[ "${N_PCI[i]}" = - ] && continue
		# 只记录第一次见到的驱动，重复运行不会把 vfio-pci 当成原驱动
		grep -q "^${N_PCI[i]} " "$STATE/nics.orig" && continue
		printf '%s %s %s\n' "${N_PCI[i]}" "${N_PCIDRV[i]}" "${N_IF[i]}" >>"$STATE/nics.orig"
	done
	return 0
}

gen_startup() {
	local plugins rxq i q a enabled=(tap ping nat44_ei dhcp acl abf mss_clamp wireguard vxlan gre af_packet) has_pci=0 has_plat=0 heap extras=${EXTRA_PLUGINS:-}
	for i in ${extras//,/ }; do enabled+=("$i"); done
	plugins=$LIBDIR/vpp_plugins
	for i in "${SEL[@]}"; do
		case ${N_KIND[i]} in dpdk|mlx) has_pci=1 ;; plat) has_plat=1 ;; esac
	done
	[ $has_pci = 1 ] || [ $has_plat = 1 ] && enabled+=(dpdk)
	# af_packet 总是启用：面板可以把 Linux 网卡接进 VPP（AF_PACKET 接口）
	[ "$IPSEC" = 1 ] && enabled+=(ipsec_ike_punt)
	rxq=$((WORKERS > 0 ? WORKERS : 1))
	heap=1G
	[ "$MEM_MB" -lt 3000 ] && heap=512M

	echo "# 由 vpp-router-install.sh 生成于 $(date -Is)；重新运行 --config-only 会覆盖"
	echo "unix {"
	echo "  nodaemon"
	echo "  runtime-dir /run/vpp"
	echo "  cli-listen /run/vpp/cli.sock"
	echo "  startup-config $CONF/router.vpp"
	echo "}"
	echo "socksvr { socket-name /run/vpp/api.sock }"
	echo "statseg { socket-name /run/vpp/stats.sock }"
	# Host Stack 的共享 RX 消息队列会持续轮询，阻止 adaptive worker 空闲休眠。
	if [ "${RX_MODE:-polling}" = interrupt ]; then
		echo "session { use-private-rx-mqs }"
	fi
	echo "memory { main-heap-size $heap }"
	if [ $has_plat = 1 ] && [ -n "${PLAT_BUFFERS:-}" ]; then
		echo "buffers { $PLAT_BUFFERS }"
	else
		echo "buffers { buffers-per-numa 16384 }"
	fi
	if [ "$CPUS" -gt 1 ]; then
		if [ "$WORKERS" -gt 0 ]; then
			echo "cpu { main-core $MAIN_CORE corelist-workers 2-$((1 + WORKERS)) }"
		else
			echo "cpu { main-core $MAIN_CORE }"
		fi
	fi
	echo "plugins {"
	echo "  path $plugins"
	echo "  plugin default { disable }"
	for i in "${enabled[@]}"; do echo "  plugin ${i}_plugin.so { enable }"; done
	echo "}"
	# 没有 DPDK 网卡时不启用 dpdk 插件：没有 dev 列表时它会接管所有处于 down 状态的网卡
	if [ $has_pci = 1 ] || [ $has_plat = 1 ]; then
		echo "dpdk {"
		# mlx4 开着 RX scatter 时每个接收描述符带多个分段，网卡收包上限从约 7.1 Mpps 降到 5.2 Mpps
		# （ConnectX-3、64 字节、两个队列实测）；路由器各接口 MTU 都是 1500，用不到多段 buffer
		local mseg=${RTL_PLATFORM:-0}
		for i in "${SEL[@]}"; do [ "${N_PCIDRV[i]:-}" = mlx4_core ] && mseg=1; done
		[ "$mseg" != 1 ] || echo "  no-multi-seg"
		if [ $has_pci = 1 ]; then echo "  uio-driver $UIO"; else echo "  no-pci"; fi
		if [ $has_plat = 1 ]; then
			for a in "${PLAT_DPDK_ARGS[@]}"; do echo "  $a"; done
		fi
		# 同一 PCI 设备的几个口（比如 ConnectX-3 的两个口，mlx4 经一个 PCI 功能驱动）只能有一个 dev 块，
		# 每个口都按它命名；name 按口的顺序（Linux 的 dev_port）列出，空位是不接入的口（补丁 0031）
		local -A port_names=() port_q=()
		local pcis=() pci port e list max n
		for i in "${SEL[@]}"; do
			case ${N_KIND[i]} in dpdk|mlx) ;; *) continue ;; esac
			q=$rxq
			[ "${N_MAXQ[i]:-0}" -gt 0 ] && [ "${N_MAXQ[i]}" -lt "$q" ] && q=${N_MAXQ[i]}
			pci=${N_PCI[i]} port=0
			if [ "${N_KIND[i]}" = mlx ] && [ "${N_IF[i]}" != - ]; then
				port=$(cat "/sys/class/net/${N_IF[i]}/dev_port" 2>/dev/null || echo 0)
			fi
			if [ -z "${port_q[$pci]:-}" ]; then pcis+=("$pci"); port_q[$pci]=$q; fi
			port_names[$pci]+=" $port:${V_NAME[i]}"
		done
		for pci in "${pcis[@]}"; do
			local -a slot=()
			max=0
			for e in ${port_names[$pci]}; do
				slot[${e%%:*}]=${e#*:}
				[ "${e%%:*}" -gt "$max" ] && max=${e%%:*}
			done
			list=
			for ((n = 0; n <= max; n++)); do
				[ "$n" -gt 0 ] && list+=,
				list+=${slot[n]:-}
			done
			echo "  dev $pci { name $list num-rx-queues ${port_q[$pci]} }"
		done
		if [ $has_plat = 1 ]; then
			# vdev 不能单独配置，只能用 dev default 命名；PCI 网卡的 dev 块覆盖其中的同名参数
			echo "  vdev $PLAT_VDEV"
			echo "  dev default { name ${V_NAME[PLAT_NIC]} ${PLAT_DEV_ARGS:-} }"
		fi
		echo "}"
	fi
}

# VPP 里的 WAN 接口：单臂时是 VLAN 子接口（WAN 不打标签时是网卡本身）
wan_if() {
	local base=${V_NAME[WAN_NIC]}
	if { [ "$SINGLE" = 1 ] || [ "${WAN_TRUNK:-0}" = 1 ]; } && [ "$WAN_VLAN" != 1 ]; then echo "$base.$WAN_VLAN"; else echo "$base"; fi
}

# WAN 网卡在 VPP 里的 MAC。没有 ROM MAC 的网卡（如 RK3588 开发板的 RTL8125）每次启动 DPDK 都随机生成一个，
# DHCPv6 的 DUID 取自它：DUID 一变，上游每次重启都另分一个委派前缀，直到地址池用完。
# 优先用上次生成的 router.vpp 里固定的值（WAN_MAC），其次是安装时内核看到的 MAC，最后按机器生成。
wan_mac() {
	local m=${WAN_MAC:-}
	[ -n "$m" ] || m=${N_MAC[WAN_NIC]:-}
	m=${m,,}
	if [[ ! $m =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ ]] || [ "$m" = 00:00:00:00:00:00 ] ||
		(( 16#${m:0:2} & 1 )); then
		m=$(stable_mac wan)
	fi
	echo "$m"
}

# 已有 router.vpp 里固定的 WAN MAC（重新生成时沿用）
pinned_wan_mac() {
	[ -e "$1" ] || return 0
	awk -v n="${V_NAME[WAN_NIC]}" '$1 == "set" && $2 == "interface" && $3 == "mac" && $4 == "address" && $5 == n { print $6; exit }' "$1"
}

gen_router_vpp() {
	local i base wan lans=() pop= loop_mac tap_mac
	loop_mac=$(stable_mac loop0)
	tap_mac=$(stable_mac tap0)
	echo "# 由 vpp-router-install.sh 生成于 $(date -Is)；重新运行 --config-only 会覆盖"
	for i in "${SEL[@]}"; do
		[ "${N_KIND[i]}" = afp ] && echo "create host-interface name ${N_IF[i]}"
	done
	if [ "${N_KIND[WAN_NIC]}" != afp ]; then
		# 必须在 dhcp6 pd client 之前：DUID 在第一次启用 DHCPv6 客户端时取这个 MAC
		echo "set interface mac address ${V_NAME[WAN_NIC]} $(wan_mac)"
	fi
	if [ "$SINGLE" = 1 ] || [ "${WAN_TRUNK:-0}" = 1 ]; then
		base=${V_NAME[WAN_NIC]}
		echo "set interface promiscuous on $base"
		echo "set interface state $base up"
		if [ "$WAN_VLAN" = 1 ]; then wan=$base
		else
			echo "create sub-interface $base $WAN_VLAN dot1q $WAN_VLAN exact-match"
			wan=$base.$WAN_VLAN
		fi
		if [ "$LAN_VLAN" = 1 ]; then lans=("$base")
		else
			echo "create sub-interface $base $LAN_VLAN dot1q $LAN_VLAN exact-match"
			lans=("$base.$LAN_VLAN") pop=$base.$LAN_VLAN
		fi
		if [ "${WAN_TRUNK:-0}" = 1 ]; then
			for i in "${LAN[@]}"; do
				echo "set interface promiscuous on ${V_NAME[i]}"
				lans+=("${V_NAME[i]}")
			done
		fi
	else
		wan=${V_NAME[WAN_NIC]}
		for i in "${LAN[@]}"; do
			echo "set interface promiscuous on ${V_NAME[i]}"
			lans+=("${V_NAME[i]}")
		done
	fi
	echo "set interface mtu packet 1500 $wan"
	echo "set interface state $wan up"
	echo
	echo "# LAN：桥域 1，BVI loop0 为网关"
	echo "create bridge-domain 1"
	echo "create loopback interface mac $loop_mac instance 0"
	echo "set interface l2 bridge loop0 1 bvi"
	echo "set interface mtu packet 1500 loop0"
	echo "set interface ip address loop0 $LAN_CIDR"
	echo "set interface state loop0 up"
	for i in "${lans[@]}"; do
		echo "set interface l2 bridge $i 1"
		[ "$i" = "$pop" ] && echo "set interface l2 tag-rewrite $i pop 1"
		echo "set interface state $i up"
	done
	if [ -n "$HOST_CIDR" ]; then
		echo
		echo "# Linux 管理接口；地址和路由由 vpp-router-ctl post 用 ip 命令设置"
		echo "create tap id 0 host-if-name $HOST_TAP host-mac-addr $tap_mac host-mtu-size 1500"
		echo "set interface mtu packet 1500 tap0"
		echo "set interface l2 bridge tap0 1"
		echo "set interface state tap0 up"
		echo "set interface rx-mode tap0 interrupt"
	fi
	echo
	echo "# WAN"
	if [ "$WAN_MODE" = dhcp ]; then
		echo "set dhcp client intfc $wan hostname $(hostname -s)"
	else
		echo "set interface ip address $wan $WAN_CIDR"
		echo "ip route add 0.0.0.0/0 via $WAN_GW $wan"
	fi
	if [ "${IPV6_PD:-0}" = 1 ]; then
		echo
		echo "# IPv6：WAN 自动获取地址、默认路由及委派前缀；LAN 使用前缀的 /64"
		echo "enable ip6 interface $wan"
		echo "ip6 nd $wan ra-suppress"
		echo "ip6 nd address autoconfig $wan default-route"
		echo "dhcp6 pd client $wan prefix group wan-pd"
		echo "enable ip6 interface loop0"
		echo "set ip6 address loop0 prefix group wan-pd ::1/64"
		echo "ip6 nd loop0 ra-interval 10 7"
	fi
	if [ -n "${LAN_ULA:-}" ]; then
		echo
		echo "# IPv6：LAN 的固定 ULA 网段，RA 里宣告（VPP 不会自动宣告接口地址的网段）"
		if [ "${IPV6_PD:-0}" != 1 ]; then
			echo "enable ip6 interface loop0"
			echo "ip6 nd loop0 ra-interval 10 7"
		fi
		echo "set interface ip address loop0 ${LAN_ULA%/64}1/64"
		echo "ip6 nd loop0 prefix $LAN_ULA 86400 14400"
	fi
	echo
	echo "# NAT44-EI：只翻译从 WAN 发出的流量"
	echo "nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384"
	# 和 RK3588 开发板一样缩短 TCP 会话的回收时间（VPP 默认已建立 7440 秒、握手和关闭中 240 秒），
	# 空闲连接不会长期占着会话表；UDP 300 秒、ICMP 60 秒保持 VPP 默认
	echo "set nat44 ei timeout tcp-established 1800 tcp-transitory 120"
	echo "nat44 ei add interface address $wan"
	echo "set interface nat44 ei out $wan output-feature"
	[ "$IPSEC" = 1 ] && gen_ipsec_vpp "$wan"
	return 0
}

# IPsec 服务器的 VPP 侧。命名空间由 vpp-router-ctl prep 在 VPP 启动前建好，
# 其中与 WAN 同名的接口上的地址由 vpp-router-ctl post（或 ipsec）按 VPP 的 WAN 地址设置
gen_ipsec_vpp() {
	local wan=$1 tap=tap$IPSEC_TAP_ID
	echo
	echo "# IPsec 服务器：charon 在命名空间 $IPSEC_NS，接口 $wan 与 VPP 的 WAN 同名（kernel-vpp 按名字找接口）"
	echo "create tap id $IPSEC_TAP_ID host-ns $IPSEC_NS host-if-name $wan host-ip4-addr 10.63.40.2/30 host-ip6-addr fd42:1111:2222:40::2/64 host-mtu-size 1500"
	echo "set interface ip address $tap 10.63.40.1/30"
	echo "set interface ip address $tap fd42:1111:2222:40::1/64"
	echo "set interface mtu packet 1500 $tap"
	echo "set interface state $tap up"
	echo "set interface rx-mode $tap interrupt"
	echo "ip6 nd $tap ra-suppress"
	echo "# UDP 4500 上以 4 个 0 开头的 IKE 报文和 UDP 500 交给命名空间，ESP 留在 VPP"
	echo "ipsec ike punt enable"
	echo "set punt udp 500"
	echo "set punt ip6 udp 500"
	echo "ip punt redirect rx $wan via 10.63.40.2 $tap"
	echo "ip6 punt redirect rx $wan via fd42:1111:2222:40::2 $tap"
	echo "# IKE 端口不做 NAT，charon 的回包保持 WAN 地址和端口"
	echo "nat44 ei add identity mapping external $wan udp 500"
	echo "nat44 ei add identity mapping external $wan udp 4500"
	echo "# 解密后的流量以 $tap 为接收接口再走路由和 NAT，不被当成从 WAN 进来的"
	echo "ipsec cleartext ingress $tap"
}

gen_env() {
	local i kind target_mb pages
	target_mb=512
	[ "$MEM_MB" -lt 2000 ] && target_mb=256
	pages=0
	if [ "$HUGE_KB" -gt 0 ] && has_kind dpdk mlx; then pages=$(((target_mb * 1024 + HUGE_KB - 1) / HUGE_KB)); fi
	echo "# vpp-router-ctl 读取的设置，由 vpp-router-install.sh 生成"
	echo "PREFIX=$PREFIX"
	echo "KMOD_DIR_BASE=updates/vpp-router"
	echo "UIO=$UIO"
	echo "NOIOMMU=$NOIOMMU"
	echo "HUGE_KB=$HUGE_KB"
	echo "HUGEPAGES=$pages"
	echo "HOST_TAP=$HOST_TAP"
	echo "HOST_CIDR=$HOST_CIDR"
	echo "HOST_GW=$LAN_GW"
	echo "HOST_DEFAULT=$HOST_DEFAULT"
	echo "WAN_TRUNK=${WAN_TRUNK:-0}"
	echo "WAN_VLAN=$WAN_VLAN"
	echo "LAN_VLAN=$LAN_VLAN"
	echo "IPV6_PD=${IPV6_PD:-0}"
	echo "LAN_ULA=${LAN_ULA:-}"
	echo "PLAT_KMOD=${PLAT_KMOD:-}"
	echo "RX_MODE=${RX_MODE:-polling}"
	echo "IPSEC=$IPSEC"
	echo "IPSEC_NS=$IPSEC_NS"
	echo "IPSEC_WAN=$([ "$IPSEC" = 1 ] && ipsec_wan_name)"
	echo "# 角色 PCI 内核接口名 接入方式 VPP接口名"
	echo "NICS=("
	for i in "${SEL[@]}"; do
		kind=${N_KIND[i]}
		printf '  "%s %s %s %s %s"\n' "$([ "$i" = "$WAN_NIC" ] && echo wan || echo lan)" "${N_PCI[i]}" "${N_IF[i]}" \
			"$kind" "${V_NAME[i]}"
	done
	echo ")"
}

gen_ipv6_sysctl() {
	[ "${IPV6_PD:-0}" = 1 ] || [ -n "${LAN_ULA:-}" ] || return 0
	echo "# 由 vpp-router-install.sh 生成；LAN 的 IPv6 RA/SLAAC（委派前缀或 ULA）"
	echo "net.ipv6.conf.vpp-host.accept_ra = 2"
	echo "net.ipv6.conf.vpp-host.autoconf = 1"
}

# 参数：暂存目录（安装时先写进暂存目录，和其他文件一起记入清单）
write_ctl() {
	local root=${1:-}
	mkdir -p "$root$PREFIX/sbin"
	cat >"$root$CTL" <<'CTL'
#!/usr/bin/env bash
# vpp-router-ctl prep|post|release|restore|rollback|confirm|status|ipsec
set -Eeuo pipefail
CONF=/etc/vpp
STATE=/var/lib/vpp-router
# shellcheck disable=SC1091
. "$CONF/router.env"
VPPCTL="$PREFIX/bin/vppctl -s /run/vpp/cli.sock"
# 平台内核模块由本服务加载的标记；/run/vpp 是服务的 RuntimeDirectory，停止时会被删除
OWNER=/run/vpp-router/kmod-owned

log() { echo "vpp-router-ctl: $*" >&2; }

has_kind() {
	local line role pci ifc kind vname
	for line in "${NICS[@]}"; do
		read -r role pci ifc kind vname <<<"$line"
		[ "$kind" = "$1" ] && return 0
	done
	return 1
}

nm_managed() {
	if command -v nmcli >/dev/null && nmcli -t general status >/dev/null 2>&1; then
		nmcli device set "$1" managed "$2" 2>/dev/null || true
	fi
}
pcidrv() {
	if [ -e "/sys/bus/pci/devices/$1/driver" ]; then basename "$(readlink -f "/sys/bus/pci/devices/$1/driver")"; else echo none; fi
}

bind() {
	local pci=$1 drv=$2 net cur
	cur=$(pcidrv "$pci")
	[ "$cur" = "$drv" ] && return 0
	for net in /sys/bus/pci/devices/"$pci"/net/*; do
		[ -e "$net" ] && ip link set dev "${net##*/}" down 2>/dev/null || true
	done
	[ "$cur" != none ] && echo "$pci" >"/sys/bus/pci/devices/$pci/driver/unbind"
	echo "$drv" >"/sys/bus/pci/devices/$pci/driver_override"
	echo "$pci" >/sys/bus/pci/drivers_probe
	[ "$(pcidrv "$pci")" = "$drv" ] || { log "$pci 无法绑定到 $drv"; return 1; }
}

prep() {
	modprobe tun 2>/dev/null || true
	modprobe vhost_net 2>/dev/null || true
	# VPP 在命名空间里建 IPsec 的 TAP，命名空间要先存在
	if [ "${IPSEC:-0}" = 1 ] && [ ! -e "/run/netns/$IPSEC_NS" ]; then ip netns add "$IPSEC_NS"; fi
	[ -e /dev/vhost-net ] || log "没有 /dev/vhost-net，VPP 无法创建 TAP（需要内核 vhost_net）"
	if [ "$HUGEPAGES" -gt 0 ]; then
		local nr=/sys/kernel/mm/hugepages/hugepages-${HUGE_KB}kB/nr_hugepages
		if [ -w "$nr" ] && [ "$(cat "$nr")" -lt "$HUGEPAGES" ]; then
			echo "$HUGEPAGES" >"$nr"
			[ "$(cat "$nr")" -ge "$HUGEPAGES" ] || log "大页只分配到 $(cat "$nr")/$HUGEPAGES 页"
		fi
		mkdir -p /dev/hugepages
		mountpoint -q /dev/hugepages || mount -t hugetlbfs nodev /dev/hugepages
	fi
	if has_kind dpdk; then
		if [ "$UIO" = vfio-pci ]; then
			modprobe vfio-pci
			[ "$NOIOMMU" = 1 ] && echo 1 >/sys/module/vfio/parameters/enable_unsafe_noiommu_mode
		else
			modprobe "$UIO"
		fi
	fi
	local line role pci ifc kind vname
	for line in "${NICS[@]}"; do
		read -r role pci ifc kind vname <<<"$line"
		case $kind in
		dpdk) bind "$pci" "$UIO" ;;
		mlx)
			# mlx4/mlx5 PMD 经 ibverbs 使用网卡，需要 ib_uverbs 和对应的 IB 驱动
			case $(pcidrv "$pci") in
			mlx4_core)
				modprobe mlx4_ib 2>/dev/null || true
				local mgm
				mgm=$(cat /sys/module/mlx4_core/parameters/log_num_mgm_entry_size 2>/dev/null || echo -)
				if [ "$mgm" != -1 ]; then
					log "mlx4_core 的 log_num_mgm_entry_size 是 ${mgm}，mlx4 PMD 需要 -1（/etc/modprobe.d/vpp-router-mlx4.conf，重新加载驱动或重启后生效）"
					return 1
				fi ;;
			mlx5_core) modprobe mlx5_ib 2>/dev/null || true ;;
			esac
			modprobe ib_uverbs 2>/dev/null || true
			# 关闭以太网流控：网卡收不过来时发 PAUSE，交换机缓冲占满后丢包更多，
			# ConnectX-3 超过收包上限后吞吐从 7.1 跌到 4.6 Mpps；关闭后保持在 7.4–7.9 Mpps。
			# 原设置记在标记文件里，release 时恢复
			mkdir -p /run/vpp-router
			if [ ! -e "/run/vpp-router/pause-$ifc" ]; then
				local prx ptx
				read -r prx ptx < <(ethtool -a "$ifc" 2>/dev/null | awk '$1 == "RX:" {r = $2} $1 == "TX:" {t = $2} END {print r, t}')
				if [ "$prx" = on ] || [ "$ptx" = on ]; then
					if ethtool -A "$ifc" rx off tx off 2>/dev/null; then
						echo "$prx $ptx" >"/run/vpp-router/pause-$ifc"
					else
						log "无法关闭 $ifc 的流控（PAUSE），超载时吞吐可能下降"
					fi
				fi
			fi
			ip link set dev "$ifc" up ;;
		afp)
			nm_managed "$ifc" no
			ip addr flush dev "$ifc"
			ethtool -K "$ifc" rxvlan off txvlan off 2>/dev/null || true
			mkdir -p /run/vpp-router
			# GRO 聚合的包交给 AF_PACKET/VPP 后可能造成大量 TCP 包丢失。
			# 只记录由本服务关闭的设置，停止时恢复原状态。
			if [ ! -e "/run/vpp-router/gro-$ifc" ] &&
				ethtool -k "$ifc" 2>/dev/null | grep -q '^generic-receive-offload: on'; then
				if ethtool -K "$ifc" gro off 2>/dev/null; then
					touch "/run/vpp-router/gro-$ifc"
				else
					log "无法关闭 $ifc 的 GRO，AF_PACKET 性能可能受影响"
				fi
			fi
			if [ ! -e "/run/vpp-router/promisc-$ifc" ] &&
				! ip -o link show dev "$ifc" | grep -q '<[^>]*PROMISC'; then
				ip link set dev "$ifc" promisc on
				touch "/run/vpp-router/promisc-$ifc"
			fi
			ip link set dev "$ifc" up ;;
		plat) load_kmod "$ifc" ;;
		esac
	done
}

# 平台网卡：Linux 保留板级电源、时钟和 PHY，helper 模块打开后独占收发和 DMA
load_kmod() {
	local ifc=$1 ko
	ko=/lib/modules/$(uname -r)/${KMOD_DIR_BASE:-updates/vpp-router}/$PLAT_KMOD.ko
	[ -f "$ko" ] || { log "没有内核 $(uname -r) 的 $PLAT_KMOD.ko，请重新运行 vpp-router-install.sh --config-only"; return 1; }
	if [ -e "/sys/module/$PLAT_KMOD" ]; then
		[ -e "$OWNER" ] || { log "$PLAT_KMOD 已由其他程序加载，拒绝复用"; return 1; }
		rmmod "$PLAT_KMOD"
	fi
	nm_managed "$ifc" no
	ip addr flush dev "$ifc"
	ip link set dev "$ifc" up
	insmod "$ko"
	mkdir -p "$(dirname "$OWNER")"
	echo vpp-router.service >"$OWNER"
}

# 服务停止后卸载本服务加载的平台模块；模块释放时把网卡还给 Linux
release() {
	local line role pci ifc kind vname marker
	for line in "${NICS[@]}"; do
		read -r role pci ifc kind vname <<<"$line"
		marker=/run/vpp-router/pause-$ifc
		if [ "$kind" = mlx ] && [ -e "$marker" ]; then
			local prx ptx
			read -r prx ptx <"$marker"
			ethtool -A "$ifc" rx "$prx" tx "$ptx" || return 1
			rm -f "$marker"
		fi
		[ "$kind" = afp ] || continue
		marker=/run/vpp-router/promisc-$ifc
		if [ -e "$marker" ]; then
			ip link set dev "$ifc" promisc off || return 1
			rm -f "$marker"
		fi
		marker=/run/vpp-router/gro-$ifc
		if [ -e "$marker" ]; then
			ethtool -K "$ifc" gro on || return 1
			rm -f "$marker"
		fi
	done
	if [ -e "$OWNER" ] && [ -n "${PLAT_KMOD:-}" ] && [ -e "/sys/module/$PLAT_KMOD" ]; then
		rmmod "$PLAT_KMOD" || { log "无法卸载 $PLAT_KMOD"; return 1; }
	fi
	rm -f "$OWNER"
}

post() {
	local i
	for i in $(seq 60); do
		$VPPCTL show version >/dev/null 2>&1 && break
		sleep 0.5
	done
	$VPPCTL show version >/dev/null 2>&1 || { log "VPP 30 秒内没有响应"; return 1; }
	[ "${RX_MODE:-polling}" = interrupt ] && set_interrupt
	# WAN 用 DHCP 时地址可能还没拿到；失败不影响 VPP，地址到了以后执行 vpp-router-ctl ipsec
	[ "${IPSEC:-0}" = 1 ] && { ipsec_ns 30 || true; }
	[ -n "$HOST_CIDR" ] || return 0
	for i in $(seq 60); do [ -e "/sys/class/net/$HOST_TAP" ] && break; sleep 0.5; done
	[ -e "/sys/class/net/$HOST_TAP" ] || { log "没有出现 $HOST_TAP"; return 1; }
	if [ "${IPV6_PD:-0}" = 1 ] || [ -n "${LAN_ULA:-}" ]; then
		# all.forwarding=1 时 accept_ra=1 会被内核忽略，必须使用 accept_ra=2。
		sysctl -qw "net.ipv6.conf.$HOST_TAP.accept_ra=2" "net.ipv6.conf.$HOST_TAP.autoconf=1"
	fi
	ip link set dev "$HOST_TAP" up
	ip addr replace "$HOST_CIDR" dev "$HOST_TAP"
	# Linux 自己算校验和再交给 VPP（与 N1 验收时的配置相同）
	ethtool -K "$HOST_TAP" tx off >/dev/null 2>&1 || true
	[ "$HOST_DEFAULT" = 1 ] && ip route replace default via "$HOST_GW" dev "$HOST_TAP"
	return 0
}

# 逐个把网卡改为 adaptive 收包：流量小时等中断，流量大时 VPP 自动转为轮询。
# PMD 不支持收包中断时 VPP 拒绝或仍显示 polling，此时保持轮询
set_interrupt() {
	local line role pci ifc kind vname placement n attempt
	for line in "${NICS[@]}"; do
		read -r role pci ifc kind vname <<<"$line"
		[ -n "$vname" ] || continue
		case $kind in dpdk|mlx|afp|plat) ;; *) continue ;; esac
		# CLI may become available before startup-config brings the interface up.
		for attempt in {1..20}; do
			$VPPCTL set interface rx-mode "$vname" adaptive >/dev/null 2>&1 || true
			placement=$($VPPCTL show interface rx-placement 2>/dev/null || true)
			n=$(grep -cE "^[[:space:]]+$vname queue [0-9]+ \(polling\)" <<<"$placement" || true)
			if [ "${n:-0}" -eq 0 ] && grep -qE "^[[:space:]]+$vname queue [0-9]+ \(adaptive\)" <<<"$placement"; then
				break
			fi
			[ "$attempt" -eq 20 ] || sleep 0.5
		done
		if [ "${n:-0}" -gt 0 ] || ! grep -qE "^[[:space:]]+$vname queue [0-9]+ \(adaptive\)" <<<"$placement"; then
			log "$vname 不支持收包中断，保持轮询"
			$VPPCTL set interface rx-mode "$vname" polling >/dev/null 2>&1 || true
		else
			log "$vname 使用 adaptive 收包"
		fi
	done
	return 0
}

restore() {
	systemctl stop vpp-router-dnsmasq.service 2>/dev/null || true
	if [ "$(systemctl show vpp-router.service -p LoadState --value 2>/dev/null)" != not-found ]; then
		systemctl stop vpp-router.service || return 1
	fi
	release || return 1
	if command -v nmcli >/dev/null; then
		local line role p name kind vname
		for line in "${NICS[@]}"; do
			read -r role p name kind vname <<<"$line"
			case $kind in afp|plat) nm_managed "$name" yes ;; esac
		done
	fi
	[ -r "$STATE/nics.orig" ] || { restore_dnsmasq; return 0; }
	local pci drv ifc cur
	while read -r pci drv ifc; do
		[ -e "/sys/bus/pci/devices/$pci" ] || continue
		cur=$(pcidrv "$pci")
		echo >"/sys/bus/pci/devices/$pci/driver_override"
		[ "$cur" = "$drv" ] && continue
		[ "$cur" != none ] && echo "$pci" >"/sys/bus/pci/devices/$pci/driver/unbind"
		if [ "$drv" != none ] && [ "$drv" != - ] && [ -e "/sys/bus/pci/drivers/$drv" ]; then
			echo "$pci" >"/sys/bus/pci/drivers/$drv/bind" 2>/dev/null || echo "$pci" >/sys/bus/pci/drivers_probe
		else
			echo "$pci" >/sys/bus/pci/drivers_probe
		fi
		log "$pci → $(pcidrv "$pci")（${ifc}）"
	done <"$STATE/nics.orig"
	restore_dnsmasq
}

# 网卡还给 Linux 后，系统 dnsmasq 原来的配置重新有效
# 命名空间 $IPSEC_NS 里与 WAN 同名的接口：WAN 的 IPv4 地址（/32）和一个全局 IPv6 地址（/128）给 charon 绑定，
# 默认路由经 TAP 回到 VPP，源地址用 TAP 的地址，其他连接（DNS、CRL）的回包才能回到命名空间。
# 参数：等待 VPP 的 WAN 地址和命名空间接口的秒数
ipsec_ns() {
	local wait=${1:-0} ns=$IPSEC_NS dev=$IPSEC_WAN i out a a4= a6= old
	for ((i = 0; i <= wait * 2; i++)); do
		out=$($VPPCTL show interface address 2>/dev/null |
			awk -v d="$dev" '$0 ~ "^"d" \\(" {f=1; next} /^[^ ]/ {f=0} f && $1 == "L3" {print $2}' || true)
		a4=$(grep -m1 -E '^[0-9]+\.' <<<"$out" | cut -d/ -f1 || true)
		a6=$(grep -m1 -vE '^[0-9]+\.|^fe80' <<<"$out" | cut -d/ -f1 || true)
		if [ -n "$a4" ] && ip -n "$ns" link show "$dev" >/dev/null 2>&1; then break; fi
		[ "$i" -lt $((wait * 2)) ] && sleep 0.5
	done
	if [ -z "$a4" ] || ! ip -n "$ns" link show "$dev" >/dev/null 2>&1; then
		log "IPsec：VPP 的 $dev 还没有 IPv4 地址，或命名空间 $ns 里没有 $dev；地址到了以后执行 $0 ipsec"
		return 1
	fi
	ip -n "$ns" link set lo up
	ip -n "$ns" link set "$dev" up
	# 地址由这里设置，不接受 RA。接口名里的点在 /proc 路径中保持原样
	ip netns exec "$ns" sh -c "echo 0 >/proc/sys/net/ipv6/conf/$dev/accept_ra; echo 0 >/proc/sys/net/ipv6/conf/$dev/autoconf"
	# 去掉以前的 WAN 地址（/32、/128），TAP 本身的地址保留
	for old in $(ip -n "$ns" -o addr show dev "$dev" scope global | awk '{print $4}' | grep -E '/(32|128)$' || true); do
		if [ "$old" = "$a4/32" ] || { [ -n "$a6" ] && [ "$old" = "$a6/128" ]; }; then continue; fi
		ip -n "$ns" addr del "$old" dev "$dev"
	done
	ip -n "$ns" addr replace "$a4/32" dev "$dev"
	ip -n "$ns" route replace default via 10.63.40.1 dev "$dev" src 10.63.40.2
	if [ -n "$a6" ]; then
		ip -n "$ns" -6 addr replace "$a6/128" dev "$dev" nodad
		ip -n "$ns" -6 route replace default via fd42:1111:2222:40::1 dev "$dev" src fd42:1111:2222:40::2
	fi
	log "IPsec：命名空间 $ns 的 $dev 使用 $a4${a6:+ 和 $a6}"
}

# 安装时停用的系统 dnsmasq：网卡还给 Linux 后恢复原来的状态
restore_dnsmasq() {
	if [ -e "$STATE/dnsmasq-orig/manifest.json" ]; then
		# 2026-11 以前的安装修改过系统 dnsmasq 的配置
		python3 -I "$PREFIX/libexec/vpp-router/dnsmasq-lan.py" restore-legacy --state "$STATE" >&2 || true
		systemctl try-restart dnsmasq.service 2>/dev/null || log "系统 dnsmasq 重启失败"
	fi
	[ -r "$STATE/system-dnsmasq" ] || return 0
	local enabled active
	read -r enabled active <"$STATE/system-dnsmasq"
	systemctl unmask dnsmasq.service >/dev/null 2>&1 || true
	if [ "$enabled" = enabled ]; then systemctl enable dnsmasq.service >/dev/null 2>&1 || log "无法重新启用系统 dnsmasq"; fi
	if [ "$active" = active ]; then systemctl start dnsmasq.service 2>/dev/null || log "系统 dnsmasq 启动失败"; fi
	rm -f "$STATE/system-dnsmasq"
	log "已恢复系统 dnsmasq（原来 ${enabled}、${active}）"
}

case ${1:-} in
prep) prep ;;
post) post ;;
release) release ;;
restore) restore ;;
# 自动回退：只停止、禁用并还原网卡，绝不重新启动 VPP
rollback) systemctl disable vpp-router.service vpp-router-dnsmasq.service vpp-router-pd-sync.service 2>/dev/null || true; restore ;;
confirm)
	systemctl stop vpp-router-rollback.timer 2>/dev/null || true
	systemctl enable vpp-router.service
	[ -e /etc/systemd/system/vpp-router-dnsmasq.service ] && systemctl enable vpp-router-dnsmasq.service
	[ -e /etc/systemd/system/vpp-router-pd-sync.service ] && systemctl enable vpp-router-pd-sync.service
	log "已取消自动回退，并设为开机启动" ;;
status)
	systemctl --no-pager status vpp-router.service || true
	$VPPCTL show interface address 2>/dev/null || true ;;
# WAN 地址变化后（例如 DHCP 换了地址）重新设置 IPsec 命名空间的地址
ipsec)
	[ "${IPSEC:-0}" = 1 ] || { log "安装时没有选择 IPsec 服务器"; exit 1; }
	ipsec_ns 0 ;;
*) echo "用法: $0 prep|post|release|restore|rollback|confirm|status|ipsec" >&2; exit 2 ;;
esac
CTL
	chmod 0755 "$root$CTL"
	install -D -m 0755 "$LANTOOL" "$root$LIBEXEC/dnsmasq-lan.py"
}

write_units() {
	local env= platform_prep= i driver
	[ -d "$LIBDIR/dpdk-glue" ] && env="Environment=MLX5_GLUE_PATH=$LIBDIR/dpdk-glue MLX4_GLUE_PATH=$LIBDIR/dpdk-glue"
	if [ "${RTL_PLATFORM:-0}" = 1 ]; then
		env+=$'\nEnvironment=R8169_DMA_NONCOHERENT=1'
		for i in "${SEL[@]}"; do
			[ "${N_PMD[i]:-}" = r8169 ] || continue
			driver=$(awk -v pci="${N_PCI[i]}" '$1 == pci {print $2; exit}' "$STATE/nics.orig")
			case $driver in r8125|r8169) ;; *) die "缺少 ${N_PCI[i]} 的原内核驱动记录，不能执行非一致性 DMA 设备初始化" ;; esac
			platform_prep+="ExecStartPre=/usr/bin/python3 $LIBEXEC/rtl8125-init.py --unit $SERVICE.service --pci ${N_PCI[i]} --kernel-driver $driver"$'\n'
		done
	fi
	cat >"$UNIT_DIR/$SERVICE.service" <<EOF
[Unit]
Description=VPP router (VPP $VPP_TAG, DPDK $DPDK_VERSION)
After=systemd-modules-load.service
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=simple
$env
ExecStartPre=$CTL prep
$platform_prep
ExecStart=$PREFIX/bin/vpp -c $STARTUP
ExecStartPost=$CTL post
ExecStopPost=$CTL release
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
	if [ "$DNSMASQ" = 1 ]; then
		local dnsmasq
		dnsmasq=$(command -v dnsmasq || echo /usr/sbin/dnsmasq)
		cat >"$UNIT_DIR/$DNS_SERVICE.service" <<EOF
[Unit]
Description=dnsmasq for the VPP router LAN
BindsTo=$SERVICE.service
After=$SERVICE.service

[Service]
ExecStart=$dnsmasq --keep-in-foreground --conf-file=$CONF/dnsmasq.conf --pid-file=
# SIGHUP 让 dnsmasq 重新读 dhcp-hostsfile（静态分配），不中断 DHCP 和 DNS
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3

[Install]
WantedBy=$SERVICE.service
EOF
	else
		rm -f "$UNIT_DIR/$DNS_SERVICE.service"
	fi
	if [ "${IPV6_PD:-0}" = 1 ]; then
		cat >"$UNIT_DIR/$PD_SERVICE.service" <<EOF
[Unit]
Description=Publish delegated IPv6 prefixes on the VPP LAN
BindsTo=$SERVICE.service
After=$SERVICE.service
PartOf=$SERVICE.service

[Service]
RuntimeDirectory=vpp-router-pd-sync
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=restart
Environment=PATH=$PREFIX/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/bin/python3 $LIBEXEC/pd-sync.py --config $CONF/router-pd-sync.json
Restart=on-failure
RestartSec=2

[Install]
WantedBy=$SERVICE.service
EOF
	else
		systemctl disable --now "$PD_SERVICE.service" 2>/dev/null || true
		rm -f "$UNIT_DIR/$PD_SERVICE.service"
	fi
	write_panel_units
	systemctl daemon-reload
}

# 面板和它转发的服务。它们都不要求 VPP 先启动：各自等 VPP 的 socket，跟随 VPP 重启
write_panel_units() {
	panel_wanted && [ -x "$PREFIX/bin/vpp-monitor" ] || return 0
	cat >"$UNIT_DIR/vpp-monitor.service" <<EOF
[Unit]
Description=VPP router management panel
# 监听 VPP 创建的 $HOST_TAP 上的地址，所以开机时排在 VPP 后面；地址还没有时失败重试
After=$SERVICE.service

[Service]
ExecStart=$PREFIX/bin/vpp-monitor --listen $(panel_listen):$PANEL_PORT --vpn-names $CONF/wireguard/names.json
StateDirectory=vpp-monitor
StateDirectoryMode=0700
Restart=always
RestartSec=5
Environment=GOGC=50 GOMEMLIMIT=48MiB
Nice=10
MemoryMax=96M
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
EOF
	local dhcp=
	# LAN 的 DHCP 在面板的“局域网”页管理：地址池、静态分配和设备
	[ "$DNSMASQ" = 1 ] && dhcp=" --dnsmasq-conf $CONF/dnsmasq.conf --dnsmasq-unit $DNS_SERVICE.service"
	cat >"$UNIT_DIR/vpp-interfaces.service" <<EOF
[Unit]
Description=VPP interface changes from the management panel
# 改动在这里等待确认，没确认就撤销，所以不随 VPP 停止

[Service]
ExecStart=$PREFIX/bin/vpp-interfaces --vpp-config $STARTUP --vpp-unit $SERVICE.service$dhcp
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
	cat >"$UNIT_DIR/vpp-wireguard.service" <<EOF
[Unit]
Description=VPP WireGuard configurations
# VPP 重启后由它恢复已启动的配置，它自己发现 VPP 重启

[Service]
ExecStart=$PREFIX/bin/vpp-wireguard --vpp-unit $SERVICE.service --nat-interface $(wan_if)
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
	cat >"$UNIT_DIR/vpp-firewall.service" <<EOF
[Unit]
Description=VPP WAN firewall: port forwards, router ports, ping and IPv6 inbound
# VPP 重启后由它恢复规则，它自己发现 VPP 重启

[Service]
ExecStart=$PREFIX/bin/vpp-firewall --vpp-unit $SERVICE.service
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
	# 平台限制 worker 数（比如 N1 只能单线程）时告诉 vpp-system，面板不让加
	local max_workers=
	if [ -n "${PLAT:-}" ] && [ -n "${PLAT_MAX_WORKERS:-}" ]; then max_workers=" --max-workers $PLAT_MAX_WORKERS"; fi
	cat >"$UNIT_DIR/vpp-system.service" <<EOF
[Unit]
Description=VPP system settings and maintenance: threads, DPDK cards, RX modes and placement, NAT44-EI, CPU governors, services, logs, network tests, backup
# 改线程、加网卡和改 NAT 会话表时重启 VPP 并等待确认，所以不随 VPP 停止；VPP 重启后由它恢复收包设置
# 加的网卡写进 router.env 的 NICS（vpp-router-ctl prep 绑定），原驱动记入 nics.orig（--restore 交还）

[Service]
ExecStart=$PREFIX/bin/vpp-system --vpp-config $STARTUP --vpp-unit $SERVICE.service$max_workers --router-env $CONF/router.env --nics-orig $STATE/nics.orig --pci-ids $IDS_FILE --unit-dir $UNIT_DIR
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
	if [ -x "$PREFIX/bin/gate-admin" ]; then
		cat >"$UNIT_DIR/gate-admin.service" <<EOF
[Unit]
Description=Gate admin service for the management panel
# 和 Gate 分开：它要重启 Gate，Gate 起不来时还要恢复旧配置

[Service]
ExecStart=$PREFIX/bin/gate-admin
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
	fi
	write_singbox
	if [ -n "$PANEL_PW" ]; then
		mkdir -p -m 700 "$PANEL_STATE"
		printf '%s\n' "$PANEL_PW" | "$PREFIX/bin/vpp-monitor" --set-password --auth-file "$PANEL_STATE/auth.json" >/dev/null 2>&1 ||
			die "设置面板密码失败"
		PANEL_PW=
	fi
	return 0
}

# sing-box 的入口（每次生成）、上游（只在第一次写）和服务。入口的端口和地址池与 Gate 的代理规则一致
write_singbox() {
	[ "$WANT_SINGBOX" = 1 ] && [ -x "$PREFIX/bin/sing-box" ] || return 0
	local v6=()
	if [ "${IPV6_PD:-0}" = 1 ] || [ -n "${LAN_ULA:-}" ]; then v6=(--ipv6); fi
	python3 -I "$SINGBOX_GEN" entry --dir "$SINGBOX_DIR" --gate-config "$GATE_CONFIG" --lan-address "$(panel_listen)" "${v6[@]}" \
		--socks-port "$SOCKS_PORT" --tproxy-port "$TPROXY_PORT" --fake-dns-port "$FAKEDNS_PORT" ||
		die "生成 sing-box 入口配置失败"
	if [ ! -e "$SINGBOX_DIR/upstream.json" ]; then
		local args=(upstream --dir "$SINGBOX_DIR" --type "${SB_TYPE:-none}")
		case $SB_TYPE in
		socks) args+=(--server "$SB_SERVER" --port "$SB_PORT" --username "$SB_USER") ;;
		trojan) args+=(--server "$SB_SERVER" --port "$SB_PORT" --sni "$SB_SNI") ;;
		file) args+=(--file "$SB_FILE") ;;
		esac
		printf '%s\n' "$SB_PASS" | python3 -I "$SINGBOX_GEN" "${args[@]}" --password-stdin || die "生成 sing-box 上游配置失败"
	fi
	SB_PASS=
	if ! "$PREFIX/bin/sing-box" check -C "$SINGBOX_DIR"; then
		die "sing-box 不接受 $SINGBOX_DIR 里的配置；上游有误时修改 upstream.json 后重新运行"
	fi
	note "$SINGBOX_DIR/entry.json      sing-box 代理入口（本脚本生成，重新运行会覆盖）"
	note "$SINGBOX_DIR/upstream.json   sing-box 上游（标签 proxy 的出站或 endpoint，本脚本不再改动）"
	write_singbox_units
}

# 也供已有代理配置的迁移使用，生成标准服务而不重写入口或上游。
write_singbox_units() {
	cat >"$UNIT_DIR/$SINGBOX_UNIT.service" <<EOF
[Unit]
Description=sing-box proxy entry for the LAN (TPROXY, Fake-IP DNS, SOCKS5)
# SOCKS5 listens on the $HOST_TAP address, which exists once VPP has started
After=network-online.target $SERVICE.service
Wants=network-online.target

[Service]
ExecStartPre=$PREFIX/bin/sing-box check -C $SINGBOX_DIR
ExecStart=$PREFIX/bin/sing-box run -C $SINGBOX_DIR
StateDirectory=vpp-router-sing-box
StateDirectoryMode=0700
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
	if [ -x "$PREFIX/bin/vpp-proxy" ]; then
		cat >"$UNIT_DIR/vpp-proxy.service" <<EOF
[Unit]
Description=sing-box upstream changes from the management panel

[Service]
ExecStart=$PREFIX/bin/vpp-proxy --sing-box-dir $SINGBOX_DIR --unit $SINGBOX_UNIT.service --binary $PREFIX/bin/sing-box
StateDirectory=vpp-proxy
StateDirectoryMode=0700
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
	fi
}

# 启用并（重新）启动面板服务，新装的程序随之生效。gate-admin 只在 Gate 装好后才有事可做
start_panel() {
	panel_wanted && [ -e "$UNIT_DIR/vpp-monitor.service" ] || return 0
	local units=(vpp-monitor vpp-interfaces vpp-wireguard vpp-firewall vpp-system)
	if gate_present && [ -e "$UNIT_DIR/gate-admin.service" ]; then units+=(gate-admin); fi
	systemctl enable "${units[@]}" >/dev/null 2>&1
	systemctl restart "${units[@]}" || warn "面板服务启动失败，查看 journalctl -u vpp-monitor 等"
	if [ -e "$UNIT_DIR/$SINGBOX_UNIT.service" ]; then
		systemctl enable "$SINGBOX_UNIT" >/dev/null 2>&1
		systemctl restart "$SINGBOX_UNIT" || warn "sing-box 启动失败，查看 journalctl -u $SINGBOX_UNIT"
	fi
	if [ -e "$UNIT_DIR/vpp-proxy.service" ]; then
		systemctl enable vpp-proxy >/dev/null 2>&1
		systemctl restart vpp-proxy || warn "vpp-proxy 启动失败，查看 journalctl -u vpp-proxy"
	fi
	note "面板 https://$(panel_listen):${PANEL_PORT}/，用户 admin（自签证书，第一次打开时浏览器会提示）"
}

# 已有的 Gate 配置补上 LAN 的 IPv6：固定 ULA 写进 lan_prefixes，loop0 写进 lan_interfaces
# （Gate 跟随它上面会变的委派前缀）。已有的或重叠的不动，别的内容不碰
gate_lan_ipv6() {
	local out
	out=$(python3 -I - "$GATE_CONFIG" "${LAN_ULA:-}" <<'PY'
import ipaddress, json, os, sys
path, ula = sys.argv[1], sys.argv[2]
with open(path) as f:
    doc = json.load(f)
changed = []
lans = doc.get('lan_prefixes')
if ula and isinstance(lans, list):
    network = ipaddress.ip_network(ula)
    if not any(isinstance(x, str) and ipaddress.ip_network(x, strict=False).overlaps(network) for x in lans):
        lans.append(str(network))
        changed.append(f'lan_prefixes 加上 {network}')
if 'lan_interfaces' not in doc:
    doc['lan_interfaces'] = ['loop0']
    changed.append('lan_interfaces 设为 loop0')
if changed:
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        f.write(json.dumps(doc, indent=2, ensure_ascii=False) + '\n')
    os.chmod(tmp, os.stat(path).st_mode & 0o7777)
    os.replace(tmp, path)
    print('；'.join(changed))
PY
) || { warn "没能给 $GATE_CONFIG 补上 LAN 的 IPv6"; return 0; }
	[ -n "$out" ] || return 0
	note "$GATE_CONFIG：$out"
	# 设备同步在 Gate 启动时做，正在运行的要重启才用上
	systemctl try-restart "$GATE_UNIT" 2>/dev/null || warn "重启 Gate 失败，查看 journalctl -u $GATE_UNIT"
}

# Gate 的 install.py 会问出口和局域网，并探测运行中的 VPP，所以在 VPP 启动后执行
install_gate() {
	# 已经装了 Gate 的，这次不管选没选安装都补上
	[ -e "$GATE_CONFIG" ] && gate_lan_ipv6
	[ "$WANT_GATE" = 1 ] || return 0
	local cmd=(python3 -I "$REPO/tools/vpp-egress-gate/install.py" --binary "$SRC/tools-bin/vpp-egress-gate")
	if [ ! -e "$GATE_CONFIG" ]; then
		# 客户端网段就是 LAN：IPv4 网段和固定 ULA，不用再问
		cmd+=(--vpp-service "$SERVICE.service" --listen-port "$GATE_DNS_PORT" --lan-prefix "$(python3 -I -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$LAN_CIDR")")
		[ -n "${LAN_ULA:-}" ] && cmd+=(--lan-prefix "$LAN_ULA")
	fi
	if [ ! -e "$GATE_CONFIG" ] && [ -e "$SINGBOX_DIR/entry.json" ]; then
		local dns port
		read -r dns port < <(python3 -I "$SINGBOX_GEN" endpoints --tproxy-port "$TPROXY_PORT" --fake-dns-port "$FAKEDNS_PORT")
		cmd+=(--tproxy "$port" --fake-dns "$dns")
	fi
	if ! systemctl is-active --quiet "$SERVICE"; then
		note "VPP 没有运行，没有安装 Gate。启动 VPP 后执行：$(printf '%q ' "${cmd[@]}")"
		note "然后重新运行一次本脚本（不加 --config-only，编译结果会复用），装上路由页面用的 gate-admin。"
		return 0
	fi
	echo
	info "安装 Gate"
	if ! "${cmd[@]}" </dev/tty; then
		warn "Gate 没有装好。处理后可以再执行：$(printf '%q ' "${cmd[@]}")"
		return 0
	fi
	if [ -e "$UNIT_DIR/gate-admin.service" ]; then
		systemctl enable --now gate-admin >/dev/null 2>&1 || warn "gate-admin 启动失败"
	fi
	if ask_yn "现在启动 Gate？（之后局域网的 DNS 由它处理）" y; then
		systemctl enable --now "$GATE_UNIT" || warn "Gate 启动失败，查看 journalctl -u $GATE_UNIT"
	else
		note "以后用 systemctl enable --now $GATE_UNIT 启动。"
	fi
}

# LAN 的 dnsmasq：就地更新 $CONF/dnsmasq.conf 里管理的几行，第一次时导入系统 dnsmasq 的配置并停用它
write_dnsmasq() {
	if [ -e "$STATE/dnsmasq-orig/manifest.json" ]; then
		# 2026-11 以前的安装改过系统 dnsmasq 的配置，$CONF/dnsmasq.conf 是被它引用的片段：先还原
		python3 -I "$LANTOOL" restore-legacy --state "$STATE" | sed 's/^/    /'
		if grep -qs 'vpp-lan' "$CONF/dnsmasq.conf"; then mv "$CONF/dnsmasq.conf" "$CONF/dnsmasq.conf.legacy"; fi
	fi
	[ "$DNSMASQ" = 1 ] || return 0
	local script=()
	# 面板的 vpp-interfaces 做 dhcp-script，记录客户端的主机名和请求特征，识别使用随机 MAC 的同一台设备
	[ -x "$PREFIX/bin/vpp-interfaces" ] && script=(--script "$PREFIX/bin/vpp-interfaces")
	python3 -I "$LANTOOL" set --conf "$CONF/dnsmasq.conf" --interface "$HOST_TAP" --listen "$DNS_LISTEN" \
		--range "$DHCP_START,$DHCP_END,$DHCP_MASK,$DHCP_LEASE" --router "$LAN_GW" \
		--leasefile "$STATE/dnsmasq.leases" --hostsfile "$CONF/dhcp-hosts" "${script[@]}" || die "生成 $CONF/dnsmasq.conf 失败"
	[ "$IMPORT_DNSMASQ" = 1 ] || return 0
	scan_args
	python3 -I "$LANTOOL" import "${SCAN_ARGS[@]}" --hosts "$CONF/dhcp-hosts" --leases "$STATE/dnsmasq.leases" |
		sed 's/^/    /' || warn "导入系统 dnsmasq 的配置失败，$CONF/dnsmasq.conf 只有基本配置"
	disable_system_dnsmasq
}

# 只屏蔽，不停止：VPP 启动前系统 dnsmasq 还在为原来的网卡服务，启动时由 stop_system_dnsmasq 停止
disable_system_dnsmasq() {
	local enabled active
	enabled=$(systemctl is-enabled dnsmasq.service 2>/dev/null) || true
	active=$(systemctl is-active dnsmasq.service 2>/dev/null) || true
	mkdir -p "$STATE"
	# 只记第一次：重复运行时服务已被屏蔽，不能把 masked 记成原状态
	[ -e "$SYSTEM_DNSMASQ" ] || echo "${enabled:-disabled} ${active:-inactive}" >"$SYSTEM_DNSMASQ"
	systemctl disable dnsmasq.service >/dev/null 2>&1 || true
	systemctl mask dnsmasq.service >/dev/null 2>&1 || warn "无法屏蔽 dnsmasq.service，已禁用"
	note "系统 dnsmasq 已禁用并屏蔽，启动 VPP 时停止"
}

stop_system_dnsmasq() {
	[ "$IMPORT_DNSMASQ" = 1 ] || return 0
	systemctl stop dnsmasq.service 2>/dev/null || warn "停止系统 dnsmasq 失败"
}

write_config() {
	info "写入配置 $CONF"
	mkdir -p "$CONF" "$STATE"
	printf '%s\n' "${EXTRA_PLUGINS:-}" >"$STATE/extra-plugins"
	save_ports
	local f
	for f in "${STARTUP##*/}" router.vpp router.env dnsmasq.conf router-pd-sync.json; do
		[ -e "$CONF/$f" ] || continue
		# 不是本脚本生成的文件另存一份，只存第一次
		if ! grep -q 'vpp-router-install.sh' "$CONF/$f" && [ ! -e "$STATE/$f.orig" ]; then
			cp -p "$CONF/$f" "$STATE/$f.orig"
			warn "$CONF/$f 不是本脚本生成的，原文件保存为 $STATE/$f.orig"
		fi
		cp -p "$CONF/$f" "$STATE/$f.bak"
	done
	gen_startup >"$STARTUP"
	# 其他程序追加的 exec 行（比如 Gate 的设备配置）保留；面板对接口的修改不保留，按这次的回答重新生成
	local keep=
	[ -e "$CONF/router.vpp" ] && keep=$(grep -E '^exec[[:space:]]' "$CONF/router.vpp" || true)
	[ -n "${WAN_MAC:-}" ] || WAN_MAC=$(pinned_wan_mac "$CONF/router.vpp")
	gen_router_vpp >"$CONF/router.vpp"
	if [ -n "$keep" ]; then
		printf '\n# 其他程序加入的命令，重新生成时保留\n%s\n' "$keep" >>"$CONF/router.vpp"
		note "保留了 router.vpp 里其他程序加入的 exec 行"
	fi
	gen_env >"$CONF/router.env"
	if [ "${RTL_PLATFORM:-0}" = 1 ]; then
		mkdir -p "$LIBEXEC"
		install -m 755 "$REPO/deploy/startup/vrouter-vpp-device-prep.py" "$LIBEXEC/rtl8125-init.py"
		manifest_add "$LIBEXEC/rtl8125-init.py"
	fi
	if [ "${IPV6_PD:-0}" = 1 ]; then
		local pd_script=$LIBEXEC/pd-sync.py
		if [ -e "$pd_script" ] && ! manifest_has "$pd_script"; then
			die "$pd_script 已存在且不是本脚本安装的"
		fi
		mkdir -p "$LIBEXEC"
		install -m 755 "$REPO/deploy/ipv6/pd-sync.py" "$pd_script"
		manifest_add "$pd_script"
		mkdir -p "$LIBEXEC/ipsec"
		install -m 644 "$REPO/tools/ipsec/ipsec-prefix-sync.py" "$LIBEXEC/ipsec/ipsec-prefix-sync.py"
		install -m 644 "$REPO/tools/vpp-egress-nat.py" "$LIBEXEC/vpp-egress-nat.py"
		manifest_add "$LIBEXEC/ipsec/ipsec-prefix-sync.py" "$LIBEXEC/vpp-egress-nat.py"
		python3 -I - "$CONF/router-pd-sync.json" "$(wan_if)" "$IPSEC" "$CTL" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
config = json.loads(path.read_text()) if path.exists() else {}
config.update(vpp_socket='/run/vpp/cli.sock', lan_interface='loop0',
              wan_interface=sys.argv[2], prefix_group='wan-pd', interval_seconds=2,
              ra_max_interval_seconds=10, withdraw_seconds=12,
              state_file='/run/vpp-router-pd-sync/state.json',
              generated_by='vpp-router-install.sh')
if sys.argv[3] == '1':
    config['ipsec_update_command'] = [sys.argv[4], 'ipsec']
else:
    config.pop('ipsec_update_command', None)
path.write_text(json.dumps(config, indent=2) + '\n')
PY
	fi
	write_dnsmasq
	if [ "${IPV6_PD:-0}" = 1 ] || [ -n "${LAN_ULA:-}" ]; then
		mkdir -p "$(dirname "$SYSCTL_IPV6")"
		gen_ipv6_sysctl >"$SYSCTL_IPV6"
		note "$SYSCTL_IPV6    vpp-host 的 IPv6 RA/SLAAC sysctl"
	fi
	note "$STARTUP     VPP 启动参数"
	note "$CONF/router.vpp     接口、桥、NAT（VPP CLI）"
	note "$CONF/router.env     网卡绑定设置"
	[ "$DNSMASQ" = 1 ] && note "$CONF/dnsmasq.conf    LAN DHCP/DNS（只改监听、地址池、网关和 DNS 几行，其余可以自己加）"
	[ "$DNSMASQ" = 1 ] && note "$CONF/dhcp-hosts      静态分配，改完 systemctl reload $DNS_SERVICE"
	note "上一版配置备份在 $STATE/*.bak"
	return 0
}

# 以前的版本把启动参数写在 $CONF/startup.conf。本脚本生成的那份移走；
# 当时另存过的原文件（发行版软件包的 startup.conf）放回原处。不是本脚本生成的不动。
# 必须在 write_units 把 ExecStart 改到 $STARTUP 之后执行：之前失败时，旧单元仍能用旧文件启动。
migrate_startup() {
	local old=$CONF/startup.conf
	[ -e "$old" ] && grep -q 'vpp-router-install.sh' "$old" || return 0
	mv -f "$old" "$STATE/startup.conf.bak"
	if [ -e "$STATE/startup.conf.orig" ]; then
		mv -f "$STATE/startup.conf.orig" "$old"
		note "$old 已还原为安装前的原文件，本脚本的启动参数改用 $STARTUP"
	else
		note "旧的 $old 已移到 $STATE/startup.conf.bak，启动参数改用 $STARTUP"
	fi
}

# 面板在 VPP 之后启动：它监听的 $HOST_TAP 地址要等 VPP 启动后才有
start_or_not() {
	start_vpp_or_not
	start_panel
}

# VPP 启动失败时不退出：面板、sing-box 照常启动，面板上能看到 VPP 未运行；Gate 由 install_gate 跳过
vpp_start_failed() {
	warn "VPP 启动失败，查看 journalctl -u $SERVICE；修好后执行 systemctl restart $SERVICE"
	return 0
}

start_vpp_or_not() {
	local ssh=0 i reach
	if [ "${MLX4_REBOOT:-0}" = 1 ]; then
		systemctl enable "$SERVICE" >/dev/null
		[ "$DNSMASQ" = 1 ] && systemctl enable "$DNS_SERVICE" >/dev/null
		[ "${IPV6_PD:-0}" = 1 ] && systemctl enable "$PD_SERVICE" >/dev/null
		echo
		info "mlx4_core 的 log_num_mgm_entry_size 还不是 -1，现在启动 VPP 端口会失败；已设为开机启动，请重启。"
		return 0
	fi
	for i in "${SEL[@]}"; do [ "${N_SSH[i]}" = 1 ] && ssh=1; done
	echo
	reach="LAN 内用 ssh $(ipv4 addr "${HOST_CIDR:-$LAN_CIDR}" 2>/dev/null || echo "$LAN_GW") 重新连接"
	[ -n "$HOST_CIDR" ] || reach="通过控制台或其余网卡登录"
	if ! ask_yn "现在启动 VPP？$([ $ssh = 1 ] && echo '（会断开当前 SSH）')" $([ $ssh = 1 ] && echo n || echo y); then
		systemctl enable "$SERVICE" >/dev/null
		[ "$DNSMASQ" = 1 ] && systemctl enable "$DNS_SERVICE" >/dev/null
		[ "${IPV6_PD:-0}" = 1 ] && systemctl enable "$PD_SERVICE" >/dev/null
		info "已设为开机启动，未启动。手动启动：systemctl start $SERVICE"
		return 0
	fi
	if [ $ssh = 1 ] && ask_yn "启用 10 分钟自动回退？到时未执行 '$CTL confirm' 就停止 VPP 并还原网卡" y; then
		systemctl stop vpp-router-rollback.timer 2>/dev/null || true
		systemd-run --quiet --unit=vpp-router-rollback --on-active=600 "$CTL" rollback
		info "启动后请在 10 分钟内${reach}，执行 $CTL confirm"
		sleep 2
		if ! systemctl start "$SERVICE"; then
			vpp_start_failed
			return 0
		fi
		stop_system_dnsmasq
		[ "$DNSMASQ" = 1 ] && systemctl start "$DNS_SERVICE"
		[ "${IPV6_PD:-0}" = 1 ] && systemctl start "$PD_SERVICE"
		return 0
	fi
	systemctl enable "$SERVICE" >/dev/null
	[ "$DNSMASQ" = 1 ] && systemctl enable "$DNS_SERVICE" >/dev/null
	[ "${IPV6_PD:-0}" = 1 ] && systemctl enable "$PD_SERVICE" >/dev/null
	if ! systemctl restart "$SERVICE"; then
		vpp_start_failed
		return 0
	fi
	stop_system_dnsmasq
	[ "$DNSMASQ" = 1 ] && systemctl restart "$DNS_SERVICE"
	[ "${IPV6_PD:-0}" = 1 ] && systemctl restart "$PD_SERVICE"
	sleep 2
	"$VPPCTL_BIN" show interface address || true
	info "已启动。状态：$CTL status 或 sudo vppctl show interface；还原网卡：$SCRIPT --restore"
}

# 已安装的控制脚本：新布局在 $PREFIX/sbin，2026-11 以前在 /opt/vpp-router/sbin
installed_ctl() {
	local c
	for c in "$CTL" "$OLD_PREFIX/sbin/vpp-router-ctl"; do
		[ -x "$c" ] && { echo "$c"; return 0; }
	done
	return 1
}

# 停掉 VPP 后，现有 rollback 只能恢复 Linux 网卡，不能恢复经 TAP 的 SSH。
# 同时检查 SSH 本地地址和回程路由，避免遗漏经 VPP 管理口登录的升级。
check_management_path() {
	local client port server rest dev local_dev old_ifs
	[ -n "${SSH_CONNECTION:-${SSH_CLIENT:-}}" ] || return 0
	systemctl is-active --quiet "$SERVICE" || return 0
	read -r client port server rest <<<"${SSH_CONNECTION:-${SSH_CLIENT:-}}"
	dev=$(ip route get "$client" | awk '{for (i=1; i<NF; i++) if ($i == "dev") {print $(i+1); exit}}')
	[ -n "$dev" ] || die "无法确认 SSH 回程接口，请从控制台或独立管理口执行"
	local_dev=$(ip -o addr show | awk -v ip="${server:-}" '{split($4,a,"/"); if (a[1] == ip) {print $2; exit}}')
	old_ifs=$(
		if [ -r "$CONF/router.env" ]; then
			. "$CONF/router.env"
			printf '%s\n' "$HOST_TAP"
			for rest in "${NICS[@]}"; do read -r port client dev rest <<<"$rest"; echo "$dev"; done
		fi
	)
	if [ "$dev" = "$HOST_TAP" ] || [ "$local_dev" = "$HOST_TAP" ] ||
		{ [ -n "$old_ifs" ] && { grep -qxF -- "$dev" <<<"$old_ifs" || { [ -n "$local_dev" ] && grep -qxF -- "$local_dev" <<<"$old_ifs"; }; }; }; then
		die "当前 SSH 经过 VPP 管理网络，停止旧 VPP 会断连且无法由 Linux 网卡回退恢复；请从控制台或独立管理口执行"
	fi
}

# 必须在覆盖控制脚本、router.env 和内核模块之前执行，使用旧配置释放旧设备。
prepare_reconfigure() {
	local ctl
	check_management_path
	if ctl=$(installed_ctl); then
		[ -r "$CONF/router.env" ] || die "缺少旧 router.env，无法安全释放旧网卡"
		if systemctl is-active --quiet "$SERVICE"; then
			systemctl stop "$SERVICE" || die "停止旧 VPP 失败，停止重新配置"
		fi
		"$ctl" restore || die "释放旧网卡失败，停止重新配置"
		[ ! -e /run/vpp-router/kmod-owned ] || die "旧平台模块尚未释放，停止重新配置"
	elif systemctl is-active --quiet "$SERVICE"; then
		die "旧 VPP 正在运行但找不到控制脚本，无法安全释放旧网卡"
	fi
}

do_restore() {
	[ "$(id -u)" = 0 ] || die "请用 root 运行"
	local ctl
	ctl=$(installed_ctl) || die "没有找到 $CTL"
	ask_yn "停止并禁用 ${SERVICE}，把网卡还给安装前的内核驱动？" y || exit 0
	systemctl stop vpp-router-rollback.timer 2>/dev/null || true
	"$ctl" rollback
	info "已还原。Linux 侧的地址需要由原来的网络配置重新获取。"
}

do_uninstall() {
	[ "$(id -u)" = 0 ] || die "请用 root 运行"
	ask_yn "停止 VPP、把网卡还给原驱动，并删除本脚本安装的程序、内核模块和服务？（保留 $CONF 和 $STATE）" y || exit 0
	local ctl f bin
	systemctl stop vpp-router-rollback.timer 2>/dev/null || true
	if ctl=$(installed_ctl); then "$ctl" rollback || warn "还原网卡时出错，继续卸载"; fi
	[ -e "/run/netns/$IPSEC_NS" ] && { ip netns del "$IPSEC_NS" 2>/dev/null || warn "无法删除命名空间 $IPSEC_NS"; }
	systemctl disable --now "$PD_SERVICE" "$DNS_SERVICE" "$SERVICE" 2>/dev/null || true
	rm -f "$UNIT_DIR/$SERVICE.service" "$UNIT_DIR/$DNS_SERVICE.service" "$UNIT_DIR/$PD_SERVICE.service"
	# 只删本脚本写的面板单元（ExecStart 指向本前缀）
	for f in vpp-monitor vpp-interfaces vpp-wireguard vpp-firewall vpp-system gate-admin vpp-proxy "$SINGBOX_UNIT"; do
		bin=$f
		[ "$f" = "$SINGBOX_UNIT" ] && bin=sing-box
		[ -e "$UNIT_DIR/$f.service" ] && grep -qE "$PREFIX/bin/$bin( |\$)" "$UNIT_DIR/$f.service" || continue
		systemctl disable --now "$f" 2>/dev/null || true
		rm -f "$UNIT_DIR/$f.service"
	done
	systemctl daemon-reload
	if [ -s "$MANIFEST" ]; then
		while read -r f; do [ -n "$f" ] && rm -f -- "$f"; done <"$MANIFEST"
		rm -f "$MANIFEST"
	fi
	prune_private_dirs
	remove_old_prefix
	if [ -e /etc/ld.so.conf.d/vpp-router.conf ]; then rm -f /etc/ld.so.conf.d/vpp-router.conf; ldconfig; fi
	depmod -a "$(uname -r)" 2>/dev/null || true
	unmask_distro_vpp
	info "已卸载。配置 $CONF 和状态 $STATE、$PANEL_STATE 保留；源码和构建目录 $SRC 可以手动删除"
	if gate_present; then note "Gate 没有卸载，要卸载用 tools/vpp-egress-gate/uninstall.py。"; fi
	return 0
}

main() {
	[ "$MODE" = restore ] && { do_restore; exit 0; }
	[ "$MODE" = uninstall ] && { do_uninstall; exit 0; }
	load_ports
	detect_platform
	[ "$MODE" = install ] || [ -x "$PREFIX/bin/vpp" ] || die "$PREFIX 中没有 VPP，请先完整安装"
	detect_nics
	show_nics
	choose_nics
	configure_roles
	ask_network
	ask_platform
	ask_mlx4
	ask_cpu
	ask_rx_mode
	ask_ipsec
	ask_panel
	ask_singbox
	ask_ports
	check_vfio_groups
	summary
	ask_distro_vpp
	check_management_path
	if [ "$MODE" = install ]; then
		install_deps
		# 先编内核模块：内核接口不兼容时几分钟内就失败，而不是编完 VPP 之后
		local reuse=0
		reuse_build && reuse=1
		[ "$reuse" = 1 ] || build_swap_on
		build_kmod
		if [ "$reuse" = 0 ]; then
			rm -f "$SRC/build.key"
			fetch_sources
			apply_patches
			build_dpdk
			build_vpp
			build_swap_off
			build_key >"$SRC/build.key"
		fi
		build_tools
		install_vpp
	else
		build_kmod
		prepare_reconfigure
	fi
	mask_distro_vpp
	install_kmod
	setup_mlx4
	verify_nics
	assign_names
	record_orig
	write_ctl
	write_config
	write_units
	migrate_startup
	start_or_not
	install_gate
}

main
