# WireGuard 安装脚本

项目入口：`install-wireguard.py`，服务器安装为 `/usr/local/sbin/vpp-install-wireguard`。
手动运行，从 `/etc/wireguard/wg0.conf`、`wg1.conf` 提取接口地址、密钥、peer 和端口，
生成 VPP 原生命令文件并创建/更新 VPP 接口。不运行 Linux wg-quick 或配置中的 PostUp。
wg1 的固定目的路由取自 `/etc/vpp/wg1-routes.conf`，不导入默认路由。

```sh
sudo vpp-install-wireguard wg0
sudo vpp-install-wireguard wg1
# 或一次安装两个接口
sudo vpp-install-wireguard all
```

首次安装且没有已生成配置时，须显式提供当前 VPP 创建命令的 src 参数：

```sh
sudo vpp-install-wireguard all --source-address 10.61.10.4
```

更新时默认沿用已经安装的 src，不查询 WAN/DHCP，也不根据 WAN 变化触发任何操作。
`import-wireguard.py` 与 `import-wireguard-client.py` 只作为转换器，已删除旧的
WAN 检查、签名同步和直接导入路径。`vpp-wireguard-static.py` 是安装器共用的应用工具。

生成的文件保存在 `/etc/vpp/wireguard/wg0.conf`、`wg1.conf`，包含私钥，权限 0600，
目录 0700；真实文件不进入项目。安装脚本更新 `/etc/vpp/nat.conf` 中自己管理的
`VPP WIREGUARD` 块，让 VPP 在自身启动时直接 `exec` 两个文件。
同时在 `/usr/local/sbin/vpp-net-prepare` 的受管块中保存 Linux 到隧道网段的回程路由。
没有 WireGuard 导入 service、timer 或后台配置同步进程。

修改 `/etc/wireguard` 后重新执行安装命令；配置未变化不重建。
配置变化会重建相应接口并中断该隧道会话。首次接管已有静态接口会核对 peer 公钥和地址，
不覆盖缺少已安装配置文件的接口。安装器沿用 NAT/DNS gate 的接口锁，先生成并验证
所有选中接口的配置，再开始修改。失败不会自动循环重试，也不承诺跨接口原子回滚；
已有配置、启动文件和旧 systemd 单元先备份至 `/root/vpp-nat-backup/wireguard-install-*/`。

## 差量热同步

需要保留 WireGuard 接口和未变化 peer 的握手状态时，使用：

```sh
sudo vpp-wg-syncconf wg0 /etc/wireguard/wg0.conf
sudo vpp-wg-syncconf wg1 /etc/wireguard/wg1.conf
```

省略配置路径时使用对应的 `/etc/wireguard/wg*.conf`。该命令只差量处理新增、删除或
内容变化的 peer，并更新对应的 `/etc/vpp/wg0.vpp` 或 `/etc/vpp/wg1.vpp` 以保持重启后的配置。未变化的
peer 不会被删除，因此其握手和收发计数保持不变。接口私钥、监听端口、MTU 或地址变化
会被拒绝，此时使用上面的完整安装命令。VPP 26.06 当前没有 peer 原地更新 CLI，发生
变化的单个 peer 会被删除后重新添加，该 peer 会重新握手；整个接口不会被重建。

应用前可预览差异：

```sh
sudo vpp-wg-syncconf wg0 --dry-run
```

两个旧 timer 及两个导入 service 已从项目和服务器删除。DNS 路由相关 service 的旧
导入服务依赖已移除，动态 nftset 路由继续由现有 DNS gate 管理。
静态 src 不包含自动选源功能；更换上游后的隧道外层可达性仍取决于实际路由和 NAT。
wg1 endpoint 保留 `10.64.20.3:42003`，本次不验证远端连通性。

## 域名 Endpoint 自动刷新

VPP 原生 peer endpoint 保存的是 IP 地址，不会自己监听 DNS 变化。若 `wg1.conf` 使用类似以下配置：

```ini
Endpoint = vpn.example.com:51820
PersistentKeepalive = 30
```

可安装随仓库提供的 refresh service/timer：

```sh
sudo install -m 0644 tools/wireguard/vpp-wireguard-endpoint-refresh.service \
  /etc/systemd/system/
sudo install -m 0644 tools/wireguard/vpp-wireguard-endpoint-refresh.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpp-wireguard-endpoint-refresh.timer
```

timer 每 30 秒重新解析域名并执行 `vpp-wg-syncconf wg1`。DNS 地址没有变化时不操作
peer；地址变化时只热替换对应 peer，整个 `wg1` 接口和其他 peer 不受影响。VPP 26.06
没有通用的 peer 超时事件回调，所以这里采用周期刷新；从 DNS 变化到恢复的最长等待约
30 秒，之后由 `PersistentKeepalive = 30` 触发新的握手。该机制当前按 IPv4 解析，域名
必须能返回 IPv4 地址。

