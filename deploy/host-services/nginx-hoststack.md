# RK3588 开发板：通过 VCL/LDP 将 nginx 接入 VPP Host Stack

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

本文基于 2026-11-08 的 RK3588 开发板实测，VPP 版本为
`v26.06.0-1~geth1test`。已验证独立 nginx 监听 `10.61.20.1:8088`，
静态文件下载和经 Unix socket 连接 PHP 8.2 FPM 均可用。
当前正式测速服务已按同一方式切换到 `10.61.20.1:80`，由
`nginx-hoststack.service` 管理；原 Linux nginx 的 LibreSpeed server 配置已移出加载目录。
测速后端为 librespeed-go（v1.1.6 `speedtest-backend`），经 systemd Unix socket
交给 nginx 反代。页面是 LibreSpeed 6.3.1 静态前端（`/var/www/speedtest`）；
PHP 测速脚本未部署，URL 仍用 `backend/garbage.php` 等兼容路径，由 Go 处理。
默认 classic UI（`config.json` `useNewDesign: false`）；`?design=new` 为 modern。
`server-list.json` 只有本机 `10.61.20.1`。

nginx 仍是 Linux 用户空间进程，客户端 TCP 连接由 VPP Host Stack 处理：

```text
客户端 → VPP 网卡 → VPP TCP/IP → 共享内存 FIFO → VCL/LDP → nginx
                                                          ↓
                                                  Unix socket → librespeed-go
```

客户端流量绕过 Linux TAP、bridge 和 Linux TCP/IP。Go 使用原始 syscall，
LDP 拦不住，所以 Go 不能自己听在 Host Stack 上；只把 client 侧放在 nginx。
LDP 对 `AF_UNIX` 走 libc，不经 VPP session。共享内存 FIFO 不代表全路径零拷贝。

下载主要走 VPP TCP 发送。上传在 nginx 读完 VCL FIFO 之后，把 POST 以
HTTP 写入 Go 的 Unix socket，Go 的 `/backend/empty.php` 把 body
`io.Copy` 到 `Discard`。PHP 测速后端已从 `/var/www/speedtest` 删除。

`client_body_buffer_size` 为 1m，与 VCL `rx-fifo-size` 对齐，并用
`upstream` keepalive 连 Go socket。

VPP `app ns` 必须绑在 `loop200` 上。接口被删后 ns 会显示 `DELETED`，LDP
nginx 的 epoll fd 失效，`epoll_wait()` 报 `File descriptor in bad state`
并占满单核，同时 `10.61.20.1:80` 回落到系统 nginx。启动前
`ensure-hoststack-appns.sh` 会在 ns 失效时按 `loop200` 重建。LibreSpeed
6.3.1 现代界面默认 6 路 × 100 MiB 下载，容易把 LDP worker 打挂；现场把
下载并发降到 3、上传 2、chunk 32 MiB。

## 1. 检查环境

在 RK3588 开发板上执行：

```sh
sudo vppctl -s /run/vpp/cli.sock show version
sudo vppctl -s /run/vpp/cli.sock show interface address
sudo vppctl -s /run/vpp/cli.sock show session
ls -l /usr/local/lib/vpp-rk3588/lib/aarch64-linux-gnu/libvcl_ldpreload.so
ls -l /run/librespeed-go/http.sock
```

`10.61.20.1` 必须是当前 VPP 网络中的本地地址；VCL 应用使用的 namespace/FIB
必须能到达客户端。库必须与运行中的 VPP 匹配，不能直接混用其他版本的库。
普通 Linux nginx 只修改 `listen` 地址不能接入 Host Stack。

部署前可先使用独立端口 8088，保留原有 Linux nginx 的 80/443 服务。
`ss -lnt` 只能检查 Linux socket，不能完整列出 VPP 的监听端点。

## 2. 启用 session 层

本机版本支持运行时启用，无需重启 VPP：

```sh
sudo vppctl -s /run/vpp/cli.sock session enable
sudo vppctl -s /run/vpp/cli.sock show session
sudo ls -l /run/vpp/app_ns_sockets/default
```

实测运行时启用后自动创建上述 app socket。若其他版本未创建，需要核对该版本
session 配置；官方启动配置是 `session { use-app-socket-api }`。
修改 `/etc/vpp/startup.conf` 后要到 VPP 重启时才生效，不能为此直接重启生产路由。

本机 app-socket-api 模式下尝试通过 `/run/vpp/api.sock` 进行应用 attach，返回过
`Feature disabled by configuration (-30)`，应使用应用 socket，而非普通 binary API socket。

## 3. 创建 VCL 配置

创建独立目录：

```sh
sudo install -d /etc/vpp/nginx-hoststack
sudo install -d /var/log/nginx-hoststack /var/lib/nginx-hoststack
```

将以下内容保存为 `/etc/vpp/nginx-hoststack/vcl.conf`：

```text
vcl {
  heapsize 64M
  segment-size 67108864
  add-segment-size 67108864
  rx-fifo-size 1048576
  tx-fifo-size 1048576
  app-socket-api /run/vpp/app_ns_sockets/default
  app-scope-global
  use-mq-eventfd
}
```

**保留 `use-mq-eventfd`。** 上轮未配置时，LDP nginx worker 空闲占约一个核心；
加入后，10 秒空闲采样的 CPU 时间增量为 0。该选项让消息队列使用 eventfd 通知，
LDP 可以通过阻塞 epoll 等待 VPP 和 Linux 事件。

FIFO 和 segment 大小是本次小规模测试值，连接数增加时须重新评估内存需求。

## 4. 创建独立 nginx 配置

将以下内容保存为 `/etc/vpp/nginx-hoststack/nginx.conf`：

```nginx
worker_processes 1;
daemon off;
master_process on;
pid /run/nginx-hoststack.pid;
error_log /var/log/nginx-hoststack/error.log info;

events {
    use epoll;
    worker_connections 128;
}

http {
    access_log off;
    sendfile off;
    gzip off;

    server {
        listen 10.61.20.1:8088;
        root /var/lib/nginx-hoststack;

        location = /payload { }

        location = /backend/garbage.php {
            include /etc/nginx/fastcgi_params;
            fastcgi_param SCRIPT_FILENAME /var/www/speedtest/backend/garbage.php;
            fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
            fastcgi_buffering off;
        }

        location = /backend/empty.php {
            client_max_body_size 128m;
            client_body_buffer_size 1m;
            include /etc/nginx/fastcgi_params;
            fastcgi_param SCRIPT_FILENAME /var/www/speedtest/backend/empty.php;
            fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
            fastcgi_param PHP_VALUE "post_max_size=128M\nupload_max_filesize=128M";
            fastcgi_request_buffering off;
            fastcgi_buffering off;
        }
    }
}
```

这是单 worker 验证配置。文件目录和 PHP socket 权限必须允许 nginx worker 访问。
示例开放静态文件、PHP 下载和 PHP 上传，未提供完整 LibreSpeed 页面、HTTPS 或通用 PHP 路由。
`sendfile off` 与 `gzip off` 用于保持本次对照测试的条件一致。

创建一个 256 MiB 稀疏测试文件，内容为零：

```sh
sudo truncate -s 256M /var/lib/nginx-hoststack/payload
sudo chmod 644 /var/lib/nginx-hoststack/payload
sudo systemctl status nginx-hoststack.service
```

普通 Linux nginx 的 `nginx -t -c` 会尝试在 Linux 内核绑定 `10.61.20.1`，
该地址属于 VPP，因此可能报告 `Cannot assign requested address`。实际检查应通过
systemd 单元启动后查看 journal 和 HTTP 请求结果。

## 5. 启动

先在终端前台运行，便于观察错误：

```sh
sudo env \
  LD_LIBRARY_PATH=/usr/local/lib/vpp-rk3588/lib/aarch64-linux-gnu \
  LD_PRELOAD=/usr/local/lib/vpp-rk3588/lib/aarch64-linux-gnu/libvcl_ldpreload.so \
  VCL_CONFIG=/etc/vpp/nginx-hoststack/vcl.conf \
  /usr/sbin/nginx -c /etc/vpp/nginx-hoststack/nginx.conf
```

仅为这个独立实例设置环境变量，不要写入 `/etc/ld.so.preload` 或全局环境。
nginx worker 数量、fork 行为或库版本改变后，需要重新验证。

正式部署使用仓库中的 `nginx-hoststack.service`。测速后端安装
`librespeed-go.socket`、`librespeed-go.service`、
`librespeed-go.settings.toml` 和官方 `speedtest-backend` linux arm64
二进制（v1.1.6）到 `/usr/local/bin/speedtest-backend`，配置放到
`/etc/librespeed-go/settings.toml`。`listen_port` 与 `bind_address` 必须
留空，才能继承 systemd socket。安装文件后执行：

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now librespeed-go.socket
sudo systemctl enable --now nginx-hoststack.service
```

该单元会在启动前执行 `session enable`，等待 app socket，加载 LDP，并在
`rk3588-vpp.service` 启动时由 `Wants=nginx-hoststack.service` 拉起。
`nginx-hoststack.service` 同时 `Wants=librespeed-go.socket`，保证反代 Unix
socket 已由 systemd 听好；首个请求会 socket-activate `librespeed-go.service`。

2026-11-09 修复：`LD_PRELOAD`、`LD_LIBRARY_PATH` 和 `VCL_CONFIG` 仅通过
`ExecStart=/usr/bin/env ... nginx` 传给 nginx，不能用 service 级 `Environment=`
传给所有命令。VPP 重启后 session 尚未启用时，前置 `vppctl session enable`
若继承 LDP，会在 constructor 阶段失败，导致服务循环重启，测速页面无法访问。
前置准备和停止命令使用正常 Linux 环境；验收须包含 VPP 重启后的启动路径。

2026-11-15 修复：在 nginx 的 `ExecStart=/usr/bin/env ...` 中设置
`LDP_SID_BIT=20`，让 VCL 虚拟描述符从 1048576 开始，高于本服务的
`LimitNOFILE=65536`。现场 LDP 默认起点为 32，会把编号达到 32 的真实
Linux Unix socket 误判为 VCL 句柄，导致 epoll 操作及 close 路径操作错误对象。
故障时可见 `epoll_ctl(EPOLL_CTL_ADD, 32) failed (17: File exists)`，
nginx 进程仍存活但 VPP TCP 监听已消失。调整后应验证并发上传下载、
`show app listeners verbose` 和新增日志；此设置不保证消除独立的
`epoll_wait() returned no events without timeout` 告警。

## 6. 从 LAN 客户端验证

```sh
curl --max-time 5 -r 0-1023 -o /dev/null \
  -w '%{http_code} %{size_download}\n' \
  http://10.61.20.1:8088/payload

curl --max-time 5 -o /dev/null \
  -w '%{http_code} %{size_download}\n' \
  'http://10.61.20.1:8088/backend/garbage.php?ckSize=1'

dd if=/dev/zero bs=1M count=20 status=none | curl --max-time 15 -o /dev/null \
  -w '%{http_code} %{size_upload} %{speed_upload}\n' \
  -X POST --data-binary @- \
  http://10.61.20.1:8088/backend/empty.php
```

本次分别返回 `206 1024` 和 `200 1048576`。上传应返回 `200` 且
`size_upload` 为 20971520。当前生产路径上 `/backend/empty.php` 由
librespeed-go 丢弃 body；早期对照曾走 PHP-FPM FastCGI。
RK3588 开发板上用以下命令确认 VPP 应用已附着：

```sh
sudo vppctl -s /run/vpp/cli.sock show app
sudo vppctl -s /run/vpp/cli.sock show session
```

固定吞吐测试命令如下。12 秒超时主动结束下载时，curl 返回码 28 是预期行为；
同时检查 HTTP 状态、接收字节数和实际速度，不能把其他错误当成有效测试。

```sh
curl --limit-rate 20M --max-time 12 -o /dev/null \
  -w '%{http_code} %{speed_download} %{size_download}\n' \
  'http://10.61.20.1:8088/backend/garbage.php?ckSize=256'

dd if=/dev/zero bs=1M count=240 status=none | curl --limit-rate 20M --max-time 12 -o /dev/null \
  -w '%{http_code} %{speed_upload} %{size_upload}\n' \
  -X POST --data-binary @- \
  http://10.61.20.1:8088/backend/empty.php
```

20 MiB/s 约为 168 Mbit/s。CPU 采样应落在传输期间，线程百分比用
`/proc/PID/task/TID/stat` 的 `(utime + stime)` 增量除以 `CLK_TCK` 和实际采样秒数，
再乘 100；这是单核口径。不要使用进程汇总值代替 main 线程自身的 CPU 时间。
系统态和上下文切换使用 `/proc/stat` 的增量；Linux 对照使用相同 nginx 配置、
相同文件、相同限速，监听地址改为 `10.61.20.2:8088`，且不加载 LDP。

## 7. 已验证的结果与范围

PHP 下载 20 MiB/s、传输期间约 8 秒采样：

| 指标 | Linux 路径 | LDP 默认配置 | LDP + eventfd |
|---|---:|---:|---:|
| nginx worker 单核占用 | 5.86% | 100.11% | 6.61% |
| 整机系统态 | 3.96% | 7.29% | 1.70% |
| 整机忙碌率 | 18.78% | 28.36% | 16.68% |
| 上下文切换/秒 | 6,941 | 3,523 | 4,627 |

这些是单轮短测，不是多轮统计或满千兆性能承诺。eventfd 的静态下载尚未重跑完整
性能对照；静态下载功能与默认 LDP 的静态性能已验证。

四流 20 MiB 上传（合计约 1 Gbit/s）在 PHP-FPM 路径上：nginx 与下载同量级，
额外 CPU 在 PHP-FPM 收 POST。当前生产已改为 Go 后端。HTTPS、多 worker、
WAN/VPN 入口、断线恢复尚未单独验收。

Host Stack 终止的客户端连接绕过 Linux 网络路径，原有 Linux nftables INPUT/DNAT
规则不能直接视为这些连接的访问控制。正式开放服务前，应核对 VPP 入口 ACL、
地址可达性和既有 punt 路径；本次仅验证 LAN 的 IPv4 8088 入口。

## 8. 停止与回退

读取独立实例 PID 并确认命令行属于本实例后，再发送 TERM：

```sh
sudo cat /run/nginx-hoststack.pid
ps -p PID -o pid,args
sudo kill -TERM PID
sudo vppctl -s /run/vpp/cli.sock show app
```

将 `PID` 替换为上一步核实的数字。不要使用 `killall nginx`，否则会停止原有服务。
只有确认 session 原先关闭、且没有其他应用使用时，才恢复关闭：

```sh
sudo vppctl -s /run/vpp/cli.sock session disable
```

2026-11-08 已部署到 RK3588 开发板：

- nginx 配置：`/etc/vpp/nginx-hoststack/nginx.conf`
- VCL 配置：`/etc/vpp/nginx-hoststack/vcl.conf`
- systemd 单元：`/etc/systemd/system/nginx-hoststack.service`
- VPP 依赖 drop-in：`/etc/systemd/system/rk3588-vpp.service.d/80-nginx-hoststack.conf`
- librespeed-go：`/usr/local/bin/speedtest-backend`（v1.1.6 linux arm64）、
  `/etc/librespeed-go/settings.toml`、
  `/etc/systemd/system/librespeed-go.service`、
  `/etc/systemd/system/librespeed-go.socket`（`unix:/run/librespeed-go/http.sock`）
- 原测速配置备份：`/var/lib/vpp-vrouter/history/<backup-id>/`

当前 `nginx-hoststack.service` 为 enabled/active，监听 VPP 地址 `10.61.20.1:80`。
`/backend/` 与 `/results/` 反代到 librespeed-go；页面是
`/var/www/speedtest` 静态文件。PHP 测速脚本已删除，备份在
`/var/lib/vpp-vrouter/history/`。原 `/etc/nginx/conf.d/speedtest.conf` 已移出加载目录；
系统 nginx 仍保留默认站点，因此 `10.61.20.2/backend/garbage.php` 不再提供测速服务。

## 参考

- [官方 nginx LDP 示例](https://github.com/FDio/vpp/wiki/VPP-HostStack-LDP-nginx)
- [VCL 配置与兼容性限制](https://github.com/FDio/vpp/wiki/VPP-HostStack-VCL)
- [LDP epoll 实现](https://github.com/FDio/vpp/blob/master/src/vcl/ldp.c)

LDP 不是完整 POSIX 兼容层；静态链接程序和部分系统调用/线程组合不支持。
上述 master 源码链接会变化，排查现场版本应以该版本实际源码为准。
