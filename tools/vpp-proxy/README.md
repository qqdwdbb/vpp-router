# vpp-proxy

管理面板“代理”页面的执行程序：管理代理入口 sing-box 的上游。以 root 运行，只在本机 Unix socket 上提供接口，由 `vpp-monitor` 转发。安装脚本选了 sing-box 时一起安装（见 `deploy/install/README.md`）。

sing-box 的配置在 `/etc/vpp/sing-box/`，用 `-C` 合并加载：`entry.json` 是局域网的入口（SOCKS5 1080、TPROXY 2080 和 2082、Fake-IP DNS），由安装脚本生成；`upstream.json` 是上游，标签为 `proxy` 的出站或 endpoint。本程序只改 `upstream.json`。

## 构建和安装

```sh
make                                   # 生成 dist/vpp-proxy-linux-{arm64,amd64}
```

通常由安装脚本编译、安装并写好 `vpp-proxy.service`。

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--socket` | `/run/vpp-proxy/proxy.sock` | 面板连接的 socket |
| `--sing-box-dir` | `/etc/vpp/sing-box` | sing-box 的配置目录 |
| `--config-dir` | `/etc/vpp/proxy` | 向导的表单 `profile.json`（含凭据，只有 root 可读） |
| `--state-dir` | `/var/lib/vpp-proxy` | 订阅和它的节点（含凭据），测试用的临时文件 |
| `--unit` | `vpp-router-sing-box.service` | 运行 sing-box 的单元 |
| `--binary` | `/usr/local/bin/sing-box` | sing-box |
| `--test-url` | `https://www.gstatic.com/generate_204` | 连通测试请求的地址 |

## 设置上游

面板的向导选协议、填地址和认证信息，本程序生成 sing-box 出站：

| 协议 | 填写 |
|---|---|
| SOCKS5、HTTP | 用户名、密码（HTTP 可选 TLS） |
| Shadowsocks | 加密方式、密码 |
| VMess | UUID、security、alterId，TLS 和传输可选 |
| VLESS | UUID、flow，TLS 或 Reality（公钥、short id）、uTLS 指纹，传输可选 |
| Trojan | 密码，TLS，传输可选 |
| Hysteria2 | 密码，obfs（salamander）和上下行 Mbps 可选，TLS |
| TUIC | UUID、密码、拥塞控制，TLS |
| AnyTLS | 密码，TLS |
| WireGuard | 本机地址、私钥、对端地址端口和公钥，预共享密钥、AllowedIPs、MTU 可选（sing-box 的 endpoint） |

TLS 可以设 SNI、跳过证书校验、ALPN、uTLS 指纹；传输有 WebSocket、gRPC、HTTP/2、HTTPUpgrade。

应用时：用 `sing-box check` 检查 `entry.json` 加新的上游，不通过就什么都不改；通过后另存原来的 `upstream.json` 为 `upstream.json.bak`，写入新文件，重启 sing-box，3 秒内没有保持运行就恢复原来的上游和表单，再重启一次。不需要 60 秒确认：上游只影响经过代理的流量，不会切断面板。

密码、UUID、私钥、预共享密钥和 obfs 密码不会返回给面板，面板只知道哪些已经设置。再次打开向导时这些字段留空，提交时空着就沿用原来的值（协议、服务器和端口不变时）。

“删除”把 `upstream.json` 换回安装脚本的占位配置（拒绝所有代理流量），同样先检查、另存 `upstream.json.bak`、重启 sing-box，没起来就恢复；向导的表单一起删掉。

`upstream.json` 不是本程序写的（手写的，或安装时导入的），页面显示为“自定义上游”，列出它的出站，可以照常测试；用向导应用后替换它，原文件在 `upstream.json.bak`。

## 导入

导入只是把节点填进向导，或者直接测试：

- **sing-box 配置**：粘贴或上传 JSON，可以是完整的客户端配置、带 `outbounds`/`endpoints` 的片段、列表或单个出站。selector、urltest、direct 等不是节点的跳过。向导表达不了的字段（比如 multiplex、detour、插件）列出来，应用时忽略。
- **分享链接**：每行一个，支持 `socks5://`、`socks://`、`http(s)://`、`ss://`（SIP002 和旧的整体 base64）、`vmess://`（base64 JSON）、`vless://`（含 Reality）、`trojan://`、`hysteria2://`、`hy2://`、`tuic://`、`anytls://`。
- **订阅**：路由器下载订阅地址（20 秒超时，最大 4 MB，User-Agent 是 `sing-box`），内容可以是 sing-box 配置、base64 的链接列表或纯文本链接列表。节点和凭据保存在路由器上，面板只看到名字、协议和服务器，“使用”直接应用。“更新”重新下载，按名字找到正在用的节点再应用；节点没了就不改上游。“删除订阅”删掉订阅和它的节点，正在用的上游不变。用向导应用别的上游或删除上游后，订阅不再记着正在用的节点。

## 连通测试

起一个临时的 sing-box：只有一个 127.0.0.1 随机端口的 SOCKS 入站，后面接要测的上游，经它请求测试地址，报告 HTTP 状态和耗时，然后结束进程。所以测试表单、导入的节点、订阅节点或当前上游，都不影响正在运行的 sing-box。

## 接口

| 路径 | 内容 |
|---|---|
| `GET /proxy` | 状态、入口、当前上游（不含凭据）、订阅、向导的选项 |
| `POST /proxy/apply` | `{"profile": {...}}` |
| `POST /proxy/clear` | `{}`，换回占位配置 |
| `POST /proxy/test` | `{"profile": {...}, "url"}`；不带 profile 时测试当前上游 |
| `POST /proxy/parse` | `{"kind": "json" 或 "links", "text"}`，返回节点 |
| `POST /proxy/subscription` | `{"url"}` |
| `POST /proxy/subscription/use`、`/subscription/test` | `{"index"}` |
| `POST /proxy/subscription/update`、`/subscription/delete` | `{}` |
| `POST /proxy/start`、`/stop`、`/restart` | `{}` |

面板从 `/api/proxy/*` 转发过来，出错时返回 409 和 `{"error": "原因"}`。修改和启停写入服务日志（`journalctl -u vpp-proxy | grep audit`）。

## 测试

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o dist/vpp-proxy.test .
# 在 Linux 主机上运行；SINGBOX=/usr/local/bin/sing-box 时还用真的 sing-box 检查每种协议生成的配置
```
