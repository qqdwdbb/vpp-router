# gate-admin

路由页自动从 `vpp-proxy`（代理页面的管理服务）读取真实 IP 和 Fake-IP TPROXY 出口，
无需重复填写端口、DNS、地址池。`--proxy-socket` 默认 `/run/vpp-proxy/proxy.sock`，
服务的 `GET /proxy/exits` 只提供其管理的 `entry.json` 中的监听设置，不包含上游凭据。
真实 IP 模式支持域名和网段，Fake-IP 模式用于域名；IPv6 按 Gate 的 LAN 配置提供。
添加规则后由 Gate 创建透明代理设备，代理上游和启停仍由代理页面管理。
TPROXY 出口不能作为默认出口。

面板修改 Gate 规则和列表的执行程序，以 root 运行，只在本机 Unix socket 上提供接口，由 `vpp-monitor` 转发。它是独立进程，因为改规则要重启 Gate，还要在 Gate 起不来时恢复旧配置。WireGuard 由 `tools/vpp-wireguard` 负责，和它无关。

## 构建和安装

```sh
make                                   # 生成 dist/gate-admin-linux-{arm64,amd64}
sudo install dist/gate-admin-linux-arm64 /usr/local/bin/gate-admin
sudo install -m 644 gate-admin.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gate-admin
```

Gate 的配置解析通过 `vpp-egress-gate` 模块的 `admin_shared.go` 共用（`go.mod` 用 `replace` 指向 `../vpp-egress-gate`），校验和同步则调用已安装的 Gate 程序。

接口路径在 `/gate/*`，面板从 `/api/gate/*` 转发过来。

## 测试

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o dist/gate-admin.test .
# 把 dist/gate-admin.test 复制到 Linux 主机上运行
```

## 管理功能

`gate-admin` 是给管理面板用的独立进程（单元文件 `gate-admin.service`），在 root 专用的 Unix socket `/run/gate-admin/admin.sock` 上提供接口，可以切换规则出口、调整规则优先级（`routes` 的顺序）、添加和删除规则、上传和删除域名表文件、增删其中的域名。它只能管理规则引用的文件和 `--list-dir` 下的 `*.domains` 文件。没有被规则使用的文件直接保存，不重启 Gate；被使用的文件和规则本身的改动要走下面的确认流程。删除文件时只允许删除没有规则使用的，副本保留在 `--state-dir` 的 `deleted/` 下。文件可以改名（同目录、保持类型，`POST /gate/file/rename`）：没有规则使用的直接改名；被使用的文件连同引用它的规则一起改，走确认流程，确认后才删除旧文件，恢复或超时则保留旧文件、删除新文件。安装 Gate 时生成的 `proxy.domains` 因此也能改名；要删除它，先删除或修改 `proxy` 规则。


| 参数 | 默认值 | 作用 |
|---|---|---|
| `--config` | `/etc/vpp/egress-gate.json` | 你编辑的入口配置，不是生成的 `gate.json` |
| `--unit` | `vpp-egress-gate.service` | 运行 Gate 的 systemd 单元 |
| `--socket` | `/run/gate-admin/admin.sock` | 面板连接的 socket |
| `--state-dir` | `/var/lib/gate-admin` | 运行状态：待确认改动的备份和已知出口 |
| `--exits-file` | `/run/vpp-wireguard/exits.json,/run/vpp-interfaces/exits.json` | 其他程序提供的出口，多个文件用逗号分隔，文件不存在时只是少这些选项。每行 `{"interface","via"}`，或 `{"interface","dhcp":true}` 表示下一跳来自 DHCP 租约：这种出口只能做默认出口，规则不能选 |
| `--custom-exits` | `/etc/vpp/gate-exits.json` | 面板手动设置的出口和下一跳 |
| `--list-dir` | `/etc/vpp/gate` | 新建和上传域名表文件的目录 |
| `--confirm` | `1m` | 确认期限，到期未确认自动恢复 |
| `--binary` | `/usr/local/bin/vpp-egress-gate` | 执行校验和同步的 Gate 程序，管理服务和 Gate 版本不同时用它指向实际运行的 Gate |

**出口和下一跳**：`--custom-exits`（默认 `/etc/vpp/gate-exits.json`）保存面板手动设置的出口，每行 `{"name","interface","via":[IPv4, IPv6],"dhcp"}`。`POST /gate/exit` 是 `{"name","interface","via4","via6","dhcp"}`，设置一个 VPP 接口出口的下一跳，下一跳可以是经这个接口能到达的任何地址，`dhcp` 表示 IPv4 用 DHCP 租约里的网关（这样的出口只能做默认出口）。`name` 留空或等于接口名时是接口本身的出口；填别的名字时在同一个接口上另加一个出口，各有各的下一跳，用它的规则写上 `"exit": 名字`，再次设置同名出口时可以换接口，规则跟着换。名字不能是某个出口已经用到的接口名。手动设置的出口优先于规则以前用过的和其他程序提供的。用这个出口的规则（包括默认出口的规则）一起改成新下一跳，有规则改动时和其他改动一样重启 Gate 并等待确认，出口文件一起备份和恢复；规则没变时直接保存。规则的某个地址族在新出口上没有下一跳时拒绝。`POST /gate/exit/delete`（`{"name"}`，也接受旧的 `{"interface"}`）删除手动设置，规则保留现有下一跳。Linux 出口和 Fake-IP 出口的下一跳由 Gate 的设备同步生成，不能在这里设置。状态里每个出口带 `interface`、`via4`、`via6`、`dhcp`、`rules`（规则能不能用）、`custom`、`editable`。

**默认出口**：`POST /gate/default-exit`，`{"exit": "wg1"}`，空字符串改回系统路由表。出口必须是能承载真实地址的出口（Fake-IP 出口不行）。写法是给这个出口上的规则加 `"default_route": true`，每个地址族一条；出口上没有规则时加一条只带出口属性、名字是 `default` 的规则，面板不把它列为规则。之后切换、删除、添加规则时，默认出口保持在原来的出口上：规则离开或被删除时补上这样一条规则，有规则回到这个出口时把它去掉。状态里的 `default.status` 是 Gate 报告的当前情况（哪些地址族在用、为什么回落），和其他改动一样要在期限内确认。

**编辑规则**：`POST /gate/rule/edit`，`{"group","exit","dns","file":[…],"ranges":[…],"keywords":[…]}`，一次修改一组规则的出口、DNS、域名表、网段表和关键词，作为一次修改等待确认。`exit` 等于当前出口时不切换；`dns` 省略时用出口自带的 DNS，空字符串是默认 DNS。域名表和关键词写到组里每条规则；网段表按里面网段的地址族分给对应的规则，组里没有那个地址族时拒绝。规则里手写的 `domains` 保留，所有匹配条件都为空时拒绝，什么都没变时也拒绝。状态里每组带 `files`（域名表）和 `range_files`（网段表）。`POST /gate/defaults`，`{"exit","dns"}`，一次修改默认出口和默认 DNS，省略的项不变。

每次改动都会备份文件、写入、用 `--sync-devices --dry-run` 校验、执行 `--sync-devices`、重启 Gate 并等待 DNS 应答。校验失败时什么都不改；Gate 没恢复或到期未确认时，恢复旧文件并再次重启。管理服务重启后会继续倒计时，已过期的立即恢复。

修改正在使用的域名表或 IP 集合内容时，面板请求 Gate 热加载，并同步路由差异。确认超时或手动回滚也走热加载。集合从空变为启用等涉及出口设备变化的情况仍走重启流程。未使用的集合直接保存。
