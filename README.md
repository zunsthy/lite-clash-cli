> [!WARNING]
> 本项目的代码和文档由 AI 生成，尚未经过人工审查。请在使用前自行审查代码，
> 不要在不了解配置含义的情况下用于重要或敏感网络环境。

# lite-clash-cli

一个轻量、无界面的仿 clash 命令行客户端，现仅支持 trojan 协议连接。
程序直接使用 Go 标准库实现 TLS、本地代理和 Trojan TCP/UDP 线协议；除了 YAML 解析库，不依赖其他代理内核。

## 功能

- 仅支持 `type: trojan` 节点，其他节点类型会在启动前报错。
- HTTP 正向代理和 CONNECT。
- SOCKS5 TCP/UDP。
- 同一端口上的 HTTP/SOCKS5 mixed 入口。
- macOS PF TCP 透明入口。
- 本地 HTTP Basic 和 SOCKS5 用户名密码认证。
- 按节点序号或名称启动代理。
- 并发测试所有节点延迟。
- 文件配置支持通过 `SIGHUP` 热重载节点参数。

不支持规则路由、代理组、远程节点提供器、TUN、TProxy、内置 DNS、自定义 listener，
以及 WebSocket、gRPC、REALITY、ECH、uTLS 和多路复用等扩展。未识别的顶层 YAML 字段会被忽略；
Trojan 节点中出现未支持字段时会明确报错。

## 环境要求

- Go 1.26.x。
- HTTP、SOCKS5 和 mixed 入口可在 Go 支持的平台构建。
- `redir-port` 仅支持 macOS、IPv4 和 TCP，并且需要自行配置 PF 规则及 `/dev/pf` 权限。

TLS ClientHello 行为固定在 Go 1.26.x。`make build` 会拒绝其他 Go 版本，避免工具链升级导致
握手参数无意变化。

## 构建

```sh
make build
```

生成文件：

```text
bin/lite-clash
```

构建过程不会启动程序、测试节点或创建本地监听。

## 配置

默认读取当前目录的 `config.yaml`。也可以通过 `-f` 或环境变量
`LITE_CLASH_CONFIG_FILE` 指定配置文件；`-f -` 表示从标准输入读取。

最小示例：

```yaml
port: 0
socks-port: 0
redir-port: 0
mixed-port: 7890
allow-lan: false
bind-address: 127.0.0.1
ipv6: false
unified-delay: true

authentication:
  - 'local-user:change-this-password'

proxies:
  - name: example
    type: trojan
    server: example.com
    port: 443
    password: replace-with-your-password
    sni: example.com
    skip-cert-verify: false
    udp: true
```

四个本地端口相互独立，值为 `0` 时不创建对应监听：

| 字段 | 入口 |
|---|---|
| `port` | HTTP |
| `socks-port` | SOCKS5 TCP/UDP |
| `mixed-port` | HTTP/SOCKS5 TCP/UDP |
| `redir-port` | macOS PF TCP 透明入口 |

指定节点启动代理时，至少需要启用一个本地端口。`authentication` 的格式为
`用户名:密码`，同时应用于 HTTP、SOCKS5 TCP 和 SOCKS5 UDP 授权。

## 使用

先查看节点序号，不创建监听或连接节点：

```sh
./bin/lite-clash -f config.yaml --list-proxies
```

使用第 2 个节点启动代理，节点序号从 1 开始：

```sh
./bin/lite-clash -f config.yaml --proxy-index 2
```

也可以按名称选择：

```sh
./bin/lite-clash -f config.yaml --proxy 'example'
```

查看帮助和版本：

```sh
./bin/lite-clash --help
./bin/lite-clash --version
```

收到 `SIGINT` 或 `SIGTERM` 时，程序会关闭监听和活动连接。收到 `SIGHUP` 时会重新读取文件配置；
监听端口、绑定地址或认证发生变化时必须重启程序。

## 节点测速

不指定 `--proxy-index` 或 `--proxy` 时，程序不会启动代理，而是并发测试配置中的全部节点，
按原始配置顺序输出序号、名称和延迟，然后退出：

```sh
./bin/lite-clash -f config.yaml
```

测速固定向 `http://cp.cloudflare.com/generate_204` 发送 HTTP `HEAD` 请求，每个节点的总超时为
5000 毫秒。`unified-delay: true` 时，程序会尽量复用连接发送第二次请求，并使用第二次耗时。

> [!CAUTION]
> 上述命令会通过每一个节点建立真实连接并发送请求。只想查看节点列表时必须使用
> `--list-proxies`。

输出示例：

```text
1    example-a    128 ms
2    example-b    fail: context deadline exceeded
```

## 透明入口

`redir-port` 只负责接收已经被 macOS PF 重定向的 TCP 连接，不会自动安装或修改 PF 规则。
程序会查询 `/dev/pf` 恢复原始 IPv4 目标地址，再通过选中的 Trojan 节点转发。PF 规则必须排除
代理服务器地址和程序自身流量，否则可能形成重定向回环。不使用透明代理时请将其设为 `0`。

## 项目结构

```text
cmd/lite-clash       CLI、配置载入和进程生命周期
internal/benchmark   节点延迟测试
internal/config      YAML 解析、校验和节点选择
internal/proxy       HTTP、SOCKS5、mixed 和透明入口
internal/socksaddr   SOCKS 地址编解码
internal/trojan      Trojan TCP/UDP 和 TLS
```

## 安全提示

- 配置文件包含明文节点密码和本地认证信息，请限制文件权限。
- `skip-cert-verify: true` 会关闭服务器证书校验，不建议使用。
- 启用 `allow-lan` 前应配置强密码，并确认监听地址和防火墙范围。
- `test-config.yaml`、`config.yaml`、密钥文件和构建产物已加入 `.gitignore`，发布前仍应检查待提交文件。
- 本项目由 AI 生成，不提供安全性、可用性或兼容性保证。

