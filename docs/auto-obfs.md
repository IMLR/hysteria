# 同端口自动兼容混淆

本分支基于上游 `app/v2.13.0`，提交
`ca8fbd874fd6ca82413948de6dc5924405e103e1`。

服务端在同一个 UDP 监听端口接受不混淆、Salamander 和 Gecko，并使用客户端
握手选择的模式回复。客户端不需要支持新增的 `auto` 配置；Shadowrocket 可继续
选择 Salamander，支持 Gecko 的客户端继续选择 Gecko。

## 服务端配置

保留原有 `listen`、TLS、认证、出站和端口跳跃配置，仅替换 `obfs`：

```yaml
obfs:
  type: auto
  auto:
    password: "replace-with-your-existing-obfs-password"
    minPacketSize: 512
    maxPacketSize: 1200
```

- `password` 是 Salamander 与 Gecko 共用的混淆密码，至少 4 字节。
- `minPacketSize`、`maxPacketSize` 只控制 Gecko 握手分片的填充，默认分别为
  512 和 1200，沿用上游 Gecko 的参数校验。
- 不混淆的客户端不填写混淆密码；三种模式都仍然需要原有 Hysteria 认证和 TLS。
- `auto` 仅用于服务器。原有 `plain`、`salamander`、`gecko` 配置继续工作。

## 客户端配置

三种客户端使用相同的服务器地址、端口或跳跃端口范围，以及相同的 Hysteria
认证信息和 TLS 配置。只需按客户端能力设置混淆：

```yaml
# Salamander，包括仅支持此模式的客户端
obfs:
  type: salamander
  salamander:
    password: "same-obfs-password"
```

```yaml
# Gecko
obfs:
  type: gecko
  gecko:
    password: "same-obfs-password"
```

不混淆时删除客户端的整个 `obfs` 配置。

## 实现

`extras/obfs/auto.go` 复用上游 Salamander 加解混淆、Gecko 分片和有界重组逻辑。
通过 QUIC v1/v2 长头结构与 Gecko 的 `0x80` 分片标记识别握手。
不能只通过 UDP 首字节判断模式，因为 Salamander 的随机盐可能具有相同的位模式。

回复模式附带于交给 QUIC 的 `net.Addr`，随连接保存，地址的 `String()` 和
`Network()` 保留真实客户端端点。后续其他握手不会更改已有连接的回复模式。
该包装类型不是 `*net.UDPAddr`，外部认证与日志应通过 `net.Addr` 接口读取地址。

接收路径最多保留 4096 个端点提示，以避免正常数据包重复解码。提示记录该端点
出现过的格式集合，并按 LRU 淘汰。端口跳跃、NAT 地址变化或同一端点同时使用
两种外层格式时，短头可能无法单凭数据区分，此时将候选数据交给 QUIC 的 AEAD
验证。地址变化后的 Gecko 数据包与 Salamander 格式相同，可以继续通信。
提示不承担认证职责；错误候选可能触发 QUIC 的常规无状态重置回复。

UDP 缓冲区和系统调用接口继续传递给底层 socket。关闭连接时同时停止 Gecko
重组清理任务。

`app/cmd/server.go` 增加 `obfs.auto` 配置入口；客户端协议和 QUIC 核心没有修改。

## GitHub 构建与验证

[Linux amd64 工作流](../.github/workflows/linux-amd64.yml) 在 GitHub runner 上执行：

1. 混淆包的竞态检查，以及 core、extras、app 的现有测试。
2. 仅编译 Linux amd64，`GOAMD64=v1`、`CGO_ENABLED=0`。
3. 下载并校验官方 v2.13.0 客户端，用真实 TCP/UDP 流量验证三种模式同时连接
   一个服务端端口、NAT 地址变化、端口跳跃、有丢包时的 TCP 传输和错误密码拒绝。
4. 上传 `hysteria-linux-amd64`、`SHA256SUMS` 与 `version.txt`，保留 14 天。

不运行多平台构建、Docker 发布或上游 Cloudflare 发布任务。生产服务器只需下载
并验证构建产物，无需安装编译依赖。

真实客户端验证脚本为 [scripts/test-auto-obfs.py](../scripts/test-auto-obfs.py)，
只依赖 Python 标准库、OpenSSL 和两个现成的 Hysteria 二进制：

```sh
python3 scripts/test-auto-obfs.py \
  --server /path/to/custom/hysteria-linux-amd64 \
  --client /path/to/official-v2.13.0/hysteria-linux-amd64
```

脚本使用本地临时证书、随机测试密码和回环端口，结束后清理进程与临时文件。
它验证官方客户端的协议兼容性；Shadowrocket 的手机端操作需在实际客户端检验。
