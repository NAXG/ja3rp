# JA3RP (JA3 反向代理)

Ja3RP 是一个基于 [JA3](https://github.com/salesforce/ja3) 指纹的基本反向代理服务器，用于过滤流量。它也可以作为常规的 HTTP 服务器用于测试目的。

灵感来自于这个 [ja3-server](https://github.com/CapacitorSet/ja3-server) POC。

## 架构

本项目通过以下几个关键组件实现基于 JA3 指纹的流量过滤：

### 核心组件

1. **修改的 Go 标准库**：自定义实现的 `crypto/tls` 和 `net/http` 包，用于在 TLS 握手期间提取 JA3 指纹
2. **JA3 指纹提取**：JA3 指纹在 `crypto/tls/common.go:JA3()` 方法中提取
3. **服务器架构**：主服务器 (`ja3rp.go`) 以两种模式运行：
   - **反向代理模式**：当 JA3 匹配条件时将流量转发到目标服务器
   - **HTTP 服务器模式**：用于测试的独立 HTTP 服务器
4. **流量过滤**：使用 JA3 字符串的 MD5 哈希进行白名单/黑名单过滤
5. **早期 TLS 检测**：在 TLS 握手阶段执行 IP 和 JA3 指纹检测，实现立即阻止

### 关键文件

- `ja3rp.go`：核心服务器实现和主服务器逻辑
- `mux.go`：自定义 HTTP 请求多路复用器（从 Go 标准库修改）
- `crypto/tls/`：修改的 TLS 实现，包含 JA3 指纹提取
- `net/http/`：包含 JA3 支持的修改 HTTP 服务器
- `cmd/main.go`：运行服务器的 CLI 入口点

## 安装

```bash
# 克隆仓库
git clone https://github.com/naxg/ja3rp.git
cd ja3rp

# 安装依赖
go mod download

# 构建二进制文件
go build ./cmd/main.go

# 或者全局安装
go install ./cmd/main.go
```

## 使用

### 准备工作

JA3 哈希是从 TLS ClientHello 数据包构建的。因此 JA3RP 服务器需要 SSL 证书才能工作。

您可以使用以下命令生成自签名证书：

```bash
$ openssl req -new -subj "/C=US/ST=Utah/CN=localhost" -newkey rsa:2048 -nodes -keyout localhost.key -out localhost.csr
$ openssl x509 -req -days 365 -in localhost.csr -signkey localhost.key -out localhost.crt
```

**注意**：项目包含测试证书在 `internal/tests/data/` 中，可用于测试目的。

### 包使用

以下示例启动一个 HTTPS 服务器并基于 JA3 哈希过滤传入流量。
如果哈希在白名单中找到，流量将被转发到配置的目标服务器。
否则或被列入黑名单，请求将被阻止。

```go
package main

import (
	"fmt"
	"github.com/naxg/ja3rp"
	"github.com/naxg/ja3rp/net/http"
	"log"
	"net/url"
)

func main() {
	address := "localhost:1337"
	d, _ := url.Parse("https://example.com")

	server := ja3rp.NewServer(address, ja3rp.ServerOptions{
		Destination: d,
		Whitelist: []string{
			"bd50e49d418ed1777b9a410d614440c4", // firefox
			"b32309a26951912be7dba376398abc3b", // chrome
		},
		Blacklist: []string{
			"3b5074b1b5d032e5620f69f9f700ff0e", // CURL
		},
		OnBlocked: func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("Sorry, you are not in our whitelist :(")
		},
	})

	err := server.ListenAndServeTLS("certificate.crt", "certificate.key")

	log.Fatal(err)
}
```

### CLI 使用

#### 基本用法
```bash
$ ja3rp -h
Usage: ja3rp -a <address> [-d <destination URL> -c <cert file> -k <cert key> -w <whitelist file> -b <blacklist file>]
Example: $ ja3rp -a localhost:1337 -d https://example.com -c certificate.crt -k certificate.key -w whitelist.txt -b blacklist.txt
```

#### 示例

**白名单模式**（只允许特定客户端）：
```bash
$ ja3rp -a localhost:1337 -d https://example.com -c cert.crt -k cert.key -w whitelist.txt
```

**黑名单模式**（阻止特定客户端）：
```bash
$ ja3rp -a localhost:1337 -d https://example.com -c cert.crt -k cert.key -b blacklist.txt
```

**HTTP 服务器模式**（用于测试，无代理）：
```bash
$ ja3rp -a localhost:1337 -c cert.crt -k cert.key
```

**TLS 阶段检测示例**（编程使用）：
```go
package main

import (
    "github.com/naxg/ja3rp"
    "net/url"
)

func main() {
    destination, _ := url.Parse("https://api.example.com")

    server := ja3rp.NewServer("0.0.0.0:443", ja3rp.ServerOptions{
        Destination: destination,
    })

    server.TLSConfig.IPBlacklist = []string{
        "192.168.1.100",
        "10.0.0.50",
    }
    server.TLSConfig.JA3Blacklist = []string{
        "bd50e49d418ed1777b9a410d614440c4",
        "suspicious_bot_fingerprint",
    }

    server.ListenAndServeTLS("cert.crt", "cert.key")
}
```

哈希应该存储在 .txt 文件中，每行一个。

### TLS 阶段检测

JA3RP 在 **TLS 握手级别**实现早期检测，在不需要的连接到达 HTTP 层之前提供立即阻止。

#### IP 地址检测
- **位置**：[`crypto/tls/handshake_server.go:48-55`](crypto/tls/handshake_server.go:48-55)
- **机制**：在 TLS 握手期间检查客户端 IP 是否在黑名单中
- **实现**：
  ```go
  if len(c.config.IPBlacklist) > 0 {
      remoteAddr := c.conn.RemoteAddr().String()
      if isIPBlacklisted(remoteAddr, c.config.IPBlacklist) {
          c.sendAlert(alertHandshakeFailure)
          return fmt.Errorf("tls: IP address %s is blacklisted", remoteAddr)
      }
  }
  ```

#### JA3 指纹检测
- **位置**：[`crypto/tls/handshake_server.go:65-69`](crypto/tls/handshake_server.go:65-69)（TLS 1.3）和 [`crypto/tls/handshake_server.go:81-85`](crypto/tls/handshake_server.go:81-85)（TLS 1.2/1.1）
- **机制**：从 ClientHello 提取 JA3 指纹并检查是否在黑名单中
- **实现**：
  ```go
  if len(c.config.JA3Blacklist) > 0 && isJA3Blacklisted(c.JA3, c.config.JA3Blacklist) {
      c.sendAlert(alertHandshakeFailure)
      return fmt.Errorf("tls: JA3 fingerprint %s is blacklisted", c.JA3)
  }
  ```

#### 检测流程
1. **TCP 连接建立** → 立即检查客户端 IP
2. **TLS 握手开始** → 从 ClientHello 提取 JA3 指纹
3. **早期决策制定** → 如果任一检查失败则终止连接
4. **绕过 HTTP 层** → 被阻止的连接不进入 HTTP 处理

#### 配置选项
- **IP 黑名单**：TLS 配置中的 `IPBlacklist []string`
- **JA3 黑名单**：TLS 配置中的 `JA3Blacklist []string`
- **检测时机**：在任何 HTTP 头被处理之前发生

这种早期检测机制提供：
- **性能**：不需要的连接在 TLS 级别被拒绝
- **安全性**：恶意客户端永远不会到达应用层
- **效率**：通过在 HTTP 处理前过滤减少资源使用

#### 性能优势

| 检测方法 | 处理阶段 | 资源使用 | 响应时间 |
|----------|----------|----------|----------|
| **TLS 阶段检测** | 握手层 | 最小化（HTTP 前） | 立即 |
| 传统检测 | HTTP 层 | 完整 HTTP 处理 | 延迟 |

**主要优势：**
- **零 HTTP 开销**：被阻止的连接从不消耗 HTTP 处理资源
- **即时响应**：TLS 握手失败警报提供即时反馈
- **内存高效**：被阻止的连接不创建 HTTP 请求/响应对象
- **CPU 优化**：对黑名单连接执行最少的加密操作

## 开发

#### 构建和测试
```bash
# 运行测试
go test -v

# 运行特定测试
go test -v -run TestReverseProxy

# 构建项目
go build ./cmd/main.go

# 更新依赖
go mod tidy
```

#### 使用证书测试
项目包含自签名证书在 `internal/tests/data/` 中，测试会自动使用这些证书进行 TLS 连接。

#### JA3 指纹格式
JA3 指纹构造为：`SSLVersion,AcceptedCiphers,Extensions,EllipticCurves,EllipticCurvePointFormats`

## 许可证

本项目使用 [MIT 许可证](LICENSE) 授权。

包含的（然后修改的）`net/http`、`internal/profile` 和 `crypto` 包属于 [go 源代码许可证](./LICENSE_GO.txt)。