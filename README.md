# TcpShow

简单直接的 HTTP/HTTPS 抓包桌面软件，用法接近 Charles：本机开代理，看请求列表，点进去看头和正文。

## 功能

- HTTP / HTTPS（MITM）抓包
- 原生桌面窗口（不是网页）
- 请求列表 + 请求/响应详情
- 过滤、录制开关、清空
- 复制为 cURL
- macOS 一键开/关系统代理
- 本地 CA 证书，用于解密 HTTPS

## 运行

需要 Go 1.22+（macOS 编译 Fyne 需要 CGO / Xcode Command Line Tools）。

```bash
go mod tidy
go run .
```

默认监听 `127.0.0.1:8888`。

也可以直接打开项目里的 `TcpShow.app`（黑色底、橙色圆环的图标），Dock 和访达里都好看得到。

打包成 Mac 应用：

```bash
go install fyne.io/fyne/v2/cmd/fyne@latest
fyne package -os darwin -name TcpShow
```

## 使用

1. 启动 TcpShow，确认底部状态是「监听 127.0.0.1:8888」
2. 点 **安装证书**，在系统弹窗里输入本机密码。这一步会把 `TcpShow CA` 写进系统钥匙串并设为始终信任（只把证书加进钥匙串不够）
3. 软件会同时打开 **系统代理**。然后**完全退出并重新打开浏览器**
4. 若不想用系统代理，也可以手动：

```bash
export http_proxy=http://127.0.0.1:8888
export https_proxy=http://127.0.0.1:8888
curl --cacert "$HOME/Library/Application Support/TcpShow/ca.pem" https://example.com
```

也可以只让某个 App / 浏览器走代理。Firefox 要在浏览器里单独导入证书。

5. 在左侧列表点一条记录，右侧看请求、响应
6. 退出软件时会自动关掉它打开的系统代理

## 说明

- 证书和私钥在 `~/Library/Application Support/TcpShow/`
- 单条正文最多保存 2MB
- HTTPS 只走 HTTP/1.1 解密（简单直接，不解析 HTTP/2）
- 这是本机调试工具，请只抓你自己授权的流量
