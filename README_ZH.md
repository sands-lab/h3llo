# h3llo: HTTP/3-based Low-latency Overlay

h3llo是一个基于标准HTTP/3上的MASQUE/CONNECT-IP（[RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)）协议和BareUDP协议的轻量级低延迟VPN。

## 快速开始

我们首先给出一个包含两个节点的示例配置。如果你熟悉`wg-quick`的配置，那么相信你将很快能理解h3llo的配置。

```yaml
# Configuration on node1
local:
  uuid: e41a6f46-c132-4d0e-9b38-34ed4a000001
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
  tun:
    ifname: h3llo0
    addr:
    - 192.168.180.1/32
peers:
  e41a6f46-c132-4d0e-9b38-34ed4a000002:
    tun:
      allowedIPs:
      - 192.168.180.2/32
```
```yaml
# Configuration on node2
local:
  uuid: e41a6f46-c132-4d0e-9b38-34ed4a000002
  tun:
    ifname: h3llo0
    addr:
    - 192.168.180.2/32
peers:
  e41a6f46-c132-4d0e-9b38-34ed4a000001:
    h3:
      endpoint: https://node1.example.com:443/path
    tun:
      allowedIPs:
      - 192.168.180.1/32
```

将配置文件保存为`host/config.yaml`以后，就可以一键启动h3llo的Docker容器了。

```bash
docker run -d --name h3llo --restart always --network host --cap-add=NET_ADMIN -v host/config.yaml:/config.yaml h3llo/h3llo -c /config.yaml
```

## 配置项

### 架构

和WireGuard类似，h3llo的每个节点是对等的，不严格区分客户端和服务端，但它们也都支持以类似客户端-服务端的架构建立连接。

**客户端-服务端架构**。在示例中我们可以看到`node1`只配置了HTTP/3的监听端口，而`node2`未配置监听端口，同时只有`node2`给出了`node1`的`endpoint`地址。这种类似客户端-服务端的架构足够让`node1`和`node2`建立连接。

**对等架构**。如果`node1`和`node2`都配置了监听端口，并且都在`peers`中指定了对方的`endpoint`，这种完全对等的配置也是支持的。h3llo将会创建两条连接并随机选择一条使用。

### 认证与安全

h3llo需要为每个节点指定独一无二的`uuid`用于身份的识别和验证。同时h3llo依赖QUIC内建的TLS保证传输层的安全，因此h3llo需要正确的配置SSL证书，即指定`cert`和`key`，来防范MitM攻击。

h3llo的URI（即`listen`和`endpoint`的字符串）包含了一个HTTP Path。这个Path可以为任意合法的值，保证连接双方的Path一致即可。

### 路由

首先h3llo会根据`peers`的`allowedIPs`修改系统路由表，以确保系统将目标IP在`allowedIPs`范围内的IP报文送入h3llo的TUN接口。

由于h3llo可能存在多个peers，因此在发送IP报文的时候，h3llo会在内部对目标IP进行最长前缀匹配，来将该报文发送到正确的peer。

## BareUDP模式

除了HTTP/3 + CONNECT-IP外，h3llo同时支持BareUDP协议以在受控网络下建立VPN。在使用BareUDP协议时，h3llo对传输的数据不进行任何加密。

## 互操作性

### 与CDN

目前主流的大型CDN尚未支持HTTP/3回源，因此目前h3llo大概率无法通过CDN进行L7转发。

### 与Cloudflare WARP

h3llo使用了与WARP不同的认证方法，应考虑使用[usque](https://github.com/Diniboy1123/usque)这个开源MASQUE WARP客户端。

