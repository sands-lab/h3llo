## 内部实现

### 依赖

h3llo主要依赖tun-rs和cloudflare的tokio-quiche。

### 递归路由

由于h3llo默认会接管系统路由，将默认路由修改为全部outbound流量发送给TUN接口，这使得h3llo在创建到peers的HTTP/3连接时可能会被系统路由送到TUN接口而不是WAN接口，也就是递归路由问题。

h3llo通过将强制绑定HTTP/3 Dialer的UDP Socket到WAN接口这种措施来预防该问题。这种措施应适用于Linux，Darwin和Windows平台。

具体来说，任何时候创建HTTP/3连接（重连）都需要进行以下几步操作：

1. 解析DNS。为了应对在HTTP/3建连（特别是重连）时可能存在的网络中断，h3llo应缓存endpoints的DNS解析结果，并在解析结果过期后立刻更新该条目的缓存。在首次连接前，h3llo需要在修改默认路由前解析所有endpoints的域名并缓存。
2. 探测WAN接口名。h3llo应执行各平台对应的命令，如`ip route show match <ip>`，来探测连接到endpoints的IPs原本使用的网络接口名。注意这里需要排除TUN接口。
3. 强制绑定HTTP/3连接使用的UDP Socket到探测到的WAN接口。应使用`SO_BINDTODEVICE`，`IP_UNICAST_IF`，`IP_BOUND_IF`等option。


### 线程模型

```mermaid
flowchart TB

        wan1[WAN Interface]@{shape: h-cyl}
        tun1[TUN Interface]@{shape: h-cyl}
        prog1[Programs]@{shape: processes}
        r2[/System<br>Route Table\]
        
        
            

        subgraph cr1["Coroutine 1"]
            tr1[TUN Reader]
            q2[MPSC Queue]@{shape: h-cyl}
            r1[/Internal<br>Route Table\]
            hw1[H3/Bare Datagram Writer]@{shape: st-rect}
        end

        subgraph cr4["Coroutine 3...n+2"]
            hr1[H3/Bare Datagram Reader]@{shape: st-rect}
        end

        subgraph cr2["Coroutine 2"]
            q1[MPSC Queue]@{shape: h-cyl}
            tw1[TUN Writer]
        end

        subgraph cra[Coroutine A]
            q3[MPSC Queue]@{shape: h-cyl}
            dns1[DNS Cache]@{shape: lin-cyl}
        end

        subgraph crb["Coroutine B"]
            t1[Timer]
        end

        ctrl1["External Controller"]

        subgraph crc["Coroutine C"]
            hh1[H3 POST Handler]
        end

        

    prog1 <--> r2 <--> tun1
    tun1 --> tr1 --> r1 --> hw1 --> wan1 --> hr1 --> q1 --> tw1 --> tun1
    
    ctrl1 -. update peers and route -.-> hh1 -.-> q2 -.-> r1 -. sync -.-> r2
    t1 -. update DNS records -.-> q3 -.-> dns1
    dns1 -. update bareudp endpoint -.-> q2
    
```

h3llo使用tokio运行时调度协程，并且h3llo应使用MPSC Queue代替所有的锁以降低异步实现的复杂度，得益于MPSC Queue显式线性化了异步操作。

应当为每个I/O读创建一个协程来驱动程序的运行，比如在有多个peers的情况下，我们会创建多个HTTP/3连接。在这种情况下我们需要为每个连接创建一个协程来进行I/O读。

控制面上，外部控制器发送POST请求或者初始化时，需要先更新内部路由表，再更新系统路由表，并且在需要连接到新的peers时，建立HTTP/3连接，并创建新的协程接收这个连接的datagram。

数据面上，在发送IP包时，通过内部路由表找到目标节点的HTTP/3连接。接收IP包时，通过写入Coroutine 2的MPSC Queue保证写入TUN接口的线程安全。

另外，还应有协程作为迷你服务在后台维护DNS缓存，通过MPSC Queue处理Timer的事件或者来自Coroutine 1建连时的DNS解析请求。

### 系统路由更新

h3llo应通过执行系统命令来对单条路由进行无中断更新，如Linux的`ip route replace`，并且实现一个简单的跨平台抽象。

### 最大前缀匹配算法

h3llo在进行内部路由表的匹配时应使用和wireguard相同的算法。