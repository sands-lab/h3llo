## 完整配置

```yaml
local:
  uuid: e41a6f46-c132-4d0e-9b38-34ed4a000002
  table: true # optional, default is true 
  h3: # optional
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
  bare: # optional
    listen: udp://[::]:6635
  tun:
    ifname: h3llo0 # optional, default is h3llo0
    addr:
    - 192.168.180.2/32
    mtu: 1280 # optional, default is 1280
peers:
- uuid: e41a6f46-c132-4d0e-9b38-34ed4a000001
  enabled: true # optional, default is true
  h3: # optional, conflict with peers.bare
    endpoint: https://node1.example.com:443/path
    ca: ./ca.pem # optional
    insecure: false # optional, default is false
  bare: # optional, conflict with peers.h3
    endpoint: udp://node1.example.com:6635
  tun:
    allowedIPs:
    - 192.168.180.1/32
```

- `table`：是否自动修改系统路由表。
- `ca`：自签名CA证书的路径。
- `insecure`：跳过SSL证书的有效性检查（强烈不建议）。如使用自签名证书，建议通过指定CA证书来完成有效性检查。