
- 使用反引号包裹配置字段名（如`local.id`），保持字段引用格式一致；代码块内不强制。
- 术语约定：HTTP/3 与 BareUDP 作为两种 protocol 描述，不再使用 data plane 说法。 
- 配置值（如布尔、数字）在文档描述中使用反引号标注，例如`true`、`1280`；代码块内不标注。 
- 文档中暂未确定的设计细节可用“TBD”占位，后续补全。
- README Quick Start 统一使用`peers`列表+`id`字段；HTTP Basic Auth 自动生成：CONNECT 使用 `username = client local.id`、`password = server local.id`，GET/POST 两者均为 server `local.id`，与 CONNECT 共享路径，HTTP 请求不做源 IP 校验。
- `local.table=false` 时不修改系统路由，OS 会为 `local.tun.addr` 添加连接路由；额外路由仅在 `local.table=true` 时根据 `peers[].tun.allowedIPs` 添加；动态更新需要 `local.h3.listen`，且在 `local.table=true` 时同步系统路由。
- BareUDP 需可互访静态 IP、无 NAT；解析出多个 IP 时 panic，不跟踪后续 DNS 变更（未定义行为）；仅做源 IP 过滤。
- MTU 策略：默认`1410`安全覆盖 IPv6 CONNECT-IP；IPv4 CONNECT-IP 可升至`1430`；仅 BareUDP 时上限 `1472/1452`；混用取下限以避免分片。
- 系统路由更新命令：Linux `ip route replace`，Darwin `route -n add/change`，Windows `netsh interface ipv4 add route`；执行失败记录为警告后继续，平台不支持时 panic。
