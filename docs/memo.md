
- 使用反引号包裹配置字段名（如`local.id`），保持字段引用格式一致；代码块内不强制。
- 术语约定：HTTP/3 与 BareUDP 作为两种 protocol 描述，不再使用 data plane 说法。 
- 配置值（如布尔、数字）在文档描述中使用反引号标注，例如`true`、`1280`；代码块内不标注。 
- 文档中暂未确定的设计细节可用“TBD”占位，后续补全。
- README Quick Start 统一使用`peers`列表+`id`字段；HTTP Basic Auth 自动生成：CONNECT 使用 `username = client local.id`、`password = server local.id`，控制平面仅在配置 `local.h3.admin` 时启用，GET/POST 使用 `username = local.h3.admin`、`password = server local.id`，与 CONNECT 共享路径，HTTP 请求不做源 IP 校验。
- mermaid 图内换行使用 `<br>`，不要使用 `\n`。
- `local.h3.admin` 需超过 8 个字符，作为控制平面开启条件。
