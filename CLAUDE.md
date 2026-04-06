## 关键词

【】符号用于标识【关键词】。【关键词】指在本语境下有特定含义的词汇。

源于 RFC 2119 / 8174 的关键词：

- 【必须】：绝对的要求。同 “MUST” / “REQUIRED”。
- 【不能】：绝对的禁止。同 “MUST NOT”。
- 【应当】：建议。同 “SHOULD” / “RECOMMENDED”。
- 【不应】：不建议。同 “SHOULD NOT”。
- 【可能】：同 “MAY” / “OPTIONAL”。

## 语言

- 如果有 Output Format Section，【必须】按照 Output Format Section 的语言输出。
- 如果没有 Output Format Section，
    - 【必须】用中文与我交流与解释，无论我使用什么语言。使用中文编写【记忆prompt】。
    - 【必须】使用英文编写其余部分（包括代码、文档、注释、commit message、GitHub Issues和PR等）。

## 能力边界

【能力边界】指在当前环境下你可以和不可以完成的操作范围。

- 【必须】进行大量的联网搜索获得最新的知识。没有大量网络研究是无法交付符合质量的产出的。
- 【不应】使用你记忆中的知识，它们不是过时的就是模糊的。
- 【应当】进行缜密的思考，即便花上很长的时间也没关系。不周密的思考很可能导致产出质量降低，反而需要浪费时间进行改进。
- 【应当】自信的指出问题。你的能力在我之上。
- 【不能】在超出【能力边界】的情况下声称已完成相关操作（如“已阅读某文件”“已执行某命令”）。
- 当【能力边界】限制了任务质量时，【必须】说明受限之处。

### 记忆 Prompt

【记忆prompt】是自动从对话中归纳的本项目实操过程中的具体要求和行动准则。[memo.md](.claude/memo.md)中保存了【记忆prompt】。

- 如果当前对话中有可归纳和固化为长期准则的内容，【应当】询问是否更新【记忆prompt】。
- 【必须】使用 markdown bullet points，用【主prompt】相同的风格编写【记忆prompt】。

## 文档索引

### 用户文档

- [README.md](README.md)：项目概览、特性摘要、Quick Start 与配置高层背景。
- [docs/configuration.md](docs/configuration.md)：完整配置示例、字段默认值与互斥规则说明。

### 开发者文档

- [docs/internals.md](docs/internals.md)：内部架构与线程模型、路由更新策略及循环路由防护。
- [docs/performance.md](docs/performance.md)：性能优化策略、profiling 数据与基准测试结果。
- [docs/plan.md](docs/plan.md)：迭代计划、模块顺序与测试闸口。
- [docs/protocol.md](docs/protocol.md)：认证方案、HTTP/3 CONNECT-IP 与 BareUDP 行为、动态重配置规则。
- [docs/refactoring.md](docs/refactoring.md)：重构模式库，三层分级（代码卫生 / 日常改进 / 架构级），~60 个可复用策略。
- [docs/test.md](docs/test.md)：测试分层指南、容器化多节点测试思路、证书策略示例。

## 文档要求

- 【必须】将 [README.md](README.md) 以外的文档放在 `docs/` 目录。
- 【必须】保持各文档之间以及文档与代码之间的一致性。
- 【应当】保证文档内容清晰、无歧义。
- 【应当】按照从 overview 到 details 的顺序介绍：
    - 在多个子章节 / 多个段落前给出不超过三行的 overview。
    - 每个 bullet point 应以关键词或一行 overview 开头。
- 如果 overview 过长，【应当】拆分成多个子章节 / 段落 / bullet points。相对的，如果 details 信息量不足，【应当】以仅 overview 的形式呈现。
- 【应当】在合适场景使用 mermaid 示意图进行说明；【不应】在单个图中塞入过多元素。
- 若单个 mermaid 图元素较多或结构复杂，【应当】询问是否拆分为多个图。
- 【必须】得到我的许可才能创建或更新 mermaid 图。
- 【应当】保持单个文档长度在 500 行以内；超过时【应当】考虑拆分为多个文档。

## 代码要求

- 注释
    - 【必须】为所有对外暴露（pub）的 API（函数/类型/trait 等）补全 rustdoc：一句英文摘要 + 按需提供 # Arguments / # Returns / # Errors / # Examples。
    - 【应当】对“非直观/易踩坑”的内部逻辑写注释，说明意图与关键约束。
-  风格与结构
    - 【应当】遵循统一风格（命名/缩进/错误处理）；避免重复代码、过度工程和高耦合；优先通过模块化/封装提升可维护性。
    - 【应当】使用 early return 避免缩进嵌套。【应当】积极使用库提供的方法，尽量避免重复造轮子。
- 并发
    - 【应当】在能简化正确性/降低锁竞争时，优先消息传递（如 MPSC）而非共享可变状态加锁。
- Idiomatic / Modern Rust
    - 【应当】使用惯用 Rust：?、所有权/借用、清晰的错误类型与边界；在合适场景使用 async、impl Trait 等提升表达力。
- 性能（性能敏感路径）
    - 【应当】尽量减少拷贝，复用 buffer 或采用零拷贝策略。
    - 【应当】优先静态分发，避免不必要的运行期多态，便于内联与优化。

## Git 要求

- 【必须】始终创建新 commit，【不能】使用 `git commit --amend`，除非我明确要求 amend。

## 任务要求

- 在当前阶段，【应当】以追求最佳实践，提高代码质量，简化设计，减少代码量为最重要的目标。【应当】积极质疑和提升已有设计，文档和代码。在当前阶段应彻底放弃向前兼容性。

