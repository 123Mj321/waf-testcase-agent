# AI 使用说明 AI Usage

本文件记录的两种事物在工程里都叫 "AI"，把它们分开写明是交付要求，不是行文风格问题。

- **A. AI 辅助开发 AI-assisted development** —— 有助手参与了本仓库代码的编写。
- **B. 运行时 LLM 用例生成 Runtime LLM testcase generation** —— 交付的工具本身在运行时调用模型来*提议*测试用例。

后者是产品能力，完整描述见 `README.md` 第 5、6 节；前者是开发过程溯源，描述在这里。

---

## A. AI 辅助开发 AI-assisted development

**助手：** 全程使用 CodeBuddy（IDE 编码助手）起草模块、重构既有代码、并针对失败进行迭代。

**人工负责的部分。** 以下内容由工程师本人决策与评审，未委托给助手：

- 流水线形态与模块边界（parser / generator / executor / harness / validator / report / CLI）
- `RuleSpec` 与 `CaseSpec` 的数据契约
- 生成器与规则感知校验器中编码的 ModSecurity 规则语义
- 验收标准：gold 作为独立 oracle、三层验证分离、显式退出码
- 各模块的测试设计与覆盖要求
- 诚实性规则：不伪造状态码、不伪造 LLM 调用、不把 "NOT RUN" 报成成功

**AI 产出代码必须经过的验证。** 每一处助手生成的改动都必须通过以下全部检查才会被保留：

1. `python -m pytest`（完整套件，不允许只跑子集）
2. 离线 CLI 运行：`baseline`，以及无凭据下的 `hybrid`，检查降级路径而不是假设模型跑过
3. gold 校验仍为 baseline 集的 `16/16`
4. 通过 `docker compose` 的真实 WAF 执行（`HttpExecutor`，非 mock）
5. 面向 LLM 层的真实 OpenAI 兼容 provider 调用，并覆盖其失败模式（超时、HTTP 错误、推理截断）
6. 静态审计：无未使用 import、无 `TODO`、无硬编码路径、源码与产物中无 secret

**开发日志。** 助手产出了什么、问题在哪、如何修正：

| # | 阶段 | 助手产出 | 发现的问题 | 修正方式 |
|---|---|---|---|---|
| 1 | 项目分析 | 从 `docker-compose.yml`、`rules.conf`、`gold.json` 推导流水线设计 | 通用性不明确 | 改为按规则形态匹配策略的策略注册表，而非按 rule id |
| 2 | RuleSpec + Parser | `RuleSpec`、支持引号与转义的 parser | 朴素 `split(",")` 会破坏含逗号、引号、`\|`、`\s` 的正则 | 改为状态机解析，完整保留 operator 参数原文 |
| 3 | CaseSpec + Generator | `CaseSpec` + 策略模式 | 规则 1006 是 `pass` + `ctl:ruleEngine=off`，不能按普通 deny 处理 | 增加差分控制策略，自动定位下游阻断探针 |
| 4 | HttpExecutor | `HttpExecutor`、`ExecutionResult` | httpx 会对 `%2e` 二次编码；系统代理干扰本地请求 | 保留已有百分号编码，`trust_env=False` |
| 5 | pytest harness | `PytestHarness`、`parametrize_cases` | 不允许动态生成 Python 测试源码；执行错误不能伪装成断言失败 | 使用静态 `pytest.param` 参数化，执行错误用 `pytest.fail` 并保留详情 |
| 6 | Gold validator | 独立 gold 比对 | 依赖顺序；`null` 与 `""` 与缺失混淆不清 | 按 `(rule_id, type)` 索引，结构化 `GoldDiff`，引入 `MISSING_VALUE` 哨兵 |
| 7 | Report | `TestReport`、阶段状态、终端 + JSON 输出 | "Docker 没起来"可能被报成 SUCCESS | 引入 `NOT_RUN` / `INCOMPLETE`，没有执行结果就不得返回 SUCCESS |
| 8 | CLI | `argparse` 流水线、退出码 | Windows 下无法执行 bash wrapper | 增加 `python -m testcase_gen.cli` 入口与 POSIX wrapper |
| 9 | 真实 WAF 集成 | 观测到 16/16 状态码匹配 | 容器挂载源不是当前工作目录 | 比对三份输入文件的 SHA256 |
| 10 | LLM 层 | `prompt.py` / `llm.py` / `validation.py` / `audit.py` 与 CLI 模式 | 助手最初让模型的语义主张直接通过；`max_tokens` 会击穿推理模型 | 校验器复算 target/operator/transformation 语义并自行推导 `expected_code`；默认不传 `max_tokens`，给出可定位的截断报错 |
| 11 | LLM 校验细节 | wire value 提取、去重、冲突检测 | `parse_qs` 会自动解码，破坏 `urlDecodeUni` 场景 | 改为按 `&`/`=` 原样切分；去重集合以 baseline 用例做种子 |
| 12 | 推理模型调试 | 定位空响应根因 | `max_tokens=2000` 被 `reasoning_tokens` 全部消耗 | 不再发送 `max_tokens`，提高默认超时，报错中给出 `finish_reason` 与 `reasoning_tokens` |
| 13 | LLM 用例的真实 WAF 比对 | 8 条 negative 用例返回 `403` | `rules.conf` 不是镜像里唯一的拦截层 | 结果如实保留，新增 `--llm-no-execute`，并在文档写明该边界 |

---

## B. 运行时 LLM 用例生成 Runtime LLM testcase generation

这是交付工具的运行时行为，不是开发活动。

```text
RuleSpec
   ↓  prompt.py      结构化 RuleSpec → 严格约束的 JSON prompt
LLM
   ↓  llm.py         OpenAI 兼容 HTTP 调用，记录 latency 与 token usage
Candidate Parser
   ↓  validation.py  容忍 markdown 代码块围栏，校验 schema 与 rule_id
Rule-aware Validator
   ↓  validation.py  target / operator / transformations / negation /
                     可执行性 / 跨规则冲突 / 去重
CaseSpec
   ↓                 仅保留通过校验的候选
Executor → Gold Validator → Report
```

职责划分：

| 组件 | 负责什么 |
|---|---|
| `RuleSpec` | 提供规则事实 |
| LLM | 提供候选*想法* |
| Validator | 负责可信性过滤 |
| `expected_code_for_rule()` | 负责期望状态码 —— **不是 LLM** |
| `gold.json` | 负责基准比对，绝不是生成素材 |

---

## C. 审计日志 Audit log

`artifacts/ai_usage_log.jsonl` 由代码在每次运行时**自动写入**。没有需要人工填写的内容，也没有需要记得去做的事情。

每次 LLM 生成尝试写一行 JSON 对象：

| 字段 | 含义 |
|---|---|
| `timestamp` | 该次尝试的 UTC 时间戳 |
| `provider` / `model` | 解析出的 provider 与实际应答的 model |
| `prompt_version` | 例如 `waf-testcase-candidate-v1` |
| `rule_id` | 为其请求候选的规则 |
| `candidate_count` | 从应答中解析出的候选数 |
| `accepted_count` / `rejected_count` | 校验器的判定结果 |
| `rejection_reasons` / `rejection_summary` | 每条拒绝原因，以及原因 → 次数的映射 |
| `token_usage` | provider 返回什么就记什么（`prompt_tokens`、`completion_tokens`、`total_tokens`，有 reasoning 明细时一并记录） |
| `latency_ms` | 调用耗时 |
| `status` | `ok` / `error` / `malformed` / `skipped` |
| `error` | 调用失败时的错误信息 |
| `simulated` | 仅脚本化测试 provider 为 `true` |
| `prompt_chars` / `response_chars`、`prompt_sha256` / `response_sha256` | 始终记录的指纹 |
| `raw_prompt_path` / `raw_response_path` | 仅 `--llm-save-raw` 时有值 |

没有凭据的运行同样会产生一行 `status: "skipped"`，说明无法解析出任何 provider，因此评审者永远能区分"模型跑过"和"模型根本没跑"。

运行级汇总（`disabled`、`partial`、`empty`、`degraded`、`degrade_reason`）位于 `report.json` 的 `llm` 段，不在每一行日志里。

---

## D. 原始 prompt / response

原始文本**默认不保存** —— 这同时保护 secret 与载荷内容。默认只记录字符数与 SHA-256 摘要。

`--llm-save-raw` 才会把 prompt 与 reply 原文写入 `artifacts/llm_raw/`。写入前，所有被配置为 secret 的值（即解析出的 API Key）都会先替换为 `***REDACTED***`，因此即使落盘完整载荷，Key 也绝不会进入磁盘。

---

## E. 不伪造真实 LLM

- CLI 触达不到 mock provider。`MockLLMProvider` 只能由测试通过依赖注入构造（`main(..., llm_provider_factory=...)`）。
- 它**没有默认输出**：没有脚本时会抛错，而不是自己编造候选。
- 它产生的每条记录都带 `"simulated": true`，终端也会标注 `mock (simulated)`。
- 用它得到的测试结果绝不能被汇报成真实模型结果。本仓库没有任何地方这么做。
- 没有凭据时，`hybrid` 运行会报 `degraded: true` 并给出具体原因、`accepted_count: 0`，不会假装模型跑过。

---

## F. AI 使用原则 AI usage principles

1. **LLM 生成候选，不生成结论。** 它负责提出请求，并声明自己认为该请求满足哪种规则语义。
2. **`RuleSpec` 掌握规则事实。** targets、operator、negation、transformations、phase、action 全部来自 parser。
3. **Validator 掌握可信性。** 每条候选都要按规则重新推导；无法验证的一律拒绝，不送执行。
4. **`expected_code` 不由 LLM 决定。** 状态码由规则动作计算；候选里出现状态码字段即被拒绝。
5. **Gold 不是生成素材。** Generator 从不读取 `gold.json`；gold 只对确定性 baseline 集做基准比对。
6. **缺少配置必须显式。** 降级到 baseline 时记录具体原因，绝不静默掩盖。
7. **保留运行时真相。** WAF 因 `rules.conf` 之外的层产生了拦截，就如实记为该用例失败，不去改写；没有 audit log 证据时，绝不把 `403` 归因为某个具体 rule id。
