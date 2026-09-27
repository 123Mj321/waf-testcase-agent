# WAF Testcase Agent

从 ModSecurity `SecRule` 文件直接生成、扩展、执行并对标 WAF 测试用例：以**确定性生成器**作为契约，以**可选 LLM**作为扩展层。

仓库入口：

```sh
./testcase-gen rules.conf
```

Windows 等价命令：

```powershell
python -m testcase_gen.cli rules.conf
```

---

## 1. 总览 Overview

工具读取 `rules.conf`，产出 `CaseSpec[]`，先用独立的 gold 基线做对标，可选择用 LLM 生成候选做扩展，再打到本地真实 WAF 上执行，最后输出终端报告、JSON 报告和 LLM 审计日志。

工程里刻意把三种验证层严格分开：

| 验证层 | 回答的问题 | 需要 Docker | 确定性 |
|---|---|---|---|
| pytest | 工具逻辑本身是否正确 | 否 | 是 |
| Gold validator | 生成用例是否与 `gold.json` 一致 | 否 | 是 |
| Runtime execution | WAF 是否真的返回期望状态码 | 是 | 否 |
| LLM generation audit | 模型究竟返回了什么、接受/拒绝了多少 | 否（仅网络） | 否 |

---

## 2. 问题 Problem

手写 WAF 回归用例慢、覆盖不均，也难以和规则集保持同步：

- 每条规则都需要一个 `positive`（规则命中）和一个 `negative`（规则不命中）用例
- 期望状态码必须从规则动作推导，不能靠猜
- 载荷变体（编码变换、大小写/空白变化、良性近似串、边界值）恰恰是人最容易漏的部分
- 规则集会演进，用例集必须能被确定性重建

确定性生成器能保证正确性，但只能产出它能从规则结构中证明的东西；模型能快速提出变体，但模型输出永远是**假设**，不是结论。

---

## 3. 核心设计 Key Design

1. **RuleSpec 是规则事实的唯一来源。** Parser 把 `rules.conf` 变成结构化模型（targets、operator、negation、transformations、phase、action、ctl）。下游所有阶段只消费 `RuleSpec`，不再消费原文。
2. **确定性生成器是契约。** 它为每条规则产出恰好一正一负两个用例，即 16 条 baseline cases，完全离线、完全不依赖模型。
3. **LLM 提议，Validator 裁决。** 模型只负责建议候选请求，以及它认为该请求满足的规则语义。
4. **`expected_code` 永远不由 LLM 决定。** 它始终由 `RuleSpec` 计算得出。
5. **`gold.json` 是外部 oracle。** Generator 从不读它；Gold Validator 是唯一消费者。
6. **缺少配置必须显式可见。** 没有可用 provider 时工具降级到 baseline 并如实标记（`llm.degraded`），不会伪造模型调用。
7. **失败必须分面呈现。** 解析错误、不支持的规则、gold 差异、HTTP 不匹配、超时、LLM 错误各自独立上报，不压缩成一个布尔值。

---

## 4. 架构 Architecture

```text
rules.conf
   │
   ▼
SecRule Parser ───────────────────────► RuleSpec
                                          │
              ┌───────────────────────────┴────────────────────────────┐
              │                                                        │
              ▼                                                        ▼
  Baseline Deterministic Generator                          LLM Prompt Builder
  (strategies/，离线、未变更)                        prompt.py: RuleSpec → 结构化 JSON
              │                                                        │
              │                                                        ▼
              │                                             LLM Candidate Generator
              │                                             llm.py: OpenAI 兼容 HTTP 调用
              │                                                        │
              │                                                        ▼
              │                                             Candidate Parser
              │                                             validation.py: 容忍代码块围栏、校验 schema
              │                                                        │
              │                                                        ▼
              │                                             Rule-aware Validator
              │                                             validation.py: target / operator /
              │                                             transformation / 可执行性 / 跨规则冲突 / 去重
              │                                                        │
              ▼                                                        ▼
        CaseSpec[] (baseline, 16) ──────► assemble_cases(mode) ───► CaseSpec[] (最终)
                                                        │
                       ┌────────────────────────────────┼──────────────────────────┐
                       ▼                                ▼                          ▼
              Gold Validator                     HttpExecutor                AI Usage Log
          validator/gold.py（oracle）        executor/http_executor.py      generator/audit.py
                       │                                │                          │
                       └────────────► Report ◄──────────┘                          │
                              report/                                              │
                       ├── 终端输出                                                │
                       └── report.json ◄─────────────────────────────────────────┘
```

代码强制的数据边界规则：

- Generator 从不读取 `gold.json`
- LLM 既拿不到 `gold.json`，也拿不到期望状态码
- Baseline 生成器从不发送 HTTP 请求
- Report 从不重复读取 `rules.conf` 或 `gold.json`
- Gold Validator 与 HttpExecutor 各自独立消费同一份 `CaseSpec[]`

---

## 5. LLM 用例生成 LLM Testcase Generation

LLM 的参与范围被严格限制在**候选提议（candidate proposal）**，除此之外什么都不做。

```text
RuleSpec ──► Prompt Builder ──► LLM ──► Candidate Parser ──► Rule-aware Validator ──► CaseSpec
```

### 输入 Input

`prompt.py` 把解析后的 `RuleSpec` 渲染成结构化 JSON 块 —— targets、operator（含 negation）、transformations、phase、disruptive action、status、ctl actions、message —— 再加上输出契约。原始规则文本只作为补充上下文附带，绝不作主要输入。

模型被明确要求：不得臆造其它规则，也不得输出状态码。

### 输出 Output

一个 JSON 对象：

```json
{
  "rule_id": 1001,
  "candidates": [
    {
      "category": "payload_mutation",
      "expected_semantics": "match",
      "method": "GET",
      "path": "/?id=DROP TABLE users",
      "headers": {},
      "body": null,
      "rationale": "drop table keyword"
    }
  ]
}
```

`category` 必须是七个被接受的值之一：

| Category | 含义 |
|---|---|
| `positive` | 直接命中规则 |
| `negative` | 干净请求，规则不生效 |
| `payload_mutation` | 命中载荷的改写（大小写、空白、拼接、引号） |
| `encoding_variation` | 百分号编码 / 多重编码变体，解码后仍指向目标值 |
| `boundary` | 算子边界值（空值、最小重复次数、临界长度） |
| `benign_lookalike` | 形似攻击但必须不命中的真实流量 |
| `rule_combination` | 同时与另一条规则发生关系的请求 |

`expected_semantics` 是模型的**主张**（`match` / `no_match`）：它不是状态码，而且会被 validator 重新验算。

### Provider

| Provider | 选择方式 | 凭据 |
|---|---|---|
| OpenAI 兼容接口 | `--llm-provider openai`（或存在 Key 时的 `auto`） | `--llm-api-key-env`，默认 `OPENAI_API_KEY` |
| 本地 Ollama | `--llm-provider ollama` | 无需凭据，默认 `http://127.0.0.1:11434/v1` |
| 任何同 wire 格式的网关 | `--llm-base-url` | 同上 |
| `MockLLMProvider` | **仅供测试** | 不适用 |

`MockLLMProvider` 是单测通过依赖注入使用的脚本化替身：**没有默认输出**，没有脚本就会抛错，CLI 永远触达不到它，它产生的每条记录都带 `"simulated": true`。**它不是模型调用，绝不能被描述成模型调用。**

---

## 6. 规则感知校验 Rule-aware Validation

`validation.py` 是让 LLM 层可信的那一层。任何候选在变成 `CaseSpec` 之前都要过检。

| 检查 | 拒绝原因示例 |
|---|---|
| 结构 | `candidate is not a JSON object`、`unknown candidate category`、`invalid or missing expected_semantics` |
| 响应完整性 | `response is not valid JSON`、`response rule_id 9999 does not match requested rule 1001` |
| LLM 不得决定状态码 | `candidate must not contain an expected status code` |
| 是否使用目标 | `candidate does not provide a value for target ARGS:id` |
| 可执行性 | `unsupported method`、`path must be a string starting with '/'`、`path contains control characters`、`body is not allowed for method GET`、表头取值与长度规则 |
| 算子与转换 | `rule semantic mismatch: candidate declares 'match' but the rule evaluates to no_match` |
| 可验证性 | `rule operator 'rx' with transformations ['base64Decode'] cannot be validated deterministically` |
| 跨规则一致性 | `candidate also triggers rule 1005 with a different status` |
| 去重 | `duplicate candidate`（与 baseline 用例、与已接受候选双向去重） |

两个关键细节：

- **wire value 提取时不解码。** 目标值按 `&`/`=` 从 query string 原样切分，`%2e%2e%2f` 保持字面值，再由 `urlDecodeUni` / `urlDecode` 显式作用，和 baseline 生成器的推理方式保持一致。
- **去重集合以 baseline 用例做种子。** 与确定性 baseline 用例完全相同的候选会被判为重复而拒绝。

### `expected_code` 是怎么来的

从不来自模型。`expected_code_for_rule()` 把 `RuleSpec` 映射成状态码：

- `deny` + status：`match → rule.status`，`no_match → success_status`（200）
- 其他情况：直接拒绝 —— 没有可断言的确定性状态

### 特例：规则 1006（`pass` + `ctl:ruleEngine=off`）

这条规则本身不阻断，它对 `/api/health*` 关闭引擎，因此期望状态取决于**另一条规则本来会怎么做**。差分是确定性的：

1. 找到 phase 更大的第一条 `deny` 规则，且它有确定性正值（规则 1001 → 探针 `id=1 OR 1=1`）
2. `match`（URI 以 `/api/health` 开头）→ 引擎已关闭 → `200`
3. `no_match` → 请求必须**携带探针载荷** `id=1 OR 1=1`，否则差分不成立 → 拒绝
4. 探针载荷本身要被复验：它必须真的能触发规则 1001
5. 引擎关闭期间，下游 `deny` 规则不参与冲突检查

---

## 7. Gold 基准 Gold Benchmark

`gold.json` 保存 16 条用例：每条规则一正一负，字段为 `rule_id`、`type`、`method`、`path`、`headers`、`body`、`expected_code`。

职责：

- 作为生成结果的独立比对 oracle
- 发现缺失 / 多余 / 重复 `(rule_id, type)`
- 发现 `method`、`path`、`headers`、`body`、`expected_code` 的字段级差异
- 从不发起 HTTP 请求

**Generator 为什么不读它：** 一旦读 gold，生成就变成"抄答案"，benchmark 失去意义，生成器回归也会被掩盖。独立性正是 gold 的全部价值。

**LLM 用例为什么不会破坏 gold：** gold 始终只对**确定性 baseline 集**做比对，报告中体现为 `gold_validation.benchmark_source = "baseline"`。因此 LLM 独占用例永远不会变成 "generated case is unexpected" 这种生成失败。真正发往 WAF 的用例集仍可能大于基准集。

---

## 8. 运行执行 Runtime Execution

`HttpExecutor` 针对最终用例集里的每一条真实发起 HTTP 请求：method、path、headers、body 逐一落地，并记录 `actual_code`、延迟、响应头、响应体摘录和传输错误。执行错误保持 `actual_code` 为 `null`，绝不包装成伪造的状态码。

阶段语义：

| 条件 | 阶段状态 | 退出码 |
|---|---|---|
| 连接错误 / 超时 / 状态码不匹配 | `FAIL` | 1 |
| 结果条数少于期望用例数 | `FAIL` | 1 |
| `--no-execute` | `NOT_RUN` | 1（`INCOMPLETE`） |
| 全部通过 | `PASS` | 0 |

`--llm-no-execute` 会把运行执行限制在确定性 baseline 用例上，同时仍然生成并上报 LLM 用例。

---

## 9. 项目结构 Project Structure

```text
waf-testcase-agent/
├── docker-compose.yml        # 本地 WAF + backend 环境
├── rules.conf                # ModSecurity SecRule 输入（8 条规则）
├── gold.json                 # 独立 gold 基线（16 条用例）
├── pyproject.toml            # 打包、依赖、pytest 配置
├── testcase-gen              # POSIX wrapper 入口（LF 换行）
├── README.md
├── AI_USAGE.md
├── .gitignore
├── .gitattributes
├── artifacts/                # 运行时生成，已被 git 忽略
│   ├── generated_cases.json
│   ├── report.json
│   ├── ai_usage_log.jsonl
│   └── llm_raw/              # 仅 --llm-save-raw 时产生
├── src/
│   └── testcase_gen/
│       ├── __init__.py
│       ├── cli.py            # CLI 编排与退出码
│       ├── models.py         # RuleSpec / CaseSpec
│       ├── parser/
│       │   ├── __init__.py
│       │   └── secrule_parser.py
│       ├── generator/
│       │   ├── __init__.py
│       │   ├── generator.py      # 确定性 baseline 生成器
│       │   ├── strategies/       # 每类规则的确定性策略
│       │   │   ├── __init__.py
│       │   │   ├── base.py
│       │   │   └── mvp.py
│       │   ├── prompt.py         # LLM prompt 构造器
│       │   ├── llm.py            # provider + candidate generator
│       │   ├── validation.py     # candidate parser + 规则感知校验器
│       │   └── audit.py          # AI 生成审计日志
│       ├── executor/
│       │   ├── __init__.py
│       │   └── http_executor.py
│       ├── runner/
│       │   ├── __init__.py
│       │   └── pytest_runner.py
│       ├── validator/
│       │   ├── __init__.py
│       │   └── gold.py
│       └── report/
│           ├── __init__.py
│           ├── json_report.py
│           ├── models.py
│           ├── reporter.py
│           └── terminal.py
└── tests/
    ├── conftest.py           # 为每个测试清除 LLM API Key 环境变量
    ├── test_secrule_parser.py
    ├── test_generator.py
    ├── test_http_executor.py
    ├── test_pytest_runner.py
    ├── test_gold_validator.py
    ├── test_report.py
    ├── test_cli.py
    ├── test_llm_generator.py
    └── test_llm_cli.py
```

---

## 10. 快速开始 Quick Start

需要 Python `3.9+`；运行阶段还需要 Docker。

```sh
python -m pip install -e .
```

或者只装运行/测试所需依赖，不装 console script：

```sh
python -m pip install httpx "pytest>=8.0,<9.0"
```

### 准备 WAF

CLI 从不启动 Docker。

```sh
docker compose up -d
docker compose ps        # waf 健康、backend 运行、8080 已发布
```

工具随后访问 `http://127.0.0.1:8080`。

### 跑 baseline（离线可用）

```sh
./testcase-gen rules.conf --generation-mode baseline
```

### 跑测试

```sh
python -m pytest
```

### 只生成、不发 HTTP

```sh
./testcase-gen rules.conf --generation-mode baseline --no-execute
```

---

## 11. LLM 配置 LLM Configuration

| 参数 | 默认值 | 用途 |
|---|---|---|
| `--llm-provider` | `auto` | `auto` / `none` / `openai` / `ollama` |
| `--llm-model` | provider 默认 | 例如 `gpt-4o-mini`、`deepseek-v4-pro-0813` |
| `--llm-base-url` | provider 默认 | 任意 OpenAI 兼容端点 |
| `--llm-api-key-env` | `OPENAI_API_KEY` | 存放 Key 的环境变量名 |
| `--llm-max-candidates` | `8` | 每条规则请求的候选数 |
| `--llm-timeout` | `120` | 单次请求超时秒数 |
| `--llm-max-tokens` | 不设置 | 显式输出上限 |
| `--llm-temperature` | `0.2` | 采样温度 |
| `--llm-no-execute` | 关闭 | 不把 LLM 用例发往 WAF |
| `--llm-save-raw` | 关闭 | 落盘原始 prompt/response（已脱敏） |

```sh
export OPENAI_API_KEY=...
./testcase-gen rules.conf --generation-mode hybrid --llm-model gpt-4o-mini

# 任意 OpenAI 兼容网关
./testcase-gen rules.conf --llm-base-url https://gateway.example/v1 --llm-model my-model

# 本地模型，不需要 Key
./testcase-gen rules.conf --llm-provider ollama --llm-model llama3.1
```

### 推理模型 Reasoning models

推理模型会把输出预算拆给隐藏的 reasoning 和可见答案。一旦发送 `max_tokens`，它就可能把预算全部耗在 reasoning 上，返回一个空的 `content`。同一 prompt 的实测：

| 变体 | 耗时 | finish_reason | reasoning_tokens | content |
|---|---|---|---|---|
| `max_tokens=2000` | 28.0s | `length` | 2000 | 空 |
| 不传 `max_tokens` | 71.9s | `stop` | 5365 | 2205 字符 |

因此 provider 默认**不发送** `max_tokens`，默认超时设为 120s，且空回复会给出带 `finish_reason` 和 `reasoning_tokens` 的可定位报错。

### 没有 API Key

不做任何伪造。`auto` 解析结果为"无 provider"，运行降级到确定性 baseline，报告中如实记录：

```json
"llm": {"enabled": false, "status": "disabled", "degraded": true,
        "degrade_reason": "llm not configured: environment variable OPENAI_API_KEY is empty",
        "accepted_count": 0}
```

终端同时打印 `Status  DEGRADED to baseline` 及具体原因。

---

## 12. 生成模式 Generation Modes

### `baseline`

仅使用确定性策略。无模型、无网络。

- 8 条规则 → 8 正 + 8 负 = **16 条 baseline cases**
- 完全离线、可复现、可与 gold 比对

### `llm`

模型为每条规则做扩展；被接受的 LLM 用例**替换**同 `(rule_id, type)` 的 baseline 用例。

- 每条规则最终仍至少各有一条 positive 和 negative（≥ 16 条）
- 若某条规则没有产出可用候选，则保留其确定性用例

### `hybrid`（默认）

确定性 baseline **加上**被接受的 LLM 用例。16 条 baseline 用例始终存在，这也是推荐把 hybrid 作为完整能力展示的原因：既不削弱确定性契约，又体现 LLM 扩展。

没有 provider 时它会降级到 baseline —— 并且明确说出来。**降级后的 hybrid 运行绝不能被描述成"模型跑过了"。**

---

## 13. CLI 参考 CLI Reference

```text
testcase-gen RULES_FILE [options]
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `RULES_FILE` | 必填 | ModSecurity 规则文件 |
| `--gold PATH` | `gold.json` | gold 基线文件 |
| `--base-url URL` | `WAF_BASE_URL`，否则 `http://127.0.0.1:8080` | WAF 基础地址 |
| `--timeout SECONDS` | `10` | WAF HTTP 超时秒数 |
| `--output-dir PATH` | `artifacts` | 产物目录 |
| `--no-execute` | 关闭 | 只解析 + 生成 + 校验，不发请求 |
| `--debug` | 关闭 | 非预期异常时打印 traceback |
| `--generation-mode` | `hybrid` | `baseline` / `llm` / `hybrid` |
| LLM 相关参数 | 见第 11 节 | `--llm-*` |

### 退出码 Exit codes

| 码 | 含义 | 例子 |
|---:|---|---|
| `0` | 完全成功 | 各阶段 PASS、用例全通过、无不支持规则 |
| `1` | 校验/执行失败或运行不完整 | gold 不一致、状态码不符、连接错误、超时、不支持规则、`--no-execute` |
| `2` | 输入/配置错误 | rules 或 gold 文件缺失、解析失败、非法参数、产物目录不可写 |

WAF 没起来属于运行执行失败（`1`），不是配置错误。

---

## 14. 报告与产物 Reports and Artifacts

| 文件 | 内容 |
|---|---|
| `artifacts/generated_cases.json` | 最终 `CaseSpec[]`（不含规则与执行数据） |
| `artifacts/report.json` | 全链路报告，机器可读 |
| `artifacts/ai_usage_log.jsonl` | 每次 LLM 生成尝试一行 JSON |
| `artifacts/llm_raw/` | 原始 prompt/response，仅 `--llm-save-raw` 时产生 |

`report.json` 顶层段落：

```text
summary  generation  llm  gold_validation  execution  cases  gold_diffs  errors
```

`llm` 段：

```json
{
  "enabled": true, "provider": "openai", "model": "deepseek-v4-pro-0813",
  "prompt_version": "waf-testcase-candidate-v1", "status": "ok",
  "candidate_count": 61, "accepted_count": 49, "rejected_count": 12,
  "error_count": 0, "errors": [],
  "rejection_reasons": ["..."], "rejection_summary": {"...": 4},
  "degraded": false, "degrade_reason": null,
  "latency_ms": 559919.853,
  "token_usage": {"prompt_tokens": 6736, "completion_tokens": 47071,
                  "completion_tokens_details": {"reasoning_tokens": 8772}},
  "simulated": false
}
```

`gold_validation` 始终标明 `benchmark_source: "baseline"`。

### AI 使用日志 AI usage log

由代码自动写入，无需人工维护。每次尝试一行：

```json
{"timestamp":"2026-09-27T15:17:45.659+00:00","status":"ok","provider":"openai","model":"deepseek-v4-pro-0813","prompt_version":"waf-testcase-candidate-v1","rule_id":1001,"candidate_count":4,"accepted_count":2,"rejected_count":2,"rejection_reasons":["candidate also triggers rule 1005 with a different status","rule semantic mismatch: candidate declares 'match' but the rule evaluates to no_match"],"rejection_summary":{"...":1},"token_usage":{"prompt_tokens":420,"completion_tokens":180,"total_tokens":600},"latency_ms":39.857,"error":null,"simulated":false,"prompt_chars":3332,"response_chars":734,"prompt_sha256":"80fa…","response_sha256":"9937…","raw_prompt_path":null,"raw_response_path":null}
```

记录字段：timestamp、provider、model、prompt version、rule id、候选/接受/拒绝数量、拒绝原因及其汇总、provider 返回的 token usage、latency、status、error、provider 是否为模拟、以及 prompt/response 指纹。

### 原始 prompt / response

默认不保存原文，只记录长度和 SHA-256 摘要，因此既不会有 Key 也不会有载荷内容落盘。使用 `--llm-save-raw` 时，prompt 与 response 原文会写入 `artifacts/llm_raw/`，写入前先把配置里的 API Key 值替换为 `***REDACTED***`。

---

## 15. 测试 Testing

```sh
python -m pytest
```

138 个测试。不需要 Docker、不需要网络、不需要 provider —— `tests/conftest.py` 会为每个测试清除 LLM API Key 环境变量，测试全部使用 `httpx.MockTransport`、脚本化 mock provider、fake executor 和临时目录。

覆盖映射：

| 领域 | 文件 |
|---|---|
| SecRule parser | `test_secrule_parser.py` |
| Baseline 生成器 | `test_generator.py`（含"从不读取 gold 或任何文件"） |
| HTTP executor | `test_http_executor.py` |
| pytest harness | `test_pytest_runner.py` |
| Gold validator | `test_gold_validator.py` |
| Report | `test_report.py` |
| CLI 与退出码 | `test_cli.py` |
| Prompt 构造、provider wire 格式、超时/HTTP 错误、block content | `test_llm_generator.py` |
| 合法 / 畸形 / 非法 / 重复 / 语义错配候选 | `test_llm_generator.py` |
| engine-off 差分类候选 | `test_llm_generator.py` |
| 无 API Key、未知 provider、降级 | `test_llm_generator.py` |
| AI 日志字段、raw 默认关闭、脱敏 | `test_llm_generator.py` |
| `baseline` / `llm` / `hybrid` CLI 模式、降级运行、provider 错误、`--llm-no-execute` | `test_llm_cli.py` |

---

## 16. 真实 WAF 验证 Real WAF Validation

环境：`docker compose up -d`，WAF 在 `http://127.0.0.1:8080`。

```sh
./testcase-gen rules.conf --generation-mode baseline
```

结果：

```text
Generation      PASS   Rules parsed 8/8   Cases generated 16   Baseline cases 16
Gold Validation PASS   Exact match 16/16  Differences 0
Runtime         PASS   Executed 16  Passed 16  Failed 0  Errors 0
Overall: SUCCESS       Exit code: 0
```

这是主验收信号：确定性生成、gold 对齐、真实 HTTP 行为三者同时成立。

### LLM 运行（真实 provider）

使用 `deepseek-v4-pro-0813` 的一次 hybrid 实测：

| 指标 | 数值 |
|---|---|
| 模型返回候选数 | 61 |
| 规则感知校验后接受 | 49 |
| 拒绝 | 12（8 条语义错配，4 条缺少 engine-off 探针载荷） |
| 最终用例数 | 65（16 baseline + 49 LLM） |
| Gold | 16/16（baseline 基准集） |
| Runtime | 57/65 通过 |
| baseline 用例运行 | 16/16 通过 |
| LLM 用例运行 | 41/49 通过 |
| LLM 失败 | 8 条 negative 被 `rules.conf` 之外的 WAF 防护层拦截 |

其中一条规则因 `--llm-timeout` 不足发生超时，被记为 LLM 错误，其余规则继续正常完成。数字随模型、采样与 prompt 版本变化，任何一次运行的权威依据永远是当次的 `report.json`。

---

## 17. 限制 Limitations

- **`expected_code` 来自 `rules.conf` / `RuleSpec`，不是从 WAF 动态推断的。** WAF 镜像还内置了其它 CRS 类规则集，nginx 层本身也参与。实测探针：

  ```text
  GET  /?id=abc                 -> 200
  GET  /?id=unionselect         -> 403   （不是 rules.conf 的规则）
  GET  /path?file=passwd        -> 200
  GET  /path?file=../etc/passwd -> 403   （不是 rules.conf 的规则）
  POST /profile body=hello      -> 403   （不是 rules.conf 的规则）
  ```

  因此 LLM 生成的 negative 用例可能相对它自己的规则是正确的，却仍被其它防护层拦掉。观测到的 8 条 LLM 运行失败全部是这个形态：期望 `200`，实际 `403`。工程从未声称"403 意味着某条 rule 触发了"。

- **不解析 audit log。** 项目无法把一次拦截归因到某个 rule id。`403` 只能证明"WAF 栈拦了它"，永远不能证明"规则 1001 命中了"。

- **LLM 用例的 runtime 结果属于探索性结果。** baseline gold 基准才是验收集；LLM 用例用于扩展覆盖，只按规则语义验证，不对其它 WAF 层负责。只想比对 baseline 时用 `--llm-no-execute`。

- **确定性校验有作用域。** 白名单之外的算子与转换一律拒绝而非猜测，因此 LLM 的增益取决于规则集的形态。

- **wire value 建模。** 目标值按上线字面值取，`urlDecodeUni` 之类显式作用。因此依赖"WAF 先解码才显得良性"的载荷可能被拒绝；对于 negative 用例，面对真实协议栈也可能偏乐观。

- **推理模型成本。** 使用推理模型的完整 hybrid 运行需要数分钟（约 30–120 秒/规则）。

- **`runner/` 是库级 harness。** `pytest_runner.py` 负责把 `CaseSpec[]` 参数化成 pytest 用例；CLI 直接通过 `HttpExecutor` 驱动同一批用例，两者消费完全相同的数据。

---

## 18. AI 使用说明 AI Usage

`AI_USAGE.md` 记录了本仓库里两种都被叫做 "AI" 的事物，并把它们严格分开：

- **AI 辅助开发** —— 使用了哪个助手、人负责了什么（架构、模块边界、规则语义、验收标准、测试）、AI 产出的代码经过了哪些验证。
- **运行时 LLM 用例生成** —— 交付工具本身在运行时调用模型 *提议* 测试用例，即第 5、6 节描述的 `RuleSpec → prompt → LLM → parser → validator → CaseSpec` 流水线，以及第 14 节的审计日志契约。

审计日志由代码自行生成，不需要人工填写。由于它记录了 provider、model、prompt version、各类计数、latency 以及 `simulated` 标记，评审者永远能分辨某次运行究竟用了真实 provider、降级到了 baseline，还是来自测试替身。
