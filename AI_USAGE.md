| 序号 | 环节 | 输入 Prompt 摘要 | AI 输出关键内容 | 问题 | 修正 |
|---|---|---|---|---|---|
| 1 | 项目分析 | 分析 `docker-compose.yml`、`rules.conf`、`gold.json`，给出技术设计方案 | 识别 WAF 镜像、8 条 SecRule、16 条 gold、1006 特殊规则；提出 Parser→Generator→Executor→Validator→Report 流水线 | 初期未明确能否完全通用生成 | 后续增加策略注册机制，按规则特征选择生成策略 |
| 2 | RuleSpec + Parser | 设计 `RuleSpec` 并实现 `SecRule` Parser | 定义 `RuleSpec`、`TargetVariable`、`RuleAction`；实现 quote-aware、escape-aware 轻量 parser | 简单 split 无法处理正则中的逗号、引号、`\|`、`\s` | 改为状态机，保留 operator 参数完整内容 |
| 3 | CaseSpec + Generator | 设计 `CaseSpec` 并实现 Test Case Generator | 设计 `CaseSpec`；实现策略模式，按变量位置、operator、transformation 生成正负用例 | 1006 是 `pass + ctl:ruleEngine=off`，不能按普通 deny 处理 | 增加 control differential 策略，自动寻找下游阻断规则构造差分用例 |
| 4 | HttpExecutor | 实现 HTTP Executor，使用 httpx，真实请求 WAF | 实现 `HttpExecutor`、`ExecutionResult`；处理 URL 编码、超时、连接错误 | httpx 可能对已编码 `%2e` 二次编码；系统代理可能干扰本地请求 | 保留已有 `%xx`；设置 `trust_env=False` 避免代理 |
| 5 | pytest Harness | 实现 pytest 参数化执行 Harness | 实现 `PytestHarness`、`parametrize_cases`、`assert_execution_result`；区分执行错误与状态不匹配 | 不能动态生成 Python 测试源码；执行错误不能伪装成断言失败 | 使用 `pytest.param` 静态参数化；执行错误用 `pytest.fail` 并保留详情 |
| 6 | Gold Validator | 实现独立 Gold Validator，比较 generated 与 gold.json | 按 `(rule_id, type)` 索引；支持缺失、多余、重复、字段差异；区分 `null`、`""`、缺失 | 不能依赖 JSON 数组顺序；不能混淆 null 与空字符串 | 引入 `GoldDiff` 结构化差异；用 `MISSING_VALUE` 标记缺失 |
| 7 | Report | 实现统一 Report，区分 Generation/Gold/Runtime | 设计 `TestReport`、`CaseResult`、`PhaseStatus`；终端与 JSON 输出 | 避免 Docker 未启动时伪造 SUCCESS | 引入 `NOT_RUN` / `INCOMPLETE`，无执行结果时不返回 SUCCESS |
| 8 | CLI | 实现最终 CLI，串联完整 pipeline，定义 exit code | 实现 `argparse` CLI；支持 `--gold`、`--base-url`、`--timeout`、`--output-dir`、`--no-execute`、`--debug`；exit code 0/1/2 | Windows 无 bash，无法直接运行 `./testcase-gen` | 增加 `python -m testcase_gen.cli` 入口和 console script；根目录 wrapper 加 `python3` 回退 |
| 9 | 真实 WAF 集成验证 | 启动 Docker WAF，执行真实 HTTP 请求并验证 | 16/16 状态码匹配；1006 positive=200，negative=403；exit code 0 | 发现容器挂载源为 `F:\waf-test` 而非当前工作区 | 比对 SHA256，确认三份输入文件完全一致，验证结果有效 |
| 10 | Final Audit | 最终审计仓库完整性、CLI、WAF、Gold、测试、跨平台 | 输出 Final Audit Report；确认 80 passed、真实 WAF 16/16、CLI exit code 正确 | 缺少 `README.md` 和 `AI_USAGE.md`；POSIX 端到端未在本机直接执行 | 后续补齐文档；在 Linux 容器中验证 `./testcase-gen` 可运行 |
| 11 | Repository Cleanup | 新增 `.gitignore`，检查待提交文件，清理缓存，补 README/AI_USAGE | 新增 `.gitignore`、`.gitattributes`、`README.md`、`AI_USAGE.md`；清理 `artifacts/`、`__pycache__`、`.pytest_cache`、`egg-info` | wrapper 修改后原有测试断言失败 | 更新 `tests/test_cli.py` 中的 wrapper 测试，并新增 `.gitignore` 忽略项测试 |
| 12 | 最终测试与冷启动 | 运行 `pytest`、CLI 成功/失败/`--no-execute`、Linux 容器 wrapper 验证 | 81 passed；CLI 成功 exit 0，`--no-execute` exit 1，失败场景 exit 1；Linux 容器 `./testcase-gen` 可执行 | 本机无 git CLI，无法执行真实 `git status` | 使用静态规则验证 `.gitignore` 生效；列出应提交文件清单 |

