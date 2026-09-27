# WAF Testcase Agent

Generate, execute, and validate WAF test cases directly from a ModSecurity `SecRule` file.

This project reads `rules.conf`, derives `positive` and `negative` HTTP test cases from the rules, validates the generated cases against `gold.json`, executes them against a real local WAF, and produces both a terminal report and a machine-readable JSON report.

Project entry point:

```sh
./testcase-gen rules.conf
```

Windows equivalent:

```powershell
python -m testcase_gen.cli rules.conf
```

See [`AI_USAGE.md`](AI_USAGE.md) for AI usage documentation.

---

## Quick Start

Copy and run these commands from the repository root.

### 1. Install Python dependencies

Requires Python `3.9+`.

```sh
python -m pip install -e .
```

If you only want to run tests and the CLI without installing the console script:

```sh
python -m pip install httpx "pytest>=8.0,<9.0"
```

### 2. Start the Docker WAF

The CLI does **not** start Docker. The WAF environment is a prerequisite.

```sh
docker compose up -d
```

Wait until the WAF container is healthy:

```sh
docker compose ps
```

Expected result:

- `waf` service: running and healthy
- `backend` service: running
- `waf` publishes `8080:8080`

The tool then talks to:

```text
http://127.0.0.1:8080
```

### 3. Run unit tests

```sh
python -m pytest
```

Expected result:

```text
80 passed
```

### 4. Run the full CLI against the real WAF

POSIX:

```sh
./testcase-gen rules.conf
```

Windows:

```powershell
python -m testcase_gen.cli rules.conf
```

Expected result on a healthy WAF:

```text
Generation
Status              PASS
Rules parsed        8/8
Cases generated     16
Positive            8
Negative            8

Gold Validation
Gold cases          16
Exact match         16/16
Differences         0

Runtime Execution
Executed            16
Passed              16
Failed              0
Errors              0

Overall: SUCCESS
Exit code: 0
```

### 5. Generate and validate without contacting the WAF

```sh
./testcase-gen rules.conf --no-execute
```

Result:

- Parser, Generator, and Gold Validator still run
- `Runtime Execution` becomes `NOT RUN`
- `Overall` becomes `INCOMPLETE`
- Exit code is `1`, because the full pipeline did not run

### 6. Point the CLI at another WAF

```sh
./testcase-gen rules.conf --base-url http://127.0.0.1:8080
```

Or via environment variable:

```sh
export WAF_BASE_URL=http://127.0.0.1:8080
./testcase-gen rules.conf
```

### 7. Inspect generated cases

```sh
cat artifacts/generated_cases.json
```

### 8. Inspect the JSON report

```sh
cat artifacts/report.json
```

---

## Three Different Kinds of Verification

This project deliberately separates three verification layers. Do not mix them.

### Unit Test

Command:

```sh
python -m pytest
```

Purpose:

- verifies Parser, Generator, Executor, pytest Harness, Gold Validator, Report, and CLI logic
- uses `httpx.MockTransport`, fake executors, and temporary directories
- never requires Docker
- never requires a running WAF

Current result:

```text
80 passed
```

### Gold Validation

Where it runs:

- inside `./testcase-gen rules.conf`
- also covered directly by `tests/test_gold_validator.py`

Purpose:

- compares generated `CaseSpec[]` against `gold.json`
- does **not** send HTTP requests
- does **not** depend on Docker

Important boundary:

- the Generator never reads `gold.json`
- `gold.json` is only an independent comparison oracle

Gold validation can report:

- missing case
- unexpected case
- duplicate `(rule_id, type)`
- rule coverage difference
- positive/negative coverage difference
- field differences for `method`, `path`, `headers`, `body`, `expected_code`

### Real WAF Integration Test

Command:

```sh
./testcase-gen rules.conf
```

Purpose:

- sends the generated HTTP requests to `http://127.0.0.1:8080`
- compares `actual_status_code == expected_code`
- records latency, response headers, response excerpt, and execution errors

Requirement:

- Docker WAF must already be running
- the CLI does not start or stop containers

Observed result in the current development environment:

- `16/16` executed
- `16/16` status codes matched
- `1006 positive` returned `200`
- `1006 negative` returned `403`
- exit code `0`

Important honesty boundary:

- these results prove the final HTTP behavior
- they do **not** prove which specific ModSecurity rule ID blocked the request
- this project does not currently parse the ModSecurity audit log
- a `403` could come from the target rule, from another CRS rule, or from a different blocking layer

---

## Architecture / Pipeline

```text
rules.conf
   ↓
Parser
   ↓
RuleSpec
   ↓
Generator
   ↓
CaseSpec[]
   ├── generated_cases.json
   ↓
Gold Validator
   ↓
HttpExecutor
   ↓
ExecutionResult[]
   ↓
Report
   ├── terminal
   └── report.json
```

Data independence rules:

- `Generator` never reads `gold.json`
- `Generator` never sends HTTP requests
- `Report` never re-reads `rules.conf` or `gold.json`
- `Gold Validator` and `HttpExecutor` both consume `CaseSpec[]`, independently

---

## Project Structure

```text
waf-testcase-agent/
├── docker-compose.yml        # local WAF + backend environment
├── gold.json                 # independent gold baseline
├── rules.conf                # ModSecurity SecRule input
├── testcase-gen              # POSIX wrapper entry point
├── pyproject.toml            # packaging, dependencies, pytest config
├── README.md
├── AI_USAGE.md
├── artifacts/                # generated at runtime, git-ignored
│   ├── generated_cases.json
│   └── report.json
├── src/
│   └── testcase_gen/
│       ├── cli.py            # CLI orchestration and exit codes
│       ├── models.py         # RuleSpec / CaseSpec data models
│       ├── parser/           # SecRule parser
│       ├── generator/        # testcase generation strategies
│       ├── executor/         # HTTP executor
│       ├── runner/           # pytest parameterization harness
│       ├── validator/        # gold.json validator
│       └── report/           # unified report model and renderers
└── tests/
    ├── test_secrule_parser.py
    ├── test_generator.py
    ├── test_http_executor.py
    ├── test_pytest_runner.py
    ├── test_gold_validator.py
    ├── test_report.py
    └── test_cli.py
```

---

## CLI Reference

Usage:

```text
testcase-gen RULES_FILE [options]
```

Options:

| Option | Default | Description |
|---|---|---|
| `RULES_FILE` | required | ModSecurity rule file, for example `rules.conf` |
| `--gold PATH` | `gold.json` | gold baseline file |
| `--base-url URL` | `WAF_BASE_URL`, then `http://127.0.0.1:8080` | WAF base URL |
| `--timeout SECONDS` | `10` | HTTP timeout in seconds, must be `> 0` |
| `--output-dir PATH` | `artifacts` | artifact output directory |
| `--no-execute` | off | parse, generate, and validate only; no HTTP requests |
| `--debug` | off | show traceback for unexpected internal errors |

Artifacts:

| File | Description |
|---|---|
| `artifacts/generated_cases.json` | generated `CaseSpec[]`, no rule or execution data |
| `artifacts/report.json` | machine-readable full pipeline report |

---

## Exit Codes

| Code | Meaning | Examples |
|---:|---|---|
| `0` | full success | parse PASS, generation PASS, gold PASS, runtime PASS, all cases PASS, no execution error, no unsupported rule |
| `1` | test/validation failure or incomplete run | gold mismatch, HTTP status mismatch, connection error, timeout, unsupported rule, partial execution, `--no-execute` |
| `2` | input/configuration/CLI error | rules file missing, gold file missing, parse failure, invalid CLI argument, unusable output directory, unreadable gold JSON |

Note:

- If the WAF is not running and requests fail with `ConnectTimeout`, this is a runtime execution error.
- It is reported as `Runtime Execution` failure and returns exit code `1`.
- It is not treated as a CLI configuration error.
- The report keeps `actual_code` as `null`; it never fabricates a status code.

---

## Limitations

- The current MVP asserts HTTP status codes only.
- It does not parse the ModSecurity audit log.
- Therefore it does not prove that a specific rule ID was hit.
- Generation strategies intentionally cover the current rule feature set; unsupported rule shapes are reported explicitly instead of silently generating wrong cases.
- The default expected success status for negative cases is `200`, based on the provided backend behavior.

---

## AI Usage

See [`AI_USAGE.md`](AI_USAGE.md).
