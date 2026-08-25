# toolguard — Python SDK for Tool Guard Core

Universal AI agent governance: evaluate any tool call against configurable
policies before it executes.  Drop-in adapters for LangChain, AutoGen,
native OpenAI/Anthropic tool use, and MCP.  Two backends — CLI (`tg evaluate`)
and HTTP proxy (`tg-proxy /evaluate`) — so you can run locally or in production.

## Install

Not yet published to PyPI — install from source:

```bash
git clone https://github.com/dimaggi-ai/tool-guard-core
pip install "./tool-guard-core/sdk/python"                    # core only (httpx)
pip install "./tool-guard-core/sdk/python[langchain]"         # + langchain-core
pip install "./tool-guard-core/sdk/python[autogen]"           # + pyautogen
pip install "./tool-guard-core/sdk/python[openai]"            # + openai SDK
pip install "./tool-guard-core/sdk/python[anthropic]"         # + anthropic SDK
```

## Quick start

```python
from toolguard import ToolGuard, ToolDenied

guard = ToolGuard(
    mode="proxy",                        # or "cli" to run tg locally
    proxy_url="http://localhost:9090",
    agent_id="my-agent",
    org_id="acme",
)

try:
    result = guard.evaluate("issue_refund", {"amount": 1000})
    # allowed — call the real tool
except ToolDenied as exc:
    # exc.result.decision_reason, exc.result.suggested_response
    print("Blocked:", exc)
```

### CLI mode (no running proxy)

```python
guard = ToolGuard(
    mode="cli",
    tg_bin="/usr/local/bin/tg",          # or just "tg" if on PATH
    policy_dir="/etc/tg/policies",       # directory of *.yaml policies
    agent_id="my-agent",
    org_id="acme",
)
result = guard.evaluate_raw("issue_refund", {"amount": 100})
print(result.decision)  # "allowed"
```

CLI mode evaluates the whole policy directory as one set. Each policy's YAML
mode owns its contribution: a `mode: shadow` policy remains observe-only under
the CLI's default `enforcement` call-site mode, while a `mode: enforcement`
policy cannot be downgraded by a shadow default. Mixed-mode behavior is pinned
against the real Go engine in `tests/test_contract.py`.

`evaluate()` raises `ToolDenied` or `ToolEscalated` on a block.
`evaluate_raw()` always returns the `EvaluationResult` without raising.

---

## LangChain / LangGraph

```python
from toolguard import ToolGuard
from toolguard.adapters.langchain import ToolGuardCallbackHandler
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor

guard = ToolGuard(mode="proxy", proxy_url="http://localhost:9090",
                  agent_id="lc-agent", org_id="acme")

handler = ToolGuardCallbackHandler(
    guard,
    tool_groups={"issue_refund": "monetary_outflow", "search": "read_ops"},
)

executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])
# Every tool call goes through policy evaluation before execution.
```

The handler raises `ToolDenied` / `ToolEscalated` on a block, stopping
the chain.  Flagged calls (recorded near-misses) proceed.

---

## Microsoft AutoGen

```python
from toolguard import ToolGuard
from toolguard.adapters.autogen import guarded

guard = ToolGuard(mode="proxy", proxy_url="http://localhost:9090",
                  agent_id="autogen-agent", org_id="acme")

@guarded(guard, tool_name="issue_refund", tool_group="monetary_outflow")
def issue_refund(order_id: str, amount: float) -> dict:
    return {"status": "refunded", "amount": amount}

# Register with AutoGen as normal:
assistant.register_for_execution(name="issue_refund")(issue_refund)
```

On deny/escalate, `guarded` returns `{"error": "denied", "reason": "...",
"suggested_response": "..."}` — the conversation loop surfaces it to the LLM.

---

## Native OpenAI tool use

```python
import openai
from toolguard import ToolGuard
from toolguard.adapters.native import guard_tool_calls

client_oai = openai.OpenAI()
guard = ToolGuard(mode="proxy", proxy_url="http://localhost:9090",
                  agent_id="openai-agent", org_id="acme")

response = client_oai.chat.completions.create(
    model="gpt-4o",
    messages=messages,
    tools=tools,
)

allowed, denied = guard_tool_calls(
    response.choices[0].message.tool_calls,
    guard,
    provider="openai",
    tool_groups={"issue_refund": "monetary_outflow"},
)

tool_results = []
for item in allowed:
    call = item["call"]
    output = MY_TOOLS[call.function.name](**json.loads(call.function.arguments))
    tool_results.append({"role": "tool", "tool_call_id": call.id, "content": str(output)})
for item in denied:
    tool_results.append(item["tool_result"])  # role=tool, error message
```

---

## Native Anthropic tool use

```python
import anthropic
from toolguard import ToolGuard
from toolguard.adapters.native import guard_tool_calls

client_ant = anthropic.Anthropic()
guard = ToolGuard(mode="proxy", proxy_url="http://localhost:9090",
                  agent_id="anthropic-agent", org_id="acme")

response = client_ant.messages.create(
    model="claude-opus-4-5",
    max_tokens=4096,
    tools=tools,
    messages=messages,
)

tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
allowed, denied = guard_tool_calls(tool_use_blocks, guard, provider="anthropic")

tool_results = []
for item in allowed:
    call = item["call"]
    output = MY_TOOLS[call.name](**call.input)
    tool_results.append({"type": "tool_result", "tool_use_id": call.id, "content": str(output)})
for item in denied:
    tool_results.append(item["tool_result"])  # type=tool_result, is_error=True
```

---

## MCP server

```python
from toolguard import ToolGuard
from toolguard.adapters.mcp import guard_mcp_tool

guard = ToolGuard(mode="proxy", proxy_url="http://localhost:9090",
                  agent_id="mcp-server", org_id="acme")

@guard_mcp_tool(guard, tool_group="data_access")
def call_tool(tool_name: str, parameters: dict, **kwargs) -> dict:
    return TOOLS[tool_name](**parameters)
```

---

## Errors

| Exception | When raised |
|---|---|
| `ToolDenied` | `action_taken` is anything other than `allowed`, `allowed_shadow`, `flagged`, or `escalated` (i.e. the call was actually blocked) |
| `ToolEscalated` | `action_taken == "escalated"` (wait for human approval) |

Raised on `action_taken`, not `decision` — deliberately. In shadow mode
the engine reports `decision="denied"` (what *would* happen) alongside
`action_taken="allowed_shadow"` (what *actually* happened, since shadow
mode never enforces); `evaluate()` never raises for that case, since
shadow mode exists specifically to observe without blocking.

Both carry a `.result` attribute with the full `EvaluationResult`:
`result.decision_reason`, `result.suggested_response`, `result.rule_results`, etc.

---

## Wire contract

The SDK mirrors the Go `pkg/domain` JSON contract exactly.  Key field names:

**ActionEnvelope** (what the SDK sends to the engine):
`envelope_id`, `timestamp`, `agent_id`, `session_id`, `org_id`,
`framework` (`"mcp"` | `"langgraph"` | `"sdk"` | `"unknown"`),
`tool_name`, `tool_group`, `parameters`, `context.verified`,
`context.session_state`, `integration_type` (`"mcp_proxy"` |
`"langgraph_middleware"` | `"sdk"`).

**EvaluationResult** (what the engine returns):
`decision` (`"allowed"` | `"denied"` | `"escalated"` | `"flagged"`),
`action_taken`, `decision_reason`, `effective_mode`, `policies_matched`,
`rules_evaluated`, `rules_triggered`, `rule_results`, `applied_rule_results`,
`primary_citation`, `applied_primary_citation`, `is_near_miss`,
`suggested_response`. The applied provenance fields explain `action_taken`;
the aggregate fields can point to stricter shadow-only telemetry.

---

## Development

```bash
cd sdk/python
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ --cov-fail-under=90
```

Or via the top-level Makefile:

```bash
make sdk-test
```
