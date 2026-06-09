# mcp-server — Tool Guard as an MCP bridge

A minimal Model Context Protocol (MCP) server that gates every tool
call through Tool Guard before invoking the upstream tool.

The server speaks JSON-RPC 2.0 over stdio (the standard MCP
transport) and implements three methods: `initialize`,
`tools/list`, and `tools/call`. It exposes two example tools —
`issue_refund` and `export_customer_data` — and every `tools/call`
goes to `tg-proxy /evaluate` first.

If Tool Guard says `allowed`, the (mocked) tool runs. If it says
`denied`, the MCP response is an error with the policy's reason. If
it says `escalated`, the client is told a human needs to approve.

This is the integration pattern any MCP-capable agent (Claude
Desktop, Continue.dev, the MCP-rs reference client, or your own
agent runtime) can use.

## Run it

```sh
# 1. From the repo root, start a Tool Guard proxy.
make build
./bin/tg-proxy \
  -listen 127.0.0.1:9090 \
  -policy-dir ./policies \
  -audit-log /tmp/mcp.jsonl &

# 2. Build and run the MCP server.
go build -o bin/mcp-server ./examples/mcp-server
./bin/mcp-server -tg-proxy http://127.0.0.1:9090
# (it will sit waiting for JSON-RPC messages on stdin)
```

## Test from the shell

In another terminal, pipe a tool-call sequence:

```sh
# A small refund — should be ALLOWED by policies/refund_cap.yaml
echo '{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"issue_refund","arguments":{"amount":85,"reason":"Refund for damaged item"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"issue_refund","arguments":{"amount":1500,"reason":"Goodwill credit"}}}' \
  | ./bin/mcp-server -tg-proxy http://127.0.0.1:9090
```

Output (one JSON-RPC response per request line):

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",...}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[...]}}
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"[STUB] issue_refund executed successfully"}],"isError":false}}
{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"DENIED BY POLICY: Denied by: [rule-amount-cap] ..."}],"isError":true}}
```

The first refund ($85) passes the cap; the second ($1500) is denied
by `policies/refund_cap.yaml`. The MCP client sees both as proper
tool-call responses — `isError: false` for allowed, `isError: true`
for denied.

## Connect it to Claude Desktop / Continue.dev

Add this to your MCP-client config (path varies by client):

```json
{
  "mcpServers": {
    "tool-guard": {
      "command": "/absolute/path/to/bin/mcp-server",
      "args": ["-tg-proxy", "http://127.0.0.1:9090"]
    }
  }
}
```

Restart the client. The two example tools will appear in its tool
list, gated by whatever policies you have loaded in the proxy.

## Scope

It is a working demonstration of the integration pattern: how to
sit in front of a real upstream tool, run every call through Tool
Guard, and faithfully surface the decision back to the MCP client.

It is not a full MCP server. It doesn't implement resources,
prompts, completion, or the streaming transport variants. It speaks
the minimum subset MCP clients need to list and call tools. For a
production deployment, use the official MCP SDK in your language of
choice and put the Tool Guard call where this example does it.

The MCP spec lives at <https://modelcontextprotocol.io/>.

## Audit chain

Every tool call — allowed, denied, escalated — lands in the audit
log configured via `tg-proxy -audit-log`. Run `./bin/tg verify` to
confirm the chain is intact at any time. The MCP client never sees
the audit log; it sees only the policy decision.
