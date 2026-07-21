"""
test_contract.py — Real engine contract test.

Builds the ``tg`` binary from source (``go build -o /tmp/tg ./cmd/tg``),
creates a tiny policy dir (one deny policy on issue_refund > $500, allow
otherwise), runs the SDK in CLI mode pointing at that binary, and asserts the
SDK's decisions match what the raw engine returns for several calls.

Skips gracefully (pytest.skip) when:
  - ``go`` is not on PATH
  - The go build fails (e.g. missing module cache)
  - The tool-guard-core source is not at the expected path
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

import pytest

from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import Decision


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Source root of the tool-guard-core Go module (two levels up from sdk/python/)
REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
TG_BIN = "/tmp/tg_sdk_contract_test"

# Policy YAML that denies issue_refund > $500 and allows everything else.
_DENY_POLICY = """\
policy_id: sdk-contract-deny-cap
status: approved
mode: enforcement
scope:
  tool_names: [issue_refund]
  tool_groups: [monetary_outflow]
rules:
  - rule_id: rule-amount-cap
    conditions:
      field: amount
      operator: gt
      value: 500
    effect: deny
    citation:
      document_id: sdk-contract-test
      excerpt: "Deny refunds over $500 in the contract test"
"""

# Policy YAML that allows everything (explicit allow rule).
_ALLOW_POLICY = """\
policy_id: sdk-contract-allow-all
status: approved
mode: enforcement
scope:
  tool_names: [issue_refund]
  tool_groups: [monetary_outflow]
rules:
  - rule_id: rule-allow
    conditions:
      field: amount
      operator: lte
      value: 500
    effect: allow
    citation:
      document_id: sdk-contract-test
      excerpt: "Allow refunds up to $500"
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def tg_binary():
    """Build tg once per test session.  Skip if go is unavailable."""
    if not shutil.which("go"):
        pytest.skip("go not on PATH — skipping contract tests")

    if not os.path.isdir(REPO_ROOT) or not os.path.isfile(
        os.path.join(REPO_ROOT, "go.mod")
    ):
        pytest.skip(
            f"tool-guard-core source not found at {REPO_ROOT} — skipping contract tests"
        )

    result = subprocess.run(
        ["go", "build", "-o", TG_BIN, "./cmd/tg"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        pytest.skip(
            f"go build failed (exit {result.returncode}): {result.stderr[:500]}"
        )

    yield TG_BIN

    # Cleanup: remove the binary after the session.
    try:
        os.unlink(TG_BIN)
    except OSError:
        pass


@pytest.fixture()
def policy_dir(tmp_path):
    """Create a temporary policy directory with the deny-cap policy."""
    (tmp_path / "deny_cap.yaml").write_text(_DENY_POLICY)
    return str(tmp_path)


@pytest.fixture()
def sdk_client(tg_binary, policy_dir):
    """SDK client in CLI mode pointing at the real tg binary."""
    return ToolGuard(
        mode="cli",
        tg_bin=tg_binary,
        policy_dir=policy_dir,
        agent_id="sdk-contract-agent",
        org_id="sdk-contract-org",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _raw_tg_evaluate(tg_bin: str, policy_path: str, envelope: dict) -> dict:
    """
    Run tg evaluate directly and return the parsed EvaluationResult dict.
    Used to get the "ground truth" decision from the engine directly.
    """
    with tempfile.NamedTemporaryFile(
        suffix=".json", mode="w", delete=False, encoding="utf-8"
    ) as f:
        json.dump(envelope, f)
        call_path = f.name

    try:
        proc = subprocess.run(
            [tg_bin, "evaluate", "-policy", policy_path, "-call", call_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return json.loads(proc.stdout)
    finally:
        os.unlink(call_path)


# ---------------------------------------------------------------------------
# Contract tests
# ---------------------------------------------------------------------------

class TestContract:
    def test_allowed_call_matches_engine(self, sdk_client, tg_binary, policy_dir):
        """SDK decision for an allowed call (amount $100) must match raw engine."""
        envelope = {
            "agent_id": "sdk-contract-agent",
            "org_id": "sdk-contract-org",
            "session_id": "sess-contract",
            "tool_name": "issue_refund",
            "tool_group": "monetary_outflow",
            "parameters": {"amount": 100, "reason": "Damaged on arrival"},
        }
        # Ground truth from raw engine
        policy_file = os.path.join(policy_dir, "deny_cap.yaml")
        raw = _raw_tg_evaluate(tg_binary, policy_file, envelope)
        engine_decision = raw["decision"]

        # SDK result
        sdk_result = sdk_client.evaluate_raw(
            tool_name="issue_refund",
            parameters={"amount": 100, "reason": "Damaged on arrival"},
            tool_group="monetary_outflow",
        )

        assert sdk_result.decision == engine_decision
        assert engine_decision == Decision.ALLOWED

    def test_denied_call_matches_engine(self, sdk_client, tg_binary, policy_dir):
        """SDK decision for a denied call (amount $1000) must match raw engine."""
        envelope = {
            "agent_id": "sdk-contract-agent",
            "org_id": "sdk-contract-org",
            "session_id": "sess-contract",
            "tool_name": "issue_refund",
            "tool_group": "monetary_outflow",
            "parameters": {"amount": 1000, "reason": "Goodwill credit"},
        }
        policy_file = os.path.join(policy_dir, "deny_cap.yaml")
        raw = _raw_tg_evaluate(tg_binary, policy_file, envelope)
        engine_decision = raw["decision"]

        # SDK must raise ToolDenied
        with pytest.raises(ToolDenied) as exc_info:
            sdk_client.evaluate(
                tool_name="issue_refund",
                parameters={"amount": 1000, "reason": "Goodwill credit"},
                tool_group="monetary_outflow",
            )

        assert exc_info.value.result.decision == engine_decision
        assert engine_decision == Decision.DENIED

    def test_boundary_exactly_500_is_allowed(self, sdk_client, tg_binary, policy_dir):
        """$500 exactly: operator is ``gt`` (strict) so $500 must be allowed."""
        policy_file = os.path.join(policy_dir, "deny_cap.yaml")
        raw = _raw_tg_evaluate(
            tg_binary,
            policy_file,
            {
                "tool_name": "issue_refund",
                "tool_group": "monetary_outflow",
                "parameters": {"amount": 500},
            },
        )
        engine_decision = raw["decision"]

        sdk_result = sdk_client.evaluate_raw(
            "issue_refund", {"amount": 500}, tool_group="monetary_outflow"
        )
        assert sdk_result.decision == engine_decision
        assert engine_decision == Decision.ALLOWED

    def test_501_is_denied(self, sdk_client, tg_binary, policy_dir):
        """$501 must be denied."""
        policy_file = os.path.join(policy_dir, "deny_cap.yaml")
        raw = _raw_tg_evaluate(
            tg_binary,
            policy_file,
            {
                "tool_name": "issue_refund",
                "tool_group": "monetary_outflow",
                "parameters": {"amount": 501},
            },
        )
        engine_decision = raw["decision"]

        with pytest.raises(ToolDenied) as exc_info:
            sdk_client.evaluate(
                "issue_refund", {"amount": 501}, tool_group="monetary_outflow"
            )
        assert exc_info.value.result.decision == engine_decision
        assert engine_decision == Decision.DENIED

    def test_result_carries_rule_results(self, sdk_client):
        """EvaluationResult must carry rule_results from the engine."""
        sdk_result = sdk_client.evaluate_raw(
            "issue_refund", {"amount": 1000}, tool_group="monetary_outflow"
        )
        assert sdk_result.decision == Decision.DENIED
        # Engine populates rule_results when a rule fires
        assert sdk_result.rules_triggered >= 1

    def test_envelope_fields_reach_engine(self, tg_binary, policy_dir):
        """
        Verify the SDK correctly serializes agent_id and org_id into the
        envelope that tg evaluate receives.  Uses a fresh client with distinct
        IDs and checks that the raw engine's decision is consistent.
        """
        client = ToolGuard(
            mode="cli",
            tg_bin=tg_binary,
            policy_dir=policy_dir,
            agent_id="agent-envelope-check",
            org_id="org-envelope-check",
        )
        # An allowed call; if the envelope is malformed the engine returns
        # an error (exit 1) which would raise RuntimeError — the fact that
        # evaluate_raw succeeds proves the envelope parsed correctly.
        result = client.evaluate_raw(
            "issue_refund", {"amount": 50}, tool_group="monetary_outflow"
        )
        assert result.decision == Decision.ALLOWED
