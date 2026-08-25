"""
test_client.py — Unit tests for ToolGuard (CLI mode and proxy mode).

Uses monkeypatching to avoid needing a real tg binary or tg-proxy server.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import (
    ActionTaken,
    Decision,
    EnvelopeContext,
)


# ---------------------------------------------------------------------------
# Helper: fake subprocess.CompletedProcess
# ---------------------------------------------------------------------------

def _fake_proc(returncode: int, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def _eval_result_json(decision: str, action_taken: str = None) -> str:
    if action_taken is None:
        action_taken = decision
    return json.dumps({
        "decision": decision,
        "action_taken": action_taken,
        "effective_mode": "enforcement",
        "policies_matched": 1,
        "rules_evaluated": 1,
        "rules_triggered": 1 if decision != "allowed" else 0,
        "rule_results": [],
        "is_near_miss": False,
    })


# ---------------------------------------------------------------------------
# CLI mode — exit-code mapping
# ---------------------------------------------------------------------------

class TestCLIMode:
    def _make_client(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "policy_id: test\nstatus: approved\nmode: enforcement\n"
            "scope:\n  tool_names: []\nrules: []\n"
        )
        return ToolGuard(
            mode="cli",
            tg_bin="/usr/bin/tg",
            policy_dir=str(tmp_path),
            agent_id="test-agent",
            org_id="test-org",
        )

    def test_exit_0_returns_allowed(self, tmp_path):
        client = self._make_client(tmp_path)
        proc = _fake_proc(0, stdout=_eval_result_json("allowed"))
        with patch("subprocess.run", return_value=proc):
            result = client.evaluate_raw("search", {"q": "hello"})
        assert result.decision == Decision.ALLOWED

    def test_exit_3_returns_denied(self, tmp_path):
        client = self._make_client(tmp_path)
        proc = _fake_proc(3, stdout=_eval_result_json("denied"))
        with patch("subprocess.run", return_value=proc):
            result = client.evaluate_raw("issue_refund", {"amount": 1000})
        assert result.decision == Decision.DENIED

    def test_exit_4_returns_escalated(self, tmp_path):
        client = self._make_client(tmp_path)
        proc = _fake_proc(4, stdout=_eval_result_json("escalated"))
        with patch("subprocess.run", return_value=proc):
            result = client.evaluate_raw("approve_payment", {"amount": 500})
        assert result.decision == Decision.ESCALATED

    def test_exit_3_raises_tool_denied(self, tmp_path):
        client = self._make_client(tmp_path)
        proc = _fake_proc(3, stdout=_eval_result_json("denied"))
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolDenied) as exc_info:
                client.evaluate("issue_refund", {"amount": 1000})
        assert exc_info.value.result is not None
        assert exc_info.value.result.decision == "denied"

    def test_exit_4_raises_tool_escalated(self, tmp_path):
        client = self._make_client(tmp_path)
        proc = _fake_proc(4, stdout=_eval_result_json("escalated"))
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(ToolEscalated):
                client.evaluate("approve_payment", {"amount": 500})

    def test_exit_0_allowed_shadow(self, tmp_path):
        """Exit 0 also covers allowed_shadow."""
        client = self._make_client(tmp_path)
        proc = _fake_proc(0, stdout=_eval_result_json("allowed", "allowed_shadow"))
        with patch("subprocess.run", return_value=proc):
            result = client.evaluate_raw("read_file", {})
        assert result.action_taken == ActionTaken.ALLOWED_SHADOW

    def test_exit_1_raises_runtime_error(self, tmp_path):
        client = self._make_client(tmp_path)
        proc = _fake_proc(1, stderr="internal error")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(RuntimeError, match="exited 1"):
                client.evaluate_raw("search", {})

    def test_exit_2_raises_runtime_error(self, tmp_path):
        client = self._make_client(tmp_path)
        proc = _fake_proc(2, stderr="usage error")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(RuntimeError, match="exited 2"):
                client.evaluate_raw("search", {})

    def test_no_policies_returns_allowed(self, tmp_path):
        """Empty policy_dir → allowed (no policies = not governed)."""
        client = ToolGuard(
            mode="cli",
            policy_dir=str(tmp_path),  # empty dir
            agent_id="a",
            org_id="o",
        )
        result = client.evaluate_raw("anything", {})
        assert result.decision == Decision.ALLOWED

    def test_policy_file_mode(self, tmp_path):
        policy = tmp_path / "p.yaml"
        policy.write_text(
            "policy_id: p\nstatus: approved\nmode: enforcement\n"
            "scope:\n  tool_names: []\nrules: []\n"
        )
        client = ToolGuard(
            mode="cli",
            policy_file=str(policy),
            agent_id="a",
            org_id="o",
        )
        proc = _fake_proc(0, stdout=_eval_result_json("allowed"))
        with patch("subprocess.run", return_value=proc) as mock_run:
            result = client.evaluate_raw("search", {})
        assert result.decision == Decision.ALLOWED
        # Verify -policy flag was passed with the single file
        cmd = mock_run.call_args[0][0]
        assert "-policy" in cmd
        assert str(policy) in cmd

    def test_multiple_policies_most_restrictive(self, tmp_path):
        """A policy directory is passed to the engine as one set."""
        pol1 = tmp_path / "a.yaml"
        pol2 = tmp_path / "b.yaml"
        pol1.write_text("policy_id: a\nstatus: approved\nmode: enforcement\n"
                        "scope:\n  tool_names: []\nrules: []\n")
        pol2.write_text("policy_id: b\nstatus: approved\nmode: enforcement\n"
                        "scope:\n  tool_names: []\nrules: []\n")

        client = ToolGuard(mode="cli", policy_dir=str(tmp_path), agent_id="a", org_id="o")

        def fake_run(cmd, **kwargs):
            return _fake_proc(3, stdout=_eval_result_json("denied"))

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            result = client.evaluate_raw("issue_refund", {"amount": 1000})

        assert result.decision == Decision.DENIED
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[2:4] == ["-policy-dir", str(tmp_path)]

    def test_envelope_fields_in_call_json(self, tmp_path):
        """The envelope written to the temp file must carry correct field names."""
        policy = tmp_path / "p.yaml"
        policy.write_text("policy_id: p\nstatus: approved\nmode: enforcement\n"
                          "scope:\n  tool_names: []\nrules: []\n")
        client = ToolGuard(
            mode="cli",
            policy_file=str(policy),
            agent_id="my-agent",
            org_id="my-org",
        )

        captured_call_json: list = []

        def fake_run(cmd, **kwargs):
            # The -call flag is followed by the path
            call_idx = cmd.index("-call") + 1
            call_path = cmd[call_idx]
            with open(call_path) as f:
                captured_call_json.append(json.load(f))
            return _fake_proc(0, stdout=_eval_result_json("allowed"))

        with patch("subprocess.run", side_effect=fake_run):
            client.evaluate_raw("my_tool", {"key": "value"}, tool_group="my_group")

        assert len(captured_call_json) == 1
        envelope = captured_call_json[0]
        assert envelope["agent_id"] == "my-agent"
        assert envelope["org_id"] == "my-org"
        assert envelope["tool_name"] == "my_tool"
        assert envelope["tool_group"] == "my_group"
        assert envelope["framework"] == "sdk"
        assert envelope["integration_type"] == "sdk"
        assert envelope["parameters"] == {"key": "value"}
        assert "envelope_id" in envelope
        assert "timestamp" in envelope
        assert "context" in envelope


# ---------------------------------------------------------------------------
# Proxy mode
# ---------------------------------------------------------------------------

class TestProxyMode:
    def _make_client(self, proxy_url="http://localhost:9090"):
        return ToolGuard(
            mode="proxy",
            proxy_url=proxy_url,
            agent_id="proxy-agent",
            org_id="proxy-org",
        )

    def _mock_httpx_post(self, decision: str):
        response = MagicMock()
        response.json.return_value = {
            "decision": decision,
            "action_taken": decision,
            "effective_mode": "enforcement",
            "policies_matched": 1,
            "rules_evaluated": 1,
            "rules_triggered": 0 if decision == "allowed" else 1,
            "rule_results": [],
            "is_near_miss": False,
        }
        response.raise_for_status = MagicMock()
        return response

    def test_allowed_returns_result(self):
        client = self._make_client()
        mock_resp = self._mock_httpx_post("allowed")
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = client.evaluate_raw("search", {"q": "test"})
        assert result.decision == Decision.ALLOWED
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "/evaluate" in call_kwargs[0][0]

    def test_denied_returns_result(self):
        client = self._make_client()
        mock_resp = self._mock_httpx_post("denied")
        with patch("httpx.post", return_value=mock_resp):
            result = client.evaluate_raw("issue_refund", {"amount": 1000})
        assert result.decision == Decision.DENIED

    def test_denied_raises_tool_denied(self):
        client = self._make_client()
        mock_resp = self._mock_httpx_post("denied")
        with patch("httpx.post", return_value=mock_resp):
            with pytest.raises(ToolDenied):
                client.evaluate("issue_refund", {"amount": 1000})

    def test_escalated_raises_tool_escalated(self):
        client = self._make_client()
        mock_resp = self._mock_httpx_post("escalated")
        with patch("httpx.post", return_value=mock_resp):
            with pytest.raises(ToolEscalated):
                client.evaluate("issue_refund", {"amount": 1000})

    def test_flagged_does_not_raise(self):
        """flagged = recorded near-miss; execution proceeds."""
        client = self._make_client()
        mock_resp = self._mock_httpx_post("flagged")
        with patch("httpx.post", return_value=mock_resp):
            result = client.evaluate("search", {"q": "test"})
        assert result.decision == Decision.FLAGGED

    def test_envelope_sent_to_correct_url(self):
        client = self._make_client(proxy_url="http://tg.internal:9090")
        mock_resp = self._mock_httpx_post("allowed")
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            client.evaluate_raw("search", {})
        url = mock_post.call_args[0][0]
        assert url == "http://tg.internal:9090/evaluate"

    def test_envelope_json_fields_in_proxy_payload(self):
        """Verify the JSON sent to tg-proxy has correct field names."""
        client = self._make_client()
        mock_resp = self._mock_httpx_post("allowed")
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            client.evaluate_raw(
                "issue_refund",
                {"amount": 100},
                tool_group="monetary_outflow",
            )
        payload = mock_post.call_args[1]["json"]
        assert payload["agent_id"] == "proxy-agent"
        assert payload["org_id"] == "proxy-org"
        assert payload["tool_name"] == "issue_refund"
        assert payload["tool_group"] == "monetary_outflow"
        assert payload["parameters"] == {"amount": 100}
        assert payload["framework"] == "sdk"
        assert payload["integration_type"] == "sdk"


# ---------------------------------------------------------------------------
# ToolGuard constructor validation
# ---------------------------------------------------------------------------

class TestConstructor:
    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="mode must be"):
            ToolGuard(mode="grpc")

    def test_default_session_id_generated(self):
        client = ToolGuard()
        assert client.session_id != ""

    def test_proxy_url_trailing_slash_stripped(self):
        client = ToolGuard(mode="proxy", proxy_url="http://localhost:9090/")
        assert not client.proxy_url.endswith("/")
