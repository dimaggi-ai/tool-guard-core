"""
toolguard.client — ToolGuard client: CLI and proxy backends.

CLI mode  — shells out to ``tg evaluate -policy|-policy-dir ... -call <tmpfile>``.
            A policy directory is evaluated as one set by the Go engine so
            mixed shadow/enforcement semantics match the proxy exactly.
            Exit-code contract (from cmd/tg/main.go):
              0 → allowed / allowed_shadow
              3 → denied
              4 → escalated
              1 → internal error  (raises RuntimeError)
              2 → usage error     (raises RuntimeError)

Proxy mode — POSTs the ActionEnvelope JSON to tg-proxy ``/evaluate`` via
             httpx and parses the EvaluationResult from the response body.

In both modes the envelope is stamped with ``framework="sdk"`` and
``integration_type="sdk"`` by default. Adapters override these fields
before calling the client.
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import (
    ActionEnvelope,
    ActionTaken,
    Decision,
    EnvelopeContext,
    EvaluationResult,
    Framework,
    IntegrationType,
)


# Exit code → Decision (cmd/tg/main.go, cmdEvaluate)
_EXITCODE_DECISION: dict[int, str] = {
    0: Decision.ALLOWED,
    3: Decision.DENIED,
    4: Decision.ESCALATED,
}


class ToolGuard:
    """
    Policy decision client for AI agent tool calls.

    Parameters
    ----------
    mode : "cli" | "proxy"
        Transport to use:
        - ``"cli"``   — runs the ``tg`` binary locally (default).
        - ``"proxy"`` — calls a running ``tg-proxy`` over HTTP.
    tg_bin : str
        Path to (or name of) the ``tg`` binary.  Resolved via ``PATH``
        when given as a bare name.  CLI mode only.
    proxy_url : str
        Base URL of the ``tg-proxy`` service.  Proxy mode only.
    policy_dir : str, optional
        Directory of ``*.yaml`` / ``*.yml`` policy files. All files are
        evaluated together as one policy set. CLI mode only.
    policy_file : str, optional
        Path to a single policy YAML.  Used when ``policy_dir`` is not
        set.  CLI mode only.
    agent_id : str
        Stamped on every envelope as ``agent_id``.
    org_id : str
        Stamped on every envelope as ``org_id``.
    session_id : str, optional
        Default session ID.  Callers can override per-call.
    framework : str
        Value stamped as ``framework`` on every envelope.  Adapters
        override this; leave at the default (``"sdk"``) for direct use.
    integration_type : str
        Value stamped as ``integration_type``.  Adapters override this.
    """

    def __init__(
        self,
        mode: str = "cli",
        tg_bin: str = "tg",
        proxy_url: str = "http://localhost:9090",
        policy_dir: Optional[str] = None,
        policy_file: Optional[str] = None,
        agent_id: str = "",
        org_id: str = "",
        session_id: Optional[str] = None,
        framework: str = Framework.SDK,
        integration_type: str = IntegrationType.SDK,
    ) -> None:
        if mode not in ("cli", "proxy"):
            raise ValueError(f"mode must be 'cli' or 'proxy', got {mode!r}")
        self.mode = mode
        self.tg_bin = tg_bin
        self.proxy_url = proxy_url.rstrip("/")
        self.policy_dir = policy_dir
        self.policy_file = policy_file
        self.agent_id = agent_id
        self.org_id = org_id
        self.session_id = session_id or str(uuid.uuid4())
        self.framework = framework
        self.integration_type = integration_type

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        tool_name: str,
        parameters: Any,
        tool_group: str = "",
        tool_server: str = "",
        session_id: Optional[str] = None,
        context: Optional[EnvelopeContext] = None,
        envelope_id: Optional[str] = None,
    ) -> EvaluationResult:
        """
        Evaluate a tool call against all configured policies.

        Returns the :class:`~toolguard.types.EvaluationResult` when the
        decision is ``"allowed"`` or ``"flagged"`` (flagged = recorded
        near-miss, execution proceeds).

        Raises
        ------
        ToolDenied
            When ``action_taken == "denied"``.
        ToolEscalated
            When ``action_taken == "escalated"`` (wait for human approval).
        RuntimeError
            When the engine returns an unrecoverable error (CLI exit 1/2).
        """
        result = self.evaluate_raw(
            tool_name=tool_name,
            parameters=parameters,
            tool_group=tool_group,
            tool_server=tool_server,
            session_id=session_id,
            context=context,
            envelope_id=envelope_id,
        )
        # Branch on action_taken, NOT decision. In shadow mode the engine
        # keeps decision="denied"/"escalated" (what WOULD have happened)
        # but action_taken="allowed_shadow" (what actually happened —
        # shadow mode never enforces) — see pkg/engine/effects.go. Branching
        # on `decision` made a shadow-mode deployment enforce through the
        # SDK when it should only observe; in enforcement mode action_taken
        # mirrors decision for denied/escalated anyway, so this doesn't
        # change enforcement-mode behavior.
        #
        # Allowlist, not denylist: only these three action_taken values
        # let the call proceed; anything else — including a future engine
        # value this SDK version doesn't recognize yet — raises ToolDenied.
        # A denylist (raise only on the values we know about, proceed on
        # everything else) would silently allow an unrecognized value
        # through, which is exactly backwards for a governance layer.
        # adapters/native.py already used an allowlist here; this brings
        # evaluate() — and therefore autogen.py/mcp.py, which call it — to
        # the same posture instead of leaving them on the weaker one.
        if result.action_taken in (
            ActionTaken.ALLOWED,
            ActionTaken.ALLOWED_SHADOW,
            ActionTaken.FLAGGED,
        ):
            return result
        if result.action_taken == ActionTaken.ESCALATED:
            raise ToolEscalated(
                result.decision_reason or "Tool call requires human escalation",
                result=result,
            )
        raise ToolDenied(
            result.decision_reason or "Tool call denied by policy",
            result=result,
        )

    def evaluate_raw(
        self,
        tool_name: str,
        parameters: Any,
        tool_group: str = "",
        tool_server: str = "",
        session_id: Optional[str] = None,
        context: Optional[EnvelopeContext] = None,
        envelope_id: Optional[str] = None,
    ) -> EvaluationResult:
        """
        Like :meth:`evaluate` but never raises — always returns the result.
        Use this when you want to inspect the decision yourself.
        """
        envelope = self._build_envelope(
            tool_name=tool_name,
            parameters=parameters,
            tool_group=tool_group,
            tool_server=tool_server,
            session_id=session_id,
            context=context,
            envelope_id=envelope_id,
        )
        if self.mode == "cli":
            return self._evaluate_cli(envelope)
        return self._evaluate_proxy(envelope)

    # ------------------------------------------------------------------
    # Envelope builder
    # ------------------------------------------------------------------

    def _build_envelope(
        self,
        tool_name: str,
        parameters: Any,
        tool_group: str = "",
        tool_server: str = "",
        session_id: Optional[str] = None,
        context: Optional[EnvelopeContext] = None,
        envelope_id: Optional[str] = None,
    ) -> ActionEnvelope:
        return ActionEnvelope(
            envelope_id=envelope_id or str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            session_id=session_id or self.session_id,
            org_id=self.org_id,
            framework=self.framework,
            tool_name=tool_name,
            tool_group=tool_group,
            tool_server=tool_server,
            parameters=parameters,
            context=context or EnvelopeContext(),
            integration_type=self.integration_type,
        )

    # ------------------------------------------------------------------
    # CLI backend  (tg evaluate -policy|-policy-dir ... -call FILE)
    # ------------------------------------------------------------------

    def _evaluate_cli(self, envelope: ActionEnvelope) -> EvaluationResult:
        policy_files = self._resolve_policy_files()
        if not policy_files:
            # No policies loaded → allow by convention (mirrors tg-proxy
            # fail-open default when no policies are present without -fail-closed).
            return EvaluationResult(
                decision=Decision.ALLOWED,
                action_taken=ActionTaken.ALLOWED,
                decision_reason="No policies configured",
            )

        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            json.dump(envelope.to_dict(), f)
            call_path = f.name

        try:
            if self.policy_dir:
                policy_args = ["-policy-dir", self.policy_dir]
            else:
                policy_args = ["-policy", policy_files[0]]
            return self._run_tg_evaluate(policy_args, call_path)
        finally:
            try:
                os.unlink(call_path)
            except OSError:
                pass

    def _resolve_policy_files(self) -> list[str]:
        """Return sorted list of policy YAML paths to evaluate against."""
        if self.policy_dir:
            files = sorted(
                glob.glob(os.path.join(self.policy_dir, "*.yaml"))
                + glob.glob(os.path.join(self.policy_dir, "*.yml"))
            )
            return files
        if self.policy_file and os.path.isfile(self.policy_file):
            return [self.policy_file]
        return []

    def _run_tg_evaluate(
        self, policy_args: list[str], call_path: str
    ) -> EvaluationResult:
        """
        Shell out to ``tg evaluate <policy_args> -call <call_path>``.

        Returns an EvaluationResult parsed from stdout JSON.
        Falls back to mapping the exit code when stdout is empty or
        unparseable (e.g. engine compiled without a matching policy).
        """
        cmd = [self.tg_bin, "evaluate", *policy_args, "-call", call_path]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        # 1 = internal error, 2 = usage error — propagate as RuntimeError
        if proc.returncode in (1, 2):
            raise RuntimeError(
                f"tg evaluate exited {proc.returncode}: {proc.stderr.strip()}"
            )

        stdout = proc.stdout.strip()
        if stdout:
            try:
                data = json.loads(stdout)
                return EvaluationResult.from_dict(data)
            except (json.JSONDecodeError, TypeError) as exc:
                if proc.returncode not in _EXITCODE_DECISION:
                    # Unparseable stdout AND an exit code we don't
                    # recognize — no principled decision to fall back to.
                    # Fail closed: raise, don't guess ALLOWED. See the
                    # comment below for why this branch exists at all.
                    raise RuntimeError(
                        f"tg evaluate exited {proc.returncode} with "
                        f"unparseable stdout — cannot determine a decision "
                        f"(fail-closed): {stdout[:500]!r}"
                    ) from exc
                # Known exit code with no/bad stdout: fall through to the exit-code
                # fallback below, same as the empty-stdout case.

        # Fallback: map exit code → decision. Only trusted for the exit
        # codes cmd/tg/main.go's cmdEvaluate actually documents (0/3/4;
        # 1/2 already raised above). Any OTHER code — a signal kill, OOM,
        # a future new exit code the Go CLI adds that this dict doesn't
        # know about yet — has no principled decision to fall back to, so
        # this fails closed (raises) instead of defaulting to ALLOWED.
        # This used to default unknown codes to ALLOWED, which is exactly
        # the class of bug the 0.5.0 Go-side work ("fail-closed evaluator
        # errors") was about closing — the SDK reintroduced it in Python.
        if proc.returncode not in _EXITCODE_DECISION:
            raise RuntimeError(
                f"tg evaluate exited unexpected code {proc.returncode} "
                f"(not 0, 1, 2, 3, or 4) — fail-closed: cannot determine "
                f"a decision. stderr: {proc.stderr.strip()!r}"
            )
        decision = _EXITCODE_DECISION[proc.returncode]
        return EvaluationResult(decision=decision, action_taken=decision)

    # ------------------------------------------------------------------
    # Proxy backend  (POST /evaluate)
    # ------------------------------------------------------------------

    def _evaluate_proxy(self, envelope: ActionEnvelope) -> EvaluationResult:
        try:
            import httpx
        except ImportError as exc:
            raise ImportError(
                "httpx is required: pip install \"./tool-guard-core/sdk/python\" "
                "(it ships as a core dep; not yet on PyPI — install from a clone "
                "of this repo)"
            ) from exc

        payload = envelope.to_dict()
        resp = httpx.post(
            f"{self.proxy_url}/evaluate",
            json=payload,
            timeout=5.0,
        )
        resp.raise_for_status()
        return EvaluationResult.from_dict(resp.json())
