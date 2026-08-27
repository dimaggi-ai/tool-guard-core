"""Attach Tool Guard receipt references to downstream dict-shaped records.

This adapter is intentionally storage-neutral and dependency-free. It performs
no network or persistence operation and adds no inbound policy field. A missing
receipt remains missing; it is never replaced by a fabricated identifier.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Union

from toolguard.types import Escalation, EvaluationResult

Receiptable = Union[EvaluationResult, Escalation]
DEFAULT_EVENT_KEY = "tool_guard_receipt_uri"


def receipt_reference(result: Receiptable) -> Optional[str]:
    """Return the opaque receipt URI attached to ``result``, or ``None``."""
    receipt = getattr(result, "decision_receipt", None)
    if receipt is None:
        receipt = getattr(result, "resolution_receipt", None)
    if receipt is None:
        return None
    required_fields = (
        "receipt_version",
        "trace_id",
        "trace_hash",
        "hash_algorithm",
        "canonical_trace_version",
        "integrity_model",
        "decision",
        "action_taken",
        "timestamp",
        "receipt_uri",
    )
    fields = {name: getattr(receipt, name, None) for name in required_fields}
    if not all(isinstance(value, str) for value in fields.values()):
        return None

    digest = fields["trace_hash"].removeprefix("sha256:")
    valid_digest = (
        fields["trace_hash"].startswith("sha256:")
        and len(digest) == 64
        and all(char in "0123456789abcdef" for char in digest)
    )
    expected_uri = (
        f"urn:tool-guard:trace:{fields['canonical_trace_version']}:"
        f"{fields['trace_hash']}"
    )
    if not (
        fields["receipt_version"] == "1"
        and fields["trace_id"]
        and valid_digest
        and fields["hash_algorithm"] == "sha256"
        and fields["canonical_trace_version"]
        and fields["integrity_model"] == "hash-chain"
        and fields["decision"]
        and fields["action_taken"]
        and fields["timestamp"]
        and fields["receipt_uri"] == expected_uri
    ):
        return None
    return fields["receipt_uri"]


def attach_receipt_reference(
    event: Dict[str, Any],
    result: Receiptable,
    key: str = DEFAULT_EVENT_KEY,
) -> Dict[str, Any]:
    """Attach a present receipt URI to ``event`` in place and return it."""
    reference = receipt_reference(result)
    if reference is not None:
        event[key] = reference
    return event


def with_receipt_reference(
    event: Dict[str, Any],
    result: Receiptable,
    key: str = DEFAULT_EVENT_KEY,
) -> Dict[str, Any]:
    """Return a shallow copy of ``event`` with a present receipt attached."""
    return attach_receipt_reference(dict(event), result, key=key)
