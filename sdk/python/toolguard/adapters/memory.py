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
    digest = receipt.trace_hash.removeprefix("sha256:")
    valid_digest = (
        receipt.trace_hash.startswith("sha256:")
        and len(digest) == 64
        and all(char in "0123456789abcdef" for char in digest)
    )
    expected_uri = (
        f"urn:tool-guard:trace:{receipt.canonical_trace_version}:"
        f"{receipt.trace_hash}"
    )
    if not (
        receipt.receipt_version == "1"
        and receipt.trace_id
        and valid_digest
        and receipt.hash_algorithm == "sha256"
        and receipt.canonical_trace_version
        and receipt.integrity_model == "hash-chain"
        and receipt.decision
        and receipt.action_taken
        and receipt.timestamp
        and receipt.receipt_uri == expected_uri
    ):
        return None
    return receipt.receipt_uri


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
