from toolguard.adapters.memory import (
    DEFAULT_EVENT_KEY,
    attach_receipt_reference,
    receipt_reference,
    with_receipt_reference,
)
from toolguard.types import DecisionReceipt, Escalation, EvaluationResult


_RECEIPT = DecisionReceipt(
    receipt_version="1",
    trace_id="trc-001",
    trace_hash="sha256:" + "ab" * 32,
    hash_algorithm="sha256",
    canonical_trace_version="v2",
    integrity_model="hash-chain",
    decision="denied",
    action_taken="denied",
    timestamp="2026-08-25T00:00:00Z",
    receipt_uri="urn:tool-guard:trace:v2:sha256:" + "ab" * 32,
)


def test_receipt_reference_supports_decision_and_resolution():
    result = EvaluationResult(
        decision="denied", action_taken="denied", decision_receipt=_RECEIPT
    )
    escalation = Escalation(
        id="esc-1",
        state="denied",
        decision=EvaluationResult(decision="escalated", action_taken="escalated"),
        resolution_receipt=_RECEIPT,
    )
    assert receipt_reference(result) == _RECEIPT.receipt_uri
    assert receipt_reference(escalation) == _RECEIPT.receipt_uri


def test_missing_or_empty_receipt_never_fabricates_reference():
    missing = EvaluationResult(decision="allowed", action_taken="allowed")
    empty = EvaluationResult(
        decision="allowed",
        action_taken="allowed",
        decision_receipt=DecisionReceipt(),
    )
    assert receipt_reference(missing) is None
    assert receipt_reference(empty) is None
    event = {"tool": "read"}
    assert attach_receipt_reference(event, missing) is event
    assert event == {"tool": "read"}


def test_malformed_receipt_uri_or_required_field_is_not_forwarded():
    wrong_uri = DecisionReceipt.from_dict(_RECEIPT.to_dict())
    wrong_uri.receipt_uri = "urn:tool-guard:trace:v2:sha256:" + "cd" * 32
    missing_trace_id = DecisionReceipt.from_dict(_RECEIPT.to_dict())
    missing_trace_id.trace_id = ""

    for receipt in (wrong_uri, missing_trace_id):
        result = EvaluationResult(
            decision="denied", action_taken="denied", decision_receipt=receipt
        )
        assert receipt_reference(result) is None
        assert attach_receipt_reference({}, result) == {}


def test_non_string_receipt_fields_are_ignored_without_raising():
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
    for field in required_fields:
        receipt = DecisionReceipt.from_dict(_RECEIPT.to_dict())
        setattr(receipt, field, 123)
        result = EvaluationResult(
            decision="denied", action_taken="denied", decision_receipt=receipt
        )
        assert receipt_reference(result) is None
        assert attach_receipt_reference({}, result) == {}


def test_attach_and_copy_helpers():
    result = EvaluationResult(
        decision="denied", action_taken="denied", decision_receipt=_RECEIPT
    )
    original = {"tool": "write"}
    copied = with_receipt_reference(original, result)
    assert DEFAULT_EVENT_KEY not in original
    assert copied[DEFAULT_EVENT_KEY] == _RECEIPT.receipt_uri

    returned = attach_receipt_reference(original, result, key="receipt")
    assert returned is original
    assert original["receipt"] == _RECEIPT.receipt_uri
