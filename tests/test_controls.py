"""Additional boundary checks; the mandatory grading tests remain unchanged."""
from dataclasses import replace
import pytest

from agent import ledger, pii, runner, tools
from agent.llm import MockLLM
from agent.policy import PolicyContext, check


@pytest.mark.parametrize("changes", [
    {"expires_at": ""}, {"expires_at": "not-a-date"},
    {"expires_at": "2099-01-01T00:00:00"},
    {"request_purpose": "attacker-export"}, {"agent_scopes": ()},
    {"delegation_depth": 1, "parent_scopes": ()},
])
def test_incomplete_authorization_fails_closed(changes):
    context = PolicyContext("restricted", "support-reply", "agent-b", 0, False,
                            "dpo", "read_customer", ("read_customer",), (),
                            "2099-01-01T00:00:00+00:00")
    allowed, reason = check(replace(context, **changes))
    assert not allowed and reason.strip()


def test_bank_context_resolves_overlap_and_redaction_preserves_offsets():
    text = "STK 012345678912; CCCD 123456789012; SĐT 0912-345-678; email a@example.vn"
    entities = pii.detect(text)
    assert [e["type"] for e in entities] == ["VN_BANK_ACCOUNT", "VN_CCCD", "VN_PHONE", "EMAIL"]
    assert [text[e["start"]:e["end"]] for e in entities] == [
        "012345678912", "123456789012", "0912-345-678", "a@example.vn"]
    assert pii.redact(text) == (
        "STK [REDACTED_VN_BANK_ACCOUNT]; CCCD [REDACTED_VN_CCCD]; "
        "SĐT [REDACTED_VN_PHONE]; email [REDACTED_EMAIL]")


def test_support_never_opens_private_store_and_summary_receives_redacted_docs(tmp_path, monkeypatch):
    values = ("123456789012", "0912345678", "12345678", "a@example.vn")
    doc = {"id": "ticket-901.md", "text": "CCCD 123456789012 SĐT 0912345678 STK 12345678 a@example.vn"}
    monkeypatch.setattr(tools, "search_docs", lambda query: [doc])
    monkeypatch.setattr(tools, "CUSTOMERS_FILE", tmp_path / "must-not-be-opened.json")

    class InspectLLM(MockLLM):
        def summarize(self, docs):
            assert all(value not in docs[0]["text"] for value in values)
            return super().summarize(docs)

    assert "1 ticket" in runner.handle("ticket", InspectLLM(), tmp_path, "support_l1")
    assert ledger.verify(tmp_path / "ledger.jsonl")


def test_invalid_audit_chain_prevents_tool_execution(tmp_path, monkeypatch):
    (tmp_path / "ledger.jsonl").write_text('{"tampered":true}\n', encoding="utf-8")

    def must_not_execute(query):
        pytest.fail("search ran before the audit write succeeded")

    monkeypatch.setattr(tools, "search_docs", must_not_execute)
    with pytest.raises(ValueError, match="invalid audit chain"):
        runner.handle("ticket", MockLLM(), tmp_path, "dpo")


def test_unknown_principal_has_no_tool_access(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "search_docs", lambda query: pytest.fail("unknown user searched"))
    result = runner.handle("ticket", MockLLM(), tmp_path, "unknown")
    assert "không được cấp quyền" in result
    assert ledger.verify(tmp_path / "ledger.jsonl")
