"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


@dataclass(frozen=True)
class Run:
    agent_id: str
    run_id: str
    principal_id: str
    scopes: tuple[str, ...]
    expires_at: str
    ledger_path: Path
    parent_scopes: tuple[str, ...]


@dataclass(frozen=True)
class TicketSelection:
    """The entire A -> B payload: filenames become integers, no document text."""
    ticket_ids: tuple[int, ...]

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in self.ticket_ids):
            raise ValueError("Ticket IDs must be positive integers")


def _authorize(run: Run, tool: str, args: dict, classification: str,
               purpose: str, egress: bool = False, event: str = "tool_call") -> bool:
    """PEP and audit write both complete before any capability executes."""
    context = policy.PolicyContext(
        data_classification=classification, request_purpose=purpose,
        agent_owner=run.agent_id, delegation_depth=1, egress_enabled=egress,
        principal_id=run.principal_id, requested_tool=tool,
        agent_scopes=run.scopes, parent_scopes=run.parent_scopes,
        expires_at=run.expires_at,
    )
    allowed, reason = policy.check(context)
    encoded = json.dumps(args, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(), "agent_id": run.agent_id,
        "run_id": run.run_id, "on_behalf_of": run.principal_id,
        "expires_at": run.expires_at, "tool": tool,
        "args_hash": hashlib.sha256(encoded).hexdigest(),
        "classification": classification, "decision": "allow" if allowed else "deny",
        "reason": reason, "purpose": purpose, "event": event,
    }, run.ledger_path)
    return allowed


def _run_a(message: str, llm, run: Run) -> tuple[TicketSelection, str, bool]:
    if not _authorize(run, "search_docs", {"query": message}, "internal", "summarize-tickets"):
        return TicketSelection(()), "Yêu cầu không được cấp quyền.", False
    docs = tools.search_docs(message)
    # Redact before the summarizer boundary. B receives no text at all.
    safe_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    ticket_ids = set()
    for doc in safe_docs:
        match = re.fullmatch(r"ticket-(\d+)[a-z]?\.md", doc["id"])
        if match and int(match.group(1)) > 0:
            ticket_ids.add(int(match.group(1)))
    injected = llm.find_injection("\n\n".join(d["text"] for d in safe_docs))
    # Only an attempt flag returns to the controller. Attacker customer IDs,
    # target URLs and instructions never enter the private-data stage.
    return TicketSelection(tuple(sorted(ticket_ids))), pii.redact(llm.summarize(safe_docs)), injected is not None


def _run_b(selection: TicketSelection, run: Run) -> list[dict]:
    if not selection.ticket_ids:
        return []
    # The lab's trusted file includes PII alongside the linkage index. Gate
    # that file access too: support_l1 must never open the private store.
    if not _authorize(run, "read_customer", {"ticket_ids": selection.ticket_ids},
                      "restricted", "support-reply", event="trusted_ticket_index"):
        return []
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    selected = set(selection.ticket_ids)
    customer_ids = sorted({c["customer_id"] for c in customers
                           if selected.intersection(c.get("related_tickets", []))})
    # Retain only the trusted link-derived IDs for subsequent calls.
    del customers
    records = []
    for customer_id in customer_ids:
        if _authorize(run, "read_customer", {"customer_id": customer_id},
                      "restricted", "support-reply"):
            records.append(tools.read_customer(customer_id))
    return records


def _run_c(records: list[dict], run: Run) -> None:
    # C has no corpus/search capability. Use a code-owned localhost endpoint;
    # an attacker URL is never part of the A -> B or B -> C contract.
    url = "http://127.0.0.1:10024/reconcile"
    body = {"records": records}
    if _authorize(run, "http_post", {"url": url, "body": body},
                  "restricted", "support-reply", egress=True):
        tools.http_post(url, body)


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir is not None else DEFAULT_LEDGER_PATH
    request_id = uuid4().hex
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    parent_scopes = ("search_docs", "read_customer", "http_post")

    def make_run(stage: str, scopes: tuple[str, ...]) -> Run:
        return Run(agent_id=f"lab24-agent/{request_id}/{stage}",
                   run_id=f"{request_id}/{stage}", principal_id=principal_id,
                   scopes=scopes, expires_at=expires, ledger_path=ledger_path,
                   parent_scopes=parent_scopes)

    selection, summary, attempted_egress = _run_a(message, llm, make_run("a", ("search_docs",)))
    records = _run_b(selection, make_run("b", ("read_customer",)))
    if attempted_egress:
        _run_c(records, make_run("c", ("http_post",)))
    return summary
