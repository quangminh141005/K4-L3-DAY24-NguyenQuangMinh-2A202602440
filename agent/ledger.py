"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
        Chỉ kiểm tra file hiện có KHÔNG phát hiện được việc xoá dòng cuối
        hoặc viết lại cả file và tính lại chuỗi. Muốn phát hiện cắt đuôi
        phải lưu hash/số dòng cuối ở một nơi tin cậy bên ngoài file rồi
        đối chiếu. Bài lab không cung cấp mốc đó.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

from pathlib import Path
import fcntl
import hashlib
import hmac
import json

GENESIS = "0" * 64
REQUIRED = {"ts", "agent_id", "run_id", "tool", "args_hash",
            "classification", "decision", "reason"}


def _digest(entry: dict) -> str:
    payload = {key: value for key, value in entry.items() if key != "hash"}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _verify_lines(lines: list[str]) -> bool:
    previous = GENESIS
    try:
        for line in lines:
            entry = json.loads(line)
            if not isinstance(entry, dict) or not REQUIRED.issubset(entry):
                return False
            reason = entry.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                return False
            if entry.get("decision") not in {"allow", "deny"}:
                return False
            if entry.get("prev_hash") != previous:
                return False
            saved = entry.get("hash")
            if not isinstance(saved, str) or not hmac.compare_digest(saved, _digest(entry)):
                return False
            previous = saved
    except (ValueError, TypeError):
        return False
    return True


def append(entry: dict, path: Path) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        stream.seek(0)
        lines = stream.read().splitlines()
        if not _verify_lines(lines):
            raise ValueError("Refusing to append to an invalid audit chain")
        record = dict(entry)
        record["prev_hash"] = json.loads(lines[-1])["hash"] if lines else GENESIS
        record["hash"] = _digest(record)
        stream.seek(0, 2)
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True,
                                allow_nan=False) + "\n")
        stream.flush()
        return record


def verify(path: Path) -> bool:
    try:
        with Path(path).open(encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            return _verify_lines(stream.read().splitlines())
    except (OSError, UnicodeError):
        return False
