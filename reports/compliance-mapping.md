# Compliance mapping — checkpoint 5

Đối chiếu nguồn chính thức ngày 12/10/2026. Các hàng pháp luật bên dưới là
liên hệ kỹ thuật phục vụ bài học, không phải kết luận tuân thủ hoặc ý kiến pháp lý.
Đã xác minh tên, số hiệu, ngày ban hành/hiệu lực trên Công báo; **điều khoản cụ thể:
chưa xác minh** (bản ký số được cung cấp dạng PDF scan, chưa đối chiếu được toàn văn
đủ tin cậy). Không gán số điều/khoản khi chưa kiểm được bản gốc.

| Nguồn / phạm vi đối chiếu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| [Luật 91/2025/QH15 — Bảo vệ dữ liệu cá nhân](https://congbao.chinhphu.vn/van-ban/luat-so-91-2025-qh15-45578.htm); ban hành 26/06/2025, hiệu lực 01/01/2026; điều khoản cụ thể chưa xác minh | Giảm dữ liệu qua boundary, giới hạn mục đích, chặn egress restricted | `agent/pii.py:47`, `agent/runner.py:130`, `agent/policy.py:62`, `reports/ledger.jsonl:264`; `reports/attack-after.log` 0 byte | Dữ liệu hoàn toàn synthetic; chưa thực hiện consent, quyền chủ thể, xóa dữ liệu hay hồ sơ pháp lý chính thức |
| [NĐ 356/2025/NĐ-CP — hướng dẫn Luật Bảo vệ dữ liệu cá nhân](https://congbao.chinhphu.vn/van-ban/nghi-dinh-so-356-2025-nd-cp-468371.htm); ban hành 31/12/2025, hiệu lực 01/01/2026; điều khoản cụ thể chưa xác minh | Phân loại restricted, truy vết allow/deny bằng ledger, DPIA-lite mô tả dòng dữ liệu | `agent/runner.py:114`, `agent/ledger.py:100`, `reports/ledger.jsonl:27`, `reports/dpia-lite.md:1` | DPIA-lite không thay hồ sơ đánh giá/nộp cơ quan có thẩm quyền; hash chain chưa có mốc tin cậy ngoài file |
| [Luật AI 134/2025/QH15 — Trí tuệ nhân tạo](https://congbao.chinhphu.vn/van-ban/luat-so-134-2025-qh15-468694.htm); ban hành 10/12/2025, hiệu lực 01/03/2026; điều khoản cụ thể chưa xác minh | Phân tách quyền theo run, TTL, kiểm quyền ở tool boundary, ghi reason để giải thích quyết định | `agent/runner.py:101`, `agent/runner.py:178`, `agent/policy.py:66`, `reports/ledger.jsonl:2` | Mock deterministic không đánh giá model thật, phân loại rủi ro AI hoặc chứng nhận/giám sát production |
| OWASP ASI01 — Agent Goal Hijack | Không cho free text attacker quyết định customer; chỉ chuyển typed ticket IDs và map qua nguồn tin cậy; chặn POST | `agent/runner.py:92`, `agent/runner.py:133`, `agent/runner.py:152`, `tests/test_split.py:76`, `reports/attack-before.log:1`, `reports/ledger.jsonl:27` | Lure gắn đúng khách qua related_tickets vẫn cho dpo đọc; split không thay rule egress |
| OWASP ASI03 — Identity and Privilege Abuse | Principal ∩ agent scopes ∩ parent scopes, purpose và TTL; support bị chặn trước private store | `agent/policy.py:78`, `agent/policy.py:80`, `agent/runner.py:147`, `data/principals.json:2`, `reports/ledger.jsonl:2` | `--as` chọn fixture mô phỏng, chưa có authentication/credential OBO thật; cùng process, chưa có sandbox OS giữa run |
| OWASP ASI04 — Agentic Supply Chain Vulnerabilities | Lock toàn bộ dependency với hash; pin hook; scan history và HEAD; incident note có rotate | `.pre-commit-config.yaml:3`, `requirements.lock:1`, `reports/gitleaks-history.json:3`, `reports/secrets-incident.md:1` | Pin/hash không loại bỏ package độc hại, không kiểm model/MCP runtime, không thu hồi secret đã lộ |

Nguồn OWASP chính thức: [Top 10 for Agentic Applications 2026](https://genai.owasp.org/download/52117/?tmstv=1765059207),
ASI01 ở trang ghi số 9–11, ASI03 trang 15–17, ASI04 trang 18–20.
Các mapping trên là phân tích của bài làm; không sao chép toàn văn tài liệu OWASP.
Nguồn bản ký số để đối chiếu tiếp: [Luật 91](https://datafiles.chinhphu.vn/cpp/files/vbpq/2025/7/91qh.signed.pdf),
[NĐ 356](https://datafiles.chinhphu.vn/cpp/files/vbpq/2026/01/356-nd.signed.pdf),
[Luật AI 134](https://datafiles.chinhphu.vn/cpp/files/vbpq/2025/12/134-luat-qh.pdf).
