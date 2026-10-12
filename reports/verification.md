# Verification — kết quả thực ngày 12/10/2026

Môi trường: Linux, Python **3.11.16** trong `.venv`, pytest **9.1.1**,
Gitleaks **8.30.1**, pre-commit **4.6.2**, pip-tools **7.6.2**.
Code và báo cáo có hỗ trợ AI; lệnh dưới đây đã thực chạy trong workspace của repo.

| Kiểm tra | Kết quả | Evidence |
|---|---|---|
| `python -m pytest tests/ -q --junitxml=reports/pytest.xml` | **43 passed in 0.57s**, exit 0, không fail/skip | `reports/test-results.txt:1`, `reports/pytest.xml:1`; 33 test gốc và 10 check bổ sung |
| `python -m pytest tests/test_pii.py -q -s` | gold=118, pred=118, tp=118; precision=1.000, recall=1.000; 2 passed | `reports/pii-metrics.txt:1`; scorer gốc ghép entity theo type và overlap offset |
| `python -m agent.check_lure 'corpus/ticket-90*.md'` | 4/4 lure SẴN SÀNG | `injection-corpus.md:1`; cặp 904 tính là một biến thể |
| Replay before | 4 biến thể riêng + query toàn corpus: **5 POST thật**, mỗi POST chứa synthetic KH-000999 | `reports/attack-before.log:1–5`, `reports/replay-before.json` |
| Replay after | **8/8** variant/principal không POST; query CLI gốc dpo sau pytest không POST; attack-after **0 byte** | `reports/replay-after.json`, `reports/attack-after.log`, `reports/ledger.jsonl:264` |
| `gitleaks version` | **8.30.1**, exit 0 | binary release chính thức, ghi trong secrets-incident.md |
| `gitleaks git --config .gitleaks.toml --redact --verbose .` | **exit 1 dự kiến**, đúng 1 finding synthetic lab24-synthetic-token tại 1bdd849 | `reports/gitleaks-history.json:3` |
| `gitleaks dir --config .gitleaks.toml --redact .` | exit 0, không finding | `reports/gitleaks-current.json:1` |
| `pre-commit run --all-files` | **Passed**, exit 0; pin hook v8.30.1, pass_filenames false | `.pre-commit-config.yaml:1`, `reports/precommit-results.txt` |
| `pip-compile --generate-hashes -o requirements.lock requirements.txt` | exit 0; 10 package pin, mỗi package có SHA-256 | `requirements.lock:1`; cache ngoài submission |
| `python -m pip install --require-hashes --force-reinstall -r requirements.lock` | exit 0; 10 package được reinstall và kiểm hash, không chỉ bỏ qua package đã cài | `requirements.lock`, `reports/dependency-install.txt` |
| `python -m pip check` | No broken requirements found; exit 0 | môi trường sau reinstall |
| `verify(Path('reports/ledger.jsonl'))` | **True**, 264 dòng; tất cả reason và metadata OBO đủ; không giá trị CCCD/SĐT/STK/email thô | `reports/evidence-summary.json`, `agent/ledger.py:100` |
| Sửa decision dòng 27 trên bản sao | verify **False**, chain gốc không thay đổi | `reports/ledger-tamper.json:1` |
| Xóa dòng cuối trên bản sao, không có anchor ngoài | verify **True**, giới hạn đã ghi nhận | `reports/ledger-tamper.json:5` |

Ledger giữ cả replay sau sửa đầu tiên (dòng 1–132) và replay sau full pytest cuối
(dòng 133–264). Tổng: search allow 18, read_customer allow 220 (gồm 10 lần gate
trusted index và 210 tool call), read_customer deny 8, http_post deny 18;
không có http_post allow. Các run có UUID riêng và TTL 5 phút. Audit reason completeness 100%.
Ledger ghi quyền trước execution; event `trusted_ticket_index` phân biệt việc mở
mapping private với các call `read_customer` thực tế.

Lỗi setup gặp và đã khắc phục: Python hệ thống 3.13 thiếu ensurepip, nên tạo venv
bằng Python 3.11.16 có sẵn; sandbox ban đầu chặn DNS và socket localhost, nên cài
dependency, fetch hook và chạy test/replay bằng các lệnh được cấp quyền phù hợp.
Lần pytest giữa chừng có lỗi socket và chưa có lock/incident note; full suite cuối
đã pass sau khi hoàn tất. Pip báo cache mặc định không ghi được trong sandbox và
pip-tools cảnh báo thay default --strip-extras trong phiên bản sau, không làm lệnh thất bại.

Không còn lỗi test hoặc scanner hiện tại. Finding history exit 1 là evidence đúng
đề bài, không phải secret thật. Điều khoản pháp luật cụ thể **chưa xác minh**;
metadata văn bản đã đối chiếu nguồn chính thức, không tuyên bố tuân thủ production.
Mock, giả lập principal, regex và giới hạn hash chain được nêu trong DPIA-lite.
Không sửa các test bắt buộc; không nới allowlist localhost; không dùng --no-verify.

Theo yêu cầu người dùng, tất cả thay đổi chỉ ở local, **không stage/commit/push**.
Lệnh staging và cài hook đã hoàn tất trước khi nhận yêu cầu này; đã undo staging
và uninstall hook, không sửa nội dung file. Staging area hiện rỗng.
Hook vẫn có file cấu hình và kết quả `pre-commit run --all-files` Passed.
Các log bị ignore (`attack-before.log`, `attack-after.log`, `ledger.jsonl`) vẫn
tồn tại trên disk và được đưa trực tiếp vào ZIP; không cần `git add` để lấy file.
Không nộp `.venv/` hoặc `reports/sink.log`. Không tạo SHA commit mới; HEAD gốc là
`52b33b5`. Handoff ghi đầy đủ SHA nguồn, hướng dẫn khôi phục history gốc và áp dụng
các file local. Git bundle chỉ chứa history sẵn có, ZIP chứa nội dung bài làm local.
