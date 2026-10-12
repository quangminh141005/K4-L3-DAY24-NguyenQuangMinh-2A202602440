# Sự cố token giả trong lịch sử Git — checkpoint 4

Scanner thực chạy: **Gitleaks 8.30.1**, binary từ release chính thức
<https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1>.

Lệnh `gitleaks git --config .gitleaks.toml --redact --verbose --report-format json --report-path reports/gitleaks-history.json .`
trả **exit code 1, đúng 1 finding**, rule **lab24-synthetic-token**.
Evidence: `reports/gitleaks-history.json:3` (rule), dòng 11 (file), dòng 13 (commit), dòng 21 (fingerprint).
Commit chứa token: **1bdd849922156c868a5ee9293d68f5b72e242d2c** (`1bdd849`), file `lab-fake-secret.txt`, dòng 1.
Đây là token `LAB24-DEMO` giả, vô hiệu, chủ đích do đề bài cài sẵn; không phải credential thật.
File bị xóa ở commit `ece6ca4`; lịch sử được giữ nguyên để TA tái hiện finding.

Lệnh `gitleaks dir --config .gitleaks.toml --redact --report-format json --report-path reports/gitleaks-current.json .`
trả **exit code 0, không finding**; `reports/gitleaks-current.json:1` là mảng rỗng.
Các báo cáo scanner đã redact, không chép token nguyên văn vào HEAD.

Nếu credential là thật: thu hồi/rotate tại nhà cung cấp ngay; khóa phiên/token dẫn xuất,
điều tra việc sử dụng trái phép và phạm vi ảnh hưởng, thông báo theo quy trình áp dụng,
cập nhật secret mới qua secret manager, rồi xử lý lịch sử/cache/fork theo kế hoạch phối hợp.
Xóa file ở HEAD hoặc rewrite Git không làm credential đã phát hành mất hiệu lực.
Với fixture vô hiệu này không có dịch vụ thật để rotate; giữ bằng chứng redacted và không dùng token.

`.pre-commit-config.yaml:3` pin tag `v8.30.1`, dùng hook chính thức `gitleaks-system`;
dòng 6 đổi entry sang quét directory hiện tại và dòng 7 đặt `pass_filenames: false`.
Nếu dùng entry quét lịch sử, finding cài sẵn sẽ làm hook luôn fail; kiểm lịch sử được chạy riêng và giữ bằng chứng.
`pre-commit run --all-files` đã chạy thành công với binary 8.30.1 trong PATH.

`requirements.lock` được sinh bằng `pip-compile --generate-hashes` từ `requirements.txt`,
pin cả dependency trực tiếp và bắc cầu; `pip install --require-hashes` kiểm tính toàn vẹn artifact khi cài.
Pin/hash giảm drift và thay thế artifact; scanner phát hiện một số mẫu secret.
Cả hai không thu hồi credential, không chứng minh package an toàn, và không thay thế đánh giá dependency.
