# DPIA-lite — mô phỏng kỹ thuật trong lab

Ngày đánh giá: 12/10/2026. Phạm vi: repo cá nhân, `--mock`, dữ liệu tổng hợp,
localhost; không kết nối cloud, không API key, không xử lý PII thật.

1. **Dữ liệu và phân loại.** Corpus ticket là dữ liệu không tin cậy (`internal` tại
   search boundary), có thể chứa PII synthetic và prompt injection. Private store
   `data/customers.json` gồm customer ID, tên, CCCD, SĐT, STK, email, related_tickets;
   coi toàn bộ record là `restricted`. PII gate nhận diện bốn nhóm CCCD/SĐT/STK/email,
   không nhận diện tên người. Trên 120 câu test, 118/118 entity nhận diện đúng;
   precision = recall = 1.000, chỉ là kết quả trên test set này.

2. **Mục đích và principal.** Run A tổng hợp ticket (`summarize-tickets`). Run B
   tra khách liên quan để hỗ trợ (`support-reply`), chỉ cho dpo có scope phù hợp.
   `support_l1` chỉ search, không mở customers.json hoặc gọi read_customer.
   `billing` có thể search nhưng mục đích support-reply không hợp lệ nên không đọc
   trong workflow này. Unknown principal, purpose sai, scope thiếu, parent scope
   hẹp hơn hoặc TTL hết hạn đều deny. `--as` là lựa chọn fixture, không xác thực thật.

3. **Dòng dữ liệu và nơi đi.** A: `search_docs` → redact văn bản → mock summary;
   customer ID/URL/lệnh trong free text không đi vào B. Payload A → B chỉ là
   `TicketSelection(tuple[int, ...])` lấy từ tên file. B không có search hay egress:
   kiểm quyền trước khi mở file mapping tin cậy và kiểm lại trước mỗi read_customer;
   chỉ các khách có related_tickets khớp mới được chọn. C chỉ có scope http_post,
   không nhận corpus, dùng endpoint cố định `http://127.0.0.1:10024/reconcile`;
   policy restricted + egress luôn deny trước POST. Controller chỉ trả summary
   đã redact, không đưa private records vào LLM hoặc câu trả lời. Trong baseline
   chưa kiểm soát, chính endpoint localhost này nhận PII synthetic như evidence.

4. **Rủi ro, biện pháp và bằng chứng.**

   | Rủi ro | Biện pháp | Kết quả quan sát |
   |---|---|---|
   | Document giấu lệnh hoặc giả DPO để exfil | Typed boundary, scope tách A/B/C, PEP | 4 biến thể × 2 principal không POST; attack-after.log 0 byte |
   | Support hoặc delegation vượt quyền | Giao principal/agent/parent, purpose, TTL | ledger dòng 2 deny support read; test_obo và test_controls pass |
   | Customer chỉ xuất hiện trong free text | Map bằng filename ticket → related_tickets | test_split không gọi đọc KH-000777, vẫn đọc khách hợp lệ |
   | dpo đọc nạn nhân liên quan ticket rồi gửi ra ngoài | restricted + egress deny độc lập OBO | ledger dòng 27 deny POST, vẫn có read_customer allow dòng 6–26 |
   | PII sang context/log | Redact trước summarize; audit chỉ lưu args_hash | test_controls kiểm PII không vào summarize; ledger không chứa giá trị CCCD/SĐT/STK/email |
   | Sửa log cũ | SHA-256 hash chain, verify trước append | test_ledger sửa dòng cũ → False; chain evidence gốc → True |
   | Secret/dependency | Gitleaks pin, hash lock, incident note | 1 token giả trong history, current files sạch; không có credential thật |

5. **Lưu giữ và trách nhiệm.** File before cố ý chứa PII synthetic để TA kiểm
   baseline. File after rỗng; ledger chỉ chứa metadata và hash arguments. Không nộp
   sink.log hoặc .venv. Record riêng giữ trong bộ nhớ B/C trong một request, không
   ghi private record ra ledger. Bài chưa triển khai retention tự động, quyền xóa,
   export dữ liệu chủ thể, mã hóa lưu trữ hay quy trình thông báo sự cố production.

6. **Rủi ro còn lại và giới hạn.** Regex có thể bỏ sót PII viết lạ và chưa xử lý PERSON;
   mock summary chỉ liệt kê ticket, không chứng minh model thật an toàn. Các run là
   ranh giới capability trong một process, không sandbox OS và không chống code độc
   có quyền đọc file trực tiếp. Mapping tin cậy hiện nằm chung file với dữ liệu riêng;
   truy cập file đã được gate, nhưng production nên có index tối thiểu riêng/API có
   record-level authorization. TTL dùng đồng hồ máy, principal JSON không phải IdP.
   Hash chain không phát hiện cắt đuôi/rewrite toàn chuỗi nếu thiếu checkpoint tin cậy
   bên ngoài; hash args không phải mã hóa hoặc bảo đảm chống đoán dữ liệu ít entropy.
   Ledger ghi quyết định cho phép trước execution, không chứng minh tool hoàn thành.
   Pin/hash không chứng minh package vô hại. Đánh giá này không phải hồ sơ DPIA
   chính thức theo luật; điều khoản cụ thể chưa xác minh, xem compliance-mapping.md.
