# 🔥 Hướng dẫn Stress Test — SecureVote E-Voting

## Mục đích

Stress test đánh giá khả năng chịu tải của hệ thống bỏ phiếu điện tử SecureVote khi có **hàng nghìn cử tri** đồng thời thực hiện đăng ký + bỏ phiếu. Mỗi virtual user sẽ chạy toàn bộ flow thực tế:

```
Blind Token → RSA Register (sync) → Unblind → ElGamal Encrypt → Submit Vote
```

---

## Yêu cầu

| Thành phần | Mô tả |
|---|---|
| Python 3.10+ | Đã cài đặt |
| Flask server | `app.py` đang chạy trên `localhost:5000` |
| Locust | `pip install locust` (đã có trong `requirements.txt`) |
| Election đã setup | Admin đã tạo Election + mở voting |

> **Lưu ý:** Stress test sử dụng endpoint **`/api/register/sync`** (không cần Celery/Redis). Toàn bộ xử lý RSA Blind Signature chạy trực tiếp trong Flask process.

---

## Các bước thực hiện

### Bước 1: Khởi động Flask server

```powershell
cd C:\E-voting-UI
python app.py
# hoặc: py app.py
```

Server sẽ chạy tại `http://localhost:5000`.

### Bước 2: Setup Election (nếu chưa có)

1. Truy cập `http://localhost:5000/login`
2. Đăng nhập Admin: **username** = `admin`, **password** = `admin`
3. Tạo Election mới với danh sách ứng viên (ví dụ: `Alice, Bob, Charlie`)
4. Nhấn **Open Voting** để chuyển sang trạng thái `voting`

> ⚠️ **Bắt buộc**: Election phải ở trạng thái **voting** thì stress test mới chạy được. Nếu không, mọi request `/api/vote` sẽ trả về lỗi `400`.

### Bước 3: Tạo 10.000 cử tri giả lập

```powershell
python seed_stress_voters.py
# hoặc: py seed_stress_voters.py
```

Script sẽ:
- Xóa toàn bộ voter có prefix `stress_voter_` cũ
- Tạo 10.000 voter mới: `stress_voter_0` → `stress_voter_9999`
- Mỗi voter có `secret_code` tương ứng: `secret_0` → `secret_9999`

Output mong đợi:
```
Đang xóa các voter stress cũ (nếu có)...
Đang tạo 10.000 voters cho stress test...
  Đã insert 1000/10000...
  ...
  Đã insert 10000/10000...
Hoàn tất tạo 10.000 stress_voter_xxx!
```

### Bước 4: Khởi động Locust

```powershell
# Cách 1: Gọi trực tiếp (nếu locust có trong PATH)
locust -f locustfile.py --host=http://localhost:5000

# Cách 2: Qua python module (nếu cách 1 báo lỗi "not recognized")
python -m locust -f locustfile.py --host=http://localhost:5000
```

Locust Web UI sẽ chạy tại **http://localhost:8089**.

### Bước 5: Cấu hình & chạy test

Truy cập `http://localhost:8089` và điền thông số:

| Tham số | Giá trị khuyến nghị | Mô tả |
|---|---|---|
| **Number of users** | `100` – `1000` | Tổng số cử tri đồng thời |
| **Ramp up** | `10` – `50` | Số user thêm mỗi giây |
| **Host** | `http://localhost:5000` | Đã điền sẵn |

Nhấn **START** để bắt đầu test.

---

## Các kịch bản test khuyến nghị

### 🟢 Kịch bản 1: Smoke Test (Nhẹ)
| Users | Ramp up | Thời gian |
|---|---|---|
| 10 | 2/s | 1 phút |

**Mục đích:** Kiểm tra flow hoạt động đúng trước khi tăng tải.

### 🟡 Kịch bản 2: Load Test (Trung bình)
| Users | Ramp up | Thời gian |
|---|---|---|
| 100 | 10/s | 3 phút |

**Mục đích:** Đánh giá hiệu năng bình thường của hệ thống.

### 🔴 Kịch bản 3: Stress Test (Nặng)
| Users | Ramp up | Thời gian |
|---|---|---|
| 500 – 1000 | 50/s | 5 phút |

**Mục đích:** Tìm giới hạn chịu tải, phát hiện bottleneck.

### ⚫ Kịch bản 4: Headless (Không cần UI)

```powershell
locust -f locustfile.py --host=http://localhost:5000 --headless -u 500 -r 50 --run-time 120s

# hoặc:
python -m locust -f locustfile.py --host=http://localhost:5000 --headless -u 500 -r 50 --run-time 120s
```

**Mục đích:** Chạy tự động, xuất kết quả ra terminal, phù hợp CI/CD.

---

## Cách đọc kết quả

### Tab Statistics

| Cột | Ý nghĩa |
|---|---|
| **# Requests** | Tổng số request đã gửi |
| **# Fails** | Số request thất bại |
| **Median (ms)** | Thời gian phản hồi trung vị |
| **95%ile (ms)** | 95% request nhanh hơn giá trị này |
| **99%ile (ms)** | 99% request nhanh hơn giá trị này |
| **Avg (ms)** | Thời gian phản hồi trung bình |
| **RPS** | Requests per second (throughput) |

### Các chỉ số đánh giá

| Mức độ | Median | 95%ile | Failure Rate |
|---|---|---|---|
| ✅ Tốt | < 500ms | < 1000ms | < 1% |
| ⚠️ Chấp nhận được | 500–1500ms | 1000–3000ms | 1–5% |
| ❌ Cần tối ưu | > 1500ms | > 3000ms | > 5% |

### Tab Charts

- **Total Requests per Second**: Throughput theo thời gian
- **Response Times**: Biểu đồ latency (median + 95th percentile)
- **Number of Users**: Đường cong ramp-up

### Tab Failures

Hiển thị chi tiết lỗi. Các lỗi thường gặp:

| Lỗi | Nguyên nhân | Cách xử lý |
|---|---|---|
| `Register failed: 400` | Election chưa ở trạng thái `voting` | Admin mở voting trước |
| `Register failed: 404` | Voter ID không tồn tại | Chạy lại `seed_stress_voters.py` |
| `Register failed: 403` | Sai secret code | Kiểm tra seed script |
| `Vote failed: 400` | Voting chưa mở hoặc dữ liệu thiếu | Kiểm tra trạng thái election |
| `Double vote detected (409)` | Voter đã bỏ phiếu rồi | Bình thường khi test lặp lại |
| `ConnectionError` | Server quá tải | Giảm số user hoặc ramp rate |

---

## Workflow chi tiết của mỗi Virtual User

```
┌─────────────────────────────────────────────────────────┐
│                   EVoterUser (Locust)                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. on_start()                                          │
│     └── Chọn random voter: stress_voter_{0..9999}       │
│     └── Load RSA + ElGamal public keys                  │
│                                                         │
│  2. full_voting_flow() [lặp lại liên tục]               │
│     │                                                   │
│     ├── Tạo token ngẫu nhiên                            │
│     ├── Blind token (RSA, local)                        │
│     │                                                   │
│     ├── POST /api/register/sync ◄── Đo thời gian       │
│     │   └── Server ký mù RSA → trả blind_signature     │
│     │                                                   │
│     ├── Unblind signature (local)                       │
│     │   └── Lấy credential hợp lệ                      │
│     │                                                   │
│     ├── Mã hóa phiếu ElGamal (local, 3 ứng viên)       │
│     │   └── Chọn random 1 ứng viên                      │
│     │                                                   │
│     ├── Tính HMAC cho packet                            │
│     │                                                   │
│     ├── POST /api/vote ◄── Đo thời gian                │
│     │   └── Server verify RSA + HMAC → lưu ballot      │
│     │                                                   │
│     └── Reset voter ID (chọn random mới)                │
│                                                         │
│     [Nghỉ 0.5 – 2 giây] → Lặp lại flow                 │
└─────────────────────────────────────────────────────────┘
```

---

## Tải kết quả

Từ Locust UI → Tab **Download Data**:
- **Download CSV**: Dữ liệu thô dạng bảng
- **Download Report**: Báo cáo HTML hoàn chỉnh (kèm biểu đồ)

---

## Lưu ý quan trọng

1. **SQLite Locking**: SQLite không tối ưu cho concurrent writes. Với > 200 users, có thể gặp `database is locked`. Đây là giới hạn của SQLite, không phải lỗi ứng dụng.

2. **Reset giữa các lần test**: Chạy lại `seed_stress_voters.py` để reset trạng thái voter về `registered` trước mỗi lần test mới.

3. **CPU-bound crypto**: RSA blind signature và ElGamal encryption tốn CPU. Trên máy yếu, tăng `wait_time` trong `locustfile.py` để giảm áp lực.

4. **Không cần Celery**: Stress test đã được cấu hình dùng `/api/register/sync` — xử lý trực tiếp trong Flask process, không cần Celery worker hay Redis.

5. **Double Vote (409)**: Khi nhiều user cùng chọn trùng `stress_voter_{idx}`, voter đầu tiên sẽ vote thành công, những lần sau sẽ nhận lỗi 409. Đây là hành vi bảo mật đúng — hệ thống chống double voting.
