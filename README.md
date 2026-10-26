# Cloudflare Alert

Bot theo dõi Cloudflare Firewall/Analytics cho zone `g-pay.vn`, tự động phát hiện bất thường và gửi cảnh báo qua Telegram. Có thể block IP trực tiếp từ Telegram (thêm vào Cloudflare IP List) thông qua nút bấm trên tin nhắn.

Helm chart deploy: `charts/devops/cloudflare-alert` (repo `applications`).

## Kiến trúc

`monitor.py` chạy 5 vòng lặp song song (`asyncio.gather` trong `main()`):

1. **`poll_loop`** — mỗi `POLL_INTERVAL` giây (mặc định 120s), chạy đồng thời 3 check: `[ATTACK]`, `[MERCHANT]`/`[WATCH IP]`, `[499]`.
2. **`referer_scan_loop`** — chạy độc lập, 1 lần/ngày vào đúng giờ `REFERER_SCAN_TIME`, quét `[REFERER]` trong 24h gần nhất.
3. **`telegram_callback_loop`** — long-poll Telegram `getUpdates` để nhận sự kiện bấm nút "🚫 Block" / "🔓 Unblock" trên các alert và lệnh `/auto`, `/manual`, `/mode`.
4. **`cleanup_scan_loop`** — chạy độc lập, 1 lần/ngày vào giờ `BLOCK_CLEANUP_TIME`, dọn IP hết hạn khỏi `BLOCK_IP_LIST`.
5. **`sandbox_whitelist_scan_loop`** — chạy độc lập, 1 lần/ngày vào giờ `SANDBOX_WHITELIST_SCAN_TIME`, báo cáo IP whitelist sandbox không còn hoạt động.

State lưu in-memory (mất khi pod restart): cooldown alert (`last_alert_time`), cache merchant IP (`merchant_ips`), cache tên↔ID của Cloudflare IP List, chế độ block hiện tại (`block_mode`).

## Các loại alert

| Alert | Điều kiện trigger | Chat | Nút Block |
|---|---|---|---|
| **`[ATTACK]`** | (a) Tổng blocked requests trong 1 chu kỳ poll ≥ `BLOCK_THRESHOLD` (burst nhanh), **hoặc** (b) 1 IP bị block cộng dồn ≥ `DAILY_BLOCK_THRESHOLD` trong 24h gần nhất (bắt kiểu tấn công chậm/lặp lại không đủ burst mỗi cửa sổ) — cả 2 đều loại trừ `source=firewallCustom`, và không alert nếu toàn bộ chỉ là Rate Limiting (INFO) | `TELEGRAM_CHAT_ID` | Có (Block hoặc Unblock tuỳ `BLOCK_MODE`) |
| **`[MERCHANT]`** | IP nằm trong 1 trong các Cloudflare IP List merchant (`MERCHANT_IP_LISTS`) mà bị block — bất kể lý do, bất kể host | `MERCHANT_ALERT_CHAT_ID` | Không |
| **`[WATCH IP]`** | IP nằm trong `WATCH_IPS` (không phải merchant) mà bị block | `WATCH_IP_ALERT_CHAT_ID` | Không |
| **`[REFERER]`** | Quét toàn bộ traffic (không riêng traffic bị block) 1 lần/ngày; referer nào không thuộc `ALLOWED_REFERER_DOMAINS` (kể cả subdomain) → liệt kê vào digest | `REFERER_ALERT_CHAT_ID` | Không |
| **`[499]`** | Với từng domain trong `STATUS_499_HOSTS`: số request `edgeResponseStatus=499` trong 1 chu kỳ poll ≥ `STATUS_499_THRESHOLD` | `MERCHANT_ALERT_CHAT_ID` | Không |
| **`[CLEANUP]`** | 1 lần/ngày; IP trong `BLOCK_IP_LIST` đã block đủ `BLOCK_CLEANUP_LOOKBACK_DAYS` ngày và không bị chặn lần nào suốt khoảng đó → bị xoá | `CLEANUP_ALERT_CHAT_ID` | Không |
| **`[SANDBOX WHITELIST]`** | 1 lần/ngày; IP trong `SANDBOX_WHITELIST_LIST` đã whitelist đủ `SANDBOX_WHITELIST_LOOKBACK_DAYS` ngày và không gọi domain nào trong `SANDBOX_WHITELIST_HOSTS` suốt khoảng đó → **chỉ báo cáo**, không tự xoá | `SANDBOX_WHITELIST_ALERT_CHAT_ID` | Không |

Mỗi loại/key (vd từng IP, từng domain 499) có cooldown riêng `ALERT_COOLDOWN` giây, tránh spam lặp lại liên tục.

`[ATTACK]` tính cooldown **theo từng IP tấn công**: IP nào chưa được alert trong `ALERT_COOLDOWN` giây thì alert ngay (tin chỉ gồm các IP mới), IP đã alert gần đây thì bỏ qua. Ở chế độ `auto`, IP đã block bị chặn bởi custom rule (`firewallCustom`, đã loại khỏi query) nên không xuất hiện lại.

**2 nguồn phát hiện IP tấn công, độc lập nhau:**
- **Burst** — khi tổng blocked trong 1 chu kỳ poll ≥ `BLOCK_THRESHOLD`, lấy top 5 IP theo tổng request thật của riêng IP đó (query ranking group **chỉ theo `clientIP`**, không group kèm path/UA/method — tránh bug 1 IP rải traffic qua nhiều path bị vỡ vụn thành nhiều dòng nhỏ, mỗi dòng không đủ lọt top 5 dù tổng IP đó rất lớn).
- **Cộng dồn 24h** — mọi IP bị block trong mỗi cửa sổ poll đều được cộng dồn vào lịch sử riêng (tính theo 24h gần nhất, tự dọn record cũ hơn), bất kể chu kỳ đó có đạt `BLOCK_THRESHOLD` hay không. IP nào cộng dồn đủ `DAILY_BLOCK_THRESHOLD` (hardcode = 20, không qua Helm) thì vẫn trigger alert, dù không cửa sổ 60s riêng lẻ nào đủ `BLOCK_THRESHOLD` — bắt được kiểu tấn công chậm/lặp lại (vd 1 IP chỉ bắn vài request mỗi giờ).
- Dù qua nguồn nào, IP đều phải qua đúng 1 query chi tiết riêng (group theo path/UA cho đúng IP đó) để lấy dữ liệu hiển thị (path, UA, severity) trước khi đưa vào alert.

### Sửa nội dung/format alert

Nội dung từng loại alert nằm trong file Jinja2 ở thư mục `templates/` (đóng gói cùng Docker image, không cần build lại code Python để sửa chữ):

| File | Alert |
|---|---|
| `templates/attack.html` | `[ATTACK]` |
| `templates/merchant.html` | `[MERCHANT]` |
| `templates/watch_ip.html` | `[WATCH IP]` |
| `templates/referer_entry.html` | 1 block domain trong `[REFERER]` |
| `templates/referer_header.html` | Header đầu tin/tin tiếp theo của `[REFERER]` |
| `templates/referer_footer.html` | Dòng link dashboard cuối `[REFERER]` |
| `templates/status499.html` | `[499]` |
| `templates/cleanup.html` | `[CLEANUP]` |
| `templates/sandbox_whitelist.html` | `[SANDBOX WHITELIST]` |

Logic tính toán (group IP, gộp domain vào trang, rút gọn prefix path, threshold...) vẫn nằm trong `monitor.py` — chỉ phần chữ/HTML hiển thị nằm trong template. Sửa xong nhớ build lại Docker image (template được `COPY` vào image, không mount runtime).

### Merchant IP whitelist

- `MERCHANT_IP_LISTS`: danh sách tên Cloudflare IP List coi là IP hợp lệ của merchant (vd `merchant_ips,merchant_ips_to_openapi`). Cache refresh mỗi `MERCHANT_CACHE_REFRESH_INTERVAL` giây.
- `MERCHANT_LIST_ALLOWED_HOSTS`: mapping list → domain khai báo, chỉ để **hiển thị thêm thông tin** trong alert (vd IP thuộc `merchant_ips` mà bị block ở domain khác domain khai báo vẫn alert bình thường — không dùng để lọc).
- Dòng trạng thái merchant trong alert (`merchant_status_line`) còn hiện kèm `comment` của item trên Cloudflare List (thường là tên merchant, vd `F2FGPAY`), lấy trực tiếp lúc refresh cache — không cần tra lại trên dashboard.
- IP thuộc merchant list sẽ **không** bao giờ có nút Block (dù xuất hiện ở `[ATTACK]`).

### Referer allowlist

`check_suspicious_referers` quét **toàn bộ HTTP traffic** (`httpRequestsAdaptiveGroups`, không lọc theo `action: block`) vì domain lạ dẫn traffic vào không nhất thiết bị WAF chặn. Referer nào không khớp `ALLOWED_REFERER_DOMAINS` (so khớp domain hoặc subdomain) bị coi là đáng ngờ.

Digest hàng ngày gộp nhiều domain vào ít tin nhắn nhất có thể (không cắt domain nào giữa chừng, luôn ≤ 4096 ký tự/tin — giới hạn của Telegram), tự động chia nhiều tin nếu cần.

### Block / Unblock IP qua Telegram

Có 2 chế độ block cho `[ATTACK]`:

| Chế độ | Hành vi |
|---|---|
| `auto` | Khi gửi `[ATTACK]`, tự động thêm **tất cả** IP trong alert vào `BLOCK_IP_LIST` (mọi severity, trừ merchant IP và `WATCH_IPS`). Mỗi IP có dòng `🔒 Đã tự động block`, kèm nút "🔓 Unblock {ip}". |
| `manual` | Như cũ: nút "🚫 Block {ip}". Block xong có thêm nút "🔓 Unblock {ip}", Unblock xong lại có nút "🚫 Block {ip}" để đảo lại. |

- Chế độ khi khởi động lấy từ `BLOCK_MODE` (mặc định `auto`); bot gửi tin báo chế độ mỗi lần khởi động.
- Đổi lúc chạy (không cần deploy) bằng lệnh trong chat `TELEGRAM_CHAT_ID`: `/auto`, `/manual`; xem chế độ: `/mode`. Chế độ đổi bằng lệnh lưu in-memory — pod restart quay về `BLOCK_MODE`.
- Unblock = xoá IP khỏi `BLOCK_IP_LIST`. IP đã unblock mà tiếp tục bị chặn thì lần sau vẫn bị auto block bình thường.
- IP đã nằm trong `BLOCK_IP_LIST` bị chặn bởi custom rule (`firewallCustom`) — nguồn này đã bị loại khỏi query nên IP đã block không xuất hiện lại trong alert.
- Block, Unblock và đổi chế độ chỉ dành cho user trong `ALLOWED_BLOCK_USERS` (username Telegram, để trống = không giới hạn).
- Thao tác trên Cloudflare List là bất đồng bộ, có poll trạng thái tối đa 40s. Auto block gửi tất cả IP trong 1 lần nên chỉ chờ 1 lần.
- Nếu bot bật privacy mode trong group, lệnh `/auto` không kèm tên bot có thể không tới được bot — dùng `/auto@<tên_bot>` hoặc cho bot làm admin group.

### Dọn IP hết hạn khỏi block list (`[CLEANUP]`)

`BLOCK_IP_LIST` không tự giới hạn dung lượng — IP auto-block tích luỹ liên tục có thể chạm quota IP Lists của tài khoản Cloudflare (số list và tổng số item/list). `cleanup_scan_loop` chạy 1 lần/ngày để dọn bớt:

1. IP nào đã nằm trong `BLOCK_IP_LIST` đủ `BLOCK_CLEANUP_LOOKBACK_DAYS` ngày (tính từ `created_on` của Cloudflare List item, mốc tuổi tối thiểu) → đưa vào diện xét xoá. Áp dụng cho **cả IP auto-block lẫn block thủ công**. IP chưa đủ tuổi thì bỏ qua.
2. Với các IP đã đủ tuổi, kiểm tra còn **gọi đến hay không** trong đúng `BLOCK_CLEANUP_LOOKBACK_DAYS` ngày đó — dùng dataset Traffic (`httpRequestsAdaptiveGroups`, toàn bộ HTTP traffic), không phân biệt request đó có khớp đúng rule block hay không: đã nằm trong `BLOCK_IP_LIST` tức đã xác định vi phạm, chỉ cần biết còn hoạt động hay đã im hẳn. Dùng Traffic thay vì Events (`firewallEventsAdaptiveGroups`) vì Events bị Cloudflare giới hạn cứng mỗi query tối đa 1 ngày và không query được dữ liệu cũ hơn 3 ngày (phát hiện thực tế từ production); Traffic không bị giới hạn này (đã verify qua API thật), nên query được nguyên `BLOCK_CLEANUP_LOOKBACK_DAYS` ngày trong 1 lần. Còn hoạt động → giữ nguyên; không có hoạt động nào → xoá khỏi `BLOCK_IP_LIST`.
3. Lỗi query hoặc không query được coi là "vẫn còn active" (không xoá) — ưu tiên an toàn, tránh unblock nhầm IP đang tấn công.
4. Có IP bị xoá → gửi digest ngắn liệt kê các IP vào `CLEANUP_ALERT_CHAT_ID` (mặc định fallback `TELEGRAM_CHAT_ID`). Không có IP nào đủ điều kiện → chỉ log, không gửi tin.
5. `BLOCK_CLEANUP_LOOKBACK_DAYS <= 0` → tắt hẳn tính năng này.

### Báo cáo IP whitelist sandbox không hoạt động (`[SANDBOX WHITELIST]`)

Cloudflare IP List `SANDBOX_WHITELIST_LIST` (mặc định `merchant_ips_to_sandbox_api`) whitelist IP merchant được gọi vào các domain sandbox. List này được quản lý qua **Terragrunt/git** (không phải chỉ qua Cloudflare dashboard), nên bot **không tự xoá** — tự gọi API xoá sẽ bị lần `terragrunt apply` tiếp theo ghi đè lại (Terraform coi là drift rồi thêm lại IP), 2 cơ chế sẽ giẫm chân nhau. `sandbox_whitelist_scan_loop` chạy 1 lần/ngày, **chỉ báo cáo**:

1. IP nào đã nằm trong list đủ `SANDBOX_WHITELIST_LOOKBACK_DAYS` ngày (tính từ `created_on`, mốc tuổi tối thiểu) → đưa vào diện xét. IP mới whitelist (merchant chưa kịp gọi thử) thì bỏ qua, tránh báo nhầm.
2. Với IP đã đủ tuổi, kiểm tra có gọi tới bất kỳ domain nào trong `SANDBOX_WHITELIST_HOSTS` trong đúng khoảng đó không (dùng Traffic, lọc theo cả IP lẫn host — khác `[CLEANUP]` ở chỗ phải lọc đúng domain sandbox, không phải "gọi bất kỳ đâu").
3. IP nào không gọi domain sandbox nào → liệt kê vào digest gửi `SANDBOX_WHITELIST_ALERT_CHAT_ID`, kèm comment (thường là tên merchant) để dễ xác định. Người nhận tự quyết định có gỡ hay không, và gỡ đúng qua Terraform.
4. Không có IP nào đủ điều kiện → chỉ log, không gửi tin.
5. `SANDBOX_WHITELIST_LOOKBACK_DAYS <= 0` hoặc `SANDBOX_WHITELIST_HOSTS` rỗng → tắt hẳn tính năng này.

## Cấu hình (biến môi trường)

### Bắt buộc

| Biến | Mô tả |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cần quyền đọc GraphQL Analytics + quyền ghi Account Rules Lists (để block IP) |
| `ZONE_ID` | Zone ID của `g-pay.vn` |
| `ACCOUNT_ID` | Account ID Cloudflare (dùng cho IP Lists API) |
| `TELEGRAM_BOT_TOKEN` | Token bot Telegram |
| `TELEGRAM_CHAT_ID` | Chat mặc định (`[ATTACK]`, và fallback cho các chat riêng chưa cấu hình) |

### Chat riêng theo loại alert (tùy chọn, mặc định fallback về `TELEGRAM_CHAT_ID`)

| Biến | Alert dùng | Nhóm Telegram (production) |
|---|---|---|
| `TELEGRAM_CHAT_ID` | `[ATTACK]`, và fallback cho các biến dưới khi chưa cấu hình | CF Alert (blocked - Infosec) |
| `MERCHANT_ALERT_CHAT_ID` | `[MERCHANT]`, `[499]` | CF Alerts (499 & merchant blocked) |
| `WATCH_IP_ALERT_CHAT_ID` | `[WATCH IP]` | chưa cấu hình (rỗng — `WATCH_IPS` cũng đang để trống) |
| `REFERER_ALERT_CHAT_ID` | `[REFERER]` | CF Ref Alert (referer) |
| `CLEANUP_ALERT_CHAT_ID` | `[CLEANUP]` | tuỳ chọn, riêng cho thông báo dọn block list |
| `SANDBOX_WHITELIST_ALERT_CHAT_ID` | `[SANDBOX WHITELIST]` | tuỳ chọn, riêng cho báo cáo whitelist sandbox |

Giá trị thật (token, chat ID) nằm trong Helm `secret.yaml`/`values-production.yaml` ở repo `applications`, không đưa vào đây.

### Ngưỡng & chu kỳ

| Biến | Mặc định | Mô tả |
|---|---|---|
| `POLL_INTERVAL` | `120` | Chu kỳ (giây) cho `[ATTACK]`, `[MERCHANT]`, `[WATCH IP]`, `[499]` |
| `ALERT_COOLDOWN` | `600` | Thời gian chờ tối thiểu giữa 2 lần alert cùng key (giây) |
| `BLOCK_THRESHOLD` | `100` | Ngưỡng blocked requests/chu kỳ để trigger `[ATTACK]` |
| `STATUS_499_THRESHOLD` | `0` (tắt) | Ngưỡng request 499/chu kỳ để trigger `[499]` |
| `STATUS_499_HOSTS` | rỗng (tắt) | Danh sách domain theo dõi 499, cách nhau bằng dấu phẩy — domain khác bị bỏ qua |
| `REFERER_SCAN_TIME` | `17:00` | Giờ VN (HH:MM) quét `[REFERER]` 1 lần/ngày |
| `MERCHANT_CACHE_REFRESH_INTERVAL` | `300` | Chu kỳ làm mới cache merchant IP (giây) |
| `BLOCK_CLEANUP_LOOKBACK_DAYS` | `7` | IP phải block đủ số ngày này mới xét xoá, và cũng là cửa sổ kiểm tra "còn hoạt động không" trước khi xoá khỏi `BLOCK_IP_LIST`; `<=0` = tắt |
| `BLOCK_CLEANUP_TIME` | `03:00` | Giờ VN (HH:MM) chạy dọn `BLOCK_IP_LIST` 1 lần/ngày |
| `SANDBOX_WHITELIST_LOOKBACK_DAYS` | `30` | IP phải whitelist đủ số ngày này mới xét báo cáo, và cũng là cửa sổ kiểm tra còn gọi domain sandbox không; `<=0` = tắt |
| `SANDBOX_WHITELIST_SCAN_TIME` | `09:00` | Giờ VN (HH:MM) chạy báo cáo `[SANDBOX WHITELIST]` 1 lần/ngày |

### Danh sách / whitelist

| Biến | Mô tả |
|---|---|
| `WATCH_IPS` | IP cần theo dõi riêng, cách nhau bằng dấu phẩy |
| `ALLOWED_REFERER_DOMAINS` | Domain hợp lệ cho referer (kể cả subdomain), cách nhau bằng dấu phẩy |
| `REFERER_HOSTS` | Chỉ quét `[REFERER]` trên các host này, cách nhau bằng dấu phẩy. **Rỗng = quét tất cả host** |
| `MERCHANT_IP_LISTS` | Tên các Cloudflare IP List coi là merchant, cách nhau bằng dấu phẩy |
| `MERCHANT_LIST_ALLOWED_HOSTS` | Mapping hiển thị: `list1:host1\|host2,list2:host3` |
| `BLOCK_IP_LIST` | Tên Cloudflare IP List dùng khi bấm nút Block (mặc định `block_ips`) |
| `ALLOWED_BLOCK_USERS` | Username Telegram được phép Block/Unblock và đổi chế độ block, cách nhau bằng dấu phẩy (rỗng = không giới hạn) |
| `BLOCK_MODE` | Chế độ block khi khởi động: `auto` (mặc định) hoặc `manual` |
| `SANDBOX_WHITELIST_LIST` | Tên Cloudflare IP List whitelist merchant sandbox (mặc định `merchant_ips_to_sandbox_api`) |
| `SANDBOX_WHITELIST_HOSTS` | Domain sandbox dùng để check IP còn gọi đến không, cách nhau bằng dấu phẩy. **Rỗng = tắt tính năng** |

## Chạy local

```bash
pip install -r requirements.txt
export CLOUDFLARE_API_TOKEN=... ZONE_ID=... ACCOUNT_ID=... TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=...
python monitor.py
```

Log in ra stdout, cần chạy Python **unbuffered** để log lên real-time khi chạy trong container (Docker image đã set sẵn `ENV PYTHONUNBUFFERED=1`).

## Lưu ý khi vận hành

- State (cooldown, cache) chỉ lưu in-memory — pod restart sẽ mất, có thể gây alert lặp lại hoặc tạm thời không nhận diện được merchant IP trong vài giây đầu (đã có `ensure_merchant_cache` tự refresh khi cần).
- `CLOUDFLARE_API_TOKEN` cần đủ quyền **Account → Rules Lists: Edit** thì nút Block mới hoạt động được, ngoài quyền đọc GraphQL Analytics.
- Đổi tên Cloudflare IP List (merchant list, block list) thì chỉ cần sửa giá trị trong Helm values, không cần sửa code hay build lại image.
