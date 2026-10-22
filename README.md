# Locket Gold VIP 2099 & Web Uploader (Bypass 10s/15MB)

Hệ thống trọn gói mở khóa Locket Gold VIP (vĩnh viễn 2099) và công cụ đăng video không giới hạn dung lượng/thời lượng lên Locket Camera.

---

## 📁 Cấu Trúc Dự Án

- `index.html`: Giao diện Web Portal (SPA) tích hợp bộ phân giải nhị phân MP4, Firebase Auth & Video Uploader.
- `server.py`: Unified Backend Core (DoH DNS-over-HTTPS Resolver, HTTPS MITM Mock API cho RevenueCat & Firebase Remote Config, cấp profile `.mobileconfig`).
- `certs.py`: Quản lý PKI tự động (sinh Root CA X.509 và Server TLS Cert đa domain).
- `status.json`: Cơ sở dữ liệu đồng bộ người dùng kích hoạt, tokens và endpoint tunnel.
- `start.bat`: Script khởi động 1-click trên Windows.
- `Dockerfile` & `docker-compose.yml`: Triển khai máy chủ Linux / VPS bằng Docker.

---

## 🚀 Hướng Dẫn Vận Hành

### Cách 1: Khởi động trên Windows
1. Nhấp đúp vào `start.bat` (hoặc mở Terminal chạy: `python server.py`).
2. Mở trình duyệt truy cập `http://localhost` hoặc IP mạng LAN hiển thị trên bảng console.

### Cách 2: Triển khai bằng Docker
```bash
docker compose up -d --build
```

---

## 📱 Các Bước Cài Đặt Trên iPhone (iOS)

1. Mở trình duyệt **Safari** trên iPhone và truy cập địa chỉ IP máy chủ của bạn (hoặc link GitHub Pages).
2. Dán link Locket hoặc nhập `@username` để kích hoạt và nhấn **"Tải Cấu Hình DNS Ngay"**.
3. Vào **Cài đặt (Settings)** -> Chọn **"Đã tải về hồ sơ"** -> Nhấn **Cài đặt**.
4. Vào **Cài đặt** -> **Cài đặt chung (General)** -> **Giới thiệu (About)** -> Cuộn xuống chọn **"Cài đặt tin cậy chứng nhận" (Certificate Trust Settings)**.
5. Gạt **BẬT XANH** chứng chỉ **"Locket Gold Root CA"** -> Chọn **Tiếp tục**.
6. Vuốt tắt hẳn ứng dụng Locket và mở lại. Huy hiệu Gold và toàn bộ tính năng VIP sẽ tự động kích hoạt!
