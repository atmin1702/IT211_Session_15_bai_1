### Phần 1: Phân tích logic cấu hình phân quyền hiện tại

Tài khoản `user` (không có quyền ADMIN) vẫn truy cập được `/admin/orders` sau khi đăng nhập do cấu hình `SecurityFilterChain` hiện tại gặp vấn đề về **phạm vi kiểm tra quyền**:

1. **Chỉ kiểm tra trạng thái đăng nhập (Authentication), bỏ qua vai trò (Authorization):** Cấu hình hiện tại sử dụng quy tắc bắt đáy `.anyRequest().authenticated()` ngay sau khi cấp quyền cho trang chủ. Lệnh `authenticated()` chỉ yêu cầu người dùng **có phiên đăng nhập hợp lệ**. Nó hoàn toàn không quan tâm người dùng đó mang Role gì (USER hay ADMIN).

2. **Thiếu quy tắc định tuyến cụ thể cho Admin:**
   Vì không có quy tắc `.requestMatchers("/admin/**").hasRole("ADMIN")` đứng trước lệnh bắt đáy, hệ thống không biết rằng các API này cần được bảo vệ ở cấp độ cao hơn.

**Kết luận:** Khi tài khoản `user` đăng nhập thành công, họ đã thỏa mãn điều kiện `.authenticated()` và được Spring Security mở cửa cho qua mọi đường dẫn còn lại, bao gồm cả `/admin/orders`.