package atmin;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity // Kích hoạt tính năng bảo mật web của Spring Security
public class SecurityConfig {

    @Bean // Khai báo Bean chính chịu trách nhiệm thiết lập các bộ lọc bảo mật
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
                // 1. PHÂN QUYỀN ĐƯỜNG DẪN (AUTHORIZATION)
                // Quản lý việc ai có quyền truy cập vào URL nào. Quy tắc chạy từ trên xuống, khớp cái nào trước thì áp dụng luôn.
                .authorizeHttpRequests(authorize -> authorize

                        // requestMatchers(): Nhắm mục tiêu đến các đường dẫn cụ thể.
                        // permitAll(): Không yêu cầu gì cả, ai cũng vào được.
                        // Thường dùng cho Trang chủ API, các API public (ví dụ: lấy danh sách sản phẩm hiển thị chung).
                        .requestMatchers("/", "/public/**").permitAll()

                        // hasRole("ADMIN"): Yêu cầu người gọi API phải có quyền ADMIN.
                        // Lưu ý: Spring tự động tìm quyền có dạng "ROLE_ADMIN". Nếu là "user" bình thường truy cập, sẽ bị chặn lại (Lỗi 403 Forbidden).
                        .requestMatchers("/admin/**").hasRole("ADMIN")

                        // anyRequest().authenticated(): Lưới lọc cuối cùng.
                        // Mọi API không được cấu hình ở 2 dòng trên đều bắt buộc người dùng phải gửi kèm thông tin đăng nhập hợp lệ (Lỗi 401 Unauthorized nếu chưa đăng nhập).
                        .anyRequest().authenticated()
                )

                // 2. CHỐNG TẤN CÔNG GIẢ MẠO (CSRF)
                // Đây là phần rất quan trọng cho API Server khi làm việc với Frontend (React, Vue, JS thuần).
                .csrf(csrf -> csrf
                        // Thay vì lưu token ở Session trên Server (khá tốn tài nguyên và khó scale), ta đẩy token về trình duyệt dưới dạng Cookie.
                        // withHttpOnlyFalse(): Cố tình tắt bảo mật HttpOnly của Cookie này để mã JavaScript ở Frontend có thể "đọc" được nó.
                        // Khi Frontend cần gọi các API thay đổi dữ liệu (POST, PUT, DELETE), nó sẽ đọc Cookie XSRF-TOKEN này và nhét vào HTTP Header có tên X-XSRF-TOKEN gửi lên Server để chứng minh yêu cầu hợp lệ.
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                )

                // 3. ĐĂNG NHẬP / ĐĂNG XUẤT
                // Kích hoạt form đăng nhập và cơ chế đăng xuất tích hợp sẵn của Spring.
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                .logout(LogoutConfigurer::permitAll);

        return http.build(); // Đóng gói cấu hình và trả về
    }

    // 4. QUẢN LÝ NGƯỜI DÙNG MẪU (IN-MEMORY USER)
    // Cung cấp dữ liệu tài khoản tạm thời trên RAM để test chức năng mà không cần kết nối Database.
    @Bean
    public UserDetailsService userDetailsService() {
        // Tạo tài khoản nhân viên thường
        UserDetails normalUser = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password")) // Mã hóa mật khẩu trước
                .roles("USER") // Spring tự động thêm prefix thành "ROLE_USER"
                .build();

        // Tạo tài khoản quản lý
        UserDetails adminUser = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("password"))
                .roles("ADMIN") // Spring tự động thêm prefix thành "ROLE_ADMIN"
                .build();

        return new InMemoryUserDetailsManager(normalUser, adminUser);
    }

    // 5. CÔNG CỤ MÃ HÓA MẬT KHẨU
    // Thuật toán để bảo vệ mật khẩu, biến chữ thường thành chuỗi hash không thể dịch ngược.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}