# WEB SERVER ATTACK TECHNIQUES AND DEFENSES

**Author:** Huynh Quoc Huy
**Course:** System Safety & Network Security
**Date:** August 2025

---

## 1. OVERVIEW AND FOUNDATIONAL CONCEPTS

### 1.1. Core Concepts of Information Security

The **CIA Triad** (Confidentiality, Integrity, Availability) remains the bedrock of information security, defining the three primary goals of any security strategy [1, 8]. 

| Principle | Description | Violation Example |
| :--- | :--- | :--- |
| **Confidentiality** | Protecting information from unauthorized access or disclosure. | A successful **SQL Injection** attack revealing user passwords and emails [3, 4]. |
| **Integrity** | Ensuring data is accurate, complete, and protected against unauthorized modification or destruction. | An attacker **deleting or altering** database records via SQLi [5, 6]. |
| **Availability** | Guaranteeing authorized users can access systems, applications, and data when needed. | **DoS/DDoS attacks** overwhelming the server and causing service outages [7, 48]. |

**Four Supplementary Properties:** Modern security concepts also include **Authenticity** (ensuring legal access), **Reliability** (error-free system operation), **Accountability** (tracking user actions), and **Non-repudiation** (proof that an action occurred, often via logging) [8].

### 1.2. Cyber Kill Chain Model

Developed by Lockheed Martin, the Cyber Kill Chain model systematically describes the path an attacker takes to compromise a target, providing a framework for multi-layered defense [11, 12].

| Stage | Description | Defense Strategy Example |
| :--- | :--- | :--- |
| 1. **Reconnaissance** | Gathering information about the target, vulnerabilities, and weaknesses (e.g., system scanning). | **IDS/IPS, Network Segmentation.** |
| 2. **Weaponization** | Creating customized attack tools (malware + exploit payload). | **Antivirus/Endpoint Protection.** |
| 3. **Delivery** | Transmitting the weapon to the target (e.g., phishing emails, compromised websites). | **Email Filters, Web Application Firewalls (WAF).** |
| 4. **Exploitation** | Triggering the exploit to gain control of the system. | **WAF, Patch Management.** |
| 5. **Installation** | Installing backdoors or persistent access mechanisms. | **Endpoint Detection and Response (EDR).** |
| 6. **Command and Control (C2)** | Establishing remote communication to send commands and exfiltrate data. | **Firewall Egress Filtering, Network Monitoring.** |
| 7. **Actions on Objectives** | Achieving the final goal (data theft, system destruction, ransomware). | **Data Loss Prevention (DLP), Automated Incident Response.** |

### 1.3. Overview of Common Web Vulnerabilities (OWASP Top 10)

The OWASP Top 10 list serves as a standard awareness document for developers to focus on the most critical web application security risks [1, 20].

| OWASP 2021 Category | Focus and Trend (2025) |
| :--- | :--- |
| **A01: Broken Access Control** | **(Rank 1)** Failure to enforce user permissions, allowing unauthorized function or data access. The top critical risk [1, 4]. |
| **A02: Cryptographic Failures** | Focuses on poor cryptographic practices leading to sensitive data exposure. |
| **A03: Injection** | Still a persistent threat (SQLi, XSS). Trend shows increased attacks targeting NoSQL, AI model prompts, and container environments [31]. |
| **A04: Insecure Design** | **(New Category)** Emphasizes the need for security architecture and threat modeling from the start [1]. |
| **A06: Vulnerable and Outdated Components** | Increased risk due to reliance on unpatched third-party libraries [1]. |
| **A09: Security Logging and Monitoring Failures** | Lack of visibility into security events, severely hindering incident detection and response [1]. |

---

## 2. WEB SERVER ATTACK TECHNIQUES

### 2.1. SQL Injection (SQLi)

SQL Injection is an attack technique that exploits input validation flaws to execute arbitrary SQL queries against a database [33, 36].

#### Attack Types:

| Type | Description | Example Payload |
| :--- | :--- | :--- |
| **In-band (Union-based)** | Uses the same channel for attack and results. | `' UNION SELECT username, password FROM users--` |
| **Error-based** | Uses database error messages to infer data structure. | `' AND (SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT @@version), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--` |
| **Blind (Boolean-based)** | Infers data by observing subtle changes in page content (True/False). | `' AND (SELECT SUBSTRING(@@version,1,1))='5'--` |
| **Blind (Time-based)** | Infers data by observing the time taken for the server to respond. | `' AND IF((SELECT SUBSTRING(@@version,1,1))='5', SLEEP(5), NULL)--` |

#### Defense Measures:

1.  **Prepared Statements (Parameterized Queries):** The most effective defense. Separates the SQL command from user data, preventing the user input from being executed as code.
2.  **Input Validation:** Strict whitelist filtering for allowed input data types and formats.
3.  **Principle of Least Privilege:** Database accounts used by the application should only have necessary permissions (avoiding `admin` or `DROP TABLE` rights).

### 2.2. Cross-Site Scripting (XSS)

XSS allows an attacker to inject malicious client-side scripts (usually JavaScript) into a legitimate web page, which then executes in the victim's browser [34, 49].

#### Attack Types:

| Type | Description |
| :--- | :--- |
| **Reflected XSS** | Payload is immediately reflected back to the user via a URL parameter (e.g., search results). |
| **Stored XSS** | Payload is permanently stored on the server (e.g., in database fields like forum posts or comments). This is the most dangerous form. |
| **DOM-based XSS** | The attack occurs entirely client-side due to vulnerable JavaScript modifying the Document Object Model (DOM). |

#### Defense Measures:

1.  **Output Encoding:** The primary defense. Convert all user-supplied data that is rendered on the page into its HTML entity equivalent (e.g., `<` becomes `&lt;`).
2.  **Content Security Policy (CSP):** A strong security layer that specifies which content sources (scripts, styles, images) are trusted and allowed to execute.
3.  **Input Sanitization:** Removing or escaping dangerous HTML/JavaScript tags (`<script>`, `onerror`, etc.) on the server side.

### 2.3. Directory Traversal (Path Traversal)

This vulnerability allows an attacker to access files and directories outside the intended web root directory by using special characters like `../` (dot-dot-slash) [69, 70].

#### Attack Mechanism:

| Type | Description | Example Payload |
| :--- | :--- | :--- |
| **Basic Traversal** | Uses parent directory traversal sequences. | `../../../etc/passwd` |
| **Bypass Filter** | Obfuscation techniques to bypass naive security filters. | `....//....//etc/passwd` |
| **URL Encoding** | Encoding characters to hide the sequence. | `%2e%2e%2f%2e%2e%2fetc%2fpasswd` |

#### Defense Measures:

1.  **Path Canonicalization:** Resolve all path components (including `../`) to their absolute, normalized format, and then check if the final path starts with the expected base directory (`realpath` check).
2.  **Input Validation:** Strictly filter user input to reject any non-alphanumeric characters or sequence patterns like `../`.
3.  **Least Privilege:** Restrict the web application's file access rights using technologies like Chroot Jail or containers.

### 2.4. File Upload Vulnerability

This occurs when an application fails to properly validate files uploaded by users, potentially leading to **Remote Code Execution (RCE)** if an attacker uploads a webshell (`.php`, `.asp`, etc.) [71].

#### Defense Measures:

1.  **Strict File Type Validation:** Do not rely on MIME type or file extension alone; use **Content Scanning** (magic bytes) to verify the file's actual type.
2.  **Rename Files:** Generate random, non-sequential file names upon storage.
3.  **Store Outside Web Root:** Place uploaded files in a location that cannot be directly accessed by a web URL.

### 2.5. Cross-Site Request Forgery (CSRF)

CSRF forces an authenticated user to unknowingly execute unwanted actions on a web application where they are currently logged in, leveraging the victim's session cookies [49, 55].

#### Defense Measures:

1.  **CSRF Tokens:** The most common defense. Use unique, unpredictable, and secret tokens in every state-changing request (POST, PUT, DELETE).
2.  **SameSite Cookies:** Set the `SameSite=Strict` or `Lax` flag on session cookies to prevent the browser from sending them with cross-site requests.

### 2.6. Server-Side Request Forgery (SSRF)

SSRF allows an attacker to instruct the server to make arbitrary HTTP requests to locations of the attacker's choosing, often targeting internal networks or cloud metadata services (e.g., `169.254.169.254`) [50, 51].

#### Defense Measures:

1.  **URL Allowlisting:** Only permit requests to a strictly defined, essential list of trusted domains/IPs.
2.  **Input Validation:** Blacklist private and non-routable IP addresses (e.g., `10.0.0.0/8`, `192.168.0.0/16`).
3.  **Network Segmentation:** Isolate the application server from the core internal infrastructure.

### 2.7. Denial of Service (DoS/DDoS)

DoS (single source) and DDoS (multiple sources/botnets) aim to disrupt service availability by overwhelming system resources [48].

#### Defense Measures:

1.  **Rate Limiting:** Restricting the number of requests a single source can make over a period of time (e.g., using Nginx or specialized services).
2.  **Traffic Filtering:** Utilizing firewalls, IPS, and specialized services (e.g., Cloudflare) to filter malicious traffic and mitigate amplification attacks.
3.  **CDN and Protection Services:** Employing Content Delivery Networks (CDN) and advanced protection platforms (e.g., AWS Shield).

### 2.8. Web Application Firewall (WAF) Bypass Techniques

WAF Bypass involves using obfuscation, encoding, and parsing discrepancies to bypass WAF security rules [59, 60].

#### Defense Measures:

1.  **Semantic Analysis:** WAF should analyze the payload after decoding and normalization, not just the raw input.
2.  **Continuous Rule Updates:** Regularly update WAF rules based on shared threat intelligence.
3.  **Advanced Filtering:** Use multi-layered filtering that inspects headers, methods, and payload structures.

---

## 3. PRACTICAL ASSESSMENT AND PENETRATION TESTING

### 3.1. Essential Testing Tools and Environments

| Category | Tool / Environment | Purpose |
| :--- | :--- | :--- |
| **Testing OS** | Kali Linux, Parrot Security OS | Operating systems pre-loaded with security tools. |
| **Web Proxy** | Burp Suite | Intercepts, modifies, and analyzes all HTTP/HTTPS traffic. |
| **Injection Testing** | SQLmap, XSStrike | Automated tools for detecting SQL Injection and XSS flaws. |
| **Vulnerable Labs** | DVWA, WebGoat | Safe, legally vulnerable applications for practicing attacks. |

### 3.2. Demo Example: Attacking Web Applications

| Attack | Sample Payload (Testing) | Primary Defense |
| :--- | :--- | :--- |
| **SQL Injection** | `' UNION SELECT 1,username,password FROM users--` | Prepared Statements |
| **Reflected XSS** | `<img src=x onerror=alert(document.cookie)>` | Output Encoding (CSP) |
| **Directory Traversal** | `../../../etc/passwd` | Path Canonicalization (`realpath`) |
| **CSRF** | Image tag forcing a transfer: `<img src="http://bank.com/transfer?amount=1000">` | CSRF Tokens & SameSite Cookies |

---

## 4. CONCLUSION AND RECOMMENDATIONS

### 4.1. Key Security Recommendations
1.  **Adopt the OWASP Top 10** as a baseline requirement for all web projects.
2.  **Utilize Prepared Statements** (parameterization) universally for all database interactions.
3.  **Implement Content Security Policy (CSP)** and **Output Encoding** to mitigate XSS risks.
4.  **Enforce Strict Input Validation** for file names (Path Traversal) and all user inputs.
5.  **Focus on Security by Design** (A04) to build robust systems from the ground up.
6.  **Maintain continuous patching and dependency management** (A06).

---

## REFERENCES

[1] "OWASP Top Ten | OWASP Foundation." Accessed: Oct. 06, 2025. [Online]. Available: https://owasp.org/www-project-top-ten/
1]	“An Toàn Thông Tin Là Gì?” Accessed: Sept. 09, 2025. [Online]. Available: https://itsystems.vn/an-toan-thong-tin-la-gi/
[2]	“An toàn thông tin là gì? 4 Nội dung cần biết.” Accessed: Sept. 09, 2025. [Online]. Available: https://vnce.vn/an-toan-thong-tin-la-gi
[3]	“Các Lỗ Hổng Bảo Mật của Website bị HACKER Tấn Công Nhất.” Accessed: Sept. 09, 2025. [Online]. Available: https://lanit.com.vn/cac-lo-hong-bao-mat-cua-website-bi-hacker-loi-dung-tan-cong-nhieu-nhat.html
[4]	“XSS là gì? Kỹ thuật tấn công XSS, cách ngăn chặn hiệu quả.” Accessed: Sept. 09, 2025. [Online]. Available: https://vietnix.vn/xss-la-gi/
[5]	“SQL Injection là gì? Cách giảm thiểu và phòng ngừa SQL Injection.” Accessed: Sept. 09, 2025. [Online]. Available: https://topdev.vn/blog/sql-injection/
[6]	FPT C. ty C. phần B. lẻ K., “SQL Injection là gì? Độ nguy hiểm và cách phòng tránh hiệu quả.” Accessed: Sept. 09, 2025. [Online]. Available: https://fptshop.com.vn/tin-tuc/danh-gia/sql-injection-la-gi-159279
[7]	T. Dang, “DDoS là gì và cách ngăn chặn các loại tấn công DDoS Server,” DDoS là gì và cách ngăn chặn các loại tấn công DDoS Server. Accessed: Sept. 09, 2025. [Online]. Available: https://www.vnetwork.vn/news/ddos-la-gi-va-cach-ngan-chan-cac-loai-tan-cong-ddos-server/
[8]	admininsho, “Tam giác bảo mật CIA (tính bảo mật, tính toàn vẹn, tính sẵn sàng) là gì?,” Tỷ lệ đạt chứng nhận 100%. Accessed: Oct. 04, 2025. [Online]. Available: https://3ac.vn/tam-giac-bao-mat-cia-tinh-bao-mat-tinh-toan-ven-tinh-san-sang-la-gi/
[9]	Admin, “Hacker là gì? Phân biệt 7 loại hacker phổ biến nhất,” TopCV Blog. Accessed: Oct. 04, 2025. [Online]. Available: https://blog.topcv.vn/hacker-la-gi/
[10]	“The OWASP Top Ten 2025.” Accessed: Oct. 04, 2025. [Online]. Available: https://www.owasptopten.org/
[11]	“The Cyber Kill Chain: A Complete Guide for 2025 - RSVR Technologies PVT LTD.” Accessed: Oct. 06, 2025. [Online]. Available: https://rsvrtech.com/blog/cyber-kill-chain-guide-2025/
[12]	“(12) The Cyber Kill Chain Explained: Applying the Cyber Kill Chain in 2025 | LinkedIn.” Accessed: Oct. 06, 2025. [Online]. Available: https://www.linkedin.com/pulse/cyber-kill-chain-explained-applying-2025-strongbox-it-pvt-ltd-s9lzf/
[13]	“Cyber Kill Chain Breakdown: Command and Control | Alert Logic.” Accessed: Oct. 06, 2025. [Online]. Available: https://www.alertlogic.com/blog/cyber-kill-chain-breakdown-understanding-stage-six-command-and-control/
[14]	“TOP 10 LỖ HỔNG BẢO MẬT WEBSITE PHỔ BIẾN NHẤT - VNCS Global.” Accessed: Oct. 04, 2025. [Online]. Available: https://vncsglobal.vn/top-10-lo-hong-bao-mat-website-pho-bien-nhat/
[15]	“OWASP Top Ten | OWASP Foundation.” Accessed: Oct. 04, 2025. [Online]. Available: https://owasp.org/www-project-top-ten/
[16]	“SQL Injection.” Accessed: Oct. 04, 2025. [Online]. Available: https://viblo.asia/p/sql-injection-MgNeWWbKeYx
[17]	“Breaking down the 5 most common SQL injection attacks,” Pentest-Tools.com. Accessed: Oct. 04, 2025. [Online]. Available: https://pentest-tools.com/blog/sql-injection-attacks
[18]	“What is SQL Injection (SQLi) and How to Prevent Attacks,” Acunetix. Accessed: Oct. 04, 2025. [Online]. Available: https://www.acunetix.com/websitesecurity/sql-injection/
[19]	“What is Cross-site Scripting (XSS): prevention and fixes.” Accessed: Oct. 04, 2025. [Online]. Available: https://www-acunetix-com.translate.goog/websitesecurity/cross-site-scripting/?_x_tr_sl=en&_x_tr_tl=vi&_x_tr_hl=vi&_x_tr_pto=tc
[20]	“Lỗ hổng Cross-Site Scripting (XSS).” Accessed: Oct. 04, 2025. [Online]. Available: https://viblo.asia/p/lo-hong-cross-site-scripting-xss-GrLZDOY3Kk0
[21]	“Tổng quan một số kỹ thuật khai thác lỗ hổng bảo mật Web (P1).” Accessed: Oct. 05, 2025. [Online]. Available: https://viblo.asia/p/tong-quan-mot-so-ky-thuat-khai-thac-lo-hong-bao-mat-web-p1-gGJ59MOP5X2
[22]	Aj, “CSRF, XSS, SSRF: The Attacks That Still Break the Web in 2025,” Medium. Accessed: Oct. 06, 2025. [Online]. Available: https://levelup.gitconnected.com/csrf-xss-ssrf-the-attacks-that-still-break-the-web-in-2025-6e2774c62ad6
[23]	“Kỹ Thuật Tấn Công XSS và Cách Ngăn Chặn - Viblo.” Accessed: Oct. 05, 2025. [Online]. Available: https://viblo.asia/p/ky-thuat-tan-cong-xss-va-cach-ngan-chan-YWOZr0Py5Q0
[24]	V. IDC, “XSS là gì? Cách kiểm tra và ngăn chặn tấn công hiệu quả,” viettelidc.com.vn. Accessed: Oct. 05, 2025. [Online]. Available: https://viettelidc.com.vn/tin-tuc/xss-la-gi-cach-kiem-tra-va-ngan-chan
[25]	“What is a Path Traversal Attack? | Directory Traversal Attack.” Accessed: Oct. 06, 2025. [Online]. Available: https://www.contrastsecurity.com/glossary/path-traversal-or-directory-traversal
[26]	“What is directory traversal? | Tutorial & examples,” Snyk Learn. Accessed: Oct. 06, 2025. [Online]. Available: https://learn.snyk.io/lesson/directory-traversal/
[27]	“What is a Directory or Path Traversal? How to Avoid These Attacks.” Accessed: Oct. 06, 2025. [Online]. Available: https://jetpack-com.translate.goog/resources/path-directory-traversal/?_x_tr_sl=en&_x_tr_tl=vi&_x_tr_hl=vi&_x_tr_pto=tc
[28]	“What Is a DDoS Attack? Distributed Denial of Service,” Cisco. Accessed: Oct. 19, 2025. [Online]. Available: https://www.cisco.com/c/en_uk/products/security/what-is-a-ddos-attack.html
[29]	“Ransom Denial of Service (RDoS) Attack,” Check Point Software. Accessed: Oct. 19, 2025. [Online]. Available: https://www.checkpoint.com/cyber-hub/cyber-security/what-is-denial-of-service/ransom-denial-of-service-rdos-attack/
[30]	J. Sheehan, “Understand the Difference: DoS vs. DDoS Attacks,” SynchroNet. Accessed: Oct. 19, 2025. [Online]. Available: https://synchronet.net/dos-vs-ddos-attacks/
[31]	“Attack types,” Prolexic Analytics API. Accessed: Oct. 19, 2025. [Online]. Available: https://techdocs.akamai.com/prolexic/reference/attack-types
[32]	“What Is a SYN Flood Attack?,” Check Point Software. Accessed: Oct. 19, 2025. [Online]. Available: https://www.checkpoint.com/cyber-hub/cyber-security/what-is-a-ddos-attack/what-is-a-syn-flood-attack/
[33]	“What is a DDoS Attack? Definition, Meaning, Types,” /. Accessed: Oct. 19, 2025. [Online]. Available: https://www.kaspersky.com/resource-center/threats/ddos-attacks
[34]	“Azure DDoS Protection and Mitigation Services | Microsoft Azure.” Accessed: Oct. 19, 2025. [Online]. Available: https://azure.microsoft.com/en-us/products/ddos-protection
[35]	“The Impact of Cybersecurity Breaches on Firm’s Market Value: the Case of the USA,” ResearchGate, Sept. 2025, doi: 10.51176/1997-9967-2023-4-200-219.
[36]	“OWASP Top 10: Cheat Sheet of Cheat Sheets.” Accessed: Oct. 19, 2025. [Online]. Available: https://www.oligo.security/academy/owasp-top-10-cheat-sheet-of-cheat-sheets
[37]	“Playbook-The-Network-Ops-DDoS-Playbook-new.pdf.” Accessed: Oct. 19, 2025. [Online]. Available: https://www.imperva.com/resources/ebooks/Playbook-The-Network-Ops-DDoS-Playbook-new.pdf
[38]	E. Rocha, “Forrester WaveTM DDoS Mitigation Solutions, Q1 2021,” GlobalDots. Accessed: Oct. 19, 2025. [Online]. Available: https://www.globaldots.com/resources/ebooks/forrester-wave-ddos-mitigation-solutions-q1-2021/
[39]	“DDoS Protection for Service Providers - DDoS Mitigation Company.” Accessed: Oct. 19, 2025. [Online]. Available: https://www.netscout.com/solutions/service-provider-ddos-protection
[40]	“Applied Cryptography,” Schneier on Security. Accessed: Oct. 20, 2025. [Online]. Available: https://www.schneier.com/books/applied-cryptography/
[41]	“Brute Force Attack | OWASP Foundation.” Accessed: Oct. 20, 2025. [Online]. Available: https://owasp.org/www-community/attacks/Brute_force_attack
[42]	V. W. Ng and S. R. Sanders, “A High-Efficiency Wide-Input-Voltage Range Switched Capacitor Point-of-Load DC–DC Converter,” IEEE Trans. Power Electron., vol. 28, no. 9, pp. 4335–4341, Sept. 2013, doi: 10.1109/TPEL.2012.2224887.
[43]	“2025 Data Breach Investigations Report,” Verizon Business. Accessed: Oct. 20, 2025. [Online]. Available: https://www.verizon.com/business/resources/reports/dbir/
[44]	“Pentest là gì? Những điều cần biết về Kiểm thử xâm nhập.” Accessed: Oct. 21, 2025. [Online]. Available: https://cystack.net/vi/blog/pentest-la-gi
