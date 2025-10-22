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

... (Citations omitted for brevity)