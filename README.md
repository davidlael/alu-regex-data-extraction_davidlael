# Enterprise Regex Processing Engine: PII/PCI Data Extraction & Defensive Validation Pipeline

A production-grade Python utility designed to extract, validate, and sanitize structured data from noisy, un-sanitized system audit logs. This application demonstrates defensive engineering, strict PII (Personally Identifiable Information) masking, PCI-DSS compliance, and complex pattern matching for educational domain verification.

---

## Technical Overview & Regex Specifications

The program implements high-precision Regular Expressions combined with secondary algorithmic checks and input sanitization to prevent downstream vulnerabilities and security risks (e.g., Cross-Site Scripting, SQL Injection, Subdomain Spoofing).

### 1. Email Extraction & Domain Categorization
* **General Pattern**: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`
* **Defensive Boundary**: Uses strict word boundaries (`\b`) to block domain spoofing attacks (e.g., `user@alueducation.com.evil.com` is safely rejected).
* **ALU Sub-Domain Validation Patterns**:
  * **ALU Official**: `^[A-Za-z0-9._%+-]+@alueducation\.com$`
  * **ALU Alumni**: `^[A-Za-z0-9._%+-]+@alumni\.alueducation\.com$`
  * **ALU SI**: `^[A-Za-z0-9._%+-]+@si\.alueducation\.com$`

### 2. Credit Card Validation (PCI-DSS Compliant)
* **Regex Pattern**: `\b(?:\d{4}[-\s]?){3}\d{1,4}\b|\b\d{15,16}\b`
* **Algorithmic Luhn Verification (Modulus 10)**: Raw matches undergo secondary validation via the Luhn Algorithm. Random 16-digit sequences or card numbers failing checksum verification are dropped.
* **Masking**: Numbers are masked (`****-****-****-1423`) before JSON serialization to eliminate financial data breach risks.

### 3. URL Extraction & Script Filtering
* **Regex Pattern**: `\bhttps?://(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>]*)?`
* **Security Control**: Matches `http`/`https` protocols, direct IP target endpoints, and port definitions (`:8080`), while filtering out unescaped HTML characters (`<`, `>`).

### 4. Phone Number Normalization
* **Regex Pattern**: `(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b`
* **Validation**: Extracts international (`+44`, `+250`), US standard, and local telephone formats, verifying length between 7 and 15 digits according to ITU-T E.164 standards.

---

## Defensive Engineering & Security Considerations

1. **Input Sanitization**: Incoming raw text is neutralized for script tags (`<script>`) before regex evaluation to protect log parsing software.
2. **PII Masking**: Sensitive email usernames are redacted (`j***e@alueducation.com`) to enforce data protection regulations.
3. **Malicious Injection Resilience**: SQL injection strings (`DROP TABLE users; --`) and illegal syntax (`john.doe@@gmail..com`) are treated as untrusted noise and automatically ignored.

---

## Handled Edge Cases & Rejected Input Types

* **Domain Spoofing**: Inputs like `hacker@alueducation.com.evil.com` are caught by strict word boundaries (`\b`) and rejected.
* **Malformed Emails**: Syntax errors like `john.doe@@gmail..com` fail RFC match checks.
* **XSS / HTML Injections**: URLs or strings containing `<script>` tags are sanitized and stripped of executable code before output.
* **Luhn Failures & Invalid Lengths**: Cards like `4000-0000-0000-0002` pass standard length regex but are dropped after failing the Modulus 10 checksum.
* **Invalid Phone Characters**: Strings containing letters like `123-ABC-7890` are discarded during digit verification.


---

## How to Run the Application

### Prerequisites
* Python 3.8 or higher installed on your environment.

### Execution Steps
1. **Clone the Repository**:
   ```bash```
   git clone [https://github.com/davidlael/alu-regex-data-extraction_davidlael.git](https://github.com/davidlael/alu-regex-data-extraction_davidlael.git)
   cd alu-regex-data-extraction_davidlael

---

## Directory Structure

```text``
alu-regex-data-extraction_davidlael/
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
├── LICENSE
└── README.md
