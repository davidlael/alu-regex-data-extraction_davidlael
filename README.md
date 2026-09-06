# Enterprise Regex Processing Engine: PII/PCI Data Extraction & Defensive Validation Pipeline

A production-grade Python utility designed to extract, validate, and sanitize structured data from noisy, un-sanitized system audit logs. This application demonstrates defensive engineering, strict PII (Personally Identifiable Information) masking, PCI-DSS compliance, and complex pattern matching for educational domain verification.

---

## Technical Overview & Regex Specifications

The program combines regular expressions with algorithmic checks and input sanitization to safely extract structured records while neutralizing potential security vulnerabilities.

### 1. Email Extraction & Domain Categorization
* **General Email Pattern**: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`
  * *Design Justification*: Captures standard RFC-compliant email formats while isolating surrounding log text using word boundaries (`\b`).
* **ALU Sub-Domain Categorization (Anchored Validation)**:
  * **ALU Official**: `^[A-Za-z0-9._%+-]+@alueducation\.com$`
  * **ALU Alumni**: `^[A-Za-z0-9._%+-]+@alumni\.alueducation\.com$`
  * **ALU SI**: `^[A-Za-z0-9._%+-]+@si\.alueducation\.com$`
  * *Design Justification*: Word boundaries (`\b`) do **not** block domain spoofing (e.g., `user@alueducation.com.evil.com` matches word boundaries because `.evil` starts with a non-word character). Instead, strict start (`^`) and end (`$`) anchors force full string matching, causing spoofed domains to fail ALU sub-domain classification and fall back or get rejected.

### 2. Credit Card Validation (PCI-DSS Compliant)
* **Regex Pattern**: `\b(?:\d{4}[-\s]?){3}\d{1,4}\b|\b\d{15,16}\b`
  * *Design Justification*: Matches common 13–19 digit credit card formats across major issuers (Visa, Mastercard, Amex), handling grouped digits with spaces or hyphens.
* **Algorithmic Verification (Luhn Algorithm / Modulus 10)**:
  * Raw matches undergo secondary validation using `luhn_check()`. This mathematical checksum detects typo-generated numbers or random 16-digit sequences that look like cards but are mathematically invalid.

### 3. URL Extraction & Script Filtering
* **Regex Pattern**: `\bhttps?://(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>]*)?`
  * *Design Justification*: Captures HTTP/HTTPS web endpoints, standard domain names, raw IP addresses (`192.168.1.100`), custom ports (`:8080`), and URL query parameters. Combined with input pre-sanitization, valid URLs containing embedded script tags (`<script>`) are rejected from output data payloads and logged in security audits.

### 4. Phone Number Normalization
* **Regex Pattern**: `(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b`
  * *Design Justification*: Matches global phone formats (E.164 international prefixes, parentheses, hyphens). Extracted strings are verified to contain 7 to 15 digits (`7 <= len(digits_only) <= 15`), automatically dropping illegal alphabetical noise (e.g., `123-ABC-7890`).

---

## Defensive Engineering & Security Considerations

1. **Input Pre-Sanitization**: Incoming raw log text passes through `sanitize_input()` to identify XSS execution attempts before regex evaluation.
2. **PII & PCI Masking**: Email usernames are redacted (`j***e@alueducation.com`) and credit card numbers are truncated (`****-****-****-1423`) within the primary payload (`data`) to enforce privacy regulations and PCI-DSS compliance.
3. **Security Audit Policy (Unmasked Forensics)**: Rejected/malformed entries captured in `security_audit` intentionally preserve raw string values (e.g., `hacker@alueducation.com.evil.com`) to allow security operation teams to perform threat analysis, block malicious IP ranges, and trace attack origins.
4. **Resilience to Injection & Noise**: SQL injection payloads (`DROP TABLE users; --`) and illegal syntax (`john.doe@@gmail..com`) fail validation checks and are safely routed to audit logs as untrusted noise.

---

## Handled Edge Cases & Validated Inputs

### Test Cases Implemented in `raw-text.txt`
* **XSS Script Tag Neutralization**: Blocked script injections while capturing legitimate targets.
* **Domain Spoofing Prevention**: `hacker@alueducation.com.evil.com` fails anchored sub-domain checks and is flagged in security audit logs.
* **Malformed Email Rejection**: `john.doe@@gmail..com` fails RFC syntax checks.
* **Non-Numeric Phone Filtering**: `123-ABC-7890` is discarded during digit verification.
* **Luhn Check & Length Failure**: `4000-0000-0000-0002` and `4111-1111-1111` are dropped due to checksum or length mismatch.

---

## Real Sample Input vs. JSON Output Demonstration

### Sample Raw Log Input (`input/raw-text.txt`)
```text```
================================================================================
SYSTEM AUDIT LOG - INGESTION ENGINE v4.2.1
TIMESTAMP: 2026-03-31T08:14:22Z
================================================================================

[INFO] User onboarding activity detected from gateway node alpha-09.

CONTACT DATA BATCH:
- Primary Contact: jane.doe@alueducation.com (verified staff)
- Alumni Contact: alex.smith88@alumni.alueducation.com
- Instructor Contact: prof.johnson@si.alueducation.com
- External Partner: dev-team_lead@tech-corp.co.uk
- Invalid Domain Injection Attempt: hacker@alueducation.com.evil.com (REJECT ME)
- Malformed Email: john.doe@@gmail..com (REJECT ME)

RESOURCE ENDPOINTS:
- Public Documentation: [https://docs.alueducation.com/api/v2/regex?query=test#section1](https://docs.alueducation.com/api/v2/regex?query=test#section1)
- Staging Portal: [http://staging-portal.internal-dev.org:8080/dashboard](http://staging-portal.internal-dev.org:8080/dashboard)
- IP Address Target: [http://192.168.1.100/admin/login](http://192.168.1.100/admin/login)
- Malicious Script Injection URL: [http://example.com/](http://example.com/)<script>alert(1)</script> (REJECT ME)

TELEPHONY DATA:
- US Standard: +1 (555) 234-5678
- Local Format: 555-876-5432
- International Extension: +44 20 7946 0958
- Compact Direct: +250788123456
- Invalid Phone: 123-ABC-7890 (REJECT ME)

PAYMENT INGESTION TESTING:
- Visa Test Card: 4532 0150 9982 1423
- Mastercard Test Card: 5412-7512-3412-3456
- Amex Test Card: 378282246310005
- Unmasked PCI Breach Risk Card: 4000-1234-5678-9010
- Invalid Card Length: 4111-1111-1111 (REJECT ME)
- Invalid Card Luhn Check Failure: 4000-0000-0000-0002 (REJECT ME)

SECURITY TESTING NOISE & XSS PAYLOADS:
<script>document.cookie='session=stolen';</script>
DROP TABLE users; -- ' OR '1'='1


## Directory Structure

```text
alu-regex-data-extraction_davidlael/
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
├── LICENSE
└── README.md
## Author

**NZIZA LAEL DAVID**
* Junior Frontend Developer / Student, Cohort 4
* African Leadership University (ALU)
