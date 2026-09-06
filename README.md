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
  * *Design Justification*: Captures HTTP/HTTPS web endpoints, standard domain names, raw IP addresses (`192.168.1.100`), custom ports (`:8080`), and URL query parameters. Combined with input pre-sanitization, valid URLs embedded adjacent to script tags are safely recovered after `<script>` tags are stripped.

### 4. Phone Number Normalization
* **Regex Pattern**: `(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b`
  * *Design Justification*: Matches global phone formats (E.164 international prefixes, parentheses, hyphens). Extracted strings are verified to contain 7 to 15 digits (`7 <= len(digits_only) <= 15`), automatically dropping illegal alphabetical noise (e.g., `123-ABC-7890`).

---

## Defensive Engineering & Security Considerations

1. **Input Pre-Sanitization**: Incoming raw log text passes through `sanitize_input()` to replace `<script>` tags with harmless placeholder tokens (`[BLOCKED_SCRIPT]`) before regex evaluation. This protects downstream log parsers while enabling recovery of valid adjacent payload URLs.
2. **PII & PCI Masking**: Email usernames are redacted (`j***e@alueducation.com`) and credit card numbers are truncated (`****-****-****-1423`) within the primary payload (`data`) to enforce privacy regulations and PCI-DSS compliance.
3. **Security Audit Policy (Unmasked Forensics)**: Rejected/malformed entries captured in `security_audit` intentionally preserve raw string values (e.g., `hacker@alueducation.com.evil.com`) to allow security operation teams to perform threat analysis, block malicious IP ranges, and trace attack origins.
4. **Resilience to Injection & Noise**: SQL injection payloads (`DROP TABLE users; --`) and illegal syntax (`john.doe@@gmail..com`) fail validation checks and are safely routed to audit logs as untrusted noise.

---

## Handled Edge Cases & Validated Inputs

### Test Cases Implemented in `raw-text.txt`
* **XSS Script Tag Neutralization**: `<script>alert('xss')</script>https://secure.site.org` neutralizes the script execution attempt while extracting the valid trailing target URL `https://secure.site.org`.
* **Domain Spoofing Prevention**: `hacker@alueducation.com.evil.com` fails anchored sub-domain checks and is flagged in security audit logs.
* **Malformed Email Rejection**: `john.doe@@gmail..com` fails RFC syntax checks.
* **Non-Numeric Phone Filtering**: `123-ABC-7890` is discarded during digit verification.
* **Luhn Check Failure**: `4000-0000-0000-0002` passes initial digit length matching but is dropped after failing the Modulus 10 checksum test.

---

## Real Sample Input vs. JSON Output Demonstration

### Sample Raw Log Input (`input/raw-text.txt`)
```text```
CONTACT & SECURITY AUDIT LOG BATCH:
- Staff Lead: jane.doe@alueducation.com (verified)
- Spoofed Email Attempt: hacker@alueducation.com.evil.com (REJECT ME)
- Invalid Syntax Email: john.doe@@gmail..com (REJECT ME)

COMMUNICATION ENDPOINTS:
- Direct Support: +250 788 123 456
- Invalid Character Phone: 123-ABC-7890 (REJECT ME)

RESOURCE ENDPOINTS:
- Staging Portal: [http://staging-portal.internal-dev.org:8080/dashboard](http://staging-portal.internal-dev.org:8080/dashboard)
- Injection Endpoint: <script>alert('xss')</script>[https://secure.site.org](https://secure.site.org)

PAYMENT INGESTION LOGS:
- Valid Visa Payment: 4532 0150 9982 1423
- Invalid Checksum Card: 4000-0000-0000-0002 (REJECT ME)

METADATA & CURRENCY NOISE:
- Processing Fee: $150.00 / RWF 200,000
- Audit Tags: #SystemAudit #SecurityLab



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
