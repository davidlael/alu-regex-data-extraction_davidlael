import json
import os
import re


def sanitize_input(text: str) -> tuple[str, int]:
    """Replaces <script> tags with placeholder tokens to prevent XSS."""
    script_pattern = re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL)
    sanitized_text, count = script_pattern.subn("[BLOCKED_SCRIPT]", text)
    return sanitized_text, count


def mask_email(email: str) -> str:
    """Masks local part of an email (e.g., jane.doe@alu... -> j***e@alu...)."""
    user, domain = email.split("@")
    if len(user) <= 2:
        masked_user = user[0] + "*"
    else:
        masked_user = user[0] + "***" + user[-1]
    return f"{masked_user}@{domain}"


def luhn_check(card_number: str) -> bool:
    """Validates credit card number using the Luhn Algorithm (Modulus 10)."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def mask_credit_card(card_number: str) -> str:
    """Masks card number showing only the last 4 digits (e.g., ****-****-****-1423)."""
    digits = [d for d in card_number if d.isdigit()]
    last_four = "".join(digits[-4:])
    return f"****-****-****-{last_four}"


def process_logs(input_path: str, output_path: str):
    """Main processing pipeline for extraction, validation, and output generation."""
    if not os.path.exists(input_path):
        print(f"Error: Input file not found at {input_path}")
        return

    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()
    sanitized_text, xss_count = sanitize_input(raw_text)
    email_regex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    all_emails = email_regex.findall(sanitized_text)

    valid_emails = []
    rejected_spoofed = []
    rejected_malformed = []

    for email in all_emails:
        if email.count("@") > 1 or ".." in email:
            rejected_malformed.append(email)
            continue

        is_alu = False
        category = "General"
        if re.match(r"^[A-Za-z0-9._%+-]+@alueducation\.com$", email):
            is_alu = True
            category = "ALU Official"
        elif re.match(r"^[A-Za-z0-9._%+-]+@alumni\.alueducation\.com$", email):
            is_alu = True
            category = "ALU Alumni"
        elif re.match(r"^[A-Za-z0-9._%+-]+@si\.alueducation\.com$", email):
            is_alu = True
            category = "ALU SI"
        elif "alueducation.com" in email:
            rejected_spoofed.append(email)
            continue

        valid_emails.append({
            "masked_value": mask_email(email),
            "category": category,
            "is_alu_domain": is_alu
        })
    raw_url_regex = re.compile(
        r"\bhttps?://[^\s<>\"]+"
    )
    all_raw_urls = raw_url_regex.findall(raw_text)

    valid_urls = []
    rejected_script_urls = []

    for url in all_raw_urls:
        if "<script" in url.lower() or "</script>" in url.lower():
            rejected_script_urls.append(url)
        else:
            valid_urls.append(url)
    phone_regex = re.compile(r"(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b")
    phone_candidates = phone_regex.findall(sanitized_text)

    valid_phones = []
    rejected_phones = []

    for p in phone_candidates:
        digits_only = re.sub(r"\D", "", p)
        if 7 <= len(digits_only) <= 15:
            valid_phones.append({
                "raw_extracted": p.strip(),
                "normalized_digits": digits_only,
                "valid_e164": True
            })
        else:
            rejected_phones.append(p.strip())
    card_regex = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{1,4}\b|\b\d{15,16}\b")
    raw_cards = card_regex.findall(sanitized_text)

    valid_cards = []
    rejected_cards = []

    for card in raw_cards:
        if luhn_check(card):
            valid_cards.append({
                "masked_card": mask_credit_card(card),
                "luhn_verified": True
            })
        else:
            rejected_cards.append(card)
    total_rejections = (
        len(rejected_spoofed)
        + len(rejected_malformed)
        + len(rejected_cards)
        + len(rejected_phones)
        + len(rejected_script_urls)
    )
    output_payload = {
        "status": "SUCCESS",
        "extracted_summary": {
            "total_emails": len(valid_emails),
            "total_urls": len(valid_urls),
            "total_phones": len(valid_phones),
            "total_valid_credit_cards": len(valid_cards),
            "rejected_entries_count": total_rejections
        },
        "data": {
            "emails": valid_emails,
            "urls": valid_urls,
            "phones": valid_phones,
            "credit_cards": valid_cards
        },
        "security_audit": {
            "sanitized_xss_tags": xss_count,
            "rejected_spoofed_domains": rejected_spoofed,
            "rejected_malformed_emails": rejected_malformed,
            "rejected_invalid_luhn_cards": rejected_cards,
            "rejected_malformed_phones": rejected_phones,
            "rejected_script_urls": rejected_script_urls
        }
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)

    print(f"Processing complete. Output written to {output_path}")


if __name__ == "__main__":
    process_logs("input/raw-text.txt", "output/sample-output.json")
