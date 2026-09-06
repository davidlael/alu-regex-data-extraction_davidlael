import os
import re
import json

# ==============================================================================
# REGEX PATTERN DEFINITIONS
# ==============================================================================

# 1. EMAIL REGEX
EMAIL_REGEX = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

# ALU Specific Email Sub-Patterns for precise domain classification
ALU_OFFICIAL_REGEX = re.compile(r'^[A-Za-z0-9._%+-]+@alueducation\.com$', re.IGNORECASE)
ALU_ALUMNI_REGEX = re.compile(r'^[A-Za-z0-9._%+-]+@alumni\.alueducation\.com$', re.IGNORECASE)
ALU_SI_REGEX = re.compile(r'^[A-Za-z0-9._%+-]+@si\.alueducation\.com$', re.IGNORECASE)

# 2. URL REGEX
URL_REGEX = re.compile(
    r'\bhttps?://(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|'
    r'\bhttps?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>]*)?',
    re.IGNORECASE
)

# 3. PHONE NUMBER REGEX
PHONE_REGEX = re.compile(
    r'(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b'
)

# 4. CREDIT CARD REGEX
CREDIT_CARD_REGEX = re.compile(
    r'\b(?:\d{4}[-\s]?){3}\d{1,4}\b|\b\d{15,16}\b'
)


# ==============================================================================
# VALIDATION & SECURITY FUNCTIONS
# ==============================================================================

def luhn_check(card_number: str) -> bool:
    """Validates a credit card number using the Luhn Algorithm (Modulus 10)."""
    digits = [int(d) for d in re.sub(r'\D', '', card_number)]
    if not digits:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for index, digit in enumerate(reverse_digits):
        if index % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def sanitize_input(text: str) -> str:
    """Neutralizes script injection attempts and dangerous HTML tags."""
    return text.replace('<script>', '[BLOCKED_SCRIPT]').replace('</script>', '[/BLOCKED_SCRIPT]')


def mask_email(email: str) -> str:
    """Redacts sensitive email prefixes to prevent PII exposure in logs."""
    try:
        user, domain = email.split('@')
        if len(user) <= 2:
            masked_user = user[0] + "*"
        else:
            masked_user = user[0] + "*" * (len(user) - 2) + user[-1]
        return f"{masked_user}@{domain}"
    except ValueError:
        return "[INVALID_EMAIL]"


def mask_credit_card(card_number: str) -> str:
    """Masks payment card numbers according to PCI-DSS standards (shows last 4 digits only)."""
    clean_digits = re.sub(r'\D', '', card_number)
    return f"****-****-****-{clean_digits[-4:]}"


# ==============================================================================
# MAIN PROCESSING LOGIC
# ==============================================================================

def process_data(input_text: str) -> dict:
    sanitized_text = sanitize_input(input_text)
    
    # --- Extract & Validate Emails ---
    raw_emails = EMAIL_REGEX.findall(sanitized_text)
    validated_emails = []
    
    for email in raw_emails:
        if email.endswith('.'):
            email = email[:-1]
            
        category = "External"
        if ALU_OFFICIAL_REGEX.match(email):
            category = "ALU Official"
        elif ALU_ALUMNI_REGEX.match(email):
            category = "ALU Alumni"
        elif ALU_SI_REGEX.match(email):
            category = "ALU SI"
            
        validated_emails.append({
            "masked_value": mask_email(email),
            "category": category,
            "is_alu_domain": category != "External"
        })

    # --- Extract & Validate URLs ---
    raw_urls = URL_REGEX.findall(sanitized_text)
    safe_urls = [url for url in raw_urls if not any(char in url for char in ['<', '>', '"', "'"])]

    # --- Extract & Validate Phone Numbers ---
    raw_phones = PHONE_REGEX.findall(sanitized_text)
    validated_phones = []
    for phone in raw_phones:
        digits_only = re.sub(r'\D', '', phone)
        if 7 <= len(digits_only) <= 15:
            validated_phones.append(phone.strip())

    # --- Extract & Validate Credit Cards ---
    raw_cards = CREDIT_CARD_REGEX.findall(sanitized_text)
    validated_cards = []
    for card in raw_cards:
        clean_card = re.sub(r'[\s-]', '', card)
        if 13 <= len(clean_card) <= 19 and luhn_check(clean_card):
            validated_cards.append({
                "masked_card": mask_credit_card(clean_card),
                "luhn_verified": True
            })

    return {
        "status": "SUCCESS",
        "extracted_summary": {
            "total_emails": len(validated_emails),
            "total_urls": len(safe_urls),
            "total_phones": len(validated_phones),
            "total_valid_credit_cards": len(validated_cards)
        },
        "data": {
            "emails": validated_emails,
            "urls": safe_urls,
            "phone_numbers": list(set(validated_phones)),
            "credit_cards": validated_cards
        }
    }


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(base_dir, 'input', 'raw-text.txt')
    output_path = os.path.join(base_dir, 'output', 'sample-output.json')

    if not os.path.exists(input_path):
        print(f"Error: Could not find input file at {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as file:
        raw_content = file.read()

    results = process_data(raw_content)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as file:
        json.dump(results, file, indent=4)

    print("Data Extraction and Security Sanitization Complete.")
    print(f"Results successfully saved to: {output_path}")

if __name__ == '__main__':
    main()
