import re


# ============================================================
# EMAIL
# ============================================================

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


# ============================================================
# PHONE
# Supports:
# +91-9876543210
# +91 9876543210
# 9876543210
# ============================================================

PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
)


# ============================================================
# EMPLOYEE ID
# Supports:
# EMP-12345
# EMP12345
# EMP 12345
# ============================================================

EMPLOYEE_ID_PATTERN = re.compile(
    r"\bEMP(?:[-\s]?\d{4,8})\b",
    re.IGNORECASE
)


# ============================================================
# CREDIT CARD
# ============================================================

CREDIT_CARD_PATTERN = re.compile(
    r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
)


# ============================================================
# EMAIL DETECTOR
# ============================================================

def detect_emails(text):

    results = []

    for match in EMAIL_PATTERN.finditer(text):

        results.append({
            "type": "EMAIL",
            "value": match.group(),
            "start": match.start(),
            "end": match.end(),
            "method": "REGEX"
        })

    return results


# ============================================================
# PHONE DETECTOR
# ============================================================

def detect_phone_numbers(text):

    results = []

    for match in PHONE_PATTERN.finditer(text):

        results.append({
            "type": "PHONE",
            "value": match.group(),
            "start": match.start(),
            "end": match.end(),
            "method": "REGEX"
        })

    return results


# ============================================================
# EMPLOYEE ID DETECTOR
# ============================================================

def detect_employee_ids(text):

    results = []

    for match in EMPLOYEE_ID_PATTERN.finditer(text):

        results.append({
            "type": "EMPLOYEE_ID",
            "value": match.group(),
            "start": match.start(),
            "end": match.end(),
            "method": "REGEX"
        })

    return results


# ============================================================
# CREDIT CARD DETECTOR
# ============================================================

def detect_credit_cards(text):

    results = []

    for match in CREDIT_CARD_PATTERN.finditer(text):

        value = match.group()

        digits = re.sub(r"[\s-]", "", value)

        if 13 <= len(digits) <= 19:

            results.append({
                "type": "CREDIT_CARD",
                "value": value,
                "start": match.start(),
                "end": match.end(),
                "method": "REGEX"
            })

    return results


# ============================================================
# MAIN REGEX DETECTOR
# ============================================================

def detect_structured_pii(text):

    results = []

    results.extend(detect_emails(text))
    results.extend(detect_phone_numbers(text))
    results.extend(detect_employee_ids(text))
    results.extend(detect_credit_cards(text))

    results.sort(
        key=lambda result: result["start"]
    )

    return results


# ============================================================
# MANUAL TEST
# ============================================================

if __name__ == "__main__":

    sample_text = """
    Employee Name: Rahul Kumar
    Employee ID: EMP-12345
    Email: rahul.kumar@example.com
    Phone: +91-9876543210
    Card Number: 4111 1111 1111 1111

    The company has 12345 employees.
    The year is 2026.
    """

    results = detect_structured_pii(sample_text)

    print("\n========== REGEX DETECTION ==========\n")

    for result in results:
        print(result)