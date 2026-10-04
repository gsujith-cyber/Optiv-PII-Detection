from detection.regex_detector import detect_structured_pii


# ============================================================
# TEST FUNCTION
# ============================================================

def run_test(test_name, text, expected_types):

    results = detect_structured_pii(text)

    detected_types = [
        result["type"]
        for result in results
    ]

    print("\n" + "=" * 60)
    print(test_name)
    print("=" * 60)

    print("Input:")
    print(text)

    print("\nDetected:")

    if results:
        for result in results:
            print(result)
    else:
        print("No PII detected")

    print("\nExpected types:")
    print(expected_types)

    # Check missing expected PII
    missing = [
        pii_type
        for pii_type in expected_types
        if pii_type not in detected_types
    ]

    # Check unexpected PII
    unexpected = [
        pii_type
        for pii_type in detected_types
        if pii_type not in expected_types
    ]

    if not missing and not unexpected:

        print("\nRESULT: PASS")
        return True

    print("\nRESULT: FAIL")

    if missing:
        print("Missing:", missing)

    if unexpected:
        print("Unexpected:", unexpected)

    return False


# ============================================================
# TEST 1 - EMAIL
# ============================================================

test1 = run_test(
    "TEST 1 - Email Detection",

    """
    Employee email: rahul.kumar@example.com
    """,

    ["EMAIL"]
)


# ============================================================
# TEST 2 - PHONE
# ============================================================

test2 = run_test(
    "TEST 2 - Phone Detection",

    """
    Employee phone: +91-9876543210
    """,

    ["PHONE"]
)


# ============================================================
# TEST 3 - EMPLOYEE ID
# ============================================================

test3 = run_test(
    "TEST 3 - Employee ID Detection",

    """
    Employee ID: EMP-12345
    """,

    ["EMPLOYEE_ID"]
)


# ============================================================
# TEST 4 - CREDIT CARD
# ============================================================

test4 = run_test(
    "TEST 4 - Credit Card Detection",

    """
    Card number: 4111 1111 1111 1111
    """,

    ["CREDIT_CARD"]
)


# ============================================================
# TEST 5 - MULTIPLE PII
# ============================================================

test5 = run_test(
    "TEST 5 - Multiple PII",

    """
    Employee: Rahul Kumar
    Employee ID: EMP-12345
    Email: rahul.kumar@example.com
    Phone: +91-9876543210
    """,

    ["EMAIL", "PHONE", "EMPLOYEE_ID"]
)


# ============================================================
# TEST 6 - NO PII
# ============================================================

test6 = run_test(
    "TEST 6 - No PII",

    """
    The company was founded in 2020.
    The security team reviewed the annual report.
    The office is located in New York.
    """,

    []
)


# ============================================================
# TEST 7 - FALSE POSITIVE CHECK
# ============================================================

test7 = run_test(
    "TEST 7 - False Positive Check",

    """
    The company has 500 employees.
    The project started in 2026.
    The department has 25 members.
    """,

    []
)


# ============================================================
# TEST 8 - EMAIL VARIATIONS
# ============================================================

test8 = run_test(
    "TEST 8 - Email Variations",

    """
    rahul.kumar@cadence-example.com
    security.team@company.org
    admin123@company.co.in
    """,

    ["EMAIL"]
)


# ============================================================
# TEST 9 - PHONE VARIATIONS
# ============================================================

test9 = run_test(
    "TEST 9 - Phone Variations",

    """
    Phone 1: +91-9876543210
    Phone 2: +91 9876543210
    Phone 3: 9876543210
    """,

    ["PHONE"]
)


# ============================================================
# TEST 10 - EMPLOYEE ID VARIATIONS
# ============================================================

test10 = run_test(
    "TEST 10 - Employee ID Variations",

    """
    Employee ID: EMP-12345
    Employee ID: EMP123456
    Employee ID: EMP 98765
    """,

    ["EMPLOYEE_ID"]
)


# ============================================================
# TEST 11 - ORDINARY NUMBERS
# ============================================================

test11 = run_test(
    "TEST 11 - Ordinary Numbers",

    """
    The company was established in 2026.
    The total count was 12345.
    The reference number is 1234567890.
    """,

    []
)


# ============================================================
# FINAL SUMMARY
# ============================================================

tests = [
    test1,
    test2,
    test3,
    test4,
    test5,
    test6,
    test7,
    test8,
    test9,
    test10,
    test11
]


print("\n")
print("=" * 60)
print("FINAL TEST SUMMARY")
print("=" * 60)

passed = sum(tests)
failed = len(tests) - passed

print(f"Passed: {passed} / {len(tests)}")
print(f"Failed: {failed} / {len(tests)}")