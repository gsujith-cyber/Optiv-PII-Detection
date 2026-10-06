"""
Member 3 - PII Redaction

Responsibilities:
1. Replace detected PII with tags.
2. Same PII value gets the same tag number.
3. Replace from the end so positions do not shift.
4. Calculate redaction percentage.
5. Re-scan the redacted text.
6. Repeat redaction if PII is still detected.
"""

from collections import defaultdict


def redact_text(text, detections):
    """
    Replace detected PII with tags.

    Example:
        rahul@example.com -> <EMAIL_1>

    The same value receives the same tag.
    """

    if not detections:
        return text, 0

    # Store tag number for each PII type/value
    tag_map = defaultdict(dict)

    # Counters for each PII type
    counters = defaultdict(int)

    # Sort from end to beginning
    # This prevents character positions from shifting.
    detections = sorted(
        detections,
        key=lambda x: x["start"],
        reverse=True
    )

    redacted_count = 0

    for detection in detections:

        pii_type = detection["type"]
        value = detection["value"]
        start = detection["start"]
        end = detection["end"]

        # Create a tag only if this value has not been seen
        if value not in tag_map[pii_type]:
            counters[pii_type] += 1

            tag_map[pii_type][value] = (
                f"<{pii_type}_{counters[pii_type]}>"
            )

        tag = tag_map[pii_type][value]

        # Replace detected PII
        text = text[:start] + tag + text[end:]

        redacted_count += 1

    return text, redacted_count


def calculate_redaction_percentage(redacted, detected):
    """
    Calculate percentage of detected PII that was redacted.

    Formula:
        (redacted / detected) * 100
    """

    if detected == 0:
        return 100.0

    return (redacted / detected) * 100


def redact_until_clean(text, detector, max_rounds=10):
    """
    Repeatedly detect and redact PII until no PII remains.

    Process:

        Detect PII
            ↓
        Redact PII
            ↓
        Detect again
            ↓
        PII remaining?
          /     \
        YES      NO
         ↓       ↓
      Redact    PASS

    max_rounds prevents an infinite loop.
    """

    current_text = text
    total_redacted = 0
    rounds = 0

    while rounds < max_rounds:

        rounds += 1

        # Detect PII
        detections = detector(current_text)

        # Nothing remains
        if not detections:
            break

        # Redact detected PII
        current_text, count = redact_text(
            current_text,
            detections
        )

        total_redacted += count

    # Final re-scan
    remaining = detector(current_text)

    return current_text, total_redacted, remaining, rounds


def verify_redaction(original_text, redacted_text, detector):
    """
    Verify that no PII remains in the redacted text.

    Returns True if the redacted text is clean.
    """

    remaining = detector(redacted_text)

    if not remaining:
        return True

    return False


# ---------------------------------------------------------
# DEMO / TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    from detection.regex_detector import detect_structured_pii

    text = """
Employee Name: Rahul Kumar
Email: rahul.kumar@example.com
Phone: +91-9876543210
Backup Email: rahul.kumar@example.com
"""

    print("=" * 60)
    print("PII REDACTION TEST")
    print("=" * 60)

    # -----------------------------------------------------
    # STEP 1 - Detect original PII
    # -----------------------------------------------------

    detections = detect_structured_pii(text)

    print("\nOriginal Text:")
    print(text)

    print("\nDetected PII:")

    for detection in detections:
        print(detection)

    detected_count = len(detections)

    print("\nTotal PII detected:", detected_count)

    # -----------------------------------------------------
    # STEP 2 - Redact
    # -----------------------------------------------------

    redacted_text, redacted_count, remaining, rounds = (
        redact_until_clean(
            text,
            detect_structured_pii
        )
    )

    print("\n" + "=" * 60)
    print("REDACTED TEXT")
    print("=" * 60)

    print(redacted_text)

    # -----------------------------------------------------
    # STEP 3 - Calculate percentage
    # -----------------------------------------------------

    percentage = calculate_redaction_percentage(
        redacted_count,
        detected_count
    )

    print("Total redactions:", redacted_count)
    print("Redaction percentage:", percentage, "%")
    print("Redaction rounds:", rounds)

    # -----------------------------------------------------
    # STEP 4 - Re-scan
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("RE-SCAN CHECK")
    print("=" * 60)

    remaining = detect_structured_pii(redacted_text)

    if not remaining:
        print("Remaining PII: []")
        print("RE-SCAN: PASS")
    else:
        print("Remaining PII:")

        for item in remaining:
            print(item)

        print("RE-SCAN: FAIL")

    # -----------------------------------------------------
    # STEP 5 - Final verification
    # -----------------------------------------------------

    clean = verify_redaction(
        text,
        redacted_text,
        detect_structured_pii
    )

    print("\n" + "=" * 60)

    if clean:
        print("FINAL RESULT: PASS")
    else:
        print("FINAL RESULT: FAIL")

    print("=" * 60)