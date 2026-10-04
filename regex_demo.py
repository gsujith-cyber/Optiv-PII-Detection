
from detection.regex_detector import detect_structured_pii


def main():

    text = """
    Employee Name: Rahul Kumar
    Employee ID: EMP-12345
    Corporate Email: rahul.kumar@cadence-example.com
    Mobile: +91-9876543210

    Rahul works with the Third-Party Risk Management team.
    """

    print("=" * 60)
    print("PII REGEX DETECTOR DEMO")
    print("=" * 60)

    print("\nINPUT TEXT:")
    print(text)

    results = detect_structured_pii(text)

    print("\nDETECTED PII:")
    print("-" * 60)

    if not results:
        print("No PII detected.")
        return

    for result in results:
        print(f"Type   : {result['type']}")
        print(f"Value  : {result['value']}")
        print(f"Start  : {result['start']}")
        print(f"End    : {result['end']}")
        print(f"Method : {result['method']}")
        print("-" * 60)

    print(f"\nTotal PII detected: {len(results)}")


if __name__ == "__main__":
    main()