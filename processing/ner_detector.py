import spacy

# Load the English NLP model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError as exc:
    raise RuntimeError(
        "spaCy English model is missing. Run: "
        "python -m spacy download en_core_web_sm"
    ) from exc


# Technical words that should not be detected as personal names
IGNORED_TERMS = {
    "storage",
    "pattern",
    "regex",
    "save",
    "store",
    "database",
    "computer",
    "network",
    "security",
    "software",
    "hardware",
    "python",
    "java",
    "linux",
    "employee id",
    "credit card",
    "email",
    "phone",
    "c. storage",
    "regex pattern",
    "store save",
}


def detect_named_entities(text):
    """
    Detect person names using spaCy.

    Returns a list of dictionaries containing:
    type, value, start, end, and method.
    """

    if not isinstance(text, str) or not text.strip():
        return []

    doc = nlp(text)
    detections = []

    for entity in doc.ents:
        value = entity.text.strip()
        normalized_value = value.casefold()

        # Ignore common technical terms
        if normalized_value in IGNORED_TERMS:
            continue

        # Detect person names
        if entity.label_ == "PERSON":
            detections.append({
                "type": "PERSON",
                "value": value,
                "start": entity.start_char,
                "end": entity.end_char,
                "method": "NER",
            })

    return detections


if __name__ == "__main__":

    sample_text = """
    Employee: Arjun Sharma
    Email: arjun.sharma@example.com
    Technical terms: C. Storage and Regex Pattern.
    Another employee: Priya Reddy.
    """

    results = detect_named_entities(sample_text)

    print("\nNamed Entity Detection Results")
    print("-" * 40)

    if results:
        for result in results:
            print(result)
    else:
        print("No person names detected.")