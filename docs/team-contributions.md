# Team Contributions

## Member 3 — Regex-Based PII Detection

### Responsibility

Developed and tested the Regex-based structured PII detection module.

### Detected PII Types

The detector currently identifies:

- EMAIL
- PHONE
- EMPLOYEE_ID
- CREDIT_CARD

### Detection Output

Each detection returns:

- `type` — PII category
- `value` — detected text
- `start` — starting character position
- `end` — ending character position
- `method` — detection method (`REGEX`)

### Testing

The Regex detector was tested using 11 test cases covering:

1. Email detection
2. Phone detection
3. Employee ID detection
4. Credit card detection
5. Multiple PII detection
6. No-PII documents
7. False-positive checks
8. Email format variations
9. Phone format variations
10. Employee ID format variations
11. Ordinary numbers

### Test Result

**Passed: 11 / 11**

**Failed: 0 / 11**

### Integration Interface

The main function is:

```python
from detection.regex_detector import detect_structured_pii

results = detect_structured_pii(text)