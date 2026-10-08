"""
detection/ — PII detection and classification.

- regex_detector.py  → Member 3 (structured patterns: email, phone, etc.)
- ner_detector.py     → Member 4 (person names via spaCy NER)
- pii_engine.py       → Member 4 (merges both into one findings list)

app.py and processing/pipeline.py should only ever import from
pii_engine — the two individual detectors are implementation detail.
"""