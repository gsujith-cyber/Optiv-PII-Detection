# Optiv-PII-Detection

## Optiv Consulting Case Study 2 – PII Detection within Text Artifacts

A team-based project developed as part of the Optiv Consulting VIT Internship Recruitment 2026 case study.

## Objective

The objective of this project is to detect Personally Identifiable Information (PII) within text artifacts and protect the detected information through masking or redaction while preserving the remaining non-sensitive content.

## Workflow

Input Artifact
↓
Text Extraction
↓
PII Detection
↓
PII Classification
↓
PII Redaction
↓
Protected Output

## PII Detection

The project uses multiple approaches where appropriate, including:

- Regex / Pattern-based detection
- Named Entity Recognition (NER)
- PII classification
- Redaction / masking

## Supported Artifacts

- PDF
- DOCX
- PPTX

## Project Structure

```text
Optiv-PII-Detection/
│
├── detection/
├── extractors/
├── processing/
├── reports/
├── tests/
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
    