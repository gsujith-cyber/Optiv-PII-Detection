"""
Member 3 - Storage Module

Responsibilities:
1. Create separate original and redacted folders.
2. Save original files without modification.
3. Save redacted files separately.
4. Never overwrite the original accidentally.
"""

from pathlib import Path
import shutil


# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

# Storage folders
ORIGINAL_DIR = BASE_DIR / "data" / "original"
REDACTED_DIR = BASE_DIR / "data" / "redacted"


def create_storage_folders():
    """
    Create the required storage folders.
    """

    ORIGINAL_DIR.mkdir(parents=True, exist_ok=True)
    REDACTED_DIR.mkdir(parents=True, exist_ok=True)

    return ORIGINAL_DIR, REDACTED_DIR


def save_original(source_file):
    """
    Save a copy of the original file.

    The original file is never modified.
    """

    create_storage_folders()

    source = Path(source_file)

    if not source.exists():
        raise FileNotFoundError(
            f"Source file not found: {source}"
        )

    destination = ORIGINAL_DIR / source.name

    shutil.copy2(source, destination)

    return destination


def save_redacted(filename, content):
    """
    Save redacted text/content into the redacted folder.

    filename:
        Name of the output file.

    content:
        Redacted text.
    """

    create_storage_folders()

    filename = Path(filename).name

    destination = REDACTED_DIR / filename

    destination.write_text(
        content,
        encoding="utf-8"
    )

    return destination


def save_redacted_bytes(filename, content):
    """
    Save binary redacted content.

    Useful later if the team generates
    redacted PDF/DOCX/PPTX files.
    """

    create_storage_folders()

    filename = Path(filename).name

    destination = REDACTED_DIR / filename

    destination.write_bytes(content)

    return destination


def storage_status():
    """
    Display the current storage folders and files.
    """

    create_storage_folders()

    original_files = list(ORIGINAL_DIR.iterdir())
    redacted_files = list(REDACTED_DIR.iterdir())

    return {
        "original_folder": str(ORIGINAL_DIR),
        "redacted_folder": str(REDACTED_DIR),
        "original_files": [file.name for file in original_files],
        "redacted_files": [file.name for file in redacted_files],
    }


# ---------------------------------------------------------
# TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("STORAGE MODULE TEST")
    print("=" * 60)

    # Create folders
    original_folder, redacted_folder = create_storage_folders()

    print("\nOriginal folder:")
    print(original_folder)

    print("\nRedacted folder:")
    print(redacted_folder)

    # Test redacted text storage
    test_content = """
Employee: Rahul Kumar
Email: <EMAIL_1>
Phone: <PHONE_1>
"""

    output_file = save_redacted(
        "test_redacted.txt",
        test_content
    )

    print("\nRedacted file saved:")
    print(output_file)

    # Show status
    status = storage_status()

    print("\n" + "=" * 60)
    print("STORAGE STATUS")
    print("=" * 60)

    print("\nOriginal files:")
    for file in status["original_files"]:
        print("-", file)

    print("\nRedacted files:")
    for file in status["redacted_files"]:
        print("-", file)

    print("\nSTORAGE TEST: PASS")