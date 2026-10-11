"""
Q-Verify Backend Analysis Engine
Unified entrypoint for forensic metadata extraction, timestamp auditing, and authenticity scoring.
"""

from datetime import datetime
from pathlib import Path

from .discrepancy_analyzer import DiscrepancyAnalyzer
from .image_inspector import ImageInspector
from .models_data import AnomalyFlag, ParsedMetadata, VerificationResult
from .ner_extractor import (
    extract_proper_nouns_and_entities,
    extract_proper_nouns_and_entities_from_file,
)
from .office_inspector import OfficeInspector
from .pdf_inspector import PDFInspector


def inspect_document(
    file_bytes: bytes,
    filename: str,
    file_created_at: datetime | None = None,
    file_modified_at: datetime | None = None,
) -> VerificationResult:
    """
    Main forensic dispatch function. Inspects file based on extension and computes authenticity score.
    """
    ext = Path(filename).suffix.lower()

    if ext == ".pdf":
        metadata = PDFInspector.inspect(file_bytes, filename, file_created_at, file_modified_at)
    elif ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm"):
        metadata = OfficeInspector.inspect(file_bytes, filename, file_created_at, file_modified_at)
    elif ext in (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp"):
        metadata = ImageInspector.inspect(file_bytes, filename, file_created_at, file_modified_at)
    else:
        # Generic fallback
        metadata = PDFInspector.inspect(file_bytes, filename, file_created_at, file_modified_at)

    return DiscrepancyAnalyzer.analyze(metadata)


__all__ = [
    "AnomalyFlag",
    "DiscrepancyAnalyzer",
    "ImageInspector",
    "OfficeInspector",
    "PDFInspector",
    "ParsedMetadata",
    "VerificationResult",
    "extract_proper_nouns_and_entities",
    "extract_proper_nouns_and_entities_from_file",
    "inspect_document",
]
