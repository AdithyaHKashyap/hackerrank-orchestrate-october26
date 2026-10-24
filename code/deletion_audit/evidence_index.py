"""Deterministic, provenance-preserving adapters for structured evidence."""

import csv
import importlib
import importlib.util
import json
import os
import re
import shlex
import sqlite3
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .errors import DataValidationError
from .models import EvidenceFact, EvidenceFile, InspectionStatus, Provenance
from .temporal import parse_timestamp


class ExtractionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    UNREADABLE = "UNREADABLE"
    UNSUPPORTED = "UNSUPPORTED"


class TemporalResolution(str, Enum):
    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class IndexedEvidence:
    evidence_id: str
    source_path: str
    source_origin: str
    extraction_method: str
    fact: EvidenceFact
    attributes_json: str
    metadata_json: str
    identifiers: Tuple[Tuple[str, str], ...]
    timestamp_fields: Tuple[Tuple[str, str], ...]

    @property
    def temporal_resolution(self) -> TemporalResolution:
        if self.fact.observed_at is None:
            return TemporalResolution.UNRESOLVED
        return TemporalResolution.RESOLVED

    @property
    def attributes(self) -> Mapping[str, Any]:
        return json.loads(self.attributes_json)

    @property
    def metadata(self) -> Mapping[str, Any]:
        return json.loads(self.metadata_json)


@dataclass(frozen=True)
class FileExtractionReport:
    evidence_id: str
    source_path: str
    source_origin: str
    captured_at: str
    status: ExtractionStatus
    extraction_method: str
    record_count: int
    temporally_unresolved_count: int = 0
    warnings: Tuple[str, ...] = ()
    error: Optional[str] = None


@dataclass(frozen=True)
class TemporalEvidencePartition:
    eligible: Tuple[IndexedEvidence, ...]
    unresolved: Tuple[IndexedEvidence, ...]
    excluded: Tuple[IndexedEvidence, ...]


class EvidenceIndex:
    """An in-memory index built once and reused across request audit cutoffs."""

    def __init__(
        self,
        records: Iterable[IndexedEvidence],
        report: Iterable[FileExtractionReport],
    ) -> None:
        self.records = tuple(
            sorted(records, key=lambda record: (record.evidence_id, record.fact.provenance.record_locator or ""))
        )
        self.report = tuple(sorted(report, key=lambda item: item.evidence_id))
        by_id: Dict[str, List[IndexedEvidence]] = {}
        by_resource_id: Dict[str, List[IndexedEvidence]] = {}
        by_system_resource: Dict[Tuple[str, str], List[IndexedEvidence]] = {}
        by_identifier: Dict[Tuple[str, str], List[IndexedEvidence]] = {}
        by_identifier_value: Dict[str, List[IndexedEvidence]] = {}
        for record in self.records:
            by_id.setdefault(record.evidence_id, []).append(record)
            if record.fact.resource_id is not None:
                by_resource_id.setdefault(record.fact.resource_id, []).append(record)
                if record.fact.system_id is not None:
                    by_system_resource.setdefault(
                        (record.fact.system_id, record.fact.resource_id), []
                    ).append(record)
            for field_name, value in record.identifiers:
                by_identifier.setdefault((field_name.casefold(), value), []).append(
                    record
                )
                by_identifier_value.setdefault(value, []).append(record)
        self._by_evidence_id = {
            evidence_id: tuple(items) for evidence_id, items in by_id.items()
        }
        self._by_resource_id = {
            resource_id: tuple(items)
            for resource_id, items in by_resource_id.items()
        }
        self._by_system_resource = {
            key: tuple(items) for key, items in by_system_resource.items()
        }
        self._by_identifier = {
            key: tuple(items) for key, items in by_identifier.items()
        }
        self._by_identifier_value = {
            value: tuple(items) for value, items in by_identifier_value.items()
        }

    @classmethod
    def build(cls, dataset_dir: Path) -> "EvidenceIndex":
        dataset_dir = Path(dataset_dir).resolve()
        manifest_path = dataset_dir / "evidence_files.csv"
        files = _load_manifest(manifest_path)
        records: List[IndexedEvidence] = []
        reports: List[FileExtractionReport] = []
        for evidence_file in files:
            file_records, file_report = _extract_file(dataset_dir, evidence_file)
            records.extend(file_records)
            reports.append(file_report)
        return cls(records, reports)

    def for_evidence(self, evidence_id: str) -> Tuple[IndexedEvidence, ...]:
        return self._by_evidence_id.get(evidence_id, tuple())

    def for_resource_id(self, resource_id: str) -> Tuple[IndexedEvidence, ...]:
        return self._by_resource_id.get(resource_id, tuple())

    def for_system_resource(
        self, system_id: str, resource_id: str
    ) -> Tuple[IndexedEvidence, ...]:
        return self._by_system_resource.get((system_id, resource_id), tuple())

    def for_identifier(
        self, value: str, identifier_type: Optional[str] = None
    ) -> Tuple[IndexedEvidence, ...]:
        if identifier_type is not None:
            return self._by_identifier.get(
                (identifier_type.casefold(), value), tuple()
            )
        return tuple(
            sorted(
                set(self._by_identifier_value.get(value, tuple())),
                key=lambda record: (
                    record.evidence_id,
                    record.fact.provenance.record_locator or "",
                ),
            )
        )

    def at_cutoff(self, audit_at) -> TemporalEvidencePartition:
        eligible = []
        unresolved = []
        excluded = []
        for record in self.records:
            available_at = record.fact.provenance.available_at
            observed_at = record.fact.observed_at
            if available_at is None or available_at > audit_at:
                excluded.append(record)
            elif observed_at is not None and observed_at > audit_at:
                excluded.append(record)
            elif observed_at is None:
                unresolved.append(record)
            else:
                eligible.append(record)
        return TemporalEvidencePartition(
            eligible=tuple(eligible),
            unresolved=tuple(unresolved),
            excluded=tuple(excluded),
        )

    def write_report_csv(self, path: Path) -> None:
        """Write a compact per-file report without copying evidence contents."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as destination:
            writer = csv.writer(destination)
            writer.writerow(
                (
                    "evidence_id",
                    "source_path",
                    "origin",
                    "captured_at",
                    "status",
                    "extraction_method",
                    "record_count",
                    "temporally_unresolved_count",
                    "warnings",
                    "error",
                )
            )
            for item in self.report:
                writer.writerow(
                    (
                        item.evidence_id,
                        item.source_path,
                        item.source_origin,
                        item.captured_at,
                        item.status.value,
                        item.extraction_method,
                        item.record_count,
                        item.temporally_unresolved_count,
                        " | ".join(item.warnings),
                        item.error or "",
                    )
                )


_OBSERVATION_TIME_KEYS = (
    "observed_at",
    "captured_at",
    "snapshot_at",
    "snapshot_time",
    "event_time",
    "event_at",
    "recorded_at",
    "timestamp",
)
_IDENTIFIER_KEY_PARTS = (
    "email",
    "phone",
    "hash",
    "reference",
    "lookup_key",
    "match_key",
    "identifier",
)
_IDENTIFIER_KEYS = {"name", "user_id", "customer_id"}
_SYSTEM_KEYS = ("system_id", "system", "service", "service_name")
_RESOURCE_KEYS = ("resource_id",)
_SUPPORTED_EXTENSIONS = {".json", ".sql", ".log", ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".tif", ".tiff"}
_SQL_ALLOWED_PREFIXES = (
    re.compile(r"^CREATE\s+TABLE\b", re.IGNORECASE),
    re.compile(r"^CREATE\s+(?:UNIQUE\s+)?INDEX\b", re.IGNORECASE),
    re.compile(r"^INSERT\s+INTO\b", re.IGNORECASE),
)
_SQL_TRANSACTION = re.compile(r"^(?:BEGIN(?:\s+TRANSACTION)?|COMMIT)\s*;?$", re.I)
_SQL_FOREIGN_KEY_PRAGMA = re.compile(
    r"^PRAGMA\s+foreign_keys\s*=\s*(?:ON|OFF)\s*;?$", re.I
)
_LOG_TIMESTAMP_PREFIX = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2}[Tt ][0-9:.+\-Zz]+)\s+(.*)$"
)
_SQL_CAPTURED_AT = re.compile(
    r"^\s*--\s*Captured at:\s*(.*?)\s*$", re.IGNORECASE | re.MULTILINE
)
_HANDOVER_SNAPSHOT = re.compile(r"^\s*Snapshot:\s*(.*?)\s*$", re.IGNORECASE)
_HANDOVER_ROW = re.compile(r"^\s*-\s*(.*?)\s*$")


def _load_manifest(path: Path) -> Tuple[EvidenceFile, ...]:
    from .csv_loader import CSV_SCHEMAS, _read_rows, _required, _timestamp, _unique

    rows = _read_rows(path, CSV_SCHEMAS["evidence_files.csv"])
    files = []
    for line_number, row in enumerate(rows, start=2):
        files.append(
            EvidenceFile(
                file_id=_required(row, "file_id", path, line_number),
                file_path=_required(row, "file_path", path, line_number),
                origin=_required(row, "origin", path, line_number),
                captured_at=_timestamp(row, "captured_at", path, line_number),
            )
        )
    return _unique(files, lambda item: item.file_id, str(path))


def _safe_evidence_path(dataset_dir: Path, file_path: str) -> Path:
    if "\\" in file_path:
        raise DataValidationError("manifest path must use forward slashes")
    relative = PurePosixPath(file_path)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise DataValidationError("manifest path must stay inside the dataset")
    resolved = (dataset_dir / Path(*relative.parts)).resolve()
    if os.path.commonpath((str(dataset_dir), str(resolved))) != str(dataset_dir):
        raise DataValidationError("manifest path resolves outside the dataset")
    return resolved


def _extract_file(
    dataset_dir: Path, evidence_file: EvidenceFile
) -> Tuple[List[IndexedEvidence], FileExtractionReport]:
    extension = PurePosixPath(evidence_file.file_path).suffix.lower()
    if extension not in _SUPPORTED_EXTENSIONS:
        return [], _report(
            evidence_file,
            ExtractionStatus.UNSUPPORTED,
            "unsupported:{}".format(extension or "no-extension"),
            0,
        )

    method = {
        ".json": "json-object-path",
        ".sql": "sqlite-table-row",
        ".log": "timestamped-log-record",
        ".txt": "handover-record",
        ".pdf": "pdf-page-text",
        ".png": "image-ocr",
        ".jpg": "image-ocr",
        ".jpeg": "image-ocr",
        ".tif": "image-ocr",
        ".tiff": "image-ocr",
    }[extension]
    try:
        path = _safe_evidence_path(dataset_dir, evidence_file.file_path)
        if extension in {".png", ".jpg", ".jpeg", ".tif", ".tiff"}:
            file_records, warnings, unsupported_reason = _extract_image(path, evidence_file)
            if unsupported_reason:
                return [], _report(
                    evidence_file,
                    ExtractionStatus.UNSUPPORTED,
                    method,
                    0,
                    error=unsupported_reason,
                )
        elif extension == ".pdf":
            file_records, warnings, unsupported_reason = _extract_pdf(path, evidence_file)
            if unsupported_reason:
                return [], _report(
                    evidence_file,
                    ExtractionStatus.UNSUPPORTED,
                    method,
                    0,
                    error=unsupported_reason,
                )
        else:
            text = path.read_text(encoding="utf-8-sig")
        if extension == ".json":
            file_records, warnings = _extract_json(text, evidence_file)
        elif extension == ".sql":
            file_records, warnings = _extract_sql(text, evidence_file)
        elif extension == ".log":
            file_records, warnings = _extract_log(text, evidence_file)
        elif extension == ".txt":
            file_records, warnings = _extract_handover(text, evidence_file)
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        sqlite3.Error,
    ) as error:
        message = str(error)
        return [], _report(
            evidence_file,
            ExtractionStatus.UNREADABLE,
            method,
            0,
            error=message,
        )

    extracted_methods = sorted({record.extraction_method for record in file_records})
    if extracted_methods:
        method = ",".join(extracted_methods)
    status = ExtractionStatus.PARTIAL if warnings else ExtractionStatus.SUCCESS
    return file_records, _report(
        evidence_file,
        status,
        method,
        len(file_records),
        temporally_unresolved_count=sum(
            record.temporal_resolution == TemporalResolution.UNRESOLVED
            for record in file_records
        ),
        warnings=tuple(warnings),
    )


def _extract_handover(
    text: str, evidence_file: EvidenceFile
) -> Tuple[List[IndexedEvidence], List[str]]:
    records: List[IndexedEvidence] = []
    warnings: List[str] = []
    snapshot_time = None
    snapshot_line = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        snapshot_match = _HANDOVER_SNAPSHOT.match(line)
        if snapshot_match:
            snapshot_line = line_number
            try:
                snapshot_time = parse_timestamp(
                    snapshot_match.group(1), "handover snapshot timestamp"
                )
            except DataValidationError as error:
                warnings.append("{} at line={}".format(error, line_number))
                snapshot_time = None
            continue
        row_match = _HANDOVER_ROW.match(line)
        if not row_match:
            continue
        fields = [field.strip() for field in row_match.group(1).split("|")]
        if len(fields) != 6:
            warnings.append(
                "expected six pipe-delimited fields at line={}".format(line_number)
            )
            continue
        timestamp, system, resource, category, result, subject = fields
        attributes = {
            "timestamp": timestamp,
            "system": system,
            "resource_id": resource,
            "record_type": category,
            "result": result,
            "subject_reference": subject,
        }
        record, record_warnings = _record(
            evidence_file,
            "line={}".format(line_number),
            "handover-record",
            attributes,
            metadata={
                "snapshot_line": snapshot_line,
                "snapshot_at": (
                    snapshot_time.isoformat() if snapshot_time is not None else None
                ),
            },
        )
        records.append(record)
        warnings.extend(record_warnings)
    if not records:
        warnings.append("no handover records were parsed")
    return records, warnings


def _optional_module(module_name: str):
    try:
        if importlib.util.find_spec(module_name) is None:
            return None
        return importlib.import_module(module_name)
    except (ImportError, ValueError):
        return None


def _extract_pdf(
    path: Path, evidence_file: EvidenceFile
) -> Tuple[List[IndexedEvidence], List[str], Optional[str]]:
    try:
        with path.open("rb") as source:
            signature = source.read(5)
    except OSError:
        raise
    if signature != b"%PDF-":
        raise DataValidationError("file does not have a PDF signature")

    reader_module = _optional_module("pypdf")
    reader_class = None
    if reader_module is not None:
        reader_class = getattr(reader_module, "PdfReader", None)
    if reader_class is None:
        reader_module = _optional_module("PyPDF2")
        if reader_module is not None:
            reader_class = getattr(reader_module, "PdfReader", None) or getattr(
                reader_module, "PdfFileReader", None
            )
    if reader_class is None:
        return [], [], "No supported local PDF text-extraction library is installed"

    with path.open("rb") as source:
        pdf_error_types = [OSError, ValueError, TypeError]
        error_namespace = getattr(reader_module, "errors", None)
        pdf_read_error = getattr(error_namespace, "PdfReadError", None)
        if isinstance(pdf_read_error, type) and issubclass(pdf_read_error, Exception):
            pdf_error_types.append(pdf_read_error)
        try:
            reader = reader_class(source)
            pages = reader.pages
        except tuple(pdf_error_types) as error:
            raise DataValidationError("PDF could not be read: {}".format(error)) from error
        records: List[IndexedEvidence] = []
        warnings: List[str] = []
        render_module = None
        ocr_module = None
        ocr_checked = False
        ocr_version = None
        ocr_error = None
        render_document = None
        try:
            for page_number, page in enumerate(pages, start=1):
                try:
                    page_text = page.extract_text()
                except tuple(pdf_error_types) as error:
                    warnings.append(
                        "PDF page {} text extraction failed: {}".format(
                            page_number, error
                        )
                    )
                    continue
                if page_text and page_text.strip():
                    for line_number, line in enumerate(page_text.splitlines(), start=1):
                        content = line.strip()
                        if not content:
                            continue
                        record, record_warnings = _record(
                            evidence_file,
                            "page={};line={}".format(page_number, line_number),
                            "pdf-page-text",
                            {"text": content},
                            metadata={"page_number": page_number},
                        )
                        records.append(record)
                        warnings.extend(record_warnings)
                    continue

                if render_module is None:
                    render_module = _optional_module("pypdfium2")
                if ocr_module is None and not ocr_checked:
                    ocr_module = _optional_module("pytesseract")
                if render_module is None:
                    warnings.append(
                        "PDF page {} has no text layer; pypdfium2 is unavailable for local OCR rendering".format(
                            page_number
                        )
                    )
                    continue
                if ocr_module is None:
                    warnings.append(
                        "PDF page {} has no text layer; pytesseract is unavailable".format(
                            page_number
                        )
                    )
                    ocr_checked = True
                    continue
                if not ocr_checked:
                    ocr_checked = True
                    try:
                        ocr_version = str(ocr_module.get_tesseract_version())
                    except (OSError, RuntimeError) as error:
                        ocr_error = str(error)
                        ocr_module = None
                if ocr_version is None:
                    warnings.append(
                        "PDF page {} OCR backend unavailable: {}".format(
                            page_number, ocr_error
                        )
                    )
                    continue
                try:
                    if render_document is None:
                        render_document = render_module.PdfDocument(str(path))
                    render_page = render_document[page_number - 1]
                    bitmap = render_page.render(scale=2)
                    with bitmap.to_pil() as image:
                        regions, ocr_warnings = _extract_ocr_regions(
                            image,
                            evidence_file,
                            ocr_module,
                            ocr_version,
                            page_number=page_number,
                        )
                    records.extend(regions)
                    warnings.extend(ocr_warnings)
                except (OSError, ValueError, RuntimeError, IndexError, TypeError) as error:
                    warnings.append(
                        "PDF page {} OCR failed: {}".format(page_number, error)
                    )
        finally:
            if render_document is not None:
                render_document.close()
        if not records and not warnings:
            warnings.append("PDF contains no text records")
        return records, warnings, None


def _extract_image(
    path: Path, evidence_file: EvidenceFile
) -> Tuple[List[IndexedEvidence], List[str], Optional[str]]:
    image_module = _optional_module("PIL.Image")
    ocr_module = _optional_module("pytesseract")
    if image_module is None:
        return [], [], "Pillow is not installed for image decoding"
    if ocr_module is None:
        try:
            with image_module.open(path) as image:
                image.load()
        except (OSError, ValueError) as error:
            raise DataValidationError("image could not be decoded: {}".format(error)) from error
        return [], [], "pytesseract is not installed; image remains OCR-unsupported"
    try:
        ocr_version = str(ocr_module.get_tesseract_version())
    except (OSError, RuntimeError) as error:
        try:
            with image_module.open(path) as image:
                image.load()
        except (OSError, ValueError) as image_error:
            raise DataValidationError(
                "image could not be decoded: {}".format(image_error)
            ) from image_error
        return [], [], "Tesseract OCR is unavailable: {}".format(error)
    try:
        with image_module.open(path) as image:
            image.load()
            records, warnings = _extract_ocr_regions(
                image, evidence_file, ocr_module, ocr_version
            )
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        raise DataValidationError("image OCR failed: {}".format(error)) from error
    return records, warnings, None


def _extract_ocr_regions(
    image,
    evidence_file: EvidenceFile,
    ocr_module,
    ocr_version: str,
    page_number: Optional[int] = None,
) -> Tuple[List[IndexedEvidence], List[str]]:
    output_module = getattr(ocr_module, "Output", None)
    output_dict = getattr(output_module, "DICT", "dict")
    ocr_data = ocr_module.image_to_data(image, output_type=output_dict)
    grouped: Dict[Tuple[Any, ...], List[str]] = {}
    boxes: Dict[Tuple[Any, ...], Tuple[int, int, int, int]] = {}
    confidences: Dict[Tuple[Any, ...], List[float]] = {}
    total_words = len(ocr_data.get("text", []))
    for index in range(total_words):
        word = str(ocr_data["text"][index]).strip()
        if not word:
            continue
        key = tuple(
            ocr_data.get(field, [0] * total_words)[index]
            for field in ("page_num", "block_num", "par_num", "line_num")
        )
        grouped.setdefault(key, []).append(word)
        left = int(ocr_data.get("left", [0] * total_words)[index])
        top = int(ocr_data.get("top", [0] * total_words)[index])
        width = int(ocr_data.get("width", [0] * total_words)[index])
        height = int(ocr_data.get("height", [0] * total_words)[index])
        previous = boxes.get(key)
        if previous is None:
            boxes[key] = (left, top, left + width, top + height)
        else:
            boxes[key] = (
                min(previous[0], left),
                min(previous[1], top),
                max(previous[2], left + width),
                max(previous[3], top + height),
            )
        try:
            confidence = float(ocr_data.get("conf", [None] * total_words)[index])
        except (TypeError, ValueError):
            continue
        if confidence >= 0:
            confidences.setdefault(key, []).append(confidence)

    records: List[IndexedEvidence] = []
    for region_number, key in enumerate(sorted(grouped), start=1):
        locator = "region={}".format(region_number)
        if page_number is not None:
            locator = "page={};{}".format(page_number, locator)
        metadata = {
            "page_number": page_number if page_number is not None else key[0],
            "block_number": key[1],
            "paragraph_number": key[2],
            "line_number": key[3],
            "bbox": boxes[key],
            "ocr_engine": "Tesseract",
            "ocr_version": ocr_version,
        }
        region_confidences = confidences.get(key, [])
        if region_confidences:
            metadata["mean_word_confidence"] = round(
                sum(region_confidences) / len(region_confidences), 2
            )
        record, _ = _record(
            evidence_file,
            locator,
            "tesseract-ocr",
            {"text": " ".join(grouped[key])},
            metadata=metadata,
        )
        records.append(record)

    if records:
        warnings = [
            "OCR text is probabilistic and requires review against the source image"
        ]
    else:
        warnings = ["OCR returned no text regions"]
    return records, warnings


def _report(
    evidence_file: EvidenceFile,
    status: ExtractionStatus,
    method: str,
    record_count: int,
    temporally_unresolved_count: int = 0,
    warnings: Tuple[str, ...] = (),
    error: Optional[str] = None,
) -> FileExtractionReport:
    return FileExtractionReport(
        evidence_id=evidence_file.file_id,
        source_path=evidence_file.file_path,
        source_origin=evidence_file.origin,
        captured_at=evidence_file.captured_at.isoformat(),
        status=status,
        extraction_method=method,
        record_count=record_count,
        temporally_unresolved_count=temporally_unresolved_count,
        warnings=warnings,
        error=error,
    )


def _record(
    evidence_file: EvidenceFile,
    locator: str,
    method: str,
    attributes: Mapping[str, Any],
    metadata: Optional[Mapping[str, Any]] = None,
    inherited_observed_at=None,
) -> Tuple[IndexedEvidence, List[str]]:
    warnings: List[str] = []
    observed_at = inherited_observed_at
    explicit_timestamp_invalid = False
    explicit_timestamp_parsed = False
    timestamp_fields = []
    for key, value in attributes.items():
        normalized_key = str(key).casefold()
        if (
            normalized_key.endswith("_at")
            or normalized_key.endswith("_time")
            or normalized_key == "timestamp"
        ):
            timestamp_fields.append((str(key), _as_json_scalar(value)))

    for key in _OBSERVATION_TIME_KEYS:
        if key not in attributes:
            continue
        raw_timestamp = attributes[key]
        if not isinstance(raw_timestamp, str):
            continue
        try:
            observed_at = parse_timestamp(raw_timestamp, "evidence timestamp")
            explicit_timestamp_parsed = True
            break
        except DataValidationError as error:
            warnings.append("{} at {}".format(error, locator))
            explicit_timestamp_invalid = True
    if explicit_timestamp_invalid and not explicit_timestamp_parsed:
        observed_at = None

    identifiers = []
    for key, value in attributes.items():
        normalized_key = str(key).casefold()
        if (
            normalized_key in _IDENTIFIER_KEYS
            or normalized_key == "id"
            or normalized_key.endswith("_id")
            or any(part in normalized_key for part in _IDENTIFIER_KEY_PARTS)
        ):
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                identifiers.append((str(key), str(value)))

    system_id = _first_string(attributes, _SYSTEM_KEYS)
    resource_id = _first_string(attributes, _RESOURCE_KEYS)
    fact = EvidenceFact(
        system_id=system_id,
        resource_id=resource_id,
        data_category=_first_string(attributes, ("data_category", "category", "record_type")),
        observed_state=None,
        inspection_status=InspectionStatus.INCONCLUSIVE,
        provenance=Provenance(
            source_type="EVIDENCE_FILE",
            source_id=evidence_file.file_id,
            source_path=evidence_file.file_path,
            record_locator=locator,
            available_at=evidence_file.captured_at,
        ),
        subject_user_id=_first_string(attributes, ("user_id",)),
        observed_at=observed_at,
    )
    return (
        IndexedEvidence(
            evidence_id=evidence_file.file_id,
            source_path=evidence_file.file_path,
            source_origin=evidence_file.origin,
            extraction_method=method,
            fact=fact,
            attributes_json=_canonical_json(attributes),
            metadata_json=_canonical_json(metadata or {}),
            identifiers=tuple(sorted(identifiers)),
            timestamp_fields=tuple(sorted(timestamp_fields)),
        ),
        warnings,
    )


def _extract_json(
    text: str, evidence_file: EvidenceFile
) -> Tuple[List[IndexedEvidence], List[str]]:
    document = json.loads(text)
    records: List[IndexedEvidence] = []
    warnings: List[str] = []

    def visit(
        value: Any,
        locator: str,
        inherited_time=None,
        inherited_scope: Optional[Mapping[str, str]] = None,
        snapshot_record: bool = False,
    ) -> None:
        if isinstance(value, dict):
            local_time = inherited_time
            for key in (
                "captured_at",
                "snapshot_at",
                "snapshot_time",
                "observed_at",
            ):
                raw = value.get(key)
                if isinstance(raw, str):
                    try:
                        local_time = parse_timestamp(raw, "JSON {}".format(key))
                    except DataValidationError as error:
                        warnings.append("{} at {}".format(error, locator))
                        local_time = None
            local_scope = dict(inherited_scope or {})
            for key in ("collection", "data_store"):
                raw_scope = value.get(key)
                if isinstance(raw_scope, str) and raw_scope.strip():
                    local_scope[key] = raw_scope.strip()
            scalar_values = {
                key: item
                for key, item in value.items()
                if not isinstance(item, (dict, list))
            }
            if scalar_values:
                record_attributes = dict(local_scope)
                record_attributes.update(scalar_values)
                record_metadata: Dict[str, Any] = {"container_path": locator}
                if snapshot_record and scalar_values.get("resource_id"):
                    record_metadata["snapshot_record"] = True
                record, record_warnings = _record(
                    evidence_file,
                    locator,
                    "json-object-path",
                    record_attributes,
                    metadata=record_metadata,
                    inherited_observed_at=local_time,
                )
                records.append(record)
                warnings.extend(record_warnings)
            for key, child in value.items():
                child_locator = "{}.{}".format(locator, key)
                if key == "records" and isinstance(child, list):
                    has_snapshot_time = any(
                        isinstance(value.get(time_key), str)
                        for time_key in ("captured_at", "snapshot_at", "snapshot_time")
                    )
                    is_snapshot_scope = (
                        has_snapshot_time
                        and bool(local_scope.get("collection"))
                        and bool(local_scope.get("data_store"))
                    )
                    for index, record_value in enumerate(child):
                        visit(
                            record_value,
                            "{}[{}]".format(child_locator, index),
                            local_time,
                            local_scope,
                            is_snapshot_scope,
                        )
                elif key in {"document", "profile"} and isinstance(child, dict):
                    nested_scope = dict(local_scope)
                    for inherited_key in (
                        "resource_id",
                        "status_code",
                        "user_id",
                        "customer_reference",
                    ):
                        inherited_value = scalar_values.get(inherited_key)
                        if isinstance(inherited_value, (str, int)):
                            nested_scope[inherited_key] = str(inherited_value)
                    visit(
                        child,
                        child_locator,
                        local_time,
                        nested_scope,
                        snapshot_record and key == "document",
                    )
                else:
                    visit(child, child_locator, local_time)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(
                    child,
                    "{}[{}]".format(locator, index),
                    inherited_time,
                )

    visit(document, "$")
    return records, warnings


def _sql_statements(text: str) -> Sequence[str]:
    statements = []
    pending = []
    for line in text.splitlines():
        pending.append(line)
        candidate = "\n".join(pending)
        if sqlite3.complete_statement(candidate):
            statement = candidate.strip()
            if statement:
                statements.append(statement)
            pending = []
    trailing = "\n".join(pending).strip()
    if trailing and not all(
        not line.strip() or line.lstrip().startswith("--")
        for line in trailing.splitlines()
    ):
        raise DataValidationError("SQL evidence ends with an incomplete statement")
    return statements


def _statement_without_leading_comments(statement: str) -> str:
    value = statement.strip()
    while value:
        if value.startswith("--"):
            _, separator, remainder = value.partition("\n")
            if not separator:
                return ""
            value = remainder.lstrip()
        elif value.startswith("/*"):
            end = value.find("*/", 2)
            if end < 0:
                raise DataValidationError("SQL evidence has an unterminated comment")
            value = value[end + 2 :].lstrip()
        else:
            break
    return value


def _json_valid(value: Any) -> int:
    if not isinstance(value, str):
        return 0
    try:
        json.loads(value)
        return 1
    except (TypeError, ValueError):
        return 0


def _extract_sql(
    text: str, evidence_file: EvidenceFile
) -> Tuple[List[IndexedEvidence], List[str]]:
    connection = sqlite3.connect(":memory:")
    connection.create_function("json_valid", 1, _json_valid, deterministic=True)
    try:
        statements = _sql_statements(text)
        for statement in statements:
            executable = _statement_without_leading_comments(statement)
            if not executable:
                continue
            if _SQL_TRANSACTION.match(executable) or _SQL_FOREIGN_KEY_PRAGMA.match(executable):
                continue
            if not any(pattern.match(executable) for pattern in _SQL_ALLOWED_PREFIXES):
                raise DataValidationError(
                    "SQL evidence contains unsupported statement: {}".format(
                        executable.split(None, 1)[0]
                    )
                )
            connection.execute(executable)

        captured_match = _SQL_CAPTURED_AT.search(text)
        file_observed_at = None
        warnings: List[str] = []
        if captured_match:
            try:
                file_observed_at = parse_timestamp(
                    captured_match.group(1), "SQL snapshot captured_at"
                )
            except DataValidationError as error:
                warnings.append(str(error))

        records: List[IndexedEvidence] = []
        tables = connection.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        for table_name, create_sql in tables:
            quoted_table = _quote_identifier(table_name)
            without_rowid = bool(
                create_sql and re.search(r"\bWITHOUT\s+ROWID\b", create_sql, re.I)
            )
            order_clause = "" if without_rowid else " ORDER BY rowid"
            cursor = connection.execute(
                "SELECT * FROM {}{}".format(quoted_table, order_clause)
            )
            columns = tuple(item[0] for item in cursor.description or ())
            for row_number, row in enumerate(cursor.fetchall(), start=1):
                attributes = dict(zip(columns, row))
                locator = "table={};row={}".format(table_name, row_number)
                record, row_warnings = _record(
                    evidence_file,
                    locator,
                    "sqlite-table-row",
                    attributes,
                    metadata={
                        "table_name": table_name,
                        "row_number": row_number,
                    },
                    inherited_observed_at=file_observed_at,
                )
                records.append(record)
                warnings.extend(row_warnings)
        return records, warnings
    finally:
        connection.close()


def _quote_identifier(value: str) -> str:
    return '"{}"'.format(value.replace('"', '""'))


def _extract_log(
    text: str, evidence_file: EvidenceFile
) -> Tuple[List[IndexedEvidence], List[str]]:
    records: List[IndexedEvidence] = []
    warnings: List[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = _LOG_TIMESTAMP_PREFIX.match(line)
        prefix_timestamp = None
        body = line
        if match:
            body = match.group(2)
            try:
                prefix_timestamp = parse_timestamp(
                    match.group(1), "log line {} timestamp".format(line_number)
                )
            except DataValidationError as error:
                warnings.append(str(error))

        method = "log-text"
        attributes: Dict[str, Any]
        stripped = body.strip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                if not isinstance(parsed, dict):
                    raise DataValidationError(
                        "JSON log entry at line {} is not an object".format(line_number)
                    )
                attributes = dict(parsed)
                method = "log-json"
            except json.JSONDecodeError as error:
                warnings.append(
                    "invalid JSON log entry at line {}: {}".format(line_number, error)
                )
                attributes = {"message": body}
        else:
            attributes = _key_value_attributes(stripped)
            for key, value in _pipe_log_fields(stripped).items():
                attributes.setdefault(key, value)
            if attributes:
                method = "log-key-value"
            else:
                attributes = {"message": body}
                warnings.append(
                    "unstructured log entry at line {}".format(line_number)
                )
        if prefix_timestamp is not None:
            attributes.setdefault("timestamp", match.group(1))
        attributes.setdefault("raw_line", line)
        record, record_warnings = _record(
            evidence_file,
            "line={}".format(line_number),
            method,
            attributes,
            metadata={"line_number": line_number},
            inherited_observed_at=prefix_timestamp,
        )
        records.append(record)
        warnings.extend(record_warnings)
    return records, warnings


def _pipe_log_fields(line: str) -> Dict[str, str]:
    parts = [part.strip() for part in line.split("|")]
    if parts and not parts[0]:
        parts = parts[1:]
    if (
        len(parts) < 4
        or parts[0].upper() not in {"DEBUG", "INFO", "WARN", "WARNING", "ERROR"}
        or not parts[1]
        or not parts[3]
    ):
        return {}
    return {
        "level": parts[0],
        "service": parts[1],
        "context_id": parts[2],
        "event": parts[3],
    }


def _key_value_attributes(line: str) -> Dict[str, str]:
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        return {}
    attributes = {}
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator and key:
            attributes[key] = value
    return attributes


def _first_string(
    values: Mapping[str, Any], keys: Sequence[str]
) -> Optional[str]:
    for key in keys:
        value = values.get(key)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            return str(value)
    return None


def _as_json_scalar(value: Any) -> str:
    if isinstance(value, str):
        return value
    return _canonical_json(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
