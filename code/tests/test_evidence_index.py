import csv
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from deletion_audit.evidence_index import (
    EvidenceIndex,
    ExtractionStatus,
    TemporalResolution,
)


class EvidenceIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.dataset_dir = Path(self.temporary_directory.name)
        (self.dataset_dir / "evidence").mkdir()

    def write_fixture(self, entries):
        manifest_path = self.dataset_dir / "evidence_files.csv"
        with manifest_path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(("file_id", "file_path", "origin", "captured_at"))
            for evidence_id, relative_path, content, captured_at in entries:
                target = self.dataset_dir / Path(*relative_path.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                writer.writerow(
                    (evidence_id, relative_path, "test_fixture", captured_at)
                )

    def test_adapts_json_sql_and_log_with_provenance(self):
        self.write_fixture(
            [
                (
                    "evidence_json",
                    "evidence/snapshot.json",
                    json.dumps(
                        {
                            "snapshots": [
                                {
                                    "captured_at": "2026-09-01T00:00:00Z",
                                    "records": [
                                        {
                                            "system": "profile_store",
                                            "resource_id": "profile_12",
                                            "user_id": "user_12",
                                            "email": "person@example.test",
                                        }
                                    ],
                                }
                            ]
                        }
                    ),
                    "2026-09-01T00:05:00Z",
                ),
                (
                    "evidence_sql",
                    "evidence/snapshot.sql",
                    """-- Captured at: 2026-09-02T00:00:00Z
BEGIN TRANSACTION;
CREATE TABLE inventory (resource_id TEXT, email TEXT, payload TEXT CHECK (json_valid(payload)));
INSERT INTO inventory VALUES ('profile_13', 'other@example.test', '{"ok":true}');
COMMIT;
""",
                    "2026-09-02T00:05:00Z",
                ),
                (
                    "evidence_log",
                    "evidence/events.log",
                    '2026-09-03T00:00:00Z INFO service=profile_store event=lookup resource_id="profile_14" subject_reference="person@example.test"\n',
                    "2026-09-03T00:05:00Z",
                ),
            ]
        )

        index = EvidenceIndex.build(self.dataset_dir)

        json_record = next(
            record
            for record in index.for_evidence("evidence_json")
            if record.fact.resource_id == "profile_12"
        )
        self.assertEqual(json_record.fact.provenance.source_id, "evidence_json")
        self.assertEqual(
            json_record.fact.provenance.source_path,
            "evidence/snapshot.json",
        )
        self.assertEqual(
            json_record.fact.provenance.record_locator,
            "$.snapshots[0].records[0]",
        )
        self.assertEqual(json_record.fact.system_id, "profile_store")
        self.assertEqual(json_record.fact.resource_id, "profile_12")
        self.assertEqual(json_record.fact.subject_user_id, "user_12")
        self.assertIn(("email", "person@example.test"), json_record.identifiers)
        self.assertIn(("user_id", "user_12"), json_record.identifiers)
        self.assertEqual(
            index.for_resource_id("profile_12"),
            (json_record,),
        )
        self.assertEqual(
            index.for_identifier("person@example.test", "email"),
            (json_record,),
        )
        self.assertEqual(json_record.extraction_method, "json-object-path")
        self.assertEqual(
            json_record.fact.observed_at,
            datetime(2026, 9, 1, tzinfo=timezone.utc),
        )

        sql_record = index.for_evidence("evidence_sql")[0]
        self.assertEqual(
            sql_record.fact.provenance.record_locator,
            "table=inventory;row=1",
        )
        self.assertEqual(sql_record.fact.resource_id, "profile_13")
        self.assertEqual(sql_record.attributes["payload"], '{"ok":true}')
        self.assertEqual(sql_record.extraction_method, "sqlite-table-row")
        self.assertEqual(
            sql_record.fact.observed_at,
            datetime(2026, 9, 2, tzinfo=timezone.utc),
        )

        log_record = index.for_evidence("evidence_log")[0]
        self.assertEqual(log_record.fact.provenance.record_locator, "line=1")
        self.assertEqual(log_record.fact.resource_id, "profile_14")
        self.assertEqual(log_record.fact.system_id, "profile_store")
        self.assertEqual(
            index.for_system_resource("profile_store", "profile_14"),
            (log_record,),
        )
        self.assertEqual(
            log_record.attributes["subject_reference"], "person@example.test"
        )
        self.assertEqual(log_record.extraction_method, "log-key-value")

    def test_unresolved_timestamp_is_preserved_and_not_promoted_to_evidence(self):
        self.write_fixture(
            [
                (
                    "evidence_no_time",
                    "evidence/no_time.json",
                    '{"records":[{"resource_id":"profile_20","email":"person@example.test"}]}',
                    "2026-09-01T00:00:00Z",
                )
            ]
        )

        index = EvidenceIndex.build(self.dataset_dir)
        record = index.for_evidence("evidence_no_time")[0]
        self.assertEqual(record.temporal_resolution, TemporalResolution.UNRESOLVED)
        self.assertEqual(record.fact.inspection_status.value, "INCONCLUSIVE")
        self.assertIsNone(record.fact.observed_state)

        partition = index.at_cutoff(datetime(2026, 9, 2, tzinfo=timezone.utc))
        self.assertEqual(partition.eligible, ())
        self.assertEqual(partition.unresolved, (record,))
        self.assertEqual(partition.excluded, ())
        self.assertEqual(
            index.report[0].temporally_unresolved_count,
            1,
        )

    def test_pipe_delimited_log_preserves_positional_service_and_event(self):
        self.write_fixture(
            [
                (
                    "evidence_pipe_log",
                    "evidence/operations.log",
                    (
                        "2026-09-03T00:00:00Z | INFO | support_platform | "
                        "tr-123 | support_ticket_read_completed | "
                        "resource_id=support_14 requester_email=person@example.test "
                        "rows=1\n"
                    ),
                    "2026-09-03T00:05:00Z",
                )
            ]
        )

        record = EvidenceIndex.build(self.dataset_dir).for_evidence(
            "evidence_pipe_log"
        )[0]

        self.assertEqual(record.fact.system_id, "support_platform")
        self.assertEqual(record.fact.resource_id, "support_14")
        self.assertEqual(record.attributes["event"], "support_ticket_read_completed")
        self.assertEqual(record.attributes["context_id"], "tr-123")
        self.assertEqual(record.fact.observed_at, datetime(2026, 9, 3, tzinfo=timezone.utc))
        self.assertEqual(record.fact.inspection_status.value, "INCONCLUSIVE")
        self.assertIsNone(record.fact.observed_state)

    def test_cutoff_excludes_later_capture_and_later_observation(self):
        self.write_fixture(
            [
                (
                    "captured_later",
                    "evidence/later_capture.json",
                    '{"records":[{"observed_at":"2026-09-01T00:00:00Z","resource_id":"r1"}]}',
                    "2026-09-03T00:00:00Z",
                ),
                (
                    "observed_later",
                    "evidence/later_observation.json",
                    '{"records":[{"observed_at":"2026-09-03T00:00:00Z","resource_id":"r2"}]}',
                    "2026-09-01T00:00:00Z",
                ),
                (
                    "available_in_time",
                    "evidence/in_time.json",
                    '{"records":[{"observed_at":"2026-09-02T00:00:00Z","resource_id":"r3"}]}',
                    "2026-09-02T00:00:00Z",
                ),
            ]
        )

        index = EvidenceIndex.build(self.dataset_dir)
        partition = index.at_cutoff(datetime(2026, 9, 2, tzinfo=timezone.utc))
        self.assertEqual(
            [item.evidence_id for item in partition.eligible],
            ["available_in_time"],
        )
        self.assertEqual(partition.unresolved, ())
        self.assertEqual(
            {item.evidence_id for item in partition.excluded},
            {"captured_later", "observed_later"},
        )

    def test_malformed_files_and_unsupported_formats_are_reported(self):
        self.write_fixture(
            [
                (
                    "broken_json",
                    "evidence/broken.json",
                    '{"broken":',
                    "2026-09-01T00:00:00Z",
                ),
                (
                    "broken_sql",
                    "evidence/broken.sql",
                    "CREATE TABLE incomplete (id TEXT",
                    "2026-09-01T00:00:00Z",
                ),
                (
                    "malformed_pdf",
                    "evidence/image.pdf",
                    "not a PDF",
                    "2026-09-01T00:00:00Z",
                ),
                (
                    "partial_log",
                    "evidence/partial.log",
                    "not structured\n",
                    "2026-09-01T00:00:00Z",
                ),
            ]
        )

        index = EvidenceIndex.build(self.dataset_dir)
        reports = {report.evidence_id: report for report in index.report}
        self.assertEqual(reports["broken_json"].status, ExtractionStatus.UNREADABLE)
        self.assertEqual(reports["broken_sql"].status, ExtractionStatus.UNREADABLE)
        self.assertEqual(reports["malformed_pdf"].status, ExtractionStatus.UNREADABLE)
        self.assertEqual(reports["partial_log"].status, ExtractionStatus.PARTIAL)
        self.assertEqual(reports["partial_log"].record_count, 1)
        self.assertEqual(len(index.for_evidence("partial_log")), 1)
        self.assertTrue(reports["broken_json"].error)
        self.assertTrue(reports["partial_log"].warnings)

    def test_repeated_builds_produce_identical_records_and_reports(self):
        self.write_fixture(
            [
                (
                    "evidence_b",
                    "evidence/b.json",
                    '{"records":[{"resource_id":"b2"},{"resource_id":"b1"}]}',
                    "2026-09-01T00:00:00Z",
                ),
                (
                    "evidence_a",
                    "evidence/a.log",
                    "2026-09-01T00:00:00Z INFO event=read resource_id=a1\n",
                    "2026-09-01T00:01:00Z",
                ),
            ]
        )

        first = EvidenceIndex.build(self.dataset_dir)
        second = EvidenceIndex.build(self.dataset_dir)
        self.assertEqual(first.records, second.records)
        self.assertEqual(first.report, second.report)
        self.assertEqual(
            [record.evidence_id for record in first.records],
            sorted(record.evidence_id for record in first.records),
        )

    def test_extraction_report_csv_has_one_row_per_manifest_file(self):
        self.write_fixture(
            [
                (
                    "one_file",
                    "evidence/one.json",
                    '{"resource_id":"resource_1"}',
                    "2026-09-01T00:00:00Z",
                )
            ]
        )
        index = EvidenceIndex.build(self.dataset_dir)
        report_path = self.dataset_dir / "report.csv"
        index.write_report_csv(report_path)
        with report_path.open(encoding="utf-8", newline="") as source:
            rows = list(csv.DictReader(source))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_id"], "one_file")
        self.assertEqual(rows[0]["status"], "SUCCESS")
        self.assertIn("temporally_unresolved_count", rows[0])

    def test_parses_handover_rows_with_line_provenance_and_timestamp(self):
        self.write_fixture(
            [
                (
                    "handover",
                    "evidence/handover.txt",
                    "\n".join(
                        (
                            "CUSTOMER PLATFORM - SHIFT HANDOVER",
                            "Snapshot: 2026-09-03T00:00:00Z",
                            "",
                            "- 2026-09-03T00:00:00Z | profile_store | profile_21 | USER_PROFILE | FOUND | person@example.test",
                        )
                    ),
                    "2026-09-03T00:05:00Z",
                )
            ]
        )

        index = EvidenceIndex.build(self.dataset_dir)
        record = index.for_evidence("handover")[0]
        self.assertEqual(index.report[0].status, ExtractionStatus.SUCCESS)
        self.assertEqual(record.fact.provenance.record_locator, "line=4")
        self.assertEqual(record.fact.system_id, "profile_store")
        self.assertEqual(record.fact.resource_id, "profile_21")
        self.assertEqual(record.fact.observed_at, datetime(2026, 9, 3, tzinfo=timezone.utc))
        self.assertEqual(record.attributes["result"], "FOUND")
        self.assertEqual(record.temporal_resolution, TemporalResolution.RESOLVED)
        self.assertEqual(record.fact.inspection_status.value, "INCONCLUSIVE")

    def test_handover_malformed_row_and_bad_timestamp_remain_partial_and_unresolved(self):
        self.write_fixture(
            [
                (
                    "partial_handover",
                    "evidence/handover.txt",
                    "Snapshot: 2026-09-03T00:00:00Z\n"
                    "- not-a-time | profile_store | profile_22 | USER_PROFILE | FOUND | person@example.test\n"
                    "- incomplete | record\n",
                    "2026-09-03T00:05:00Z",
                )
            ]
        )

        index = EvidenceIndex.build(self.dataset_dir)
        report = index.report[0]
        record = index.for_evidence("partial_handover")[0]
        self.assertEqual(report.status, ExtractionStatus.PARTIAL)
        self.assertEqual(report.record_count, 1)
        self.assertEqual(report.temporally_unresolved_count, 1)
        self.assertIsNone(record.fact.observed_at)
        self.assertEqual(record.temporal_resolution, TemporalResolution.UNRESOLVED)
        self.assertEqual(record.fact.provenance.record_locator, "line=2")
        self.assertGreaterEqual(len(report.warnings), 2)

    def test_valid_pdf_stays_explicitly_unsupported_without_local_reader(self):
        self.write_fixture(
            [
                (
                    "pdf_without_reader",
                    "evidence/report.pdf",
                    "%PDF-1.4\n",
                    "2026-09-03T00:05:00Z",
                )
            ]
        )
        with patch("deletion_audit.evidence_index._optional_module", return_value=None):
            index = EvidenceIndex.build(self.dataset_dir)

        self.assertEqual(index.report[0].status, ExtractionStatus.UNSUPPORTED)
        self.assertIn("PDF", index.report[0].error or "")
        self.assertEqual(index.for_evidence("pdf_without_reader"), ())

    def test_pdf_page_text_preserves_page_locator_and_provenance(self):
        self.write_fixture(
            [
                (
                    "pdf_with_reader",
                    "evidence/report.pdf",
                    "%PDF-1.4\n",
                    "2026-09-03T00:05:00Z",
                )
            ]
        )

        class Page:
            @staticmethod
            def extract_text():
                return "Audit record user_25\nEmail: person@example.test"

        class Reader:
            def __init__(self, source):
                self.pages = [Page(), Page()]

        with patch(
            "deletion_audit.evidence_index._optional_module",
            return_value=type("PdfModule", (), {"PdfReader": Reader}),
        ):
            index = EvidenceIndex.build(self.dataset_dir)

        records = index.for_evidence("pdf_with_reader")
        self.assertEqual(index.report[0].status, ExtractionStatus.SUCCESS)
        self.assertEqual(records[0].fact.provenance.record_locator, "page=1;line=1")
        self.assertEqual(records[0].metadata["page_number"], 1)
        self.assertEqual(records[0].fact.inspection_status.value, "INCONCLUSIVE")
        self.assertEqual(records[0].temporal_resolution, TemporalResolution.UNRESOLVED)
        self.assertEqual(records[0].extraction_method, "pdf-page-text")
        self.assertIn("pdf-page-text", index.report[0].extraction_method)

    def test_scanned_pdf_page_uses_local_ocr_with_page_provenance(self):
        self.write_fixture(
            [
                (
                    "scanned_pdf",
                    "evidence/scanned.pdf",
                    "%PDF-1.4\n",
                    "2026-09-03T00:05:00Z",
                )
            ]
        )

        class Page:
            @staticmethod
            def extract_text():
                return ""

        class Reader:
            def __init__(self, source):
                self.pages = [Page()]

        class Bitmap:
            @staticmethod
            def to_pil():
                return ImageContext()

        class RenderPage:
            @staticmethod
            def render(scale):
                return Bitmap()

        class RenderDocument:
            def __getitem__(self, index):
                self.page_index = index
                return RenderPage()

            def close(self):
                self.closed = True

        class RenderModule:
            @staticmethod
            def PdfDocument(path):
                return RenderDocument()

        class ImageContext:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

        class FakeOcrModule:
            class Output:
                DICT = "dict"

            @staticmethod
            def get_tesseract_version():
                return "test-version"

            @staticmethod
            def image_to_data(image, output_type):
                return {
                    "text": ["Resource", "archive_27"],
                    "page_num": [1, 1],
                    "block_num": [1, 1],
                    "par_num": [1, 1],
                    "line_num": [1, 1],
                    "left": [12, 80],
                    "top": [25, 25],
                    "width": [62, 76],
                    "height": [14, 14],
                    "conf": ["96", "91"],
                }

        pdf_module = type("PdfModule", (), {"PdfReader": Reader})
        with patch(
            "deletion_audit.evidence_index._optional_module",
            side_effect=[None, pdf_module, RenderModule, FakeOcrModule],
        ):
            index = EvidenceIndex.build(self.dataset_dir)

        record = index.for_evidence("scanned_pdf")[0]
        self.assertEqual(index.report[0].status, ExtractionStatus.PARTIAL)
        self.assertEqual(index.report[0].extraction_method, "tesseract-ocr")
        self.assertEqual(record.fact.provenance.source_id, "scanned_pdf")
        self.assertEqual(
            record.fact.provenance.record_locator, "page=1;region=1"
        )
        self.assertEqual(record.metadata["page_number"], 1)
        self.assertEqual(record.metadata["bbox"], [12, 25, 156, 39])
        self.assertEqual(record.metadata["mean_word_confidence"], 93.5)
        self.assertEqual(record.metadata["ocr_version"], "test-version")
        self.assertIn("probabilistic", index.report[0].warnings[0])
        self.assertEqual(record.temporal_resolution, TemporalResolution.UNRESOLVED)

    def test_invalid_pdf_signature_is_reported_unreadable(self):
        self.write_fixture(
            [
                (
                    "invalid_pdf",
                    "evidence/broken.pdf",
                    "not a PDF",
                    "2026-09-03T00:05:00Z",
                )
            ]
        )
        index = EvidenceIndex.build(self.dataset_dir)
        self.assertEqual(index.report[0].status, ExtractionStatus.UNREADABLE)
        self.assertIn("signature", index.report[0].error or "")

    def test_ocr_backend_unavailable_keeps_image_unsupported_with_provenance(self):
        self.write_fixture(
            [
                (
                    "image_without_ocr",
                    "evidence/screen.png",
                    "not a valid png",
                    "2026-09-03T00:05:00Z",
                )
            ]
        )

        class ImageContext:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def load(self):
                return None

        class ImageModule:
            @staticmethod
            def open(path):
                return ImageContext()

        with patch(
            "deletion_audit.evidence_index._optional_module",
            side_effect=[ImageModule, None],
        ):
            index = EvidenceIndex.build(self.dataset_dir)

        self.assertEqual(index.report[0].status, ExtractionStatus.UNSUPPORTED)
        self.assertEqual(index.report[0].evidence_id, "image_without_ocr")
        self.assertEqual(index.report[0].source_path, "evidence/screen.png")
        self.assertIn("OCR", index.report[0].error or "")

    def test_ocr_text_regions_preserve_region_locator_and_bounds(self):
        self.write_fixture(
            [
                (
                    "image_with_ocr",
                    "evidence/screen.png",
                    "test image bytes",
                    "2026-09-03T00:05:00Z",
                )
            ]
        )

        class ImageContext:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def load(self):
                return None

        class ImageModule:
            @staticmethod
            def open(path):
                return ImageContext()

        class FakeOcrModule:
            class Output:
                DICT = "dict"

            @staticmethod
            def get_tesseract_version():
                return "test"

            @staticmethod
            def image_to_data(image, output_type):
                return {
                    "text": ["Resource", "profile_26"],
                    "page_num": [1, 1],
                    "block_num": [2, 2],
                    "par_num": [1, 1],
                    "line_num": [3, 3],
                    "left": [10, 65],
                    "top": [20, 20],
                    "width": [50, 55],
                    "height": [12, 12],
                }

        with patch(
            "deletion_audit.evidence_index._optional_module",
            side_effect=[ImageModule, FakeOcrModule],
        ):
            index = EvidenceIndex.build(self.dataset_dir)

        record = index.for_evidence("image_with_ocr")[0]
        self.assertEqual(index.report[0].status, ExtractionStatus.PARTIAL)
        self.assertEqual(record.extraction_method, "tesseract-ocr")
        self.assertEqual(record.fact.provenance.source_id, "image_with_ocr")
        self.assertEqual(record.fact.provenance.source_path, "evidence/screen.png")
        self.assertEqual(record.fact.provenance.record_locator, "region=1")
        self.assertEqual(record.attributes["text"], "Resource profile_26")
        self.assertEqual(record.metadata["bbox"], [10, 20, 120, 32])
        self.assertIn("probabilistic", index.report[0].warnings[0])
        self.assertEqual(record.temporal_resolution, TemporalResolution.UNRESOLVED)


if __name__ == "__main__":
    unittest.main()
