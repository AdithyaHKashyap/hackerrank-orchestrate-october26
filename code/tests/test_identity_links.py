import csv
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from deletion_audit.evidence_index import EvidenceIndex
from deletion_audit.identity_links import (
    IdentityLinkConfidence,
    IdentityLinkResolutionStatus,
    IdentityLinkResolver,
    IdentityLinkSource,
    IdentifierType,
)
from deletion_audit.models import DeletionRequest, Identity, IdentityEvent
from deletion_audit.temporal import parse_timestamp


def timestamp(value):
    return parse_timestamp(value, "test timestamp")


def identity(user_id, email, updated_at="2026-01-01T00:00:00Z", name="Example"):
    return Identity(
        user_id=user_id,
        name=name,
        email=email,
        phone="+1 555 0100",
        email_hash="hash-{}".format(user_id),
        updated_at=timestamp(updated_at),
    )


def email_event(
    audit_id,
    user_id,
    old_value,
    new_value,
    event_time="2025-03-01T00:00:00Z",
):
    return IdentityEvent(
        audit_id=audit_id,
        user_id=user_id,
        event_time=timestamp(event_time),
        field_name="email",
        old_value=old_value,
        new_value=new_value,
    )


class IdentityLinkResolverTests(unittest.TestCase):
    def test_historical_email_change_is_bounded_and_cites_audit_provenance(self):
        resolver = IdentityLinkResolver(
            [identity("user-1", "new@example.test")],
            [email_event("audit-1", "user-1", "old@example.test", "new@example.test")],
        )

        result = resolver.resolve(
            IdentifierType.EMAIL,
            "OLD@example.test",
            audit_at=timestamp("2025-06-01T00:00:00Z"),
            valid_at=timestamp("2025-02-01T00:00:00Z"),
        )

        self.assertEqual(result.status, IdentityLinkResolutionStatus.RESOLVED)
        self.assertEqual(result.user_id, "user-1")
        self.assertEqual(len(result.links), 1)
        link = result.links[0]
        self.assertEqual(link.source, IdentityLinkSource.HISTORICAL)
        self.assertEqual(link.provenance.source_id, "audit-1")
        self.assertIsNone(link.valid_from)
        self.assertEqual(link.valid_until, timestamp("2025-03-01T00:00:00Z"))
        self.assertTrue(link.is_valid_at(timestamp("2025-02-01T00:00:00Z")))
        self.assertFalse(link.is_valid_at(timestamp("2025-03-01T00:00:00Z")))

    def test_expired_historical_email_resolves_when_no_reassignment_exists(self):
        resolver = IdentityLinkResolver(
            [identity("user-1", "new@example.test")],
            [email_event("audit-1", "user-1", "old@example.test", "new@example.test")],
        )

        after_change = resolver.resolve(
            IdentifierType.EMAIL,
            "old@example.test",
            audit_at=timestamp("2025-06-01T00:00:00Z"),
            valid_at=timestamp("2025-05-01T00:00:00Z"),
        )
        before_change_was_known = resolver.resolve(
            IdentifierType.EMAIL,
            "old@example.test",
            audit_at=timestamp("2025-02-01T00:00:00Z"),
            valid_at=timestamp("2025-01-01T00:00:00Z"),
        )

        self.assertEqual(after_change.status, IdentityLinkResolutionStatus.RESOLVED)
        self.assertEqual(after_change.user_id, "user-1")
        self.assertEqual(after_change.links[0].source, IdentityLinkSource.HISTORICAL)
        self.assertEqual(
            before_change_was_known.status, IdentityLinkResolutionStatus.UNMATCHED
        )

    def test_reassigned_email_resolves_by_request_time_not_arbitrarily(self):
        resolver = IdentityLinkResolver(
            [
                identity("user-1", "first@example.test"),
                identity(
                    "user-2",
                    "reused@example.test",
                    updated_at="2025-04-01T00:00:00Z",
                ),
            ],
            [
                email_event(
                    "audit-1",
                    "user-1",
                    "reused@example.test",
                    "first@example.test",
                )
            ],
        )

        before_reassignment = resolver.resolve(
            IdentifierType.EMAIL,
            "reused@example.test",
            audit_at=timestamp("2025-06-01T00:00:00Z"),
            valid_at=timestamp("2025-02-01T00:00:00Z"),
        )
        after_reassignment = resolver.resolve(
            IdentifierType.EMAIL,
            "reused@example.test",
            audit_at=timestamp("2025-06-01T00:00:00Z"),
            valid_at=timestamp("2025-05-01T00:00:00Z"),
        )

        self.assertEqual(before_reassignment.status, IdentityLinkResolutionStatus.RESOLVED)
        self.assertEqual(before_reassignment.user_id, "user-1")
        self.assertEqual(after_reassignment.status, IdentityLinkResolutionStatus.RESOLVED)
        self.assertEqual(after_reassignment.user_id, "user-2")

    def test_reused_expired_email_with_multiple_prior_owners_is_ambiguous(self):
        resolver = IdentityLinkResolver(
            [
                identity(
                    "user-1",
                    "first@example.test",
                    updated_at="2025-03-01T00:00:00Z",
                ),
                identity(
                    "user-2",
                    "second@example.test",
                    updated_at="2025-03-01T00:00:00Z",
                ),
            ],
            [
                email_event(
                    "audit-1",
                    "user-1",
                    "reused@example.test",
                    "first@example.test",
                    "2025-01-01T00:00:00Z",
                ),
                email_event(
                    "audit-2",
                    "user-2",
                    "reused@example.test",
                    "second@example.test",
                    "2025-02-01T00:00:00Z",
                ),
            ],
        )

        result = resolver.resolve(
            IdentifierType.EMAIL,
            "reused@example.test",
            audit_at=timestamp("2025-04-01T00:00:00Z"),
            valid_at=timestamp("2025-04-01T00:00:00Z"),
        )

        self.assertEqual(result.status, IdentityLinkResolutionStatus.AMBIGUOUS)
        self.assertIsNone(result.user_id)
        self.assertEqual({link.user_id for link in result.links}, {"user-1", "user-2"})

    def test_shared_phone_is_ambiguous(self):
        resolver = IdentityLinkResolver(
            [
                identity("user-1", "one@example.test"),
                identity("user-2", "two@example.test"),
            ],
            [],
        )

        result = resolver.resolve(
            IdentifierType.PHONE,
            "+1 (555) 0100",
            audit_at=timestamp("2026-02-01T00:00:00Z"),
        )

        self.assertEqual(result.status, IdentityLinkResolutionStatus.AMBIGUOUS)
        self.assertIsNone(result.user_id)
        self.assertEqual({link.user_id for link in result.links}, {"user-1", "user-2"})

    def test_duplicate_names_do_not_create_identifier_links(self):
        resolver = IdentityLinkResolver(
            [
                identity("user-1", "one@example.test", name="Shared Name"),
                identity("user-2", "two@example.test", name="Shared Name"),
            ],
            [],
        )

        result = resolver.resolve(
            IdentifierType.EMAIL,
            "Shared Name",
            audit_at=timestamp("2026-02-01T00:00:00Z"),
        )

        self.assertEqual(result.status, IdentityLinkResolutionStatus.UNMATCHED)
        self.assertEqual(result.links, ())
        self.assertEqual(result.candidates, ())

    def test_evidence_alias_requires_explicit_user_id_and_preserves_file_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset_dir = Path(directory)
            evidence_dir = dataset_dir / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "snapshot.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "observed_at": "2025-05-01T12:00:00Z",
                                "user_id": "user-1",
                                "email": "evidence-alias@example.test",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with (dataset_dir / "evidence_files.csv").open(
                "w", encoding="utf-8", newline=""
            ) as manifest:
                writer = csv.writer(manifest)
                writer.writerow(("file_id", "file_path", "origin", "captured_at"))
                writer.writerow(
                    (
                        "evidence-1",
                        "evidence/snapshot.json",
                        "test",
                        "2025-05-02T00:00:00Z",
                    )
                )
            index = EvidenceIndex.build(dataset_dir)
            resolver = IdentityLinkResolver(
                [identity("user-1", "current@example.test")],
                [],
                evidence_index=index,
            )

        result = resolver.resolve(
            IdentifierType.EMAIL,
            "evidence-alias@example.test",
            audit_at=timestamp("2025-06-01T00:00:00Z"),
            valid_at=timestamp("2025-05-01T12:00:00Z"),
        )

        self.assertEqual(result.status, IdentityLinkResolutionStatus.RESOLVED)
        self.assertEqual(result.user_id, "user-1")
        self.assertEqual(result.links[0].source, IdentityLinkSource.EVIDENCE)
        self.assertEqual(result.links[0].confidence, IdentityLinkConfidence.STRONG)
        self.assertEqual(result.links[0].provenance.source_id, "evidence-1")
        self.assertEqual(
            result.links[0].provenance.record_locator,
            "$.records[0]",
        )

    def test_timestamp_unresolved_evidence_alias_is_candidate_only(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset_dir = Path(directory)
            evidence_dir = dataset_dir / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "snapshot.json").write_text(
                (
                    '{"records":[{"user_id":"user-1","phone":"+15550102",'
                    '"backup_phone":"null"}]}'
                ),
                encoding="utf-8",
            )
            with (dataset_dir / "evidence_files.csv").open(
                "w", encoding="utf-8", newline=""
            ) as manifest:
                writer = csv.writer(manifest)
                writer.writerow(("file_id", "file_path", "origin", "captured_at"))
                writer.writerow(
                    (
                        "evidence-1",
                        "evidence/snapshot.json",
                        "test",
                        "2025-05-02T00:00:00Z",
                    )
                )
            index = EvidenceIndex.build(dataset_dir)
            resolver = IdentityLinkResolver(
                [identity("user-1", "current@example.test")],
                [],
                evidence_index=index,
            )

        result = resolver.resolve(
            IdentifierType.PHONE,
            "+1 (555) 0102",
            audit_at=timestamp("2025-06-01T00:00:00Z"),
        )

        self.assertEqual(result.status, IdentityLinkResolutionStatus.UNCERTAIN)
        self.assertIsNone(result.user_id)
        self.assertEqual(result.links, ())
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].confidence, IdentityLinkConfidence.CANDIDATE)
        self.assertIn("time is unresolved", result.candidates[0].reason)

    def test_ocr_alias_is_candidate_only_and_never_strong(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset_dir = Path(directory)
            evidence_dir = dataset_dir / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "snapshot.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "observed_at": "2025-05-01T12:00:00Z",
                                "user_id": "user-1",
                                "email": "possible@example.test",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with (dataset_dir / "evidence_files.csv").open(
                "w", encoding="utf-8", newline=""
            ) as manifest:
                writer = csv.writer(manifest)
                writer.writerow(("file_id", "file_path", "origin", "captured_at"))
                writer.writerow(
                    (
                        "evidence-1",
                        "evidence/snapshot.json",
                        "test",
                        "2025-05-02T00:00:00Z",
                    )
                )
            index = EvidenceIndex.build(dataset_dir)
            ocr_record = replace(
                index.records[0],
                extraction_method="tesseract-ocr",
            )
            ocr_index = EvidenceIndex([ocr_record], index.report)
            resolver = IdentityLinkResolver(
                [identity("user-1", "current@example.test")],
                [],
                evidence_index=ocr_index,
            )

        result = resolver.resolve(
            IdentifierType.EMAIL,
            "possible@example.test",
            audit_at=timestamp("2025-06-01T00:00:00Z"),
            valid_at=timestamp("2025-05-01T12:00:00Z"),
        )

        self.assertEqual(result.status, IdentityLinkResolutionStatus.UNCERTAIN)
        self.assertEqual(result.links, ())
        self.assertEqual(len(result.candidates), 1)
        self.assertIn("OCR", result.candidates[0].reason)

    def test_conflicting_links_are_ambiguous_even_if_one_is_evidence_derived(self):
        identities = [
            identity(
                "user-1",
                "shared@example.test",
                updated_at="2025-01-01T00:00:00Z",
            ),
            identity(
                "user-2",
                "other@example.test",
                updated_at="2025-01-01T00:00:00Z",
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            dataset_dir = Path(directory)
            evidence_dir = dataset_dir / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "snapshot.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "observed_at": "2025-05-01T12:00:00Z",
                                "user_id": "user-2",
                                "email": "shared@example.test",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with (dataset_dir / "evidence_files.csv").open(
                "w", encoding="utf-8", newline=""
            ) as manifest:
                writer = csv.writer(manifest)
                writer.writerow(("file_id", "file_path", "origin", "captured_at"))
                writer.writerow(
                    (
                        "evidence-1",
                        "evidence/snapshot.json",
                        "test",
                        "2025-05-02T00:00:00Z",
                    )
                )
            index = EvidenceIndex.build(dataset_dir)
            ocr_record = replace(
                index.records[0],
                extraction_method="tesseract-ocr",
            )
            index = EvidenceIndex([ocr_record], index.report)
            resolver = IdentityLinkResolver(identities, [], evidence_index=index)

        result = resolver.resolve(
            IdentifierType.EMAIL,
            "shared@example.test",
            audit_at=timestamp("2025-06-01T00:00:00Z"),
            valid_at=timestamp("2025-05-01T12:00:00Z"),
        )

        self.assertEqual(result.status, IdentityLinkResolutionStatus.AMBIGUOUS)
        self.assertIsNone(result.user_id)
        self.assertEqual({link.user_id for link in result.links}, {"user-1"})
        self.assertEqual({link.user_id for link in result.candidates}, {"user-2"})

    def test_resolve_request_uses_request_time_and_audit_cutoff(self):
        event = email_event(
            "audit-1",
            "user-1",
            "old@example.test",
            "new@example.test",
        )
        resolver = IdentityLinkResolver(
            [identity("user-1", "new@example.test")],
            [event],
        )
        request = DeletionRequest(
            case_id="test",
            email="old@example.test",
            requested_at=timestamp("2025-02-01T00:00:00Z"),
            reported_status="COMPLETE",
            reported_at=timestamp("2025-04-01T00:00:00Z"),
            audit_at=timestamp("2025-06-01T00:00:00Z"),
            request_text="Please delete my account.",
        )

        result = resolver.resolve_request(request)

        self.assertEqual(result.status, IdentityLinkResolutionStatus.RESOLVED)
        self.assertEqual(result.user_id, "user-1")


if __name__ == "__main__":
    unittest.main()
