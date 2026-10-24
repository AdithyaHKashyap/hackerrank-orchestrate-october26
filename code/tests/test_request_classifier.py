import unittest

from deletion_audit.request_classifier import (
    AuthorizationStatus,
    RequestIntent,
    SignalPolarity,
    classify_request,
)


class RequestClassifierTests(unittest.TestCase):
    def assert_authorized(self, text):
        result = classify_request(text)
        self.assertEqual(result.authorization, AuthorizationStatus.AUTHORIZED)
        self.assertIn(RequestIntent.DELETION, result.intents)
        return result

    def test_explicit_account_deletion_is_authorized(self):
        self.assert_authorized("Please permanently delete my account.")

    def test_removal_of_personal_details_is_deletion_intent(self):
        self.assert_authorized("Please remove my name and contact details.")

    def test_audit_question_about_prior_deletion_is_authorized(self):
        self.assert_authorized(
            "Please verify whether my account was deleted and my profile is gone."
        )

    def test_attempted_deletion_followed_by_request_to_complete_is_authorized(self):
        self.assert_authorized(
            "I tried to delete my account. Please complete the deletion if needed."
        )

    def test_spanish_deletion_request_is_authorized(self):
        self.assert_authorized(
            "Solicito eliminar mi cuenta y completar la eliminación."
        )

    def test_french_deletion_request_is_authorized(self):
        self.assert_authorized(
            "Je demande la suppression définitive de mon compte."
        )

    def test_portuguese_deletion_request_is_authorized(self):
        self.assert_authorized(
            "Solicito a exclusão permanente da conta associada a este e-mail."
        )

    def test_japanese_deletion_request_is_authorized(self):
        self.assert_authorized(
            "\u3053\u306e\u30a2\u30ab\u30a6\u30f3\u30c8\u306e"
            "\u524a\u9664\u3092\u4f9d\u983c\u3057\u307e\u3059\u3002"
        )

    def test_korean_deletion_request_is_authorized(self):
        self.assert_authorized(
            "\uc601\uad6c \uc0ad\uc81c\ub97c \uc694\uccad\ud569\ub2c8\ub2e4."
        )

    def test_access_only_request_is_not_authorized_for_deletion(self):
        result = classify_request(
            "Please give me access to my personal data and account records."
        )
        self.assertEqual(result.authorization, AuthorizationStatus.NOT_AUTHORIZED)
        self.assertEqual(result.intents, (RequestIntent.ACCESS,))

    def test_correction_only_request_is_not_authorized_for_deletion(self):
        result = classify_request(
            "Please correct the phone number on my profile and keep my account active."
        )
        self.assertEqual(result.authorization, AuthorizationStatus.NOT_AUTHORIZED)
        self.assertIn(RequestIntent.CORRECTION, result.intents)

    def test_export_only_request_is_not_authorized_for_deletion(self):
        result = classify_request(
            "I would like to download my account information in a portable format."
        )
        self.assertEqual(result.authorization, AuthorizationStatus.NOT_AUTHORIZED)
        self.assertIn(RequestIntent.EXPORT, result.intents)

    def test_marketing_opt_out_is_not_authorized_for_deletion(self):
        result = classify_request(
            "Please unsubscribe me from promotional emails and marketing messages."
        )
        self.assertEqual(
            result.authorization, AuthorizationStatus.NOT_AUTHORIZED
        )
        self.assertIn(RequestIntent.MARKETING_OPTOUT, result.intents)

    def test_requesting_deletion_is_a_deletion_request_frame(self):
        self.assert_authorized(
            "I am requesting deletion of the account registered to this email address."
        )

    def test_first_person_deleting_statement_authorizes_deletion(self):
        self.assert_authorized(
            "I'm deleting my account. You can keep anonymous statistics."
        )

    def test_would_like_it_deleted_is_a_deletion_request_frame(self):
        self.assert_authorized(
            "I no longer use this account and would like it permanently deleted."
        )

    def test_marketing_list_removal_only_is_not_deletion(self):
        result = classify_request(
            "Please remove me from marketing lists only. "
            "I still want receipts and service messages for this account."
        )
        self.assertEqual(result.authorization, AuthorizationStatus.NOT_AUTHORIZED)
        self.assertIn(RequestIntent.MARKETING_OPTOUT, result.intents)

    def test_account_support_request_is_not_authorized_for_deletion(self):
        result = classify_request(
            "I cannot log in. Please help me reset my password."
        )
        self.assertEqual(result.authorization, AuthorizationStatus.NOT_AUTHORIZED)
        self.assertIn(RequestIntent.OTHER, result.intents)

    def test_negated_deletion_is_not_authorized(self):
        result = classify_request(
            "Do not delete my account; I want to continue using the service."
        )
        self.assertEqual(result.authorization, AuthorizationStatus.NOT_AUTHORIZED)

    def test_first_person_negated_deletion_is_not_authorized(self):
        result = classify_request("I am not deleting my account.")
        self.assertEqual(result.authorization, AuthorizationStatus.NOT_AUTHORIZED)
        self.assertIn(
            SignalPolarity.NEGATED,
            tuple(signal.polarity for signal in result.signals),
        )

    def test_deletion_mixed_with_correction_remains_authorized_and_tracks_both(self):
        result = self.assert_authorized(
            "Please delete my account and also correct my contact details."
        )
        self.assertIn(RequestIntent.CORRECTION, result.intents)

    def test_conflicting_positive_and_negated_deletion_is_uncertain(self):
        result = classify_request(
            "Please delete my account, but I do not want account deletion."
        )
        self.assertEqual(result.authorization, AuthorizationStatus.UNCERTAIN)
        self.assertIn("CONFLICTING_DELETION_INTENT", result.uncertainty_reasons)

    def test_question_about_how_to_delete_is_not_an_authorization(self):
        result = classify_request("How do I delete my account?")
        self.assertEqual(result.authorization, AuthorizationStatus.NOT_AUTHORIZED)
        self.assertIn(RequestIntent.OTHER, result.intents)

    def test_deletion_mention_without_a_request_is_uncertain(self):
        result = classify_request("I have a question about account deletion policy.")
        self.assertEqual(result.authorization, AuthorizationStatus.UNCERTAIN)
        self.assertIn(
            "DELETION_INTENT_NOT_ESTABLISHED", result.uncertainty_reasons
        )

    def test_unrecognized_text_is_uncertain_not_assumed_authorized(self):
        result = classify_request("Hello, I need help with my account.")
        self.assertEqual(result.authorization, AuthorizationStatus.UNCERTAIN)
        self.assertEqual(result.uncertainty_reasons, ("NO_RECOGNIZED_REQUEST_INTENT",))

    def test_empty_or_invalid_text_is_uncertain(self):
        self.assertEqual(
            classify_request("").authorization, AuthorizationStatus.UNCERTAIN
        )
        self.assertEqual(
            classify_request(None).authorization, AuthorizationStatus.UNCERTAIN
        )


if __name__ == "__main__":
    unittest.main()
